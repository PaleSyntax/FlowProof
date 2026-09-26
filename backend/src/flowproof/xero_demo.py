"""Zero-secret-copy Xero Demo PKCE connection and observe-only qualification.

The implementation is deliberately ephemeral: OAuth tokens live only in process
memory, are never logged or persisted, and disappear on restart. The product can
therefore prove one real read-only outcome without asking an operator to copy a
secret or granting any provider-write authority.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import quote, urlencode, urlsplit
from uuid import uuid4

import httpx

from flowproof.accounting import (
    InvoiceObservation,
    ObservationState,
    ProviderContract,
    RecoveryWriteOutcome,
    WriteOutcomeState,
)
from flowproof.clock import monotonic_utc_now

XERO_ACCOUNTING_ORIGIN = "https://api.xero.com"
XERO_ACCOUNTING_BASE_PATH = "/api.xro/2.0"
XERO_AUTHORIZE_URL = "https://login.xero.com/identity/connect/authorize"
XERO_TOKEN_URL = "https://identity.xero.com/connect/token"
XERO_CONNECTIONS_URL = "https://api.xero.com/connections"
XERO_PKCE_SCOPES = (
    "openid",
    "profile",
    "email",
    "accounting.invoices.read",
    "accounting.settings.read",
)
XERO_CALLBACK_PATH = "/api/v1/provider-connections/xero/callback"

_CLIENT_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_MAX_ACCESS_TOKEN_LENGTH = 8192
_MAX_OPERATION_REFERENCE_LENGTH = 255
_MAX_AUTHORIZATION_CODE_LENGTH = 2048
_MAX_CONNECTED_TENANTS = 25
_PKCE_TTL = timedelta(minutes=5)


class XeroConnectionError(RuntimeError):
    """Safe, bounded error code for the product-facing OAuth path."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True, repr=False)
class _PendingAuthorization:
    state: str
    code_verifier: str
    client_id: str
    redirect_uri: str
    principal_id: str
    principal_name: str
    principal_role: str
    expires_at: datetime


@dataclass(frozen=True, slots=True, repr=False)
class _ActiveConnection:
    access_token: str
    tenant_id: str
    principal_id: str
    principal_name: str
    principal_role: str
    connected_at: datetime
    expires_at: datetime


def _utc_now() -> datetime:
    return monotonic_utc_now()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class XeroDemoAccountingClient:
    """Canonical Xero invoice reader plus one-time PKCE browser connection."""

    def __init__(
        self,
        base_url: str,
        contract: ProviderContract,
        timeout_seconds: float = 5.0,
        *,
        clock: Any = None,
    ) -> None:
        parsed = urlsplit(base_url.rstrip("/"))
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.xero.com"
            or parsed.port is not None
            or parsed.path.rstrip("/") != XERO_ACCOUNTING_BASE_PATH
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("Xero adapter requires the canonical Accounting API base URL")
        if contract.provider_id != "xero-demo" or contract.environment != "sandbox":
            raise ValueError("Xero Demo adapter requires the xero-demo sandbox contract")
        if contract.authentication.get("mode") != "oauth2-pkce-user-consent":
            raise ValueError("Xero Demo adapter requires the PKCE user-consent mode")
        if contract.authentication.get("credential_reference") != "not-applicable":
            raise ValueError("Xero PKCE must not declare a copied credential reference")

        self.base_url = f"{XERO_ACCOUNTING_ORIGIN}{XERO_ACCOUNTING_BASE_PATH}"
        self.contract = contract
        self.timeout_seconds = timeout_seconds
        self._clock = clock or _utc_now
        self._lock = threading.RLock()
        self._pending: dict[str, _PendingAuthorization] = {}
        self._connection: _ActiveConnection | None = None

    @staticmethod
    def _validate_redirect_uri(redirect_uri: str) -> str:
        parsed = urlsplit(redirect_uri)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "localhost"
            or parsed.port is None
            or parsed.path != XERO_CALLBACK_PATH
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise XeroConnectionError("XERO_LOCALHOST_CALLBACK_REQUIRED")
        return redirect_uri

    def start_authorization(
        self,
        *,
        principal_id: str,
        principal_name: str,
        principal_role: str,
        client_id: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        if not _CLIENT_ID.fullmatch(client_id):
            raise XeroConnectionError("XERO_CLIENT_ID_INVALID")
        redirect_uri = self._validate_redirect_uri(redirect_uri)
        now = self._clock().astimezone(UTC)
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        pending = _PendingAuthorization(
            state=state,
            code_verifier=verifier,
            client_id=client_id,
            redirect_uri=redirect_uri,
            principal_id=principal_id,
            principal_name=principal_name,
            principal_role=principal_role,
            expires_at=now + _PKCE_TTL,
        )
        with self._lock:
            self._remove_expired(now)
            self._pending = {
                key: value
                for key, value in self._pending.items()
                if value.principal_id != principal_id
            }
            self._pending[state] = pending
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": " ".join(XERO_PKCE_SCOPES),
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            quote_via=quote,
        )
        return {
            "authorization_url": f"{XERO_AUTHORIZE_URL}?{query}",
            "expires_at": _iso(pending.expires_at),
            "requested_scopes": list(XERO_PKCE_SCOPES),
            "manual_secret_copy_required": False,
        }

    def cancel_authorization(self, state: str) -> None:
        with self._lock:
            self._pending.pop(state, None)

    def complete_authorization(self, *, state: str, code: str) -> dict[str, Any]:
        now = self._clock().astimezone(UTC)
        with self._lock:
            pending = self._pending.pop(state, None)
        if pending is None or pending.expires_at <= now:
            raise XeroConnectionError("XERO_AUTHORIZATION_STATE_INVALID_OR_EXPIRED")
        if (
            not code
            or len(code) > _MAX_AUTHORIZATION_CODE_LENGTH
            or not code.isascii()
        ):
            raise XeroConnectionError("XERO_AUTHORIZATION_CODE_INVALID")

        token_response = self._exchange_code(pending, code)
        access_token = token_response.get("access_token")
        expires_in = token_response.get("expires_in")
        token_type = token_response.get("token_type")
        if (
            not isinstance(access_token, str)
            or not 20 <= len(access_token) <= _MAX_ACCESS_TOKEN_LENGTH
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 1 <= expires_in <= 3600
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or "refresh_token" in token_response
        ):
            raise XeroConnectionError("XERO_TOKEN_RESPONSE_MALFORMED")

        tenant_id = self._find_exact_demo_tenant(access_token)
        connected_at = self._clock().astimezone(UTC)
        connection = _ActiveConnection(
            access_token=access_token,
            tenant_id=tenant_id,
            principal_id=pending.principal_id,
            principal_name=pending.principal_name,
            principal_role=pending.principal_role,
            connected_at=connected_at,
            expires_at=connected_at + timedelta(seconds=expires_in),
        )
        with self._lock:
            self._connection = connection
        return self.public_status(pending.principal_id)

    def _exchange_code(
        self, pending: _PendingAuthorization, code: str
    ) -> dict[str, Any]:
        try:
            response = httpx.post(
                XERO_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": pending.client_id,
                    "code": code,
                    "redirect_uri": pending.redirect_uri,
                    "code_verifier": pending.code_verifier,
                },
                headers={"Accept": "application/json"},
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise XeroConnectionError("XERO_TOKEN_EXCHANGE_UNAVAILABLE") from exc
        if response.status_code != 200:
            raise XeroConnectionError("XERO_TOKEN_EXCHANGE_REJECTED")
        try:
            body = response.json()
        except ValueError as exc:
            raise XeroConnectionError("XERO_TOKEN_RESPONSE_MALFORMED") from exc
        if not isinstance(body, dict):
            raise XeroConnectionError("XERO_TOKEN_RESPONSE_MALFORMED")
        return body

    def _find_exact_demo_tenant(self, access_token: str) -> str:
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        try:
            response = httpx.get(
                XERO_CONNECTIONS_URL,
                headers=headers,
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise XeroConnectionError("XERO_CONNECTIONS_UNAVAILABLE") from exc
        if response.status_code != 200:
            raise XeroConnectionError("XERO_CONNECTIONS_REJECTED")
        try:
            connections = response.json()
        except ValueError as exc:
            raise XeroConnectionError("XERO_CONNECTIONS_MALFORMED") from exc
        if (
            not isinstance(connections, list)
            or not 1 <= len(connections) <= _MAX_CONNECTED_TENANTS
        ):
            raise XeroConnectionError("XERO_CONNECTIONS_MALFORMED")

        demo_tenants: list[str] = []
        for item in connections:
            if not isinstance(item, dict) or item.get("tenantType") != "ORGANISATION":
                continue
            tenant_id = item.get("tenantId")
            if not isinstance(tenant_id, str) or not 1 <= len(tenant_id) <= 128:
                raise XeroConnectionError("XERO_CONNECTIONS_MALFORMED")
            if self._tenant_is_active_demo(access_token, tenant_id):
                demo_tenants.append(tenant_id)
        if len(demo_tenants) != 1:
            raise XeroConnectionError("XERO_EXACTLY_ONE_DEMO_COMPANY_REQUIRED")
        return demo_tenants[0]

    def _tenant_is_active_demo(self, access_token: str, tenant_id: str) -> bool:
        try:
            response = httpx.get(
                f"{self.base_url}/Organisation",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "xero-tenant-id": tenant_id,
                },
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise XeroConnectionError("XERO_ORGANISATION_READ_UNAVAILABLE") from exc
        if response.status_code != 200:
            raise XeroConnectionError("XERO_ORGANISATION_READ_REJECTED")
        try:
            body = response.json()
        except ValueError as exc:
            raise XeroConnectionError("XERO_ORGANISATION_RESPONSE_MALFORMED") from exc
        organisations = body.get("Organisations") if isinstance(body, dict) else None
        if not isinstance(organisations, list) or len(organisations) != 1:
            raise XeroConnectionError("XERO_ORGANISATION_RESPONSE_MALFORMED")
        organisation = organisations[0]
        if not isinstance(organisation, dict):
            raise XeroConnectionError("XERO_ORGANISATION_RESPONSE_MALFORMED")
        return (
            organisation.get("IsDemoCompany") is True
            and organisation.get("OrganisationStatus") == "ACTIVE"
        )

    def public_status(self, principal_id: str | None = None) -> dict[str, Any]:
        now = self._clock().astimezone(UTC)
        with self._lock:
            self._remove_expired(now)
            connection = self._connection
            pending = any(
                item.principal_id == principal_id for item in self._pending.values()
            ) if principal_id is not None else False
        visible_connection = (
            connection
            if connection is not None
            and (principal_id is None or connection.principal_id == principal_id)
            else None
        )
        return {
            "provider_id": self.contract.provider_id,
            "environment": self.contract.environment,
            "connection_mode": "oauth2_pkce_ephemeral",
            "connected": visible_connection is not None,
            "pending_authorization": pending,
            "demo_company_confirmed": visible_connection is not None,
            "expires_at": _iso(visible_connection.expires_at) if visible_connection else None,
            "manual_secret_copy_required": False,
            "refresh_token_persisted": False,
        }

    def connection_operator(self) -> tuple[str, str, str]:
        connection = self._connection_snapshot()
        return (
            connection.principal_id,
            connection.principal_name,
            connection.principal_role,
        )

    def disconnect(self, principal_id: str) -> bool:
        with self._lock:
            connection = self._connection
            if connection is None:
                return False
            if connection.principal_id != principal_id:
                raise XeroConnectionError("XERO_CONNECTION_OWNER_MISMATCH")
            self._connection = None
        return True

    def _connection_snapshot(self, principal_id: str | None = None) -> _ActiveConnection:
        now = self._clock().astimezone(UTC)
        with self._lock:
            self._remove_expired(now)
            connection = self._connection
        if connection is None:
            raise XeroConnectionError("XERO_CONNECTION_REQUIRED")
        if principal_id is not None and connection.principal_id != principal_id:
            raise XeroConnectionError("XERO_CONNECTION_OWNER_MISMATCH")
        return connection

    def _remove_expired(self, now: datetime) -> None:
        self._pending = {
            key: value for key, value in self._pending.items() if value.expires_at > now
        }
        if self._connection is not None and self._connection.expires_at <= now:
            self._connection = None

    @staticmethod
    def _retry_after(response: httpx.Response) -> int | None:
        raw = response.headers.get("retry-after")
        if raw is None or not raw.isdigit():
            return None
        return min(int(raw), 86_400)

    @staticmethod
    def _operation_reference(response: httpx.Response) -> str | None:
        value = response.headers.get("xero-correlation-id") or response.headers.get(
            "x-request-id"
        )
        if value is None or not value or len(value) > _MAX_OPERATION_REFERENCE_LENGTH:
            return None
        return value

    @staticmethod
    def _project_invoice(value: object, requested_id: str) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        provider_ids = {str(value.get("InvoiceID", "")), str(value.get("InvoiceNumber", ""))}
        if requested_id not in provider_ids:
            return None
        amount = value.get("Total")
        currency = value.get("CurrencyCode")
        status = value.get("Status")
        if (
            not isinstance(amount, (int, float))
            or isinstance(amount, bool)
            or (isinstance(amount, float) and not math.isfinite(amount))
            or not isinstance(currency, str)
            or not re.fullmatch(r"[A-Z]{3}", currency)
            or not isinstance(status, str)
            or not status
            or len(status) > 255
        ):
            return None
        return {
            "invoice_id": requested_id,
            "amount": amount,
            "currency": currency,
            "status": status,
        }

    def observe_invoice(self, invoice_id: str) -> InvoiceObservation:
        if not invoice_id or len(invoice_id) > 255:
            raise ValueError("invoice_id is empty or exceeds its safe bound")
        common = {
            "provider_id": self.contract.provider_id,
            "environment": self.contract.environment,
            "adapter_version": self.contract.adapter_version,
            "entity_reference": invoice_id,
            "observed_at": self._clock().astimezone(UTC),
        }
        try:
            connection = self._connection_snapshot()
        except XeroConnectionError as exc:
            return InvoiceObservation(
                state=ObservationState.AUTHENTICATION_FAILED,
                error_code=exc.code,
                **common,
            )
        headers = {
            "Authorization": f"Bearer {connection.access_token}",
            "Accept": "application/json",
            "xero-tenant-id": connection.tenant_id,
        }
        try:
            response = httpx.get(
                f"{self.base_url}/Invoices/{quote(invoice_id, safe='')}",
                headers=headers,
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            return InvoiceObservation(
                state=ObservationState.TEMPORARILY_UNAVAILABLE,
                error_code=type(exc).__name__,
                **common,
            )
        except httpx.HTTPError as exc:
            return InvoiceObservation(
                state=ObservationState.PERMANENT_PROVIDER_ERROR,
                error_code=type(exc).__name__,
                **common,
            )

        operation_reference = self._operation_reference(response)
        if response.status_code in {401, 403}:
            return InvoiceObservation(
                state=ObservationState.AUTHENTICATION_FAILED,
                operation_reference=operation_reference,
                **common,
            )
        if response.status_code == 404:
            return InvoiceObservation(
                state=ObservationState.AVAILABLE_ABSENT,
                operation_reference=operation_reference,
                **common,
            )
        if response.status_code == 429:
            return InvoiceObservation(
                state=ObservationState.RATE_LIMITED,
                retry_after_seconds=self._retry_after(response),
                operation_reference=operation_reference,
                **common,
            )
        if response.status_code >= 500:
            return InvoiceObservation(
                state=ObservationState.TEMPORARILY_UNAVAILABLE,
                operation_reference=operation_reference,
                **common,
            )
        if response.status_code != 200:
            return InvoiceObservation(
                state=ObservationState.PERMANENT_PROVIDER_ERROR,
                operation_reference=operation_reference,
                **common,
            )

        try:
            body = response.json()
        except ValueError:
            return InvoiceObservation(
                state=ObservationState.MALFORMED_RESPONSE,
                operation_reference=operation_reference,
                **common,
            )
        raw_records = body.get("Invoices") if isinstance(body, dict) else None
        if not isinstance(raw_records, list):
            return InvoiceObservation(
                state=ObservationState.MALFORMED_RESPONSE,
                operation_reference=operation_reference,
                **common,
            )
        records = tuple(
            projected
            for value in raw_records
            if (projected := self._project_invoice(value, invoice_id)) is not None
        )
        if len(records) != len(raw_records):
            return InvoiceObservation(
                state=ObservationState.MALFORMED_RESPONSE,
                operation_reference=operation_reference,
                **common,
            )
        state = (
            ObservationState.AVAILABLE_ABSENT
            if not records
            else ObservationState.AVAILABLE_PRESENT
            if len(records) == 1
            else ObservationState.AVAILABLE_CONFLICT
        )
        return InvoiceObservation(
            state=state,
            records=records,
            operation_reference=operation_reference,
            **common,
        )

    def qualify_invoice(
        self,
        *,
        principal_id: str,
        principal_name: str,
        principal_role: str,
        invoice_id: str,
        expected_exists: bool,
        expected_amount: Decimal,
        currency: str,
        confirmations: dict[str, bool],
    ) -> dict[str, Any]:
        connection = self._connection_snapshot(principal_id)
        if (
            connection.principal_name != principal_name
            or connection.principal_role != principal_role
        ):
            raise XeroConnectionError("XERO_CONNECTION_OPERATOR_CHANGED")
        if set(confirmations) != {
            "provider_identity_confirmed",
            "entity_confirmed",
            "evidence_bounded",
            "no_mutation_confirmed",
        } or not all(confirmations.values()):
            raise XeroConnectionError("XERO_OPERATOR_CONFIRMATIONS_REQUIRED")

        started_at = self._clock().astimezone(UTC)
        observation = self.observe_invoice(invoice_id)
        observation_evidence = observation.to_evidence()
        available = observation.available
        actual_record = observation.records[0] if len(observation.records) == 1 else None
        invariant_passed = (
            available
            and (
                (not expected_exists and observation.state is ObservationState.AVAILABLE_ABSENT)
                or (
                    expected_exists
                    and observation.state is ObservationState.AVAILABLE_PRESENT
                    and actual_record is not None
                    and Decimal(str(actual_record["amount"])) == expected_amount
                    and actual_record["currency"] == currency
                )
            )
        )
        invariant_result = (
            "PASSED" if invariant_passed else "VIOLATED" if available else "ERROR"
        )
        completed_at = self._clock().astimezone(UTC)
        evidence = [
            f"provider_observation_sha256:{observation_evidence['content_digest']}",
            "xero_demo_company_confirmed:true",
            "provider_mutation_count:0",
            "manual_secret_copy_required:false",
        ]
        if observation.operation_reference:
            evidence.append(f"provider_operation_reference:{observation.operation_reference}")
        return {
            "schema_version": "1.0",
            "result": "PASS" if available else "BLOCKED_EXTERNAL",
            "session_id": str(uuid4()),
            "started_at": _iso(started_at),
            "completed_at": _iso(completed_at),
            "provider": {
                "provider_id": self.contract.provider_id,
                "environment": self.contract.environment,
                "adapter_version": self.contract.adapter_version,
                "contract_version": self.contract.contract_version,
                "contract_sha256": self.contract.digest,
                "evidence_classification": (
                    "LIVE_SANDBOX_OBSERVED" if available else None
                ),
            },
            "safe_entity": {
                "entity_type": "invoice",
                "entity_id": invoice_id,
                "expected_exists": expected_exists,
                "expected_amount": float(expected_amount),
                "currency": currency,
                "contains_customer_data": False,
            },
            "observation": {
                "classification": observation.state.value,
                "content_digest": observation_evidence["content_digest"],
                "records": list(observation.records),
                "invariant_id": "external_invoice_exists",
                "invariant_result": invariant_result,
                "incident_id": None,
            },
            "operator_review": {
                "operator_name": principal_name,
                "operator_role": principal_role,
                "reviewed_at": _iso(completed_at),
                "decision": "REVIEWED",
                **confirmations,
            },
            "safety": {
                "permitted_methods": ["GET"],
                "provider_mutation_count": 0,
                "recovery_writes_enabled": False,
                "raw_secret_persisted": False,
                "raw_customer_payload_persisted": False,
                "manual_secret_copy_required": False,
                "refresh_token_persisted": False,
            },
            "evidence": evidence,
        }

    def write_invoice(
        self, invoice: dict[str, Any], idempotency_key: str
    ) -> RecoveryWriteOutcome:
        del invoice, idempotency_key
        return RecoveryWriteOutcome(
            state=WriteOutcomeState.REJECTED,
            provider_id=self.contract.provider_id,
            environment=self.contract.environment,
            adapter_version=self.contract.adapter_version,
            observed_at=self._clock().astimezone(UTC),
            safe_result={"accepted": False, "status": "read_only_adapter"},
            error_code="READ_ONLY_ADAPTER",
        )
