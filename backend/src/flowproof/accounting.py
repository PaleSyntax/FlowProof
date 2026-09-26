from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx

from flowproof.clock import monotonic_utc_now

SAFE_RECORD_FIELDS = frozenset({"invoice_id", "id", "amount", "currency", "status"})
SAFE_WRITE_RESULT_FIELDS = frozenset({"accepted", "duplicate", "status", "status_code"})
MAX_PROVIDER_ID_LENGTH = 64
MAX_ADAPTER_VERSION_LENGTH = 64
MAX_ENTITY_REFERENCE_LENGTH = 255
MAX_OPERATION_REFERENCE_LENGTH = 255
MAX_ERROR_CODE_LENGTH = 64
MAX_SAFE_STRING_LENGTH = 255
EVIDENCE_CLASSIFICATIONS = frozenset(
    {
        "DOCUMENTED",
        "CONTRACT_TESTED",
        "LIVE_SANDBOX_OBSERVED",
        "UNVERIFIED",
        "TEST_FIXTURE_ONLY",
    }
)
CREDENTIAL_REFERENCE = re.compile(
    r"^(?:env|file|docker-secret|vault|aws-secrets-manager|gcp-secret-manager|"
    r"azure-key-vault):[A-Za-z0-9][A-Za-z0-9._/@:-]{0,254}$"
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _utc_now() -> datetime:
    return monotonic_utc_now()


def _bounded_text(value: str | None, maximum: int, field_name: str) -> None:
    if value is not None and (not value or len(value) > maximum):
        raise ValueError(f"{field_name} is empty or exceeds its safe bound")


def _safe_scalar(value: object) -> bool:
    if isinstance(value, str):
        return len(value) <= MAX_SAFE_STRING_LENGTH
    if isinstance(value, float):
        return math.isfinite(value)
    return isinstance(value, (int, bool)) or value is None


class ObservationState(StrEnum):
    AVAILABLE_PRESENT = "AVAILABLE_PRESENT"
    AVAILABLE_ABSENT = "AVAILABLE_ABSENT"
    AVAILABLE_CONFLICT = "AVAILABLE_CONFLICT"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    PERMANENT_PROVIDER_ERROR = "PERMANENT_PROVIDER_ERROR"


class WriteOutcomeState(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    PRE_ACCEPTANCE_FAILURE = "PRE_ACCEPTANCE_FAILURE"
    POST_ACCEPTANCE_OUTCOME_UNKNOWN = "POST_ACCEPTANCE_OUTCOME_UNKNOWN"
    RATE_LIMITED = "RATE_LIMITED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"


@dataclass(frozen=True, slots=True)
class ProviderContract:
    provider_id: str
    adapter_version: str
    environment: str
    contract_version: str
    sandbox_only: bool
    authoritative_read: dict[str, Any]
    authentication: dict[str, Any]
    rate_limits: dict[str, Any]
    idempotency: dict[str, Any]
    duplicate_guarantees: dict[str, Any]
    write_acceptance: dict[str, Any]
    read_after_write: dict[str, Any]
    maximum_safe_write_attempts: int
    evidence_classification: dict[str, str]
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.provider_id or not self.adapter_version or not self.contract_version:
            raise ValueError("provider contract identity is incomplete")
        if self.environment not in {"sandbox", "partner_test"}:
            raise ValueError("provider environment is not authorized for the v0.6.0 gate")
        if not self.sandbox_only:
            raise ValueError("the v0.6.0 provider contract must be sandbox-only")
        if not 1 <= self.maximum_safe_write_attempts <= 3:
            raise ValueError("maximum_safe_write_attempts must be between one and three")
        if set(self.authentication) != {"mode", "credential_reference"}:
            raise ValueError("authentication must contain only mode and credential_reference")
        if not all(
            isinstance(value, str) and value
            for value in (self.authentication["mode"], self.authentication["credential_reference"])
        ):
            raise ValueError("authentication metadata must be non-empty references")
        mode = self.authentication["mode"]
        credential_reference = self.authentication["credential_reference"]
        if mode.startswith("none") or mode.startswith("oauth2-pkce"):
            if credential_reference != "not-applicable":
                raise ValueError(
                    "no-auth and PKCE contracts must use the not-applicable reference"
                )
        elif not CREDENTIAL_REFERENCE.fullmatch(credential_reference):
            raise ValueError("authentication credentials must use an indirect reference")
        overall = self.evidence_classification.get("overall")
        if overall not in EVIDENCE_CLASSIFICATIONS or any(
            value not in EVIDENCE_CLASSIFICATIONS for value in self.evidence_classification.values()
        ):
            raise ValueError("provider evidence classification is invalid")
        object.__setattr__(self, "digest", _digest(self.to_manifest(include_digest=False)))

    @classmethod
    def load(cls, path: Path) -> ProviderContract:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("provider contract must be a JSON object")
        allowed = {
            "provider_id",
            "adapter_version",
            "environment",
            "contract_version",
            "sandbox_only",
            "authoritative_read",
            "authentication",
            "rate_limits",
            "idempotency",
            "duplicate_guarantees",
            "write_acceptance",
            "read_after_write",
            "maximum_safe_write_attempts",
            "evidence_classification",
            "sha256",
        }
        if set(raw) - allowed:
            raise ValueError("provider contract contains unknown fields")
        expected = raw.pop("sha256", None)
        if not isinstance(expected, str):
            raise ValueError("provider contract must declare its SHA-256 digest")
        contract = cls(**raw)
        if expected != contract.digest:
            raise ValueError("provider contract digest does not match its content")
        return contract

    def to_manifest(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = {
            "provider_id": self.provider_id,
            "adapter_version": self.adapter_version,
            "environment": self.environment,
            "contract_version": self.contract_version,
            "sandbox_only": self.sandbox_only,
            "authoritative_read": self.authoritative_read,
            "authentication": self.authentication,
            "rate_limits": self.rate_limits,
            "idempotency": self.idempotency,
            "duplicate_guarantees": self.duplicate_guarantees,
            "write_acceptance": self.write_acceptance,
            "read_after_write": self.read_after_write,
            "maximum_safe_write_attempts": self.maximum_safe_write_attempts,
            "evidence_classification": self.evidence_classification,
        }
        if include_digest:
            value["sha256"] = self.digest
        return value


@dataclass(frozen=True, slots=True)
class InvoiceObservation:
    state: ObservationState
    provider_id: str
    environment: str
    adapter_version: str
    entity_reference: str
    observed_at: datetime
    records: tuple[dict[str, Any], ...] = ()
    operation_reference: str | None = None
    retry_after_seconds: int | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("observation timestamp must be timezone-aware")
        _bounded_text(self.provider_id, MAX_PROVIDER_ID_LENGTH, "provider_id")
        _bounded_text(self.adapter_version, MAX_ADAPTER_VERSION_LENGTH, "adapter_version")
        _bounded_text(self.entity_reference, MAX_ENTITY_REFERENCE_LENGTH, "entity_reference")
        _bounded_text(
            self.operation_reference,
            MAX_OPERATION_REFERENCE_LENGTH,
            "operation_reference",
        )
        _bounded_text(self.error_code, MAX_ERROR_CODE_LENGTH, "error_code")
        if self.retry_after_seconds is not None and not 0 <= self.retry_after_seconds <= 86_400:
            raise ValueError("retry_after_seconds is outside its safe bound")
        expected_count = {
            ObservationState.AVAILABLE_ABSENT: 0,
            ObservationState.AVAILABLE_PRESENT: 1,
        }.get(self.state)
        if expected_count is not None and len(self.records) != expected_count:
            raise ValueError("observation record count contradicts its classification")
        if self.state == ObservationState.AVAILABLE_CONFLICT and len(self.records) < 2:
            raise ValueError("conflict observation requires multiple records")
        if not self.available and self.records:
            raise ValueError("unavailable observations cannot contain records")
        for record in self.records:
            if (
                not {"invoice_id", "id"}.intersection(record)
                or set(record) - SAFE_RECORD_FIELDS
                or any(not _safe_scalar(value) for value in record.values())
            ):
                raise ValueError("observation contains an unsafe provider projection")

    @property
    def available(self) -> bool:
        return self.state in {
            ObservationState.AVAILABLE_PRESENT,
            ObservationState.AVAILABLE_ABSENT,
            ObservationState.AVAILABLE_CONFLICT,
        }

    @property
    def exists(self) -> bool:
        return self.state in {
            ObservationState.AVAILABLE_PRESENT,
            ObservationState.AVAILABLE_CONFLICT,
        }

    def to_evidence(self) -> dict[str, Any]:
        projection = {
            "classification": self.state.value,
            "provider_id": self.provider_id,
            "environment": self.environment,
            "adapter_version": self.adapter_version,
            "entity_reference": self.entity_reference,
            "observed_at": self.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "presence_count": len(self.records),
            "records": list(self.records),
            "operation_reference": self.operation_reference,
            "retry_after_seconds": self.retry_after_seconds,
            "error_code": self.error_code,
        }
        projection["content_digest"] = _digest(projection)
        return projection


@dataclass(frozen=True, slots=True)
class RecoveryWriteOutcome:
    state: WriteOutcomeState
    provider_id: str
    environment: str
    adapter_version: str
    observed_at: datetime
    operation_reference: str | None = None
    retry_after_seconds: int | None = None
    safe_result: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("write outcome timestamp must be timezone-aware")
        _bounded_text(self.provider_id, MAX_PROVIDER_ID_LENGTH, "provider_id")
        _bounded_text(self.adapter_version, MAX_ADAPTER_VERSION_LENGTH, "adapter_version")
        _bounded_text(
            self.operation_reference,
            MAX_OPERATION_REFERENCE_LENGTH,
            "operation_reference",
        )
        _bounded_text(self.error_code, MAX_ERROR_CODE_LENGTH, "error_code")
        if self.retry_after_seconds is not None and not 0 <= self.retry_after_seconds <= 86_400:
            raise ValueError("retry_after_seconds is outside its safe bound")
        if set(self.safe_result) - SAFE_WRITE_RESULT_FIELDS or any(
            not _safe_scalar(value) for value in self.safe_result.values()
        ):
            raise ValueError("write outcome contains an unsafe provider projection")

    def to_evidence(self) -> dict[str, Any]:
        projection = {
            "classification": self.state.value,
            "provider_id": self.provider_id,
            "environment": self.environment,
            "adapter_version": self.adapter_version,
            "observed_at": self.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "operation_reference": self.operation_reference,
            "retry_after_seconds": self.retry_after_seconds,
            "safe_result": self.safe_result,
            "error_code": self.error_code,
        }
        projection["content_digest"] = _digest(projection)
        return projection


@runtime_checkable
class AuthoritativeInvoiceReader(Protocol):
    contract: ProviderContract

    def observe_invoice(self, invoice_id: str) -> InvoiceObservation: ...


@runtime_checkable
class RecoveryInvoiceWriter(Protocol):
    contract: ProviderContract

    def write_invoice(
        self, invoice: dict[str, Any], idempotency_key: str
    ) -> RecoveryWriteOutcome: ...


@runtime_checkable
class MockChaosControl(Protocol):
    def set_chaos_mode(self, mode: str) -> dict[str, Any]: ...


class AccountingClient(AuthoritativeInvoiceReader, RecoveryInvoiceWriter, Protocol):
    """Composite used by the current invoice service; mock chaos is deliberately excluded."""


class HttpAccountingClient:
    """Server-configured bounded adapter for the existing accounting HTTP shape.

    The endpoint is never accepted from an API/browser request. A real provider may use
    this adapter only after an owner-supplied contract and sandbox acceptance evidence.
    """

    def __init__(
        self,
        base_url: str,
        contract: ProviderContract,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.contract = contract
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _retry_after(response: httpx.Response) -> int | None:
        raw = response.headers.get("retry-after")
        if raw is None or not raw.isdigit():
            return None
        return min(int(raw), 86_400)

    @staticmethod
    def _safe_record(value: object) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        projected = {str(key): value[key] for key in sorted(SAFE_RECORD_FIELDS.intersection(value))}
        if not {"invoice_id", "id"}.intersection(projected) or any(
            not _safe_scalar(item) for item in projected.values()
        ):
            return None
        return projected

    def observe_invoice(self, invoice_id: str) -> InvoiceObservation:
        common = {
            "provider_id": self.contract.provider_id,
            "environment": self.contract.environment,
            "adapter_version": self.contract.adapter_version,
            "entity_reference": invoice_id,
            "observed_at": _utc_now(),
        }
        try:
            response = httpx.get(
                f"{self.base_url}/invoices/{invoice_id}", timeout=self.timeout_seconds
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
        if response.status_code in {401, 403}:
            return InvoiceObservation(state=ObservationState.AUTHENTICATION_FAILED, **common)
        if response.status_code == 404:
            return InvoiceObservation(state=ObservationState.AVAILABLE_ABSENT, **common)
        if response.status_code == 429:
            return InvoiceObservation(
                state=ObservationState.RATE_LIMITED,
                retry_after_seconds=self._retry_after(response),
                **common,
            )
        if response.status_code >= 500:
            return InvoiceObservation(state=ObservationState.TEMPORARILY_UNAVAILABLE, **common)
        if response.status_code != 200:
            return InvoiceObservation(state=ObservationState.PERMANENT_PROVIDER_ERROR, **common)
        try:
            body = response.json()
        except ValueError:
            return InvoiceObservation(state=ObservationState.MALFORMED_RESPONSE, **common)
        if not isinstance(body, dict):
            return InvoiceObservation(state=ObservationState.MALFORMED_RESPONSE, **common)
        raw_records = body.get("records", [body])
        if not isinstance(raw_records, list):
            return InvoiceObservation(state=ObservationState.MALFORMED_RESPONSE, **common)
        records = tuple(
            record for item in raw_records if (record := self._safe_record(item)) is not None
        )
        if len(records) != len(raw_records):
            return InvoiceObservation(state=ObservationState.MALFORMED_RESPONSE, **common)
        if any(
            str(record.get("invoice_id", record.get("id"))) != str(invoice_id)
            for record in records
        ):
            return InvoiceObservation(state=ObservationState.MALFORMED_RESPONSE, **common)
        state = (
            ObservationState.AVAILABLE_ABSENT
            if not records
            else ObservationState.AVAILABLE_PRESENT
            if len(records) == 1
            else ObservationState.AVAILABLE_CONFLICT
        )
        return InvoiceObservation(state=state, records=records, **common)

    def write_invoice(self, invoice: dict[str, Any], idempotency_key: str) -> RecoveryWriteOutcome:
        common = {
            "provider_id": self.contract.provider_id,
            "environment": self.contract.environment,
            "adapter_version": self.contract.adapter_version,
            "observed_at": _utc_now(),
        }
        try:
            response = httpx.post(
                f"{self.base_url}/invoices",
                json={key: invoice.get(key) for key in ("invoice_id", "amount", "currency")},
                headers={"Idempotency-Key": idempotency_key},
                timeout=self.timeout_seconds,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return RecoveryWriteOutcome(
                state=WriteOutcomeState.PRE_ACCEPTANCE_FAILURE,
                error_code=type(exc).__name__,
                **common,
            )
        except (httpx.ReadTimeout, httpx.WriteError, httpx.ReadError) as exc:
            return RecoveryWriteOutcome(
                state=WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN,
                error_code=type(exc).__name__,
                **common,
            )
        except httpx.HTTPError as exc:
            return RecoveryWriteOutcome(
                state=WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN,
                error_code=type(exc).__name__,
                **common,
            )
        if response.status_code in {401, 403}:
            return RecoveryWriteOutcome(state=WriteOutcomeState.AUTHENTICATION_FAILED, **common)
        if response.status_code == 429:
            return RecoveryWriteOutcome(
                state=WriteOutcomeState.RATE_LIMITED,
                retry_after_seconds=self._retry_after(response),
                **common,
            )
        if response.status_code >= 500:
            return RecoveryWriteOutcome(
                state=WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN, **common
            )
        if response.status_code not in {200, 201, 202}:
            return RecoveryWriteOutcome(state=WriteOutcomeState.REJECTED, **common)
        try:
            body = response.json()
        except ValueError:
            return RecoveryWriteOutcome(state=WriteOutcomeState.MALFORMED_RESPONSE, **common)
        if not isinstance(body, dict):
            return RecoveryWriteOutcome(state=WriteOutcomeState.MALFORMED_RESPONSE, **common)
        reference = response.headers.get("x-request-id")
        if not reference:
            candidate = body.get("operation_id") or body.get("id")
            reference = str(candidate)[:255] if candidate is not None else None
        else:
            reference = reference[:MAX_OPERATION_REFERENCE_LENGTH]
        known_result_values = {
            key: body[key] for key in ("accepted", "duplicate", "status") if key in body
        }
        if any(not _safe_scalar(value) for value in known_result_values.values()):
            return RecoveryWriteOutcome(state=WriteOutcomeState.MALFORMED_RESPONSE, **common)
        safe_result = {
            key: value for key, value in known_result_values.items() if value is not None
        }
        return RecoveryWriteOutcome(
            state=WriteOutcomeState.ACCEPTED,
            operation_reference=reference,
            safe_result=safe_result,
            **common,
        )

    # Compatibility wrappers keep the current API/tests operational while the service
    # moves to the typed boundary. New adapters implement observe_invoice/write_invoice.
    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        observation = self.observe_invoice(invoice_id)
        return {
            **observation.to_evidence(),
            "available": observation.available,
            "exists": observation.exists,
        }

    def register_invoice(self, invoice: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        return self.write_invoice(invoice, idempotency_key).to_evidence()


class HttpMockAccountingClient(HttpAccountingClient):
    """Local demo composition that exposes mock-only chaos outside the provider contract."""

    def set_chaos_mode(self, mode: str) -> dict[str, Any]:
        response = httpx.post(
            f"{self.base_url}/chaos/mode", json={"mode": mode}, timeout=self.timeout_seconds
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("mock chaos response must be an object")
        return {
            key: value
            for key, value in body.items()
            if key in {"mode", "previous_mode"} and isinstance(value, str)
        }


def coerce_observation(client: object, invoice_id: str) -> InvoiceObservation:
    if isinstance(client, AuthoritativeInvoiceReader):
        return client.observe_invoice(invoice_id)
    legacy = client.get_invoice(invoice_id)
    records = tuple(record for record in legacy.get("records", []) if isinstance(record, dict))
    state = (
        ObservationState.TEMPORARILY_UNAVAILABLE
        if not legacy.get("available")
        else ObservationState.AVAILABLE_ABSENT
        if not legacy.get("exists")
        else ObservationState.AVAILABLE_PRESENT
        if len(records) == 1
        else ObservationState.AVAILABLE_CONFLICT
    )
    contract = client_contract(client)
    return InvoiceObservation(
        state=state,
        provider_id=contract.provider_id,
        environment=contract.environment,
        adapter_version=contract.adapter_version,
        entity_reference=invoice_id,
        observed_at=_utc_now(),
        records=records,
        error_code=str(legacy.get("error"))[:64] if legacy.get("error") else None,
    )


def coerce_write_outcome(
    client: object, invoice: dict[str, Any], idempotency_key: str
) -> RecoveryWriteOutcome:
    if isinstance(client, RecoveryInvoiceWriter):
        return client.write_invoice(invoice, idempotency_key)
    legacy = client.register_invoice(invoice, idempotency_key)
    status = int(legacy.get("status_code", 0))
    state = (
        WriteOutcomeState.ACCEPTED
        if status in {200, 201, 202}
        else WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN
        if status == 0
        else WriteOutcomeState.REJECTED
    )
    contract = client_contract(client)
    return RecoveryWriteOutcome(
        state=state,
        provider_id=contract.provider_id,
        environment=contract.environment,
        adapter_version=contract.adapter_version,
        observed_at=_utc_now(),
        safe_result={"status_code": status},
        error_code=str(legacy.get("error"))[:64] if legacy.get("error") else None,
    )


def client_contract(client: object) -> ProviderContract:
    contract = getattr(client, "contract", None)
    if isinstance(contract, ProviderContract):
        return contract
    # Legacy deterministic fakes are test/demo composition only and never real-provider proof.
    return ProviderContract(
        provider_id="mock-accounting",
        adapter_version="legacy-test-fixture",
        environment="sandbox",
        contract_version="fixture-1",
        sandbox_only=True,
        authoritative_read={"not_found": "AVAILABLE_ABSENT"},
        authentication={
            "mode": "none-test-fixture",
            "credential_reference": "not-applicable",
        },
        rate_limits={"classification": "UNVERIFIED"},
        idempotency={"support": "CONTRACT_TESTED", "scope": "invoice-create"},
        duplicate_guarantees={"classification": "CONTRACT_TESTED"},
        write_acceptance={"classification": "CONTRACT_TESTED"},
        read_after_write={"consistency": "strong-test-fixture"},
        maximum_safe_write_attempts=1,
        evidence_classification={"overall": "TEST_FIXTURE_ONLY"},
    )
