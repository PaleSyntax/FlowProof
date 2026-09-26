from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import func, select

from flowproof.accounting import ObservationState, ProviderContract, WriteOutcomeState
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.identity import IdentityService
from flowproof.main import create_app
from flowproof.models import Base, SecurityAuditEvent
from flowproof.provider_factory import PROVIDER_ADAPTER_REGISTRY, create_provider_adapter
from flowproof.xero_demo import XeroConnectionError, XeroDemoAccountingClient

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "specs" / "providers" / "xero-demo" / "contract.json"
CONTRACT_SCHEMA_PATH = ROOT / "specs" / "providers" / "provider-contract.schema.json"
ACCESS_SCHEMA_PATH = (
    ROOT / "quality" / "productization" / "provider-access-request.schema.json"
)
ACCESS_TEMPLATE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "provider-access-request.xero-demo.template.json"
)
LIFECYCLE_SCHEMA_PATH = (
    ROOT / "quality" / "productization" / "observe-only-provider-lifecycle.schema.json"
)
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
PEPPER = "xero-pkce-test-pepper-with-at-least-thirty-two-characters"
REDIRECT_URI = "http://localhost:8000/api/v1/provider-connections/xero/callback"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _contract() -> ProviderContract:
    return ProviderContract.load(CONTRACT_PATH)


def _client() -> XeroDemoAccountingClient:
    return XeroDemoAccountingClient("https://api.xero.com/api.xro/2.0", _contract())


def _start(client: XeroDemoAccountingClient) -> tuple[dict[str, Any], str]:
    result = client.start_authorization(
        principal_id="operator-id",
        principal_name="Independent operator",
        principal_role="operator",
        client_id="PUBLIC-CLIENT-ID-123",
        redirect_uri=REDIRECT_URI,
    )
    state = parse_qs(urlsplit(result["authorization_url"]).query)["state"][0]
    return result, state


def _install_successful_oauth(
    monkeypatch: pytest.MonkeyPatch,
    *,
    invoice_response: httpx.Response | None = None,
    demo: bool = True,
) -> dict[str, Any]:
    captured: dict[str, Any] = {"gets": []}

    def token(url: str, **kwargs: Any) -> httpx.Response:
        captured["token_url"] = url
        captured["token_kwargs"] = kwargs
        return httpx.Response(
            200,
            json={
                "access_token": "a" * 64,
                "expires_in": 1800,
                "token_type": "Bearer",
            },
            request=httpx.Request("POST", url),
        )

    def get(url: str, **kwargs: Any) -> httpx.Response:
        captured["gets"].append((url, kwargs))
        if url == "https://api.xero.com/connections":
            return httpx.Response(
                200,
                json=[{"tenantId": "tenant-demo", "tenantType": "ORGANISATION"}],
                request=httpx.Request("GET", url),
            )
        if url.endswith("/Organisation"):
            return httpx.Response(
                200,
                json={
                    "Organisations": [
                        {
                            "IsDemoCompany": demo,
                            "OrganisationStatus": "ACTIVE",
                            "TaxNumber": "must-not-persist",
                        }
                    ]
                },
                request=httpx.Request("GET", url),
            )
        if invoice_response is not None and "/Invoices/" in url:
            return invoice_response
        raise AssertionError(f"unexpected Xero GET: {url}")

    monkeypatch.setattr(httpx, "post", token)
    monkeypatch.setattr(httpx, "get", get)
    return captured


def test_xero_contract_and_owner_access_template_are_valid_pkce_contracts() -> None:
    contract_raw = _load(CONTRACT_PATH)
    contract_schema = _load(CONTRACT_SCHEMA_PATH)
    Draft202012Validator(contract_schema).validate(contract_raw)
    contract = _contract()
    assert contract.digest == contract_raw["sha256"]
    assert contract.authentication == {
        "mode": "oauth2-pkce-user-consent",
        "credential_reference": "not-applicable",
    }

    access_schema = _load(ACCESS_SCHEMA_PATH)
    access_template = _load(ACCESS_TEMPLATE_PATH)
    Draft202012Validator(
        access_schema, format_checker=FormatChecker()
    ).validate(access_template)
    assert access_template["status"] == "OWNER_AUTHORIZED_PROVIDER_ACCESS_REQUIRED"
    assert access_template["provider"]["credential_reference"] == "not-applicable"
    assert access_template["authorization"]["mutations_allowed"] is False
    assert access_template["operator"] == {"name": None, "role": None}


def test_pkce_start_uses_exact_read_only_scopes_and_no_secret() -> None:
    result, _ = _start(_client())
    parsed = urlsplit(result["authorization_url"])
    query = parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        "https://login.xero.com/identity/connect/authorize"
    )
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == [REDIRECT_URI]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == [
        "openid profile email accounting.invoices.read accounting.settings.read"
    ]
    assert "offline_access" not in query["scope"][0]
    assert "client_secret" not in query
    assert result["manual_secret_copy_required"] is False


def test_pkce_callback_is_one_time_and_confirms_demo_company(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _install_successful_oauth(monkeypatch)
    client = _client()
    _, state = _start(client)
    status = client.complete_authorization(state=state, code="one-time-code")
    assert status == {
        "provider_id": "xero-demo",
        "environment": "sandbox",
        "connection_mode": "oauth2_pkce_ephemeral",
        "connected": True,
        "pending_authorization": False,
        "demo_company_confirmed": True,
        "expires_at": status["expires_at"],
        "manual_secret_copy_required": False,
        "refresh_token_persisted": False,
    }
    token_data = captured["token_kwargs"]["data"]
    assert set(token_data) == {
        "grant_type",
        "client_id",
        "code",
        "redirect_uri",
        "code_verifier",
    }
    assert "client_secret" not in token_data
    assert captured["gets"][1][1]["headers"]["xero-tenant-id"] == "tenant-demo"
    with pytest.raises(XeroConnectionError, match="STATE_INVALID_OR_EXPIRED"):
        client.complete_authorization(state=state, code="replayed-code")


def test_non_demo_tenant_fails_closed_without_retaining_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_successful_oauth(monkeypatch, demo=False)
    client = _client()
    _, state = _start(client)
    with pytest.raises(XeroConnectionError, match="EXACTLY_ONE_DEMO"):
        client.complete_authorization(state=state, code="one-time-code")
    assert client.public_status()["connected"] is False


def test_xero_adapter_normalizes_invoice_without_customer_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoice_url = "https://api.xero.com/api.xro/2.0/Invoices/INV%2FSAFE%201"
    invoice_response = httpx.Response(
        200,
        json={
            "Invoices": [
                {
                    "InvoiceID": "a-provider-uuid",
                    "InvoiceNumber": "INV/SAFE 1",
                    "Total": 42.5,
                    "CurrencyCode": "USD",
                    "Status": "AUTHORISED",
                    "Contact": {"Name": "must-not-enter-evidence"},
                }
            ]
        },
        headers={"xero-correlation-id": "corr-1"},
        request=httpx.Request("GET", invoice_url),
    )
    captured = _install_successful_oauth(
        monkeypatch, invoice_response=invoice_response
    )
    client = _client()
    _, state = _start(client)
    client.complete_authorization(state=state, code="one-time-code")
    observation = client.observe_invoice("INV/SAFE 1")

    assert observation.state == ObservationState.AVAILABLE_PRESENT
    assert observation.records == (
        {
            "invoice_id": "INV/SAFE 1",
            "amount": 42.5,
            "currency": "USD",
            "status": "AUTHORISED",
        },
    )
    invoice_get = captured["gets"][-1]
    assert invoice_get[0] == invoice_url
    assert invoice_get[1]["headers"]["xero-tenant-id"] == "tenant-demo"
    assert "must-not-enter-evidence" not in json.dumps(observation.to_evidence())


def test_qualification_emits_schema_valid_named_bounded_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoice_response = httpx.Response(
        200,
        json={
            "Invoices": [
                {
                    "InvoiceID": "provider-id",
                    "InvoiceNumber": "INV-QUAL-1",
                    "Total": 100.0,
                    "CurrencyCode": "USD",
                    "Status": "AUTHORISED",
                }
            ]
        },
        request=httpx.Request(
            "GET", "https://api.xero.com/api.xro/2.0/Invoices/INV-QUAL-1"
        ),
    )
    _install_successful_oauth(monkeypatch, invoice_response=invoice_response)
    client = _client()
    _, state = _start(client)
    client.complete_authorization(state=state, code="one-time-code")
    lifecycle = client.qualify_invoice(
        principal_id="operator-id",
        principal_name="Independent operator",
        principal_role="operator",
        invoice_id="INV-QUAL-1",
        expected_exists=True,
        expected_amount=Decimal("100.00"),
        currency="USD",
        confirmations={
            "provider_identity_confirmed": True,
            "entity_confirmed": True,
            "evidence_bounded": True,
            "no_mutation_confirmed": True,
        },
    )
    schema = _load(LIFECYCLE_SCHEMA_PATH)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(lifecycle)
    assert lifecycle["result"] == "PASS"
    assert lifecycle["observation"]["invariant_result"] == "PASSED"
    assert lifecycle["operator_review"]["operator_name"] == "Independent operator"
    assert lifecycle["safety"]["provider_mutation_count"] == 0
    assert lifecycle["safety"]["manual_secret_copy_required"] is False
    encoded = json.dumps(lifecycle)
    assert "a" * 64 not in encoded
    assert "must-not-persist" not in encoded


def test_xero_adapter_never_dispatches_a_provider_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> httpx.Response:
        del args, kwargs
        raise AssertionError("provider mutation was attempted")

    monkeypatch.setattr(httpx, "post", forbidden)
    adapter = _client()
    outcome = adapter.write_invoice(
        {"invoice_id": "INV-1", "amount": 10, "currency": "USD"}, "unused-key"
    )
    assert outcome.state == WriteOutcomeState.REJECTED
    assert outcome.error_code == "READ_ONLY_ADAPTER"
    assert outcome.safe_result == {"accepted": False, "status": "read_only_adapter"}
    assert PROVIDER_ADAPTER_REGISTRY["xero-demo"].owner_coordinates_required is True


class _PrimaryFixtureAccounting:
    def set_chaos_mode(self, mode: str) -> dict[str, str]:
        return {"mode": mode}

    def register_invoice(
        self, invoice: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        del invoice, idempotency_key
        return {"status_code": 200, "body": {"accepted": True}}

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        del invoice_id
        return {"available": True, "exists": False, "records": []}


def test_http_pkce_and_qualification_path_requires_human_csrf_and_audits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoice_response = httpx.Response(
        200,
        json={
            "Invoices": [
                {
                    "InvoiceID": "provider-id",
                    "InvoiceNumber": "INV-HTTP-1",
                    "Total": 75.0,
                    "CurrencyCode": "USD",
                    "Status": "AUTHORISED",
                }
            ]
        },
        request=httpx.Request(
            "GET", "https://api.xero.com/api.xro/2.0/Invoices/INV-HTTP-1"
        ),
    )
    _install_successful_oauth(monkeypatch, invoice_response=invoice_response)
    database_url = f"sqlite:///{tmp_path / 'xero-http.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as session:
        IdentityService(session, PEPPER).create_human(
            "xero-operator", "xero-operator-password-123", "operator"
        )
    settings = Settings(
        database_url=database_url,
        cors_origin="http://127.0.0.1:8080",
        mock_accounting_url="http://fixture",
        policy_path=POLICY_PATH,
        environment="development",
        token_pepper=PEPPER,
        xero_pkce_enabled=True,
        xero_provider_contract_path=CONTRACT_PATH,
        xero_redirect_uri=REDIRECT_URI,
    )
    app = create_app(settings, _PrimaryFixtureAccounting(), factory)
    with TestClient(app) as browser:
        login = browser.post(
            "/api/v1/auth/login",
            json={
                "name": "xero-operator",
                "password": "xero-operator-password-123",
            },
        )
        csrf = login.json()["csrf_token"]
        denied = browser.post(
            "/api/v1/provider-connections/xero/pkce/start",
            json={"client_id": "PUBLIC-CLIENT-ID-123"},
        )
        assert denied.status_code == 403, denied.text
        started = browser.post(
            "/api/v1/provider-connections/xero/pkce/start",
            headers={"X-CSRF-Token": csrf},
            json={"client_id": "PUBLIC-CLIENT-ID-123"},
        )
        assert started.status_code == 200
        state = parse_qs(urlsplit(started.json()["authorization_url"]).query)["state"][0]
        callback = browser.get(
            "/api/v1/provider-connections/xero/callback",
            params={"state": state, "code": "one-time-code"},
        )
        assert callback.status_code == 200
        assert "No token was copied" in callback.text
        status_response = browser.get("/api/v1/provider-connections/xero/status")
        assert status_response.json()["connected"] is True
        lifecycle = browser.post(
            "/api/v1/provider-connections/xero/qualify-invoice",
            headers={"X-CSRF-Token": csrf},
            json={
                "invoice_id": "INV-HTTP-1",
                "expected_exists": True,
                "expected_amount": 75.0,
                "currency": "USD",
                "provider_identity_confirmed": True,
                "entity_confirmed": True,
                "evidence_bounded": True,
                "no_mutation_confirmed": True,
            },
        )
        assert lifecycle.status_code == 200, lifecycle.text
        assert lifecycle.json()["observation"]["invariant_result"] == "PASSED"

    with factory() as session:
        actions = session.scalars(
            select(SecurityAuditEvent.action).where(
                SecurityAuditEvent.action.in_(
                    {
                        "xero_pkce_started",
                        "xero_pkce_connected",
                        "xero_observe_only_qualified",
                    }
                )
            )
        ).all()
        assert set(actions) == {
            "xero_pkce_started",
            "xero_pkce_connected",
            "xero_observe_only_qualified",
        }
        assert session.scalar(select(func.count(SecurityAuditEvent.id))) >= 3


def test_xero_adapter_factory_constructs_disconnected_pkce_client() -> None:
    adapter = create_provider_adapter(
        "https://api.xero.com/api.xro/2.0",
        _contract(),
        environment="local-appliance",
    )
    assert isinstance(adapter, XeroDemoAccountingClient)
    assert adapter.public_status()["connected"] is False
