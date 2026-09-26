from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator

from flowproof.accounting import (
    HttpAccountingClient,
    InvoiceObservation,
    ObservationState,
    ProviderContract,
    RecoveryWriteOutcome,
    WriteOutcomeState,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "specs" / "providers" / "mock-accounting" / "contract.json"
SCHEMA_PATH = ROOT / "specs" / "providers" / "provider-contract.schema.json"


def test_provider_contract_schema_and_declared_digest_are_deterministic(tmp_path: Path) -> None:
    raw = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(raw)
    authenticated_without_reference = {
        **raw,
        "authentication": {"mode": "bearer", "credential_reference": "not-applicable"},
    }
    assert any(
        error.validator == "pattern"
        for error in Draft202012Validator(schema).iter_errors(
            authenticated_without_reference
        )
    )
    no_auth_with_reference = {
        **raw,
        "authentication": {
            "mode": "none-test-fixture",
            "credential_reference": "env:FLOWPROOF_PROVIDER_TOKEN",
        },
    }
    assert any(
        error.validator == "const"
        for error in Draft202012Validator(schema).iter_errors(no_auth_with_reference)
    )
    contract = ProviderContract.load(CONTRACT_PATH)
    assert contract.digest == raw["sha256"]
    assert contract.to_manifest() == raw

    changed = {**raw, "adapter_version": "changed"}
    changed_path = tmp_path / "changed.json"
    changed_path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="digest does not match"):
        ProviderContract.load(changed_path)

    missing_digest = {key: value for key, value in raw.items() if key != "sha256"}
    missing_path = tmp_path / "missing-digest.json"
    missing_path.write_text(json.dumps(missing_digest), encoding="utf-8")
    with pytest.raises(ValueError, match="must declare"):
        ProviderContract.load(missing_path)

    constructor_values = {key: value for key, value in raw.items() if key != "sha256"}
    with pytest.raises(ValueError, match="environment is not authorized"):
        ProviderContract(**{**constructor_values, "environment": "production"})
    with pytest.raises(ValueError, match="indirect reference"):
        ProviderContract(
            **{
                **constructor_values,
                "authentication": {
                    "mode": "bearer",
                    "credential_reference": "raw-secret-value",
                },
            }
        )


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (404, ObservationState.AVAILABLE_ABSENT),
        (401, ObservationState.AUTHENTICATION_FAILED),
        (429, ObservationState.RATE_LIMITED),
        (503, ObservationState.TEMPORARILY_UNAVAILABLE),
    ],
)
def test_authoritative_read_maps_provider_status_without_credential_material(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected: ObservationState,
) -> None:
    contract = ProviderContract.load(CONTRACT_PATH)
    response = httpx.Response(
        status_code,
        headers={"Retry-After": "12", "Authorization": "Bearer must-not-leak"},
        request=httpx.Request("GET", "https://provider.test/invoices/INV-1"),
    )
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: response)
    observation = HttpAccountingClient("https://provider.test", contract).observe_invoice("INV-1")
    assert observation.state == expected
    assert "must-not-leak" not in json.dumps(observation.to_evidence())
    assert observation.retry_after_seconds == (12 if status_code == 429 else None)


def test_write_timeout_is_unknown_and_requires_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = ProviderContract.load(CONTRACT_PATH)

    def read_timeout(*args: object, **kwargs: object) -> httpx.Response:
        del args, kwargs
        raise httpx.ReadTimeout("unknown after dispatch")

    monkeypatch.setattr(httpx, "post", read_timeout)
    outcome = HttpAccountingClient("https://provider.test", contract).write_invoice(
        {"invoice_id": "INV-1", "amount": "10.00", "currency": "RUB"},
        "bounded-idempotency-key",
    )
    assert outcome.state == WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            httpx.Response(
                200,
                content=b"{",
                request=httpx.Request("GET", "https://provider.test/invoices/INV-1"),
            ),
            ObservationState.MALFORMED_RESPONSE,
        ),
        (
            httpx.Response(
                200,
                json={"records": [{"access_token": "must-not-enter-projection"}]},
                request=httpx.Request("GET", "https://provider.test/invoices/INV-1"),
            ),
            ObservationState.MALFORMED_RESPONSE,
        ),
        (
            httpx.Response(
                200,
                json={"records": [{"invoice_id": "x" * 256}]},
                request=httpx.Request("GET", "https://provider.test/invoices/INV-1"),
            ),
            ObservationState.MALFORMED_RESPONSE,
        ),
    ],
)
def test_malformed_provider_read_is_typed_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    expected: ObservationState,
) -> None:
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: response)
    contract = ProviderContract.load(CONTRACT_PATH)
    observation = HttpAccountingClient("https://provider.test", contract).observe_invoice("INV-1")
    assert observation.state == expected
    assert observation.records == ()
    assert "must-not-enter-projection" not in json.dumps(observation.to_evidence())


def test_authoritative_read_rejects_a_different_entity_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = httpx.Response(
        200,
        json={"invoice_id": "INV-OTHER", "amount": "10.00", "currency": "RUB"},
        request=httpx.Request("GET", "https://provider.test/invoices/INV-1"),
    )
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: response)
    observation = HttpAccountingClient(
        "https://provider.test", ProviderContract.load(CONTRACT_PATH)
    ).observe_invoice("INV-1")
    assert observation.state == ObservationState.MALFORMED_RESPONSE
    assert observation.records == ()


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, WriteOutcomeState.AUTHENTICATION_FAILED),
        (403, WriteOutcomeState.AUTHENTICATION_FAILED),
        (429, WriteOutcomeState.RATE_LIMITED),
        (500, WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN),
    ],
)
def test_provider_write_failures_are_typed_without_hidden_retry(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected: WriteOutcomeState,
) -> None:
    calls = 0

    def respond(*args: object, **kwargs: object) -> httpx.Response:
        nonlocal calls
        del args, kwargs
        calls += 1
        return httpx.Response(
            status_code,
            headers={"Retry-After": "999999"},
            request=httpx.Request("POST", "https://provider.test/invoices"),
        )

    monkeypatch.setattr(httpx, "post", respond)
    contract = ProviderContract.load(CONTRACT_PATH)
    outcome = HttpAccountingClient("https://provider.test", contract).write_invoice(
        {"invoice_id": "INV-1", "amount": "10.00", "currency": "RUB"},
        "bounded-idempotency-key",
    )
    assert calls == 1
    assert outcome.state == expected
    assert outcome.retry_after_seconds == (86_400 if status_code == 429 else None)


def test_dns_failure_is_typed_as_pre_acceptance_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def unavailable(*args: object, **kwargs: object) -> httpx.Response:
        nonlocal calls
        del args, kwargs
        calls += 1
        raise httpx.ConnectError(
            "dns unavailable", request=httpx.Request("POST", "https://provider.test/invoices")
        )

    monkeypatch.setattr(httpx, "post", unavailable)
    contract = ProviderContract.load(CONTRACT_PATH)
    outcome = HttpAccountingClient("https://provider.test", contract).write_invoice(
        {"invoice_id": "INV-1", "amount": "10.00", "currency": "RUB"},
        "bounded-idempotency-key",
    )
    assert calls == 1
    assert outcome.state == WriteOutcomeState.PRE_ACCEPTANCE_FAILURE
    assert outcome.error_code == "ConnectError"


def test_success_with_unbounded_known_write_field_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = httpx.Response(
        202,
        json={"accepted": True, "status": "x" * 256},
        headers={"X-Request-ID": "r" * 300},
        request=httpx.Request("POST", "https://provider.test/invoices"),
    )
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: response)
    contract = ProviderContract.load(CONTRACT_PATH)
    outcome = HttpAccountingClient("https://provider.test", contract).write_invoice(
        {"invoice_id": "INV-1", "amount": "10.00", "currency": "RUB"},
        "bounded-idempotency-key",
    )
    assert outcome.state == WriteOutcomeState.MALFORMED_RESPONSE


def test_typed_provider_results_reject_unsafe_or_contradictory_projections() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="record count contradicts"):
        InvoiceObservation(
            state=ObservationState.AVAILABLE_PRESENT,
            provider_id="provider",
            environment="sandbox",
            adapter_version="1",
            entity_reference="INV-1",
            observed_at=now,
        )
    with pytest.raises(ValueError, match="unsafe provider projection"):
        RecoveryWriteOutcome(
            state=WriteOutcomeState.ACCEPTED,
            provider_id="provider",
            environment="sandbox",
            adapter_version="1",
            observed_at=now,
            safe_result={"access_token": "must-not-persist"},
        )
