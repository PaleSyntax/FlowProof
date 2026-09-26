from __future__ import annotations

import copy
import json
from pathlib import Path
from uuid import uuid4

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from flowproof.policy import load_policy

ROOT = Path(__file__).resolve().parents[2]
PACK_SCHEMA = ROOT / "specs" / "outcome-packs" / "outcome-pack.schema.json"
PACK_PATH = ROOT / "specs" / "outcome-packs" / "invoice-accounting" / "pack.json"
POLICY_PATH = (
    ROOT
    / "specs"
    / "outcome-packs"
    / "invoice-accounting"
    / "policy.observe-only.yaml"
)
EVENT_PATH = (
    ROOT
    / "specs"
    / "outcome-packs"
    / "invoice-accounting"
    / "registration-acknowledged.event.json"
)
EVENT_SCHEMA = ROOT / "specs" / "events" / "business-event.schema.json"
POLICY_SCHEMA = ROOT / "specs" / "policies" / "policy.schema.json"
ACCESS_SCHEMA = (
    ROOT / "quality" / "productization" / "provider-access-request.schema.json"
)
ACCESS_TEMPLATE = (
    ROOT / "quality" / "productization" / "provider-access-request.template.json"
)
LIFECYCLE_SCHEMA = (
    ROOT
    / "quality"
    / "productization"
    / "observe-only-provider-lifecycle.schema.json"
)
LIFECYCLE_TEMPLATE = (
    ROOT
    / "quality"
    / "productization"
    / "observe-only-provider-lifecycle.template.json"
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(path: Path) -> Draft202012Validator:
    schema = _load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_invoice_outcome_pack_is_observe_only_and_all_assets_exist() -> None:
    pack = _load(PACK_PATH)
    _validator(PACK_SCHEMA).validate(pack)

    assert pack["status"] == "LOCAL_PACK_READY_PROVIDER_BLOCKED"
    assert pack["default_mode"] == "observe_only"
    assert pack["provider_gate"] == {
        "selection_status": "OWNER_AUTHORIZED_PROVIDER_ACCESS_REQUIRED",
        "allowed_environments": ["sandbox", "partner_test"],
        "contract_schema": "specs/providers/provider-contract.schema.json",
        "explicit_adapter_registration_required": True,
        "credential_material_allowed_in_pack": False,
        "live_evidence_available": False,
    }
    assert pack["authoritative_read"]["method"] == "GET"
    assert pack["authoritative_read"]["allowed_mutation_methods"] == []
    assert pack["recovery_boundary"]["enabled"] is False
    assert pack["recovery_boundary"]["write_authority_included"] is False
    assert all(item["recovery_action"] is None for item in pack["invariants"])

    for relative_path in pack["assets"].values():
        assert (ROOT / relative_path).is_file(), relative_path


def test_observe_only_policy_and_event_template_are_loadable_contracts() -> None:
    policy = load_policy(POLICY_PATH, POLICY_SCHEMA)
    assert "recovery" not in policy
    assert all("recovery_action" not in item for item in policy["invariants"])
    assert any(
        item["id"] == "external_invoice_exists"
        and item["type"] == "external_assertion"
        and item["verifier"] == "owner_authorized_invoice_provider"
        for item in policy["invariants"]
    )

    _validator(EVENT_SCHEMA).validate(_load(EVENT_PATH))
    event = _load(EVENT_PATH)
    assert event["source"]["system"] == "n8n"
    assert event["event_type"] == "invoice.registration_acknowledged"
    assert set(event["payload"]) == {"amount", "currency"}


def _ready_access_request() -> dict[str, object]:
    request = copy.deepcopy(_load(ACCESS_TEMPLATE))
    request.update(
        {
            "status": "READY_FOR_ADAPTER_IMPLEMENTATION",
            "request_id": str(uuid4()),
            "requested_at": "2026-08-06T12:00:00Z",
        }
    )
    request["provider"].update(
        {
            "provider_name": "Owner Sandbox Accounting",
            "provider_id": "owner-sandbox-accounting",
            "environment": "sandbox",
            "official_api_version": "2026-01",
            "documentation_url": "https://provider.example.test/docs",
            "sandbox_base_url": "https://sandbox.provider.example.test",
            "authentication_mode": "bearer",
            "credential_reference": "docker-secret:owner_sandbox_provider_token",
        }
    )
    request["safe_entity"].update(
        {
            "invoice_id": "SAFE-SANDBOX-INVOICE-001",
            "expected_exists": True,
            "expected_amount": 100.0,
            "currency": "USD",
        }
    )
    request["authorization"].update(
        {
            "owner_name": "Sandbox owner",
            "authorized_at": "2026-08-06T12:00:00Z",
            "expires_at": "2026-08-07T12:00:00Z",
            "authorization_reference": "approval-record",
            "permitted_path_template": "/invoices/{invoice_id}",
        }
    )
    request["operator"].update(
        {"name": "Independent operator", "role": "FinanceOps reviewer"}
    )
    return request


def test_provider_access_request_requires_non_fixture_indirect_read_only_authority() -> None:
    validator = _validator(ACCESS_SCHEMA)
    validator.validate(_load(ACCESS_TEMPLATE))
    ready = _ready_access_request()
    validator.validate(ready)

    for mutation in (
        ("provider", "provider_id", "mock-accounting"),
        ("provider", "credential_reference", "raw-secret-value"),
        ("authorization", "permitted_methods", ["GET", "POST"]),
        ("authorization", "mutations_allowed", True),
        ("authorization", "recovery_write_authorized", True),
    ):
        invalid = copy.deepcopy(ready)
        section, field, value = mutation
        invalid[section][field] = value
        assert list(validator.iter_errors(invalid)), mutation


def _passing_lifecycle() -> dict[str, object]:
    lifecycle = copy.deepcopy(_load(LIFECYCLE_TEMPLATE))
    lifecycle.update(
        {
            "result": "PASS",
            "session_id": str(uuid4()),
            "started_at": "2026-08-06T12:10:00Z",
            "completed_at": "2026-08-06T12:12:00Z",
        }
    )
    lifecycle["provider"].update(
        {
            "provider_id": "owner-sandbox-accounting",
            "environment": "sandbox",
            "adapter_version": "0.1.0",
            "contract_version": "2026-01",
            "contract_sha256": "a" * 64,
            "evidence_classification": "LIVE_SANDBOX_OBSERVED",
        }
    )
    lifecycle["safe_entity"].update(
        {
            "entity_id": "SAFE-SANDBOX-INVOICE-001",
            "expected_exists": True,
            "expected_amount": 100.0,
            "currency": "USD",
        }
    )
    lifecycle["observation"].update(
        {
            "classification": "AVAILABLE_PRESENT",
            "content_digest": "b" * 64,
            "records": [
                {
                    "invoice_id": "SAFE-SANDBOX-INVOICE-001",
                    "amount": 100.0,
                    "currency": "USD",
                    "status": "AUTHORISED",
                }
            ],
            "invariant_result": "PASSED",
        }
    )
    lifecycle["operator_review"].update(
        {
            "operator_name": "Independent operator",
            "operator_role": "FinanceOps reviewer",
            "reviewed_at": "2026-08-06T12:13:00Z",
            "decision": "REVIEWED",
            "provider_identity_confirmed": True,
            "entity_confirmed": True,
            "evidence_bounded": True,
            "no_mutation_confirmed": True,
        }
    )
    lifecycle["evidence"] = ["evidence/provider-observation.json"]
    return lifecycle


def test_live_lifecycle_cannot_be_promoted_from_fixture_or_mutating_run() -> None:
    validator = _validator(LIFECYCLE_SCHEMA)
    validator.validate(_load(LIFECYCLE_TEMPLATE))
    passing = _passing_lifecycle()
    validator.validate(passing)

    for mutation in (
        ("provider", "provider_id", "mock-accounting"),
        ("safety", "provider_mutation_count", 1),
        ("safety", "recovery_writes_enabled", True),
        ("operator_review", "no_mutation_confirmed", False),
        ("provider", "evidence_classification", None),
    ):
        invalid = copy.deepcopy(passing)
        section, field, value = mutation
        invalid[section][field] = value
        assert list(validator.iter_errors(invalid)), mutation


def test_pack_contract_contains_no_secret_material_or_fixture_provider_claim() -> None:
    combined = "\n".join(
        (
            PACK_PATH.read_text(encoding="utf-8"),
            POLICY_PATH.read_text(encoding="utf-8"),
            yaml.safe_dump(_load(EVENT_PATH)),
        )
    ).lower()
    assert "bearer " not in combined
    assert "access_token" not in combined
    assert "api_key" not in combined
    assert "mock-accounting" not in combined
