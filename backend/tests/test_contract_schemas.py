from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.main import create_app
from flowproof.models import Base

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "specs" / "events"


def _load(name: str) -> dict[str, object]:
    return json.loads(
        (SCHEMA_ROOT / name).read_text(encoding="utf-8")
    )


def _validator(
    schema: dict[str, object],
    *dependencies: dict[str, object],
) -> Draft202012Validator:
    registry = Registry()
    for dependency in dependencies:
        registry = registry.with_resource(
            str(dependency["$id"]),
            Resource.from_contents(dependency),
        )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def _plan(status: str = "superseded") -> dict[str, object]:
    incident_id = str(uuid4())
    contract_digest = "b" * 64
    return {
        "id": str(uuid4()),
        "incident_id": incident_id,
        "action_type": "register_missing_invoice",
        "parameters": {
            "invoice_id": "INV-SCHEMA",
            "amount": 10.0,
            "currency": "RUB",
        },
        "idempotency_key": (
            f"recovery:{incident_id}:register_missing_invoice"
        ),
        "risk_level": "bounded_sandbox_write",
        "requires_approval": True,
        "status": status,
        "plan_hash": "a" * 64,
        "provider_id": "mock-accounting",
        "provider_environment": "sandbox",
        "adapter_version": "0.6.0-test-fixture",
        "provider_contract_digest": contract_digest,
        "provider_contract_snapshot": {
            "sha256": contract_digest,
        },
        "guardrails": {
            "provider_id": "mock-accounting",
            "environment": "sandbox",
            "sandbox_only": True,
            "entity_type": "invoice",
            "entity_id": "INV-SCHEMA",
            "action_type": "register_missing_invoice",
            "allowed_currencies": ["RUB"],
            "maximum_amount_minor": 1_000_000,
            "amount_scale": 2,
            "observed_amount_minor": 1_000,
            "maximum_semantic_write_attempts": 1,
            "maximum_transport_invocations": 2,
            "approval_ttl_seconds": 900,
            "provider_contract_digest": contract_digest,
            "reconciliation_method": (
                "authoritative_invoice_reread"
            ),
            "batch_allowed": False,
            "wildcards_allowed": False,
        },
        "approved_by": None,
        "approval_context": {},
        "approved_at": None,
        "approval_expires_at": None,
        "executed_at": None,
        "verified_at": None,
        "result": {
            "external_resolution": {
                "classification": (
                    "INVARIANT_PASS_WITHOUT_RECOVERY_EXECUTION"
                ),
                "transport_invocation_count": 0,
            }
        },
    }


def test_recovery_plan_schema_has_superseded_external_resolution() -> None:
    validator = _validator(
        _load("recovery-plan.schema.json")
    )
    candidate = _plan()
    validator.validate(candidate)

    active_approval = {
        **candidate,
        "approved_by": "operator",
        "approved_at": datetime.now(UTC).isoformat(),
    }
    assert any(
        error.validator == "type"
        for error in validator.iter_errors(active_approval)
    )


def test_recovery_attempt_schema_requires_active_reservation_and_claim_history() -> None:
    schema = _load("recovery-attempt.schema.json")
    validator = _validator(schema)
    now = datetime.now(UTC)
    reservation_id = str(uuid4())
    candidate = {
        "id": str(uuid4()),
        "recovery_plan_id": str(uuid4()),
        "incident_id": str(uuid4()),
        "approval_decision_id": str(uuid4()),
        "active_transport_invocation_id": reservation_id,
        "attempt_ordinal": 1,
        "execution_idempotency_key": "recovery-key",
        "plan_hash": "a" * 64,
        "provider_contract_digest": "b" * 64,
        "provider_id": "mock-accounting",
        "provider_environment": "sandbox",
        "adapter_version": "0.6.0-test-fixture",
        "request_digest": "c" * 64,
        "precondition_observation_digest": "d" * 64,
        "state": "RECONCILED_EFFECT_ABSENT",
        "outcome_classification": "PRE_ACCEPTANCE_FAILURE",
        "provider_operation_reference": None,
        "retry_after_seconds": None,
        "semantic_attempt_count": 1,
        "transport_invocation_count": 1,
        "retry_permitted": True,
        "retry_reason": "pre_acceptance_failure_proven",
        "safe_result": {
            "reconciliation_history": [
                {
                    "reservation_id": reservation_id,
                    "observation": {
                        "classification": "AVAILABLE_ABSENT"
                    },
                    "reconciled_at": now.isoformat(),
                    "prior_attempt_state": "PRE_ACCEPTANCE_FAILED",
                    "prior_reservation_state": (
                        "PRE_ACCEPTANCE_FAILED"
                    ),
                    "transport_invocation_count": 1,
                    "reapproval_action": (
                        "retry_reapproval_required"
                    ),
                    "retry_reason": (
                        "pre_acceptance_failure_proven"
                    ),
                    "write_outcome": {
                        "classification": (
                            "PRE_ACCEPTANCE_FAILURE"
                        )
                    },
                    "reconciliation_claim": {
                        "owner": "reconciler-a",
                        "generation": 1,
                        "reservation_lock_version": 2,
                        "attempt_lock_version": 2,
                        "lease_expires_at": (
                            now + timedelta(seconds=60)
                        ).isoformat(),
                        "reason": "explicit_reconcile",
                    },
                }
            ]
        },
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "accepted_at": None,
        "reconciled_at": now.isoformat(),
        "lock_version": 3,
    }
    validator.validate(candidate)

    stale = {
        **candidate,
        "safe_result": {
            "reconciliation_history": [
                {
                    **candidate["safe_result"][
                        "reconciliation_history"
                    ][0],
                    "reconciliation_claim": {
                        "owner": "reconciler-a"
                    },
                }
            ]
        },
    }
    assert any(
        error.validator == "required"
        for error in validator.iter_errors(stale)
    )


def test_transport_schema_contains_full_dispatch_and_reconciliation_boundary() -> None:
    schema = _load(
        "recovery-transport-invocation.schema.json"
    )
    validator = _validator(schema)
    now = datetime.now(UTC)
    candidate = {
        "id": str(uuid4()),
        "recovery_attempt_id": str(uuid4()),
        "recovery_plan_id": str(uuid4()),
        "approval_decision_id": str(uuid4()),
        "invocation_ordinal": 1,
        "request_digest": "a" * 64,
        "reserved_at": now.isoformat(),
        "state": "EFFECT_PRESENT",
        "dispatch_owner": "dispatcher-a",
        "dispatch_generation": 1,
        "dispatch_started_at": now.isoformat(),
        "dispatch_lease_expires_at": (
            now + timedelta(seconds=60)
        ).isoformat(),
        "abandoned_at": None,
        "abandoned_by": None,
        "abandonment_reason": None,
        "reconciliation_owner": "reconciler-a",
        "reconciliation_generation": 1,
        "reconciliation_started_at": now.isoformat(),
        "reconciliation_lease_expires_at": (
            now + timedelta(seconds=60)
        ).isoformat(),
        "reconciliation_abandoned_at": None,
        "outcome_classification": "ACCEPTED",
        "outcome_observed_at": now.isoformat(),
        "provider_operation_reference": "operation-1",
        "retry_after_seconds": None,
        "safe_outcome": {
            "provider_write_outcome": {
                "classification": "ACCEPTED"
            },
            "authoritative_reconciliation": {
                "classification": "AVAILABLE_PRESENT"
            },
        },
        "completed_at": now.isoformat(),
        "lock_version": 4,
    }
    validator.validate(candidate)

    missing_generation = {
        key: value
        for key, value in candidate.items()
        if key != "reconciliation_generation"
    }
    assert any(
        error.validator == "required"
        for error in validator.iter_errors(
            missing_generation
        )
    )


def test_decision_and_capsule_schemas_name_external_resolution_and_0010() -> None:
    decision = _load("recovery-decision.schema.json")
    Draft202012Validator.check_schema(decision)
    assert "external_resolution" in decision["properties"][
        "action"
    ]["enum"]

    capsule = json.loads(
        (
            ROOT
            / "specs"
            / "evidence"
            / "evidence-capsule.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(capsule)
    assert capsule["properties"]["schema_version"]["const"] == "1.1"
    assert (
        capsule["properties"]["migration_head"]["const"]
        == "0010_release_groundwork_fencing"
    )


class _NoDuplicateSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(
            value_node,
            deep=deep,
        )
    return mapping


_NoDuplicateSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _SchemaAccounting:
    def get_invoice(self, invoice_id: str) -> dict[str, object]:
        return {
            "available": True,
            "exists": False,
            "records": [],
        }

    def register_invoice(
        self,
        invoice: dict[str, object],
        idempotency_key: str,
    ) -> dict[str, object]:
        return {
            "status_code": 200,
            "body": {"accepted": True},
        }

    def set_chaos_mode(self, mode: str) -> dict[str, str]:
        return {"mode": mode}


def _operations(
    document: dict[str, object],
) -> set[tuple[str, str]]:
    return {
        (path, method)
        for path, method, _operation in _operation_records(
            document
        )
    }


def _operation_records(
    document: dict[str, object],
) -> list[tuple[str, str, dict[str, object]]]:
    methods = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "head",
        "trace",
    }
    paths = document["paths"]
    assert isinstance(paths, dict)
    return [
        (str(path), str(method), operation)
        for path, item in paths.items()
        if isinstance(item, dict)
        for method, operation in item.items()
        if method in methods and isinstance(operation, dict)
    ]


def _load_committed_openapi() -> dict[str, object]:
    document = yaml.load(
        (ROOT / "specs" / "openapi.yaml").read_text(
            encoding="utf-8"
        ),
        Loader=_NoDuplicateSafeLoader,
    )
    assert isinstance(document, dict)
    return document


def _typescript_union_members(name: str) -> set[str]:
    source = (ROOT / "frontend" / "src" / "types.ts").read_text(
        encoding="utf-8"
    )
    match = re.search(
        rf"export type {re.escape(name)} =(?P<body>.*?)(?:\n\n|\Z)",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    return set(re.findall(r"'([^']+)'", match.group("body")))


def test_committed_openapi_has_unique_route_methods_and_operation_ids() -> None:
    committed = _load_committed_openapi()
    operations = _operation_records(committed)
    route_methods = [
        (path, method)
        for path, method, _operation in operations
    ]
    operation_ids = [
        operation.get("operationId")
        for _path, _method, operation in operations
    ]
    assert len(route_methods) == len(set(route_methods))
    assert all(
        isinstance(operation_id, str) and operation_id
        for operation_id in operation_ids
    )
    assert len(operation_ids) == len(set(operation_ids))


def test_all_recovery_routes_document_status_and_auth() -> None:
    recovery_operations = [
        (path, method, operation)
        for path, method, operation in _operation_records(
            _load_committed_openapi()
        )
        if isinstance(operation.get("tags"), list)
        and "recovery" in operation["tags"]
    ]
    assert recovery_operations
    for path, method, operation in recovery_operations:
        responses = operation.get("responses")
        security = operation.get("security")
        assert isinstance(responses, dict) and responses, (
            f"{method.upper()} {path} has no documented status codes"
        )
        assert isinstance(security, list) and security, (
            f"{method.upper()} {path} has no documented auth"
        )


def test_typescript_state_enums_match_committed_json_schemas() -> None:
    mappings = {
        "RecoveryPlanStatus": (
            "recovery-plan.schema.json",
            "status",
        ),
        "RecoveryAttemptState": (
            "recovery-attempt.schema.json",
            "state",
        ),
        "RecoveryTransportState": (
            "recovery-transport-invocation.schema.json",
            "state",
        ),
    }
    for type_name, (schema_name, property_name) in mappings.items():
        schema = _load(schema_name)
        properties = schema["properties"]
        assert isinstance(properties, dict)
        state_schema = properties[property_name]
        assert isinstance(state_schema, dict)
        assert _typescript_union_members(type_name) == set(
            state_schema["enum"]
        )


def test_committed_openapi_has_unique_keys_and_matches_runtime_routes(
    tmp_path: Path,
) -> None:
    committed = _load_committed_openapi()

    database_url = (
        f"sqlite:///{tmp_path / 'openapi.sqlite3'}"
    )
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    settings = Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=(
            ROOT
            / "specs"
            / "policies"
            / "invoice-processing.yaml"
        ),
        environment="test",
        token_pepper=(
            "openapi-test-token-pepper-with-at-least-"
            "thirty-two-characters"
        ),
        legacy_ingestion_token="test-token",
        legacy_operator_token="test-operator-token",
        legacy_header_auth_enabled=True,
    )
    runtime = create_app(
        settings,
        _SchemaAccounting(),
        make_session_factory(engine),
    ).openapi()

    assert committed["info"]["version"] == "0.6.0"
    assert runtime["info"]["version"] == "0.6.0"
    assert _operations(committed) == _operations(runtime)
    attempts = committed["paths"][
        "/api/v1/recovery-plans/{plan_id}/attempts"
    ]["get"]
    assert "200" in attempts["responses"]
