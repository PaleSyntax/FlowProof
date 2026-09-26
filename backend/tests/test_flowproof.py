from __future__ import annotations

import hashlib
import json
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from flowproof import accounting as accounting_module
from flowproof.accounting import ProviderContract
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.evidence import (
    EvidenceError,
    export_capsule,
    verify_capsule,
)
from flowproof.evidence import (
    main as evidence_main,
)
from flowproof.evidence_contract import (
    PROOF_CHECKPOINT,
    PROOF_WRITE,
    REQUIRED_MEMBERS,
)
from flowproof.identity import IdentityService
from flowproof.main import create_app
from flowproof.models import (
    Base,
    BusinessEvent,
    Incident,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.policy import PolicyValidationError, load_policy
from flowproof.service import FlowProofService

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
PROVIDER_CONTRACT_PATH = ROOT / "specs" / "providers" / "mock-accounting" / "contract.json"
TEST_GIT_COMMIT = "a" * 40
TEST_GIT_TREE = "b" * 40
EXPECTED_CAPSULE_MEMBERS = frozenset(
    {"manifest.json", *REQUIRED_MEMBERS}
)
TEST_CLOCK_WALL_ANCHOR = datetime.now(UTC)
TEST_CLOCK_MONOTONIC_ANCHOR = time.monotonic()


def stable_test_now() -> datetime:
    """Keep domain time monotonic when the host wall clock is resynchronized."""

    elapsed = time.monotonic() - TEST_CLOCK_MONOTONIC_ANCHOR
    return TEST_CLOCK_WALL_ANCHOR + timedelta(seconds=elapsed)


class FakeAccounting:
    def __init__(self) -> None:
        self.mode = "normal"
        self.records: dict[str, dict[str, Any]] = {}
        self.request_keys: dict[str, dict[str, Any]] = {}
        self.register_calls = 0

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        record = self.records.get(invoice_id)
        return {"available": True, "exists": bool(record), "records": [record] if record else []}

    def register_invoice(self, invoice: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        self.register_calls += 1
        if self.mode == "crash_after_dispatch":
            raise RuntimeError("injected crash after durable dispatch intent")
        if self.mode == "crash_after_effect":
            self.records[str(invoice["invoice_id"])] = dict(invoice)
            raise RuntimeError("injected crash after provider effect")
        if self.mode == "outcome_unknown_applied":
            self.records[str(invoice["invoice_id"])] = dict(invoice)
            return {"status_code": 0, "error": "read_timeout"}
        if self.mode == "outcome_unknown_absent":
            return {"status_code": 0, "error": "read_timeout"}
        if self.mode == "pre_acceptance_failure":
            return {"status_code": 400}
        if idempotency_key in self.request_keys:
            return self.request_keys[idempotency_key]
        result = {
            "status_code": 202 if self.mode == "delayed_write" else 200,
            "body": {"accepted": True},
        }
        self.request_keys[idempotency_key] = result
        if self.mode not in {"false_200", "delayed_write"}:
            self.records[str(invoice["invoice_id"])] = dict(invoice)
        return result

    def set_chaos_mode(self, mode: str) -> dict[str, Any]:
        self.mode = mode
        return {"mode": mode}


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOWPROOF_GIT_COMMIT", TEST_GIT_COMMIT)
    monkeypatch.setenv("FLOWPROOF_GIT_TREE", TEST_GIT_TREE)
    service_init = FlowProofService.__init__
    identity_init = IdentityService.__init__

    def stable_service_init(self: FlowProofService, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("now", stable_test_now)
        service_init(self, *args, **kwargs)

    def stable_identity_init(self: IdentityService, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("clock", stable_test_now)
        identity_init(self, *args, **kwargs)

    monkeypatch.setattr(FlowProofService, "__init__", stable_service_init)
    monkeypatch.setattr(IdentityService, "__init__", stable_identity_init)
    monkeypatch.setattr(accounting_module, "_utc_now", stable_test_now)
    database_url = f"sqlite:///{tmp_path / 'flowproof.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    accounting = FakeAccounting()
    settings = Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="test",
        token_pepper="test-token-pepper-with-at-least-thirty-two-characters",
        legacy_ingestion_token="test-token",
        legacy_operator_token="test-operator-token",
        legacy_header_auth_enabled=True,
    )
    with factory() as session:
        IdentityService(session, settings.token_pepper or "").create_human(
            "human-operator", "human-operator-password-123", "operator"
        )
    app = create_app(settings, accounting, factory)
    with TestClient(app) as client:
        yield client, accounting, factory


def event_body(
    event_type: str,
    key: str,
    *,
    correlation_id: str = "order-8841",
    invoice_id: str = "INV-142",
    amount: float = 18000.0,
    occurred_at: datetime | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "idempotency_key": key,
        "correlation_id": correlation_id,
        "entity_type": "invoice",
        "entity_id": invoice_id,
        "event_type": event_type,
        "occurred_at": (occurred_at or stable_test_now()).isoformat(),
        "source": {"system": "n8n", "workflow_id": "invoice-intake", "execution_id": "42"},
        "payload": payload or {"amount": amount, "currency": "RUB"},
    }


def ingest(client: TestClient, body: dict[str, Any]):
    return client.post("/api/v1/events", json=body, headers={"X-FlowProof-Token": "test-token"})


def operator_headers() -> dict[str, str]:
    return {"X-FlowProof-Operator-Token": "test-operator-token"}


def human_operator_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"name": "human-operator", "password": "human-operator-password-123"},
    )
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def rewrite_capsule_member(
    source: Path,
    destination: Path,
    member_name: str,
    transform: Any,
    *,
    proof_type: str | None = None,
) -> None:
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert set(names) == EXPECTED_CAPSULE_MEMBERS
        contents = {name: archive.read(name) for name in names}

    def canonical(value: object) -> bytes:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")

    contents[member_name] = canonical(
        transform(json.loads(contents[member_name]))
    )
    manifest = json.loads(contents["manifest.json"])
    coordinates = json.loads(
        contents["release-coordinates.json"]
    )
    if proof_type is not None:
        manifest["proof_type"] = proof_type
        coordinates["proof_type"] = proof_type
        contents["release-coordinates.json"] = canonical(
            coordinates
        )
    else:
        assert manifest["proof_type"] == coordinates["proof_type"]
    declarations = [
        {
            "name": name,
            "size": len(contents[name]),
            "sha256": hashlib.sha256(contents[name]).hexdigest(),
        }
        for name in sorted(REQUIRED_MEMBERS)
    ]
    manifest["files"] = declarations
    manifest["bundle_sha256"] = hashlib.sha256(canonical(declarations)).hexdigest()
    manifest["review_subject_sha256"] = hashlib.sha256(
        canonical(
            [
                item
                for item in declarations
                if item["name"] not in {"operator-review.json", "audit-references.json"}
            ]
        )
    ).hexdigest()
    contents["manifest.json"] = canonical(manifest)
    with zipfile.ZipFile(destination, "w") as archive:
        for name, content in sorted(contents.items()):
            archive.writestr(name, content)


def object_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def verify_with_declared_anchor(
    path: Path,
    *,
    allow_legacy_v1: bool = False,
) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        bundle_sha256 = json.loads(archive.read("manifest.json"))["bundle_sha256"]
    return verify_capsule(
        path,
        expected_bundle_sha256=bundle_sha256,
        expected_git_commit=TEST_GIT_COMMIT,
        expected_git_tree=TEST_GIT_TREE,
        allow_legacy_v1=allow_legacy_v1,
    )


def seed_false_200_path(client: TestClient, *, occurred_at: datetime | None = None) -> None:
    for event_type, suffix in (
        ("invoice.approved", "approved"),
        ("invoice.validated", "validated"),
        ("invoice.registration_requested", "requested"),
        ("invoice.registration_acknowledged", "ack"),
    ):
        response = ingest(
            client, event_body(event_type, f"invoice-142:{suffix}", occurred_at=occurred_at)
        )
        assert response.status_code == 201


def proposed_recovery(client: TestClient) -> tuple[dict[str, Any], dict[str, Any]]:
    seed_false_200_path(client, occurred_at=stable_test_now() - timedelta(seconds=31))
    response = client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    assert response.status_code == 200
    incident = client.get("/api/v1/incidents", headers=operator_headers()).json()["items"][0]
    plan = incident["recovery_plan"]
    assert plan is not None
    return incident, plan


def effect_absent_retry_required(
    client: TestClient, accounting: FakeAccounting
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    csrf = human_operator_headers(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers={**csrf, "X-Request-ID": "initial-retry-lineage-approval"},
        ).status_code
        == 200
    )
    accounting.mode = "pre_acceptance_failure"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "proposed"
    return incident, plan, csrf


def test_event_ingestion_is_authenticated_idempotent_and_redacted(setup) -> None:
    client, _, _ = setup
    body = event_body(
        "invoice.received", "delivery-1", payload={"amount": 10, "token": "do-not-store"}
    )
    assert client.post("/api/v1/events", json=body).status_code == 401
    assert client.post("/api/v1/chaos/mode", json={"mode": "normal"}).status_code == 401
    first = ingest(client, body)
    assert first.status_code == 201
    duplicate = ingest(client, body)
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True

    timeline = client.get(
        "/api/v1/entities/invoice/INV-142/timeline", headers=operator_headers()
    ).json()["items"]
    assert timeline[0]["payload"]["token"] == "[REDACTED]"
    conflict_body = {**body, "payload": {"amount": 11}}
    assert ingest(client, conflict_body).status_code == 409


def test_correlation_is_fail_closed_for_mixed_entities(setup) -> None:
    client, _, factory = setup
    first = event_body(
        "invoice.validated",
        "mixed-correlation:first",
        correlation_id="mixed-correlation",
        invoice_id="INV-A",
        amount=18_000,
    )
    assert ingest(client, first).status_code == 201
    blocked = ingest(
        client,
        event_body(
            "invoice.validated",
            "mixed-correlation:second",
            correlation_id="mixed-correlation",
            invoice_id="INV-B",
            amount=100,
        ),
    )
    assert blocked.status_code == 422
    assert "different entity" in blocked.json()["detail"]

    with factory() as session:
        session.add(
            BusinessEvent(
                id="legacy-mixed-entity-event",
                idempotency_key="legacy-mixed-entity-key",
                correlation_id="mixed-correlation",
                entity_type="invoice",
                entity_id="INV-B",
                event_type="invoice.validated",
                occurred_at=stable_test_now(),
                source_system="legacy-fixture",
                workflow_id="legacy-fixture",
                workflow_version="1",
                execution_id="legacy-fixture",
                node_name="legacy-fixture",
                payload={"amount": 100, "currency": "RUB"},
                content_hash="c" * 64,
            )
        )
        session.commit()
    evaluation = client.post(
        "/api/v1/correlations/mixed-correlation/evaluate", headers=operator_headers()
    )
    assert evaluation.status_code == 422
    assert "multiple entities" in evaluation.json()["detail"]


def test_false_200_opens_one_incident_and_human_approved_recovery_resolves_it(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    seed_false_200_path(client, occurred_at=stable_test_now() - timedelta(seconds=31))

    first = client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    assert first.status_code == 200
    external = next(
        item
        for item in first.json()["evaluations"]
        if item["invariant_id"] == "external_invoice_exists"
    )
    assert external["state"] == "violated"
    incidents = client.get("/api/v1/incidents", headers=operator_headers()).json()["items"]
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["summary"] == "missing_external_invoice"
    assert incident["evidence"]["event_ids"]
    plan = incident["recovery_plan"]
    assert plan["action_type"] == "register_missing_invoice"
    assert plan["requires_approval"] is True

    client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    assert len(client.get("/api/v1/incidents", headers=operator_headers()).json()["items"]) == 1
    assert client.post(f"/api/v1/recovery-plans/{plan['id']}/execute").status_code == 401
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": "0" * 64, "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 409
    )
    approved = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        headers=human_operator_headers(client),
    )
    assert approved.status_code == 200
    assert approved.json()["approval_context"]["incident_status"] == "recovery_proposed"
    assert approved.json()["approval_context"]["approval_decision_id"]

    accounting.mode = "normal"
    executed = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "verifying"
    verified = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
    )
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts",
        headers=operator_headers(),
    ).json()["items"]
    assert attempts[0]["state"] == "VERIFIED"
    assert attempts[0]["transport_invocations"][0]["state"] == "EFFECT_PRESENT"
    assert attempts[0]["transport_invocations"][0]["reconciliation_generation"] == 1
    assert (
        attempts[0]["transport_invocations"][0]["safe_outcome"][
            "authoritative_reconciliation"
        ]["classification"]
        == "AVAILABLE_PRESENT"
    )
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 200
    )
    assert len(accounting.records) == 1
    resolved = client.get(f"/api/v1/incidents/{incident['id']}", headers=operator_headers()).json()
    assert resolved["status"] == "resolved"


def test_invariant_engine_covers_order_count_deadline_and_value_mismatch(setup) -> None:
    client, accounting, factory = setup
    now = stable_test_now()
    with factory() as session:
        service = FlowProofService(session, str(POLICY_PATH), accounting, now=lambda: now)
        for event_type, suffix, when, amount in (
            ("invoice.registration_requested", "requested", now - timedelta(minutes=2), 10.0),
            ("invoice.registration_acknowledged", "ack-1", now - timedelta(minutes=1), 10.0),
            ("invoice.registration_acknowledged", "ack-2", now - timedelta(seconds=50), 10.0),
            ("invoice.validated", "validated", now - timedelta(minutes=3), 10.0),
            ("invoice.verified", "verified", now - timedelta(minutes=1), 12.0),
        ):
            response = ingest(
                client, event_body(event_type, suffix, occurred_at=when, amount=amount)
            )
            assert response.status_code == 201
        policy = service.ensure_policy().definition
        events = list(
            session.query(
                __import__("flowproof.models", fromlist=["BusinessEvent"]).BusinessEvent
            ).all()
        )
        results = {
            item["id"]: service._evaluate_invariant(item, events) for item in policy["invariants"]
        }
    assert results["approval_before_registration"]["state"] == "violated"
    assert results["registration_ack_exactly_once"]["state"] == "violated"
    assert results["process_completes"]["state"] == "passed"
    assert results["validated_amount_matches_registered_amount"]["state"] == "violated"


def test_eventually_is_pending_before_and_violated_after_deadline(setup) -> None:
    client, accounting, factory = setup
    now = stable_test_now()
    response = ingest(
        client,
        event_body(
            "invoice.registration_acknowledged",
            "deadline-ack",
            correlation_id="deadline-order",
            occurred_at=now - timedelta(seconds=20),
        ),
    )
    assert response.status_code == 201
    with factory() as session:
        events = list(
            session.query(BusinessEvent)
            .filter(BusinessEvent.correlation_id == "deadline-order")
            .all()
        )
        eventually = next(
            item
            for item in FlowProofService(session, str(POLICY_PATH), accounting, now=lambda: now)
            .ensure_policy()
            .definition["invariants"]
            if item["id"] == "process_completes"
        )
        assert (
            FlowProofService(session, str(POLICY_PATH), accounting, now=lambda: now)._eventually(
                eventually, events
            )["state"]
            == "pending"
        )
        assert (
            FlowProofService(
                session, str(POLICY_PATH), accounting, now=lambda: now + timedelta(seconds=61)
            )._eventually(eventually, events)["state"]
            == "violated"
        )


def test_external_assertion_is_pending_before_and_violated_after_deadline(setup) -> None:
    client, accounting, factory = setup
    now = stable_test_now()
    acknowledgement = event_body(
        "invoice.registration_acknowledged",
        "external-deadline-ack",
        correlation_id="external-deadline-order",
        occurred_at=now - timedelta(seconds=20),
    )
    assert ingest(client, acknowledgement).status_code == 201
    with factory() as session:
        events = list(
            session.query(BusinessEvent)
            .filter(BusinessEvent.correlation_id == "external-deadline-order")
            .all()
        )
        invariant = next(
            item
            for item in FlowProofService(session, str(POLICY_PATH), accounting, now=lambda: now)
            .ensure_policy()
            .definition["invariants"]
            if item["id"] == "external_invoice_exists"
        )
        pending = FlowProofService(
            session, str(POLICY_PATH), accounting, now=lambda: now
        )._external_assertion(invariant, events)
        violated = FlowProofService(
            session, str(POLICY_PATH), accounting, now=lambda: now + timedelta(seconds=11)
        )._external_assertion(invariant, events)
    assert pending["state"] == "pending"
    assert violated["state"] == "violated"
    assert violated["message"] == "missing_external_invoice"


def test_deadline_job_observability_requires_the_operator_token(setup) -> None:
    client, _, _ = setup
    response = ingest(
        client,
        event_body(
            "invoice.registration_acknowledged",
            "deadline-observability-ack",
            correlation_id="deadline-observability",
        ),
    )
    assert response.status_code == 201
    assert client.get("/api/v1/deadline-jobs").status_code == 401
    jobs = client.get(
        "/api/v1/deadline-jobs",
        params={"correlation_id": "deadline-observability"},
        headers=operator_headers(),
    )
    assert jobs.status_code == 200
    items = jobs.json()["items"]
    assert {item["invariant_id"] for item in items} == {
        "external_invoice_exists",
        "process_completes",
    }
    detail = client.get(f"/api/v1/deadline-jobs/{items[0]['id']}", headers=operator_headers())
    assert detail.status_code == 200
    assert detail.json()["state"] == "pending"


def test_recovery_verification_fails_closed_on_delayed_write_without_reexecution(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    seed_false_200_path(client, occurred_at=stable_test_now() - timedelta(seconds=31))
    client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    incident = client.get("/api/v1/incidents", headers=operator_headers()).json()["items"][0]
    plan = incident["recovery_plan"]
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "delayed_write"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).json()["status"]
        == "verifying"
    )
    first_verification = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
    )
    assert first_verification.status_code == 200
    assert first_verification.json()["status"] == "needs_attention"
    current_incident = client.get(
        f"/api/v1/incidents/{incident['id']}", headers=operator_headers()
    ).json()
    assert current_incident["status"] == "needs_attention"
    assert len(accounting.request_keys) == 1

    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts",
        headers=operator_headers(),
    ).json()["items"]
    assert attempts[0]["state"] == "NEEDS_ATTENTION"
    assert attempts[0]["transport_invocations"][0]["state"] == "EFFECT_ABSENT"

    accounting.records[plan["parameters"]["invoice_id"]] = dict(plan["parameters"])
    second_verification = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
    )
    assert second_verification.status_code == 409
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "verifying"
    final_verification = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
    )
    assert final_verification.status_code == 200
    assert final_verification.json()["status"] == "verified"
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts",
        headers=operator_headers(),
    ).json()["items"]
    reservation = attempts[0]["transport_invocations"][0]
    assert reservation["state"] == "EFFECT_PRESENT"
    assert reservation["reconciliation_generation"] == 2
    assert len(accounting.request_keys) == 1


def test_recovery_verification_rejects_a_matching_record_for_another_invoice(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "normal"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 200
    )
    accounting.records[plan["parameters"]["invoice_id"]] = {
        **plan["parameters"],
        "invoice_id": "INV-OTHER",
    }
    verified = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
    )
    assert verified.status_code == 200
    assert verified.json()["status"] == "needs_attention"
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts",
        headers=operator_headers(),
    ).json()["items"]
    assert attempts[0]["state"] == "RECONCILED_CONFLICT"
    reservation = attempts[0]["transport_invocations"][0]
    assert reservation["state"] == "CONFLICT"
    assert reservation["safe_outcome"]["authoritative_reconciliation"]["records"][0][
        "invoice_id"
    ] == "INV-OTHER"


def test_approval_is_bound_to_the_current_incident_state(setup) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    seed_false_200_path(client, occurred_at=stable_test_now() - timedelta(seconds=31))
    client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    incident = client.get("/api/v1/incidents", headers=operator_headers()).json()["items"][0]
    plan = incident["recovery_plan"]

    missing_state = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"]},
        headers=human_operator_headers(client),
    )
    assert missing_state.status_code == 422

    with factory() as session:
        current_incident = session.get(Incident, incident["id"])
        assert current_incident is not None
        current_incident.status = "resolved"
        current_incident.resolved_at = stable_test_now()
        session.commit()

    stale = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
        headers=human_operator_headers(client),
    )
    assert stale.status_code == 409
    assert "incident state changed" in stale.json()["detail"]


def test_plan_content_tampering_invalidates_approval(setup) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    seed_false_200_path(client, occurred_at=stable_test_now() - timedelta(seconds=31))
    client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    incident = client.get("/api/v1/incidents", headers=operator_headers()).json()["items"][0]
    plan = incident["recovery_plan"]
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    with factory() as session:
        mutable_plan = session.get(RecoveryPlan, plan["id"])
        assert mutable_plan is not None
        mutable_plan.parameters = {**mutable_plan.parameters, "amount": 999999.0}
        session.commit()
    accounting.mode = "normal"
    rejected = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert rejected.status_code == 409
    assert "plan content changed" in rejected.json()["detail"]


def test_approval_context_tampering_blocks_execution(setup) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    seed_false_200_path(client, occurred_at=stable_test_now() - timedelta(seconds=31))
    client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    incident = client.get("/api/v1/incidents", headers=operator_headers()).json()["items"][0]
    plan = incident["recovery_plan"]
    approved = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        headers=human_operator_headers(client),
    )
    assert approved.status_code == 200

    with factory() as session:
        mutable_plan = session.get(RecoveryPlan, plan["id"])
        assert mutable_plan is not None
        mutable_plan.approval_context = {
            **mutable_plan.approval_context,
            "scope": "recovery:execute",
        }
        session.commit()

    accounting.mode = "normal"
    rejected = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert rejected.status_code == 409
    assert "approval context changed" in rejected.json()["detail"]


def test_invalid_policy_fails_with_a_clear_error(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("name: no-schema-version\ninvariants: []\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="policy schema validation failed"):
        load_policy(invalid, POLICY_PATH.with_name("policy.schema.json"))


def test_reject_is_append_only_idempotent_and_never_writes_to_provider(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    headers = {**human_operator_headers(client), "X-Request-ID": "reject-once"}
    payload = {
        "plan_hash": plan["plan_hash"],
        "incident_status": incident["status"],
        "reason_code": "operator_rejected",
        "note": "Evidence is insufficient",
    }
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/reject",
            json=payload,
            headers=operator_headers(),
        ).status_code
        == 403
    )
    first = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reject", json=payload, headers=headers
    )
    second = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reject", json=payload, headers=headers
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == "rejected"
    assert accounting.register_calls == 0
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert [item["action"] for item in decisions] == ["reject"]
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    client.post("/api/v1/correlations/order-8841/evaluate", headers=operator_headers())
    current = client.get(f"/api/v1/incidents/{incident['id']}", headers=operator_headers()).json()
    assert current["status"] == "recovery_rejected"
    assert current["recovery_plan"]["id"] == plan["id"]


def test_revoke_requires_no_dispatch_and_reapproval_preserves_genealogy(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    csrf = human_operator_headers(client)
    approved = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        headers={**csrf, "X-Request-ID": "approval-one"},
    )
    assert approved.status_code == 200
    revoked = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/revoke-approval",
        json={
            "plan_hash": plan["plan_hash"],
            "incident_status": "recovery_approved",
            "reason_code": "operator_withdrew_consent",
        },
        headers={**csrf, "X-Request-ID": "revoke-one"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "proposed"
    assert revoked.json()["approved_by"] is None
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    reapproved = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
        headers={**csrf, "X-Request-ID": "approval-two"},
    )
    assert reapproved.status_code == 200
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert [item["action"] for item in decisions] == [
        "approve",
        "revoke_approval",
        "approve",
    ]
    assert accounting.register_calls == 0


def test_expired_or_changed_approval_fails_closed_before_provider_call(setup) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    with factory() as session:
        row = session.get(RecoveryPlan, plan["id"])
        assert row is not None
        row.approval_expires_at = stable_test_now() - timedelta(seconds=1)
        session.commit()
    expired = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert expired.status_code == 409
    assert "expired" in expired.json()["detail"]
    current = client.get(f"/api/v1/recovery-plans/{plan['id']}", headers=operator_headers()).json()
    assert current["status"] == "proposed"
    assert current["approved_by"] is None
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert decisions[-1]["action"] == "approval_expired"
    assert decisions[-1]["decision_kind"] == "system"
    assert decisions[-1]["actor_principal_id"] is None
    assert accounting.register_calls == 0


def test_provider_contract_change_clears_unexecuted_approval(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.contract = ProviderContract(
        provider_id="mock-accounting",
        adapter_version="changed-test-fixture",
        environment="sandbox",
        contract_version="fixture-2",
        sandbox_only=True,
        authoritative_read={"not_found": "AVAILABLE_ABSENT"},
        authentication={"mode": "none-test-fixture", "credential_reference": "not-applicable"},
        rate_limits={"classification": "UNVERIFIED"},
        idempotency={"support": "CONTRACT_TESTED"},
        duplicate_guarantees={"classification": "CONTRACT_TESTED"},
        write_acceptance={"classification": "CONTRACT_TESTED"},
        read_after_write={"consistency": "strong-test-fixture"},
        maximum_safe_write_attempts=1,
        evidence_classification={"overall": "TEST_FIXTURE_ONLY"},
    )
    response = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert response.status_code == 409
    assert "provider contract changed" in response.json()["detail"]
    current = client.get(f"/api/v1/recovery-plans/{plan['id']}", headers=operator_headers()).json()
    assert current["status"] == "proposed"
    assert current["approved_by"] is None
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert decisions[-1]["action"] == "approval_invalidated"
    assert decisions[-1]["decision_kind"] == "system"
    assert accounting.register_calls == 0


def test_revised_plan_supersedes_revoked_binding_and_keeps_capsule_verifiable(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    csrf = human_operator_headers(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers={**csrf, "X-Request-ID": "superseded-approval"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/revoke-approval",
            json={
                "plan_hash": plan["plan_hash"],
                "incident_status": "recovery_approved",
                "reason_code": "operator_withdrew_consent",
            },
            headers={**csrf, "X-Request-ID": "superseded-revoke"},
        ).status_code
        == 200
    )
    contract_values = ProviderContract.load(PROVIDER_CONTRACT_PATH).to_manifest()
    contract_values.pop("sha256")
    accounting.contract = ProviderContract(
        **{**contract_values, "adapter_version": "revised-test-fixture"}
    )
    assert (
        client.post(
            "/api/v1/correlations/order-8841/evaluate", headers=operator_headers()
        ).status_code
        == 200
    )
    current = client.get(
        f"/api/v1/recovery-plans/{plan['id']}", headers=operator_headers()
    ).json()
    assert current["status"] == "proposed"
    assert current["plan_hash"] != plan["plan_hash"]
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert [item["action"] for item in decisions] == [
        "approve",
        "revoke_approval",
        "plan_binding_superseded",
    ]
    capsule = tmp_path / "superseded-plan.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_unknown_outcome_reconciles_before_any_duplicate_write(setup) -> None:
    client, accounting, _ = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "outcome_unknown_applied"
    ambiguous = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert ambiguous.status_code == 409
    assert accounting.register_calls == 1
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts", headers=operator_headers()
    ).json()["items"]
    assert len(attempts) == 1
    assert attempts[0]["state"] == "OUTCOME_UNKNOWN"
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "verifying"
    assert accounting.register_calls == 1


@pytest.mark.parametrize("provider_mode", ["outcome_unknown_absent", "pre_acceptance_failure"])
def test_unproven_outcome_with_unverified_idempotency_never_blindly_retries(
    setup, provider_mode: str
) -> None:
    client, accounting, _ = setup
    contract_values = ProviderContract.load(PROVIDER_CONTRACT_PATH).to_manifest()
    contract_values.pop("sha256")
    accounting.contract = ProviderContract(
        **{
            **contract_values,
            "idempotency": {"support": "UNVERIFIED", "scope": "invoice-create"},
            "maximum_safe_write_attempts": 2,
        }
    )
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = provider_mode
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    assert accounting.register_calls == 1
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "needs_attention"
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts", headers=operator_headers()
    ).json()["items"]
    assert attempts[0]["state"] == "NEEDS_ATTENTION"
    assert attempts[0]["retry_permitted"] is False
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    assert accounting.register_calls == 1


def test_crash_after_durable_intent_stays_reconciliation_required(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "crash_after_dispatch"
    crashed = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute",
        headers=operator_headers(),
    )
    assert crashed.status_code == 409
    assert "authoritative reconciliation is required" in crashed.json()["detail"]
    with factory() as session:
        attempt = session.query(RecoveryAttempt).filter_by(recovery_plan_id=plan["id"]).one()
        assert attempt.state == "OUTCOME_UNKNOWN"
        assert attempt.transport_invocation_count == 1
        assert attempt.safe_result["write_outcome"]["classification"] == (
            "POST_ACCEPTANCE_OUTCOME_UNKNOWN"
        )
        dispatch_capsule = tmp_path / "dispatch-crash.zip"
        export_capsule(session, incident["id"], dispatch_capsule)
    assert verify_with_declared_anchor(dispatch_capsule)["status"] == "VALID"
    impossible_dispatch = tmp_path / "dispatch-without-reservation.zip"
    rewrite_capsule_member(
        dispatch_capsule,
        impossible_dispatch,
        "recovery-attempts.json",
        lambda value: [{**value[0], "transport_invocation_count": 0}],
    )
    with pytest.raises(EvidenceError, match="transport reservation ledger|state requires"):
        verify_with_declared_anchor(impossible_dispatch)
    assert accounting.register_calls == 1
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    assert accounting.register_calls == 1
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "needs_attention"
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts", headers=operator_headers()
    ).json()["items"]
    assert attempts[0]["transport_invocation_count"] == 1
    assert attempts[0]["retry_permitted"] is False
    assert accounting.register_calls == 1


def test_dispatch_crash_with_transport_room_requires_reapproval_and_valid_evidence(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "crash_after_dispatch"
    crashed = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute",
        headers=operator_headers(),
    )
    assert crashed.status_code == 409
    assert "authoritative reconciliation is required" in crashed.json()["detail"]
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "proposed"
    capsule = tmp_path / "dispatch-crash-reapproval-required.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_prepared_crash_checkpoint_is_valid_evidence(
    setup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )

    original_dispatch = FlowProofService._dispatch_attempt

    def crash_after_prepared(*args: object, **kwargs: object) -> RecoveryPlan:
        del args, kwargs
        raise RuntimeError("injected crash after prepared intent")

    monkeypatch.setattr(FlowProofService, "_dispatch_attempt", crash_after_prepared)
    with pytest.raises(RuntimeError, match="after prepared intent"):
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        )
    monkeypatch.setattr(FlowProofService, "_dispatch_attempt", original_dispatch)
    capsule = tmp_path / "prepared-crash.zip"
    with factory() as session:
        attempt = session.query(RecoveryAttempt).filter_by(recovery_plan_id=plan["id"]).one()
        assert attempt.state == "PREPARED"
        assert attempt.transport_invocation_count == 0
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"

    original_completion = FlowProofService._complete_reconciliation

    def crash_after_reconciling(*args: object, **kwargs: object) -> RecoveryPlan:
        del args, kwargs
        raise RuntimeError("injected crash after reconciling checkpoint")

    monkeypatch.setattr(
        FlowProofService,
        "_complete_reconciliation",
        crash_after_reconciling,
    )
    with pytest.raises(RuntimeError, match="reconciling checkpoint"):
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/reconcile",
            json={"plan_hash": plan["plan_hash"]},
            headers=operator_headers(),
        )
    monkeypatch.setattr(
        FlowProofService,
        "_complete_reconciliation",
        original_completion,
    )
    with factory() as session:
        attempt = session.query(RecoveryAttempt).filter_by(recovery_plan_id=plan["id"]).one()
        assert attempt.state == "RECONCILING"
        assert attempt.transport_invocation_count == 0
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "proposed"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "normal"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).json()["status"]
        == "verifying"
    )
    reapproved_capsule = tmp_path / "prepared-crash-reapproved.zip"
    with factory() as session:
        export_capsule(session, incident["id"], reapproved_capsule)
    assert verify_with_declared_anchor(reapproved_capsule)["status"] == "VALID"


@pytest.mark.parametrize(
    ("provider_mode", "checkpoint"),
    [
        ("outcome_unknown_absent", "RECONCILING"),
        ("outcome_unknown_applied", "VERIFYING"),
    ],
)
def test_reconciliation_crash_checkpoints_are_valid_evidence(
    setup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_mode: str,
    checkpoint: str,
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = provider_mode
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )

    original_completion = FlowProofService._complete_reconciliation

    def crash_at_checkpoint(
        self: FlowProofService,
        *args: object,
        **kwargs: object,
    ) -> RecoveryPlan:
        if checkpoint == "VERIFYING":
            original_completion(self, *args, **kwargs)
        raise RuntimeError(f"injected crash at {checkpoint}")

    monkeypatch.setattr(
        FlowProofService,
        "_complete_reconciliation",
        crash_at_checkpoint,
    )
    with pytest.raises(RuntimeError, match=checkpoint):
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/reconcile",
            json={"plan_hash": plan["plan_hash"]},
            headers=operator_headers(),
        )
    monkeypatch.setattr(
        FlowProofService,
        "_complete_reconciliation",
        original_completion,
    )
    capsule = tmp_path / f"{checkpoint.lower()}-crash.zip"
    with factory() as session:
        attempt = session.query(RecoveryAttempt).filter_by(recovery_plan_id=plan["id"]).one()
        assert attempt.state == checkpoint
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"
    if checkpoint == "RECONCILING":
        with factory() as session:
            attempt = session.query(RecoveryAttempt).filter_by(
                recovery_plan_id=plan["id"]
            ).one()
            reservation = attempt.active_transport_invocation_id
            assert reservation is not None
            row = session.get(RecoveryTransportInvocation, reservation)
            assert row is not None
            row.reconciliation_started_at = stable_test_now() - timedelta(seconds=120)
            row.reconciliation_lease_expires_at = stable_test_now() - timedelta(seconds=60)
            session.commit()
    resumed = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert resumed.status_code == 200
    assert resumed.json()["status"] == (
        "proposed" if checkpoint == "RECONCILING" else "verifying"
    )
    resumed_capsule = tmp_path / f"{checkpoint.lower()}-resumed.zip"
    with factory() as session:
        export_capsule(session, incident["id"], resumed_capsule)
    assert verify_with_declared_anchor(resumed_capsule)["status"] == "VALID"


def test_crash_after_provider_effect_reconciles_by_read_without_duplicate_write(setup) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "crash_after_effect"
    crashed = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute",
        headers=operator_headers(),
    )
    assert crashed.status_code == 409
    assert "authoritative reconciliation is required" in crashed.json()["detail"]
    with factory() as session:
        attempt = session.query(RecoveryAttempt).filter_by(recovery_plan_id=plan["id"]).one()
        assert attempt.state == "OUTCOME_UNKNOWN"
    assert accounting.register_calls == 1
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "verifying"
    assert accounting.register_calls == 1


def test_crash_after_accepted_outcome_commit_recovers_from_durable_accepted_state(
    setup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )

    original_advance = FlowProofService._advance_accepted_to_verifying

    def crash_after_accepted(
        self: FlowProofService,
        claim: object,
    ) -> RecoveryPlan:
        del self, claim
        raise RuntimeError("injected crash after accepted outcome commit")

    accounting.mode = "normal"
    monkeypatch.setattr(
        FlowProofService,
        "_advance_accepted_to_verifying",
        crash_after_accepted,
    )
    with pytest.raises(RuntimeError, match="after accepted outcome commit"):
        client.post(f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers())
    monkeypatch.setattr(
        FlowProofService,
        "_advance_accepted_to_verifying",
        original_advance,
    )
    with factory() as session:
        attempt = session.query(RecoveryAttempt).filter_by(recovery_plan_id=plan["id"]).one()
        persisted_plan = session.get(RecoveryPlan, plan["id"])
        assert attempt.state == "ACCEPTED"
        assert persisted_plan is not None and persisted_plan.status == "executing"
    assert accounting.register_calls == 1
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "verifying"
    assert accounting.register_calls == 1


def test_revoke_after_durable_attempt_is_refused_and_requires_reconciliation(setup) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    csrf = human_operator_headers(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=csrf,
        ).status_code
        == 200
    )
    now = stable_test_now()
    with factory() as session:
        persisted_plan = session.get(RecoveryPlan, plan["id"])
        assert persisted_plan is not None
        session.add(
            RecoveryAttempt(
                id="durable-attempt-before-revoke",
                recovery_plan_id=plan["id"],
                incident_id=incident["id"],
                approval_decision_id=persisted_plan.approval_context[
                    "approval_decision_id"
                ],
                attempt_ordinal=1,
                execution_idempotency_key="durable-attempt-before-revoke-key",
                plan_hash=plan["plan_hash"],
                provider_contract_digest=plan["provider_contract_digest"],
                provider_id=plan["provider_id"],
                provider_environment=plan["provider_environment"],
                adapter_version=plan["adapter_version"],
                request_digest="1" * 64,
                precondition_observation_digest="2" * 64,
                state="DISPATCHING",
                semantic_attempt_count=1,
                transport_invocation_count=0,
                retry_permitted=False,
                safe_result={},
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()
    revoked = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/revoke-approval",
        json={
            "plan_hash": plan["plan_hash"],
            "incident_status": "recovery_approved",
            "reason_code": "operator_withdrew_consent",
        },
        headers=csrf,
    )
    assert revoked.status_code == 409
    assert "reconcile" in revoked.json()["detail"]
    assert accounting.register_calls == 0


def test_contract_tested_idempotency_allows_one_same_key_transport_retry(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    csrf = human_operator_headers(client)
    assert plan["guardrails"]["maximum_transport_invocations"] == 2
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers={**csrf, "X-Request-ID": "first-transport-approval"},
        ).status_code
        == 200
    )
    accounting.mode = "pre_acceptance_failure"
    first = client.post(f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers())
    assert first.status_code == 409
    assert accounting.register_calls == 1
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "proposed"
    retry_required_capsule = tmp_path / "retry-required.zip"
    with factory() as session:
        export_capsule(session, incident["id"], retry_required_capsule)
    assert verify_with_declared_anchor(retry_required_capsule)["status"] == "VALID"
    missing_reconciliation = tmp_path / "retry-without-reconciliation-observation.zip"
    rewrite_capsule_member(
        retry_required_capsule,
        missing_reconciliation,
        "recovery-attempts.json",
        lambda values: [
            {
                **values[0],
                "safe_result": {
                    key: value
                    for key, value in values[0]["safe_result"].items()
                    if key != "reconciliation_observation"
                },
            }
        ],
    )
    with pytest.raises(EvidenceError, match="does not preserve its latest reconciliation proof"):
        verify_with_declared_anchor(missing_reconciliation)
    missing_write_outcome = tmp_path / "retry-without-write-outcome.zip"

    def forge_missing_provider_outcome(
        values: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        attempt = values[0]
        history = [
            {
                **attempt["safe_result"]["reconciliation_history"][0],
                "retry_reason": "pre_acceptance_failure_proven",
                "write_outcome": None,
            }
        ]
        return [
            {
                **attempt,
                "outcome_classification": "PRE_ACCEPTANCE_FAILURE",
                "retry_reason": "pre_acceptance_failure_proven",
                "safe_result": {
                    **attempt["safe_result"],
                    "reconciliation_history": history,
                },
            }
        ]

    rewrite_capsule_member(
        retry_required_capsule,
        missing_write_outcome,
        "recovery-attempts.json",
        forge_missing_provider_outcome,
    )
    with pytest.raises(EvidenceError, match="lacks its transport outcome"):
        verify_with_declared_anchor(missing_write_outcome)
    with zipfile.ZipFile(retry_required_capsule) as archive:
        reserved_at = json.loads(archive.read("transport-invocations.json"))[0][
            "reserved_at"
        ]
    early_write_outcome = tmp_path / "retry-with-early-write-outcome.zip"

    def forge_early_write_outcome(
        values: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        attempt = values[0]
        history_entry = attempt["safe_result"]["reconciliation_history"][0]
        outcome = {
            **history_entry["write_outcome"],
            "classification": "PRE_ACCEPTANCE_FAILURE",
            "observed_at": (
                datetime.fromisoformat(reserved_at.replace("Z", "+00:00"))
                - timedelta(days=1)
            )
            .isoformat()
            .replace("+00:00", "Z"),
        }
        outcome["content_digest"] = object_digest(
            {key: value for key, value in outcome.items() if key != "content_digest"}
        )
        return [
            {
                **attempt,
                "outcome_classification": "PRE_ACCEPTANCE_FAILURE",
                "retry_reason": "pre_acceptance_failure_proven",
                "safe_result": {
                    **attempt["safe_result"],
                    "reconciliation_history": [
                        {
                            **history_entry,
                            "retry_reason": "pre_acceptance_failure_proven",
                            "write_outcome": outcome,
                        }
                    ],
                },
            }
        ]

    rewrite_capsule_member(
        retry_required_capsule,
        early_write_outcome,
        "recovery-attempts.json",
        forge_early_write_outcome,
    )
    with pytest.raises(EvidenceError, match="not causally ordered"):
        verify_with_declared_anchor(early_write_outcome)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers={**csrf, "X-Request-ID": "second-transport-approval"},
        ).status_code
        == 200
    )
    retry_approved_capsule = tmp_path / "retry-approved.zip"
    with factory() as session:
        export_capsule(session, incident["id"], retry_approved_capsule)
    assert verify_with_declared_anchor(retry_approved_capsule)["status"] == "VALID"
    missing_retry_grant = tmp_path / "retry-approved-without-grant.zip"
    rewrite_capsule_member(
        retry_approved_capsule,
        missing_retry_grant,
        "recovery-decisions.json",
        lambda value: [value[0]],
    )
    with pytest.raises(EvidenceError, match="effective approval|effect-absent attempt lacks"):
        verify_with_declared_anchor(missing_retry_grant)
    accounting.mode = "normal"
    second = client.post(f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers())
    assert second.status_code == 200
    assert second.json()["status"] == "verifying"
    attempts = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/attempts", headers=operator_headers()
    ).json()["items"]
    assert len(attempts) == 1
    assert attempts[0]["semantic_attempt_count"] == 1
    assert attempts[0]["transport_invocation_count"] == 2
    assert attempts[0]["execution_idempotency_key"] == plan["idempotency_key"]
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert attempts[0]["approval_decision_id"] == decisions[0]["id"]
    assert accounting.register_calls == 2
    retry_consumed_capsule = tmp_path / "retry-consumed.zip"
    with factory() as session:
        export_capsule(session, incident["id"], retry_consumed_capsule)
    assert verify_with_declared_anchor(retry_consumed_capsule)["status"] == "VALID"
    missing_history = tmp_path / "retry-consumed-without-history.zip"
    rewrite_capsule_member(
        retry_consumed_capsule,
        missing_history,
        "recovery-attempts.json",
        lambda values: [
            {
                **values[0],
                "safe_result": {
                    key: value
                    for key, value in values[0]["safe_result"].items()
                    if key != "reconciliation_history"
                },
            }
        ],
    )
    with pytest.raises(EvidenceError, match="complete reconciliation history"):
        verify_with_declared_anchor(missing_history)

    erased_first_transport = tmp_path / "retry-erased-first-transport-stage.zip"
    rewrite_capsule_member(
        retry_consumed_capsule,
        erased_first_transport,
        "transport-invocations.json",
        lambda values: [{**values[1], "invocation_ordinal": 1}],
    )
    erased_first_transport_capsule = tmp_path / "retry-erased-first-transport.zip"
    rewrite_capsule_member(
        erased_first_transport,
        erased_first_transport_capsule,
        "recovery-attempts.json",
        lambda values: [{**values[0], "transport_invocation_count": 1}],
    )
    with pytest.raises(EvidenceError, match="lacks its reapproval grant"):
        verify_with_declared_anchor(erased_first_transport_capsule)


def test_exhausted_transport_retry_preserves_valid_reconciliation_evidence(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    incident, plan, csrf = effect_absent_retry_required(client, accounting)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers={**csrf, "X-Request-ID": "exhausted-retry-approval"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    exhausted = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert exhausted.status_code == 200
    assert exhausted.json()["status"] == "needs_attention"
    capsule = tmp_path / "exhausted-retry-needs-attention.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_retry_effect_present_reconciliation_preserves_prior_retry_proof(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    incident, plan, csrf = effect_absent_retry_required(client, accounting)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers={**csrf, "X-Request-ID": "effect-present-retry-approval"},
        ).status_code
        == 200
    )
    accounting.mode = "outcome_unknown_applied"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    reconciled = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "verifying"
    capsule = tmp_path / "retry-effect-present-verifying.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_open_retry_grant_can_be_rejected_and_capsule_remains_valid(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    incident, plan, csrf = effect_absent_retry_required(client, accounting)
    rejected = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reject",
        json={
            "plan_hash": plan["plan_hash"],
            "incident_status": "recovery_proposed",
            "reason_code": "operator_declined_retry",
        },
        headers={**csrf, "X-Request-ID": "reject-open-retry-grant"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    capsule = tmp_path / "rejected-open-retry.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_unconsumed_retry_reapproval_can_be_revoked_and_capsule_remains_valid(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    incident, plan, csrf = effect_absent_retry_required(client, accounting)
    approved = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
        headers={**csrf, "X-Request-ID": "approve-unconsumed-retry"},
    )
    assert approved.status_code == 200
    revoked = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/revoke-approval",
        json={
            "plan_hash": plan["plan_hash"],
            "incident_status": "recovery_approved",
            "reason_code": "operator_withdrew_retry_consent",
        },
        headers={**csrf, "X-Request-ID": "revoke-unconsumed-retry"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "proposed"
    assert revoked.json()["approved_by"] is None
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 409
    )
    decisions = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert [item["action"] for item in decisions] == [
        "approve",
        "retry_reapproval_required",
        "approve",
        "revoke_approval",
    ]
    capsule = tmp_path / "revoked-unconsumed-retry.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_unconsumed_retry_reapproval_can_expire_and_be_reapproved(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    incident, plan, csrf = effect_absent_retry_required(client, accounting)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers={**csrf, "X-Request-ID": "retry-approval-before-expiry"},
        ).status_code
        == 200
    )
    decisions_before = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    blocked_reconcile = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reconcile",
        json={"plan_hash": plan["plan_hash"]},
        headers=operator_headers(),
    )
    assert blocked_reconcile.status_code == 409
    assert "retry approval is active" in blocked_reconcile.json()["detail"]
    decisions_after = client.get(
        f"/api/v1/recovery-plans/{plan['id']}/decisions", headers=operator_headers()
    ).json()["items"]
    assert decisions_after == decisions_before
    with factory() as session:
        row = session.get(RecoveryPlan, plan["id"])
        assert row is not None
        row.approval_expires_at = stable_test_now() - timedelta(seconds=1)
        session.commit()
    expired = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert expired.status_code == 409
    assert "expired" in expired.json()["detail"]
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers={**csrf, "X-Request-ID": "retry-reapproval-after-expiry"},
        ).status_code
        == 200
    )
    capsule = tmp_path / "retry-reapproved-after-expiry.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_contract_drift_clears_unconsumed_retry_authority_and_allows_rejection(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    incident, plan, csrf = effect_absent_retry_required(client, accounting)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": "recovery_proposed"},
            headers={**csrf, "X-Request-ID": "retry-approval-before-contract-drift"},
        ).status_code
        == 200
    )
    changed_contract = ProviderContract.load(PROVIDER_CONTRACT_PATH).to_manifest()
    changed_contract.pop("sha256")
    accounting.contract = ProviderContract(
        **{
            **changed_contract,
            "adapter_version": "changed-after-retry-approval",
            "contract_version": "fixture-contract-drift",
        }
    )
    invalidated = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
    )
    assert invalidated.status_code == 409
    assert "provider contract changed" in invalidated.json()["detail"]
    current = client.get(
        f"/api/v1/recovery-plans/{plan['id']}", headers=operator_headers()
    ).json()
    assert current["status"] == "proposed"
    assert current["approved_by"] is None
    rejected = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/reject",
        json={
            "plan_hash": plan["plan_hash"],
            "incident_status": "recovery_proposed",
            "reason_code": "operator_terminated_stale_retry",
        },
        headers={**csrf, "X-Request-ID": "reject-invalidated-retry-grant"},
    )
    assert rejected.status_code == 200
    capsule = tmp_path / "contract-drift-retry-rejected.zip"
    with factory() as session:
        export_capsule(session, incident["id"], capsule)
    assert verify_with_declared_anchor(capsule)["status"] == "VALID"


def test_evidence_capsule_is_deterministic_sanitized_and_review_bound(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    csrf = human_operator_headers(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers={**csrf, "X-Request-ID": "evidence-approval"},
        ).status_code
        == 200
    )
    first_path = tmp_path / "first.zip"
    second_path = tmp_path / "second.zip"
    with factory() as session:
        first = export_capsule(session, incident["id"], first_path)
        second = export_capsule(session, incident["id"], second_path)
    assert first["zip_sha256"] == second["zip_sha256"]
    assert first_path.read_bytes() == second_path.read_bytes()
    assert verify_with_declared_anchor(first_path)["status"] == "VALID"
    with zipfile.ZipFile(first_path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert set(names) == EXPECTED_CAPSULE_MEMBERS
        manifest_document = json.loads(archive.read("manifest.json"))
        plan_document = json.loads(archive.read("recovery-plan.json"))
        decision_document = json.loads(archive.read("recovery-decisions.json"))[0]
    assert manifest_document["package_version"] == "0.6.0"
    assert manifest_document["migration_head"] == "0010_release_groundwork_fencing"
    assert manifest_document["git_commit"] == TEST_GIT_COMMIT
    assert manifest_document["git_tree"] == TEST_GIT_TREE
    assert set(plan_document["approval_actor"]) == {"bundle_scoped_digest"}
    assert set(decision_document["actor"]) == {"bundle_scoped_digest"}
    assert "human-operator" not in first_path.read_bytes().decode("latin1")

    retry_plan = tmp_path / "retry-without-attempt-plan.zip"
    retry_incident = tmp_path / "retry-without-attempt-incident.zip"
    retry_without_attempt = tmp_path / "retry-without-attempt.zip"
    rewrite_capsule_member(
        first_path,
        retry_plan,
        "recovery-plan.json",
        lambda value: {
            **value,
            "status": "proposed",
            "approval_actor": None,
            "approved_at": None,
            "approval_expires_at": None,
        },
    )
    rewrite_capsule_member(
        retry_plan,
        retry_incident,
        "incident.json",
        lambda value: {**value, "status": "recovery_proposed"},
    )

    def append_unbacked_retry(value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        approval = value[-1]
        return [
            *value,
            {
                **approval,
                "id": "forged-retry-without-attempt",
                "request_id_digest": "e" * 64,
                "action": "retry_reapproval_required",
                "decision_kind": "system",
                "actor": {"system": "flowproof"},
                "authorization_scope": "system:approval_lifecycle",
                "approval_expires_at": None,
                "reason_code": "forged_retry_without_attempt",
                "previous_plan_state": "needs_attention",
                "resulting_plan_state": "proposed",
                "previous_incident_state": "needs_attention",
                "resulting_incident_state": "recovery_proposed",
                "decided_at": (
                    datetime.fromisoformat(approval["decided_at"].replace("Z", "+00:00"))
                    + timedelta(microseconds=1)
                ).isoformat().replace("+00:00", "Z"),
            },
        ]

    rewrite_capsule_member(
        retry_incident,
        retry_without_attempt,
        "recovery-decisions.json",
        append_unbacked_retry,
    )
    with pytest.raises(EvidenceError, match="retry reapproval transition requires"):
        verify_with_declared_anchor(retry_without_attempt)

    private_path = tmp_path / "owner-private.zip"
    with factory() as session:
        private = export_capsule(session, incident["id"], private_path, private_identity=True)
    assert private["identity_mode"] == "owner-private"
    assert "human-operator" in private_path.read_bytes().decode("latin1")

    review = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/operator-review",
        json={
            "plan_hash": plan["plan_hash"],
            "capsule_digest": first["review_subject_sha256"],
            "evidence_understood": True,
            "authoritative_source_understood": True,
            "blast_radius_understood": True,
            "proposed_action_understood": True,
            "reject_path_available": True,
            "revoke_path_available": True,
            "reconciliation_path_understood": True,
            "final_decision": "approve",
            "note": "Reviewed bounded sandbox evidence",
        },
        headers={**csrf, "X-Request-ID": "operator-review-one"},
    )
    assert review.status_code == 200
    assert review.json()["verdict"] == "BLOCKED_EXTERNAL"
    final_path = tmp_path / "final.zip"
    with factory() as session:
        final = export_capsule(session, incident["id"], final_path)
    assert final["review_subject_sha256"] == first["review_subject_sha256"]
    assert verify_with_declared_anchor(final_path)["status"] == "VALID"


def test_terminal_proof_cannot_downgrade_to_checkpoint(
    setup,
    tmp_path: Path,
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    approved = client.post(
        f"/api/v1/recovery-plans/{plan['id']}/approve",
        json={
            "plan_hash": plan["plan_hash"],
            "incident_status": incident["status"],
        },
        headers=human_operator_headers(client),
    )
    assert approved.status_code == 200
    accounting.mode = "normal"
    assert client.post(
        f"/api/v1/recovery-plans/{plan['id']}/execute",
        headers=operator_headers(),
    ).status_code == 200
    assert client.post(
        f"/api/v1/recovery-plans/{plan['id']}/verify",
        headers=operator_headers(),
    ).status_code == 200

    terminal = tmp_path / "terminal-proof.zip"
    with factory() as session:
        export_capsule(session, incident["id"], terminal)
    with zipfile.ZipFile(terminal) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["proof_type"] == PROOF_WRITE

    downgraded = tmp_path / "terminal-as-checkpoint.zip"
    rewrite_capsule_member(
        terminal,
        downgraded,
        "recovery-plan.json",
        lambda value: value,
        proof_type=PROOF_CHECKPOINT,
    )
    with pytest.raises(
        EvidenceError,
        match="durable checkpoint incorrectly claims a terminal lifecycle",
    ):
        verify_with_declared_anchor(downgraded)


def test_evidence_capsule_rejects_undeclared_zip_member(
    setup,
    tmp_path: Path,
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, _ = proposed_recovery(client)
    source = tmp_path / "exact-members.zip"
    with factory() as session:
        export_capsule(session, incident["id"], source)

    undeclared = tmp_path / "undeclared-member.zip"
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(
        undeclared,
        "w",
    ) as changed:
        for info in original.infolist():
            changed.writestr(info, original.read(info.filename))
        changed.writestr("undeclared.json", b"{}\n")
    with pytest.raises(
        EvidenceError,
        match="actual ZIP members do not exactly match",
    ):
        verify_with_declared_anchor(undeclared)


def test_evidence_capsule_rejects_duplicate_declaration_and_zip_name(
    setup,
    tmp_path: Path,
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, _ = proposed_recovery(client)
    source = tmp_path / "unique-members.zip"
    with factory() as session:
        export_capsule(session, incident["id"], source)

    duplicate_name = tmp_path / "duplicate-name.zip"
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(
        duplicate_name,
        "w",
    ) as changed:
        for info in original.infolist():
            changed.writestr(info, original.read(info.filename))
        with pytest.warns(UserWarning, match="Duplicate name"):
            changed.writestr(
                "incident.json",
                original.read("incident.json"),
            )
    with pytest.raises(
        EvidenceError,
        match="duplicate ZIP names",
    ):
        verify_with_declared_anchor(duplicate_name)

    duplicate_declaration = tmp_path / "duplicate-declaration.zip"
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(
        duplicate_declaration,
        "w",
    ) as changed:
        manifest = json.loads(original.read("manifest.json"))
        manifest["files"].append(dict(manifest["files"][0]))
        encoded_manifest = (
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        for info in original.infolist():
            content = (
                encoded_manifest
                if info.filename == "manifest.json"
                else original.read(info.filename)
            )
            changed.writestr(info, content)
    with pytest.raises(
        EvidenceError,
        match="duplicate declarations",
    ):
        verify_with_declared_anchor(duplicate_declaration)


def test_evidence_cli_reports_bounded_invalid_and_exit_one(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = evidence_main(
        [
            "verify",
            "--input",
            str(tmp_path / "missing.zip"),
            "--expected-bundle-sha256",
            "a" * 64,
            "--expected-git-commit",
            TEST_GIT_COMMIT,
            "--expected-git-tree",
            TEST_GIT_TREE,
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert exit_code == 1
    assert captured.out == ""
    assert payload["status"] == "INVALID"
    assert len(payload["message"]) <= 256


def test_evidence_capsule_rejects_tampering_traversal_and_raw_secrets(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, _ = proposed_recovery(client)
    source = tmp_path / "source.zip"
    with factory() as session:
        export_capsule(session, incident["id"], source)

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(tampered, "w") as changed:
        for name in original.namelist():
            content = original.read(name)
            if name == "incident.json":
                content += b" "
            changed.writestr(name, content)
    with pytest.raises(EvidenceError, match="digest or size mismatch"):
        verify_with_declared_anchor(tampered)

    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../manifest.json", "{}")
    with pytest.raises(EvidenceError, match="unsafe member"):
        verify_capsule(
            traversal,
            expected_bundle_sha256="0" * 64,
            expected_git_commit=TEST_GIT_COMMIT,
            expected_git_tree=TEST_GIT_TREE,
        )

    with factory() as session:
        row = session.get(Incident, incident["id"])
        assert row is not None
        row.evidence = {**row.evidence, "api_key": "sk-not-safe-in-evidence-capsule"}
        session.commit()
        with pytest.raises(EvidenceError, match="forbidden evidence field"):
            export_capsule(session, incident["id"], tmp_path / "secret.zip")


def test_evidence_capsule_recomputes_provider_plan_decision_and_attempt_bindings(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "normal"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 200
    )
    source = tmp_path / "bound-source.zip"
    with factory() as session:
        source_result = export_capsule(session, incident["id"], source)

    provider_tamper = tmp_path / "provider-tamper.zip"
    rewrite_capsule_member(
        source,
        provider_tamper,
        "provider-contract.json",
        lambda value: {**value, "adapter_version": "attacker-changed"},
    )
    with pytest.raises(EvidenceError, match="external bundle trust anchor mismatch"):
        verify_capsule(
            provider_tamper,
            expected_bundle_sha256=source_result["bundle_sha256"],
            expected_git_commit=TEST_GIT_COMMIT,
            expected_git_tree=TEST_GIT_TREE,
        )
    with pytest.raises(EvidenceError, match="provider contract content digest mismatch"):
        verify_with_declared_anchor(provider_tamper)

    plan_tamper = tmp_path / "plan-tamper.zip"
    rewrite_capsule_member(
        source,
        plan_tamper,
        "recovery-plan.json",
        lambda value: {**value, "parameters": {**value["parameters"], "amount": 1}},
    )
    with pytest.raises(EvidenceError, match="recovery amount is outside"):
        verify_with_declared_anchor(plan_tamper)

    decision_tamper = tmp_path / "decision-tamper.zip"
    rewrite_capsule_member(
        source,
        decision_tamper,
        "recovery-decisions.json",
        lambda value: [{**value[0], "plan_hash": "0" * 64}],
    )
    with pytest.raises(EvidenceError, match="unaccounted historical plan binding"):
        verify_with_declared_anchor(decision_tamper)

    attempt_tamper = tmp_path / "attempt-tamper.zip"
    rewrite_capsule_member(
        source,
        attempt_tamper,
        "recovery-attempts.json",
        lambda value: [{**value[0], "request_digest": "0" * 64}],
    )
    with pytest.raises(EvidenceError, match="attempt request digest mismatch"):
        verify_with_declared_anchor(attempt_tamper)

    approval_binding_tamper = tmp_path / "attempt-approval-binding-tamper.zip"
    rewrite_capsule_member(
        source,
        approval_binding_tamper,
        "recovery-attempts.json",
        lambda value: [{**value[0], "approval_decision_id": "missing-approval"}],
    )
    with pytest.raises(EvidenceError, match="attempt approval binding is invalid"):
        verify_with_declared_anchor(approval_binding_tamper)

    invocation_genealogy_tamper = tmp_path / "attempt-invocation-genealogy-tamper.zip"
    rewrite_capsule_member(
        source,
        invocation_genealogy_tamper,
        "recovery-attempts.json",
        lambda value: [{**value[0], "transport_invocation_count": 2}],
    )
    with pytest.raises(EvidenceError, match="transport reservation ledger"):
        verify_with_declared_anchor(invocation_genealogy_tamper)


def test_evidence_capsule_rejects_rehashed_semantic_authority_forgery(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.contract = ProviderContract.load(PROVIDER_CONTRACT_PATH)
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "normal"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
        ).json()["status"]
        == "verified"
    )
    source = tmp_path / "semantic-authority-source.zip"
    with factory() as session:
        export_capsule(session, incident["id"], source)
    assert verify_with_declared_anchor(source)["status"] == "VALID"

    wrong_source_event = tmp_path / "wrong-policy-source-event.zip"
    rewrite_capsule_member(
        source,
        wrong_source_event,
        "timeline-evidence.json",
        lambda values: [
            {
                **event,
                "payload_projection": {"amount": 1, "currency": "USD"},
            }
            if event["event_type"] == "invoice.validated"
            else event
            for event in values
        ],
    )
    with pytest.raises(EvidenceError, match="policy-selected source event"):
        verify_with_declared_anchor(wrong_source_event)

    missing_precondition = tmp_path / "missing-precondition.zip"
    rewrite_capsule_member(
        source,
        missing_precondition,
        "recovery-attempts.json",
        lambda values: [
            {
                **values[0],
                "safe_result": {
                    key: value
                    for key, value in values[0]["safe_result"].items()
                    if key != "precondition"
                },
            }
        ],
    )
    with pytest.raises(EvidenceError, match="missing its typed observation"):
        verify_with_declared_anchor(missing_precondition)

    wrong_precondition = tmp_path / "wrong-precondition.zip"

    def forge_precondition(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        attempt = values[0]
        precondition = {
            **attempt["safe_result"]["precondition"],
            "entity_reference": "INV-ATTACKER",
        }
        precondition["content_digest"] = object_digest(
            {key: value for key, value in precondition.items() if key != "content_digest"}
        )
        return [
            {
                **attempt,
                "precondition_observation_digest": precondition["content_digest"],
                "safe_result": {**attempt["safe_result"], "precondition": precondition},
            }
        ]

    rewrite_capsule_member(
        source,
        wrong_precondition,
        "recovery-attempts.json",
        forge_precondition,
    )
    with pytest.raises(EvidenceError, match="required authoritative state"):
        verify_with_declared_anchor(wrong_precondition)

    with zipfile.ZipFile(source) as archive:
        reserved_at = json.loads(archive.read("transport-invocations.json"))[0][
            "reserved_at"
        ]
    late_precondition = tmp_path / "late-precondition.zip"

    def forge_late_precondition(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        attempt = values[0]
        observed_at = (
            datetime.fromisoformat(reserved_at.replace("Z", "+00:00"))
            + timedelta(days=1)
        ).isoformat().replace("+00:00", "Z")
        precondition = {
            **attempt["safe_result"]["precondition"],
            "observed_at": observed_at,
        }
        precondition["content_digest"] = object_digest(
            {key: value for key, value in precondition.items() if key != "content_digest"}
        )
        return [
            {
                **attempt,
                "precondition_observation_digest": precondition["content_digest"],
                "safe_result": {**attempt["safe_result"], "precondition": precondition},
            }
        ]

    rewrite_capsule_member(
        source,
        late_precondition,
        "recovery-attempts.json",
        forge_late_precondition,
    )
    with pytest.raises(EvidenceError, match="not observed before durable intent"):
        verify_with_declared_anchor(late_precondition)

    system_labeled_human = tmp_path / "system-labeled-human.zip"
    rewrite_capsule_member(
        source,
        system_labeled_human,
        "recovery-decisions.json",
        lambda values: [
            {
                **decision,
                "actor": {"system": "flowproof"},
                "authorization_scope": "system:approval_lifecycle",
            }
            if decision["action"] == "approve"
            else decision
            for decision in values
        ],
    )
    with pytest.raises(EvidenceError, match="human recovery decision has invalid provenance"):
        verify_with_declared_anchor(system_labeled_human)

    expired_before_decision = tmp_path / "expiry-before-decision.zip"

    def forge_expiry(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for decision in values:
            if decision["action"] != "approve":
                result.append(decision)
                continue
            decided_at = datetime.fromisoformat(decision["decided_at"].replace("Z", "+00:00"))
            result.append(
                {
                    **decision,
                    "approval_expires_at": (decided_at - timedelta(seconds=1))
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            )
        return result

    rewrite_capsule_member(
        source,
        expired_before_decision,
        "recovery-decisions.json",
        forge_expiry,
    )
    with pytest.raises(EvidenceError, match="approval expiry does not derive"):
        verify_with_declared_anchor(expired_before_decision)

    with zipfile.ZipFile(source) as archive:
        approval_expiry = json.loads(archive.read("recovery-decisions.json"))[0][
            "approval_expires_at"
        ]
    dispatched_after_expiry = tmp_path / "dispatch-after-expiry.zip"
    rewrite_capsule_member(
        source,
        dispatched_after_expiry,
        "transport-invocations.json",
        lambda values: [{**values[0], "reserved_at": approval_expiry}],
    )
    with pytest.raises(EvidenceError, match="not reserved under active consent"):
        verify_with_declared_anchor(dispatched_after_expiry)

    missing_reservation = tmp_path / "missing-transport-reservation.zip"
    rewrite_capsule_member(
        source,
        missing_reservation,
        "transport-invocations.json",
        lambda _values: [],
    )
    with pytest.raises(EvidenceError, match="transport reservation ledger"):
        verify_with_declared_anchor(missing_reservation)

    no_final_pass = tmp_path / "no-final-invariant-pass.zip"
    rewrite_capsule_member(
        source,
        no_final_pass,
        "evaluations.json",
        lambda values: [
            {**evaluation, "state": "violated"}
            if evaluation["invariant_id"] == incident["invariant_id"]
            and evaluation["state"] == "passed"
            else evaluation
            for evaluation in values
        ],
    )
    with pytest.raises(EvidenceError, match="claimed resolution lacks"):
        verify_with_declared_anchor(no_final_pass)

    early_final_evaluation = tmp_path / "early-final-evaluation.zip"

    def forge_early_final_observation(
        values: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result = []
        for evaluation in values:
            if (
                evaluation["invariant_id"] != incident["invariant_id"]
                or evaluation["state"] != "passed"
            ):
                result.append(evaluation)
                continue
            observation = {
                **evaluation["evidence"]["observation"],
                "observed_at": (
                    datetime.fromisoformat(reserved_at.replace("Z", "+00:00"))
                    - timedelta(days=1)
                ).isoformat().replace("+00:00", "Z"),
            }
            observation["content_digest"] = object_digest(
                {key: value for key, value in observation.items() if key != "content_digest"}
            )
            result.append(
                {
                    **evaluation,
                    "evidence": {**evaluation["evidence"], "observation": observation},
                }
            )
        return result

    rewrite_capsule_member(
        source,
        early_final_evaluation,
        "evaluations.json",
        forge_early_final_observation,
    )
    with zipfile.ZipFile(early_final_evaluation) as archive:
        forged_evaluations = json.loads(archive.read("evaluations.json"))
    early_final = tmp_path / "early-final-observation.zip"
    rewrite_capsule_member(
        early_final_evaluation,
        early_final,
        "postcondition-observations.json",
        lambda _values: [
            evaluation["evidence"]
            for evaluation in forged_evaluations
            if evaluation["invariant_id"] == incident["invariant_id"]
            and evaluation.get("evidence")
        ],
    )
    with pytest.raises(EvidenceError, match="postcondition timestamps are inconsistent"):
        verify_with_declared_anchor(early_final)

    with zipfile.ZipFile(source) as archive:
        plan_document = json.loads(archive.read("recovery-plan.json"))
    forged_parameters = {**plan_document["parameters"], "invoice_id": "INV-ATTACKER"}
    forged_plan_hash = object_digest(
        {
            "action_type": plan_document["action_type"],
            "parameters": forged_parameters,
            "guardrails": plan_document["guardrails"],
            "provider_contract_digest": plan_document["provider_contract_digest"],
        }
    )
    coherent_plan = tmp_path / "coherent-subject-plan.zip"
    coherent_decisions = tmp_path / "coherent-subject-decisions.zip"
    coherent_attempt = tmp_path / "coherent-subject-attempt.zip"
    coherent_forgery = tmp_path / "coherent-subject-forgery.zip"
    rewrite_capsule_member(
        source,
        coherent_plan,
        "recovery-plan.json",
        lambda value: {
            **value,
            "parameters": forged_parameters,
            "plan_hash": forged_plan_hash,
        },
    )
    rewrite_capsule_member(
        coherent_plan,
        coherent_decisions,
        "recovery-decisions.json",
        lambda values: [{**decision, "plan_hash": forged_plan_hash} for decision in values],
    )
    forged_request_digest = object_digest(forged_parameters)
    rewrite_capsule_member(
        coherent_decisions,
        coherent_attempt,
        "recovery-attempts.json",
        lambda values: [
            {
                **values[0],
                "plan_hash": forged_plan_hash,
                "request_digest": forged_request_digest,
            }
        ],
    )
    rewrite_capsule_member(
        coherent_attempt,
        coherent_forgery,
        "transport-invocations.json",
        lambda values: [{**values[0], "request_digest": forged_request_digest}],
    )
    with pytest.raises(EvidenceError, match="exact incident subject"):
        verify_with_declared_anchor(coherent_forgery)


def test_evidence_capsule_rejects_rehashed_but_incomplete_verified_lifecycle(
    setup, tmp_path: Path
) -> None:
    client, accounting, factory = setup
    accounting.mode = "false_200"
    incident, plan = proposed_recovery(client)
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/approve",
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
            headers=human_operator_headers(client),
        ).status_code
        == 200
    )
    accounting.mode = "normal"
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/execute", headers=operator_headers()
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/recovery-plans/{plan['id']}/verify", headers=operator_headers()
        ).json()["status"]
        == "verified"
    )
    source = tmp_path / "verified-source.zip"
    with factory() as session:
        export_capsule(session, incident["id"], source)
    assert verify_with_declared_anchor(source)["status"] == "VALID"

    cases = (
        ("evaluations.json", "policy evaluations"),
        ("recovery-decisions.json", "decision genealogy"),
        ("recovery-attempts.json", "durable attempt"),
    )
    for member, message in cases:
        destination = tmp_path / f"empty-{member}.zip"
        rewrite_capsule_member(source, destination, member, lambda _value: [])
        with pytest.raises(EvidenceError, match=message):
            verify_with_declared_anchor(destination)

    inconsistent = tmp_path / "revoked-but-verified.zip"

    def append_revoke(value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        approval = value[-1]
        return [
            *value,
            {
                **approval,
                "id": "forged-revoke",
                "request_id_digest": "f" * 64,
                "action": "revoke_approval",
                "approval_expires_at": None,
                "previous_plan_state": "approved",
                "resulting_plan_state": "proposed",
                "previous_incident_state": "recovery_approved",
                "resulting_incident_state": "recovery_proposed",
            },
        ]

    rewrite_capsule_member(
        source,
        inconsistent,
        "recovery-decisions.json",
        append_revoke,
    )
    with pytest.raises(EvidenceError, match="latest recovery decision is inconsistent"):
        verify_with_declared_anchor(inconsistent)

    with zipfile.ZipFile(source) as archive:
        attempt_created_at = json.loads(archive.read("recovery-attempts.json"))[0][
            "created_at"
        ]
    forged_dispatch = tmp_path / "dispatch-under-revoked-approval.zip"

    def insert_revoke_before_attempt_then_reapprove(
        value: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        approval = value[-1]
        reapproved_at = (
            datetime.fromisoformat(attempt_created_at.replace("Z", "+00:00"))
            + timedelta(microseconds=1)
        ).isoformat().replace("+00:00", "Z")
        reapproved_expires_at = (
            datetime.fromisoformat(reapproved_at.replace("Z", "+00:00"))
            + timedelta(seconds=900)
        ).isoformat().replace("+00:00", "Z")
        return [
            *value,
            {
                **approval,
                "id": "forged-revoke-before-attempt",
                "request_id_digest": "e" * 64,
                "action": "revoke_approval",
                "approval_expires_at": None,
                "reason_code": "forged_revoke_before_attempt",
                "previous_plan_state": "approved",
                "resulting_plan_state": "proposed",
                "previous_incident_state": "recovery_approved",
                "resulting_incident_state": "recovery_proposed",
                "decided_at": attempt_created_at,
            },
            {
                **approval,
                "id": "forged-reapproval-after-attempt",
                "request_id_digest": "d" * 64,
                "reason_code": "forged_reapproval_after_attempt",
                "approval_expires_at": reapproved_expires_at,
                "previous_plan_state": "proposed",
                "resulting_plan_state": "approved",
                "previous_incident_state": "recovery_proposed",
                "resulting_incident_state": "recovery_approved",
                "decided_at": reapproved_at,
            },
        ]

    rewrite_capsule_member(
        source,
        forged_dispatch,
        "recovery-decisions.json",
        insert_revoke_before_attempt_then_reapprove,
    )
    with pytest.raises(
        EvidenceError, match="effective approval|not created under its bound approval"
    ):
        verify_with_declared_anchor(forged_dispatch)
