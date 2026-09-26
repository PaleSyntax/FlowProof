from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from flowproof.accounting import (
    InvoiceObservation,
    ObservationState,
    ProviderContract,
    RecoveryWriteOutcome,
    WriteOutcomeState,
)
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.main import create_app
from flowproof.models import (
    Base,
    BusinessEvent,
    Incident,
    Principal,
    RecoveryAttempt,
    RecoveryDecision,
    RecoveryPlan,
    RecoveryTransportInvocation,
    SecurityAuditEvent,
)
from flowproof.policy import canonical_hash
from flowproof.provider_factory import (
    PROVIDER_ADAPTER_REGISTRY,
    ProviderAdapterRegistration,
    create_provider_adapter,
)
from flowproof.recovery_dispatch import ReconciliationRequired
from flowproof.schemas import BusinessEventIn
from flowproof.service import (
    FlowProofService,
    IdempotencyConflict,
    PayloadRejected,
    RecoveryGateError,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
CONTRACT_PATH = (
    ROOT
    / "specs"
    / "providers"
    / "mock-accounting"
    / "contract.json"
)


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class TypedAccounting:
    def __init__(self) -> None:
        self.contract = ProviderContract.load(CONTRACT_PATH)
        self.records: dict[str, dict[str, Any]] = {}
        self.observation_state = ObservationState.AVAILABLE_ABSENT
        self.write_state = WriteOutcomeState.ACCEPTED
        self.read_calls = 0
        self.write_calls = 0

    def observe_invoice(self, invoice_id: str) -> InvoiceObservation:
        self.read_calls += 1
        records: tuple[dict[str, Any], ...] = ()
        if self.observation_state == ObservationState.AVAILABLE_PRESENT:
            records = (
                self.records.get(
                    invoice_id,
                    {
                        "invoice_id": invoice_id,
                        "amount": 10.0,
                        "currency": "RUB",
                    },
                ),
            )
        return InvoiceObservation(
            state=self.observation_state,
            provider_id=self.contract.provider_id,
            environment=self.contract.environment,
            adapter_version=self.contract.adapter_version,
            entity_reference=invoice_id,
            observed_at=datetime.now(UTC),
            records=records,
        )

    def write_invoice(
        self,
        invoice: dict[str, Any],
        idempotency_key: str,
    ) -> RecoveryWriteOutcome:
        del idempotency_key
        self.write_calls += 1
        if self.write_state == WriteOutcomeState.ACCEPTED:
            self.records[str(invoice["invoice_id"])] = dict(invoice)
        return RecoveryWriteOutcome(
            state=self.write_state,
            provider_id=self.contract.provider_id,
            environment=self.contract.environment,
            adapter_version=self.contract.adapter_version,
            observed_at=datetime.now(UTC),
            safe_result={"accepted": self.write_state == WriteOutcomeState.ACCEPTED},
        )


@dataclass(frozen=True)
class SeededRecovery:
    plan_id: str
    incident_id: str
    attempt_id: str | None
    reservation_id: str | None


def _factory(tmp_path: Path):
    engine = make_engine(
        f"sqlite:///{tmp_path / f'flowproof-{uuid4()}.sqlite3'}"
    )
    Base.metadata.create_all(engine)
    return make_session_factory(engine)


def _service(
    factory: Any,
    accounting: TypedAccounting,
    clock: MutableClock,
    *,
    owner: str,
    writes_enabled: bool = True,
) -> FlowProofService:
    return FlowProofService(
        factory(),
        str(POLICY_PATH),
        accounting,
        now=clock,
        recovery_writes_enabled=writes_enabled,
        dispatch_owner=f"dispatch:{owner}",
        reconciliation_owner=f"reconcile:{owner}",
        dispatch_lease_seconds=30,
        reconciliation_lease_seconds=30,
    )


def _seed_recovery(
    factory: Any,
    accounting: TypedAccounting,
    clock: MutableClock,
    *,
    plan_status: str = "approved",
    attempt_state: str | None = "PREPARED",
    reservation_state: str | None = None,
    lease_expires_at: datetime | None = None,
) -> SeededRecovery:
    principal_id = str(uuid4())
    incident_id = str(uuid4())
    plan_id = str(uuid4())
    decision_id = str(uuid4())
    attempt_id = str(uuid4()) if attempt_state is not None else None
    parameters = {
        "invoice_id": "INV-FENCE",
        "amount": 10.0,
        "currency": "RUB",
    }
    guardrails = {
        "provider_id": accounting.contract.provider_id,
        "environment": accounting.contract.environment,
        "sandbox_only": True,
        "entity_type": "invoice",
        "entity_id": "INV-FENCE",
        "action_type": "register_missing_invoice",
        "allowed_currencies": ["RUB"],
        "maximum_amount_minor": 1_000_000,
        "amount_scale": 2,
        "observed_amount_minor": 1_000,
        "maximum_semantic_write_attempts": 1,
        "maximum_transport_invocations": 2,
        "approval_ttl_seconds": 900,
        "provider_contract_digest": accounting.contract.digest,
        "reconciliation_method": "authoritative_invoice_reread",
        "batch_allowed": False,
        "wildcards_allowed": False,
    }
    plan_hash = canonical_hash(
        {
            "action_type": "register_missing_invoice",
            "parameters": parameters,
            "guardrails": guardrails,
            "provider_contract_digest": accounting.contract.digest,
        }
    )
    approval_expires_at = clock() + timedelta(minutes=10)
    reservation_id: str | None = None
    with factory() as session:
        session.add(
            Principal(
                id=principal_id,
                name=f"operator-{principal_id}",
                kind="human",
                role="operator",
                allowed_scopes=["recovery:approve"],
            )
        )
        session.add(
            Incident(
                id=incident_id,
                correlation_id="correlation-fence",
                entity_type="invoice",
                entity_id="INV-FENCE",
                policy_name="invoice-processing",
                policy_version="1.0.0",
                invariant_id="external_invoice_exists",
                severity="high",
                status=(
                    "recovery_approved"
                    if plan_status == "approved"
                    else "recovery_proposed"
                ),
                summary="missing_external_invoice",
                evidence={},
                opened_at=clock(),
            )
        )
        session.add(
            RecoveryPlan(
                id=plan_id,
                incident_id=incident_id,
                action_type="register_missing_invoice",
                parameters=parameters,
                idempotency_key=f"recovery:{incident_id}",
                risk_level="bounded_sandbox_write",
                requires_approval=True,
                status=plan_status,
                plan_hash=plan_hash,
                provider_id=accounting.contract.provider_id,
                provider_environment=accounting.contract.environment,
                adapter_version=accounting.contract.adapter_version,
                provider_contract_digest=accounting.contract.digest,
                provider_contract_snapshot=accounting.contract.to_manifest(),
                guardrails=guardrails,
                approved_plan_hash=(
                    plan_hash if plan_status == "approved" else None
                ),
                approved_by=(
                    "operator" if plan_status == "approved" else None
                ),
                approval_context=(
                    {
                        "actor_principal_id": principal_id,
                        "actor_name": "operator",
                        "scope": "recovery:approve",
                        "incident_id": incident_id,
                        "incident_status": "recovery_proposed",
                        "plan_hash": plan_hash,
                        "provider_contract_digest": accounting.contract.digest,
                        "guardrail_digest": canonical_hash(guardrails),
                        "approval_expires_at": approval_expires_at.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "approval_decision_id": decision_id,
                    }
                    if plan_status == "approved"
                    else {}
                ),
                approved_at=(clock() if plan_status == "approved" else None),
                approval_expires_at=(
                    approval_expires_at if plan_status == "approved" else None
                ),
                result={},
            )
        )
        session.add(
            RecoveryDecision(
                id=decision_id,
                recovery_plan_id=plan_id,
                incident_id=incident_id,
                request_id=f"approval-{decision_id}",
                action="approve",
                decision_kind="human",
                actor_principal_id=principal_id,
                actor_display_name="operator",
                authorization_scope="recovery:approve",
                plan_hash=plan_hash,
                provider_contract_digest=accounting.contract.digest,
                incident_state_observed="recovery_proposed",
                plan_state_observed="proposed",
                reason_code="approved_by_operator",
                note_digest=None,
                previous_plan_state="proposed",
                resulting_plan_state="approved",
                previous_incident_state="recovery_proposed",
                resulting_incident_state="recovery_approved",
                decided_at=clock(),
                approval_expires_at=approval_expires_at,
            )
        )
        if attempt_id is not None:
            attempt = RecoveryAttempt(
                id=attempt_id,
                recovery_plan_id=plan_id,
                incident_id=incident_id,
                approval_decision_id=decision_id,
                active_transport_invocation_id=None,
                attempt_ordinal=1,
                execution_idempotency_key=f"recovery:{incident_id}",
                plan_hash=plan_hash,
                provider_contract_digest=accounting.contract.digest,
                provider_id=accounting.contract.provider_id,
                provider_environment=accounting.contract.environment,
                adapter_version=accounting.contract.adapter_version,
                request_digest=canonical_hash(parameters),
                precondition_observation_digest="d" * 64,
                state=attempt_state,
                semantic_attempt_count=1,
                transport_invocation_count=(
                    1 if reservation_state is not None else 0
                ),
                retry_permitted=False,
                safe_result={
                    "precondition": {
                        "classification": "AVAILABLE_ABSENT"
                    }
                },
                created_at=clock(),
                updated_at=clock(),
            )
            session.add(attempt)
            session.flush()
            if reservation_state is not None:
                reservation_id = str(uuid4())
                reservation = RecoveryTransportInvocation(
                    id=reservation_id,
                    recovery_attempt_id=attempt_id,
                    recovery_plan_id=plan_id,
                    approval_decision_id=decision_id,
                    invocation_ordinal=1,
                    request_digest=attempt.request_digest,
                    reserved_at=clock(),
                    state=reservation_state,
                    dispatch_owner="dispatch:seed",
                    dispatch_generation=1,
                    dispatch_started_at=clock(),
                    dispatch_lease_expires_at=(
                        lease_expires_at
                        or clock() + timedelta(seconds=30)
                    ),
                    reconciliation_owner=None,
                    reconciliation_generation=0,
                    safe_outcome={},
                    lock_version=1,
                )
                session.add(reservation)
                attempt.active_transport_invocation_id = reservation_id
        session.commit()
    return SeededRecovery(
        plan_id=plan_id,
        incident_id=incident_id,
        attempt_id=attempt_id,
        reservation_id=reservation_id,
    )


def _event(
    *,
    key: str,
    correlation_id: str,
    entity_id: str,
    amount: float = 10.0,
) -> BusinessEventIn:
    return BusinessEventIn.model_validate(
        {
            "idempotency_key": key,
            "correlation_id": correlation_id,
            "entity_type": "invoice",
            "entity_id": entity_id,
            "event_type": "invoice.approved",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source": {"system": "test"},
            "payload": {"amount": amount, "currency": "RUB"},
        }
    )


def test_reconcile_does_not_take_live_dispatch_lease(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(
        factory,
        accounting,
        clock,
        reservation_state="DISPATCHING",
        lease_expires_at=clock() + timedelta(seconds=30),
    )
    service = _service(factory, accounting, clock, owner="a")
    plan = service.get_plan(seeded.plan_id)
    assert plan is not None

    with pytest.raises(ReconciliationRequired, match="lease is still live"):
        service.reconcile(
            seeded.plan_id,
            submitted_hash=plan.plan_hash,
        )
    assert accounting.read_calls == 0


def test_reconcile_takes_over_only_after_dispatch_lease_expiry(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(
        factory,
        accounting,
        clock,
        reservation_state="DISPATCHING",
        lease_expires_at=clock() - timedelta(seconds=1),
    )
    service = _service(factory, accounting, clock, owner="takeover")
    plan = service.get_plan(seeded.plan_id)
    assert plan is not None

    result = service.reconcile(
        seeded.plan_id,
        submitted_hash=plan.plan_hash,
    )
    assert result.status == "proposed"
    with factory() as session:
        reservation = session.get(
            RecoveryTransportInvocation,
            seeded.reservation_id,
        )
        attempt = session.get(RecoveryAttempt, seeded.attempt_id)
        assert reservation is not None
        assert attempt is not None
        assert reservation.state == "EFFECT_ABSENT"
        assert reservation.abandoned_at is not None
        assert reservation.abandonment_reason == "dispatch_lease_expired"
        assert reservation.reconciliation_generation == 1
        assert reservation.completed_at is not None
        history = attempt.safe_result["reconciliation_history"]
        assert history[-1]["reservation_id"] == reservation.id
        assert history[-1]["reconciliation_claim"]["generation"] == 1


def test_stale_reconciler_cannot_overwrite_newer_terminal_result(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(
        factory,
        accounting,
        clock,
        reservation_state="DISPATCHING",
        lease_expires_at=clock() - timedelta(seconds=1),
    )
    service_a = _service(factory, accounting, clock, owner="a")
    with service_a.session:
        plan_a = service_a._locked_plan(seeded.plan_id)
        incident_a = service_a.session.get(Incident, seeded.incident_id)
        attempt_a = service_a._attempt_for_plan(seeded.plan_id, lock=True)
        reservation_a = service_a._active_reservation(attempt_a)
        assert incident_a is not None
        assert attempt_a is not None
        assert reservation_a is not None
        claim_a = service_a._claim_reservation_reconciliation(
            plan_a,
            incident_a,
            attempt_a,
            reservation_a,
            reason="test_stale_reconciler",
        )

    clock.advance(31)
    service_b = _service(factory, accounting, clock, owner="b")
    with service_b.session:
        plan_b = service_b._locked_plan(seeded.plan_id)
        incident_b = service_b.session.get(Incident, seeded.incident_id)
        attempt_b = service_b._attempt_for_plan(seeded.plan_id, lock=True)
        reservation_b = service_b._active_reservation(attempt_b)
        assert incident_b is not None
        assert attempt_b is not None
        assert reservation_b is not None
        claim_b = service_b._claim_reservation_reconciliation(
            plan_b,
            incident_b,
            attempt_b,
            reservation_b,
            reason="test_takeover",
        )
        accounting.observation_state = ObservationState.AVAILABLE_PRESENT
        accounting.records["INV-FENCE"] = {
            "invoice_id": "INV-FENCE",
            "amount": 10.0,
            "currency": "RUB",
        }
        service_b._complete_reconciliation(
            claim_b,
            accounting.observe_invoice("INV-FENCE"),
        )

    accounting.observation_state = ObservationState.AVAILABLE_ABSENT
    with pytest.raises(
        ReconciliationRequired,
        match="stale reconciliation",
    ):
        service_a._complete_reconciliation(
            claim_a,
            accounting.observe_invoice("INV-FENCE"),
        )
    with factory() as session:
        reservation = session.get(
            RecoveryTransportInvocation,
            seeded.reservation_id,
        )
        assert reservation is not None
        assert reservation.state == "EFFECT_PRESENT"
        assert reservation.reconciliation_generation == 2


def test_late_dispatch_completion_after_takeover_is_not_success(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(factory, accounting, clock)
    service_a = _service(factory, accounting, clock, owner="a")
    with service_a.session:
        plan = service_a._locked_plan(seeded.plan_id)
        incident = service_a.session.get(Incident, seeded.incident_id)
        attempt = service_a._attempt_for_plan(seeded.plan_id, lock=True)
        assert incident is not None
        assert attempt is not None
        approval = service_a._active_dispatch_approval(plan)
        claim = service_a._reserve_transport(
            plan,
            incident,
            attempt,
            approval,
        )

    clock.advance(31)
    service_b = _service(factory, accounting, clock, owner="b")
    with service_b.session:
        plan_b = service_b._locked_plan(seeded.plan_id)
        incident_b = service_b.session.get(Incident, seeded.incident_id)
        attempt_b = service_b._attempt_for_plan(seeded.plan_id, lock=True)
        reservation_b = service_b._active_reservation(attempt_b)
        assert incident_b is not None
        assert attempt_b is not None
        assert reservation_b is not None
        service_b._claim_reservation_reconciliation(
            plan_b,
            incident_b,
            attempt_b,
            reservation_b,
            reason="dispatch_takeover",
        )

    outcome = accounting.write_invoice(
        {
            "invoice_id": "INV-FENCE",
            "amount": 10.0,
            "currency": "RUB",
        },
        "late-completion",
    )
    with pytest.raises(ReconciliationRequired):
        service_a._complete_reserved_transport(claim, outcome)


def test_cas_loss_returns_conflict_and_does_not_audit_recovery_executed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'audit-cas.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    settings = Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="test",
        token_pepper="test-token-pepper-with-at-least-thirty-two-characters",
        legacy_ingestion_token="test-events-token",
        legacy_operator_token="test-operator-token",
        legacy_header_auth_enabled=True,
    )

    def lose_cas(self: FlowProofService, plan_id: str) -> RecoveryPlan:
        del self, plan_id
        raise ReconciliationRequired("reservation CAS lost")

    monkeypatch.setattr(FlowProofService, "execute", lose_cas)
    app = create_app(settings, TypedAccounting(), factory)
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/recovery-plans/{uuid4()}/execute",
            headers={
                "X-FlowProof-Operator-Token": "test-operator-token"
            },
        )
    assert response.status_code == 409
    with factory() as session:
        assert session.scalar(
            select(SecurityAuditEvent.id).where(
                SecurityAuditEvent.action == "recovery_executed"
            )
        ) is None


@pytest.mark.parametrize("plan_status", ["proposed", "approved"])
def test_write_disable_does_not_block_plan_creation(
    tmp_path: Path,
    plan_status: str,
) -> None:
    del plan_status
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    service = _service(
        factory,
        accounting,
        clock,
        owner="disabled-plan",
        writes_enabled=False,
    )
    policy = service.ensure_policy()
    event = BusinessEvent(
        id=str(uuid4()),
        idempotency_key="validated-disabled",
        correlation_id="disabled-correlation",
        entity_type="invoice",
        entity_id="INV-DISABLED",
        event_type="invoice.validated",
        occurred_at=clock(),
        source_system="test",
        payload={"amount": 10.0, "currency": "RUB"},
        content_hash="a" * 64,
    )
    incident = Incident(
        id=str(uuid4()),
        correlation_id=event.correlation_id,
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        policy_name=policy.name,
        policy_version=policy.version,
        invariant_id="external_invoice_exists",
        severity="high",
        status="open",
        summary="missing_external_invoice",
        evidence={},
        opened_at=clock(),
    )
    service.session.add_all([event, incident])
    service.session.flush()
    service._ensure_missing_invoice_plan(policy, incident, event)
    service.session.commit()
    plan = service.session.scalar(
        select(RecoveryPlan).where(
            RecoveryPlan.incident_id == incident.id
        )
    )
    assert plan is not None
    assert plan.status == "proposed"
    assert accounting.write_calls == 0


def test_write_disable_after_prepared_blocks_only_new_reservation(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(factory, accounting, clock)
    service = _service(
        factory,
        accounting,
        clock,
        owner="disabled-dispatch",
        writes_enabled=False,
    )
    with service.session:
        plan = service._locked_plan(seeded.plan_id)
        incident = service.session.get(Incident, seeded.incident_id)
        attempt = service._attempt_for_plan(seeded.plan_id, lock=True)
        assert incident is not None
        assert attempt is not None
        with pytest.raises(
            RecoveryGateError,
            match="new external recovery reservations are disabled",
        ):
            service._dispatch_attempt(plan, incident, attempt)
    with factory() as session:
        attempt = session.get(RecoveryAttempt, seeded.attempt_id)
        assert attempt is not None
        assert attempt.state == "PREPARED"
        assert session.scalar(
            select(RecoveryTransportInvocation.id)
        ) is None


def test_write_disable_after_ambiguous_dispatch_still_allows_reconciliation(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    accounting.observation_state = ObservationState.AVAILABLE_PRESENT
    accounting.records["INV-FENCE"] = {
        "invoice_id": "INV-FENCE",
        "amount": 10.0,
        "currency": "RUB",
    }
    factory = _factory(tmp_path)
    seeded = _seed_recovery(
        factory,
        accounting,
        clock,
        attempt_state="OUTCOME_UNKNOWN",
        reservation_state="OUTCOME_UNKNOWN",
    )
    service = _service(
        factory,
        accounting,
        clock,
        owner="disabled-reconcile",
        writes_enabled=False,
    )
    plan = service.get_plan(seeded.plan_id)
    assert plan is not None
    result = service.reconcile(
        seeded.plan_id,
        submitted_hash=plan.plan_hash,
    )
    assert result.status == "verifying"
    assert accounting.write_calls == 0
    assert accounting.read_calls == 1


def _concurrent_ingest(
    factory: Any,
    accounting: TypedAccounting,
    clock: MutableClock,
    events: list[BusinessEventIn],
) -> list[str]:
    with factory() as session:
        FlowProofService(
            session,
            str(POLICY_PATH),
            accounting,
            now=clock,
        ).ensure_policy()
    barrier = Barrier(len(events))

    def worker(index: int) -> str:
        service = _service(
            factory,
            accounting,
            clock,
            owner=f"ingest-{index}",
        )
        barrier.wait()
        try:
            _, duplicate = service.ingest(events[index])
            return "duplicate" if duplicate else "created"
        except PayloadRejected:
            return "subject_conflict"
        except IdempotencyConflict:
            return "idempotency_conflict"
        finally:
            service.session.close()

    with ThreadPoolExecutor(max_workers=len(events)) as executor:
        return list(executor.map(worker, range(len(events))))


def test_concurrent_mixed_entity_first_ingest_is_fail_closed(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    results = _concurrent_ingest(
        factory,
        accounting,
        clock,
        [
            _event(
                key="mixed-a",
                correlation_id="mixed-correlation",
                entity_id="INV-A",
            ),
            _event(
                key="mixed-b",
                correlation_id="mixed-correlation",
                entity_id="INV-B",
            ),
        ],
    )
    assert sorted(results) == ["created", "subject_conflict"]


def test_concurrent_identical_idempotency_replay_is_duplicate(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    event = _event(
        key="identical-key",
        correlation_id="identical-correlation",
        entity_id="INV-IDENTICAL",
    )
    results = _concurrent_ingest(
        factory,
        accounting,
        clock,
        [event, event],
    )
    assert sorted(results) == ["created", "duplicate"]


def test_concurrent_conflicting_idempotency_replay_is_conflict(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    results = _concurrent_ingest(
        factory,
        accounting,
        clock,
        [
            _event(
                key="conflicting-key",
                correlation_id="conflicting-correlation",
                entity_id="INV-CONFLICT",
                amount=10.0,
            ),
            _event(
                key="conflicting-key",
                correlation_id="conflicting-correlation",
                entity_id="INV-CONFLICT",
                amount=20.0,
            ),
        ],
    )
    assert sorted(results) == ["created", "idempotency_conflict"]


@pytest.mark.parametrize("plan_status", ["proposed", "approved"])
def test_external_resolution_supersedes_unused_plan(
    tmp_path: Path,
    plan_status: str,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(
        factory,
        accounting,
        clock,
        plan_status=plan_status,
        attempt_state=None,
    )
    service = _service(factory, accounting, clock, owner="external")
    policy = service.ensure_policy()
    entity_event = BusinessEvent(
        id=str(uuid4()),
        idempotency_key="external-source",
        correlation_id="correlation-fence",
        entity_type="invoice",
        entity_id="INV-FENCE",
        event_type="invoice.registration_acknowledged",
        occurred_at=clock(),
        source_system="test",
        payload={},
        content_hash="a" * 64,
    )
    service._sync_incident(
        policy,
        {"id": "external_invoice_exists"},
        entity_event,
        {
            "state": "passed",
            "message": "external assertion is satisfied",
            "evidence": {"observation": {"classification": "AVAILABLE_PRESENT"}},
        },
    )
    service.session.commit()
    plan = service.get_plan(seeded.plan_id)
    incident = service.session.get(Incident, seeded.incident_id)
    assert plan is not None
    assert incident is not None
    assert plan.status == "superseded"
    assert plan.approval_context == {}
    assert incident.status == "resolved"
    decisions = service.list_decisions(plan.id)
    assert [item["action"] for item in decisions].count("external_resolution") == 1


def test_external_resolution_supersedes_zero_reservation_prepared_attempt(
    tmp_path: Path,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(factory, accounting, clock)
    service = _service(factory, accounting, clock, owner="prepared-external")
    policy = service.ensure_policy()
    entity_event = BusinessEvent(
        id=str(uuid4()),
        idempotency_key="prepared-external-source",
        correlation_id="correlation-fence",
        entity_type="invoice",
        entity_id="INV-FENCE",
        event_type="invoice.registration_acknowledged",
        occurred_at=clock(),
        source_system="test",
        payload={},
        content_hash="a" * 64,
    )
    service._sync_incident(
        policy,
        {"id": "external_invoice_exists"},
        entity_event,
        {
            "state": "passed",
            "message": "external assertion is satisfied",
            "evidence": {"observation": {"classification": "AVAILABLE_PRESENT"}},
        },
    )
    service.session.commit()
    with factory() as session:
        attempt = session.get(RecoveryAttempt, seeded.attempt_id)
        plan = session.get(RecoveryPlan, seeded.plan_id)
        incident = session.get(Incident, seeded.incident_id)
        assert attempt is not None
        assert plan is not None
        assert incident is not None
        assert attempt.state == "SUPERSEDED_EXTERNAL_RESOLUTION"
        assert plan.status == "superseded"
        assert incident.status == "resolved"


@pytest.mark.parametrize(
    "reservation_state",
    ["DISPATCHING", "OUTCOME_UNKNOWN"],
)
def test_external_pass_does_not_overwrite_live_or_ambiguous_reservation(
    tmp_path: Path,
    reservation_state: str,
) -> None:
    clock = MutableClock(datetime(2026, 8, 4, tzinfo=UTC))
    accounting = TypedAccounting()
    factory = _factory(tmp_path)
    seeded = _seed_recovery(
        factory,
        accounting,
        clock,
        attempt_state=reservation_state,
        reservation_state=reservation_state,
    )
    service = _service(factory, accounting, clock, owner="active-external")
    policy = service.ensure_policy()
    entity_event = BusinessEvent(
        id=str(uuid4()),
        idempotency_key=f"active-external-{reservation_state}",
        correlation_id="correlation-fence",
        entity_type="invoice",
        entity_id="INV-FENCE",
        event_type="invoice.registration_acknowledged",
        occurred_at=clock(),
        source_system="test",
        payload={},
        content_hash="a" * 64,
    )
    service._sync_incident(
        policy,
        {"id": "external_invoice_exists"},
        entity_event,
        {
            "state": "passed",
            "message": "external assertion is satisfied",
            "evidence": {"observation": {"classification": "AVAILABLE_PRESENT"}},
        },
    )
    service.session.commit()
    incident = service.session.get(Incident, seeded.incident_id)
    plan = service.get_plan(seeded.plan_id)
    assert incident is not None
    assert plan is not None
    assert incident.status != "resolved"
    assert plan.status != "superseded"
    assert incident.evidence["pending_external_pass"]["reservation_id"] == (
        seeded.reservation_id
    )


def test_unknown_provider_is_rejected_before_startup() -> None:
    base = ProviderContract.load(CONTRACT_PATH)
    unknown = ProviderContract(
        **{
            **base.to_manifest(include_digest=False),
            "provider_id": "owner-coordinates-not-supplied",
        }
    )
    with pytest.raises(ValueError, match="no explicit FlowProof adapter"):
        create_provider_adapter(
            "https://provider.invalid",
            unknown,
            environment="test",
        )


def test_registered_provider_without_constructor_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = ProviderContract.load(CONTRACT_PATH)
    monkeypatch.setitem(
        PROVIDER_ADAPTER_REGISTRY,
        contract.provider_id,
        ProviderAdapterRegistration(
            provider_id=contract.provider_id,
            constructor=None,
            adapter_kind="invalid-registration",
            evidence_boundary="UNVERIFIED",
            owner_coordinates_required=True,
        ),
    )
    with pytest.raises(ValueError, match="without a constructor"):
        create_provider_adapter(
            "http://mock-accounting",
            contract,
            environment="test",
        )
