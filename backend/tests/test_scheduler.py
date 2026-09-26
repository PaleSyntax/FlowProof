from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError

from flowproof import scheduler as scheduler_module
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import Base, DeadlineJob, Incident, RecoveryPlan
from flowproof.scheduler import DeadlineScheduler, build_accounting_client
from flowproof.schemas import BusinessEventIn
from flowproof.service import FlowProofService, normalize_utc

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
PROVIDER_CONTRACT_PATH = ROOT / "specs" / "providers" / "mock-accounting" / "contract.json"


class FakeAccounting:
    def __init__(self) -> None:
        self.available = True
        self.records: dict[str, dict[str, Any]] = {}
        self.registration_calls = 0

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        if not self.available:
            return {"available": False}
        record = self.records.get(invoice_id)
        return {"available": True, "exists": bool(record), "records": [record] if record else []}

    def register_invoice(self, invoice: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        self.registration_calls += 1
        self.records.setdefault(str(invoice["invoice_id"]), dict(invoice))
        return {"status_code": 200, "body": {"accepted": True}}

    def set_chaos_mode(self, mode: str) -> dict[str, Any]:
        return {"mode": mode}


def test_scheduler_main_validates_production_security_before_composition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectedSettings:
        @staticmethod
        def validate_production_security() -> None:
            raise ValueError("scheduler production validation")

    monkeypatch.setattr(
        scheduler_module.Settings,
        "from_environment",
        classmethod(lambda _cls: RejectedSettings()),
    )
    with pytest.raises(ValueError, match="scheduler production validation"):
        scheduler_module.main()


@pytest.fixture
def scheduler_setup(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'flowproof.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    now_ref = {"value": datetime(2026, 7, 31, 12, 0, tzinfo=UTC)}
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
        scheduler_poll_seconds=0.01,
        scheduler_lease_seconds=30,
        scheduler_max_attempts=3,
        scheduler_retry_base_seconds=2,
    )
    return settings, factory, FakeAccounting(), now_ref


def event(
    event_type: str, key: str, occurred_at: datetime, *, correlation_id: str = "scheduler-order"
) -> BusinessEventIn:
    return BusinessEventIn.model_validate(
        {
            "idempotency_key": key,
            "correlation_id": correlation_id,
            "entity_type": "invoice",
            "entity_id": "INV-SCHEDULER",
            "event_type": event_type,
            "occurred_at": occurred_at.isoformat(),
            "source": {"system": "scheduler-test"},
            "payload": {"amount": 18000.0, "currency": "RUB"},
        }
    )


def seed_acknowledgement(
    settings: Settings,
    factory,
    accounting: FakeAccounting,
    ack_at: datetime,
    *,
    correlation_id: str = "scheduler-order",
) -> None:
    for event_type, suffix, offset in (
        ("invoice.validated", "validated", -10),
        ("invoice.approved", "approved", -9),
        ("invoice.registration_requested", "requested", -5),
        ("invoice.registration_acknowledged", "ack", 0),
    ):
        with factory() as session:
            FlowProofService(session, str(settings.policy_path), accounting).ingest(
                event(
                    event_type,
                    f"{correlation_id}:{suffix}",
                    ack_at + timedelta(seconds=offset),
                    correlation_id=correlation_id,
                )
            )


def make_scheduler(
    settings: Settings, factory, accounting: FakeAccounting, now_ref, worker_id: str
):
    return DeadlineScheduler(
        settings,
        factory,
        accounting,
        worker_id=worker_id,
        now=lambda: now_ref["value"],
    )


def test_jobs_use_event_time_and_duplicate_delivery_does_not_reschedule(scheduler_setup) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    ack_at = now_ref["value"]
    seed_acknowledgement(settings, factory, accounting, ack_at)
    with factory() as session:
        service = FlowProofService(session, str(settings.policy_path), accounting)
        duplicate, replayed = service.ingest(
            event("invoice.registration_acknowledged", "scheduler-order:ack", ack_at)
        )
        assert replayed is True
        jobs = session.query(DeadlineJob).order_by(DeadlineJob.due_at).all()
        assert [job.invariant_id for job in jobs] == [
            "external_invoice_exists",
            "process_completes",
        ]
        assert normalize_utc(jobs[0].due_at) == ack_at + timedelta(seconds=30)
        assert normalize_utc(jobs[1].due_at) == ack_at + timedelta(seconds=60)
        with pytest.raises(IntegrityError):
            session.add(
                DeadlineJob(
                    id="duplicate-deadline-job",
                    policy_id=jobs[0].policy_id,
                    correlation_id=jobs[0].correlation_id,
                    invariant_id=jobs[0].invariant_id,
                    trigger_event_id=jobs[0].trigger_event_id,
                    due_at=jobs[0].due_at,
                    state="pending",
                    attempt_count=0,
                    next_attempt_at=jobs[0].due_at,
                )
            )
            session.commit()
        session.rollback()
        assert duplicate.id == jobs[0].trigger_event_id


def test_scheduler_waits_then_completes_once_after_restart(scheduler_setup) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    seed_acknowledgement(settings, factory, accounting, now_ref["value"] - timedelta(seconds=20))
    first_worker = make_scheduler(settings, factory, accounting, now_ref, "worker-before-due")
    assert first_worker.run_once() == 0
    with factory() as session:
        assert session.query(Incident).count() == 0

    now_ref["value"] += timedelta(seconds=11)
    assert first_worker.run_once() == 1
    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        plan = session.query(RecoveryPlan).one()
        assert job.state == "completed"
        assert job.attempt_count == 1
        assert session.query(Incident).count() == 1
        assert session.query(RecoveryPlan).count() == 1
        assert plan.status == "proposed"
        assert plan.requires_approval is True

    restarted_worker = make_scheduler(
        settings, factory, accounting, now_ref, "worker-after-restart"
    )
    assert restarted_worker.run_once() == 0
    with factory() as session:
        assert session.query(Incident).count() == 1
        assert session.query(RecoveryPlan).count() == 1


def test_due_job_uses_claim_time_when_wall_clock_moves_backwards(scheduler_setup) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    claimed_at = now_ref["value"]
    seed_acknowledgement(
        settings,
        factory,
        accounting,
        claimed_at - timedelta(seconds=31),
        correlation_id="scheduler-clock-rollback",
    )
    calls = 0

    def backwards_clock() -> datetime:
        nonlocal calls
        calls += 1
        # Heartbeat and claim see the deadline as due. The VM clock then
        # resynchronizes backwards before evaluation and completion.
        return claimed_at if calls <= 2 else claimed_at - timedelta(seconds=40)

    worker = DeadlineScheduler(
        settings,
        factory,
        accounting,
        worker_id="clock-rollback-worker",
        now=backwards_clock,
    )
    assert worker.run_once() == 1
    with factory() as session:
        job = session.query(DeadlineJob).filter_by(
            correlation_id="scheduler-clock-rollback",
            invariant_id="external_invoice_exists",
        ).one()
        assert job.state == "completed"
        assert normalize_utc(job.completed_at) >= normalize_utc(job.due_at)
        incident = session.query(Incident).filter_by(
            correlation_id="scheduler-clock-rollback"
        ).one()
        assert incident.summary == "missing_external_invoice"


def test_scheduler_retries_unavailable_verifier_without_creating_incident(scheduler_setup) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    seed_acknowledgement(settings, factory, accounting, now_ref["value"] - timedelta(seconds=31))
    accounting.available = False
    worker = make_scheduler(settings, factory, accounting, now_ref, "retry-worker")
    assert worker.run_once() == 1
    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        assert job.state == "retry"
        assert job.attempt_count == 1
        assert job.last_error == "external_verifier_unavailable"
        assert session.query(Incident).count() == 0

    accounting.available = True
    now_ref["value"] += timedelta(seconds=2)
    assert worker.run_once() == 1
    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        assert job.state == "completed"
        assert job.attempt_count == 2
        assert session.query(Incident).count() == 1


def test_expired_lease_is_claimed_and_existing_external_record_has_no_incident(
    scheduler_setup,
) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    acknowledgement_at = now_ref["value"] - timedelta(seconds=31)
    seed_acknowledgement(settings, factory, accounting, acknowledgement_at)
    accounting.records["INV-SCHEDULER"] = {
        "invoice_id": "INV-SCHEDULER",
        "amount": 18000.0,
        "currency": "RUB",
    }
    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        job.state = "running"
        job.attempt_count = 1
        job.lease_owner = "lost-worker"
        job.lease_expires_at = now_ref["value"] - timedelta(seconds=1)
        session.commit()

    worker = make_scheduler(settings, factory, accounting, now_ref, "reclaimer")
    assert worker.run_once() == 1
    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        assert job.state == "completed"
        assert job.attempt_count == 2
        assert session.query(Incident).count() == 0


def test_unit_claim_lease_prevents_second_worker_and_keeps_effects_single(scheduler_setup) -> None:
    """Fast SQLite regression only; the smoke runner proves concurrent PostgreSQL workers."""
    settings, factory, accounting, now_ref = scheduler_setup
    seed_acknowledgement(settings, factory, accounting, now_ref["value"] - timedelta(seconds=31))
    first_worker = make_scheduler(settings, factory, accounting, now_ref, "worker-one")
    second_worker = make_scheduler(settings, factory, accounting, now_ref, "worker-two")

    first_claim = first_worker._claim_due_jobs(1)
    assert len(first_claim) == 1
    assert second_worker._claim_due_jobs(1) == []
    first_worker._process_claimed_job(first_claim[0])

    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        plan = session.query(RecoveryPlan).one()
        assert job.state == "completed"
        assert job.attempt_count == 1
        assert job.lease_owner is None
        external_jobs = session.query(DeadlineJob).filter_by(
            invariant_id="external_invoice_exists"
        )
        assert external_jobs.count() == 1
        assert session.query(Incident).count() == 1
        assert session.query(RecoveryPlan).count() == 1
        assert plan.status == "proposed"
        assert plan.approved_at is None
        assert plan.executed_at is None
    assert accounting.registration_calls == 0


def test_scheduler_fails_after_bounded_unavailable_verifier_retries(scheduler_setup) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    seed_acknowledgement(settings, factory, accounting, now_ref["value"] - timedelta(seconds=31))
    accounting.available = False
    worker = make_scheduler(settings, factory, accounting, now_ref, "bounded-retry-worker")

    assert worker.run_once() == 1
    now_ref["value"] += timedelta(seconds=2)
    assert worker.run_once() == 1
    now_ref["value"] += timedelta(seconds=4)
    assert worker.run_once() == 1

    with factory() as session:
        job = session.query(DeadlineJob).filter_by(invariant_id="external_invoice_exists").one()
        assert job.state == "failed"
        assert job.attempt_count == settings.scheduler_max_attempts
        assert job.lease_owner is None
        assert job.lease_expires_at is None
        assert job.last_error == "external_verifier_unavailable"
        assert session.query(Incident).count() == 0
        assert session.query(RecoveryPlan).count() == 0
    assert accounting.registration_calls == 0


def test_scheduler_composition_loads_the_provider_contract(scheduler_setup) -> None:
    settings, _, _, _ = scheduler_setup
    client = build_accounting_client(
        replace(settings, provider_contract_path=PROVIDER_CONTRACT_PATH)
    )
    assert client.contract.provider_id == "mock-accounting"
    assert client.contract.environment == "sandbox"


def test_scheduler_honors_disabled_recovery_writes(scheduler_setup) -> None:
    settings, factory, accounting, now_ref = scheduler_setup
    settings = replace(settings, recovery_writes_enabled=False)
    seed_acknowledgement(settings, factory, accounting, now_ref["value"] - timedelta(seconds=31))

    worker = make_scheduler(settings, factory, accounting, now_ref, "read-only-worker")
    assert worker.run_once() == 1

    with factory() as session:
        incident = session.query(Incident).one()
        assert incident.status == "recovery_proposed"
        plan = session.query(RecoveryPlan).one()
        assert plan.status == "proposed"
        assert plan.approved_at is None
        assert plan.executed_at is None
    assert accounting.registration_calls == 0
