from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import (
    AlertOutbox,
    ApiCredential,
    Base,
    DeadlineJob,
    Incident,
    OperationalAlertState,
    Principal,
    RecoveryPlan,
    ServiceHeartbeat,
)
from flowproof.ops_watcher import OpsWatcher

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"


def credential_alert_state(session, condition: str, subject: str) -> OperationalAlertState | None:
    return session.scalar(
        select(OperationalAlertState).where(
            OperationalAlertState.condition == condition,
            OperationalAlertState.subject == subject,
        )
    )


def test_ops_watcher_persists_transitions_and_alert_generations(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'watcher.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    clock = {"now": datetime(2026, 8, 1, 12, 0, tzinfo=UTC)}
    settings = Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="test",
        token_pepper="watcher-test-pepper-with-at-least-thirty-two-characters",
        alert_webhook_url="https://alerts.example.test/hook",
        alert_open_incident_seconds=30,
        ops_watcher_heartbeat_stale_seconds=30,
        ops_watcher_verifier_failure_threshold=1,
        ops_watcher_verifier_observation_seconds=30,
    )
    with factory() as session:
        session.add(
            DeadlineJob(
                id="deadline-failed",
                policy_id="policy-id",
                correlation_id="watcher-correlation",
                invariant_id="external_invoice_exists",
                trigger_event_id="event-id",
                due_at=clock["now"] - timedelta(minutes=1),
                state="failed",
                attempt_count=3,
                next_attempt_at=clock["now"] - timedelta(minutes=1),
                last_error="external_verifier_unavailable",
            )
        )
        session.add(
            Incident(
                id="incident-open",
                correlation_id="watcher-correlation",
                entity_type="invoice",
                entity_id="INV-WATCHER",
                policy_name="invoice-processing",
                policy_version="v1",
                invariant_id="external_invoice_exists",
                severity="high",
                status="open",
                summary="open too long",
                evidence={},
                opened_at=clock["now"] - timedelta(minutes=1),
            )
        )
        session.add(
            RecoveryPlan(
                id="plan-attention",
                incident_id="incident-open",
                action_type="register_missing_invoice",
                parameters={},
                idempotency_key="recovery:plan-attention",
                requires_approval=True,
                status="needs_attention",
                plan_hash="a" * 64,
            )
        )
        session.add(
            ServiceHeartbeat(
                service="scheduler",
                observed_at=clock["now"] - timedelta(minutes=1),
                details={"state": "stalled"},
            )
        )
        session.commit()

    watcher = OpsWatcher(settings, factory, now=lambda: clock["now"])
    assert watcher.run_once() == 6
    assert watcher.run_once() == 0
    with factory() as session:
        assert session.get(ServiceHeartbeat, "ops-watcher") is not None
        assert {row.condition for row in session.query(AlertOutbox).all()} == {
            "deadline_job_terminal_failure",
            "verifier_unavailable_threshold",
            "scheduler_heartbeat_stale",
            "incident_open_too_long",
            "recovery_needs_attention",
            "migration_mismatch",
        }

        heartbeat = session.get(ServiceHeartbeat, "scheduler")
        assert heartbeat is not None
        heartbeat.observed_at = clock["now"]
        heartbeat.details = {"state": "running"}
        session.commit()

    assert watcher.run_once() == 1
    clock["now"] += timedelta(seconds=31)
    assert watcher.run_once() >= 1
    with factory() as session:
        rows = session.query(AlertOutbox).all()
        assert sum(row.condition == "scheduler_heartbeat_stale" for row in rows) == 2
        assert sum(row.condition == "scheduler_heartbeat_restored" for row in rows) == 1

        session.get(Incident, "incident-open").status = "resolved"  # type: ignore[union-attr]
        session.get(RecoveryPlan, "plan-attention").status = "verified"  # type: ignore[union-attr]
        session.get(DeadlineJob, "deadline-failed").state = "completed"  # type: ignore[union-attr]
        heartbeat = session.get(ServiceHeartbeat, "scheduler")
        assert heartbeat is not None
        heartbeat.observed_at = clock["now"]
        verifier_state = session.scalar(
            session.query(OperationalAlertState)
            .filter_by(condition="verifier_unavailable_threshold", subject="deadline-jobs")
            .statement
        )
        assert verifier_state is not None
        # Healthy observations must persist for the full configured window.
        verifier_state.updated_at = clock["now"]
        session.commit()

    assert watcher.run_once() == 1
    clock["now"] += timedelta(seconds=31)
    with factory() as session:
        heartbeat = session.get(ServiceHeartbeat, "scheduler")
        assert heartbeat is not None
        heartbeat.observed_at = clock["now"]
        session.commit()

    assert watcher.run_once() == 0
    with factory() as session:
        assert not session.scalar(
            session.query(OperationalAlertState.active)
            .filter_by(condition="incident_open_too_long", subject="incident-open")
            .statement
        )
        assert not session.scalar(
            session.query(OperationalAlertState.active)
            .filter_by(condition="recovery_needs_attention", subject="plan-attention")
            .statement
        )
        assert not session.scalar(
            session.query(OperationalAlertState.active)
            .filter_by(condition="verifier_unavailable_threshold", subject="deadline-jobs")
            .statement
        )
        session.get(Incident, "incident-open").status = "open"  # type: ignore[union-attr]
        session.get(RecoveryPlan, "plan-attention").status = "needs_attention"  # type: ignore[union-attr]
        session.commit()

    assert watcher.run_once() == 2
    with factory() as session:
        incident_state = session.scalar(
            session.query(OperationalAlertState)
            .filter_by(condition="incident_open_too_long", subject="incident-open")
            .statement
        )
        recovery_state = session.scalar(
            session.query(OperationalAlertState)
            .filter_by(condition="recovery_needs_attention", subject="plan-attention")
            .statement
        )
        assert (
            incident_state is not None and incident_state.active and incident_state.generation == 2
        )
        assert (
            recovery_state is not None and recovery_state.active and recovery_state.generation == 2
        )


def test_ops_watcher_alerts_for_n8n_credential_expiry_without_secret_metadata(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'credential-watcher.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    now = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    settings = Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="test",
        token_pepper="watcher-test-pepper-with-at-least-thirty-two-characters",
        alert_webhook_url="https://alerts.example.test/hook",
        n8n_credential_ttl_seconds=300,
        credential_expiry_alert_seconds=120,
    )
    with factory() as session:
        principal = Principal(
            id="n8n-principal",
            name="n8n-flowproof",
            kind="service",
            role=None,
            allowed_scopes=["events:write", "recovery:execute", "recovery:verify"],
        )
        session.add(principal)
        session.add(
            ApiCredential(
                id="n8n-credential",
                principal_id=principal.id,
                token_prefix="prefix",
                token_hash="a" * 64,
                scopes=["events:write"],
                credential_type="api",
                details={"label": "n8n-flowproof"},
                expires_at=now + timedelta(seconds=60),
            )
        )
        session.commit()

    watcher = OpsWatcher(settings, factory, now=lambda: now)
    assert watcher.run_once() >= 1
    assert watcher.run_once() == 0
    with factory() as session:
        alert = session.query(AlertOutbox).filter_by(condition="service_credential_expiring").one()
        summary = alert.payload["summary"]
        assert "n8n-credential" in summary and "n8n-principal" in summary
        assert "token" not in summary.lower() and "secret" not in summary.lower()
        session.get(ApiCredential, "n8n-credential").expires_at = now - timedelta(seconds=1)  # type: ignore[union-attr]
        session.commit()
    assert watcher.run_once() == 1
    with factory() as session:
        assert (
            session.query(AlertOutbox).filter_by(condition="service_credential_expired").count()
            == 1
        )


def test_n8n_credential_expiry_alert_lifecycle_handles_revoke_disable_and_replacement(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'credential-lifecycle.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    now = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
    settings = Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="test",
        token_pepper="watcher-test-pepper-with-at-least-thirty-two-characters",
        alert_webhook_url="https://alerts.example.test/hook",
        n8n_credential_ttl_seconds=300,
        credential_expiry_alert_seconds=120,
    )
    with factory() as session:
        principal = Principal(
            id="n8n-lifecycle-principal",
            name="n8n-flowproof",
            kind="service",
            role=None,
            allowed_scopes=["events:write", "recovery:execute", "recovery:verify"],
        )
        session.add(principal)
        for credential_id, expires_at, revoked_at, label in (
            ("outside-window", now + timedelta(seconds=121), None, "outside"),
            ("warning-window", now + timedelta(seconds=60), None, "warning"),
            ("expired-unrevoked", now - timedelta(seconds=1), None, "expired"),
            ("already-revoked", now + timedelta(seconds=60), now, "revoked"),
        ):
            session.add(
                ApiCredential(
                    id=credential_id,
                    principal_id=principal.id,
                    token_prefix="unused-prefix",
                    token_hash=(credential_id[0] * 64),
                    scopes=["events:write"],
                    credential_type="api",
                    details={"label": label},
                    expires_at=expires_at,
                    revoked_at=revoked_at,
                )
            )
        session.commit()

    watcher = OpsWatcher(settings, factory, now=lambda: now)
    assert watcher.run_once() >= 2
    assert watcher.run_once() == 0
    with factory() as session:
        warning = credential_alert_state(session, "service_credential_expiring", "warning-window")
        expired = credential_alert_state(session, "service_credential_expired", "expired-unrevoked")
        assert warning is not None and warning.active
        assert expired is not None and expired.active
        assert (
            credential_alert_state(session, "service_credential_expiring", "outside-window") is None
        )
        assert (
            credential_alert_state(session, "service_credential_expiring", "already-revoked")
            is None
        )
        summary = (
            session.query(AlertOutbox)
            .filter_by(condition="service_credential_expiring")
            .one()
            .payload["summary"]
        )
        assert all(
            value in summary for value in ("n8n-lifecycle-principal", "warning-window", "warning")
        )
        assert "token" not in summary.lower() and "secret" not in summary.lower()
        session.get(ApiCredential, "warning-window").revoked_at = now  # type: ignore[union-attr]
        session.get(Principal, "n8n-lifecycle-principal").disabled_at = now  # type: ignore[union-attr]
        session.commit()

    assert watcher.run_once() == 0
    with factory() as session:
        assert not credential_alert_state(
            session, "service_credential_expiring", "warning-window"
        ).active  # type: ignore[union-attr]
        assert not credential_alert_state(
            session, "service_credential_expired", "expired-unrevoked"
        ).active  # type: ignore[union-attr]
        session.get(Principal, "n8n-lifecycle-principal").disabled_at = None  # type: ignore[union-attr]
        session.add(
            ApiCredential(
                id="replacement-generation",
                principal_id="n8n-lifecycle-principal",
                token_prefix="unused-prefix",
                token_hash="r" * 64,
                scopes=["events:write"],
                credential_type="api",
                details={"label": "replacement"},
                expires_at=now + timedelta(seconds=60),
            )
        )
        session.commit()

    restarted_watcher = OpsWatcher(settings, factory, now=lambda: now)
    assert restarted_watcher.run_once() >= 1
    assert restarted_watcher.run_once() == 0
    with factory() as session:
        replacement = credential_alert_state(
            session, "service_credential_expiring", "replacement-generation"
        )
        assert replacement is not None and replacement.active and replacement.generation == 1
        session.get(ApiCredential, "replacement-generation").expires_at = now - timedelta(seconds=1)  # type: ignore[union-attr]
        session.commit()

    assert restarted_watcher.run_once() >= 1
    with factory() as session:
        assert not credential_alert_state(
            session, "service_credential_expiring", "replacement-generation"
        ).active  # type: ignore[union-attr]
        assert credential_alert_state(
            session, "service_credential_expired", "replacement-generation"
        ).active  # type: ignore[union-attr]
