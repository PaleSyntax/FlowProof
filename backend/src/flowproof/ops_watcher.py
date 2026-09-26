"""Durable operational-alert reconciliation, separate from the scheduler."""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from flowproof.alerts import Alert, enqueue_alert, normalize_utc, utc_now
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.health import migration_revision
from flowproof.models import (
    ApiCredential,
    DeadlineJob,
    Incident,
    OperationalAlertState,
    Principal,
    RecoveryPlan,
    ServiceHeartbeat,
)
from flowproof.observability import configure_structured_logging

LOG = logging.getLogger(__name__)


class OpsWatcher:
    """Turns durable operational state changes into bounded, deduplicated alerts."""

    def __init__(
        self,
        settings: Settings,
        factory: sessionmaker[Session],
        *,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.settings = settings
        self.factory = factory
        self.now = now

    def run_once(self) -> int:
        now = normalize_utc(self.now())
        with self.factory() as session:
            self._heartbeat(session, now)
            queued = (
                self._terminal_deadlines(session, now)
                + self._verifier_threshold(session, now)
                + self._scheduler_heartbeat(session, now)
                + self._open_incidents(session, now)
                + self._recoveries_needing_attention(session, now)
                + self._migration_state(session, now)
                + self._service_credential_expiry(session, now)
            )
            session.commit()
        return queued

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            queued = self.run_once()
            if queued:
                LOG.info("ops_watcher_alerts_queued", extra={"status_code": queued})
            stop_event.wait(self.settings.ops_watcher_poll_seconds)

    @staticmethod
    def _heartbeat(session: Session, now: datetime) -> None:
        row = session.get(ServiceHeartbeat, "ops-watcher")
        if row is None:
            session.add(
                ServiceHeartbeat(
                    service="ops-watcher", observed_at=now, details={"state": "running"}
                )
            )
        else:
            row.observed_at = now
            row.details = {"state": "running"}

    def _activate(
        self,
        session: Session,
        *,
        condition: str,
        subject: str,
        severity: str,
        summary: str,
        now: datetime,
        dedupe_key: str | None = None,
    ) -> int:
        state = session.scalar(
            select(OperationalAlertState).where(
                OperationalAlertState.condition == condition,
                OperationalAlertState.subject == subject,
            )
        )
        if state is None:
            state = OperationalAlertState(
                id=str(uuid4()), condition=condition, subject=subject, active=False, generation=0
            )
            session.add(state)
            session.flush()
        if state.active:
            return 0
        state.active = True
        state.generation += 1
        state.activated_at = now
        state.resolved_at = None
        _, duplicate = enqueue_alert(
            session,
            Alert(condition=condition, severity=severity, summary=summary, occurred_at=now),
            dedupe_key=dedupe_key or f"ops:{condition}:{subject}:{state.generation}",
        )
        return 0 if duplicate else 1

    @staticmethod
    def _deactivate(session: Session, *, condition: str, subject: str, now: datetime) -> bool:
        state = session.scalar(
            select(OperationalAlertState).where(
                OperationalAlertState.condition == condition,
                OperationalAlertState.subject == subject,
            )
        )
        if state is None or not state.active:
            return False
        state.active = False
        state.resolved_at = now
        return True

    def _terminal_deadlines(self, session: Session, now: datetime) -> int:
        jobs = session.scalars(select(DeadlineJob).where(DeadlineJob.state == "failed")).all()
        return sum(
            self._activate(
                session,
                condition="deadline_job_terminal_failure",
                subject=job.id,
                severity="high",
                summary="A deadline job reached its terminal failure state",
                now=now,
                dedupe_key=f"deadline_job_terminal_failure:{job.id}",
            )
            for job in jobs
        )

    def _verifier_threshold(self, session: Session, now: datetime) -> int:
        cutoff = now - timedelta(seconds=self.settings.ops_watcher_verifier_observation_seconds)
        count = (
            session.scalar(
                select(func.count())
                .select_from(DeadlineJob)
                .where(DeadlineJob.last_error.like("external_verifier%"))
                .where(DeadlineJob.state.in_(("retry", "failed")))
                .where(DeadlineJob.updated_at >= cutoff)
            )
            or 0
        )
        subject = "deadline-jobs"
        state = session.scalar(
            select(OperationalAlertState).where(
                OperationalAlertState.condition == "verifier_unavailable_threshold",
                OperationalAlertState.subject == subject,
            )
        )
        if count >= self.settings.ops_watcher_verifier_failure_threshold:
            if state is not None and state.active:
                # Keep the last unhealthy observation durable. A single healthy
                # poll must not immediately resolve a degraded verifier fleet.
                state.updated_at = now
                return 0
            return self._activate(
                session,
                condition="verifier_unavailable_threshold",
                subject=subject,
                severity="high",
                summary="External verifier failures exceeded the configured threshold",
                now=now,
            )
        if state is None or not state.active:
            return 0
        if normalize_utc(state.updated_at) > cutoff:
            return 0
        self._deactivate(
            session, condition="verifier_unavailable_threshold", subject=subject, now=now
        )
        return 0

    def _scheduler_heartbeat(self, session: Session, now: datetime) -> int:
        subject = "scheduler"
        heartbeat = session.get(ServiceHeartbeat, subject)
        stale = heartbeat is None or normalize_utc(heartbeat.observed_at) < now - timedelta(
            seconds=self.settings.ops_watcher_heartbeat_stale_seconds
        )
        if stale:
            return self._activate(
                session,
                condition="scheduler_heartbeat_stale",
                subject=subject,
                severity="high",
                summary="The scheduler durable heartbeat is stale or absent",
                now=now,
            )
        restored = self._deactivate(
            session, condition="scheduler_heartbeat_stale", subject=subject, now=now
        )
        if not restored:
            return 0
        state = session.scalar(
            select(OperationalAlertState).where(
                OperationalAlertState.condition == "scheduler_heartbeat_stale",
                OperationalAlertState.subject == subject,
            )
        )
        assert state is not None
        _, duplicate = enqueue_alert(
            session,
            Alert(
                condition="scheduler_heartbeat_restored",
                severity="info",
                summary="The scheduler durable heartbeat has resumed",
                occurred_at=now,
            ),
            dedupe_key=f"scheduler_heartbeat_restored:{subject}:{state.generation}",
        )
        return 0 if duplicate else 1

    def _open_incidents(self, session: Session, now: datetime) -> int:
        cutoff = now - timedelta(seconds=self.settings.alert_open_incident_seconds)
        incidents = session.scalars(
            select(Incident).where(Incident.status != "resolved", Incident.opened_at <= cutoff)
        ).all()
        active_subjects = {incident.id for incident in incidents}
        for state in session.scalars(
            select(OperationalAlertState).where(
                OperationalAlertState.condition == "incident_open_too_long",
                OperationalAlertState.active.is_(True),
            )
        ):
            if state.subject not in active_subjects:
                self._deactivate(
                    session,
                    condition="incident_open_too_long",
                    subject=state.subject,
                    now=now,
                )
        return sum(
            self._activate(
                session,
                condition="incident_open_too_long",
                subject=incident.id,
                severity=incident.severity,
                summary="An incident remains open beyond the configured operational threshold",
                now=now,
            )
            for incident in incidents
        )

    def _recoveries_needing_attention(self, session: Session, now: datetime) -> int:
        plans = session.scalars(
            select(RecoveryPlan).where(RecoveryPlan.status == "needs_attention")
        ).all()
        active_subjects = {plan.id for plan in plans}
        for state in session.scalars(
            select(OperationalAlertState).where(
                OperationalAlertState.condition == "recovery_needs_attention",
                OperationalAlertState.active.is_(True),
            )
        ):
            if state.subject not in active_subjects:
                self._deactivate(
                    session,
                    condition="recovery_needs_attention",
                    subject=state.subject,
                    now=now,
                )
        return sum(
            self._activate(
                session,
                condition="recovery_needs_attention",
                subject=plan.id,
                severity="high",
                summary="A recovery plan requires operator attention",
                now=now,
            )
            for plan in plans
        )

    def _migration_state(self, session: Session, now: datetime) -> int:
        current, head = migration_revision(self.factory)
        subject = "database"
        if current == head:
            self._deactivate(session, condition="migration_mismatch", subject=subject, now=now)
            return 0
        return self._activate(
            session,
            condition="migration_mismatch",
            subject=subject,
            severity="critical",
            summary="Database Alembic revision does not match the application migration head",
            now=now,
        )

    def _service_credential_expiry(self, session: Session, now: datetime) -> int:
        """Alert only for the fixed n8n service account; metadata stays public."""
        principal = session.scalar(select(Principal).where(Principal.name == "n8n-flowproof"))
        credentials = (
            session.scalars(
                select(ApiCredential).where(ApiCredential.principal_id == principal.id)
            ).all()
            if principal is not None
            else []
        )
        observable_subjects = {
            credential.id
            for credential in credentials
            if principal is not None
            and principal.disabled_at is None
            and credential.revoked_at is None
            and credential.expires_at is not None
        }
        for state in session.scalars(
            select(OperationalAlertState).where(
                OperationalAlertState.condition.in_(
                    ("service_credential_expiring", "service_credential_expired")
                ),
                OperationalAlertState.active.is_(True),
            )
        ):
            if state.subject not in observable_subjects:
                self._deactivate(session, condition=state.condition, subject=state.subject, now=now)
        if principal is None or principal.disabled_at is not None:
            return 0
        queued = 0
        for credential in credentials:
            if credential.revoked_at is not None or credential.expires_at is None:
                continue
            expires_at = normalize_utc(credential.expires_at)
            subject = credential.id
            label = str(credential.details.get("label") or "unlabeled")[:64]
            metadata = (
                f"credential_id={credential.id}; principal_id={principal.id}; label={label}; "
                f"expires_at={expires_at.isoformat()}"
            )
            if expires_at <= now:
                self._deactivate(
                    session, condition="service_credential_expiring", subject=subject, now=now
                )
                queued += self._activate(
                    session,
                    condition="service_credential_expired",
                    subject=subject,
                    severity="high",
                    summary=f"n8n service credential expired ({metadata})",
                    now=now,
                )
            elif expires_at <= now + timedelta(
                seconds=self.settings.credential_expiry_alert_seconds
            ):
                self._deactivate(
                    session, condition="service_credential_expired", subject=subject, now=now
                )
                queued += self._activate(
                    session,
                    condition="service_credential_expiring",
                    subject=subject,
                    severity="warning",
                    summary=f"n8n service credential is expiring ({metadata})",
                    now=now,
                )
            else:
                self._deactivate(
                    session, condition="service_credential_expiring", subject=subject, now=now
                )
                self._deactivate(
                    session, condition="service_credential_expired", subject=subject, now=now
                )
        return queued


def main() -> None:
    settings = Settings.from_environment()
    configure_structured_logging(settings)
    watcher = OpsWatcher(settings, make_session_factory(make_engine(settings.database_url)))
    stop_event = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        LOG.info("ops_watcher_stopping", extra={"status_code": signum})
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, request_stop)
    watcher.run_forever(stop_event)


if __name__ == "__main__":
    main()
