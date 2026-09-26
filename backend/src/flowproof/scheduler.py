"""Durable, lease-based deadline evaluation worker for FlowProof."""

from __future__ import annotations

import logging
import signal
import socket
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from flowproof.accounting import AccountingClient, HttpAccountingClient, ProviderContract
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import DeadlineJob, ServiceHeartbeat
from flowproof.observability import configure_structured_logging
from flowproof.service import FlowProofService, normalize_utc, utc_now

LOG = logging.getLogger(__name__)
PENDING_STATES = ("pending", "retry")


class DeadlineScheduler:
    """Claims due persisted jobs and delegates deterministic evaluation to the service layer.

    Delivery is at-least-once: an expired lease can make an already-started job eligible again.
    Business effects remain safe because the service preserves its existing database constraints and
    idempotency keys for incidents, recovery plans, and verified events.
    """

    def __init__(
        self,
        settings: Settings,
        factory: sessionmaker[Session],
        accounting: AccountingClient,
        *,
        worker_id: str | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.settings = settings
        self.factory = factory
        self.accounting = accounting
        self.worker_id = worker_id or f"scheduler-{socket.gethostname()}-{uuid4().hex[:8]}"
        self.now = now

    def run_once(self, limit: int = 32) -> int:
        """Claim and process one bounded batch; useful for tests and supervised processes."""
        self._heartbeat()
        job_ids = self._claim_due_jobs(limit)
        for job_id in job_ids:
            self._process_claimed_job(job_id)
        return len(job_ids)

    def _heartbeat(self) -> None:
        now = normalize_utc(self.now())
        with self.factory() as session:
            row = session.get(ServiceHeartbeat, "scheduler")
            if row is None:
                session.add(
                    ServiceHeartbeat(
                        service="scheduler", observed_at=now, details={"state": "running"}
                    )
                )
            else:
                row.observed_at = now
                row.details = {"state": "running"}
            session.commit()

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            claimed = self.run_once()
            if claimed:
                LOG.info("scheduler processed %s deadline job(s)", claimed)
            stop_event.wait(self.settings.scheduler_poll_seconds)

    def _eligible_clause(self, now: datetime):
        return or_(
            and_(
                DeadlineJob.state.in_(PENDING_STATES),
                DeadlineJob.due_at <= now,
                DeadlineJob.next_attempt_at <= now,
            ),
            and_(
                DeadlineJob.state == "running",
                DeadlineJob.lease_expires_at.is_not(None),
                DeadlineJob.lease_expires_at <= now,
            ),
        )

    def _claim_due_jobs(self, limit: int) -> list[str]:
        now = normalize_utc(self.now())
        eligible = self._eligible_clause(now)
        lease_expires_at = now + timedelta(seconds=self.settings.scheduler_lease_seconds)
        claimed: list[str] = []
        with self.factory() as session:
            session.execute(
                update(DeadlineJob)
                .where(eligible, DeadlineJob.attempt_count >= self.settings.scheduler_max_attempts)
                .values(
                    state="failed",
                    lease_owner=None,
                    lease_expires_at=None,
                    last_error="attempt_limit_reached",
                    completed_at=now,
                    updated_at=now,
                )
            )
            candidates = session.scalars(
                select(DeadlineJob.id)
                .where(eligible, DeadlineJob.attempt_count < self.settings.scheduler_max_attempts)
                .order_by(DeadlineJob.next_attempt_at, DeadlineJob.id)
                .limit(limit)
            ).all()
            for job_id in candidates:
                result = session.execute(
                    update(DeadlineJob)
                    .where(
                        DeadlineJob.id == job_id,
                        self._eligible_clause(now),
                        DeadlineJob.attempt_count < self.settings.scheduler_max_attempts,
                    )
                    .values(
                        state="running",
                        attempt_count=DeadlineJob.attempt_count + 1,
                        lease_owner=self.worker_id,
                        lease_expires_at=lease_expires_at,
                        last_error=None,
                        updated_at=now,
                    )
                )
                if result.rowcount == 1:
                    claimed.append(job_id)
            session.commit()
        return claimed

    def _process_claimed_job(self, job_id: str) -> None:
        with self.factory() as session:
            job = session.get(DeadlineJob, job_id)
            if not job or job.state != "running" or job.lease_owner != self.worker_id:
                return
            effective_now = max(
                normalize_utc(self.now()),
                normalize_utc(job.due_at),
                normalize_utc(job.updated_at),
            )
            try:
                results = FlowProofService(
                    session,
                    str(self.settings.policy_path),
                    self.accounting,
                    # A claimed due job must not become pre-deadline if the VM
                    # wall clock is resynchronized backwards mid-batch.
                    now=lambda: effective_now,
                    recovery_writes_enabled=self.settings.recovery_writes_enabled,
                ).evaluate(job.correlation_id, policy_id=job.policy_id)
                target = next(
                    (result for result in results if result["invariant_id"] == job.invariant_id),
                    None,
                )
                if target is None:
                    self._fail(
                        session,
                        job_id,
                        "scheduled_invariant_missing",
                        effective_now=effective_now,
                    )
                elif target["state"] == "error":
                    self._retry_or_fail(
                        session,
                        job_id,
                        "external_verifier_unavailable",
                        effective_now=effective_now,
                    )
                elif target["state"] == "pending":
                    self._retry_or_fail(
                        session,
                        job_id,
                        "scheduled_invariant_still_pending",
                        effective_now=effective_now,
                    )
                else:
                    self._complete(session, job_id, effective_now=effective_now)
            except Exception as exc:  # Keep unexpected worker failures retryable and sanitized.
                session.rollback()
                LOG.warning("deadline job %s evaluation failed: %s", job_id, type(exc).__name__)
                self._retry_or_fail(
                    session,
                    job_id,
                    f"evaluation_failed:{type(exc).__name__}",
                    effective_now=effective_now,
                )

    def _complete(
        self,
        session: Session,
        job_id: str,
        *,
        effective_now: datetime | None = None,
    ) -> None:
        now = effective_now or normalize_utc(self.now())
        session.execute(
            update(DeadlineJob)
            .where(
                DeadlineJob.id == job_id,
                DeadlineJob.state == "running",
                DeadlineJob.lease_owner == self.worker_id,
            )
            .values(
                state="completed",
                lease_owner=None,
                lease_expires_at=None,
                last_error=None,
                completed_at=now,
                updated_at=now,
            )
        )
        session.commit()

    def _retry_or_fail(
        self,
        session: Session,
        job_id: str,
        error: str,
        *,
        effective_now: datetime | None = None,
    ) -> None:
        job = session.get(DeadlineJob, job_id)
        if not job or job.state != "running" or job.lease_owner != self.worker_id:
            return
        now = effective_now or normalize_utc(self.now())
        if job.attempt_count >= self.settings.scheduler_max_attempts:
            self._fail(session, job_id, error, effective_now=now)
            return
        delay_seconds = min(
            self.settings.scheduler_retry_base_seconds * (2 ** min(job.attempt_count - 1, 8)),
            3_600,
        )
        session.execute(
            update(DeadlineJob)
            .where(
                DeadlineJob.id == job_id,
                DeadlineJob.state == "running",
                DeadlineJob.lease_owner == self.worker_id,
            )
            .values(
                state="retry",
                next_attempt_at=now + timedelta(seconds=delay_seconds),
                lease_owner=None,
                lease_expires_at=None,
                last_error=error[:255],
                updated_at=now,
            )
        )
        session.commit()

    def _fail(
        self,
        session: Session,
        job_id: str,
        error: str,
        *,
        effective_now: datetime | None = None,
    ) -> None:
        now = effective_now or normalize_utc(self.now())
        session.execute(
            update(DeadlineJob)
            .where(
                DeadlineJob.id == job_id,
                DeadlineJob.state == "running",
                DeadlineJob.lease_owner == self.worker_id,
            )
            .values(
                state="failed",
                lease_owner=None,
                lease_expires_at=None,
                last_error=error[:255],
                completed_at=now,
                updated_at=now,
            )
        )
        session.commit()


def build_accounting_client(settings: Settings) -> HttpAccountingClient:
    if settings.provider_contract_path is None:
        raise RuntimeError("provider contract path is required")
    return HttpAccountingClient(
        settings.mock_accounting_url,
        ProviderContract.load(settings.provider_contract_path),
    )


def main() -> None:
    settings = Settings.from_environment()
    settings.validate_production_security()
    configure_structured_logging(settings)
    scheduler = DeadlineScheduler(
        settings,
        make_session_factory(make_engine(settings.database_url)),
        build_accounting_client(settings),
    )
    stop_event = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        LOG.info("scheduler received signal %s; stopping after the current job", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, request_stop)
    scheduler.run_forever(stop_event)


if __name__ == "__main__":
    main()
