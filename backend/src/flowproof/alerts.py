"""A narrow generic webhook alert contract; no provider-specific alerting is embedded."""

from __future__ import annotations

import logging
import signal
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

import httpx
from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from flowproof.clock import monotonic_utc_now
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import AlertOutbox, ServiceHeartbeat
from flowproof.observability import configure_structured_logging

LOG = logging.getLogger(__name__)
PENDING_STATES = ("pending", "retry")


def utc_now() -> datetime:
    return monotonic_utc_now()


def normalize_utc(value: datetime) -> datetime:
    """SQLite test rows can be naive while PostgreSQL keeps UTC offsets."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Alert:
    condition: str
    severity: str
    summary: str
    occurred_at: datetime
    service: str = "flowproof-api"
    version: str = "0.6.0"

    def payload(self) -> dict[str, str]:
        return {
            "condition": self.condition,
            "severity": self.severity,
            "summary": self.summary,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat(),
            "service": self.service,
            "version": self.version,
        }


class AlertDispatchError(RuntimeError):
    pass


class AlertDispatcher(Protocol):
    def dispatch(self, alert: Alert) -> None: ...


class WebhookAlertDispatcher:
    def __init__(self, destination: str, timeout_seconds: float = 5.0) -> None:
        self.destination = destination
        self.timeout_seconds = timeout_seconds

    def dispatch(self, alert: Alert) -> None:
        try:
            response = httpx.post(
                self.destination, json=alert.payload(), timeout=self.timeout_seconds
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AlertDispatchError(type(exc).__name__) from exc


class NullAlertDispatcher:
    def dispatch(self, alert: Alert) -> None:
        del alert


def enqueue_alert(session: Session, alert: Alert, dedupe_key: str) -> tuple[AlertOutbox, bool]:
    """Add an alert once. A unique dedupe key makes repeated effects safe."""

    now = normalize_utc(alert.occurred_at)
    row = AlertOutbox(
        id=str(uuid4()),
        condition=alert.condition,
        dedupe_key=dedupe_key,
        severity=alert.severity,
        payload=alert.payload(),
        state="pending",
        attempt_count=0,
        next_attempt_at=now,
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        existing = session.scalar(select(AlertOutbox).where(AlertOutbox.dedupe_key == dedupe_key))
        if existing is None:  # pragma: no cover - defensive concurrent rollback guard
            raise
        return existing, True
    return row, False


class AlertOutboxWorker:
    """Lease-based at-least-once dispatcher for durable outbound alerts."""

    def __init__(
        self,
        settings: Settings,
        factory: sessionmaker[Session],
        dispatcher: AlertDispatcher,
        *,
        worker_id: str | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.settings = settings
        self.factory = factory
        self.dispatcher = dispatcher
        self.worker_id = worker_id or f"alert-worker-{socket.gethostname()}-{uuid4().hex[:8]}"
        self.now = now

    def run_once(self, limit: int = 32) -> int:
        self._heartbeat()
        rows = self._claim_due(limit)
        for row_id in rows:
            self._deliver(row_id)
        return len(rows)

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            claimed = self.run_once()
            if claimed:
                LOG.info("alert_outbox_processed", extra={"status_code": claimed})
            stop_event.wait(self.settings.alert_worker_poll_seconds)

    def _heartbeat(self) -> None:
        now = normalize_utc(self.now())
        with self.factory() as session:
            row = session.get(ServiceHeartbeat, "alert-worker")
            if row is None:
                session.add(
                    ServiceHeartbeat(
                        service="alert-worker", observed_at=now, details={"state": "running"}
                    )
                )
            else:
                row.observed_at = now
                row.details = {"state": "running"}
            session.commit()

    def _eligible(self, now: datetime):
        return or_(
            and_(AlertOutbox.state.in_(PENDING_STATES), AlertOutbox.next_attempt_at <= now),
            and_(
                AlertOutbox.state == "running",
                AlertOutbox.lease_expires_at.is_not(None),
                AlertOutbox.lease_expires_at <= now,
            ),
        )

    def _claim_due(self, limit: int) -> list[str]:
        now = normalize_utc(self.now())
        lease_until = now + timedelta(seconds=self.settings.alert_lease_seconds)
        claimed: list[str] = []
        with self.factory() as session:
            eligible = self._eligible(now)
            session.execute(
                update(AlertOutbox)
                .where(eligible, AlertOutbox.attempt_count >= self.settings.alert_max_attempts)
                .values(
                    state="terminal",
                    lease_owner=None,
                    lease_expires_at=None,
                    terminal_at=now,
                    last_error="attempt_limit_reached",
                    updated_at=now,
                )
            )
            candidates = session.scalars(
                select(AlertOutbox.id)
                .where(eligible, AlertOutbox.attempt_count < self.settings.alert_max_attempts)
                .order_by(AlertOutbox.next_attempt_at, AlertOutbox.id)
                .limit(limit)
            ).all()
            for row_id in candidates:
                result = session.execute(
                    update(AlertOutbox)
                    .where(
                        AlertOutbox.id == row_id,
                        self._eligible(now),
                        AlertOutbox.attempt_count < self.settings.alert_max_attempts,
                    )
                    .values(
                        state="running",
                        attempt_count=AlertOutbox.attempt_count + 1,
                        lease_owner=self.worker_id,
                        lease_expires_at=lease_until,
                        last_error=None,
                        updated_at=now,
                    )
                )
                if result.rowcount == 1:
                    claimed.append(row_id)
            session.commit()
        return claimed

    def _deliver(self, row_id: str) -> None:
        with self.factory() as session:
            row = session.get(AlertOutbox, row_id)
            if not row or row.state != "running" or row.lease_owner != self.worker_id:
                return
            try:
                payload = row.payload
                occurred_at = datetime.fromisoformat(
                    str(payload["occurred_at"]).replace("Z", "+00:00")
                )
                self.dispatcher.dispatch(
                    Alert(
                        condition=str(payload["condition"]),
                        severity=str(payload["severity"]),
                        summary=str(payload["summary"]),
                        occurred_at=occurred_at,
                        service=str(payload.get("service", "flowproof-api")),
                        version=str(payload.get("version", "0.6.0")),
                    )
                )
            except (AlertDispatchError, KeyError, TypeError, ValueError) as exc:
                session.rollback()
                self._retry_or_terminal(row_id, type(exc).__name__)
                return
            now = normalize_utc(self.now())
            session.execute(
                update(AlertOutbox)
                .where(
                    AlertOutbox.id == row_id,
                    AlertOutbox.state == "running",
                    AlertOutbox.lease_owner == self.worker_id,
                )
                .values(
                    state="delivered",
                    lease_owner=None,
                    lease_expires_at=None,
                    delivered_at=now,
                    last_error=None,
                    updated_at=now,
                )
            )
            session.commit()

    def _retry_or_terminal(self, row_id: str, error_type: str) -> None:
        now = normalize_utc(self.now())
        with self.factory() as session:
            row = session.get(AlertOutbox, row_id)
            if not row or row.state != "running" or row.lease_owner != self.worker_id:
                return
            if row.attempt_count >= self.settings.alert_max_attempts:
                row.state = "terminal"
                row.terminal_at = now
                row.next_attempt_at = now
            else:
                row.state = "retry"
                row.next_attempt_at = now + timedelta(
                    seconds=min(
                        self.settings.alert_retry_base_seconds
                        * (2 ** min(row.attempt_count - 1, 8)),
                        3_600,
                    )
                )
            row.lease_owner = None
            row.lease_expires_at = None
            row.last_error = error_type[:255]
            row.updated_at = now
            session.commit()


def main() -> None:
    settings = Settings.from_environment()
    configure_structured_logging(settings)
    dispatcher: AlertDispatcher = (
        WebhookAlertDispatcher(settings.alert_webhook_url)
        if settings.alert_webhook_url
        else NullAlertDispatcher()
    )
    worker = AlertOutboxWorker(
        settings,
        make_session_factory(make_engine(settings.database_url)),
        dispatcher,
    )
    stop_event = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        LOG.info("alert_worker_stopping", extra={"status_code": signum})
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, request_stop)
    worker.run_forever(stop_event)


if __name__ == "__main__":
    main()
