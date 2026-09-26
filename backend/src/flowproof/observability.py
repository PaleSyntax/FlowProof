"""Redacted structured logs and bounded-cardinality Prometheus text metrics."""

from __future__ import annotations

import json
import logging
from collections import Counter
from threading import Lock
from typing import TYPE_CHECKING

from sqlalchemy import func, select

from flowproof.models import DeadlineJob, Incident, RecoveryPlan

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from flowproof.config import Settings


SAFE_EVENT_CODES = frozenset(
    {
        "alert_outbox_processed",
        "alert_worker_stopping",
        "ops_watcher_alerts_queued",
        "ops_watcher_stopping",
        "readiness_failed",
        "request_completed",
        "request_failed",
        "scheduler processed %s deadline job(s)",
        "scheduler received signal %s; stopping after the current job",
    }
)
SAFE_LOG_FIELDS = ("request_id", "status_code", "error_type")


class JsonFormatter(logging.Formatter):
    """Whitelists operational fields so headers, bodies and exception text never leak."""

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def format(self, record: logging.LogRecord) -> str:
        message = record.msg if isinstance(record.msg, str) else ""
        payload: dict[str, object] = {
            "level": record.levelname.lower(),
            "event": message if message in SAFE_EVENT_CODES else "unclassified_log_event",
            "service": "flowproof-api",
            "version": "0.6.0",
            "environment": self.settings.environment,
        }
        for key in SAFE_LOG_FIELDS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        error_type = getattr(record, "error_type", None)
        if error_type:
            payload["error_type"] = error_type
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def configure_structured_logging(settings: Settings) -> None:
    root = logging.getLogger()
    handler = getattr(root, "_flowproof_json_handler", None)
    if isinstance(handler, logging.Handler):
        handler.setFormatter(JsonFormatter(settings))
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter(settings))
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    root._flowproof_json_handler = handler  # type: ignore[attr-defined]
    for logger_name in (
        "httpcore",
        "httpx",
        "sqlalchemy.engine",
        "sqlalchemy.pool",
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
    ):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.WARNING)
        logger.propagate = False


class Metrics:
    """Small in-process counters plus database-derived gauges; labels are intentionally finite."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._http_requests: Counter[tuple[str, int]] = Counter()
        self._authentication_failures = 0
        self._authorization_denials = 0
        self._alert_deliveries: Counter[str] = Counter()

    def record_http(self, method: str, status_code: int) -> None:
        with self._lock:
            self._http_requests[(method.upper(), status_code)] += 1

    def record_authentication_failure(self) -> None:
        with self._lock:
            self._authentication_failures += 1

    def record_authorization_denial(self) -> None:
        with self._lock:
            self._authorization_denials += 1

    def record_alert_delivery(self, outcome: str) -> None:
        with self._lock:
            self._alert_deliveries[outcome] += 1

    def render(self, factory: sessionmaker[Session]) -> str:
        with self._lock:
            requests = dict(self._http_requests)
            authentication_failures = self._authentication_failures
            authorization_denials = self._authorization_denials
            alert_deliveries = dict(self._alert_deliveries)
        with factory() as session:
            deadline_states = dict(
                session.execute(
                    select(DeadlineJob.state, func.count()).group_by(DeadlineJob.state)
                ).all()
            )
            open_incidents = session.scalar(
                select(func.count()).select_from(Incident).where(Incident.status != "resolved")
            )
            recovery_states = dict(
                session.execute(
                    select(RecoveryPlan.status, func.count()).group_by(RecoveryPlan.status)
                ).all()
            )
            verifier_failures = session.scalar(
                select(func.count())
                .select_from(DeadlineJob)
                .where(DeadlineJob.last_error.like("external_verifier%"))
            )
        lines = [
            "# HELP flowproof_http_requests_total HTTP responses by method and status.",
            "# TYPE flowproof_http_requests_total counter",
        ]
        lines.extend(
            f'flowproof_http_requests_total{{method="{method}",status="{status}"}} {count}'
            for (method, status), count in sorted(requests.items())
        )
        lines.extend(
            [
                "# TYPE flowproof_authentication_failures_total counter",
                f"flowproof_authentication_failures_total {authentication_failures}",
                "# TYPE flowproof_authorization_denials_total counter",
                f"flowproof_authorization_denials_total {authorization_denials}",
                "# TYPE flowproof_deadline_jobs gauge",
            ]
        )
        lines.extend(
            f'flowproof_deadline_jobs{{state="{state}"}} {count}'
            for state, count in sorted(deadline_states.items())
            if state in {"pending", "retry", "running", "completed", "failed"}
        )
        lines.extend(
            [
                "# TYPE flowproof_open_incidents gauge",
                f"flowproof_open_incidents {open_incidents or 0}",
                "# TYPE flowproof_recovery_outcomes gauge",
            ]
        )
        lines.extend(
            f'flowproof_recovery_outcomes{{status="{state}"}} {count}'
            for state, count in sorted(recovery_states.items())
            if state
            in {
                "proposed",
                "approved",
                "executing",
                "verifying",
                "still_failed",
                "verified",
                "needs_attention",
            }
        )
        lines.extend(
            [
                "# TYPE flowproof_verifier_failures gauge",
                f"flowproof_verifier_failures {verifier_failures or 0}",
                "# TYPE flowproof_alert_deliveries_total counter",
            ]
        )
        lines.extend(
            f'flowproof_alert_deliveries_total{{outcome="{outcome}"}} {count}'
            for outcome, count in sorted(alert_deliveries.items())
            if outcome in {"delivered", "failed"}
        )
        return "\n".join(lines) + "\n"
