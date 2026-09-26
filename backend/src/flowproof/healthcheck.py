"""Container health probes that fail closed on stale durable worker heartbeats."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta

from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import ServiceHeartbeat


def is_service_healthy(service: str, max_age_seconds: int = 90) -> bool:
    settings = Settings.from_environment()
    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as session:
        heartbeat = session.get(ServiceHeartbeat, service)
        if heartbeat is None:
            return False
        observed_at = heartbeat.observed_at
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=UTC)
        return observed_at >= datetime.now(UTC) - timedelta(seconds=max_age_seconds)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--service", required=True, choices=("scheduler", "alert-worker", "ops-watcher")
    )
    parser.add_argument("--max-age-seconds", type=int, default=90)
    args = parser.parse_args()
    if args.max_age_seconds <= 0:
        parser.error("--max-age-seconds must be positive")
    return 0 if is_service_healthy(args.service, args.max_age_seconds) else 1


if __name__ == "__main__":
    raise SystemExit(main())
