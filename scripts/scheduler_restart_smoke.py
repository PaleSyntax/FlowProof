"""Phases for the isolated Docker scheduler restart and PostgreSQL contention smoke."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from flowproof.accounting import HttpAccountingClient
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import DeadlineJob, Incident, RecoveryPlan
from flowproof.scheduler import DeadlineScheduler
from flowproof.schemas import BusinessEventIn
from flowproof.service import FlowProofService

API = os.getenv("FLOWPROOF_API_URL", "http://localhost:8000/api/v1").rstrip("/")
MOCK = os.getenv("MOCK_ACCOUNTING_URL", "http://localhost:8001").rstrip("/")
SMOKE_TOKEN = os.getenv("FLOWPROOF_SCHEDULER_SMOKE_TOKEN")
CORRELATION_ID = os.environ.get("FLOWPROOF_SMOKE_CORRELATION_ID")
INVOICE_ID = os.environ.get("FLOWPROOF_SMOKE_INVOICE_ID")


def service_headers() -> dict[str, str]:
    if not SMOKE_TOKEN:
        raise RuntimeError("scheduler smoke Bearer credential is missing for an HTTP phase")
    return {"Authorization": f"Bearer {SMOKE_TOKEN}"}


def request(
    client: httpx.Client, method: str, url: str, **kwargs: Any
) -> dict[str, Any]:
    response = client.request(method, url, **kwargs)
    if response.status_code == 204:
        return {}
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"{method} {url} returned non-JSON {response.status_code}"
        ) from exc
    if response.is_error:
        raise RuntimeError(f"{method} {url} -> {response.status_code}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"{method} {url} returned an unexpected JSON type")
    return payload


def required_identifiers() -> tuple[str, str]:
    if not CORRELATION_ID or not INVOICE_ID:
        raise RuntimeError("restart smoke identifiers are missing")
    return CORRELATION_ID, INVOICE_ID


def event_body(
    event_type: str, suffix: str, occurred_at: datetime
) -> dict[str, object]:
    correlation_id, invoice_id = required_identifiers()
    return {
        "idempotency_key": f"restart-smoke:{invoice_id}:{suffix}",
        "correlation_id": correlation_id,
        "entity_type": "invoice",
        "entity_id": invoice_id,
        "event_type": event_type,
        "occurred_at": occurred_at.isoformat(),
        "source": {"system": "scheduler-restart-smoke", "execution_id": correlation_id},
        "payload": {"amount": 18000.0, "currency": "RUB"},
    }


def target_job(items: list[object]) -> dict[str, Any]:
    matches = [
        item
        for item in items
        if isinstance(item, dict)
        and item.get("invariant_id") == "external_invoice_exists"
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one external deadline job, found {len(matches)}")
    return matches[0]


def correlation_items(client: httpx.Client) -> list[object]:
    correlation_id, _ = required_identifiers()
    payload = request(
        client,
        "GET",
        f"{API}/deadline-jobs",
        params={"correlation_id": correlation_id},
        headers=service_headers(),
    )
    items = payload.get("items")
    if not isinstance(items, list):
        raise RuntimeError("deadline job list is malformed")
    return items


def correlation_incident(client: httpx.Client) -> tuple[dict[str, Any], dict[str, Any]]:
    correlation_id, _ = required_identifiers()
    incidents = request(
        client, "GET", f"{API}/incidents", headers=service_headers()
    ).get("items")
    matches = [
        item
        for item in incidents
        if isinstance(item, dict) and item.get("correlation_id") == correlation_id
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one incident, found {len(matches)}")
    plan = matches[0].get("recovery_plan")
    if not isinstance(plan, dict):
        raise RuntimeError("missing approval-gated recovery plan")
    return matches[0], plan


def assert_proposed_only(plan: dict[str, Any]) -> None:
    if (
        plan.get("status") != "proposed"
        or plan.get("requires_approval") is not True
        or plan.get("approved_at") is not None
        or plan.get("executed_at") is not None
    ):
        raise RuntimeError("scheduler crossed the recovery approval boundary")


def seed() -> None:
    correlation_id, invoice_id = required_identifiers()
    occurred_at = datetime.now(UTC)
    with httpx.Client(timeout=10.0) as client:
        request(client, "DELETE", f"{MOCK}/state")
        request(
            client,
            "POST",
            f"{API}/chaos/mode",
            json={"mode": "false_200", "correlation_id": correlation_id},
            headers=service_headers(),
        )
        for event_type, suffix in (
            ("invoice.received", "received"),
            ("invoice.validated", "validated"),
            ("invoice.approved", "approved"),
            ("invoice.registration_requested", "requested"),
        ):
            request(
                client,
                "POST",
                f"{API}/events",
                json=event_body(event_type, suffix, occurred_at),
                headers=service_headers(),
            )
        request(
            client,
            "POST",
            f"{MOCK}/invoices",
            json={"invoice_id": invoice_id, "amount": 18000.0, "currency": "RUB"},
            headers={"Idempotency-Key": f"restart-smoke:{invoice_id}:false-200"},
        )
        request(
            client,
            "POST",
            f"{API}/events",
            json=event_body("invoice.registration_acknowledged", "ack", occurred_at),
            headers=service_headers(),
        )
        job = target_job(correlation_items(client))
        if job.get("state") != "pending" or job.get("attempt_count") != 0:
            raise RuntimeError(
                "persisted deadline job was not pending while scheduler was stopped"
            )


def wait_for_completed(client: httpx.Client) -> dict[str, Any]:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        job = target_job(correlation_items(client))
        if job.get("state") == "completed":
            return job
        if job.get("state") == "failed":
            raise RuntimeError(f"deadline job failed: {job.get('last_error')}")
        time.sleep(0.5)
    raise RuntimeError(
        "scheduler did not claim the persisted due job within 45 seconds"
    )


def short_id(value: object) -> str:
    raw = str(value)
    return f"{raw[:8]}…" if len(raw) > 8 else raw


def restarted() -> None:
    with httpx.Client(timeout=10.0) as client:
        job = wait_for_completed(client)
        _, plan = correlation_incident(client)
        assert_proposed_only(plan)
        if job.get("attempt_count") != 1:
            raise RuntimeError(
                "persisted job was not processed exactly once after restart"
            )
        response = client.get(f"{MOCK}/invoices/{required_identifiers()[1]}")
        if response.status_code != 404:
            raise RuntimeError("scheduler executed accounting compensation")


def stable() -> None:
    with httpx.Client(timeout=10.0) as client:
        job = target_job(correlation_items(client))
        incident, plan = correlation_incident(client)
        assert_proposed_only(plan)
        if job.get("state") != "completed" or job.get("attempt_count") != 1:
            raise RuntimeError("second scheduler restart reprocessed the completed job")
        response = client.get(f"{MOCK}/invoices/{required_identifiers()[1]}")
        if response.status_code != 404:
            raise RuntimeError("scheduler executed accounting compensation")
    print(
        json.dumps(
            {
                "restart_proof": "passed",
                "correlation_id": short_id(required_identifiers()[0]),
                "deadline_job_id": short_id(job["id"]),
                "deadline_job_state": job["state"],
                "deadline_job_attempts": job["attempt_count"],
                "incident_id": short_id(incident["id"]),
                "incident_count": 1,
                "recovery_plan_id": short_id(plan["id"]),
                "recovery_plan_count": 1,
                "recovery_status": plan["status"],
                "scheduler_compensation_calls": 0,
            },
            indent=2,
        )
    )


def contention_event(
    event_type: str, suffix: str, occurred_at: datetime, correlation_id: str
) -> BusinessEventIn:
    return BusinessEventIn.model_validate(
        {
            "idempotency_key": f"postgres-contention:{correlation_id}:{suffix}",
            "correlation_id": correlation_id,
            "entity_type": "invoice",
            "entity_id": f"INV-CONTENTION-{correlation_id[-8:].upper()}",
            "event_type": event_type,
            "occurred_at": occurred_at.isoformat(),
            "source": {"system": "scheduler-restart-smoke"},
            "payload": {"amount": 18000.0, "currency": "RUB"},
        }
    )


def postgres_contention() -> None:
    settings = Settings.from_environment()
    if not settings.database_url.startswith("postgresql"):
        raise RuntimeError(
            "PostgreSQL contention proof must run inside the Compose API container"
        )
    correlation_id = f"postgres-contention-{uuid4()}"
    occurred_at = datetime.now(UTC) - timedelta(seconds=31)
    accounting = HttpAccountingClient(settings.mock_accounting_url)
    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as session:
        service = FlowProofService(session, str(settings.policy_path), accounting)
        for event_type, suffix in (
            ("invoice.validated", "validated"),
            ("invoice.approved", "approved"),
            ("invoice.registration_requested", "requested"),
            ("invoice.registration_acknowledged", "ack"),
        ):
            service.ingest(
                contention_event(event_type, suffix, occurred_at, correlation_id)
            )

    barrier = threading.Barrier(2)
    outcomes: list[int] = []
    failures: list[BaseException] = []
    outcome_lock = threading.Lock()

    def claim(worker_id: str) -> None:
        try:
            scheduler = DeadlineScheduler(
                settings,
                make_session_factory(make_engine(settings.database_url)),
                accounting,
                worker_id=worker_id,
            )
            barrier.wait(timeout=10)
            result = scheduler.run_once(limit=1)
            with outcome_lock:
                outcomes.append(result)
        except BaseException as exc:
            with outcome_lock:
                failures.append(exc)

    workers = [
        threading.Thread(target=claim, args=("postgres-worker-one",)),
        threading.Thread(target=claim, args=("postgres-worker-two",)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)
    if any(worker.is_alive() for worker in workers):
        raise RuntimeError("PostgreSQL contention workers did not finish")
    if failures:
        raise RuntimeError(
            f"PostgreSQL contention worker failed: {type(failures[0]).__name__}"
        )
    if sorted(outcomes) != [0, 1]:
        raise RuntimeError(f"expected one PostgreSQL claim, received {outcomes}")

    with factory() as session:
        jobs = list(
            session.query(DeadlineJob)
            .filter_by(
                correlation_id=correlation_id, invariant_id="external_invoice_exists"
            )
            .all()
        )
        incidents = list(
            session.query(Incident).filter_by(correlation_id=correlation_id).all()
        )
        plans = list(
            session.query(RecoveryPlan)
            .join(Incident, RecoveryPlan.incident_id == Incident.id)
            .filter(Incident.correlation_id == correlation_id)
            .all()
        )
        if len(jobs) != 1 or jobs[0].state != "completed" or jobs[0].attempt_count != 1:
            raise RuntimeError(
                "PostgreSQL contention did not leave one completed single-attempt job"
            )
        if len(incidents) != 1 or len(plans) != 1:
            raise RuntimeError("PostgreSQL contention duplicated business effects")
        assert_proposed_only(FlowProofService.plan_view(plans[0]))
        result = {
            "postgres_contention_proof": "passed",
            "worker_count": len(workers),
            "worker_claims": sorted(outcomes),
            "correlation_id": short_id(correlation_id),
            "deadline_job_id": short_id(jobs[0].id),
            "deadline_job_count": len(jobs),
            "deadline_job_attempts": jobs[0].attempt_count,
            "incident_count": len(incidents),
            "recovery_plan_count": len(plans),
            "recovery_status": plans[0].status,
            "scheduler_compensation_calls": 0,
        }
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--phase",
        required=True,
        choices=("seed", "restarted", "stable", "postgres-contention"),
    )
    phase = parser.parse_args().phase
    phases = {
        "seed": seed,
        "restarted": restarted,
        "stable": stable,
        "postgres-contention": postgres_contention,
    }
    phases[phase]()


if __name__ == "__main__":
    main()
