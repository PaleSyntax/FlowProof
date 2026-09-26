"""Run the isolated false-200 FlowProof vertical slice with Bearer and human approval."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from uuid import uuid4

import httpx

API = os.getenv("FLOWPROOF_API_URL", "http://api:8000/api/v1").rstrip("/")
MOCK = os.getenv("MOCK_ACCOUNTING_URL", "http://mock-accounting:8001").rstrip("/")
VERIFY_TLS = os.getenv("FLOWPROOF_HTTP_VERIFY_TLS", "true").strip().lower() not in {
    "0",
    "false",
    "no",
}
EVENT_TOKEN = os.environ["FLOWPROOF_DEMO_EVENT_TOKEN"]
ADMIN_NAME = os.environ["FLOWPROOF_DEMO_ADMIN_NAME"]
ADMIN_PASSWORD = os.environ["FLOWPROOF_DEMO_ADMIN_PASSWORD"]


def request(client: httpx.Client, method: str, url: str, **kwargs: object) -> object:
    response = client.request(method, url, **kwargs)
    if response.status_code == 204:
        return None
    if response.is_error:
        try:
            body = response.json()
            detail = body.get("detail") if isinstance(body, dict) else body
        except ValueError:
            detail = response.text[:500]
        raise RuntimeError(f"{method} {url} returned HTTP {response.status_code}: {detail}")
    return response.json()


def mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("expected a JSON object")
    return value


def event(correlation_id: str, invoice_id: str, event_type: str, suffix: str) -> dict[str, object]:
    return {
        "idempotency_key": f"demo:{invoice_id}:{suffix}",
        "correlation_id": correlation_id,
        "entity_type": "invoice",
        "entity_id": invoice_id,
        "event_type": event_type,
        "occurred_at": datetime.now(UTC).isoformat(),
        "source": {"system": "demo-equivalent-n8n-path", "workflow_id": "invoice-intake"},
        "payload": {"amount": 18000.0, "currency": "RUB"},
    }


def main() -> None:
    correlation_id = f"demo-{uuid4()}"
    invoice_id = f"INV-DEMO-{uuid4().hex[:8].upper()}"
    operator_name = f"demo-operator-{uuid4().hex[:8]}"
    with (
        httpx.Client(timeout=15.0, verify=VERIFY_TLS) as admin,
        httpx.Client(timeout=15.0, verify=VERIFY_TLS) as operator,
    ):
        admin_login = mapping(
            request(
                admin,
                "POST",
                f"{API}/auth/login",
                json={"name": ADMIN_NAME, "password": ADMIN_PASSWORD},
            )
        )
        admin_csrf = admin_login["csrf_token"]
        if not isinstance(admin_csrf, str):
            raise TypeError("admin login did not return CSRF")
        request(
            admin,
            "POST",
            f"{API}/identity/humans",
            headers={"X-CSRF-Token": admin_csrf},
            json={
                "name": operator_name,
                "password": "demo-operator-password-123",
                "role": "operator",
            },
        )
        operator_login = mapping(
            request(
                operator,
                "POST",
                f"{API}/auth/login",
                json={"name": operator_name, "password": "demo-operator-password-123"},
            )
        )
        operator_csrf = operator_login["csrf_token"]
        if not isinstance(operator_csrf, str):
            raise TypeError("operator login did not return CSRF")
        request(operator, "DELETE", f"{MOCK}/state")
        request(
            operator,
            "POST",
            f"{MOCK}/chaos/mode",
            json={"mode": "false_200"},
        )
        for event_type, suffix in (
            ("invoice.received", "received"),
            ("invoice.validated", "validated"),
            ("invoice.approved", "approved"),
            ("invoice.registration_requested", "requested"),
        ):
            request(
                operator,
                "POST",
                f"{API}/events",
                headers={"Authorization": f"Bearer {EVENT_TOKEN}"},
                json=event(correlation_id, invoice_id, event_type, suffix),
            )
        upstream = request(
            operator,
            "POST",
            f"{MOCK}/invoices",
            json={"invoice_id": invoice_id, "amount": 18000.0, "currency": "RUB"},
            headers={"Idempotency-Key": f"demo:{invoice_id}:accounting"},
        )
        if upstream != {"accepted": True, "persisted": False, "mode": "false_200"}:
            raise RuntimeError("mock accounting did not produce its explicit false-200 response")
        request(
            operator,
            "POST",
            f"{API}/events",
            headers={"Authorization": f"Bearer {EVENT_TOKEN}"},
            json=event(correlation_id, invoice_id, "invoice.registration_acknowledged", "ack"),
        )
        deadline = time.monotonic() + 45
        incident: dict[str, object] | None = None
        deadline_job: dict[str, object] | None = None
        while time.monotonic() < deadline:
            jobs = mapping(
                request(
                    operator,
                    "GET",
                    f"{API}/deadline-jobs",
                    params={"correlation_id": correlation_id},
                )
            ).get("items")
            incidents = mapping(request(operator, "GET", f"{API}/incidents")).get("items")
            deadline_job = (
                next(
                    (
                        item
                        for item in jobs
                        if isinstance(item, dict)
                        and item.get("invariant_id") == "external_invoice_exists"
                        and item.get("state") == "completed"
                    ),
                    None,
                )
                if isinstance(jobs, list)
                else None
            )
            incident = (
                next(
                    (
                        item
                        for item in incidents
                        if isinstance(item, dict) and item.get("correlation_id") == correlation_id
                    ),
                    None,
                )
                if isinstance(incidents, list)
                else None
            )
            if deadline_job and incident:
                break
            time.sleep(1)
        if (
            incident is None
            or deadline_job is None
            or incident.get("summary") != "missing_external_invoice"
        ):
            raise RuntimeError("false-200 did not open a completed deadline incident")
        plan = incident.get("recovery_plan")
        if not isinstance(plan, dict):
            raise TypeError("incident did not expose a recovery plan")
        request(
            operator,
            "POST",
            f"{API}/recovery-plans/{plan['id']}/approve",
            headers={"X-CSRF-Token": operator_csrf},
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        )
        request(
            operator,
            "POST",
            f"{MOCK}/chaos/mode",
            json={"mode": "normal"},
        )
        request(
            operator,
            "POST",
            f"{API}/recovery-plans/{plan['id']}/execute",
            headers={"X-CSRF-Token": operator_csrf},
        )
        verified = mapping(
            request(
                operator,
                "POST",
                f"{API}/recovery-plans/{plan['id']}/verify",
                headers={"X-CSRF-Token": operator_csrf},
            )
        )
        final_incident = mapping(request(operator, "GET", f"{API}/incidents/{incident['id']}"))
        record = mapping(request(operator, "GET", f"{MOCK}/invoices/{invoice_id}"))
        if (
            verified.get("status") != "verified"
            or final_incident.get("status") != "resolved"
            or not isinstance(record.get("records"), list)
            or len(record["records"]) != 1
        ):
            raise RuntimeError("false-200 recovery did not resolve exactly one invoice")
    print(
        json.dumps(
            {
                "upstream_transport_status": "200 false_200",
                "correlation_id": correlation_id[:8] + "…",
                "invoice_id": invoice_id[:12] + "…",
                "incident_id": str(incident["id"])[:8] + "…",
                "recovery_plan_id": str(plan["id"])[:8] + "…",
                "deadline_job_id": str(deadline_job["id"])[:8] + "…",
                "final_incident_status": final_incident["status"],
                "final_recovery_status": verified["status"],
                "mock_invoice_count": 1,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
