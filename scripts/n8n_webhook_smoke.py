"""Exercise the live n8n 2.30.5 Bearer path with human-only recovery approval."""

from __future__ import annotations

import json
import os
import time
from uuid import uuid4

import httpx

API = os.getenv("FLOWPROOF_API_URL", "http://localhost:8000/api/v1").rstrip("/")
MOCK = os.getenv("MOCK_ACCOUNTING_URL", "http://localhost:8001").rstrip("/")
N8N = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook").rstrip("/")
ADMIN_NAME = os.environ["FLOWPROOF_N8N_SMOKE_ADMIN_NAME"]
ADMIN_PASSWORD = os.environ["FLOWPROOF_N8N_SMOKE_ADMIN_PASSWORD"]
OPERATOR_NAME = os.environ["FLOWPROOF_N8N_SMOKE_OPERATOR_NAME"]
OPERATOR_PASSWORD = os.environ["FLOWPROOF_N8N_SMOKE_OPERATOR_PASSWORD"]
N8N_TOKEN = os.environ["FLOWPROOF_N8N_SMOKE_TOKEN"]
SESSION_HOST = os.getenv("FLOWPROOF_N8N_SMOKE_SESSION_HOST", "")


def request(client: httpx.Client, method: str, url: str, **kwargs: object) -> object:
    response = client.request(method, url, **kwargs)
    # n8n can report /healthz before its published webhook registry is ready
    # after a restart. Retrying the same delivery is safe: each workflow uses
    # the stable delivery/correlation identifiers as idempotency inputs.
    if response.status_code == 404 and url.startswith(f"{N8N}/"):
        deadline = time.monotonic() + 30
        while response.status_code == 404 and time.monotonic() < deadline:
            time.sleep(1)
            response = client.request(method, url, **kwargs)
    if response.status_code == 204:
        return None
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"{method} {response.request.url.path} returned non-JSON {response.status_code}"
        ) from exc
    if response.is_error:
        raise RuntimeError(
            f"{method} {response.request.url.path} -> {response.status_code}"
        )
    return payload


def mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} returned an unexpected JSON type")
    return value


def login(client: httpx.Client, name: str, password: str) -> str:
    body = mapping(
        request(
            client,
            "POST",
            f"{API}/auth/login",
            json={"name": name, "password": password},
        ),
        "login",
    )
    csrf = body.get("csrf_token")
    if not isinstance(csrf, str):
        raise RuntimeError("login did not return CSRF")
    return csrf


def csrf_after_me(client: httpx.Client) -> str:
    body = mapping(request(client, "GET", f"{API}/auth/me"), "auth/me")
    csrf = body.get("csrf_token")
    if not isinstance(csrf, str):
        raise RuntimeError("auth/me did not return a rotated CSRF token")
    return csrf


def bearer() -> dict[str, str]:
    return {"Authorization": f"Bearer {N8N_TOKEN}"}


def session_headers() -> dict[str, str]:
    """Select the production virtual host without changing the URL cookie jar."""

    return {"Host": SESSION_HOST} if SESSION_HOST else {}


def wait_for_plan(
    client: httpx.Client, correlation_id: str
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        jobs = mapping(
            request(
                client,
                "GET",
                f"{API}/deadline-jobs",
                params={"correlation_id": correlation_id},
            ),
            "deadline jobs",
        ).get("items")
        incidents = mapping(
            request(client, "GET", f"{API}/incidents"), "incidents"
        ).get("items")
        if isinstance(jobs, list) and isinstance(incidents, list):
            job = next(
                (
                    item
                    for item in jobs
                    if isinstance(item, dict)
                    and item.get("invariant_id") == "external_invoice_exists"
                    and item.get("state") == "completed"
                ),
                None,
            )
            incident = next(
                (
                    item
                    for item in incidents
                    if isinstance(item, dict)
                    and item.get("correlation_id") == correlation_id
                ),
                None,
            )
            if (
                isinstance(job, dict)
                and isinstance(incident, dict)
                and isinstance(incident.get("recovery_plan"), dict)
            ):
                return job, incident, incident["recovery_plan"]
        time.sleep(1)
    raise RuntimeError(
        "scheduler did not open an incident and proposed plan within 45 seconds"
    )


def short(value: object) -> str:
    raw = str(value)
    return f"{raw[:8]}…" if len(raw) > 8 else raw


def main() -> None:
    correlation_id = f"n8n-{uuid4()}"
    invoice_id = f"INV-N8N-{uuid4().hex[:8].upper()}"
    delivery_id = f"delivery-{uuid4().hex[:12]}"
    invoice = {"invoice_id": invoice_id, "amount": 18000.0, "currency": "RUB"}
    # Human sessions travel through the TLS proxy so their Secure cookies are
    # exercised on the same boundary as production. n8n webhooks and the mock
    # receiver intentionally use a separate client on their internal network.
    with (
        httpx.Client(timeout=20.0, verify=False, headers=session_headers()) as admin,
        httpx.Client(timeout=20.0, verify=False, headers=session_headers()) as operator,
        httpx.Client(timeout=20.0, verify=False) as internal,
    ):
        login(admin, ADMIN_NAME, ADMIN_PASSWORD)
        admin_csrf = csrf_after_me(admin)
        created_operator = mapping(
            request(
                admin,
                "POST",
                f"{API}/identity/humans",
                headers={"X-CSRF-Token": admin_csrf},
                json={
                    "name": OPERATOR_NAME,
                    "password": OPERATOR_PASSWORD,
                    "role": "operator",
                },
            ),
            "create operator",
        )
        login(operator, OPERATOR_NAME, OPERATOR_PASSWORD)
        operator_csrf = csrf_after_me(operator)
        # Production deliberately excludes mock chaos control from its provider
        # adapter. This deployment-only fixture stays on the internal network.
        request(
            internal,
            "POST",
            f"{MOCK}/chaos/mode",
            json={"mode": "false_200"},
        )
        intake = mapping(
            request(
                internal,
                "POST",
                f"{N8N}/invoice-intake",
                json={
                    "delivery_id": delivery_id,
                    "correlation_id": correlation_id,
                    "invoice": invoice,
                },
            ),
            "invoice intake",
        )
        if intake.get("status") != "pending_approval":
            raise RuntimeError("n8n intake did not stop for business approval")
        approval = mapping(
            request(
                internal,
                "POST",
                f"{N8N}/invoice-approve",
                json={
                    "delivery_id": delivery_id,
                    "correlation_id": correlation_id,
                    "invoice": invoice,
                    "decision": "approved",
                    "actor": "n8n-webhook-input",
                },
            ),
            "invoice approval",
        )
        if approval.get("acknowledged") is not True:
            raise RuntimeError("n8n invoice approval did not emit the expected events")
        job, incident, plan = wait_for_plan(operator, correlation_id)
        denied = admin.post(
            f"{API}/recovery-plans/{plan['id']}/approve",
            headers=bearer(),
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        )
        if denied.status_code != 403:
            raise RuntimeError(
                "n8n service account crossed the human recovery approval gate"
            )
        request(
            operator,
            "POST",
            f"{API}/recovery-plans/{plan['id']}/approve",
            headers={"X-CSRF-Token": operator_csrf},
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        )
        request(
            internal,
            "POST",
            f"{MOCK}/chaos/mode",
            json={"mode": "normal"},
        )
        recovery = mapping(
            request(
                internal,
                "POST",
                f"{N8N}/flowproof-recovery",
                json={
                    "plan_id": plan["id"],
                    "plan_hash": plan["plan_hash"],
                    "correlation_id": correlation_id,
                },
            ),
            "n8n recovery",
        )
        if recovery.get("status") != "verified":
            raise RuntimeError("n8n recovery did not verify the approved plan")
        final_incident = mapping(
            request(operator, "GET", f"{API}/incidents/{incident['id']}"),
            "final incident",
        )
        records = mapping(
            request(internal, "GET", f"{MOCK}/invoices/{invoice_id}"), "invoice"
        ).get("records")
        if (
            final_incident.get("status") != "resolved"
            or not isinstance(records, list)
            or len(records) != 1
        ):
            raise RuntimeError("expected one resolved invoice after n8n recovery")
        audit = mapping(request(admin, "GET", f"{API}/security/audit"), "audit").get(
            "items"
        )
        if not isinstance(audit, list):
            raise RuntimeError("audit response was malformed")
        for action, actor_kind, actor_id in (
            ("event_ingested", "service", None),
            ("recovery_approved", "human", created_operator["id"]),
            ("recovery_executed", "service", None),
            ("recovery_verified", "service", None),
        ):
            rows = [
                item
                for item in audit
                if isinstance(item, dict) and item.get("action") == action
            ]
            if not rows or not any(
                item.get("actor_kind") == actor_kind
                and (actor_id is None or item.get("actor_principal_id") == actor_id)
                for item in rows
            ):
                raise RuntimeError(f"audit actor separation failed for {action}")
        if N8N_TOKEN in str(audit):
            raise RuntimeError("audit contains a raw n8n token")
    print(
        json.dumps(
            {
                "n8n_execution": "successful",
                "correlation_id": short(correlation_id),
                "invoice_id": short(invoice_id),
                "incident_id": short(incident["id"]),
                "recovery_plan_id": short(plan["id"]),
                "deadline_job_id": short(job["id"]),
                "final_incident_status": final_incident["status"],
                "mock_invoice_count": len(records),
                "human_approval": "passed",
                "actor_separation": "passed",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
