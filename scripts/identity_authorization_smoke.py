"""Isolated PostgreSQL proof for identity, authorization, sessions, and audit boundaries."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import UTC, datetime
from uuid import uuid4

import httpx

API = os.getenv("FLOWPROOF_API_URL", "http://localhost:8000/api/v1").rstrip("/")
MOCK = os.getenv("MOCK_ACCOUNTING_URL", "http://localhost:8001").rstrip("/")
WEB = os.getenv("FLOWPROOF_WEB_URL", "http://localhost:5173")
HEALTH = API.rsplit("/api/v1", 1)[0] + "/health"
ADMIN_NAME = os.environ["FLOWPROOF_IDENTITY_SMOKE_ADMIN_NAME"]
ADMIN_PASSWORD = os.environ["FLOWPROOF_IDENTITY_SMOKE_ADMIN_PASSWORD"]
OPERATOR_NAME = os.environ["FLOWPROOF_IDENTITY_SMOKE_OPERATOR_NAME"]
OPERATOR_PASSWORD = os.environ["FLOWPROOF_IDENTITY_SMOKE_OPERATOR_PASSWORD"]


def request(client: httpx.Client, method: str, url: str, **kwargs: object) -> object:
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


def login(
    client: httpx.Client, name: str, password: str
) -> tuple[dict[str, object], str]:
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
        raise RuntimeError("login did not return a transient CSRF token")
    return body, csrf


def fresh_csrf(client: httpx.Client) -> str:
    body = mapping(request(client, "GET", f"{API}/auth/me"), "auth/me")
    csrf = body.get("csrf_token")
    if not isinstance(csrf, str):
        raise RuntimeError("auth/me did not rotate a CSRF token")
    return csrf


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def short(value: object) -> str:
    raw = str(value)
    return f"{raw[:8]}…" if len(raw) > 8 else raw


def event_body(
    correlation_id: str, invoice_id: str, suffix: str, event_type: str
) -> dict[str, object]:
    return {
        "idempotency_key": f"identity-smoke:{invoice_id}:{suffix}",
        "correlation_id": correlation_id,
        "entity_type": "invoice",
        "entity_id": invoice_id,
        "event_type": event_type,
        "occurred_at": datetime.now(UTC).isoformat(),
        "source": {"system": "identity-smoke", "workflow_id": "identity-smoke"},
        "payload": {"amount": 18000.0, "currency": "RUB"},
    }


def wait_for_plan(
    client: httpx.Client, correlation_id: str
) -> tuple[dict[str, object], dict[str, object]]:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        incidents = mapping(
            request(client, "GET", f"{API}/incidents"), "incidents"
        ).get("items")
        if isinstance(incidents, list):
            for incident in incidents:
                if (
                    isinstance(incident, dict)
                    and incident.get("correlation_id") == correlation_id
                ):
                    plan = incident.get("recovery_plan")
                    if isinstance(plan, dict) and plan.get("status") == "proposed":
                        return incident, plan
        time.sleep(1)
    raise RuntimeError(
        "scheduler did not create a proposed recovery plan within 45 seconds"
    )


def restart_api_and_check_session(client: httpx.Client) -> None:
    completed = subprocess.run(
        ["docker", "compose", "restart", "api"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode:
        raise RuntimeError(
            "API restart command failed during session persistence proof"
        )
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            if httpx.get(HEALTH, timeout=3.0).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("API did not become healthy after restart")
    if client.get(f"{API}/auth/me").status_code != 200:
        raise RuntimeError("non-revoked database session did not survive API restart")


def main() -> None:
    suffix = uuid4().hex[:12]
    correlation_id = f"identity-smoke-{uuid4()}"
    invoice_id = f"INV-IDENTITY-{suffix.upper()}"
    request_id = f"identity-smoke-{suffix}"
    denial_request_id = f"identity-denial-{suffix}"
    revocation_request_id = f"identity-revoke-{suffix}"
    evidence: dict[str, object] = {"identity_smoke": "passed"}
    with (
        httpx.Client(timeout=20.0) as admin,
        httpx.Client(timeout=20.0) as viewer,
        httpx.Client(timeout=20.0) as operator,
    ):
        _, admin_csrf = login(admin, ADMIN_NAME, ADMIN_PASSWORD)
        admin_csrf = fresh_csrf(admin)
        created_viewer = mapping(
            request(
                admin,
                "POST",
                f"{API}/identity/humans",
                headers={"X-CSRF-Token": admin_csrf},
                json={
                    "name": f"identity-viewer-{suffix}",
                    "password": "viewer-password-123",
                    "role": "viewer",
                },
            ),
            "create viewer",
        )
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
        service = mapping(
            request(
                admin,
                "POST",
                f"{API}/identity/service-accounts",
                headers={"X-CSRF-Token": admin_csrf},
                json={
                    "name": f"n8n-identity-{suffix}",
                    "scopes": ["events:write", "recovery:execute", "recovery:verify"],
                },
            ),
            "create n8n service account",
        )
        issued = mapping(
            request(
                admin,
                "POST",
                f"{API}/identity/principals/{service['id']}/credentials",
                headers={"X-CSRF-Token": admin_csrf},
                json={
                    "scopes": ["events:write", "recovery:execute", "recovery:verify"],
                    "expires_in_seconds": 600,
                    "label": "identity smoke",
                },
            ),
            "issue n8n credential",
        )
        token = issued.get("token")
        credential_id = issued.get("credential_id")
        if not isinstance(token, str) or not isinstance(credential_id, str):
            raise RuntimeError("credential issue did not return its one-time raw token")

        _, viewer_csrf = login(
            viewer, str(created_viewer["name"]), "viewer-password-123"
        )
        if viewer.get(f"{API}/incidents").status_code != 200:
            raise RuntimeError("viewer read did not pass")
        if (
            viewer.post(
                f"{API}/identity/service-accounts",
                headers={"X-CSRF-Token": viewer_csrf},
                json={"name": "viewer-denied", "scopes": ["events:write"]},
            ).status_code
            != 403
        ):
            raise RuntimeError("viewer mutation was not denied")

        _, operator_csrf = login(operator, OPERATOR_NAME, OPERATOR_PASSWORD)
        operator_csrf = fresh_csrf(operator)
        request(
            operator,
            "POST",
            f"{API}/chaos/mode",
            headers={"X-CSRF-Token": operator_csrf},
            json={"mode": "false_200", "correlation_id": correlation_id},
        )
        for suffix_part, event_type in (
            ("received", "invoice.received"),
            ("validated", "invoice.validated"),
            ("approved", "invoice.approved"),
            ("requested", "invoice.registration_requested"),
            ("ack", "invoice.registration_acknowledged"),
        ):
            request(
                admin,
                "POST",
                f"{API}/events",
                headers={**bearer(token), "X-Request-ID": request_id},
                json=event_body(correlation_id, invoice_id, suffix_part, event_type),
            )
        if (
            admin.post(
                f"{API}/recovery-plans/not-a-real-plan/approve",
                headers={**bearer(token), "X-Request-ID": denial_request_id},
                json={"plan_hash": "0" * 64, "incident_status": "recovery_proposed"},
            ).status_code
            != 403
        ):
            raise RuntimeError("n8n service account crossed the human approval gate")
        incident, plan = wait_for_plan(operator, correlation_id)
        if viewer.get(f"{API}/recovery-plans/{plan['id']}").status_code != 200:
            raise RuntimeError("viewer could not read the immutable recovery plan")
        service_plan = admin.get(
            f"{API}/recovery-plans/{plan['id']}", headers=bearer(token)
        )
        if service_plan.status_code != 200:
            raise RuntimeError("n8n service could not read the immutable recovery plan")
        request(
            operator,
            "POST",
            f"{API}/recovery-plans/{plan['id']}/approve",
            headers={"X-CSRF-Token": operator_csrf},
            json={"plan_hash": plan["plan_hash"], "incident_status": incident["status"]},
        )
        rotated = mapping(
            request(
                admin,
                "POST",
                f"{API}/identity/credentials/{credential_id}/rotate",
                headers={"X-CSRF-Token": admin_csrf},
                json={"expires_in_seconds": 600},
            ),
            "rotate n8n credential",
        )
        new_token = rotated.get("token")
        if not isinstance(new_token, str):
            raise RuntimeError(
                "credential rotation did not return its one-time raw token"
            )
        if (
            admin.post(
                f"{API}/events",
                headers=bearer(token),
                json=event_body(
                    correlation_id, invoice_id, "old", "technical.workflow_failed"
                ),
            ).status_code
            != 401
        ):
            raise RuntimeError("rotated old token remained valid")
        request(
            admin,
            "POST",
            f"{API}/events",
            headers=bearer(new_token),
            json=event_body(
                correlation_id, invoice_id, "new", "technical.workflow_failed"
            ),
        )
        request(
            operator,
            "POST",
            f"{API}/chaos/mode",
            headers={"X-CSRF-Token": operator_csrf},
            json={"mode": "normal", "correlation_id": correlation_id},
        )
        request(
            admin,
            "POST",
            f"{API}/recovery-plans/{plan['id']}/execute",
            headers=bearer(new_token),
        )
        request(
            admin,
            "POST",
            f"{API}/recovery-plans/{plan['id']}/verify",
            headers=bearer(new_token),
        )
        final_incident = mapping(
            request(operator, "GET", f"{API}/incidents/{incident['id']}"),
            "final incident",
        )
        records = mapping(
            request(admin, "GET", f"{MOCK}/invoices/{invoice_id}"), "invoice"
        ).get("records")
        if (
            final_incident.get("status") != "resolved"
            or not isinstance(records, list)
            or len(records) != 1
        ):
            raise RuntimeError("recovery did not resolve exactly one invoice")
        restart_api_and_check_session(operator)
        request(
            admin,
            "POST",
            f"{API}/identity/credentials/{rotated['credential_id']}/revoke",
            headers={"X-CSRF-Token": admin_csrf},
        )
        if (
            admin.post(
                f"{API}/events",
                headers=bearer(new_token),
                json=event_body(
                    correlation_id, invoice_id, "revoked", "technical.workflow_failed"
                ),
            ).status_code
            != 401
        ):
            raise RuntimeError("revoked token remained valid")
        request(
            admin,
            "POST",
            f"{API}/identity/principals/{created_viewer['id']}/password",
            headers={"X-CSRF-Token": admin_csrf, "X-Request-ID": revocation_request_id},
            json={"password": "viewer-password-updated-123"},
        )
        if viewer.get(f"{API}/auth/me").status_code != 401:
            raise RuntimeError("password change did not revoke the viewer session")
        audit = mapping(request(admin, "GET", f"{API}/security/audit"), "audit").get(
            "items"
        )
        if not isinstance(audit, list):
            raise RuntimeError("audit response was malformed")
        actor_checks = {
            "event_ingested": service["id"],
            "recovery_approved": created_operator["id"],
            "recovery_executed": service["id"],
            "recovery_verified": service["id"],
        }
        for action, actor_id in actor_checks.items():
            if not any(
                item.get("action") == action
                and item.get("actor_principal_id") == actor_id
                for item in audit
                if isinstance(item, dict)
            ):
                raise RuntimeError(
                    f"audit did not retain the expected actor for {action}"
                )
        if not any(
            item.get("action") == "event_ingested"
            and item.get("request_id") == request_id
            and item.get("correlation_id") == correlation_id
            for item in audit
            if isinstance(item, dict)
        ):
            raise RuntimeError("event audit did not retain request and correlation IDs")
        if not any(
            item.get("action") == "authorization_denied"
            and item.get("request_id") == denial_request_id
            for item in audit
            if isinstance(item, dict)
        ):
            raise RuntimeError("authorization denial audit did not retain request ID")
        if not any(
            item.get("action") == "session_revoked"
            and item.get("target_type") == "auth_session"
            and item.get("metadata", {}).get("reason") == "password_changed"
            and item.get("request_id") == revocation_request_id
            for item in audit
            if isinstance(item, dict)
        ):
            raise RuntimeError("session revocation audit did not retain safe request metadata")
        if (
            token in str(audit)
            or new_token in str(audit)
            or ADMIN_PASSWORD in str(audit)
        ):
            raise RuntimeError("audit contains a raw secret")
        request(
            admin, "POST", f"{API}/auth/logout", headers={"X-CSRF-Token": admin_csrf}
        )
        if admin.get(f"{API}/auth/me").status_code != 401:
            raise RuntimeError("logout did not revoke the session")
        if httpx.get(WEB, timeout=10.0).status_code != 200:
            raise RuntimeError("frontend UI did not return HTTP 200")
        evidence.update(
            {
                "incident_id": short(incident["id"]),
                "recovery_plan_id": short(plan["id"]),
                "service_principal_id": short(service["id"]),
                "operator_principal_id": short(created_operator["id"]),
                "final_incident_status": final_incident["status"],
                "mock_invoice_count": len(records),
                "audit_actor_separation": "passed",
                "viewer_recovery_plan_read": "passed",
                "session_revocation_audit": "passed",
                "request_id_audit": "passed",
                "api_restart_session": "passed",
                "ui_http_status": 200,
            }
        )
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
