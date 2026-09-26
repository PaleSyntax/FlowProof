from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from flowproof.accounting import client_contract
from flowproof.config import KNOWN_INSECURE_TOKEN_PEPPERS, Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.identity import (
    N8N_SCOPES,
    AuthorizationDenied,
    IdentityService,
    IdentityValidationError,
    InvalidCredentials,
)
from flowproof.main import create_app
from flowproof.models import (
    ApiCredential,
    AuthSession,
    Base,
    Incident,
    Principal,
    RecoveryPlan,
    SecurityAuditEvent,
)
from flowproof.policy import canonical_hash

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
PEPPER = "test-token-pepper-with-at-least-thirty-two-characters"


class FakeAccounting:
    def get_invoice(self, invoice_id: str) -> dict[str, object]:
        return {"available": True, "exists": False, "records": []}

    def register_invoice(
        self, invoice: dict[str, object], idempotency_key: str
    ) -> dict[str, object]:
        return {"status_code": 200, "body": {"accepted": True}}

    def set_chaos_mode(self, mode: str) -> dict[str, object]:
        return {"mode": mode}


def settings_for(database_url: str, **changes: object) -> Settings:
    values: dict[str, object] = {
        "database_url": database_url,
        "cors_origin": "http://localhost:5173",
        "mock_accounting_url": "http://fake",
        "policy_path": POLICY_PATH,
        "environment": "test",
        "token_pepper": PEPPER,
        "session_cookie_secure": False,
        "session_idle_seconds": 60,
        "session_absolute_seconds": 300,
        "api_token_default_ttl_seconds": 60,
        "api_token_max_ttl_seconds": 300,
    }
    values.update(changes)
    if values["environment"] == "production" and "recovery_writes_enabled" not in changes:
        values["recovery_writes_enabled"] = False
    return Settings(**values)  # type: ignore[arg-type]


def login(client: TestClient, name: str, password: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"name": name, "password": password})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def event_body(key: str) -> dict[str, object]:
    return {
        "idempotency_key": key,
        "correlation_id": "identity-order",
        "entity_type": "invoice",
        "entity_id": "INV-IDENTITY",
        "event_type": "invoice.received",
        "occurred_at": datetime.now(UTC).isoformat(),
        "source": {"system": "n8n", "workflow_id": "identity-test"},
        "payload": {"amount": 10.0, "token": "must-redact"},
    }


def add_plan(factory, suffix: str) -> RecoveryPlan:
    contract = client_contract(FakeAccounting())
    parameters = {"invoice_id": f"INV-{suffix}", "amount": 10.0, "currency": "RUB"}
    guardrails = {
        "provider_id": contract.provider_id,
        "environment": contract.environment,
        "sandbox_only": True,
        "entity_type": "invoice",
        "entity_id": f"INV-{suffix}",
        "action_type": "register_missing_invoice",
        "allowed_currencies": ["RUB"],
        "maximum_amount_minor": 10000000,
        "amount_scale": 2,
        "observed_amount_minor": 1000,
        "maximum_semantic_write_attempts": 1,
        "maximum_transport_invocations": 1,
        "approval_ttl_seconds": 900,
        "provider_contract_digest": contract.digest,
        "reconciliation_method": "authoritative_invoice_reread",
        "batch_allowed": False,
        "wildcards_allowed": False,
    }
    plan_hash = canonical_hash(
        {
            "action_type": "register_missing_invoice",
            "parameters": parameters,
            "guardrails": guardrails,
            "provider_contract_digest": contract.digest,
        }
    )
    with factory() as session:
        incident = Incident(
            id=f"incident-{suffix}",
            correlation_id=f"correlation-{suffix}",
            entity_type="invoice",
            entity_id=f"INV-{suffix}",
            policy_name="test",
            policy_version="1",
            invariant_id="missing_external_invoice",
            severity="medium",
            status="recovery_proposed",
            summary="missing_external_invoice",
            evidence={},
            opened_at=datetime.now(UTC),
        )
        plan = RecoveryPlan(
            id=f"plan-{suffix}",
            incident_id=incident.id,
            action_type="register_missing_invoice",
            parameters=parameters,
            idempotency_key=f"plan:{suffix}",
            plan_hash=plan_hash,
            provider_id=contract.provider_id,
            provider_environment=contract.environment,
            adapter_version=contract.adapter_version,
            provider_contract_digest=contract.digest,
            provider_contract_snapshot=contract.to_manifest(),
            guardrails=guardrails,
            result={},
        )
        session.add_all([incident, plan])
        session.commit()
        return plan


@pytest.fixture
def identity_setup(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'identity.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as session:
        identity = IdentityService(
            session,
            PEPPER,
            session_idle_seconds=60,
            session_absolute_seconds=300,
            api_token_default_ttl_seconds=60,
            api_token_max_ttl_seconds=300,
        )
        admin = identity.create_human("admin", "admin-password-123", "admin")
        identity.create_human("viewer", "viewer-password-123", "viewer")
        identity.create_human("operator", "operator-password-123", "operator")
        n8n = identity.create_service_account("n8n", set(N8N_SCOPES))
        n8n_token = identity.issue_api_credential(n8n.id, set(N8N_SCOPES)).token
        approver = identity.create_service_account("mistaken-approver", {"recovery:approve"})
        approver_token = identity.issue_api_credential(approver.id, {"recovery:approve"}).token
    app = create_app(settings_for(database_url), FakeAccounting(), factory)
    with TestClient(app) as client:
        yield client, factory, admin, n8n_token, approver_token, database_url


def test_human_approval_gate_and_authorization_denial_audit(identity_setup) -> None:
    client, _, _, n8n_token, approver_token, _ = identity_setup
    plan = add_plan(client.app.state.session_factory, "a")

    viewer_csrf = login(client, "viewer", "viewer-password-123")
    denied = client.post(
        f"/api/v1/recovery-plans/{plan.id}/approve",
        json={"plan_hash": plan.plan_hash, "incident_status": "recovery_proposed"},
        headers=viewer_csrf,
    )
    assert denied.status_code == 403
    client.cookies.clear()
    for token in (n8n_token, approver_token):
        response = client.post(
            f"/api/v1/recovery-plans/{plan.id}/approve",
            json={"plan_hash": plan.plan_hash, "incident_status": "recovery_proposed"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    client.cookies.clear()
    operator_csrf = login(client, "operator", "operator-password-123")
    approved = client.post(
        f"/api/v1/recovery-plans/{plan.id}/approve",
        json={"plan_hash": plan.plan_hash, "incident_status": "recovery_proposed"},
        headers=operator_csrf,
    )
    assert approved.status_code == 200
    approval_context = approved.json()["approval_context"]
    assert approval_context["actor_principal_id"]
    assert approval_context["actor_name"] == "operator"
    assert approval_context["scope"] == "recovery:approve"
    assert approval_context["incident_status"] == "recovery_proposed"
    assert approval_context["plan_hash"] == plan.plan_hash
    admin_csrf = login(client, "admin", "admin-password-123")
    audit = client.get("/api/v1/security/audit", headers=admin_csrf).json()["items"]
    assert any(item["action"] == "authorization_denied" for item in audit)
    assert all(n8n_token not in str(item) and approver_token not in str(item) for item in audit)
    assert any(
        item["action"] == "recovery_approved" and item["actor_kind"] == "human" for item in audit
    )


def test_recovery_plan_read_scopes_and_request_id_audit(identity_setup) -> None:
    client, _, _, n8n_token, approver_token, _ = identity_setup
    plan = add_plan(client.app.state.session_factory, "read")

    login(client, "viewer", "viewer-password-123")
    viewer_read = client.get(
        f"/api/v1/recovery-plans/{plan.id}", headers={"X-Request-ID": "viewer-read-42"}
    )
    assert viewer_read.status_code == 200
    assert viewer_read.headers["X-Request-ID"] == "viewer-read-42"
    client.cookies.clear()
    assert (
        client.get(
            f"/api/v1/recovery-plans/{plan.id}",
            headers={"Authorization": f"Bearer {n8n_token}"},
        ).status_code
        == 200
    )
    denied = client.get(
        f"/api/v1/recovery-plans/{plan.id}",
        headers={
            "Authorization": f"Bearer {approver_token}",
            "X-Request-ID": "denied-read-42",
        },
    )
    assert denied.status_code == 403
    assert denied.headers["X-Request-ID"] == "denied-read-42"

    supplied = "event-request-42"
    event_response = client.post(
        "/api/v1/events",
        json=event_body("request-id-supplied"),
        headers={"Authorization": f"Bearer {n8n_token}", "X-Request-ID": supplied},
    )
    assert event_response.status_code == 201
    assert event_response.headers["X-Request-ID"] == supplied
    generated_response = client.post(
        "/api/v1/events",
        json=event_body("request-id-generated"),
        headers={"Authorization": f"Bearer {n8n_token}"},
    )
    assert generated_response.status_code == 201
    generated = generated_response.headers["X-Request-ID"]
    assert len(generated) == 36 and generated != supplied
    invalid_response = client.post(
        "/api/v1/events",
        json=event_body("request-id-invalid"),
        headers={"Authorization": f"Bearer {n8n_token}", "X-Request-ID": "x" * 129},
    )
    assert invalid_response.status_code == 201
    assert invalid_response.headers["X-Request-ID"] != "x" * 129

    client.cookies.clear()
    admin_csrf = login(client, "admin", "admin-password-123")
    chaos = client.post(
        "/api/v1/chaos/mode",
        json={"mode": "normal", "correlation_id": "identity-order"},
        headers={**admin_csrf, "X-Request-ID": "chaos-request-42"},
    )
    assert chaos.status_code == 200
    audit = client.get("/api/v1/security/audit", headers=admin_csrf).json()["items"]
    assert any(
        item["action"] == "event_ingested"
        and item["request_id"] == supplied
        and item["correlation_id"] == "identity-order"
        for item in audit
    )
    assert any(
        item["action"] == "event_ingested" and item["request_id"] == generated for item in audit
    )
    assert any(
        item["action"] == "authorization_denied" and item["request_id"] == "denied-read-42"
        for item in audit
    )
    assert any(
        item["action"] == "chaos_mode_changed"
        and item["request_id"] == "chaos-request-42"
        and item["correlation_id"] == "identity-order"
        for item in audit
    )


def test_service_scope_envelope_expiry_rotation_revoke_and_admin_actor(identity_setup) -> None:
    client, factory, _, _, _, _ = identity_setup
    csrf = login(client, "admin", "admin-password-123")
    service = client.post(
        "/api/v1/identity/service-accounts",
        json={"name": "billing-automation", "scopes": ["events:write"]},
        headers=csrf,
    )
    assert service.status_code == 200
    service_id = service.json()["id"]
    invalid = client.post(
        f"/api/v1/identity/principals/{service_id}/credentials",
        json={"scopes": ["events:write", "recovery:verify"], "expires_in_seconds": 60},
        headers=csrf,
    )
    assert invalid.status_code == 422
    issued = client.post(
        f"/api/v1/identity/principals/{service_id}/credentials",
        json={"scopes": ["events:write"], "expires_in_seconds": 60, "label": "billing"},
        headers=csrf,
    )
    assert issued.status_code == 200
    raw = issued.json()["token"]
    credential_id = issued.json()["credential_id"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert me.status_code == 200
    assert me.json()["principal"]["credential_id"] == credential_id
    assert (
        client.post(
            "/api/v1/events",
            json=event_body("rotating-event"),
            headers={"Authorization": f"Bearer {raw}"},
        ).status_code
        == 201
    )
    rotated = client.post(
        f"/api/v1/identity/credentials/{credential_id}/rotate",
        json={"expires_in_seconds": 60},
        headers=csrf,
    )
    assert rotated.status_code == 200
    replacement = rotated.json()["token"]
    assert (
        client.post(
            "/api/v1/events",
            json=event_body("old-token"),
            headers={"Authorization": f"Bearer {raw}"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/events",
            json=event_body("new-token"),
            headers={"Authorization": f"Bearer {replacement}"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/api/v1/identity/credentials/{rotated.json()['credential_id']}/revoke", headers=csrf
        ).status_code
        == 204
    )
    assert (
        client.post(
            "/api/v1/events",
            json=event_body("revoked-token"),
            headers={"Authorization": f"Bearer {replacement}"},
        ).status_code
        == 401
    )
    metadata = client.get(
        f"/api/v1/identity/principals/{service_id}/credentials", headers=csrf
    ).json()["items"]
    assert metadata and all("token" not in item and "token_hash" not in item for item in metadata)
    audit = client.get("/api/v1/security/audit", headers=csrf).json()["items"]
    for action in ("credential_issued", "credential_rotated", "credential_revoked"):
        assert any(item["action"] == action and item["actor_principal_id"] for item in audit)
    assert raw not in str(audit) and replacement not in str(audit)
    with factory() as session:
        assert (
            session.scalar(select(ApiCredential).where(ApiCredential.id == credential_id))
            is not None
        )


def test_password_change_and_disable_audit_each_revoked_session(identity_setup) -> None:
    _, factory, admin, _, _, _ = identity_setup
    admin_id = admin.id
    with factory() as session:
        identity = IdentityService(session, PEPPER)
        password_target = identity.create_human("password-target", "password-target-123", "viewer")
        _, password_session_one, password_csrf_one = identity.login(
            "password-target", "password-target-123"
        )
        _, password_session_two, password_csrf_two = identity.login(
            "password-target", "password-target-123"
        )
        identity.change_password(
            password_target.id,
            "password-target-updated-123",
            actor_id=admin_id,
            request_id="password-change-42",
        )
        password_audit = session.scalars(
            select(SecurityAuditEvent).where(SecurityAuditEvent.action == "session_revoked")
        ).all()
        assert len(password_audit) == 2
        target_sessions = session.scalars(
            select(AuthSession).where(AuthSession.principal_id == password_target.id)
        ).all()
        assert {row.target_id for row in password_audit} == {row.id for row in target_sessions}
        assert all(
            row.actor_principal_id == admin_id
            and row.target_type == "auth_session"
            and row.details == {"reason": "password_changed"}
            and row.request_id == "password-change-42"
            for row in password_audit
        )
        assert all(
            secret not in str([identity.public_audit(row) for row in password_audit])
            for secret in (
                password_session_one,
                password_session_two,
                password_csrf_one,
                password_csrf_two,
            )
        )
        with pytest.raises(InvalidCredentials):
            identity.authenticate_session(password_session_one)

        disabled_target = identity.create_human("disable-target", "disable-target-123", "viewer")
        _, disabled_session, disabled_csrf = identity.login("disable-target", "disable-target-123")
        identity.disable_principal(
            disabled_target.id,
            actor_id=admin_id,
            request_id="principal-disable-42",
        )
        disable_audit = session.scalars(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.action == "session_revoked",
                SecurityAuditEvent.target_id
                == session.scalar(
                    select(AuthSession.id).where(AuthSession.principal_id == disabled_target.id)
                ),
            )
        ).all()
        assert len(disable_audit) == 1
        assert disable_audit[0].details == {"reason": "principal_disabled"}
        assert disable_audit[0].request_id == "principal-disable-42"
        assert disabled_session not in str(identity.public_audit(disable_audit[0]))
        assert disabled_csrf not in str(identity.public_audit(disable_audit[0]))
        revoked_count = session.scalar(
            select(func.count())
            .select_from(SecurityAuditEvent)
            .where(SecurityAuditEvent.action == "session_revoked")
        )
        identity.disable_principal(disabled_target.id, actor_id=admin_id)
        assert (
            session.scalar(
                select(func.count())
                .select_from(SecurityAuditEvent)
                .where(SecurityAuditEvent.action == "session_revoked")
            )
            == revoked_count
        )


def test_session_idle_absolute_refresh_csrf_and_restart_persistence(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'sessions.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    clock = {"now": datetime(2026, 8, 1, 12, 0, tzinfo=UTC)}
    with factory() as session:
        identity = IdentityService(
            session,
            PEPPER,
            clock=lambda: clock["now"],
            session_idle_seconds=10,
            session_absolute_seconds=20,
        )
        human = identity.create_human("session-user", "session-password-123", "operator")
        current, raw_session, csrf = identity.login("session-user", "session-password-123")
        row = session.get(AuthSession, current.session_id)
        assert row is not None and identity._as_utc(row.idle_expires_at) == clock[
            "now"
        ] + timedelta(seconds=10)
        clock["now"] += timedelta(seconds=8)
        identity.authenticate_session(raw_session)
        assert identity._as_utc(row.idle_expires_at) == clock["now"] + timedelta(seconds=10)
        clock["now"] += timedelta(seconds=5)
        identity.authenticate_session(raw_session)
        assert identity._as_utc(row.idle_expires_at) == identity._as_utc(row.absolute_expires_at)
        replacement_csrf = identity.issue_csrf(current)
        assert replacement_csrf is not None
        identity.validate_csrf(current, replacement_csrf)
        with pytest.raises(AuthorizationDenied):
            identity.validate_csrf(current, csrf)
        _, other_session, other_csrf = identity.login("session-user", "session-password-123")
        other = identity.authenticate_session(other_session)
        with pytest.raises(AuthorizationDenied):
            identity.validate_csrf(current, other_csrf)
        clock["now"] += timedelta(seconds=8)
        with pytest.raises(InvalidCredentials):
            identity.authenticate_session(raw_session)
        assert identity.authenticate_session(other_session) == other
        identity.change_password(human.id, "session-password-456")
        with pytest.raises(InvalidCredentials):
            identity.authenticate_session(other_session)

    app = create_app(settings_for(database_url), FakeAccounting(), factory)
    with TestClient(app) as client:
        csrf_header = login(client, "session-user", "session-password-456")
        cookie = client.cookies.get("flowproof_session")
        assert cookie and csrf_header["X-CSRF-Token"]
    # A new ASGI application instance sees the durable session row, not process-local state.
    app_after_restart = create_app(settings_for(database_url), FakeAccounting(), factory)
    with TestClient(app_after_restart) as client:
        client.cookies.set("flowproof_session", cookie)
        assert client.get("/api/v1/auth/me").status_code == 200


def test_bootstrap_lockout_role_change_and_last_admin_protection(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'bootstrap.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    now = {"value": datetime(2026, 8, 1, 13, 0, tzinfo=UTC)}
    with factory() as session:
        identity = IdentityService(
            session, PEPPER, clock=lambda: now["value"], login_failure_limit=2, lock_seconds=60
        )
        admin, first = identity.bootstrap_admin("bootstrap", "bootstrap-password-123")
        assert first is False
        same, repeated = identity.bootstrap_admin("bootstrap", "ignored-password-123")
        assert repeated is True and same.id == admin.id
        with pytest.raises(IdentityValidationError):
            identity.bootstrap_admin("second-admin", "second-admin-password")
        viewer = identity.create_human("locked", "locked-password-123", "viewer")
        with pytest.raises(InvalidCredentials):
            identity.login("locked", "wrong-password")
        with pytest.raises(InvalidCredentials):
            identity.login("locked", "wrong-password")
        locked_until = session.get(Principal, viewer.id).locked_until
        with pytest.raises(InvalidCredentials):
            identity.login("locked", "wrong-password")
        assert session.get(Principal, viewer.id).locked_until == locked_until
        now["value"] += timedelta(seconds=61)
        logged_in, _, _ = identity.login("locked", "locked-password-123")
        assert session.get(Principal, logged_in.id).last_successful_login_at == now["value"]
        identity.change_role(viewer.id, "operator", actor_id=admin.id)
        assert (
            identity._human_context(session.get(Principal, viewer.id), "session").role == "operator"
        )
        with pytest.raises(IdentityValidationError):
            identity.change_role(admin.id, "viewer", actor_id=admin.id)
        with pytest.raises(IdentityValidationError):
            identity.disable_principal(admin.id, actor_id=admin.id)


@pytest.mark.parametrize("pepper", [None, "short", *KNOWN_INSECURE_TOKEN_PEPPERS])
def test_production_rejects_missing_short_and_committed_placeholder_peppers(
    tmp_path: Path, pepper: str | None
) -> None:
    settings = settings_for(
        f"sqlite:///{tmp_path / 'production.sqlite3'}",
        environment="production",
        token_pepper=pepper,
        session_cookie_secure=True,
        alert_webhook_url="https://alerts.example.test/hook",
    )
    with pytest.raises(RuntimeError, match="invalid production identity configuration"):
        create_app(settings, FakeAccounting())


def test_production_requires_secure_cookie_and_legacy_off_and_accepts_safe_values(
    tmp_path: Path,
) -> None:
    base = f"sqlite:///{tmp_path / 'production.sqlite3'}"
    safe = "safe-production-pepper-with-at-least-thirty-two-characters"
    for changes in ({"session_cookie_secure": False}, {"legacy_header_auth_enabled": True}):
        with pytest.raises(RuntimeError):
            create_app(
                settings_for(base, environment="production", token_pepper=safe, **changes),
                FakeAccounting(),
            )
    assert create_app(
        settings_for(
            base,
            environment="production",
            token_pepper=safe,
            session_cookie_secure=True,
            alert_webhook_url="https://alerts.example.test/hook",
            n8n_credential_ttl_seconds=300,
            credential_expiry_alert_seconds=200,
        ),
        FakeAccounting(),
    )
    with pytest.raises(RuntimeError, match="invalid production identity configuration"):
        create_app(
            settings_for(
                base,
                environment="production",
                token_pepper=safe,
                session_cookie_secure=True,
                alert_webhook_url="https://alerts.example.test/hook",
                n8n_credential_ttl_seconds=300,
                credential_expiry_alert_seconds=200,
                recovery_writes_enabled=True,
            ),
            FakeAccounting(),
        )


def test_expired_token_and_fixed_n8n_scope_envelope(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite:///{tmp_path / 'expiry.sqlite3'}")
    Base.metadata.create_all(engine)
    now = {"value": datetime(2026, 8, 1, 14, 0, tzinfo=UTC)}
    with make_session_factory(engine)() as session:
        identity = IdentityService(
            session,
            PEPPER,
            clock=lambda: now["value"],
            api_token_default_ttl_seconds=1,
            api_token_max_ttl_seconds=10,
        )
        service = identity.create_service_account("short-lived", {"events:write"})
        token = identity.issue_api_credential(
            service.id, {"events:write"}, expires_in_seconds=1
        ).token
        now["value"] += timedelta(seconds=2)
        with pytest.raises(InvalidCredentials):
            identity.authenticate_bearer(token)
        with pytest.raises(IdentityValidationError):
            identity.create_service_account("n8n-too-wide", {"events:write", "recovery:approve"})


def test_n8n_replacement_operation_metadata_and_orphan_remediation_are_public(
    tmp_path: Path,
) -> None:
    engine = make_engine(f"sqlite:///{tmp_path / 'replacement.sqlite3'}")
    Base.metadata.create_all(engine)
    operation_id = str(uuid4())
    with make_session_factory(engine)() as session:
        identity = IdentityService(
            session,
            PEPPER,
            api_token_default_ttl_seconds=60,
            api_token_max_ttl_seconds=300,
        )
        principal = identity.create_service_account("n8n-flowproof", set(N8N_SCOPES))
        issued = identity.issue_api_credential(
            principal.id,
            set(N8N_SCOPES),
            expires_in_seconds=120,
            label="n8n-flowproof",
            replacement_operation_id=operation_id,
        )
        credential = session.get(ApiCredential, issued.id)
        assert credential is not None
        assert credential.details == {
            "label": "n8n-flowproof",
            "replacement_operation_id": operation_id,
        }
        identity.remediate_orphan_credential(issued.id, operation_id)
        assert session.get(ApiCredential, issued.id).revoked_at is not None  # type: ignore[union-attr]
        audit = session.scalar(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.action == "credential_replacement_orphan_remediated"
            )
        )
        assert audit is not None
        assert audit.details == {"replacement_operation_id": operation_id}
        assert issued.token not in json.dumps(audit.details)

        with pytest.raises(IdentityValidationError, match="replacement operation ID"):
            identity.issue_api_credential(
                principal.id,
                set(N8N_SCOPES),
                replacement_operation_id="not-a-uuid",
            )
