from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from flowproof.alerts import Alert, AlertDispatchError, AlertOutboxWorker
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.identity import IdentityService
from flowproof.main import create_app
from flowproof.models import AlertOutbox, Base, ServiceHeartbeat
from flowproof.observability import JsonFormatter

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
MOCK_CONTRACT_PATH = ROOT / "specs" / "providers" / "mock-accounting" / "contract.json"
PEPPER = "production-foundation-test-pepper-at-least-32-characters"


class FakeAccounting:
    def get_invoice(self, invoice_id: str) -> dict[str, object]:
        return {"available": True, "exists": False, "records": [], "invoice_id": invoice_id}

    def register_invoice(
        self, invoice: dict[str, object], idempotency_key: str
    ) -> dict[str, object]:
        return {"status_code": 201, "body": {"invoice": invoice, "key": idempotency_key}}

    def set_chaos_mode(self, mode: str) -> dict[str, str]:
        return {"mode": mode}


class CapturingAlerts:
    def __init__(self) -> None:
        self.conditions: list[str] = []

    def dispatch(self, alert: Alert) -> None:
        self.conditions.append(alert.condition)


class FailingAlerts:
    def dispatch(self, alert: Alert) -> None:
        del alert
        raise AlertDispatchError("mock receiver unavailable")


@pytest.fixture
def production_client(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'production-foundation.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    settings = Settings(
        database_url=database_url,
        cors_origin="https://dashboard.example.test",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="test",
        token_pepper=PEPPER,
        alert_webhook_url="https://alerts.example.test/hook",
    )
    with factory() as session:
        identity = IdentityService(session, PEPPER)
        identity.create_human("operations-user", "operations-user-password-123", "operator")
        identity.create_human("admin-user", "admin-user-password-123", "admin")
    app = create_app(settings, FakeAccounting(), factory)
    alerts = CapturingAlerts()
    app.state.alerts = alerts
    with TestClient(app) as client:
        yield client, alerts


def login(client: TestClient, name: str, password: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"name": name, "password": password})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def test_secret_files_build_database_url_and_missing_file_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pepper = tmp_path / "pepper"
    password = tmp_path / "postgres_password"
    alert = tmp_path / "alert"
    pepper.write_text(PEPPER + "\n", encoding="utf-8")
    password.write_text("password with spaces\n", encoding="utf-8")
    alert.write_text("https://alerts.example.test/private\n", encoding="utf-8")
    monkeypatch.delenv("FLOWPROOF_DATABASE_URL", raising=False)
    monkeypatch.setenv("FLOWPROOF_ENV", "production")
    monkeypatch.setenv("FLOWPROOF_TOKEN_PEPPER_FILE", str(pepper))
    monkeypatch.setenv("POSTGRES_PASSWORD_FILE", str(password))
    monkeypatch.setenv("FLOWPROOF_ALERT_WEBHOOK_URL_FILE", str(alert))
    monkeypatch.setenv("FLOWPROOF_DATABASE_HOST", "postgres")
    monkeypatch.setenv("FLOWPROOF_CORS_ORIGIN", "https://dashboard.example.test")
    settings = Settings.from_environment()
    settings.validate_production_security()
    assert settings.token_pepper == PEPPER
    assert "password+with+spaces" in settings.database_url

    monkeypatch.setenv("FLOWPROOF_TOKEN_PEPPER_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="FLOWPROOF_TOKEN_PEPPER_FILE cannot be read"):
        Settings.from_environment()


def test_production_recovery_writes_require_exact_proof_authorization() -> None:
    settings = Settings(
        database_url="postgresql+psycopg://flowproof@postgres/flowproof",
        cors_origin="https://caddy",
        mock_accounting_url="http://mock-accounting:8001",
        policy_path=POLICY_PATH,
        environment="production",
        recovery_writes_enabled=True,
        token_pepper=PEPPER,
        session_cookie_secure=True,
        n8n_credential_ttl_seconds=300,
        credential_expiry_alert_seconds=200,
        alert_webhook_url="http://mock-accounting:8001/alerts",
    )
    with pytest.raises(ValueError, match="separately authorized gate"):
        settings.validate_production_security()

    authorized = replace(settings, deployment_proof_recovery_writes_authorized=True)
    authorized.validate_production_security()
    with pytest.raises(ValueError, match="isolated mock-accounting fixture"):
        replace(authorized, mock_accounting_url="https://accounting.example.test").validate_production_security()
    with pytest.raises(ValueError, match="requires production writes"):
        replace(authorized, recovery_writes_enabled=False).validate_production_security()


def test_local_appliance_is_hardened_and_fixture_writes_are_explicit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pepper = tmp_path / "pepper"
    password = tmp_path / "postgres_password"
    pepper.write_text(PEPPER, encoding="utf-8")
    password.write_text("local-appliance-database-password", encoding="utf-8")
    monkeypatch.delenv("FLOWPROOF_DATABASE_URL", raising=False)
    monkeypatch.delenv("FLOWPROOF_RECOVERY_WRITES_ENABLED", raising=False)
    monkeypatch.setenv("FLOWPROOF_ENV", "local-appliance")
    monkeypatch.setenv("FLOWPROOF_TOKEN_PEPPER_FILE", str(pepper))
    monkeypatch.setenv("POSTGRES_PASSWORD_FILE", str(password))
    monkeypatch.setenv("FLOWPROOF_DATABASE_HOST", "postgres")
    monkeypatch.setenv("FLOWPROOF_CORS_ORIGIN", "http://127.0.0.1:8080")
    monkeypatch.setenv("FLOWPROOF_PROVIDER_CONTRACT_PATH", str(MOCK_CONTRACT_PATH))

    settings = Settings.from_environment()
    assert settings.recovery_writes_enabled is False
    settings.validate_production_security()

    fixture_writes = replace(
        settings,
        recovery_writes_enabled=True,
        mock_accounting_url="http://mock-accounting:8001",
        provider_contract_path=MOCK_CONTRACT_PATH,
    )
    fixture_writes.validate_production_security()
    with pytest.raises(ValueError, match="mock-accounting fixture"):
        replace(
            fixture_writes,
            mock_accounting_url="https://provider.example.test",
        ).validate_production_security()
    with pytest.raises(ValueError, match="exact loopback HTTP origin"):
        replace(
            settings,
            cors_origin="http://192.0.2.1:8080",
        ).validate_production_security()
    with pytest.raises(ValueError, match="non-default value"):
        replace(settings, token_pepper="too-short").validate_production_security()


def test_request_id_cors_is_exact_and_exposed(
    production_client: tuple[TestClient, CapturingAlerts],
) -> None:
    client, _ = production_client
    preflight = client.options(
        "/api/v1/events",
        headers={
            "Origin": "https://dashboard.example.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,X-Request-ID",
        },
    )
    assert preflight.status_code == 200
    assert "x-request-id" in preflight.headers["access-control-allow-headers"].lower()
    assert preflight.headers["access-control-allow-origin"] == "https://dashboard.example.test"
    assert preflight.headers["access-control-allow-credentials"] == "true"

    response = client.get(
        "/health/live",
        headers={"Origin": "https://dashboard.example.test", "X-Request-ID": "cors-42"},
    )
    assert response.headers["X-Request-ID"] == "cors-42"
    assert response.headers["access-control-expose-headers"] == "X-Request-ID"
    assert response.headers["access-control-allow-origin"] == "https://dashboard.example.test"

    unsafe = client.options(
        "/api/v1/events",
        headers={
            "Origin": "https://unsafe.example.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Request-ID",
        },
    )
    assert unsafe.status_code == 400
    assert "access-control-allow-origin" not in unsafe.headers


def test_liveness_readiness_metrics_and_redacted_structured_logs(
    production_client: tuple[TestClient, CapturingAlerts],
) -> None:
    client, _ = production_client
    assert client.get("/health/live").json() == {"status": "live", "version": "0.6.0"}
    # Test schema uses Base.metadata rather than Alembic.
    # Readiness must therefore fail closed on the migration-head mismatch.
    assert client.get("/health/ready").status_code == 503
    operator_headers = login(client, "operations-user", "operations-user-password-123")
    metrics = client.get("/metrics", headers=operator_headers)
    assert metrics.status_code == 200
    assert "flowproof_http_requests_total" in metrics.text
    assert "flowproof_deadline_jobs" in metrics.text
    assert "operations-user" not in metrics.text
    assert "production-foundation" not in metrics.text

    formatter = JsonFormatter(client.app.state.settings)
    rendered = formatter.format(
        logging.makeLogRecord(
            {
                "name": "test",
                "levelno": logging.INFO,
                "levelname": "INFO",
                "msg": "postgresql://unsafe:password@db.example.test:5432/flowproof?token=canary",
                "args": (),
                "token": "must-not-appear",
                "authorization": "Bearer must-not-appear",
                "cookie": "session=must-not-appear",
                "csrf": "must-not-appear",
                "pepper": "must-not-appear",
                "n8n_token": "must-not-appear",
                "url": "https://unsafe.example.test/webhook?token=must-not-appear",
            }
        )
    )
    assert "must-not-appear" not in rendered
    assert "unsafe" not in rendered
    assert json.loads(rendered)["service"] == "flowproof-api"
    assert json.loads(rendered)["event"] == "unclassified_log_event"
    assert logging.getLogger("httpx").level >= logging.WARNING


def test_admin_can_dispatch_test_alert_and_production_requires_destination(
    production_client: tuple[TestClient, CapturingAlerts], tmp_path: Path
) -> None:
    client, alerts = production_client
    csrf = login(client, "admin-user", "admin-user-password-123")
    response = client.post("/api/v1/operations/alerts/test", headers=csrf)
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert alerts.conditions == []
    with client.app.state.session_factory() as session:
        row = session.query(AlertOutbox).one()
        assert row.condition == "test_alert"
        assert row.state == "pending"

    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'production.sqlite3'}",
        cors_origin="https://dashboard.example.test",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="production",
        recovery_writes_enabled=False,
        token_pepper=PEPPER,
        session_cookie_secure=True,
    )
    with pytest.raises(ValueError, match="alert webhook destination"):
        settings.validate_production_security()


def test_durable_alert_worker_retries_deduplicates_and_records_heartbeat(
    production_client: tuple[TestClient, CapturingAlerts],
) -> None:
    client, delivered = production_client
    csrf = login(client, "admin-user", "admin-user-password-123")
    assert client.post("/api/v1/operations/alerts/test", headers=csrf).json()["status"] == "queued"
    assert (
        client.post("/api/v1/operations/alerts/test", headers=csrf).json()["status"] == "duplicate"
    )
    settings = client.app.state.settings
    factory = client.app.state.session_factory
    clock = {"now": datetime.now(UTC) + timedelta(seconds=1)}
    failing = AlertOutboxWorker(
        settings, factory, FailingAlerts(), worker_id="failing", now=lambda: clock["now"]
    )
    assert failing.run_once() == 1
    with factory() as session:
        row = session.query(AlertOutbox).one()
        assert row.state == "retry"
        assert row.attempt_count == 1
        assert row.last_error == "AlertDispatchError"
        assert session.get(ServiceHeartbeat, "alert-worker") is not None
    clock["now"] += timedelta(seconds=settings.alert_retry_base_seconds)
    succeeding = AlertOutboxWorker(
        settings, factory, delivered, worker_id="succeeding", now=lambda: clock["now"]
    )
    assert succeeding.run_once() == 1
    with factory() as session:
        row = session.query(AlertOutbox).one()
        assert row.state == "delivered"
        assert row.attempt_count == 2
        assert row.delivered_at is not None
        assert row.delivered_at.replace(tzinfo=UTC) == clock["now"]
    assert delivered.conditions == ["test_alert"]


def test_production_compose_and_deployment_guards_are_declared() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.production.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert "ports" not in services["postgres"]
    assert "caddy" not in services
    assert "n8n" not in services
    assert "build" not in services["api"]
    assert services["migrate"]["command"] == ["python", "-m", "flowproof.deployment", "migrate"]
    assert services["api"]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert services["api"]["read_only"] is True
    assert services["ops-watcher"]["command"] == ["python", "-m", "flowproof.ops_watcher"]
    for service_name in ("migrate", "api", "scheduler", "alert-worker", "ops-watcher"):
        environment = services[service_name]["environment"]
        assert environment["FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS"] == (
            "${FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS:-2592000}"
        )
        assert environment["FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS"] == (
            "${FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS:-604800}"
        )
    assert services["api"]["ports"][0].startswith("${FLOWPROOF_API_BIND:-127.0.0.1}")
    assert services["web"]["ports"][0].startswith("${FLOWPROOF_WEB_BIND:-127.0.0.1}")
    assert "postgres_password" in compose["secrets"]
    assert "FLOWPROOF_API_IMAGE" in services["api"]["image"]
    for service_name in ("api", "scheduler"):
        assert services[service_name]["environment"][
            "FLOWPROOF_PROVIDER_CONTRACT_PATH"
        ] == "/app/specs/providers/mock-accounting/contract.json"
    for service_name in ("api", "scheduler"):
        assert services[service_name]["environment"][
            "FLOWPROOF_RECOVERY_WRITES_ENABLED"
        ] == "false"
    proof = yaml.safe_load(
        (ROOT / "docker-compose.deployment-proof.yml").read_text(encoding="utf-8")
    )
    assert proof["services"]["api"]["environment"][
        "FLOWPROOF_RECOVERY_WRITES_ENABLED"
    ] == "true"
    assert proof["services"]["api"]["environment"][
        "FLOWPROOF_DEPLOYMENT_PROOF_RECOVERY_WRITES_AUTHORIZED"
    ] == "true"
    assert "scheduler" not in proof["services"]
    development = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for service_name in ("api", "scheduler"):
        assert development["services"][service_name]["environment"][
            "FLOWPROOF_PROVIDER_CONTRACT_PATH"
        ] == "/app/specs/providers/mock-accounting/contract.json"
    rollback = (ROOT / "deploy" / "scripts" / "rollback.sh").read_text(encoding="utf-8")
    assert "validate_state_file()" in rollback
    assert 'source "$FLOWPROOF_DEPLOY_STATE_FILE"' not in rollback
    assert rollback.index("current_schema=") < rollback.index('"${COMPOSE[@]}" up -d')
    assert "--isolated" in (ROOT / "deploy" / "scripts" / "restore-proof.sh").read_text(
        encoding="utf-8"
    )
    integration = yaml.safe_load(
        (ROOT / "docker-compose.integration-n8n.yml").read_text(encoding="utf-8")
    )
    assert integration["services"]["n8n"]["profiles"] == ["n8n"]
    edge = (ROOT / "deploy" / "examples" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    assert "redir https://{host}{uri} permanent" in edge
    assert "X-Request-ID" in edge
    assert "FLOWPROOF_METRICS_SOURCE_CIDRS" in edge
    assert "Caddyfile.proof" in (ROOT / "docker-compose.deployment-proof.yml").read_text(
        encoding="utf-8"
    )
    assert "NET_BIND_SERVICE" in (ROOT / "docker-compose.deployment-proof.yml").read_text(
        encoding="utf-8"
    )
