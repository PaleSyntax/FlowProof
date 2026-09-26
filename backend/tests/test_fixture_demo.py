from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.identity import IdentityService
from flowproof.main import create_app
from flowproof.models import Base, BusinessEvent, SecurityAuditEvent

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "specs" / "policies" / "invoice-processing.yaml"
PEPPER = "fixture-demo-test-pepper-with-at-least-thirty-two-characters"


class FixtureAccounting:
    def __init__(self, *, fail_write: bool = False) -> None:
        self.mode = "normal"
        self.fail_write = fail_write
        self.records: dict[str, dict[str, Any]] = {}

    def set_chaos_mode(self, mode: str) -> dict[str, str]:
        self.mode = mode
        return {"mode": mode}

    def register_invoice(
        self, invoice: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        if self.fail_write:
            raise RuntimeError("fixture provider unavailable")
        if self.mode != "false_200":
            self.records[str(invoice["invoice_id"])] = dict(invoice)
        return {"status_code": 200, "body": {"accepted": True}}

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        record = self.records.get(invoice_id)
        return {
            "available": True,
            "exists": record is not None,
            "records": [record] if record is not None else [],
        }


def fixture_settings(database_url: str, *, enabled: bool = True) -> Settings:
    return Settings(
        database_url=database_url,
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://fake",
        policy_path=POLICY_PATH,
        environment="development",
        recovery_writes_enabled=True,
        fixture_demo_enabled=enabled,
        token_pepper=PEPPER,
        session_cookie_secure=False,
    )


def client_setup(tmp_path: Path, accounting: FixtureAccounting, *, enabled: bool = True):
    database_url = f"sqlite:///{tmp_path / 'fixture-demo.sqlite3'}"
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as session:
        IdentityService(session, PEPPER).create_human(
            "fixture-admin", "fixture-admin-password-123", "admin"
        )
    app = create_app(fixture_settings(database_url, enabled=enabled), accounting, factory)
    return app, factory


def login(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"name": "fixture-admin", "password": "fixture-admin-password-123"},
    )
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def test_fixture_demo_creates_bounded_timeline_and_independent_incident(
    tmp_path: Path,
) -> None:
    app, factory = client_setup(tmp_path, FixtureAccounting())
    with TestClient(app) as client:
        headers = login(client)
        response = client.post("/api/v1/demo/false-200/start", headers=headers)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["evidence_classification"] == "TEST_FIXTURE_ONLY"
        assert result["execution"] == {
            "classification": "FIXTURE_TRANSPORT_ACCEPTED",
            "transport_accepted": True,
            "real_n8n_execution_proven": False,
            "source": "flowproof-safe-fixture",
        }
        assert result["outcome"]["classification"] == "INDEPENDENT_READ_MISSING"
        assert result["outcome"]["state"] == "FAILED"
        assert len(result["timeline_event_ids"]) == 5

        incident = client.get(
            f"/api/v1/incidents/{result['incident_id']}", headers=headers
        )
        assert incident.status_code == 200
        assert incident.json()["summary"] == "missing_external_invoice"
        assert incident.json()["status"] == "recovery_proposed"
        assert incident.json()["recovery_plan"]["id"] == result["recovery_plan_id"]

        approved = client.post(
            f"/api/v1/recovery-plans/{result['recovery_plan_id']}/approve",
            headers=headers,
            json={
                "plan_hash": incident.json()["recovery_plan"]["plan_hash"],
                "incident_status": "recovery_proposed",
            },
        )
        assert approved.status_code == 200
        reevaluated = client.post(
            f"/api/v1/correlations/{result['correlation_id']}/evaluate",
            headers=headers,
        )
        assert reevaluated.status_code == 200
        after_reevaluation = client.get(
            f"/api/v1/incidents/{result['incident_id']}", headers=headers
        ).json()
        assert after_reevaluation["status"] == "recovery_approved"
        assert after_reevaluation["recovery_plan"]["status"] == "approved"

        timeline = client.get(
            f"/api/v1/entities/invoice/{result['entity_id']}/timeline", headers=headers
        )
        assert timeline.status_code == 200
        assert [item["event_type"] for item in timeline.json()["items"]] == [
            "invoice.received",
            "invoice.validated",
            "invoice.approved",
            "invoice.registration_requested",
            "invoice.registration_acknowledged",
        ]

    with factory() as session:
        events = session.scalars(select(BusinessEvent)).all()
        assert len(events) == 5
        assert len({event.idempotency_key for event in events}) == 5
        assert {event.source_system for event in events} == {"flowproof-safe-fixture"}
        audit_count = session.scalar(
            select(func.count(SecurityAuditEvent.id)).where(
                SecurityAuditEvent.action == "fixture_demo_started"
            )
        )
        assert audit_count == 1


def test_fixture_demo_is_hidden_when_not_explicitly_enabled(tmp_path: Path) -> None:
    app, _ = client_setup(tmp_path, FixtureAccounting(), enabled=False)
    with TestClient(app) as client:
        response = client.post("/api/v1/demo/false-200/start", headers=login(client))
    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}


def test_fixture_provider_error_preserves_already_committed_timeline(tmp_path: Path) -> None:
    app, factory = client_setup(tmp_path, FixtureAccounting(fail_write=True))
    with TestClient(app) as client:
        response = client.post("/api/v1/demo/false-200/start", headers=login(client))
    assert response.status_code == 502
    assert response.json()["detail"].startswith("safe fixture demo unavailable:")
    with factory() as session:
        events = session.scalars(select(BusinessEvent).order_by(BusinessEvent.occurred_at)).all()
        assert [event.event_type for event in events] == [
            "invoice.received",
            "invoice.validated",
            "invoice.approved",
            "invoice.registration_requested",
        ]


def test_fixture_demo_cannot_be_enabled_in_production() -> None:
    settings = fixture_settings("sqlite:///ignored.sqlite3")
    object.__setattr__(settings, "environment", "production")
    object.__setattr__(settings, "session_cookie_secure", True)
    object.__setattr__(settings, "recovery_writes_enabled", False)
    try:
        settings.validate_production_security()
    except ValueError as exc:
        assert str(exc) == "fixture demo is allowed only in explicit local runtimes"
    else:
        raise AssertionError("production fixture demo configuration was accepted")
