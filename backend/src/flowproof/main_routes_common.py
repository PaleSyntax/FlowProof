"""Health, operations, auth, event, scheduler and incident routes."""

import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from sqlalchemy import text

from flowproof.alerts import Alert, enqueue_alert
from flowproof.health import readiness_checks
from flowproof.identity import CurrentPrincipal, InvalidCredentials
from flowproof.models import Principal
from flowproof.schemas import BusinessEventIn, EventReceipt, LoginIn
from flowproof.service import IdempotencyConflict, PayloadRejected


def register_common_routes(
    app: FastAPI,
    *,
    factory: Any,
    boundary: Any,
    metrics: Any,
    config: Any,
    Service: Any,
) -> None:
    @app.get("/health/live", tags=["health"])
    def health_live() -> dict[str, str]:
        return {"status": "live", "version": "0.6.0"}

    @app.get("/health/ready", tags=["health"])
    def health_ready() -> Response:
        try:
            checks = readiness_checks(config, factory)
        except Exception as exc:
            logging.getLogger("flowproof.health").warning(
                "readiness_failed", extra={"error_type": type(exc).__name__}
            )
            return Response(
                content='{"status":"not_ready"}',
                media_type="application/json",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        if checks["migration"] != "ok":
            return Response(
                content='{"status":"not_ready","reason":"migration_mismatch"}',
                media_type="application/json",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(
            content='{"status":"ready"}',
            media_type="application/json",
            status_code=status.HTTP_200_OK,
        )

    @app.get("/health", tags=["health"], include_in_schema=False)
    def health_compatibility() -> dict[str, str]:
        """Temporary compatibility alias for local development health checks."""
        with factory() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ok"}

    @app.get("/metrics", tags=["operations"], include_in_schema=False)
    def metrics_endpoint(
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
    ) -> Response:
        return Response(content=metrics.render(factory), media_type="text/plain; version=0.0.4")

    @app.post("/api/v1/operations/alerts/test", tags=["operations"])
    def send_test_alert(
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "alerts:write", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> dict[str, str]:
        alert = Alert(
            condition="test_alert",
            severity="info",
            summary="FlowProof operator-requested alert test",
            occurred_at=datetime.now().astimezone(),
        )
        with factory() as session:
            row, duplicate = enqueue_alert(
                session,
                alert,
                dedupe_key=f"operator_test_alert:{current.id}",
            )
            session.commit()
        boundary.audit("alert_test_queued", current, request=request)
        return {"status": "duplicate" if duplicate else "queued", "alert_id": row.id}

    @app.post("/api/v1/auth/login", tags=["auth"])
    def login(payload: LoginIn, response: Response) -> dict[str, object]:
        try:
            with factory() as session:
                identity = boundary._identity_service(session)
                current, session_token, csrf_token = identity.login(payload.name, payload.password)
                principal = identity.public_principal(session.get(Principal, current.id))
        except InvalidCredentials:
            raise boundary._invalid_credentials() from None
        response.set_cookie(
            "flowproof_session",
            session_token,
            httponly=True,
            secure=config.session_cookie_secure,
            samesite="lax",
            path="/",
            max_age=config.session_absolute_seconds,
        )
        return {"principal": principal, "csrf_token": csrf_token}

    @app.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
    def logout(
        response: Response,
        current: Annotated[CurrentPrincipal, Depends(boundary.authenticated(state_change=True))],
    ) -> None:
        boundary.logout(current)
        response.delete_cookie("flowproof_session", path="/")

    @app.get("/api/v1/auth/me", tags=["auth"])
    def me(
        current: Annotated[CurrentPrincipal, Depends(boundary.authenticated())],
    ) -> dict[str, object]:
        return {
            "principal": {
                "id": current.id,
                "name": current.name,
                "kind": current.kind,
                "role": current.role,
                "scopes": sorted(current.scopes),
                "credential_id": current.credential_id,
            },
            "csrf_token": boundary.issue_csrf(current),
        }

    @app.post(
        "/api/v1/events",
        response_model=EventReceipt,
        status_code=status.HTTP_201_CREATED,
        tags=["events"],
    )
    def ingest_event(
        event: BusinessEventIn,
        response: Response,
        request: Request,
        service: Service,
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("events:write", state_change=True))
        ],
    ) -> EventReceipt:
        try:
            row, duplicate = service.ingest(event)
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PayloadRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        boundary.audit(
            "event_ingested",
            current,
            target_type="business_event",
            target_id=row.id,
            correlation_id=event.correlation_id,
            request=request,
            details={"duplicate": duplicate},
        )
        if duplicate:
            response.status_code = status.HTTP_200_OK
        return EventReceipt(id=row.id, duplicate=duplicate, content_hash=row.content_hash)

    @app.get("/api/v1/entities/{entity_type}/{entity_id}/timeline", tags=["entities"])
    def entity_timeline(
        entity_type: str,
        entity_id: str,
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
    ) -> dict[str, object]:
        return {"items": service.timeline(entity_type, entity_id)}

    @app.post("/api/v1/correlations/{correlation_id}/evaluate", tags=["evaluation"])
    def evaluate_correlation(
        correlation_id: str,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("evaluations:write", state_change=True))
        ],
    ) -> dict[str, object]:
        try:
            result = service.evaluate(correlation_id)
        except PayloadRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        boundary.audit(
            "evaluation_requested",
            current,
            target_type="correlation",
            target_id=correlation_id,
            correlation_id=correlation_id,
            request=request,
        )
        return {"correlation_id": correlation_id, "evaluations": result}

    @app.get("/api/v1/deadline-jobs", tags=["scheduler"])
    def list_deadline_jobs(
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
        state: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, object]:
        return {"items": service.list_deadline_jobs(state, correlation_id)}

    @app.get("/api/v1/deadline-jobs/{job_id}", tags=["scheduler"])
    def deadline_job_detail(
        job_id: str,
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
    ) -> dict[str, object]:
        job = service.get_deadline_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="deadline job not found")
        return job

    @app.get("/api/v1/incidents", tags=["incidents"])
    def list_incidents(
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
        status_filter: str | None = None,
    ) -> dict[str, object]:
        return {"items": service.list_incidents(status_filter)}

    @app.get("/api/v1/incidents/{incident_id}", tags=["incidents"])
    def incident_detail(
        incident_id: str,
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
    ) -> dict[str, object]:
        incident = service.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident

    @app.get("/api/v1/blast-radius", tags=["incidents"])
    def blast_radius(
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
    ) -> dict[str, object]:
        return {"items": service.blast_radius()}

    @app.get("/api/v1/policies", tags=["policies"])
    def active_policies(
        service: Service,
        _: Annotated[CurrentPrincipal, Depends(boundary.require("read:operations"))],
    ) -> dict[str, object]:
        policy = service.ensure_policy()
        return {
            "items": [
                {
                    "id": policy.id,
                    "name": policy.name,
                    "version": policy.version,
                    "entity_type": policy.entity_type,
                    "definition_hash": policy.definition_hash,
                    "definition": policy.definition,
                }
            ]
        }

