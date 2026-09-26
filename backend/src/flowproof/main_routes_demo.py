"""Routes for the explicitly local TEST_FIXTURE_ONLY onboarding path."""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, status

from flowproof.fixture_demo import FixtureDemoError, FixtureDemoService
from flowproof.identity import CurrentPrincipal


def register_demo_routes(
    app: FastAPI,
    *,
    boundary: Any,
    config: Any,
    Service: Any,
) -> None:
    @app.post("/api/v1/demo/false-200/start", tags=["demo"])
    def start_false_200_demo(
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "chaos:write",
                    roles=frozenset({"operator", "admin"}),
                    state_change=True,
                )
            ),
        ],
    ) -> dict[str, object]:
        if not config.fixture_demo_enabled:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        try:
            result = FixtureDemoService(service).start_false_200()
        except FixtureDemoError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"safe fixture demo unavailable: {exc}",
            ) from exc
        boundary.audit(
            "fixture_demo_started",
            current,
            target_type="correlation",
            target_id=result.correlation_id,
            correlation_id=result.correlation_id,
            request=request,
            details={"classification": "TEST_FIXTURE_ONLY", "scenario": "false_200"},
        )
        return result.as_dict()
