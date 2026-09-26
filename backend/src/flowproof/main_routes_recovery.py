"""Recovery decision, dispatch, reconciliation and verification routes."""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request

from flowproof.identity import CurrentPrincipal
from flowproof.schemas import (
    ApprovalIn,
    OperatorReviewIn,
    ReconcileIn,
    RecoveryDecisionIn,
)
from flowproof.service import RecoveryGateError


def register_recovery_routes(
    app: FastAPI,
    *,
    boundary: Any,
    Service: Any,
    recovery_gate_http_exception: Any,
) -> None:
    @app.get("/api/v1/recovery-plans/{plan_id}", tags=["recovery"])
    def recovery_plan(
        plan_id: str,
        service: Service,
        _: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_any_scope(frozenset({"read:operations", "recovery:execute"}))),
        ],
    ) -> dict[str, object]:
        plan = service.get_plan(plan_id)
        if not plan:
            raise HTTPException(status_code=404, detail="recovery plan not found")
        return service.plan_view(plan)

    @app.post("/api/v1/recovery-plans/{plan_id}/approve", tags=["recovery"])
    def approve_recovery(
        plan_id: str,
        payload: ApprovalIn,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("recovery:approve", state_change=True)),
        ],
    ) -> dict[str, object]:
        try:
            approved = service.approve(
                plan_id,
                actor_id=current.id,
                actor_name=current.name,
                approval_scope="recovery:approve",
                submitted_hash=payload.plan_hash,
                submitted_incident_status=payload.incident_status,
                request_id=boundary.request_id(request),
                reason_code=payload.reason_code,
                note=payload.note,
            )
            plan = service.plan_view(approved)
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "recovery_approved",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
            details={
                "scope": "recovery:approve",
                "incident_status": payload.incident_status,
                "plan_hash": payload.plan_hash,
            },
        )
        return plan

    @app.post("/api/v1/recovery-plans/{plan_id}/reject", tags=["recovery"])
    def reject_recovery(
        plan_id: str,
        payload: RecoveryDecisionIn,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("recovery:approve", state_change=True)),
        ],
    ) -> dict[str, object]:
        try:
            plan = service.plan_view(
                service.reject(
                    plan_id,
                    actor_id=current.id,
                    actor_name=current.name,
                    authorization_scope="recovery:approve",
                    submitted_hash=payload.plan_hash,
                    submitted_incident_status=payload.incident_status,
                    request_id=boundary.request_id(request) or "",
                    reason_code=payload.reason_code,
                    note=payload.note,
                )
            )
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "recovery_rejected",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
            details={"reason_code": payload.reason_code, "plan_hash": payload.plan_hash},
        )
        return plan

    @app.post("/api/v1/recovery-plans/{plan_id}/revoke-approval", tags=["recovery"])
    def revoke_recovery_approval(
        plan_id: str,
        payload: RecoveryDecisionIn,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("recovery:approve", state_change=True)),
        ],
    ) -> dict[str, object]:
        try:
            plan = service.plan_view(
                service.revoke_approval(
                    plan_id,
                    actor_id=current.id,
                    actor_name=current.name,
                    authorization_scope="recovery:approve",
                    submitted_hash=payload.plan_hash,
                    submitted_incident_status=payload.incident_status,
                    request_id=boundary.request_id(request) or "",
                    reason_code=payload.reason_code,
                    note=payload.note,
                )
            )
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "recovery_approval_revoked",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
            details={"reason_code": payload.reason_code, "plan_hash": payload.plan_hash},
        )
        return plan

    @app.post("/api/v1/recovery-plans/{plan_id}/reconcile", tags=["recovery"])
    def reconcile_recovery(
        plan_id: str,
        payload: ReconcileIn,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("recovery:verify", state_change=True))
        ],
    ) -> dict[str, object]:
        try:
            plan = service.plan_view(service.reconcile(plan_id, submitted_hash=payload.plan_hash))
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "recovery_reconciled",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
        )
        return plan

    @app.get("/api/v1/recovery-plans/{plan_id}/attempts", tags=["recovery"])
    def recovery_attempts(
        plan_id: str,
        service: Service,
        _: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_any_scope(
                    frozenset({"read:operations", "recovery:execute", "recovery:verify"})
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            return {"items": service.list_attempts(plan_id)}
        except RecoveryGateError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/recovery-plans/{plan_id}/decisions", tags=["recovery"])
    def recovery_decisions(
        plan_id: str,
        service: Service,
        _: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_any_scope(
                    frozenset({"read:operations", "recovery:execute", "recovery:verify"})
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            return {"items": service.list_decisions(plan_id)}
        except RecoveryGateError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/v1/recovery-plans/{plan_id}/operator-review", tags=["recovery"])
    def record_operator_review(
        plan_id: str,
        payload: OperatorReviewIn,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("recovery:approve", state_change=True)),
        ],
    ) -> dict[str, object]:
        try:
            review = service.record_operator_review(
                plan_id,
                actor_id=current.id,
                actor_name=current.name,
                request_id=boundary.request_id(request) or "",
                payload=payload.model_dump(),
            )
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "operator_review_recorded",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
            details={"verdict": review["verdict"], "plan_hash": payload.plan_hash},
        )
        return review

    @app.post("/api/v1/recovery-plans/{plan_id}/execute", tags=["recovery"])
    def execute_recovery(
        plan_id: str,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("recovery:execute", state_change=True))
        ],
    ) -> dict[str, object]:
        try:
            plan = service.plan_view(service.execute(plan_id))
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "recovery_executed",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
        )
        return plan

    @app.post("/api/v1/recovery-plans/{plan_id}/verify", tags=["recovery"])
    def verify_recovery(
        plan_id: str,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("recovery:verify", state_change=True))
        ],
    ) -> dict[str, object]:
        try:
            plan = service.plan_view(service.verify_recovery(plan_id))
        except RecoveryGateError as exc:
            raise recovery_gate_http_exception(exc) from exc
        boundary.audit(
            "recovery_verified",
            current,
            target_type="recovery_plan",
            target_id=plan_id,
            request=request,
        )
        return plan

