"""Chaos, identity credential and security-audit routes."""

from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from sqlalchemy.exc import IntegrityError

from flowproof.identity import CurrentPrincipal, IdentityValidationError
from flowproof.schemas import (
    ChaosModeIn,
    CredentialIssueIn,
    CredentialRotateIn,
    HumanPrincipalIn,
    PasswordChangeIn,
    RoleChangeIn,
    ServiceAccountIn,
)


def register_admin_routes(
    app: FastAPI,
    *,
    factory: Any,
    boundary: Any,
    Service: Any,
) -> None:
    @app.post("/api/v1/chaos/mode", tags=["chaos"])
    def set_chaos_mode(
        payload: ChaosModeIn,
        service: Service,
        request: Request,
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("chaos:write", state_change=True))
        ],
    ) -> dict[str, object]:
        try:
            result = service.configure_chaos(payload.mode, payload.correlation_id)
        except Exception as exc:  # External errors never become business violations.
            raise HTTPException(
                status_code=502, detail=f"mock accounting unavailable: {type(exc).__name__}"
            ) from exc
        boundary.audit(
            "chaos_mode_changed",
            current,
            target_type="chaos_configuration",
            target_id=payload.correlation_id or "global",
            correlation_id=payload.correlation_id,
            request=request,
            details={"mode": payload.mode},
        )
        return result

    def issued_credential_response(issued: Any) -> dict[str, object]:
        # This is the only HTTP response that includes an un-hashed raw API token.
        return {
            "credential_id": issued.id,
            "token_prefix": issued.token_prefix,
            "scopes": issued.scopes,
            "expires_at": issued.expires_at.isoformat(),
            "token": issued.token,
        }

    @app.get("/api/v1/identity/principals", tags=["identity"])
    def list_principals(
        _: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("identity:manage", roles=frozenset({"admin"}))),
        ],
    ) -> dict[str, object]:
        with factory() as session:
            return {"items": boundary._identity_service(session).list_principals()}

    @app.post("/api/v1/identity/humans", tags=["identity"])
    def create_human(
        payload: HumanPrincipalIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            with factory() as session:
                identity = boundary._identity_service(session)
                principal = identity.create_human(
                    payload.name,
                    payload.password,
                    payload.role,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
                return identity.public_principal(principal)
        except (IdentityValidationError, IntegrityError) as exc:
            raise HTTPException(status_code=422, detail="invalid principal") from exc

    @app.post("/api/v1/identity/service-accounts", tags=["identity"])
    def create_service_account(
        payload: ServiceAccountIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            with factory() as session:
                identity = boundary._identity_service(session)
                principal = identity.create_service_account(
                    payload.name,
                    payload.scopes,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
                return identity.public_principal(principal)
        except (IdentityValidationError, IntegrityError) as exc:
            raise HTTPException(status_code=422, detail="invalid principal") from exc

    @app.post("/api/v1/identity/principals/{principal_id}/role", tags=["identity"])
    def change_role(
        principal_id: str,
        payload: RoleChangeIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            with factory() as session:
                identity = boundary._identity_service(session)
                return identity.public_principal(
                    identity.change_role(
                        principal_id,
                        payload.role,
                        actor_id=current.id,
                        request_id=boundary.request_id(request),
                    )
                )
        except IdentityValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid role change") from exc

    @app.post("/api/v1/identity/principals/{principal_id}/password", tags=["identity"])
    def change_password(
        principal_id: str,
        payload: PasswordChangeIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> Response:
        try:
            with factory() as session:
                boundary._identity_service(session).change_password(
                    principal_id,
                    payload.password,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
        except IdentityValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid password change") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/api/v1/identity/principals/{principal_id}/disable", tags=["identity"])
    def disable_principal(
        principal_id: str,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> Response:
        try:
            with factory() as session:
                boundary._identity_service(session).disable_principal(
                    principal_id,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
        except IdentityValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid principal disable") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/identity/principals/{principal_id}/credentials", tags=["identity"])
    def list_credentials(
        principal_id: str,
        _: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("identity:manage", roles=frozenset({"admin"}))),
        ],
    ) -> dict[str, object]:
        with factory() as session:
            return {"items": boundary._identity_service(session).list_credentials(principal_id)}

    @app.post("/api/v1/identity/principals/{principal_id}/credentials", tags=["identity"])
    def issue_credential(
        principal_id: str,
        payload: CredentialIssueIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            with factory() as session:
                issued = boundary._identity_service(session).issue_api_credential(
                    principal_id,
                    payload.scopes,
                    expires_in_seconds=payload.expires_in_seconds,
                    label=payload.label,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
                return issued_credential_response(issued)
        except IdentityValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid credential issue") from exc

    @app.post("/api/v1/identity/credentials/{credential_id}/rotate", tags=["identity"])
    def rotate_credential(
        credential_id: str,
        payload: CredentialRotateIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            with factory() as session:
                issued = boundary._identity_service(session).rotate_api_credential(
                    credential_id,
                    expires_in_seconds=payload.expires_in_seconds,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
                return issued_credential_response(issued)
        except IdentityValidationError as exc:
            raise HTTPException(status_code=404, detail="credential not found") from exc

    @app.post("/api/v1/identity/credentials/{credential_id}/revoke", tags=["identity"])
    def revoke_credential(
        credential_id: str,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "identity:manage", roles=frozenset({"admin"}), state_change=True
                )
            ),
        ],
    ) -> Response:
        try:
            with factory() as session:
                boundary._identity_service(session).revoke_api_credential(
                    credential_id,
                    actor_id=current.id,
                    request_id=boundary.request_id(request),
                )
        except IdentityValidationError as exc:
            raise HTTPException(status_code=404, detail="credential not found") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/security/audit", tags=["security"])
    def security_audit(
        _: Annotated[
            CurrentPrincipal,
            Depends(boundary.require_human_scope("audit:read", roles=frozenset({"admin"}))),
        ],
        limit: int = Query(default=50, ge=1, le=200),
        before: datetime | None = None,
    ) -> dict[str, object]:
        with factory() as session:
            return {"items": boundary._identity_service(session).list_audit(limit, before)}

