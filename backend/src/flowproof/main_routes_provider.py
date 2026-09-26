"""Human-gated browser PKCE and real observe-only qualification routes."""

from decimal import Decimal
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from flowproof.identity import CurrentPrincipal
from flowproof.xero_demo import XeroConnectionError, XeroDemoAccountingClient


class XeroPkceStartIn(BaseModel):
    client_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")


class XeroQualificationIn(BaseModel):
    invoice_id: str = Field(min_length=1, max_length=255)
    expected_exists: bool = True
    expected_amount: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    provider_identity_confirmed: bool
    entity_confirmed: bool
    evidence_bounded: bool
    no_mutation_confirmed: bool


def _provider_or_404(
    provider: XeroDemoAccountingClient | None,
) -> XeroDemoAccountingClient:
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return provider


def _provider_error(exc: XeroConnectionError) -> HTTPException:
    if exc.code.endswith("UNAVAILABLE"):
        code = status.HTTP_502_BAD_GATEWAY
    elif exc.code.endswith("INVALID") or exc.code.endswith("REQUIRED"):
        code = status.HTTP_422_UNPROCESSABLE_ENTITY
    else:
        code = status.HTTP_409_CONFLICT
    return HTTPException(status_code=code, detail=exc.code)


def register_provider_routes(
    app: FastAPI,
    *,
    boundary: Any,
    config: Any,
    provider: XeroDemoAccountingClient | None,
) -> None:
    @app.get("/api/v1/provider-connections/xero/status", tags=["providers"])
    def xero_status(
        current: Annotated[
            CurrentPrincipal, Depends(boundary.require("read:operations"))
        ],
    ) -> dict[str, Any]:
        return _provider_or_404(provider).public_status(current.id)

    @app.post("/api/v1/provider-connections/xero/pkce/start", tags=["providers"])
    def xero_pkce_start(
        payload: XeroPkceStartIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "evaluations:write",
                    roles=frozenset({"operator", "admin"}),
                    state_change=True,
                )
            ),
        ],
    ) -> dict[str, Any]:
        selected = _provider_or_404(provider)
        try:
            result = selected.start_authorization(
                principal_id=current.id,
                principal_name=current.name,
                principal_role=current.role or "operator",
                client_id=payload.client_id,
                redirect_uri=config.xero_redirect_uri,
            )
        except XeroConnectionError as exc:
            raise _provider_error(exc) from exc
        boundary.audit(
            "xero_pkce_started",
            current,
            target_type="provider_connection",
            target_id="xero-demo",
            request=request,
            details={
                "connection_mode": "oauth2_pkce_ephemeral",
                "manual_secret_copy_required": False,
                "requested_scopes": result["requested_scopes"],
            },
        )
        return result

    @app.get(
        "/api/v1/provider-connections/xero/callback",
        tags=["providers"],
        response_class=HTMLResponse,
    )
    def xero_pkce_callback(
        state: str,
        code: str | None = None,
        error: str | None = None,
    ) -> HTMLResponse:
        selected = _provider_or_404(provider)
        if error is not None or code is None:
            selected.cancel_authorization(state)
            return HTMLResponse(
                "<!doctype html><title>FlowProof Xero</title>"
                "<h1>Xero connection was not completed</h1>"
                "<p>Return to FlowProof and start the connection again.</p>",
                status_code=status.HTTP_400_BAD_REQUEST,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": "default-src 'none'",
                },
            )
        try:
            selected.complete_authorization(state=state, code=code)
            principal_id, principal_name, principal_role = selected.connection_operator()
        except XeroConnectionError as exc:
            return HTMLResponse(
                "<!doctype html><title>FlowProof Xero</title>"
                f"<h1>Xero connection failed</h1><p>{exc.code}</p>"
                "<p>Return to FlowProof and start the connection again.</p>",
                status_code=status.HTTP_409_CONFLICT,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": "default-src 'none'",
                },
            )
        callback_actor = CurrentPrincipal(
            id=principal_id,
            name=principal_name,
            kind="human",
            role=principal_role,
            scopes=frozenset({"read:operations", "evaluations:write"}),
            authentication="xero_pkce_state",
        )
        boundary.audit(
            "xero_pkce_connected",
            callback_actor,
            target_type="provider_connection",
            target_id="xero-demo",
            details={
                "demo_company_confirmed": True,
                "manual_secret_copy_required": False,
                "refresh_token_persisted": False,
            },
        )
        return HTMLResponse(
            "<!doctype html><title>FlowProof Xero</title>"
            "<h1>Xero Demo connected</h1>"
            "<p>No token was copied. Return to FlowProof and check the connection.</p>",
            headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'"},
        )

    @app.post("/api/v1/provider-connections/xero/disconnect", tags=["providers"])
    def xero_disconnect(
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "evaluations:write",
                    roles=frozenset({"operator", "admin"}),
                    state_change=True,
                )
            ),
        ],
    ) -> dict[str, Any]:
        selected = _provider_or_404(provider)
        try:
            disconnected = selected.disconnect(current.id)
        except XeroConnectionError as exc:
            raise _provider_error(exc) from exc
        boundary.audit(
            "xero_pkce_disconnected",
            current,
            target_type="provider_connection",
            target_id="xero-demo",
            request=request,
            details={"local_token_discarded": disconnected},
        )
        return selected.public_status(current.id)

    @app.post("/api/v1/provider-connections/xero/qualify-invoice", tags=["providers"])
    def xero_qualify_invoice(
        payload: XeroQualificationIn,
        request: Request,
        current: Annotated[
            CurrentPrincipal,
            Depends(
                boundary.require_human_scope(
                    "evaluations:write",
                    roles=frozenset({"operator", "admin"}),
                    state_change=True,
                )
            ),
        ],
    ) -> dict[str, Any]:
        selected = _provider_or_404(provider)
        try:
            lifecycle = selected.qualify_invoice(
                principal_id=current.id,
                principal_name=current.name,
                principal_role=current.role or "operator",
                invoice_id=payload.invoice_id,
                expected_exists=payload.expected_exists,
                expected_amount=payload.expected_amount,
                currency=payload.currency,
                confirmations={
                    "provider_identity_confirmed": payload.provider_identity_confirmed,
                    "entity_confirmed": payload.entity_confirmed,
                    "evidence_bounded": payload.evidence_bounded,
                    "no_mutation_confirmed": payload.no_mutation_confirmed,
                },
            )
        except XeroConnectionError as exc:
            raise _provider_error(exc) from exc
        boundary.audit(
            "xero_observe_only_qualified",
            current,
            target_type="invoice",
            target_id=payload.invoice_id,
            request=request,
            details={
                "provider_id": "xero-demo",
                "result": lifecycle["result"],
                "invariant_result": lifecycle["observation"]["invariant_result"],
                "provider_mutation_count": 0,
            },
        )
        return lifecycle
