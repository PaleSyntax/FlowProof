"""Pure FastAPI route composer for validated settings and an explicit provider client."""

from __future__ import annotations

import logging
from collections.abc import Callable, Generator
from contextlib import asynccontextmanager
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, sessionmaker

from flowproof.accounting import AccountingClient, ProviderContract
from flowproof.alerts import NullAlertDispatcher, WebhookAlertDispatcher
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.identity import (
    AuthorizationDenied,
    CurrentPrincipal,
    IdentityService,
    InvalidCredentials,
)
from flowproof.main_openapi import install_openapi_contract
from flowproof.main_routes_admin import register_admin_routes
from flowproof.main_routes_common import register_common_routes
from flowproof.main_routes_demo import register_demo_routes
from flowproof.main_routes_provider import register_provider_routes
from flowproof.main_routes_recovery import register_recovery_routes
from flowproof.observability import Metrics, configure_structured_logging
from flowproof.service import FlowProofService, RecoveryGateError
from flowproof.xero_demo import (
    XERO_ACCOUNTING_BASE_PATH,
    XERO_ACCOUNTING_ORIGIN,
    XeroDemoAccountingClient,
)

REQUEST_ID_MAX_LENGTH = 128


def recovery_gate_http_exception(exc: RecoveryGateError) -> HTTPException:
    code = (
        status.HTTP_404_NOT_FOUND
        if str(exc) == "recovery plan was not found"
        else status.HTTP_409_CONFLICT
    )
    return HTTPException(status_code=code, detail=str(exc))


class AuthorizationBoundary:
    """Central HTTP adapter for all authentication, scopes, and session CSRF checks."""

    def __init__(self, config: Settings, factory: sessionmaker[Session], metrics: Metrics) -> None:
        self.config = config
        self.factory = factory
        self.metrics = metrics

    def require(
        self, scope: str, *, state_change: bool = False
    ) -> Callable[[Request], CurrentPrincipal]:
        def dependency(request: Request) -> CurrentPrincipal:
            current = self.current(request)
            if scope not in current.scopes:
                self._audit_denial(current, request, scope, "missing_scope")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="insufficient scope"
                )
            if state_change:
                self._validate_csrf(current, request)
            return current

        return dependency

    def require_any_scope(self, scopes: frozenset[str]) -> Callable[[Request], CurrentPrincipal]:
        """Require at least one listed scope without broadening a caller's credential."""
        required_scope = "any(" + ",".join(sorted(scopes)) + ")"

        def dependency(request: Request) -> CurrentPrincipal:
            current = self.current(request)
            if not current.scopes.intersection(scopes):
                self._audit_denial(current, request, required_scope, "missing_any_scope")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="insufficient scope"
                )
            return current

        return dependency

    def require_human_scope(
        self,
        scope: str,
        *,
        roles: frozenset[str] = frozenset({"operator", "admin"}),
        state_change: bool = False,
    ) -> Callable[[Request], CurrentPrincipal]:
        """Require a role-bearing human; service credentials never cross this gate."""

        def dependency(request: Request) -> CurrentPrincipal:
            current = self.current(request)
            if scope not in current.scopes:
                self._audit_denial(current, request, scope, "missing_scope")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="insufficient scope"
                )
            if current.kind != "human":
                self._audit_denial(current, request, scope, "human_only")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="human approval required"
                )
            if current.role not in roles:
                self._audit_denial(current, request, scope, "role_violation")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="role is not authorized"
                )
            if state_change:
                self._validate_csrf(current, request)
            return current

        return dependency

    def authenticated(self, *, state_change: bool = False) -> Callable[[Request], CurrentPrincipal]:
        def dependency(request: Request) -> CurrentPrincipal:
            current = self.current(request)
            if state_change:
                self._validate_csrf(current, request)
            return current

        return dependency

    def current(self, request: Request) -> CurrentPrincipal:
        authorization = request.headers.get("authorization")
        aliases = [
            value
            for value in (
                request.headers.get("x-flowproof-token"),
                request.headers.get("x-flowproof-operator-token"),
            )
            if value
        ]
        if len(aliases) > 1 or (authorization and aliases):
            raise self._invalid_credentials()
        try:
            with self.factory() as session:
                identity = self._identity_service(session)
                if authorization:
                    scheme, separator, token = authorization.partition(" ")
                    if scheme.lower() != "bearer" or not separator or not token:
                        raise InvalidCredentials("invalid credentials")
                    return identity.authenticate_bearer(token)
                if aliases:
                    if not self.config.legacy_header_auth_enabled:
                        raise InvalidCredentials("invalid credentials")
                    return identity.authenticate_bearer(aliases[0])
                session_token = request.cookies.get("flowproof_session")
                if not session_token:
                    raise InvalidCredentials("invalid credentials")
                return identity.authenticate_session(session_token)
        except InvalidCredentials:
            self.metrics.record_authentication_failure()
            raise self._invalid_credentials() from None

    def issue_csrf(self, current: CurrentPrincipal) -> str | None:
        with self.factory() as session:
            try:
                return self._identity_service(session).issue_csrf(current)
            except InvalidCredentials:
                raise self._invalid_credentials() from None

    def logout(self, current: CurrentPrincipal) -> None:
        with self.factory() as session:
            self._identity_service(session).logout(current)

    def audit(
        self,
        action: str,
        current: CurrentPrincipal,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        correlation_id: str | None = None,
        request: Request | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self.factory() as session:
            self._identity_service(session).record_action(
                action,
                current,
                target_type=target_type,
                target_id=target_id,
                correlation_id=correlation_id,
                request_id=request_id or self.request_id(request),
                details=details,
            )

    @staticmethod
    def request_id(request: Request | None) -> str | None:
        value = getattr(getattr(request, "state", None), "request_id", None)
        return value if isinstance(value, str) else None

    def _audit_denial(
        self, current: CurrentPrincipal, request: Request, scope: str, reason: str
    ) -> None:
        self.metrics.record_authorization_denial()
        route = request.scope.get("route")
        path = getattr(route, "path", request.url.path)
        try:
            with self.factory() as session:
                self._identity_service(session).record_authorization_denied(
                    current,
                    required_scope=scope,
                    reason=reason,
                    method=request.method,
                    path=str(path)[:256],
                    request_id=self.request_id(request),
                )
        except Exception:
            # A best-effort denial audit must never turn a correctly denied request into a 500.
            return

    def _validate_csrf(self, current: CurrentPrincipal, request: Request) -> None:
        if current.authentication != "session":
            return
        try:
            with self.factory() as session:
                self._identity_service(session).validate_csrf(
                    current, request.headers.get("x-csrf-token")
                )
        except AuthorizationDenied:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed"
            ) from None

    def _identity_service(self, session: Session) -> IdentityService:
        if not self.config.token_pepper:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="identity authentication is unavailable",
            )
        return IdentityService(
            session,
            self.config.token_pepper,
            login_failure_limit=self.config.login_failure_limit,
            lock_seconds=self.config.login_lock_seconds,
            session_ttl_seconds=self.config.session_ttl_seconds,
            session_idle_seconds=self.config.session_idle_seconds,
            session_absolute_seconds=self.config.session_absolute_seconds,
            api_token_default_ttl_seconds=self.config.api_token_default_ttl_seconds,
            api_token_max_ttl_seconds=self.config.api_token_max_ttl_seconds,
        )

    @staticmethod
    def _invalid_credentials() -> HTTPException:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")


def compose_app(
    settings: Settings,
    accounting: AccountingClient,
    session_factory: sessionmaker[Session] | None = None,
) -> FastAPI:
    """Compose routes from already validated settings and an explicit provider client."""

    config = settings
    client = accounting
    factory = session_factory or make_session_factory(make_engine(config.database_url))
    configure_structured_logging(config)
    metrics = Metrics()
    boundary = AuthorizationBoundary(config, factory, metrics)
    xero_provider = None
    if config.xero_pkce_enabled:
        if config.xero_provider_contract_path is None:
            raise RuntimeError("Xero provider contract path is required")
        try:
            xero_contract = ProviderContract.load(config.xero_provider_contract_path)
            xero_provider = XeroDemoAccountingClient(
                f"{XERO_ACCOUNTING_ORIGIN}{XERO_ACCOUNTING_BASE_PATH}",
                xero_contract,
            )
        except ValueError as exc:
            raise RuntimeError("Xero PKCE provider configuration is invalid") from exc
    alerts = (
        WebhookAlertDispatcher(config.alert_webhook_url)
        if config.alert_webhook_url
        else NullAlertDispatcher()
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with factory() as session:
            FlowProofService(
                session,
                str(config.policy_path),
                client,
                max_payload_bytes=config.max_payload_bytes,
                recovery_writes_enabled=config.recovery_writes_enabled,
            ).ensure_policy()
            if config.legacy_header_auth_enabled:
                identity = boundary._identity_service(session)
                identity.ensure_legacy_credential(
                    "legacy-events",
                    config.legacy_ingestion_token or "",
                    {"events:write"},
                )
                identity.ensure_legacy_credential(
                    "legacy-operator",
                    config.legacy_operator_token or "",
                    {
                        "read:operations",
                        "evaluations:write",
                        "recovery:approve",
                        "recovery:execute",
                        "recovery:verify",
                        "chaos:write",
                    },
                )
        yield

    app = FastAPI(title="FlowProof API", version="0.6.0", lifespan=lifespan)
    app.state.settings = config
    app.state.session_factory = factory
    app.state.accounting = client
    app.state.metrics = metrics
    app.state.alerts = alerts
    app.state.xero_provider = xero_provider
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[config.cors_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-CSRF-Token",
            "X-Request-ID",
            "X-FlowProof-Token",
            "X-FlowProof-Operator-Token",
        ],
        expose_headers=["X-Request-ID"],
    )

    @app.middleware("http")
    async def limit_request_body(request: Request, call_next):
        candidate = request.headers.get("x-request-id")
        if (
            candidate
            and len(candidate) <= REQUEST_ID_MAX_LENGTH
            and candidate.isascii()
            and candidate[0].isalnum()
            and all(character.isalnum() or character in "._:-" for character in candidate)
        ):
            request.state.request_id = candidate
        else:
            request.state.request_id = str(uuid4())
        length = request.headers.get("content-length")
        try:
            if length and int(length) > config.max_body_bytes:
                response = Response(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            else:
                response = await call_next(request)
        except Exception as exc:
            logging.getLogger("flowproof.request").exception(
                "request_failed",
                extra={
                    "request_id": request.state.request_id,
                    "error_type": type(exc).__name__,
                },
            )
            raise
        response.headers["X-Request-ID"] = request.state.request_id
        metrics.record_http(request.method, response.status_code)
        logging.getLogger("flowproof.request").info(
            "request_completed",
            extra={
                "request_id": request.state.request_id,
                "status_code": response.status_code,
            },
        )
        return response

    def get_service() -> Generator[FlowProofService, None, None]:
        with factory() as session:
            yield FlowProofService(
                session,
                str(config.policy_path),
                client,
                max_payload_bytes=config.max_payload_bytes,
                recovery_writes_enabled=config.recovery_writes_enabled,
            )

    Service = Annotated[FlowProofService, Depends(get_service)]

    register_common_routes(
        app,
        factory=factory,
        boundary=boundary,
        metrics=metrics,
        config=config,
        Service=Service,
    )
    register_recovery_routes(
        app,
        boundary=boundary,
        Service=Service,
        recovery_gate_http_exception=recovery_gate_http_exception,
    )
    register_admin_routes(
        app,
        factory=factory,
        boundary=boundary,
        Service=Service,
    )
    register_demo_routes(
        app,
        boundary=boundary,
        config=config,
        Service=Service,
    )
    register_provider_routes(
        app,
        boundary=boundary,
        config=config,
        provider=xero_provider,
    )
    install_openapi_contract(app)
    return app
