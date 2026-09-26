"""Persistent authentication, authorization, and sanitized security audit primitives."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from flowproof.clock import monotonic_utc_now
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import (
    ApiCredential,
    AuthSession,
    HumanCredential,
    Principal,
    SecurityAuditEvent,
)

ALL_SCOPES = frozenset(
    {
        "events:write",
        "read:operations",
        "evaluations:write",
        "recovery:approve",
        "recovery:execute",
        "recovery:verify",
        "chaos:write",
        "identity:manage",
        "audit:read",
        "alerts:write",
    }
)
ROLE_SCOPES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read:operations"}),
    "operator": frozenset(
        {
            "read:operations",
            "evaluations:write",
            "recovery:approve",
            "recovery:execute",
            "recovery:verify",
            "chaos:write",
        }
    ),
    "admin": ALL_SCOPES,
}
N8N_SCOPES = frozenset({"events:write", "recovery:execute", "recovery:verify"})
AUDIT_TARGET_TYPES = frozenset(
    {
        "principal",
        "api_credential",
        "auth_session",
        "business_event",
        "correlation",
        "invoice",
        "provider_connection",
        "recovery_plan",
        "chaos_configuration",
    }
)

# Deliberately one process-wide Argon2 value: unknown-user login timing remains comparable
# without paying the hash-creation cost for every service/request instance.
_DUMMY_PASSWORD_HASH = PasswordHasher().hash("flowproof-process-dummy-password")


class IdentityError(Exception):
    """Base identity failure safe to expose through an intentionally generic response."""


class InvalidCredentials(IdentityError):
    pass


class AuthorizationDenied(IdentityError):
    pass


class IdentityValidationError(IdentityError):
    pass


@dataclass(frozen=True, slots=True)
class CurrentPrincipal:
    id: str
    name: str
    kind: str
    role: str | None
    scopes: frozenset[str]
    authentication: str
    credential_id: str | None = None
    session_id: str | None = None
    csrf_token: str | None = None


@dataclass(frozen=True, slots=True)
class IssuedApiCredential:
    id: str
    token: str
    token_prefix: str
    scopes: tuple[str, ...]
    expires_at: datetime


Clock = Callable[[], datetime]


class IdentityService:
    """Owns credential resolution and every authorization-relevant state transition."""

    def __init__(
        self,
        session: Session,
        token_pepper: str,
        *,
        clock: Clock | None = None,
        login_failure_limit: int = 5,
        lock_seconds: int = 900,
        session_ttl_seconds: int = 28_800,
        session_idle_seconds: int | None = None,
        session_absolute_seconds: int | None = None,
        api_token_default_ttl_seconds: int = 86_400,
        api_token_max_ttl_seconds: int = 2_592_000,
    ) -> None:
        if len(token_pepper) < 32:
            raise IdentityValidationError("FLOWPROOF_TOKEN_PEPPER must be at least 32 characters")
        self.session = session
        self.token_pepper = token_pepper
        self.clock = clock or monotonic_utc_now
        self.login_failure_limit = login_failure_limit
        self.lock_seconds = lock_seconds
        self.session_idle_seconds = session_idle_seconds or session_ttl_seconds
        self.session_absolute_seconds = session_absolute_seconds or session_ttl_seconds
        self.api_token_default_ttl_seconds = api_token_default_ttl_seconds
        self.api_token_max_ttl_seconds = api_token_max_ttl_seconds
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise IdentityValidationError("session idle lifetime exceeds absolute lifetime")
        if self.api_token_default_ttl_seconds > self.api_token_max_ttl_seconds:
            raise IdentityValidationError("credential default lifetime exceeds maximum")
        self.password_hasher = PasswordHasher()

    def create_human(
        self,
        name: str,
        password: str,
        role: str,
        *,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> Principal:
        self._validate_name(name)
        self._validate_password(password)
        if role not in ROLE_SCOPES:
            raise IdentityValidationError("unknown human role")
        principal = Principal(
            id=str(uuid4()), name=name.strip(), kind="human", role=role, allowed_scopes=[]
        )
        now = self.now()
        self.session.add(principal)
        self.session.flush()
        self.session.add(
            HumanCredential(
                principal_id=principal.id,
                password_hash=self.password_hasher.hash(password),
                password_changed_at=now,
            )
        )
        self._audit(
            "principal_created",
            "success",
            actor_id=actor_id,
            target_type="principal",
            target_id=principal.id,
            request_id=request_id,
        )
        self.session.commit()
        return principal

    def bootstrap_admin(self, name: str, password: str) -> tuple[Principal, bool]:
        self._validate_name(name)
        existing = self.session.scalar(select(Principal).where(Principal.name == name.strip()))
        enabled_admin = self.session.scalar(
            select(Principal).where(
                Principal.kind == "human",
                Principal.role == "admin",
                Principal.disabled_at.is_(None),
            )
        )
        if enabled_admin is not None:
            if existing is not None and existing.id == enabled_admin.id:
                return existing, True
            raise IdentityValidationError("an enabled bootstrap admin already exists")
        if existing is not None:
            raise IdentityValidationError("existing principal is not an enabled admin")
        return self.create_human(name, password, "admin"), False

    def create_service_account(
        self,
        name: str,
        scopes: set[str],
        *,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> Principal:
        self._validate_name(name)
        self._validate_scopes(scopes)
        normalized_name = name.strip()
        if self._is_n8n_account(normalized_name) and frozenset(scopes) != N8N_SCOPES:
            raise IdentityValidationError(
                "n8n service accounts have a fixed least-privilege envelope"
            )
        principal = Principal(
            id=str(uuid4()),
            name=normalized_name,
            kind="service",
            role=None,
            allowed_scopes=sorted(scopes),
        )
        self.session.add(principal)
        self._audit(
            "service_account_created",
            "success",
            actor_id=actor_id,
            target_type="principal",
            target_id=principal.id,
            request_id=request_id,
            details={"allowed_scopes": sorted(scopes)},
        )
        self.session.commit()
        return principal

    def issue_api_credential(
        self,
        principal_id: str,
        scopes: set[str],
        *,
        expires_in_seconds: int | None = None,
        label: str | None = None,
        replacement_operation_id: str | None = None,
        credential_type: str = "api",
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> IssuedApiCredential:
        principal = self._available_service_principal(principal_id)
        credential, issued = self._new_credential(
            principal,
            scopes,
            expires_in_seconds=expires_in_seconds,
            label=label,
            replacement_operation_id=replacement_operation_id,
            credential_type=credential_type,
        )
        self._audit(
            "credential_issued",
            "success",
            actor_id=actor_id,
            target_type="api_credential",
            target_id=credential.id,
            credential_id=credential.id,
            request_id=request_id,
            details={
                "credential_type": credential_type,
                "scopes": sorted(scopes),
                "replacement_operation_id": replacement_operation_id,
            },
        )
        self.session.commit()
        return issued

    def rotate_api_credential(
        self,
        credential_id: str,
        *,
        expires_in_seconds: int | None = None,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> IssuedApiCredential:
        credential = self.session.get(ApiCredential, credential_id)
        if credential is None or credential.revoked_at is not None:
            raise IdentityValidationError("credential is unavailable")
        principal = self._available_service_principal(credential.principal_id)
        replacement, issued = self._new_credential(
            principal,
            set(credential.scopes),
            expires_in_seconds=expires_in_seconds,
            label=self._credential_label(credential),
            replacement_operation_id=None,
            credential_type=credential.credential_type,
        )
        credential.revoked_at = self.now()
        self._audit(
            "credential_rotated",
            "success",
            actor_id=actor_id,
            target_type="api_credential",
            target_id=replacement.id,
            credential_id=replacement.id,
            request_id=request_id,
            details={"replaced_credential_id": credential.id},
        )
        self.session.commit()
        return issued

    def revoke_api_credential(
        self, credential_id: str, actor_id: str | None = None, request_id: str | None = None
    ) -> None:
        credential = self.session.get(ApiCredential, credential_id)
        if credential is None:
            raise IdentityValidationError("credential is unavailable")
        if credential.revoked_at is None:
            credential.revoked_at = self.now()
            self._audit(
                "credential_revoked",
                "success",
                actor_id=actor_id,
                target_type="api_credential",
                target_id=credential.id,
                credential_id=credential.id,
                request_id=request_id,
            )
            self.session.commit()

    def remediate_orphan_credential(
        self, credential_id: str, replacement_operation_id: str
    ) -> None:
        """Revoke an operation match without ever attempting raw-token recovery."""
        credential = self.session.get(ApiCredential, credential_id)
        if (
            credential is None
            or credential.details.get("replacement_operation_id") != replacement_operation_id
        ):
            raise IdentityValidationError("credential does not match the replacement operation")
        if credential.revoked_at is None:
            credential.revoked_at = self.now()
        self._audit(
            "credential_replacement_orphan_remediated",
            "success",
            actor_id=None,
            target_type="api_credential",
            target_id=credential.id,
            credential_id=credential.id,
            details={"replacement_operation_id": replacement_operation_id},
        )
        self.session.commit()

    def login(self, name: str, password: str) -> tuple[CurrentPrincipal, str, str]:
        now = self.now()
        principal = self.session.scalar(
            select(Principal).where(Principal.name == name.strip(), Principal.kind == "human")
        )
        credential = (
            self.session.get(HumanCredential, principal.id) if principal is not None else None
        )
        locked = bool(
            principal is not None
            and principal.locked_until is not None
            and self._as_utc(principal.locked_until) > now
        )
        if locked:
            self._audit_login_failure(principal)
            self.session.commit()
            raise InvalidCredentials("invalid credentials")
        if principal is not None and principal.locked_until is not None:
            principal.locked_until = None
            principal.failed_login_count = 0
        password_hash = credential.password_hash if credential is not None else _DUMMY_PASSWORD_HASH
        valid_password = self._verify_password(password_hash, password)
        unavailable = principal is None or credential is None or principal.disabled_at is not None
        if unavailable or not valid_password:
            if principal is not None and credential is not None and principal.disabled_at is None:
                principal.failed_login_count += 1
                if principal.failed_login_count >= self.login_failure_limit:
                    principal.locked_until = now + timedelta(seconds=self.lock_seconds)
            self._audit_login_failure(principal)
            self.session.commit()
            raise InvalidCredentials("invalid credentials")

        principal.failed_login_count = 0
        principal.locked_until = None
        principal.last_successful_login_at = now
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        absolute_expires_at = now + timedelta(seconds=self.session_absolute_seconds)
        idle_expires_at = min(
            now + timedelta(seconds=self.session_idle_seconds), absolute_expires_at
        )
        auth_session = AuthSession(
            id=str(uuid4()),
            principal_id=principal.id,
            token_hash=self.secret_hash(session_token),
            csrf_hash=self.secret_hash(csrf_token),
            # Retained as a deprecated compatibility mirror for 0003 consumers.
            expires_at=absolute_expires_at,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            last_seen_at=now,
        )
        self.session.add(auth_session)
        self._audit(
            "login_success",
            "success",
            actor_id=principal.id,
            target_type="auth_session",
            target_id=auth_session.id,
        )
        self.session.commit()
        return (
            self._human_context(
                principal, "session", session_id=auth_session.id, csrf_token=csrf_token
            ),
            session_token,
            csrf_token,
        )

    def authenticate_bearer(self, token: str) -> CurrentPrincipal:
        credential = self.session.scalar(
            select(ApiCredential).where(ApiCredential.token_hash == self.secret_hash(token))
        )
        if credential is None or credential.revoked_at is not None:
            raise InvalidCredentials("invalid credentials")
        now = self.now()
        if credential.expires_at is not None and self._as_utc(credential.expires_at) <= now:
            raise InvalidCredentials("invalid credentials")
        principal = self.session.get(Principal, credential.principal_id)
        if principal is None or principal.disabled_at is not None:
            raise InvalidCredentials("invalid credentials")
        if principal.kind == "service" and not set(credential.scopes) <= set(
            principal.allowed_scopes
        ):
            # 0005 preserves legacy credential rows but fail-closes a credential
            # that exceeds its backfilled service-account envelope.
            raise InvalidCredentials("invalid credentials")
        credential.last_used_at = now
        self.session.commit()
        return CurrentPrincipal(
            id=principal.id,
            name=principal.name,
            kind=principal.kind,
            role=principal.role,
            scopes=frozenset(credential.scopes),
            authentication="bearer",
            credential_id=credential.id,
        )

    def authenticate_session(self, session_token: str) -> CurrentPrincipal:
        auth_session = self.session.scalar(
            select(AuthSession).where(AuthSession.token_hash == self.secret_hash(session_token))
        )
        now = self.now()
        if (
            auth_session is None
            or auth_session.revoked_at is not None
            or self._as_utc(auth_session.idle_expires_at) <= now
            or self._as_utc(auth_session.absolute_expires_at) <= now
        ):
            raise InvalidCredentials("invalid credentials")
        principal = self.session.get(Principal, auth_session.principal_id)
        if principal is None or principal.disabled_at is not None:
            raise InvalidCredentials("invalid credentials")
        auth_session.last_seen_at = now
        auth_session.idle_expires_at = min(
            now + timedelta(seconds=self.session_idle_seconds),
            self._as_utc(auth_session.absolute_expires_at),
        )
        self.session.commit()
        return self._human_context(principal, "session", session_id=auth_session.id)

    def validate_csrf(self, current: CurrentPrincipal, csrf_token: str | None) -> None:
        if current.authentication != "session" or current.session_id is None:
            return
        auth_session = self.session.get(AuthSession, current.session_id)
        if auth_session is None or auth_session.revoked_at is not None or csrf_token is None:
            raise AuthorizationDenied("CSRF validation failed")
        if not hmac.compare_digest(auth_session.csrf_hash, self.secret_hash(csrf_token)):
            raise AuthorizationDenied("CSRF validation failed")

    def issue_csrf(self, current: CurrentPrincipal) -> str | None:
        if current.authentication != "session" or current.session_id is None:
            return None
        auth_session = self.session.get(AuthSession, current.session_id)
        if auth_session is None or auth_session.revoked_at is not None:
            raise InvalidCredentials("invalid credentials")
        csrf_token = secrets.token_urlsafe(32)
        auth_session.csrf_hash = self.secret_hash(csrf_token)
        self.session.commit()
        return csrf_token

    def logout(self, current: CurrentPrincipal) -> None:
        if current.session_id is None:
            return
        auth_session = self.session.get(AuthSession, current.session_id)
        if auth_session is not None and auth_session.revoked_at is None:
            auth_session.revoked_at = self.now()
            self._audit(
                "logout",
                "success",
                actor_id=current.id,
                target_type="auth_session",
                target_id=auth_session.id,
            )
            self.session.commit()

    def change_password(
        self,
        principal_id: str,
        password: str,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        self._validate_password(password)
        credential = self.session.get(HumanCredential, principal_id)
        if credential is None:
            raise IdentityValidationError("human credential is unavailable")
        credential.password_hash = self.password_hasher.hash(password)
        credential.password_changed_at = self.now()
        self._revoke_sessions(
            principal_id,
            actor_id=actor_id,
            reason="password_changed",
            request_id=request_id,
        )
        self._audit(
            "password_changed",
            "success",
            actor_id=actor_id,
            target_type="principal",
            target_id=principal_id,
            request_id=request_id,
        )
        self.session.commit()

    def change_role(
        self,
        principal_id: str,
        role: str,
        *,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> Principal:
        if role not in ROLE_SCOPES:
            raise IdentityValidationError("unknown human role")
        principal = self.session.get(Principal, principal_id)
        if principal is None or principal.kind != "human":
            raise IdentityValidationError("role changes require a human principal")
        if principal.role == "admin" and role != "admin" and self._is_last_enabled_admin(principal):
            raise IdentityValidationError("cannot demote the last enabled admin")
        principal.role = role
        self._audit(
            "role_changed",
            "success",
            actor_id=actor_id,
            target_type="principal",
            target_id=principal.id,
            request_id=request_id,
            details={"role": role},
        )
        self.session.commit()
        return principal

    def disable_principal(
        self, principal_id: str, actor_id: str | None = None, request_id: str | None = None
    ) -> None:
        principal = self.session.get(Principal, principal_id)
        if principal is None:
            raise IdentityValidationError("principal is unavailable")
        if principal.disabled_at is None and self._is_last_enabled_admin(principal):
            raise IdentityValidationError("cannot disable the last enabled admin")
        if principal.disabled_at is None:
            principal.disabled_at = self.now()
            self._revoke_sessions(
                principal_id,
                actor_id=actor_id,
                reason="principal_disabled",
                request_id=request_id,
            )
            self.session.query(ApiCredential).filter(
                ApiCredential.principal_id == principal_id, ApiCredential.revoked_at.is_(None)
            ).update({ApiCredential.revoked_at: self.now()}, synchronize_session=False)
            self._audit(
                "principal_disabled",
                "success",
                actor_id=actor_id,
                target_type="principal",
                target_id=principal_id,
                request_id=request_id,
            )
            self.session.commit()

    def list_principals(self) -> list[dict[str, Any]]:
        principals = self.session.scalars(
            select(Principal).order_by(Principal.created_at, Principal.name)
        ).all()
        return [self.public_principal(principal) for principal in principals]

    def list_credentials(self, principal_id: str) -> list[dict[str, Any]]:
        rows = self.session.scalars(
            select(ApiCredential)
            .where(ApiCredential.principal_id == principal_id)
            .order_by(ApiCredential.created_at)
        ).all()
        return [self.public_credential(row) for row in rows]

    def list_audit(self, limit: int, before: datetime | None = None) -> list[dict[str, Any]]:
        statement = (
            select(SecurityAuditEvent).order_by(SecurityAuditEvent.occurred_at.desc()).limit(limit)
        )
        if before is not None:
            statement = (
                select(SecurityAuditEvent)
                .where(SecurityAuditEvent.occurred_at < before)
                .order_by(SecurityAuditEvent.occurred_at.desc())
                .limit(limit)
            )
        return [self.public_audit(row) for row in self.session.scalars(statement).all()]

    def record_action(
        self,
        action: str,
        current: CurrentPrincipal,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._audit(
            action,
            "success",
            actor_id=current.id,
            actor_kind=current.kind,
            target_type=target_type,
            target_id=target_id,
            credential_id=current.credential_id,
            request_id=request_id,
            correlation_id=correlation_id,
            details=details,
        )
        self.session.commit()

    def record_authorization_denied(
        self,
        current: CurrentPrincipal,
        *,
        required_scope: str,
        reason: str,
        method: str,
        path: str,
        request_id: str | None = None,
    ) -> None:
        self._audit(
            "authorization_denied",
            "denied",
            actor_id=current.id,
            actor_kind=current.kind,
            credential_id=current.credential_id,
            request_id=request_id,
            details={
                "method": method,
                "path": path,
                "required_scope": required_scope,
                "reason": reason,
            },
        )
        self.session.commit()

    def ensure_legacy_credential(self, name: str, token: str, scopes: set[str]) -> None:
        if not token:
            return
        digest = self.secret_hash(token)
        if self.session.scalar(select(ApiCredential).where(ApiCredential.token_hash == digest)):
            return
        principal = self.session.scalar(select(Principal).where(Principal.name == name))
        if principal is None:
            principal = self.create_service_account(name, scopes)
        credential = ApiCredential(
            id=str(uuid4()),
            principal_id=principal.id,
            token_prefix=self.token_prefix(token),
            token_hash=digest,
            scopes=sorted(scopes),
            credential_type="legacy",
            details={"deprecated": True},
            # Legacy aliases are development-only and production rejects their entire mode.
            expires_at=None,
        )
        self.session.add(credential)
        self._audit(
            "credential_issued",
            "success",
            actor_id=None,
            target_type="api_credential",
            target_id=credential.id,
            credential_id=credential.id,
            details={"credential_type": "legacy"},
        )
        self.session.commit()

    def public_principal(self, principal: Principal) -> dict[str, Any]:
        return {
            "id": principal.id,
            "name": principal.name,
            "kind": principal.kind,
            "role": principal.role,
            "disabled_at": self._iso(principal.disabled_at),
            "created_at": self._iso(principal.created_at),
            "last_successful_login_at": self._iso(principal.last_successful_login_at),
            "scopes": sorted(ROLE_SCOPES[principal.role]) if principal.kind == "human" else [],
            "allowed_scopes": sorted(principal.allowed_scopes)
            if principal.kind == "service"
            else [],
        }

    @classmethod
    def public_credential(cls, credential: ApiCredential) -> dict[str, Any]:
        return {
            "id": credential.id,
            "token_prefix": credential.token_prefix,
            "scopes": credential.scopes,
            "credential_type": credential.credential_type,
            "label": cls._credential_label(credential),
            "created_at": cls._iso(credential.created_at),
            "expires_at": cls._iso(credential.expires_at),
            "last_used_at": cls._iso(credential.last_used_at),
            "revoked_at": cls._iso(credential.revoked_at),
        }

    @classmethod
    def public_audit(cls, row: SecurityAuditEvent) -> dict[str, Any]:
        return {
            "id": row.id,
            "occurred_at": cls._iso(row.occurred_at),
            "action": row.action,
            "outcome": row.outcome,
            "actor_principal_id": row.actor_principal_id,
            "actor_kind": row.actor_kind,
            "target_principal_id": row.target_principal_id,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "credential_id": row.credential_id,
            "request_id": row.request_id,
            "correlation_id": row.correlation_id,
            "metadata": row.details,
        }

    def now(self) -> datetime:
        return self.clock().astimezone(UTC)

    def secret_hash(self, value: str) -> str:
        return hmac.new(
            self.token_pepper.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def token_prefix(token: str) -> str:
        return token[:12]

    @staticmethod
    def sanitize_details(details: dict[str, Any]) -> dict[str, Any]:
        prohibited = ("password", "token", "secret", "cookie", "csrf", "authorization", "pepper")
        return {
            str(key)[:64]: "[REDACTED]"
            if any(fragment in str(key).lower() for fragment in prohibited)
            else str(value)[:256]
            if isinstance(value, (str, int, float, bool))
            else "[OMITTED]"
            for key, value in details.items()
        }

    def _new_credential(
        self,
        principal: Principal,
        scopes: set[str],
        *,
        expires_in_seconds: int | None,
        label: str | None,
        replacement_operation_id: str | None,
        credential_type: str,
    ) -> tuple[ApiCredential, IssuedApiCredential]:
        self._validate_scopes(scopes)
        allowed = set(principal.allowed_scopes)
        if not scopes <= allowed:
            raise IdentityValidationError("credential scopes exceed the service account envelope")
        ttl = self._credential_ttl(expires_in_seconds)
        token = secrets.token_urlsafe(32)
        expires_at = self.now() + timedelta(seconds=ttl)
        metadata: dict[str, str] = {}
        if label:
            metadata["label"] = label
        if replacement_operation_id is not None:
            try:
                UUID(replacement_operation_id)
            except ValueError as exc:
                raise IdentityValidationError("replacement operation ID must be a UUID") from exc
            metadata["replacement_operation_id"] = replacement_operation_id
        credential = ApiCredential(
            id=str(uuid4()),
            principal_id=principal.id,
            token_prefix=self.token_prefix(token),
            token_hash=self.secret_hash(token),
            scopes=sorted(scopes),
            credential_type=credential_type,
            details=self.sanitize_details(metadata),
            expires_at=expires_at,
        )
        self.session.add(credential)
        return credential, IssuedApiCredential(
            id=credential.id,
            token=token,
            token_prefix=credential.token_prefix,
            scopes=tuple(sorted(scopes)),
            expires_at=expires_at,
        )

    def _available_service_principal(self, principal_id: str) -> Principal:
        principal = self.session.get(Principal, principal_id)
        if principal is None or principal.disabled_at is not None or principal.kind != "service":
            raise IdentityValidationError("API credentials require an enabled service account")
        return principal

    def _credential_ttl(self, value: int | None) -> int:
        ttl = self.api_token_default_ttl_seconds if value is None else value
        if not 1 <= ttl <= self.api_token_max_ttl_seconds:
            raise IdentityValidationError("credential lifetime is outside the configured bound")
        return ttl

    def _human_context(
        self,
        principal: Principal,
        authentication: str,
        *,
        session_id: str | None = None,
        csrf_token: str | None = None,
    ) -> CurrentPrincipal:
        if principal.role not in ROLE_SCOPES:
            raise InvalidCredentials("invalid credentials")
        return CurrentPrincipal(
            id=principal.id,
            name=principal.name,
            kind=principal.kind,
            role=principal.role,
            scopes=ROLE_SCOPES[principal.role],
            authentication=authentication,
            session_id=session_id,
            csrf_token=csrf_token,
        )

    def _audit_login_failure(self, principal: Principal | None) -> None:
        self._audit(
            "login_failure",
            "denied",
            actor_id=None,
            actor_kind="anonymous",
            target_type="principal" if principal is not None else None,
            target_id=principal.id if principal is not None else None,
        )

    def _audit(
        self,
        action: str,
        outcome: str,
        *,
        actor_id: str | None,
        actor_kind: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        credential_id: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if target_type is not None and target_type not in AUDIT_TARGET_TYPES:
            raise IdentityValidationError("unsupported audit target type")
        if target_id is not None and len(target_id) > 255:
            raise IdentityValidationError("audit target ID is too long")
        if actor_id is not None and actor_kind is None:
            actor = self.session.get(Principal, actor_id)
            actor_kind = actor.kind if actor is not None else None
        self.session.add(
            SecurityAuditEvent(
                id=str(uuid4()),
                occurred_at=self.now(),
                action=action,
                outcome=outcome,
                actor_principal_id=actor_id,
                actor_kind=actor_kind,
                target_principal_id=target_id if target_type == "principal" else None,
                target_type=target_type,
                target_id=target_id,
                credential_id=credential_id,
                request_id=request_id[:128] if request_id else None,
                correlation_id=correlation_id[:255] if correlation_id else None,
                details=self.sanitize_details(details or {}),
            )
        )

    def _revoke_sessions(
        self,
        principal_id: str,
        *,
        actor_id: str | None,
        reason: str,
        request_id: str | None = None,
    ) -> None:
        active_sessions = self.session.scalars(
            select(AuthSession).where(
                AuthSession.principal_id == principal_id, AuthSession.revoked_at.is_(None)
            )
        ).all()
        revoked_at = self.now()
        for auth_session in active_sessions:
            auth_session.revoked_at = revoked_at
            self._audit(
                "session_revoked",
                "success",
                actor_id=actor_id,
                target_type="auth_session",
                target_id=auth_session.id,
                request_id=request_id,
                details={"reason": reason},
            )

    def _is_last_enabled_admin(self, principal: Principal) -> bool:
        if (
            principal.kind != "human"
            or principal.role != "admin"
            or principal.disabled_at is not None
        ):
            return False
        return (
            self.session.scalar(
                select(func.count(Principal.id)).where(
                    Principal.kind == "human",
                    Principal.role == "admin",
                    Principal.disabled_at.is_(None),
                )
            )
            == 1
        )

    @staticmethod
    def _is_n8n_account(name: str) -> bool:
        return name == "n8n" or name.startswith("n8n-")

    @staticmethod
    def _credential_label(credential: ApiCredential) -> str | None:
        label = credential.details.get("label") if isinstance(credential.details, dict) else None
        return label if isinstance(label, str) else None

    @staticmethod
    def _validate_name(name: str) -> None:
        if not 1 <= len(name.strip()) <= 128:
            raise IdentityValidationError("principal name must be between 1 and 128 characters")

    @staticmethod
    def _validate_password(password: str) -> None:
        if not 12 <= len(password) <= 1024:
            raise IdentityValidationError("password must be between 12 and 1024 characters")

    @staticmethod
    def _validate_scopes(scopes: set[str]) -> None:
        if not scopes or not scopes <= ALL_SCOPES:
            raise IdentityValidationError("credential scopes are invalid")

    def _verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self.password_hasher.verify(password_hash, password)
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _iso(value: datetime | None) -> str | None:
        return value.isoformat() if value is not None else None


def cli_main(argv: list[str] | None = None) -> int:
    """Administrative CLI. A newly issued raw token is emitted exactly once."""
    parser = argparse.ArgumentParser(prog="python -m flowproof.identity")
    commands = parser.add_subparsers(dest="command", required=True)

    bootstrap = commands.add_parser("bootstrap-admin")
    bootstrap.add_argument("--name", required=True)
    bootstrap.add_argument("--password-stdin", action="store_true")

    service = commands.add_parser("create-service-account")
    service.add_argument("--name", required=True)
    service.add_argument("--scope", action="append", required=True)

    issue = commands.add_parser("issue-token")
    issue.add_argument("--principal-id", required=True)
    issue.add_argument("--scope", action="append", required=True)
    issue.add_argument("--expires-in-seconds", type=int)
    issue.add_argument("--label")
    issue.add_argument("--operation-id")

    rotate = commands.add_parser("rotate-token")
    rotate.add_argument("--credential-id", required=True)
    rotate.add_argument("--expires-in-seconds", type=int)

    revoke = commands.add_parser("revoke-token")
    revoke.add_argument("--credential-id", required=True)

    status = commands.add_parser("service-credential-status")
    status.add_argument("--name", required=True)
    status.add_argument("--operation-id")

    remediate = commands.add_parser("remediate-orphan-credential")
    remediate.add_argument("--credential-id", required=True)
    remediate.add_argument("--operation-id", required=True)

    args = parser.parse_args(argv)
    config = Settings.from_environment()
    try:
        config.validate_production_security()
        if not config.token_pepper:
            raise IdentityValidationError("FLOWPROOF_TOKEN_PEPPER is required")
        factory = make_session_factory(make_engine(config.database_url))
        with factory() as session:
            identity = IdentityService(
                session,
                config.token_pepper,
                login_failure_limit=config.login_failure_limit,
                lock_seconds=config.login_lock_seconds,
                session_ttl_seconds=config.session_ttl_seconds,
                session_idle_seconds=config.session_idle_seconds,
                session_absolute_seconds=config.session_absolute_seconds,
                api_token_default_ttl_seconds=config.api_token_default_ttl_seconds,
                api_token_max_ttl_seconds=config.api_token_max_ttl_seconds,
            )
            if args.command == "bootstrap-admin":
                principal, idempotent = identity.bootstrap_admin(
                    args.name, _read_password(args.password_stdin)
                )
                print(
                    json.dumps(
                        {
                            "idempotent": idempotent,
                            "principal": identity.public_principal(principal),
                        }
                    )
                )
                return 0
            if args.command == "create-service-account":
                existing = session.scalar(select(Principal).where(Principal.name == args.name))
                if existing is not None:
                    print(
                        json.dumps(
                            {"idempotent": True, "principal": identity.public_principal(existing)}
                        )
                    )
                    return 0
                principal = identity.create_service_account(args.name, set(args.scope))
                print(
                    json.dumps(
                        {"idempotent": False, "principal": identity.public_principal(principal)}
                    )
                )
                return 0
            if args.command == "issue-token":
                issued = identity.issue_api_credential(
                    args.principal_id,
                    set(args.scope),
                    expires_in_seconds=args.expires_in_seconds,
                    label=args.label,
                    replacement_operation_id=args.operation_id,
                )
                print(json.dumps(_issued_response(issued)))
                return 0
            if args.command == "rotate-token":
                issued = identity.rotate_api_credential(
                    args.credential_id, expires_in_seconds=args.expires_in_seconds
                )
                print(json.dumps(_issued_response(issued)))
                return 0
            if args.command == "revoke-token":
                identity.revoke_api_credential(args.credential_id)
                print(json.dumps({"credential_id": args.credential_id, "revoked": True}))
                return 0
            if args.command == "remediate-orphan-credential":
                identity.remediate_orphan_credential(args.credential_id, args.operation_id)
                print(
                    json.dumps(
                        {
                            "credential_id": args.credential_id,
                            "operation_id": args.operation_id,
                            "remediated": True,
                        }
                    )
                )
                return 0
            if args.command == "service-credential-status":
                principal = session.scalar(select(Principal).where(Principal.name == args.name))
                if principal is None or principal.kind != "service":
                    raise IdentityValidationError("service account was not found")
                now = identity.now()
                credentials = session.scalars(
                    select(ApiCredential)
                    .where(ApiCredential.principal_id == principal.id)
                    .order_by(ApiCredential.created_at)
                ).all()
                if args.operation_id:
                    credentials = [
                        credential
                        for credential in credentials
                        if credential.details.get("replacement_operation_id") == args.operation_id
                    ]

                def credential_status(credential: ApiCredential) -> str:
                    if credential.revoked_at is not None:
                        return "revoked"
                    if (
                        credential.expires_at is not None
                        and identity._as_utc(credential.expires_at) <= now
                    ):
                        return "expired_unrevoked"
                    return "unexpired_unrevoked"

                public_credentials = []
                for credential in credentials:
                    lifecycle_status = credential_status(credential)
                    public_credentials.append(
                        {
                            "credential_id": credential.id,
                            "label": identity._credential_label(credential),
                            "operation_id": credential.details.get("replacement_operation_id"),
                            "created_at": identity._iso(credential.created_at),
                            "expires_at": identity._iso(credential.expires_at),
                            "revoked_at": identity._iso(credential.revoked_at),
                            "status": lifecycle_status,
                            "operationally_active": lifecycle_status == "unexpired_unrevoked"
                            and principal.disabled_at is None,
                        }
                    )
                counts = {
                    "unexpired_unrevoked": sum(
                        credential["operationally_active"] for credential in public_credentials
                    ),
                    "expired_unrevoked": sum(
                        credential["status"] == "expired_unrevoked"
                        for credential in public_credentials
                    ),
                    "revoked": sum(
                        credential["status"] == "revoked" for credential in public_credentials
                    ),
                }
                print(
                    json.dumps(
                        {
                            "principal_id": principal.id,
                            "principal_enabled": principal.disabled_at is None,
                            "credentials": public_credentials,
                            "counts": counts,
                        },
                        sort_keys=True,
                    )
                )
                return 0
    except (IdentityError, ValueError) as exc:
        print(f"identity command failed: {exc}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable command")


def _issued_response(issued: IssuedApiCredential) -> dict[str, object]:
    return {
        "credential_id": issued.id,
        "token_prefix": issued.token_prefix,
        "scopes": issued.scopes,
        "expires_at": issued.expires_at.isoformat(),
        "token": issued.token,
    }


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass("Password: ")


if __name__ == "__main__":
    raise SystemExit(cli_main())
