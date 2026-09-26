from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
ENTITY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system: str = Field(min_length=1, max_length=64)
    workflow_id: str | None = Field(default=None, max_length=255)
    workflow_version: str | None = Field(default=None, max_length=255)
    execution_id: str | None = Field(default=None, max_length=255)
    node_name: str | None = Field(default=None, max_length=255)


class BusinessEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=255)
    entity_type: str = Field(pattern=ENTITY_PATTERN.pattern)
    entity_id: str = Field(min_length=1, max_length=255)
    event_type: str = Field(pattern=EVENT_PATTERN.pattern)
    occurred_at: datetime
    source: SourceIn
    payload: dict[str, Any] = Field(default_factory=dict, max_length=64)

    @field_validator("occurred_at")
    @classmethod
    def require_utc_aware_and_reasonable(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        normalized = value.astimezone(UTC)
        if normalized > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("occurred_at is too far in the future")
        return normalized

    @model_validator(mode="after")
    def ensure_payload_is_json(self) -> BusinessEventIn:
        try:
            json.dumps(self.payload, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("payload must be JSON serializable") from exc
        return self


class EventReceipt(BaseModel):
    id: str
    duplicate: bool
    content_hash: str


class ApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_status: str = Field(pattern=r"^recovery_proposed$")
    reason_code: str = Field(default="approved_by_operator", pattern=r"^[a-z][a-z0-9_]{0,63}$")
    note: str | None = Field(default=None, min_length=1, max_length=500)


class RecoveryDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_status: str = Field(pattern=r"^(recovery_proposed|recovery_approved)$")
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    note: str | None = Field(default=None, min_length=1, max_length=500)


class ReconcileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class OperatorReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    capsule_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence_understood: bool
    authoritative_source_understood: bool
    blast_radius_understood: bool
    proposed_action_understood: bool
    reject_path_available: bool
    revoke_path_available: bool
    reconciliation_path_understood: bool
    final_decision: str = Field(pattern=r"^(approve|reject|revoke_approval|observe_only)$")
    note: str | None = Field(default=None, min_length=1, max_length=500)


class ChaosModeIn(BaseModel):
    mode: str = Field(
        pattern=r"^(normal|false_200|timeout|delayed_write|amount_mismatch|partial_success)$"
    )
    correlation_id: str | None = Field(default=None, max_length=255)


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class HumanPrincipalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=1024)
    role: str = Field(pattern=r"^(viewer|operator|admin)$")


class ServiceAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    scopes: set[str] = Field(min_length=1, max_length=9)


class PasswordChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=12, max_length=1024)


class CredentialRevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(min_length=36, max_length=36)


class CredentialIssueIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopes: set[str] = Field(min_length=1, max_length=9)
    expires_in_seconds: int | None = Field(default=None, ge=1, le=2_592_000)
    label: str | None = Field(default=None, min_length=1, max_length=128)


class CredentialRotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_in_seconds: int | None = Field(default=None, ge=1, le=2_592_000)


class RoleChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(pattern=r"^(viewer|operator|admin)$")
