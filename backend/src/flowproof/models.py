from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JsonValue = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class Principal(Base):
    __tablename__ = "principals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    allowed_scopes: Mapped[list[str]] = mapped_column(JsonValue, default=list)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_successful_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class HumanCredential(Base):
    __tablename__ = "human_credentials"

    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ApiCredential(Base):
    __tablename__ = "api_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    token_prefix: Mapped[str] = mapped_column(String(16), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[list[str]] = mapped_column(JsonValue, default=list)
    credential_type: Mapped[str] = mapped_column(String(32), default="api")
    details: Mapped[dict[str, Any]] = mapped_column("metadata", JsonValue, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    actor_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("principals.id"), nullable=True, index=True
    )
    actor_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("principals.id"), nullable=True, index=True
    )
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    credential_id: Mapped[str | None] = mapped_column(
        ForeignKey("api_credentials.id"), nullable=True, index=True
    )
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    details: Mapped[dict[str, Any]] = mapped_column("metadata", JsonValue, default=dict)


class CorrelationBinding(Base):
    """Atomic durable binding from one correlation ID to one business entity."""

    __tablename__ = "correlation_bindings"

    correlation_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_correlation_bindings_entity", "entity_type", "entity_id"),
    )


class BusinessEvent(Base):
    __tablename__ = "business_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    correlation_id: Mapped[str] = mapped_column(String(255), index=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    source_system: Mapped[str] = mapped_column(String(64))
    workflow_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workflow_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    node_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)

    __table_args__ = (
        Index("ix_events_entity_timeline", "entity_type", "entity_id", "occurred_at"),
    )


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(default=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JsonValue)
    definition_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("name", "version", name="uq_policy_name_version"),)


class PolicyEvaluation(Base):
    __tablename__ = "policy_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(255), index=True)
    invariant_id: Mapped[str] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class DeadlineJob(Base):
    __tablename__ = "deadline_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(255), index=True)
    invariant_id: Mapped[str] = mapped_column(String(128))
    trigger_event_id: Mapped[str] = mapped_column(ForeignKey("business_events.id"), index=True)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    state: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "correlation_id",
            "invariant_id",
            "trigger_event_id",
            "due_at",
            name="uq_deadline_job_semantics",
        ),
        Index("ix_deadline_jobs_state_next_attempt", "state", "next_attempt_at"),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String(255), index=True)
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(255))
    policy_name: Mapped[str] = mapped_column(String(128))
    policy_version: Mapped[str] = mapped_column(String(64))
    invariant_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), index=True)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "correlation_id", "policy_version", "invariant_id", name="uq_incident_identity"
        ),
    )


class RecoveryPlan(Base):
    __tablename__ = "recovery_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), unique=True, index=True)
    action_type: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict[str, Any]] = mapped_column(JsonValue)
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="controlled")
    requires_approval: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(32), default="proposed", index=True)
    plan_hash: Mapped[str] = mapped_column(String(64))
    provider_id: Mapped[str] = mapped_column(String(64), default="mock-accounting", index=True)
    provider_environment: Mapped[str] = mapped_column(String(32), default="sandbox")
    adapter_version: Mapped[str] = mapped_column(String(64), default="legacy-test-fixture")
    provider_contract_digest: Mapped[str] = mapped_column(String(64), default="")
    provider_contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    guardrails: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    approved_plan_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approval_context: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    lock_version: Mapped[int] = mapped_column(default=1)

    __mapper_args__ = {"version_id_col": lock_version}


class RecoveryDecision(Base):
    """Append-only human or system decision genealogy."""

    __tablename__ = "recovery_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recovery_plan_id: Mapped[str] = mapped_column(ForeignKey("recovery_plans.id"), index=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    request_id: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(32), index=True)
    decision_kind: Mapped[str] = mapped_column(String(16), default="human")
    actor_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("principals.id"), nullable=True, index=True
    )
    actor_display_name: Mapped[str] = mapped_column(String(128))
    authorization_scope: Mapped[str] = mapped_column(String(64))
    plan_hash: Mapped[str] = mapped_column(String(64))
    provider_contract_digest: Mapped[str] = mapped_column(String(64))
    incident_state_observed: Mapped[str] = mapped_column(String(32))
    plan_state_observed: Mapped[str] = mapped_column(String(32))
    reason_code: Mapped[str] = mapped_column(String(64))
    note_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_plan_state: Mapped[str] = mapped_column(String(32))
    resulting_plan_state: Mapped[str] = mapped_column(String(32))
    previous_incident_state: Mapped[str] = mapped_column(String(32))
    resulting_incident_state: Mapped[str] = mapped_column(String(32))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    approval_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "recovery_plan_id", "request_id", name="uq_recovery_decision_plan_request"
        ),
        Index("ix_recovery_decisions_plan_time", "recovery_plan_id", "decided_at"),
    )


class RecoveryAttempt(Base):
    """Durable intent and ambiguity ledger for one semantic compensation."""

    __tablename__ = "recovery_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recovery_plan_id: Mapped[str] = mapped_column(ForeignKey("recovery_plans.id"), index=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    approval_decision_id: Mapped[str] = mapped_column(
        ForeignKey("recovery_decisions.id"), index=True
    )
    active_transport_invocation_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "recovery_transport_invocations.id",
            name="fk_recovery_attempts_active_transport_invocation",
            use_alter=True,
        ),
        nullable=True,
        index=True,
    )
    attempt_ordinal: Mapped[int] = mapped_column(default=1)
    execution_idempotency_key: Mapped[str] = mapped_column(String(255), unique=True)
    plan_hash: Mapped[str] = mapped_column(String(64))
    provider_contract_digest: Mapped[str] = mapped_column(String(64))
    provider_id: Mapped[str] = mapped_column(String(64), index=True)
    provider_environment: Mapped[str] = mapped_column(String(32))
    adapter_version: Mapped[str] = mapped_column(String(64))
    request_digest: Mapped[str] = mapped_column(String(64))
    precondition_observation_digest: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(48), index=True)
    outcome_classification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_operation_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    retry_after_seconds: Mapped[int | None] = mapped_column(nullable=True)
    semantic_attempt_count: Mapped[int] = mapped_column(default=1)
    transport_invocation_count: Mapped[int] = mapped_column(default=0)
    retry_permitted: Mapped[bool] = mapped_column(default=False)
    retry_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    safe_result: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lock_version: Mapped[int] = mapped_column(default=1)

    __mapper_args__ = {"version_id_col": lock_version}

    __table_args__ = (
        UniqueConstraint(
            "recovery_plan_id", "attempt_ordinal", name="uq_recovery_attempt_plan_ordinal"
        ),
        Index("ix_recovery_attempts_plan_state", "recovery_plan_id", "state"),
    )


class RecoveryTransportInvocation(Base):
    """Durable transport reservation and its fenced outcome authority."""

    __tablename__ = "recovery_transport_invocations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recovery_attempt_id: Mapped[str] = mapped_column(
        ForeignKey("recovery_attempts.id"), index=True
    )
    recovery_plan_id: Mapped[str] = mapped_column(ForeignKey("recovery_plans.id"), index=True)
    approval_decision_id: Mapped[str] = mapped_column(
        ForeignKey("recovery_decisions.id"), index=True
    )
    invocation_ordinal: Mapped[int]
    request_digest: Mapped[str] = mapped_column(String(64))
    reserved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    state: Mapped[str] = mapped_column(String(32), default="OUTCOME_UNRECORDED", index=True)
    dispatch_owner: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    dispatch_generation: Mapped[int] = mapped_column(
        nullable=False,
        default=1,
        server_default="1",
    )
    dispatch_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    dispatch_lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    abandoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    abandoned_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    abandonment_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reconciliation_owner: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    reconciliation_generation: Mapped[int] = mapped_column(default=0)
    reconciliation_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reconciliation_lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reconciliation_abandoned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    outcome_classification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    provider_operation_reference: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    retry_after_seconds: Mapped[int | None] = mapped_column(nullable=True)
    safe_outcome: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lock_version: Mapped[int] = mapped_column(default=1)

    __mapper_args__ = {"version_id_col": lock_version}

    __table_args__ = (
        UniqueConstraint(
            "recovery_attempt_id",
            "invocation_ordinal",
            name="uq_recovery_transport_invocation_ordinal",
        ),
        UniqueConstraint(
            "recovery_attempt_id",
            "approval_decision_id",
            name="uq_recovery_transport_invocation_approval",
        ),
        Index(
            "ix_recovery_transport_invocations_state_lease",
            "state",
            "dispatch_lease_expires_at",
        ),
        Index(
            "ix_recovery_transport_invocations_reconciliation_lease",
            "state",
            "reconciliation_lease_expires_at",
        ),
    )


class OperatorReview(Base):
    """Bounded contestability review; never a worker-performance record."""

    __tablename__ = "operator_reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    recovery_plan_id: Mapped[str] = mapped_column(ForeignKey("recovery_plans.id"), index=True)
    request_id: Mapped[str] = mapped_column(String(128), unique=True)
    actor_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    actor_display_name: Mapped[str] = mapped_column(String(128))
    plan_hash: Mapped[str] = mapped_column(String(64))
    capsule_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_understood: Mapped[bool]
    authoritative_source_understood: Mapped[bool]
    blast_radius_understood: Mapped[bool]
    proposed_action_understood: Mapped[bool]
    reject_path_available: Mapped[bool]
    revoke_path_available: Mapped[bool]
    reconciliation_path_understood: Mapped[bool]
    final_decision: Mapped[str] = mapped_column(String(32))
    note_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verdict: Mapped[str] = mapped_column(String(64))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AlertOutbox(Base):
    """A durable, deduplicated alert delivery record."""

    __tablename__ = "alert_outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    condition: Mapped[str] = mapped_column(String(64), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    severity: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
    state: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_alert_outbox_state_next_attempt", "state", "next_attempt_at"),)


class ServiceHeartbeat(Base):
    """Last durable heartbeat per supervised internal worker."""

    __tablename__ = "service_heartbeats"

    service: Mapped[str] = mapped_column(String(64), primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    details: Mapped[dict[str, Any]] = mapped_column("metadata", JsonValue, default=dict)


class OperationalAlertState(Base):
    """Durable condition state for transition-only operational alerts."""

    __tablename__ = "operational_alert_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    condition: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    active: Mapped[bool] = mapped_column(default=False, index=True)
    generation: Mapped[int] = mapped_column(default=0)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("condition", "subject", name="uq_operational_alert_condition_subject"),
    )


class ChaosRun(Base):
    __tablename__ = "chaos_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expected_invariants: Mapped[list[str]] = mapped_column(JsonValue, default=list)
    observed_incidents: Mapped[list[str]] = mapped_column(JsonValue, default=list)
    result: Mapped[dict[str, Any]] = mapped_column(JsonValue, default=dict)
