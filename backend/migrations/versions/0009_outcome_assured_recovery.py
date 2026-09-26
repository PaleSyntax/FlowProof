"""Add outcome-assured recovery attempts, decisions, guardrails, and review evidence.

Revision ID: 0009_outcome_assured_recovery
Revises: 0008_recovery_approval_context
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_outcome_assured_recovery"
down_revision = "0008_recovery_approval_context"
branch_labels = None
depends_on = None

JSON_VALUE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column(
        "recovery_plans",
        sa.Column("provider_id", sa.String(length=64), nullable=False, server_default="legacy"),
    )
    op.add_column(
        "recovery_plans",
        sa.Column(
            "provider_environment", sa.String(length=32), nullable=False, server_default="unknown"
        ),
    )
    op.add_column(
        "recovery_plans",
        sa.Column("adapter_version", sa.String(length=64), nullable=False, server_default="legacy"),
    )
    op.add_column(
        "recovery_plans",
        sa.Column(
            "provider_contract_digest", sa.String(length=64), nullable=False, server_default=""
        ),
    )
    op.add_column(
        "recovery_plans",
        sa.Column(
            "provider_contract_snapshot",
            JSON_VALUE,
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.add_column(
        "recovery_plans",
        sa.Column("guardrails", JSON_VALUE, nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "recovery_plans",
        sa.Column("approval_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "recovery_plans",
        sa.Column("lock_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_recovery_plans_provider_id", "recovery_plans", ["provider_id"])
    op.create_index(
        "ix_recovery_plans_approval_expires_at", "recovery_plans", ["approval_expires_at"]
    )

    # Old unexecuted consent lacks contract, expiry and guardrail binding. It cannot execute.
    op.execute(
        sa.text(
            "UPDATE recovery_plans SET status = 'proposed', approved_plan_hash = NULL, "
            "approved_by = NULL, approved_at = NULL, approval_expires_at = NULL, "
            "approval_context = '{}' WHERE status = 'approved'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE incidents SET status = 'recovery_proposed' WHERE status = 'recovery_approved' "
            "AND id IN (SELECT incident_id FROM recovery_plans WHERE status = 'proposed')"
        )
    )
    op.execute(
        sa.text("UPDATE recovery_plans SET status = 'needs_attention' WHERE status = 'executing'")
    )
    op.execute(
        sa.text(
            "UPDATE incidents SET status = 'needs_attention' WHERE id IN "
            "(SELECT incident_id FROM recovery_plans WHERE status = 'needs_attention') "
            "AND status != 'resolved'"
        )
    )

    op.create_table(
        "recovery_decisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("recovery_plan_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("decision_kind", sa.String(length=16), nullable=False, server_default="human"),
        sa.Column("actor_principal_id", sa.String(length=36), nullable=True),
        sa.Column("actor_display_name", sa.String(length=128), nullable=False),
        sa.Column("authorization_scope", sa.String(length=64), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("provider_contract_digest", sa.String(length=64), nullable=False),
        sa.Column("incident_state_observed", sa.String(length=32), nullable=False),
        sa.Column("plan_state_observed", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("note_digest", sa.String(length=64), nullable=True),
        sa.Column("previous_plan_state", sa.String(length=32), nullable=False),
        sa.Column("resulting_plan_state", sa.String(length=32), nullable=False),
        sa.Column("previous_incident_state", sa.String(length=32), nullable=False),
        sa.Column("resulting_incident_state", sa.String(length=32), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approval_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["recovery_plan_id"], ["recovery_plans.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["actor_principal_id"], ["principals.id"]),
        sa.UniqueConstraint(
            "recovery_plan_id", "request_id", name="uq_recovery_decision_plan_request"
        ),
    )
    op.create_index(
        "ix_recovery_decisions_recovery_plan_id", "recovery_decisions", ["recovery_plan_id"]
    )
    op.create_index("ix_recovery_decisions_incident_id", "recovery_decisions", ["incident_id"])
    op.create_index(
        "ix_recovery_decisions_actor_principal_id",
        "recovery_decisions",
        ["actor_principal_id"],
    )
    op.create_index("ix_recovery_decisions_action", "recovery_decisions", ["action"])
    op.create_index("ix_recovery_decisions_decided_at", "recovery_decisions", ["decided_at"])
    op.create_index(
        "ix_recovery_decisions_plan_time",
        "recovery_decisions",
        ["recovery_plan_id", "decided_at"],
    )

    op.create_table(
        "recovery_attempts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("recovery_plan_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("approval_decision_id", sa.String(length=36), nullable=False),
        sa.Column("attempt_ordinal", sa.Integer(), nullable=False),
        sa.Column("execution_idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("provider_contract_digest", sa.String(length=64), nullable=False),
        sa.Column("provider_id", sa.String(length=64), nullable=False),
        sa.Column("provider_environment", sa.String(length=32), nullable=False),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("precondition_observation_digest", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=48), nullable=False),
        sa.Column("outcome_classification", sa.String(length=64), nullable=True),
        sa.Column("provider_operation_reference", sa.String(length=255), nullable=True),
        sa.Column("retry_after_seconds", sa.Integer(), nullable=True),
        sa.Column("semantic_attempt_count", sa.Integer(), nullable=False),
        sa.Column("transport_invocation_count", sa.Integer(), nullable=False),
        sa.Column("retry_permitted", sa.Boolean(), nullable=False),
        sa.Column("retry_reason", sa.String(length=128), nullable=True),
        sa.Column("safe_result", JSON_VALUE, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lock_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["recovery_plan_id"], ["recovery_plans.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["approval_decision_id"], ["recovery_decisions.id"]),
        sa.UniqueConstraint("execution_idempotency_key"),
        sa.UniqueConstraint(
            "recovery_plan_id", "attempt_ordinal", name="uq_recovery_attempt_plan_ordinal"
        ),
    )
    op.create_index(
        "ix_recovery_attempts_recovery_plan_id", "recovery_attempts", ["recovery_plan_id"]
    )
    op.create_index("ix_recovery_attempts_incident_id", "recovery_attempts", ["incident_id"])
    op.create_index(
        "ix_recovery_attempts_approval_decision_id",
        "recovery_attempts",
        ["approval_decision_id"],
    )
    op.create_index("ix_recovery_attempts_provider_id", "recovery_attempts", ["provider_id"])
    op.create_index("ix_recovery_attempts_state", "recovery_attempts", ["state"])
    op.create_index("ix_recovery_attempts_created_at", "recovery_attempts", ["created_at"])
    op.create_index(
        "ix_recovery_attempts_plan_state",
        "recovery_attempts",
        ["recovery_plan_id", "state"],
    )

    op.create_table(
        "recovery_transport_invocations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("recovery_attempt_id", sa.String(length=36), nullable=False),
        sa.Column("recovery_plan_id", sa.String(length=36), nullable=False),
        sa.Column("approval_decision_id", sa.String(length=36), nullable=False),
        sa.Column("invocation_ordinal", sa.Integer(), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["recovery_attempt_id"], ["recovery_attempts.id"]),
        sa.ForeignKeyConstraint(["recovery_plan_id"], ["recovery_plans.id"]),
        sa.ForeignKeyConstraint(["approval_decision_id"], ["recovery_decisions.id"]),
        sa.UniqueConstraint(
            "recovery_attempt_id",
            "invocation_ordinal",
            name="uq_recovery_transport_invocation_ordinal",
        ),
        sa.UniqueConstraint(
            "recovery_attempt_id",
            "approval_decision_id",
            name="uq_recovery_transport_invocation_approval",
        ),
    )
    for column in (
        "recovery_attempt_id",
        "recovery_plan_id",
        "approval_decision_id",
        "reserved_at",
    ):
        op.create_index(
            f"ix_recovery_transport_invocations_{column}",
            "recovery_transport_invocations",
            [column],
        )

    op.create_table(
        "operator_reviews",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("recovery_plan_id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False, unique=True),
        sa.Column("actor_principal_id", sa.String(length=36), nullable=False),
        sa.Column("actor_display_name", sa.String(length=128), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("capsule_digest", sa.String(length=64), nullable=True),
        sa.Column("evidence_understood", sa.Boolean(), nullable=False),
        sa.Column("authoritative_source_understood", sa.Boolean(), nullable=False),
        sa.Column("blast_radius_understood", sa.Boolean(), nullable=False),
        sa.Column("proposed_action_understood", sa.Boolean(), nullable=False),
        sa.Column("reject_path_available", sa.Boolean(), nullable=False),
        sa.Column("revoke_path_available", sa.Boolean(), nullable=False),
        sa.Column("reconciliation_path_understood", sa.Boolean(), nullable=False),
        sa.Column("final_decision", sa.String(length=32), nullable=False),
        sa.Column("note_digest", sa.String(length=64), nullable=True),
        sa.Column("verdict", sa.String(length=64), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["recovery_plan_id"], ["recovery_plans.id"]),
        sa.ForeignKeyConstraint(["actor_principal_id"], ["principals.id"]),
    )
    op.create_index("ix_operator_reviews_incident_id", "operator_reviews", ["incident_id"])
    op.create_index(
        "ix_operator_reviews_recovery_plan_id", "operator_reviews", ["recovery_plan_id"]
    )
    op.create_index(
        "ix_operator_reviews_actor_principal_id", "operator_reviews", ["actor_principal_id"]
    )
    op.create_index("ix_operator_reviews_reviewed_at", "operator_reviews", ["reviewed_at"])


def downgrade() -> None:
    op.drop_index("ix_operator_reviews_reviewed_at", table_name="operator_reviews")
    op.drop_index("ix_operator_reviews_actor_principal_id", table_name="operator_reviews")
    op.drop_index("ix_operator_reviews_recovery_plan_id", table_name="operator_reviews")
    op.drop_index("ix_operator_reviews_incident_id", table_name="operator_reviews")
    op.drop_table("operator_reviews")
    for column in (
        "reserved_at",
        "approval_decision_id",
        "recovery_plan_id",
        "recovery_attempt_id",
    ):
        op.drop_index(
            f"ix_recovery_transport_invocations_{column}",
            table_name="recovery_transport_invocations",
        )
    op.drop_table("recovery_transport_invocations")
    op.drop_index("ix_recovery_attempts_plan_state", table_name="recovery_attempts")
    op.drop_index("ix_recovery_attempts_created_at", table_name="recovery_attempts")
    op.drop_index("ix_recovery_attempts_state", table_name="recovery_attempts")
    op.drop_index("ix_recovery_attempts_provider_id", table_name="recovery_attempts")
    op.drop_index("ix_recovery_attempts_incident_id", table_name="recovery_attempts")
    op.drop_index(
        "ix_recovery_attempts_approval_decision_id", table_name="recovery_attempts"
    )
    op.drop_index("ix_recovery_attempts_recovery_plan_id", table_name="recovery_attempts")
    op.drop_table("recovery_attempts")
    op.drop_index("ix_recovery_decisions_plan_time", table_name="recovery_decisions")
    op.drop_index("ix_recovery_decisions_decided_at", table_name="recovery_decisions")
    op.drop_index("ix_recovery_decisions_action", table_name="recovery_decisions")
    op.drop_index("ix_recovery_decisions_actor_principal_id", table_name="recovery_decisions")
    op.drop_index("ix_recovery_decisions_incident_id", table_name="recovery_decisions")
    op.drop_index("ix_recovery_decisions_recovery_plan_id", table_name="recovery_decisions")
    op.drop_table("recovery_decisions")
    op.drop_index("ix_recovery_plans_approval_expires_at", table_name="recovery_plans")
    op.drop_index("ix_recovery_plans_provider_id", table_name="recovery_plans")
    for column in (
        "lock_version",
        "approval_expires_at",
        "guardrails",
        "provider_contract_snapshot",
        "provider_contract_digest",
        "adapter_version",
        "provider_environment",
        "provider_id",
    ):
        op.drop_column("recovery_plans", column)
