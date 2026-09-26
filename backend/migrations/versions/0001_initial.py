"""Create FlowProof's event, policy, incident, recovery, and chaos tables."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

JSON_VALUE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "business_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("source_system", sa.String(length=64), nullable=False),
        sa.Column("workflow_id", sa.String(length=255)),
        sa.Column("workflow_version", sa.String(length=255)),
        sa.Column("execution_id", sa.String(length=255)),
        sa.Column("node_name", sa.String(length=255)),
        sa.Column("payload", JSON_VALUE, nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_business_events_idempotency_key", "business_events", ["idempotency_key"])
    op.create_index("ix_business_events_correlation_id", "business_events", ["correlation_id"])
    op.create_index("ix_business_events_entity_type", "business_events", ["entity_type"])
    op.create_index("ix_business_events_entity_id", "business_events", ["entity_id"])
    op.create_index("ix_business_events_event_type", "business_events", ["event_type"])
    op.create_index("ix_business_events_occurred_at", "business_events", ["occurred_at"])
    op.create_index("ix_events_entity_timeline", "business_events", ["entity_type", "entity_id", "occurred_at"])

    op.create_table(
        "policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("definition", JSON_VALUE, nullable=False),
        sa.Column("definition_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("name", "version", name="uq_policy_name_version"),
    )

    op.create_table(
        "policy_evaluations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("policy_id", sa.String(length=36), sa.ForeignKey("policies.id"), nullable=False),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("invariant_id", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("evidence", JSON_VALUE, nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_evaluations_policy_id", "policy_evaluations", ["policy_id"])
    op.create_index("ix_policy_evaluations_correlation_id", "policy_evaluations", ["correlation_id"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("policy_name", sa.String(length=128), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("invariant_id", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence", JSON_VALUE, nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("correlation_id", "policy_version", "invariant_id", name="uq_incident_identity"),
    )
    op.create_index("ix_incidents_correlation_id", "incidents", ["correlation_id"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_opened_at", "incidents", ["opened_at"])

    op.create_table(
        "recovery_plans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id"), nullable=False, unique=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("parameters", JSON_VALUE, nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("risk_level", sa.String(length=32), nullable=False, server_default="controlled"),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="proposed"),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("approved_plan_hash", sa.String(length=64)),
        sa.Column("approved_by", sa.String(length=128)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("result", JSON_VALUE, nullable=False),
    )
    op.create_index("ix_recovery_plans_incident_id", "recovery_plans", ["incident_id"])
    op.create_index("ix_recovery_plans_status", "recovery_plans", ["status"])

    op.create_table(
        "chaos_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=255)),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("expected_invariants", JSON_VALUE, nullable=False),
        sa.Column("observed_incidents", JSON_VALUE, nullable=False),
        sa.Column("result", JSON_VALUE, nullable=False),
    )
    op.create_index("ix_chaos_runs_scenario_id", "chaos_runs", ["scenario_id"])
    op.create_index("ix_chaos_runs_correlation_id", "chaos_runs", ["correlation_id"])


def downgrade() -> None:
    op.drop_table("chaos_runs")
    op.drop_table("recovery_plans")
    op.drop_table("incidents")
    op.drop_table("policy_evaluations")
    op.drop_table("policies")
    op.drop_table("business_events")
