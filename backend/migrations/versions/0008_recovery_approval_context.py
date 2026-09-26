"""Bind recovery approvals to actor, scope, plan hash, and incident state.

Revision ID: 0008_recovery_approval_context
Revises: 0007_operational_alert_state
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0008_recovery_approval_context"
down_revision = "0007_operational_alert_state"
branch_labels = None
depends_on = None

JSON_VALUE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column(
        "recovery_plans",
        sa.Column(
            "approval_context",
            JSON_VALUE,
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )

    # A legacy unexecuted approval lacks the current incident-state and scope
    # binding introduced by this migration. Fail closed by requiring a fresh
    # human approval. An interrupted legacy execution cannot be resumed safely.
    op.execute(
        sa.text(
            "UPDATE recovery_plans "
            "SET status = 'proposed', approved_plan_hash = NULL, "
            "approved_by = NULL, approved_at = NULL "
            "WHERE status = 'approved'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE incidents SET status = 'recovery_proposed' "
            "WHERE status = 'recovery_approved' AND id IN ("
            "SELECT incident_id FROM recovery_plans WHERE status = 'proposed'"
            ")"
        )
    )
    op.execute(
        sa.text("UPDATE recovery_plans SET status = 'needs_attention' WHERE status = 'executing'")
    )
    op.execute(
        sa.text(
            "UPDATE incidents SET status = 'needs_attention' "
            "WHERE id IN (SELECT incident_id FROM recovery_plans WHERE status = 'needs_attention') "
            "AND status != 'resolved'"
        )
    )


def downgrade() -> None:
    op.drop_column("recovery_plans", "approval_context")
