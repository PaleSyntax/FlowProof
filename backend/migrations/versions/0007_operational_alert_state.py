"""Add durable operational watcher condition generations.

Revision ID: 0007_operational_alert_state
Revises: 0006_alert_outbox_and_heartbeats
"""

from alembic import op
import sqlalchemy as sa


revision = "0007_operational_alert_state"
down_revision = "0006_alert_outbox_and_heartbeats"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operational_alert_states",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("condition", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("condition", "subject", name="uq_operational_alert_condition_subject"),
    )
    op.create_index("ix_operational_alert_states_condition", "operational_alert_states", ["condition"])
    op.create_index("ix_operational_alert_states_subject", "operational_alert_states", ["subject"])
    op.create_index("ix_operational_alert_states_active", "operational_alert_states", ["active"])


def downgrade() -> None:
    op.drop_table("operational_alert_states")
