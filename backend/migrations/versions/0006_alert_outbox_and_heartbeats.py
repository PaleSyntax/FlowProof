"""Add durable alert delivery state and internal worker heartbeats.

Revision ID: 0006_alert_outbox_and_heartbeats
Revises: 0005_identity_scope_envelope_backfill
"""

from alembic import op
import sqlalchemy as sa


revision = "0006_alert_outbox_and_heartbeats"
down_revision = "0005_identity_scope_envelope_backfill"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_outbox",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("condition", sa.String(length=64), nullable=False),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=128)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=255)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_alert_outbox_condition", "alert_outbox", ["condition"])
    op.create_index("ix_alert_outbox_dedupe_key", "alert_outbox", ["dedupe_key"])
    op.create_index("ix_alert_outbox_state", "alert_outbox", ["state"])
    op.create_index("ix_alert_outbox_next_attempt_at", "alert_outbox", ["next_attempt_at"])
    op.create_index(
        "ix_alert_outbox_state_next_attempt", "alert_outbox", ["state", "next_attempt_at"]
    )
    op.create_table(
        "service_heartbeats",
        sa.Column("service", sa.String(length=64), primary_key=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_service_heartbeats_observed_at", "service_heartbeats", ["observed_at"])


def downgrade() -> None:
    op.drop_table("service_heartbeats")
    op.drop_table("alert_outbox")
