"""Persist durable deadline evaluation jobs.

Revision ID: 0002_deadline_jobs
Revises: 0001_initial
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_deadline_jobs"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deadline_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("policy_id", sa.String(length=36), sa.ForeignKey("policies.id"), nullable=False),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("invariant_id", sa.String(length=128), nullable=False),
        sa.Column(
            "trigger_event_id", sa.String(length=36), sa.ForeignKey("business_events.id"), nullable=False
        ),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=128)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "policy_id",
            "correlation_id",
            "invariant_id",
            "trigger_event_id",
            "due_at",
            name="uq_deadline_job_semantics",
        ),
    )
    op.create_index("ix_deadline_jobs_policy_id", "deadline_jobs", ["policy_id"])
    op.create_index("ix_deadline_jobs_correlation_id", "deadline_jobs", ["correlation_id"])
    op.create_index("ix_deadline_jobs_trigger_event_id", "deadline_jobs", ["trigger_event_id"])
    op.create_index("ix_deadline_jobs_due_at", "deadline_jobs", ["due_at"])
    op.create_index("ix_deadline_jobs_state", "deadline_jobs", ["state"])
    op.create_index("ix_deadline_jobs_next_attempt_at", "deadline_jobs", ["next_attempt_at"])
    op.create_index(
        "ix_deadline_jobs_state_next_attempt", "deadline_jobs", ["state", "next_attempt_at"]
    )


def downgrade() -> None:
    op.drop_table("deadline_jobs")
