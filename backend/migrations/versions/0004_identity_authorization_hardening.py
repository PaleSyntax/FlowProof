"""Harden identity lifecycle, generic audit targets, and session bounds.

Revision ID: 0004_identity_authorization_hardening
Revises: 0003_identity_authorization
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_identity_authorization_hardening"
down_revision = "0003_identity_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Alembic's default version table is VARCHAR(32), while this deliberately
    # descriptive revision ID is longer. PostgreSQL enforces the length;
    # SQLite does not, so avoid an unnecessary table rebuild there.
    if op.get_bind().dialect.name == "postgresql":
        op.alter_column(
            "alembic_version",
            "version_num",
            existing_type=sa.String(length=32),
            type_=sa.String(length=64),
        )
    with op.batch_alter_table("principals") as batch:
        batch.add_column(sa.Column("allowed_scopes", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("last_successful_login_at", sa.DateTime(timezone=True)))
    op.execute("UPDATE principals SET allowed_scopes = '[]' WHERE allowed_scopes IS NULL")
    with op.batch_alter_table("principals") as batch:
        batch.alter_column("allowed_scopes", nullable=False)

    with op.batch_alter_table("auth_sessions") as batch:
        batch.add_column(sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        "UPDATE auth_sessions SET idle_expires_at = expires_at, absolute_expires_at = expires_at "
        "WHERE idle_expires_at IS NULL OR absolute_expires_at IS NULL"
    )
    with op.batch_alter_table("auth_sessions") as batch:
        batch.alter_column("idle_expires_at", nullable=False)
        batch.alter_column("absolute_expires_at", nullable=False)
        batch.create_index("ix_auth_sessions_idle_expires_at", ["idle_expires_at"])
        batch.create_index("ix_auth_sessions_absolute_expires_at", ["absolute_expires_at"])

    with op.batch_alter_table("security_audit_events") as batch:
        batch.add_column(sa.Column("actor_kind", sa.String(length=16)))
        batch.add_column(sa.Column("target_type", sa.String(length=64)))
        batch.add_column(sa.Column("target_id", sa.String(length=255)))
        batch.add_column(sa.Column("request_id", sa.String(length=128)))
        batch.add_column(sa.Column("correlation_id", sa.String(length=255)))
        batch.create_index("ix_security_audit_events_target_type", ["target_type"])
        batch.create_index("ix_security_audit_events_target_id", ["target_id"])
        batch.create_index("ix_security_audit_events_request_id", ["request_id"])
        batch.create_index("ix_security_audit_events_correlation_id", ["correlation_id"])
    op.execute(
        "UPDATE security_audit_events SET target_type = 'principal', "
        "target_id = target_principal_id WHERE target_principal_id IS NOT NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("security_audit_events") as batch:
        batch.drop_index("ix_security_audit_events_correlation_id")
        batch.drop_index("ix_security_audit_events_request_id")
        batch.drop_index("ix_security_audit_events_target_id")
        batch.drop_index("ix_security_audit_events_target_type")
        batch.drop_column("correlation_id")
        batch.drop_column("request_id")
        batch.drop_column("target_id")
        batch.drop_column("target_type")
        batch.drop_column("actor_kind")
    with op.batch_alter_table("auth_sessions") as batch:
        batch.drop_index("ix_auth_sessions_absolute_expires_at")
        batch.drop_index("ix_auth_sessions_idle_expires_at")
        batch.drop_column("absolute_expires_at")
        batch.drop_column("idle_expires_at")
    with op.batch_alter_table("principals") as batch:
        batch.drop_column("last_successful_login_at")
        batch.drop_column("allowed_scopes")
