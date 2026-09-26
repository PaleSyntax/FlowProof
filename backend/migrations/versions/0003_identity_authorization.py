"""Add persistent production identity and authorization state.

Revision ID: 0003_identity_authorization
Revises: 0002_deadline_jobs
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_identity_authorization"
down_revision = "0002_deadline_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("role", sa.String(length=16)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_principals_name", "principals", ["name"])
    op.create_index("ix_principals_kind", "principals", ["kind"])

    op.create_table(
        "human_credentials",
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), primary_key=True),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "api_credentials",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("credential_type", sa.String(length=32), nullable=False, server_default="api"),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_api_credentials_principal_id", "api_credentials", ["principal_id"])
    op.create_index("ix_api_credentials_token_prefix", "api_credentials", ["token_prefix"])

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("csrf_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_auth_sessions_principal_id", "auth_sessions", ["principal_id"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])

    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("actor_principal_id", sa.String(length=36), sa.ForeignKey("principals.id")),
        sa.Column("target_principal_id", sa.String(length=36), sa.ForeignKey("principals.id")),
        sa.Column("credential_id", sa.String(length=36), sa.ForeignKey("api_credentials.id")),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_security_audit_events_occurred_at", "security_audit_events", ["occurred_at"])
    op.create_index(
        "ix_security_audit_events_action", "security_audit_events", ["action"]
    )
    op.create_index(
        "ix_security_audit_events_actor_principal_id", "security_audit_events", ["actor_principal_id"]
    )
    op.create_index(
        "ix_security_audit_events_target_principal_id",
        "security_audit_events",
        ["target_principal_id"],
    )
    op.create_index(
        "ix_security_audit_events_credential_id", "security_audit_events", ["credential_id"]
    )


def downgrade() -> None:
    op.drop_table("security_audit_events")
    op.drop_table("auth_sessions")
    op.drop_table("api_credentials")
    op.drop_table("human_credentials")
    op.drop_table("principals")
