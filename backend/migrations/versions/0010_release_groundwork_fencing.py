"""Add correlation identity and durable transport dispatch fencing.

Revision ID: 0010_release_groundwork_fencing
Revises: 0009_outcome_assured_recovery
"""

from __future__ import annotations

from collections import defaultdict

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010_release_groundwork_fencing"
down_revision = "0009_outcome_assured_recovery"
branch_labels = None
depends_on = None

JSON_VALUE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    _reject_populated_draft_0009_recovery_tables()
    op.create_table(
        "correlation_bindings",
        sa.Column("correlation_id", sa.String(length=255), primary_key=True),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_correlation_bindings_entity",
        "correlation_bindings",
        ["entity_type", "entity_id"],
    )
    _backfill_correlation_bindings()

    with op.batch_alter_table(
        "recovery_transport_invocations"
    ) as batch:
        batch.add_column(
            sa.Column(
                "state",
                sa.String(length=32),
                nullable=False,
                server_default="OUTCOME_UNRECORDED",
            )
        )
        batch.add_column(
            sa.Column(
                "dispatch_owner",
                sa.String(length=128),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "dispatch_generation",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch.add_column(
            sa.Column(
                "dispatch_started_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "dispatch_lease_expires_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "abandoned_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "abandoned_by",
                sa.String(length=128),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "abandonment_reason",
                sa.String(length=128),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "reconciliation_owner",
                sa.String(length=128),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "reconciliation_generation",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "reconciliation_started_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "reconciliation_lease_expires_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "reconciliation_abandoned_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "outcome_classification",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "outcome_observed_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "provider_operation_reference",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "retry_after_seconds",
                sa.Integer(),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "safe_outcome",
                JSON_VALUE,
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch.add_column(
            sa.Column(
                "completed_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "lock_version",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch.create_index(
            "ix_recovery_transport_invocations_state_lease",
            ["state", "dispatch_lease_expires_at"],
        )
        batch.create_index(
            "ix_recovery_transport_invocations_reconciliation_lease",
            ["state", "reconciliation_lease_expires_at"],
        )
        batch.create_index(
            "ix_recovery_transport_invocations_dispatch_owner",
            ["dispatch_owner"],
        )
        batch.create_index(
            "ix_recovery_transport_invocations_reconciliation_owner",
            ["reconciliation_owner"],
        )

    with op.batch_alter_table("recovery_attempts") as batch:
        batch.add_column(
            sa.Column(
                "active_transport_invocation_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch.create_foreign_key(
            "fk_recovery_attempts_active_transport_invocation",
            "recovery_transport_invocations",
            ["active_transport_invocation_id"],
            ["id"],
        )
        batch.create_index(
            "ix_recovery_attempts_active_transport_invocation_id",
            ["active_transport_invocation_id"],
        )


def _backfill_correlation_bindings() -> None:
    connection = op.get_bind()
    events = sa.table(
        "business_events",
        sa.column("correlation_id", sa.String(length=255)),
        sa.column("entity_type", sa.String(length=64)),
        sa.column("entity_id", sa.String(length=255)),
        sa.column(
            "ingested_at",
            sa.DateTime(timezone=True),
        ),
    )
    subjects: dict[str, set[tuple[str, str]]] = defaultdict(set)
    first_seen: dict[str, object] = {}
    rows = connection.execute(
        sa.select(
            events.c.correlation_id,
            events.c.entity_type,
            events.c.entity_id,
            events.c.ingested_at,
        )
    )
    for correlation_id, entity_type, entity_id, ingested_at in rows:
        key = str(correlation_id)
        subjects[key].add(
            (str(entity_type), str(entity_id))
        )
        current = first_seen.get(key)
        if (
            current is None
            or (
                ingested_at is not None
                and ingested_at < current
            )
        ):
            first_seen[key] = ingested_at

    mixed = sorted(
        correlation_id
        for correlation_id, values in subjects.items()
        if len(values) != 1
    )
    if mixed:
        raise RuntimeError(
            "cannot add atomic correlation binding while existing "
            "correlations name multiple entities: "
            + ", ".join(mixed[:5])
        )

    binding_table = sa.table(
        "correlation_bindings",
        sa.column("correlation_id", sa.String(length=255)),
        sa.column("entity_type", sa.String(length=64)),
        sa.column("entity_id", sa.String(length=255)),
        sa.column(
            "created_at",
            sa.DateTime(timezone=True),
        ),
    )
    bindings: list[dict[str, object]] = []
    for correlation_id, values in sorted(subjects.items()):
        entity_type, entity_id = next(iter(values))
        bindings.append(
            {
                "correlation_id": correlation_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "created_at": first_seen[correlation_id],
            }
        )
    if bindings:
        op.bulk_insert(binding_table, bindings)


def _reject_populated_draft_0009_recovery_tables() -> None:
    connection = op.get_bind()
    populated = []
    for table_name in (
        "recovery_attempts",
        "recovery_transport_invocations",
    ):
        table = sa.table(
            table_name,
            sa.column("id", sa.String(length=36)),
        )
        if connection.execute(
            sa.select(table.c.id).limit(1)
        ).first() is not None:
            populated.append(table_name)
    if populated:
        raise RuntimeError(
            "migration 0010 rejects draft-0009 runtime rows; "
            "manually remediate or recreate the local database"
        )


def downgrade() -> None:
    with op.batch_alter_table("recovery_attempts") as batch:
        batch.drop_index(
            "ix_recovery_attempts_active_transport_invocation_id"
        )
        batch.drop_constraint(
            "fk_recovery_attempts_active_transport_invocation",
            type_="foreignkey",
        )
        batch.drop_column("active_transport_invocation_id")

    with op.batch_alter_table(
        "recovery_transport_invocations"
    ) as batch:
        batch.drop_index(
            "ix_recovery_transport_invocations_reconciliation_owner"
        )
        batch.drop_index(
            "ix_recovery_transport_invocations_dispatch_owner"
        )
        batch.drop_index(
            "ix_recovery_transport_invocations_reconciliation_lease"
        )
        batch.drop_index(
            "ix_recovery_transport_invocations_state_lease"
        )
        for column in (
            "lock_version",
            "completed_at",
            "safe_outcome",
            "retry_after_seconds",
            "provider_operation_reference",
            "outcome_observed_at",
            "outcome_classification",
            "reconciliation_abandoned_at",
            "reconciliation_lease_expires_at",
            "reconciliation_started_at",
            "reconciliation_generation",
            "reconciliation_owner",
            "abandonment_reason",
            "abandoned_by",
            "abandoned_at",
            "dispatch_lease_expires_at",
            "dispatch_started_at",
            "dispatch_generation",
            "dispatch_owner",
            "state",
        ):
            batch.drop_column(column)

    op.drop_index(
        "ix_correlation_bindings_entity",
        table_name="correlation_bindings",
    )
    op.drop_table("correlation_bindings")
