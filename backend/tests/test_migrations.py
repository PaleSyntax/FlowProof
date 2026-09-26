from __future__ import annotations

import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
MIGRATION_HEAD = "0010_release_groundwork_fencing"


def alembic_config(database_url: str) -> Config:
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(BACKEND / "migrations"),
    )
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _insert_event(
    connection: object,
    *,
    event_id: str,
    key: str,
    correlation_id: str,
    entity_id: str,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO business_events (
                id,
                idempotency_key,
                correlation_id,
                entity_type,
                entity_id,
                event_type,
                occurred_at,
                source_system,
                payload,
                content_hash
            ) VALUES (
                :id,
                :key,
                :correlation_id,
                'invoice',
                :entity_id,
                'invoice.validated',
                :occurred_at,
                'migration-test',
                :payload,
                :content_hash
            )
            """
        ),
        {
            "id": event_id,
            "key": key,
            "correlation_id": correlation_id,
            "entity_id": entity_id,
            "occurred_at": "2026-08-04T00:00:00+00:00",
            "payload": json.dumps(
                {"amount": 10.0, "currency": "RUB"}
            ),
            "content_hash": "a" * 64,
        },
    )


def _insert_draft_0009_recovery_row(
    connection: object,
    table_name: str,
) -> None:
    if table_name == "recovery_attempts":
        connection.execute(
            text(
                """
                INSERT INTO recovery_attempts (
                    id,
                    recovery_plan_id,
                    incident_id,
                    approval_decision_id,
                    attempt_ordinal,
                    execution_idempotency_key,
                    plan_hash,
                    provider_contract_digest,
                    provider_id,
                    provider_environment,
                    adapter_version,
                    request_digest,
                    precondition_observation_digest,
                    state,
                    semantic_attempt_count,
                    transport_invocation_count,
                    retry_permitted,
                    safe_result,
                    created_at,
                    updated_at
                ) VALUES (
                    'draft-attempt',
                    'draft-plan',
                    'draft-incident',
                    'draft-decision',
                    1,
                    'draft-idempotency-key',
                    :digest,
                    :digest,
                    'mock-accounting',
                    'sandbox',
                    'draft-0009',
                    :digest,
                    :digest,
                    'PREPARED',
                    1,
                    0,
                    0,
                    :empty_json,
                    :created_at,
                    :created_at
                )
                """
            ),
            {
                "created_at": "2026-08-04T00:00:00+00:00",
                "digest": "d" * 64,
                "empty_json": json.dumps({}),
            },
        )
        return
    connection.execute(
        text(
            """
            INSERT INTO recovery_transport_invocations (
                id,
                recovery_attempt_id,
                recovery_plan_id,
                approval_decision_id,
                invocation_ordinal,
                request_digest,
                reserved_at
            ) VALUES (
                'draft-invocation',
                'draft-attempt',
                'draft-plan',
                'draft-decision',
                1,
                :digest,
                :reserved_at
            )
            """
        ),
        {
            "digest": "d" * 64,
            "reserved_at": "2026-08-04T00:00:00+00:00",
        },
    )


def test_fresh_upgrade_reaches_0010_and_exposes_full_fencing_schema(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'fresh-0010.sqlite3'}"
    config = alembic_config(database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    inspector = inspect(engine)

    assert "correlation_bindings" in inspector.get_table_names()
    transport_columns = {
        column["name"]: column
        for column in inspector.get_columns(
            "recovery_transport_invocations"
        )
    }
    assert {
        "active_transport_invocation_id",
        "lock_version",
    } <= {
        column["name"]
        for column in inspector.get_columns("recovery_attempts")
    }
    assert {
        "state",
        "dispatch_owner",
        "dispatch_generation",
        "dispatch_started_at",
        "dispatch_lease_expires_at",
        "abandoned_at",
        "abandoned_by",
        "abandonment_reason",
        "reconciliation_owner",
        "reconciliation_generation",
        "reconciliation_started_at",
        "reconciliation_lease_expires_at",
        "reconciliation_abandoned_at",
        "outcome_classification",
        "outcome_observed_at",
        "provider_operation_reference",
        "retry_after_seconds",
        "safe_outcome",
        "completed_at",
        "lock_version",
    } <= set(transport_columns)
    dispatch_generation = transport_columns[
        "dispatch_generation"
    ]
    assert dispatch_generation["nullable"] is False
    assert str(dispatch_generation["default"]).strip(
        "'\"()"
    ) == "1"
    attempt_indexes = {
        index["name"]
        for index in inspector.get_indexes("recovery_attempts")
    }
    reservation_indexes = {
        index["name"]
        for index in inspector.get_indexes(
            "recovery_transport_invocations"
        )
    }
    assert (
        "ix_recovery_attempts_active_transport_invocation_id"
        in attempt_indexes
    )
    assert {
        "ix_recovery_transport_invocations_state_lease",
        "ix_recovery_transport_invocations_reconciliation_lease",
        "ix_recovery_transport_invocations_dispatch_owner",
        "ix_recovery_transport_invocations_reconciliation_owner",
    } <= reservation_indexes
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            == MIGRATION_HEAD
        )


def test_upgrade_0010_with_empty_recovery_tables_backfills_correlation_subject(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'backfill-0010.sqlite3'}"
    config = alembic_config(database_url)
    command.upgrade(config, "0009_outcome_assured_recovery")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        _insert_event(
            connection,
            event_id="event-backfill-0010",
            key="event-backfill-0010",
            correlation_id="correlation-backfill-0010",
            entity_id="INV-BACKFILL-0010",
        )

    command.upgrade(config, "head")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT correlation_id, entity_type, entity_id
                FROM correlation_bindings
                WHERE correlation_id = 'correlation-backfill-0010'
                """
            )
        ).mappings().one()
        assert dict(row) == {
            "correlation_id": "correlation-backfill-0010",
            "entity_type": "invoice",
            "entity_id": "INV-BACKFILL-0010",
        }
        assert (
            connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            == MIGRATION_HEAD
        )


@pytest.mark.parametrize(
    "table_name",
    [
        "recovery_attempts",
        "recovery_transport_invocations",
    ],
)
def test_upgrade_0010_rejects_populated_draft_0009_recovery_tables(
    tmp_path: Path,
    table_name: str,
) -> None:
    database_url = f"sqlite:///{tmp_path / f'populated-{table_name}.sqlite3'}"
    config = alembic_config(database_url)
    command.upgrade(config, "0009_outcome_assured_recovery")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        _insert_draft_0009_recovery_row(
            connection,
            table_name,
        )

    with pytest.raises(
        RuntimeError,
        match=(
            "draft-0009 runtime rows; manually remediate or "
            "recreate the local database"
        ),
    ):
        command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            == "0009_outcome_assured_recovery"
        )


def test_upgrade_0010_fails_closed_for_existing_mixed_entity_correlation(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'mixed-0010.sqlite3'}"
    config = alembic_config(database_url)
    command.upgrade(config, "0009_outcome_assured_recovery")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        _insert_event(
            connection,
            event_id="event-mixed-a",
            key="event-mixed-a",
            correlation_id="correlation-mixed-0010",
            entity_id="INV-MIXED-A",
        )
        _insert_event(
            connection,
            event_id="event-mixed-b",
            key="event-mixed-b",
            correlation_id="correlation-mixed-0010",
            entity_id="INV-MIXED-B",
        )

    with pytest.raises(
        RuntimeError,
        match="correlations name multiple entities",
    ):
        command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            == "0009_outcome_assured_recovery"
        )
