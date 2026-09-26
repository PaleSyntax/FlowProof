"""Fail-closed static, database, and migration entry points for production core."""

from __future__ import annotations

import argparse
import json

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from flowproof.config import Settings
from flowproof.db import make_engine
from flowproof.health import migration_paths
from flowproof.policy import load_policy

MIGRATION_LOCK_ID = 4_158_222_021


def _alembic_config(database_url: str) -> Config:
    ini, migrations = migration_paths()
    config = Config(str(ini))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def static_preflight(settings: Settings) -> None:
    """Validate FlowProof-owned configuration without requiring a running database."""

    settings.validate_production_security()
    if settings.database_url.startswith("sqlite"):
        raise RuntimeError("production deployment requires PostgreSQL")
    schema_path = settings.policy_path.with_name("policy.schema.json")
    load_policy(settings.policy_path, schema_path)
    print(json.dumps({"status": "static_preflight_ok", "policy": settings.policy_path.name}))


def _database_state(settings: Settings) -> tuple[bool, str | None, int]:
    """Return whether FlowProof is initialized, its revision, and owned table count."""

    engine = make_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            revision_table = bool(
                connection.scalar(text("SELECT to_regclass('public.alembic_version') IS NOT NULL"))
            )
            revision = (
                connection.scalar(text("SELECT version_num FROM alembic_version"))
                if revision_table
                else None
            )
            flowproof_tables = int(
                connection.scalar(
                    text(
                        """
                        SELECT count(*)
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                          AND table_name IN ('principals', 'policies', 'business_events')
                        """
                    )
                )
                or 0
            )
    finally:
        engine.dispose()
    return revision_table or flowproof_tables > 0, revision, flowproof_tables


def database_preflight(settings: Settings, mode: str) -> None:
    """Fail closed when install/upgrade mode disagrees with durable database state."""

    static_preflight(settings)
    initialized, revision, flowproof_tables = _database_state(settings)
    if mode == "install" and initialized:
        raise RuntimeError("install mode requires a fresh, uninitialized FlowProof database")
    if mode == "upgrade" and not initialized:
        raise RuntimeError("upgrade mode requires an existing initialized FlowProof database")
    if mode == "upgrade" and not revision:
        raise RuntimeError("upgrade mode requires an Alembic revision before migration")
    print(
        json.dumps(
            {
                "status": "database_preflight_ok",
                "mode": mode,
                "initialized": initialized,
                "current_revision": revision,
                "flowproof_table_count": flowproof_tables,
            }
        )
    )


def migrate(settings: Settings) -> None:
    static_preflight(settings)
    engine = make_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            connection.execute(
                text("SELECT pg_advisory_lock(:lock_id)"), {"lock_id": MIGRATION_LOCK_ID}
            )
            try:
                command.upgrade(_alembic_config(settings.database_url), "head")
            finally:
                connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": MIGRATION_LOCK_ID}
                )
    finally:
        engine.dispose()
    head = ScriptDirectory.from_config(_alembic_config(settings.database_url)).get_current_head()
    print(json.dumps({"status": "migration_ok", "head": head}))


def main() -> int:
    parser = argparse.ArgumentParser(description="FlowProof production deployment helper")
    parser.add_argument("command", choices=("static-preflight", "database-preflight", "migrate"))
    parser.add_argument("--mode", choices=("install", "upgrade"))
    args = parser.parse_args()
    settings = Settings.from_environment()
    if args.command == "static-preflight":
        static_preflight(settings)
    elif args.command == "database-preflight":
        if args.mode is None:
            parser.error("database-preflight requires --mode")
        database_preflight(settings, args.mode)
    else:
        migrate(settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
