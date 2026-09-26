"""Readiness is deliberately stricter than process liveness."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text

from flowproof.policy import load_policy

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from flowproof.config import Settings


def migration_paths() -> tuple[Path, Path]:
    package = Path(__file__).resolve()
    candidates = [
        Path(os.getenv("FLOWPROOF_RUNTIME_ROOT", "/app")),
        package.parents[2],
        package.parents[3],
    ]
    for root in candidates:
        if (root / "migrations").is_dir() and (root / "alembic.ini").is_file():
            return root / "alembic.ini", root / "migrations"
        if (root / "backend" / "migrations").is_dir():
            return root / "backend" / "alembic.ini", root / "backend" / "migrations"
    raise RuntimeError("FlowProof Alembic migration files are unavailable")


def migration_revision(factory: sessionmaker[Session]) -> tuple[str | None, str]:
    ini, migrations = migration_paths()
    config = Config(str(ini))
    config.set_main_option("script_location", str(migrations))
    head = ScriptDirectory.from_config(config).get_current_head()
    with factory() as session:
        connection = session.connection()
        current = MigrationContext.configure(connection).get_current_revision()
    return current, head


def readiness_checks(settings: Settings, factory: sessionmaker[Session]) -> dict[str, str]:
    checks: dict[str, str] = {"database": "failed", "migration": "unknown", "policy": "failed"}
    with factory() as session:
        session.execute(text("SELECT 1"))
    checks["database"] = "ok"
    current, head = migration_revision(factory)
    checks["migration"] = "ok" if current == head else "mismatch"
    schema_path = settings.policy_path.with_name("policy.schema.json")
    load_policy(settings.policy_path, schema_path)
    checks["policy"] = "ok"
    return checks
