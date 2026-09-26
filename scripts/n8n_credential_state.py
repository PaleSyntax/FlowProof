#!/usr/bin/env python3
"""Strict, secret-free durable state for n8n credential replacement.

The shell lifecycle entrypoint treats this file as an opaque data contract.  It
is deliberately not a shell fragment: duplicate keys, unknown keys and even a
single malformed field fail closed before an operator action can continue.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from uuid import UUID

STATE_FIELDS = frozenset(
    {
        "operation_id",
        "principal_id",
        "superseded_credential_id",
        "replacement_credential_id",
        "status",
        "created_at",
        "updated_at",
        "replacement_expires_at",
    }
)
FORBIDDEN_FIELD_FRAGMENTS = frozenset(
    {
        "token",
        "hash",
        "pepper",
        "password",
        "cookie",
        "csrf",
        "authorization",
        "database_url",
        "webhook_url",
    }
)
STATUSES = frozenset(
    {
        "planned",
        "replacement_issued",
        "token_staged",
        "imported_pending_verification",
        "verified_pending_activation",
        "verified_pending_revocation",
        "finalized",
        "aborted",
    }
)
TRANSITIONS = {
    "planned": {"replacement_issued", "aborted"},
    "replacement_issued": {"token_staged", "aborted"},
    "token_staged": {"imported_pending_verification", "aborted"},
    "imported_pending_verification": {"verified_pending_activation", "aborted"},
    "verified_pending_activation": {"verified_pending_revocation"},
    "verified_pending_revocation": {"finalized"},
    "finalized": set(),
    "aborted": set(),
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"n8n credential state rejected: {message}")


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            fail(f"duplicate key {key!r}")
        payload[key] = value
    return payload


def _timestamp(value: object, field: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str):
        fail(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{field} must be an RFC3339 timestamp")
    if parsed.tzinfo is None:
        fail(f"{field} must include a timezone")


def validate(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        fail("root value must be an object")
    keys = set(payload)
    forbidden = sorted(
        key
        for key in keys
        if any(fragment in key.lower() for fragment in FORBIDDEN_FIELD_FRAGMENTS)
        and key not in STATE_FIELDS
    )
    if forbidden:
        fail(f"forbidden field names: {', '.join(forbidden)}")
    if keys != STATE_FIELDS:
        missing = sorted(STATE_FIELDS - keys)
        unknown = sorted(keys - STATE_FIELDS)
        fail(f"schema mismatch missing={missing!r} unknown={unknown!r}")
    try:
        UUID(str(payload["operation_id"]))
    except (TypeError, ValueError):
        fail("operation_id must be a UUID")
    for field in ("principal_id",):
        if not isinstance(payload[field], str) or not payload[field]:
            fail(f"{field} must be a non-empty public identifier")
    for field in ("superseded_credential_id", "replacement_credential_id"):
        if payload[field] is not None and (
            not isinstance(payload[field], str) or not payload[field]
        ):
            fail(f"{field} must be null or a non-empty public identifier")
    if payload["status"] not in STATUSES:
        fail("status is not a recognized lifecycle state")
    _timestamp(payload["created_at"], "created_at")
    _timestamp(payload["updated_at"], "updated_at")
    _timestamp(
        payload["replacement_expires_at"], "replacement_expires_at", nullable=True
    )
    return payload


def load(path: Path) -> dict[str, Any]:
    try:
        if not path.is_file():
            fail("state file is missing")
        if os.name != "nt" and path.stat().st_mode & 0o077:
            fail("state file must be owner-only (0600)")
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object
        )
    except OSError as exc:
        fail(f"cannot read state file: {exc.strerror or exc}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc.msg}")
    return validate(payload)


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    validate(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def optional_identifier(value: str | None) -> str | None:
    return value if value else None


def create(args: argparse.Namespace) -> int:
    now = args.created_at or utc_now()
    payload = {
        "operation_id": args.operation_id,
        "principal_id": args.principal_id,
        "superseded_credential_id": optional_identifier(args.superseded_credential_id),
        "replacement_credential_id": optional_identifier(
            args.replacement_credential_id
        ),
        "status": args.status,
        "created_at": now,
        "updated_at": args.updated_at or now,
        "replacement_expires_at": optional_identifier(args.replacement_expires_at),
    }
    atomic_write(args.state_file, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0


def transition(args: argparse.Namespace) -> int:
    payload = load(args.state_file)
    target = args.status
    if target != payload["status"] and target not in TRANSITIONS[payload["status"]]:
        fail(f"invalid transition {payload['status']!r} -> {target!r}")
    if args.replacement_credential_id is not None:
        payload["replacement_credential_id"] = optional_identifier(
            args.replacement_credential_id
        )
    if args.replacement_expires_at is not None:
        payload["replacement_expires_at"] = optional_identifier(
            args.replacement_expires_at
        )
    payload["status"] = target
    payload["updated_at"] = utc_now()
    atomic_write(args.state_file, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--state-file", type=Path, required=True)
    create_parser.add_argument("--operation-id", required=True)
    create_parser.add_argument("--principal-id", required=True)
    create_parser.add_argument("--superseded-credential-id")
    create_parser.add_argument("--replacement-credential-id")
    create_parser.add_argument("--replacement-expires-at")
    create_parser.add_argument("--status", choices=sorted(STATUSES), required=True)
    create_parser.add_argument("--created-at")
    create_parser.add_argument("--updated-at")
    create_parser.set_defaults(handler=create)
    transition_parser = commands.add_parser("transition")
    transition_parser.add_argument("--state-file", type=Path, required=True)
    transition_parser.add_argument("--status", choices=sorted(STATUSES), required=True)
    transition_parser.add_argument("--replacement-credential-id")
    transition_parser.add_argument("--replacement-expires-at")
    transition_parser.set_defaults(handler=transition)
    read_parser = commands.add_parser("read")
    read_parser.add_argument("--state-file", type=Path, required=True)
    read_parser.set_defaults(
        handler=lambda args: (
            print(json.dumps(load(args.state_file), sort_keys=True)),
            0,
        )[1]
    )
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
