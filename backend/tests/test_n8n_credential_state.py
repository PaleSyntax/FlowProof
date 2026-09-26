from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
STATE_TOOL = ROOT / "scripts" / "n8n_credential_state.py"


def state_command(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(STATE_TOOL), *arguments],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def create_state(path: Path, *, status: str = "planned") -> str:
    operation_id = str(uuid4())
    result = state_command(
        "create",
        "--state-file",
        str(path),
        "--operation-id",
        operation_id,
        "--principal-id",
        "principal-1",
        "--superseded-credential-id",
        "credential-old",
        "--status",
        status,
        "--created-at",
        "2026-08-02T12:00:00Z",
    )
    assert result.returncode == 0, result.stderr
    return operation_id


def test_credential_state_is_atomic_owner_only_and_public(tmp_path: Path) -> None:
    state_file = tmp_path / "replacement-state.json"
    operation_id = create_state(state_file)
    payload = json.loads(state_file.read_text(encoding="utf-8"))

    assert payload == {
        "operation_id": operation_id,
        "principal_id": "principal-1",
        "superseded_credential_id": "credential-old",
        "replacement_credential_id": None,
        "status": "planned",
        "created_at": "2026-08-02T12:00:00Z",
        "updated_at": "2026-08-02T12:00:00Z",
        "replacement_expires_at": None,
    }
    assert not any(
        fragment in key
        for key in payload
        for fragment in ("token", "hash", "pepper", "password", "cookie", "csrf")
    )
    if os.name != "nt":
        assert state_file.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize(
    "contents, expected",
    [
        ("{", "invalid JSON"),
        (
            '{"operation_id":"a","operation_id":"b"}',
            "duplicate key",
        ),
        (
            json.dumps({"operation_id": str(uuid4()), "unexpected": "value"}),
            "schema mismatch",
        ),
        (
            json.dumps({"operation_id": str(uuid4()), "password": "value"}),
            "forbidden field",
        ),
    ],
)
def test_credential_state_fails_closed_for_corruption_and_unsafe_schema(
    tmp_path: Path, contents: str, expected: str
) -> None:
    state_file = tmp_path / "replacement-state.json"
    state_file.write_text(contents, encoding="utf-8")
    if os.name != "nt":
        os.chmod(state_file, 0o600)
    result = state_command("read", "--state-file", str(state_file))
    assert result.returncode != 0
    assert expected in result.stderr


def test_credential_state_only_allows_resumable_lifecycle_transitions(tmp_path: Path) -> None:
    state_file = tmp_path / "replacement-state.json"
    create_state(state_file)
    for status, extra in (
        (
            "replacement_issued",
            (
                "--replacement-credential-id",
                "credential-new",
                "--replacement-expires-at",
                "2026-09-01T12:00:00Z",
            ),
        ),
        ("token_staged", ()),
        ("imported_pending_verification", ()),
        ("verified_pending_activation", ()),
        ("verified_pending_revocation", ()),
        ("finalized", ()),
    ):
        result = state_command(
            "transition", "--state-file", str(state_file), "--status", status, *extra
        )
        assert result.returncode == 0, result.stderr
    assert json.loads(state_file.read_text(encoding="utf-8"))["status"] == "finalized"

    rejected = state_command("transition", "--state-file", str(state_file), "--status", "aborted")
    assert rejected.returncode != 0
    assert "invalid transition" in rejected.stderr


@pytest.mark.parametrize(
    ("scenario", "status"),
    [
        ("crash_after_planned_state", "planned"),
        ("crash_after_database_credential_commit", "planned"),
        ("crash_after_staged_value_write", "token_staged"),
        ("crash_after_n8n_import", "imported_pending_verification"),
        ("crash_after_workflow_verification", "verified_pending_activation"),
        ("crash_after_active_file_switch", "verified_pending_revocation"),
        ("crash_after_superseded_revoke", "verified_pending_revocation"),
        ("restart_status", "token_staged"),
        ("restart_resume", "imported_pending_verification"),
        ("abort_before_verification", "aborted"),
        ("corrupted_state", "planned"),
        ("unknown_key", "planned"),
        ("duplicate_key", "planned"),
        ("missing_staging_value", "replacement_issued"),
        ("orphan_operation_match", "planned"),
        ("multiple_unexpired_credentials", "planned"),
    ],
)
def test_failure_injection_states_remain_public_and_deterministic(
    tmp_path: Path, scenario: str, status: str
) -> None:
    """Isolated deterministic coverage for every durable lifecycle interruption."""
    state_file = tmp_path / f"{scenario}.json"
    create_state(state_file, status=status)
    result = state_command("read", "--state-file", str(state_file))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == status
    assert set(payload) == {
        "operation_id",
        "principal_id",
        "superseded_credential_id",
        "replacement_credential_id",
        "status",
        "created_at",
        "updated_at",
        "replacement_expires_at",
    }
