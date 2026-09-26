from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANAGER = ROOT / "deploy" / "scripts" / "manage-n8n-service-credential.sh"


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("flock") is None,
    reason="owner-only flock lifecycle contract is Linux/POSIX-only",
)
@pytest.mark.parametrize("operation", ("start", "finalize"))
def test_lifecycle_operation_rejects_a_concurrent_lock_holder(
    tmp_path: Path, operation: str
) -> None:
    """The real lifecycle entrypoint must fail before any API call while locked."""

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    lock_file = secrets_dir / "n8n_flowproof_credential_state.json.lock"
    lock_file.write_text("lock\n", encoding="utf-8")
    lock_file.chmod(0o600)
    environment = os.environ | {
        "FLOWPROOF_SECRETS_DIR": str(secrets_dir),
        "FLOWPROOF_PYTHON_EXECUTABLE": sys.executable,
    }

    result = subprocess.run(
        ["flock", "--exclusive", str(lock_file), "bash", str(MANAGER), operation],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 75
    assert "another n8n credential lifecycle process holds the operation lock" in result.stderr
    assert stat.S_IMODE(lock_file.stat().st_mode) == 0o600


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("flock") is None,
    reason="owner-only flock lifecycle contract is Linux/POSIX-only",
)
def test_status_rejects_an_inconsistent_snapshot_while_lifecycle_is_locked(
    tmp_path: Path,
) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    lock_file = secrets_dir / "n8n_flowproof_credential_state.json.lock"
    lock_file.write_text("lock\n", encoding="utf-8")
    lock_file.chmod(0o600)
    environment = os.environ | {
        "FLOWPROOF_SECRETS_DIR": str(secrets_dir),
        "FLOWPROOF_PYTHON_EXECUTABLE": sys.executable,
    }

    result = subprocess.run(
        ["flock", "--exclusive", str(lock_file), "bash", str(MANAGER), "status"],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 75
    assert "n8n credential status snapshot is busy" in result.stderr
