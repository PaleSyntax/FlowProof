#!/usr/bin/env python3
"""Prove that an exact Gitleaks range does not lose a secret after 30 commits."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

GITLEAKS_IMAGE = "zricethezav/gitleaks@sha256:f44e526acc67786b7476db413edb993ce2d152660d32fb3eb48d9bca06fa83f8"
COMMIT_COUNT = 35


def run(
    arguments: list[str], *, cwd: Path, expected: int = 0
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments, cwd=cwd, text=True, capture_output=True, check=False
    )
    if completed.returncode != expected:
        raise RuntimeError(
            f"command outcome mismatch for {arguments[0]!r}: expected {expected}, got {completed.returncode}"
        )
    return completed


def commit(repository: Path, filename: str, contents: str, message: str) -> str:
    repository.joinpath(filename).write_text(contents, encoding="utf-8")
    run(["git", "add", filename], cwd=repository)
    run(["git", "commit", "--quiet", "-m", message], cwd=repository)
    return run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()


def make_repository(root: Path, *, include_canary: bool) -> tuple[str, str, int]:
    repository = root / ("canary" if include_canary else "clean")
    repository.mkdir()
    run(["git", "init", "--quiet"], cwd=repository)
    run(
        ["git", "config", "user.email", "gitleaks-regression@example.test"],
        cwd=repository,
    )
    run(["git", "config", "user.name", "Gitleaks regression"], cwd=repository)
    base = commit(repository, "history.txt", "base\n", "base")
    for index in range(1, COMMIT_COUNT + 1):
        commit(repository, "history.txt", f"commit {index}\n", f"history {index}")
    if include_canary:
        # Synthetic test-only value, never emitted to stdout/stderr or reports.
        commit(
            repository,
            "canary.txt",
            "ghp_" + ("0" * 36) + "\n",
            "synthetic canary",
        )
    head = run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()
    count = int(
        run(["git", "rev-list", "--count", f"{base}..{head}"], cwd=repository).stdout
    )
    if (
        head != run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()
        or count < COMMIT_COUNT
    ):
        raise RuntimeError("exact-range fixture did not reach its expected head/count")
    return base, head, count


def scan(repository: Path, base: str, head: str, *, expected: int) -> None:
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{repository}:/repo:ro",
            "-w",
            "/repo",
            GITLEAKS_IMAGE,
            "detect",
            "--source",
            "/repo",
            "--log-opts",
            f"{base}..{head}",
            "--redact=100",
            "--no-banner",
        ],
        cwd=repository,
        expected=expected,
    )


def main() -> int:
    if shutil.which("docker") is None:
        raise SystemExit("Gitleaks range regression requires Docker")
    with tempfile.TemporaryDirectory(prefix="flowproof-gitleaks-range-") as temporary:
        root = Path(temporary)
        canary_base, canary_head, canary_count = make_repository(
            root, include_canary=True
        )
        scan(root / "canary", canary_base, canary_head, expected=1)
        clean_base, clean_head, clean_count = make_repository(
            root, include_canary=False
        )
        scan(root / "clean", clean_base, clean_head, expected=0)
    print(
        json.dumps(
            {
                "base_sha": clean_base,
                "head_sha": clean_head,
                "commit_count": clean_count,
                "canary_range_failed": True,
                "clean_range_passed": True,
                "scanner_image": GITLEAKS_IMAGE,
                "scanner_version": "8.18.4",
                "result": "passed",
                "canary_commit_count": canary_count,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
