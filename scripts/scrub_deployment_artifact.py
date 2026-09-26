#!/usr/bin/env python3
"""Fail closed if a deployment-proof artifact contains a secret-shaped value."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import NoReturn

FORBIDDEN_NAME = re.compile(
    r"(?i)(?:token|hash|pepper|password|cookie|csrf|authorization|database_url|webhook_url)"
)
PATTERNS = {
    "bearer value": re.compile(r"(?i)bearer\s+[a-z0-9._~-]{16,}"),
    "cookie value": re.compile(r"(?i)(?:set-)?cookie\s*[:=]\s*[^;\s]{8,}"),
    "credential DSN": re.compile(
        r"[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE
    ),
    "secret-shaped webhook URL": re.compile(
        r"(?i)https?://[^\s]+/(?:hook|webhook)/[^\s/?#]{12,}"
    ),
    "synthetic Gitleaks canary": re.compile(r"ghp_0{36}"),
}
ALLOWED_BASENAMES = {
    "deployment-proof.log",
    "result.json",
    "n8n-credential-replacement.json",
    "credential-crash-recovery-evidence.json",
    "credential-lifetime-evidence.json",
    "gitleaks-range-evidence.json",
    "failed-command.json",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"deployment artifact scrub failed: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path, nargs="+")
    args = parser.parse_args()
    for artifact in args.artifact:
        if artifact.name not in ALLOWED_BASENAMES:
            fail(f"unexpected artifact {artifact.name!r}")
        if "secret" in artifact.as_posix().lower():
            fail(f"artifact path {artifact.name!r} is under a secret directory")
        if not artifact.is_file():
            fail(f"artifact {artifact.name!r} is missing")
        contents = artifact.read_text(encoding="utf-8", errors="replace")
        if artifact.suffix == ".json":
            for key in re.findall(r'"([^"\\]+)"\s*:', contents):
                if FORBIDDEN_NAME.search(key):
                    fail(f"artifact {artifact.name!r} contains a forbidden field name")
        for reason, pattern in PATTERNS.items():
            if pattern.search(contents):
                fail(f"artifact {artifact.name!r} contains {reason}")
    print("deployment artifact scrub passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
