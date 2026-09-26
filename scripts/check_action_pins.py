"""Reject mutable GitHub Action references in repository workflows."""

from __future__ import annotations

import re
from pathlib import Path

USES = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")


def main() -> None:
    failures: list[str] = []
    for workflow in sorted(Path(".github/workflows").glob("*.y*ml")):
        for reference in USES.findall(workflow.read_text(encoding="utf-8")):
            if not SHA.fullmatch(reference):
                failures.append(f"{workflow}: mutable action reference {reference}")
    if failures:
        raise SystemExit("\n".join(failures))
    print("all GitHub Actions are pinned by full commit SHA")


if __name__ == "__main__":
    main()
