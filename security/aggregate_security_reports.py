"""Blocking aggregate for independently-produced normalized image scan reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from validate_postgres_gosu_vex import IMAGE, PURL, expected_ids, validate


def blocking_findings(report_dir: Path) -> list[str]:
    """Return only findings not covered by the exact PostgreSQL/gosu VEX."""

    component_paths = {path.stem: path for path in report_dir.glob("*.json")}
    expected = {"api", "dashboard", "postgres"}
    found = expected.intersection(component_paths)
    if found != expected:
        raise ValueError(
            f"missing or unexpected component reports: expected={sorted(expected)} actual={sorted(found)}"
        )
    # The raw PostgreSQL scan is validated before normalization. Recheck the
    # immutable VEX identity here so a changed digest cannot inherit an allow.
    reproduction = report_dir / "postgres-gosu-reproduction.json"
    if not reproduction.is_file():
        raise ValueError("missing PostgreSQL/gosu machine-produced reachability reproduction")
    raw = report_dir / "postgres-gosu-govulncheck.jsonl"
    if not raw.is_file():
        raise ValueError("missing PostgreSQL/gosu raw govulncheck JSONL")
    module_metadata = report_dir / "postgres-gosu-module-download.json"
    if not module_metadata.is_file():
        raise ValueError("missing PostgreSQL/gosu Go module download metadata")
    validate(
        Path("security/openvex/postgres-gosu-57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777.json"),
        IMAGE,
        reproduction_path=reproduction,
        module_metadata_path=module_metadata,
        raw_path=raw,
    )
    reviewed_postgres_ids = expected_ids()
    blocking: list[str] = []
    for component in sorted(expected):
        report_path = component_paths[component]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        findings = report.get("findings", [])
        for finding in findings:
            if finding.get("severity") not in {"HIGH", "CRITICAL"}:
                continue
            is_scoped_postgres_vex = (
                report_path.stem == "postgres"
                and finding.get("target") == "usr/local/bin/gosu"
                and finding.get("purl") == PURL
                and finding.get("id") in reviewed_postgres_ids
            )
            if not is_scoped_postgres_vex:
                blocking.append(f"{report_path.stem}:{finding.get('id')}")
    return blocking


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_dir", type=Path)
    args = parser.parse_args()
    blocking = blocking_findings(args.report_dir)
    if blocking:
        raise SystemExit("blocking HIGH/CRITICAL findings: " + ", ".join(blocking))
    print("all FlowProof-owned image security reports are clean after scoped VEX processing")


if __name__ == "__main__":
    main()
