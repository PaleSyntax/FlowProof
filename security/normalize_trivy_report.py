"""Create stable, secret-safe JSON, table and SARIF artifacts from a Trivy image report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def findings(report: dict[str, object]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for result in report.get("Results", []):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", ""))
        for finding in result.get("Vulnerabilities") or []:
            if not isinstance(finding, dict):
                continue
            rows.append(
                {
                    "target": target,
                    "id": str(finding.get("VulnerabilityID", "")),
                    "package": str(finding.get("PkgName", "")),
                    "installed_version": str(finding.get("InstalledVersion", "")),
                    "fixed_version": str(finding.get("FixedVersion", "")),
                    "severity": str(finding.get("Severity", "")),
                    "purl": str((finding.get("PkgIdentifier") or {}).get("PURL", "")),
                }
            )
    return sorted(rows, key=lambda row: (row["target"], row["id"], row["package"]))


def suppressed(report: dict[str, object]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for result in report.get("Results", []):
        if not isinstance(result, dict):
            continue
        for modified in result.get("ExperimentalModifiedFindings") or []:
            if not isinstance(modified, dict):
                continue
            finding = modified.get("Finding") or {}
            rows.append(
                {
                    "id": str(finding.get("VulnerabilityID", "")),
                    "status": str(modified.get("Status", "")),
                    "justification": str(modified.get("Statement", "")),
                    "package": str(finding.get("PkgIdentifier", {}).get("PURL", "")),
                }
            )
    return sorted(rows, key=lambda row: row["id"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    rows = findings(report)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    normalized = {
        "schema_version": 1,
        "component": args.component,
        "findings": rows,
        "suppressed": suppressed(report),
    }
    (args.output_dir / f"{args.component}.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    table = ["target | id | severity | package | installed | fixed"]
    table.extend(
        " | ".join(
            (row["target"], row["id"], row["severity"], row["package"], row["installed_version"], row["fixed_version"])
        )
        for row in rows
    )
    (args.output_dir / f"{args.component}.table.txt").write_text(
        "\n".join(table) + "\n", encoding="utf-8"
    )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": [
            {"ruleId": row["id"], "level": "error" if row["severity"] == "CRITICAL" else "warning", "message": {"text": f"{row['package']} {row['installed_version']}"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"container://{args.component}/{row['target']}"}}}]}
            for row in rows
        ]}],
    }
    (args.output_dir / f"{args.component}.sarif").write_text(
        json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
