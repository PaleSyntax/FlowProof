"""Fail closed unless the PostgreSQL/gosu VEX matches its exact reviewed artifact."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

_compare_spec = importlib.util.spec_from_file_location(
    "postgres_gosu_comparison", Path(__file__).with_name("compare_postgres_gosu_reachability.py")
)
assert _compare_spec and _compare_spec.loader
_compare_module = importlib.util.module_from_spec(_compare_spec)
_compare_spec.loader.exec_module(_compare_module)
compare = _compare_module.compare

IMAGE = "postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
PURL = "pkg:golang/stdlib@v1.24.6"
EVIDENCE = Path("security/postgres-gosu-reachability.json")
MODULE_METADATA_FILENAME = "postgres-gosu-module-download.json"
RAW_FILENAME = "postgres-gosu-govulncheck.jsonl"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def expected_ids() -> set[str]:
    evidence = load_json(EVIDENCE)
    assert isinstance(evidence, dict)
    return {item["id"] for item in evidence["findings"]}


def validate(
    vex_path: Path,
    image_ref: str,
    report_path: Path | None = None,
    reproduction_path: Path | None = None,
    module_metadata_path: Path | None = None,
    raw_path: Path | None = None,
) -> None:
    if image_ref != IMAGE:
        raise ValueError("VEX may only be used with the reviewed PostgreSQL image digest")
    vex = load_json(vex_path)
    assert isinstance(vex, dict)
    if "57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777" not in str(
        vex.get("@id", "")
    ):
        raise ValueError("OpenVEX document is not bound to the reviewed image digest")
    statements = vex.get("statements")
    if not isinstance(statements, list):
        raise TypeError("OpenVEX statements are required")
    seen: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict):
            raise TypeError("invalid OpenVEX statement")
        vulnerability = statement.get("vulnerability", {})
        cve = vulnerability.get("name") if isinstance(vulnerability, dict) else None
        products = statement.get("products")
        if (
            not isinstance(cve, str)
            or statement.get("status") != "not_affected"
            or statement.get("justification") != "vulnerable_code_not_in_execute_path"
            or not isinstance(products, list)
            or products != [{"@id": PURL}]
            or "security/postgres-gosu-reachability.json"
            not in str(statement.get("impact_statement", ""))
        ):
            raise ValueError("OpenVEX statement is not scoped to the reviewed component and digest")
        seen.add(cve)
    if seen != expected_ids() or len(seen) != len(statements):
        raise ValueError("OpenVEX must cover exactly the reviewed CVE set")
    proof_paths = (reproduction_path, module_metadata_path, raw_path)
    if any(path is not None for path in proof_paths) and not all(path is not None for path in proof_paths):
        raise ValueError("PostgreSQL/gosu reproduction, module metadata and raw JSONL must be supplied together")
    if reproduction_path is not None and module_metadata_path is not None and raw_path is not None:
        if module_metadata_path.name != MODULE_METADATA_FILENAME or not module_metadata_path.is_file():
            raise ValueError("required PostgreSQL/gosu module metadata JSON is missing")
        if raw_path.name != RAW_FILENAME or not raw_path.is_file():
            raise ValueError("required PostgreSQL/gosu raw JSONL is missing")
        reproduction = load_json(reproduction_path)
        evidence = load_json(EVIDENCE)
        if not isinstance(reproduction, dict) or not isinstance(evidence, dict):
            raise TypeError("PostgreSQL reachability reproduction and evidence must be JSON objects")
        compare(
            reproduction,
            evidence,
            module_metadata_path=module_metadata_path,
            raw_path=raw_path,
        )
    if report_path is not None:
        report = load_json(report_path)
        assert isinstance(report, dict)
        found = {
            finding["VulnerabilityID"]
            for result in report.get("Results", [])
            for finding in (result.get("Vulnerabilities") or [])
            if result.get("Target") == "usr/local/bin/gosu"
            and finding.get("PkgIdentifier", {}).get("PURL") == PURL
            and finding.get("Severity") in {"HIGH", "CRITICAL"}
        }
        if found != seen:
            raise ValueError(
                "raw PostgreSQL report must contain exactly the reviewed gosu findings: "
                f"expected={sorted(seen)} actual={sorted(found)}"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vex", type=Path, required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--reproduction", type=Path)
    parser.add_argument("--module-metadata", type=Path)
    parser.add_argument("--raw", type=Path)
    args = parser.parse_args()
    validate(
        args.vex,
        args.image_ref,
        args.report,
        args.reproduction,
        args.module_metadata,
        args.raw,
    )
    print("PostgreSQL/gosu VEX scope verified")


if __name__ == "__main__":
    main()
