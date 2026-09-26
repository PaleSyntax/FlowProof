"""Validate Go-proxy provenance and source-level gosu reachability evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_MODULE = "github.com/tianon/gosu"
EXPECTED_QUERY = "6456aaa0f3c854d199d0f037f068eb97515b7513"
EXPECTED_VERSION = "v0.0.0-20250923190938-6456aaa0f3c8"
EXPECTED_SUM = "h1:HIpXk5mGBQGfOqcaBbRT4Vnss8NPICnMGlD5xTlPBdQ="
EXPECTED_GO_MOD_SUM = "h1:SwhRwWsO6iqXZN9CpIaU9CnOrUqpWDINW16KaaSqnrU="
EXPECTED_ORIGIN_HASH = EXPECTED_QUERY
EXPECTED_GOVULNCHECK = "v1.1.4"
EXPECTED_GO_IMAGE = "golang:1.24.6-alpine@sha256:c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d"
EXPECTED_GO_VERSION = "go1.24.6"
EXPECTED_PROTOCOL_VERSION = "v1.0.0"
EXPECTED_SCANNER_NAME = "govulncheck"
EXPECTED_SCAN_MODE = "source"
EXPECTED_SCAN_LEVEL = "symbol"
EXPECTED_DATABASE = "https://vuln.go.dev"
MODULE_METADATA_FILENAME = "postgres-gosu-module-download.json"
RAW_FILENAME = "postgres-gosu-govulncheck.jsonl"


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    raw = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        item, offset = decoder.raw_decode(raw, offset)
        if not isinstance(item, dict):
            raise TypeError("govulncheck output must contain JSON objects")
        events.append(item)
    if not events:
        raise ValueError("govulncheck raw output is empty")
    return events


def load_module_metadata(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("Go module download metadata must contain an object")
    return payload


def validate_module_metadata(metadata: dict[str, Any]) -> None:
    expected = {
        "Path": EXPECTED_MODULE,
        "Version": EXPECTED_VERSION,
        "Query": EXPECTED_QUERY,
        "Sum": EXPECTED_SUM,
        "GoModSum": EXPECTED_GO_MOD_SUM,
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise ValueError(f"Go module download field {field!r} is not exact")
    origin = metadata.get("Origin")
    if not isinstance(origin, dict):
        raise TypeError("Go module download origin metadata is missing")
    if (
        origin.get("VCS") != "git"
        or origin.get("URL") != "https://github.com/tianon/gosu"
        or origin.get("Hash") != EXPECTED_ORIGIN_HASH
    ):
        raise ValueError("Go module download origin does not match the reviewed commit")
    if metadata.get("Error") is not None:
        raise ValueError("Go module download metadata contains an error")


def _scan_config(events: list[dict[str, Any]]) -> dict[str, Any]:
    configs = [event["config"] for event in events if isinstance(event.get("config"), dict)]
    if len(configs) != 1:
        raise ValueError(f"govulncheck raw output must contain exactly one config event, found {len(configs)}")
    config = configs[0]
    if config.get("scan_mode") != EXPECTED_SCAN_MODE:
        raise ValueError("govulncheck raw output is not an exact source-mode scan")
    if config.get("scan_level") != EXPECTED_SCAN_LEVEL:
        raise ValueError("govulncheck raw output is not a symbol-level scan")
    if str(config.get("db", "")).rstrip("/") != EXPECTED_DATABASE:
        raise ValueError("govulncheck raw output used an unexpected vulnerability database")
    if config.get("protocol_version") != EXPECTED_PROTOCOL_VERSION:
        raise ValueError("govulncheck raw output used an unexpected protocol version")
    if config.get("scanner_name") != EXPECTED_SCANNER_NAME:
        raise ValueError("govulncheck raw output used an unexpected scanner name")
    if config.get("scanner_version") != EXPECTED_GOVULNCHECK:
        raise ValueError("govulncheck raw output used an unexpected scanner version")
    if config.get("go_version") != EXPECTED_GO_VERSION:
        raise ValueError("govulncheck raw output used an unexpected Go version")
    return config


def _osv_aliases(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    aliases: dict[str, list[str]] = {}
    for event in events:
        osv = event.get("osv")
        if not isinstance(osv, dict) or not isinstance(osv.get("id"), str):
            continue
        aliases[osv["id"]] = sorted(
            alias
            for alias in osv.get("aliases", [])
            if isinstance(alias, str) and alias.startswith("CVE-")
        )
    return aliases


def _finding_identifier(finding: dict[str, Any]) -> tuple[str, list[str]]:
    osv = finding.get("osv")
    if isinstance(osv, str) and osv:
        return osv, []
    if isinstance(osv, dict) and isinstance(osv.get("id"), str):
        return osv["id"], sorted(
            alias
            for alias in osv.get("aliases", [])
            if isinstance(alias, str) and alias.startswith("CVE-")
        )
    return "<unknown>", []


def _has_function_trace(finding: dict[str, Any]) -> bool:
    trace = finding.get("trace")
    return isinstance(trace, list) and any(
        isinstance(frame, dict)
        and isinstance(frame.get("function"), str)
        and bool(frame["function"].strip())
        for frame in trace
    )


def reachable_findings(events: list[dict[str, Any]]) -> list[str]:
    result: set[str] = set()
    for event in events:
        finding = event.get("finding")
        if isinstance(finding, dict) and _has_function_trace(finding):
            result.add(_finding_identifier(finding)[0])
    return sorted(result)


def reachable_cves(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    aliases = _osv_aliases(events)
    result: dict[str, list[str]] = {}
    for event in events:
        finding = event.get("finding")
        if not isinstance(finding, dict) or not _has_function_trace(finding):
            continue
        identifier, embedded_aliases = _finding_identifier(finding)
        values = embedded_aliases or aliases.get(identifier, [])
        if values:
            result[identifier] = values
    return dict(sorted(result.items()))


def observed_findings(events: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    aliases = _osv_aliases(events)
    identifiers: set[str] = set()
    cves: set[str] = set()
    for event in events:
        finding = event.get("finding")
        if not isinstance(finding, dict):
            continue
        identifier, embedded_aliases = _finding_identifier(finding)
        if identifier == "<unknown>":
            raise ValueError("govulncheck raw output contains a finding without an OSV ID")
        identifiers.add(identifier)
        cves.update(embedded_aliases or aliases.get(identifier, []))
    return sorted(identifiers), sorted(cves)


def reviewed_cves(evidence: dict[str, Any]) -> list[str]:
    findings = evidence.get("findings")
    if not isinstance(findings, list):
        raise TypeError("committed reachability evidence must contain reviewed findings")
    result = sorted(
        item.get("id")
        for item in findings
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    if len(result) != len(findings) or not result:
        raise ValueError("committed reachability evidence has invalid reviewed CVE identifiers")
    return result


def require_reviewed_cve_coverage(observed_cves: list[str], evidence: dict[str, Any]) -> None:
    missing = sorted(set(reviewed_cves(evidence)).difference(observed_cves))
    if missing:
        raise ValueError(
            "govulncheck raw output is missing reviewed CVE findings: " + ", ".join(missing)
        )


def validate_raw(
    events: list[dict[str, Any]],
) -> tuple[list[str], dict[str, list[str]], list[str], list[str]]:
    _scan_config(events)
    findings = reachable_findings(events)
    mappings = reachable_cves(events)
    observed_ids, observed_cves = observed_findings(events)
    if findings:
        raise ValueError("source govulncheck reported function-reachable findings: " + ", ".join(findings))
    return findings, mappings, observed_ids, observed_cves


def write_result(
    output: Path,
    *,
    module_metadata_path: Path,
    raw_path: Path,
    metadata: dict[str, Any],
    tool_version: str,
    vulnerability_database: str,
    finding_ids: list[str],
    mappings: dict[str, list[str]],
    observed_ids: list[str],
    observed_cves: list[str],
) -> dict[str, Any]:
    origin = metadata["Origin"]
    result = {
        "schema_version": 2,
        "source": {
            "module_path": metadata["Path"],
            "module_query": metadata["Query"],
            "module_version": metadata["Version"],
            "module_sum": metadata["Sum"],
            "go_mod_sum": metadata["GoModSum"],
            "origin_hash": origin["Hash"],
        },
        "toolchain": {
            "go_image": EXPECTED_GO_IMAGE,
            "govulncheck": tool_version,
            "scan_mode": EXPECTED_SCAN_MODE,
            "vulnerability_database": vulnerability_database,
        },
        "module_download": {
            "path": module_metadata_path.name,
            "sha256": hashlib.sha256(module_metadata_path.read_bytes()).hexdigest(),
        },
        "raw_output": {
            "path": raw_path.name,
            "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        },
        "observed_finding_ids": observed_ids,
        "observed_cves": observed_cves,
        "reachable_finding_ids": finding_ids,
        "go_to_cve": mappings,
        "reachable_findings": sorted({cve for values in mappings.values() for cve in values}),
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def compare(
    result: dict[str, Any],
    evidence: dict[str, Any],
    *,
    module_metadata_path: Path,
    raw_path: Path,
) -> None:
    if result.get("schema_version") != 2:
        raise ValueError("gosu reproduction schema version is not supported")
    source = result.get("source")
    toolchain = result.get("toolchain")
    module_download = result.get("module_download")
    raw_output = result.get("raw_output")
    if not all(isinstance(item, dict) for item in (source, toolchain, module_download, raw_output)):
        raise TypeError("gosu reproduction metadata is incomplete")

    metadata = load_module_metadata(module_metadata_path)
    validate_module_metadata(metadata)
    expected_source = {
        "module_path": EXPECTED_MODULE,
        "module_query": EXPECTED_QUERY,
        "module_version": EXPECTED_VERSION,
        "module_sum": EXPECTED_SUM,
        "go_mod_sum": EXPECTED_GO_MOD_SUM,
        "origin_hash": EXPECTED_ORIGIN_HASH,
    }
    if source != expected_source:
        raise ValueError("gosu reproduction source provenance is not exact")
    reviewed_source = evidence.get("source")
    if not isinstance(reviewed_source, dict) or reviewed_source.get("commit") != EXPECTED_ORIGIN_HASH:
        raise ValueError("committed gosu evidence is not bound to the reviewed commit")
    reviewed_acquisition = reviewed_source.get("acquisition")
    expected_acquisition = {
        "module_proxy": "https://proxy.golang.org",
        "module_path": EXPECTED_MODULE,
        "module_query": EXPECTED_QUERY,
        "module_version": EXPECTED_VERSION,
        "module_sum": EXPECTED_SUM,
        "go_mod_sum": EXPECTED_GO_MOD_SUM,
        "direct_vcs_disabled": True,
    }
    if reviewed_acquisition != expected_acquisition:
        raise ValueError("committed gosu evidence is not bound to exact Go proxy provenance")
    if reviewed_source.get("scan_level") != EXPECTED_SCAN_LEVEL:
        raise ValueError("committed gosu evidence is not bound to symbol-level source scanning")

    if toolchain.get("govulncheck") != EXPECTED_GOVULNCHECK:
        raise ValueError("govulncheck version does not match the reviewed tool")
    if toolchain.get("go_image") != EXPECTED_GO_IMAGE:
        raise ValueError("Go toolchain image does not match the reviewed digest")
    if toolchain.get("scan_mode") != EXPECTED_SCAN_MODE:
        raise ValueError("gosu reproduction is not a source-mode scan")
    if str(toolchain.get("vulnerability_database", "")).rstrip("/") != EXPECTED_DATABASE:
        raise ValueError("gosu reproduction used an unexpected vulnerability database")

    if module_download.get("path") != MODULE_METADATA_FILENAME or module_metadata_path.name != MODULE_METADATA_FILENAME:
        raise ValueError("gosu module metadata filename is not exact")
    if module_download.get("sha256") != hashlib.sha256(module_metadata_path.read_bytes()).hexdigest():
        raise ValueError("gosu module metadata SHA-256 does not match the required JSON")
    if raw_output.get("path") != RAW_FILENAME or raw_path.name != RAW_FILENAME:
        raise ValueError("gosu reproduction raw filename is not exact")
    if raw_output.get("sha256") != hashlib.sha256(raw_path.read_bytes()).hexdigest():
        raise ValueError("gosu reproduction raw SHA-256 does not match the required JSONL")

    finding_ids, mappings, observed_ids, observed_cves = validate_raw(load_events(raw_path))
    require_reviewed_cve_coverage(observed_cves, evidence)
    if (
        result.get("reachable_finding_ids") != finding_ids
        or result.get("go_to_cve") != mappings
        or result.get("observed_finding_ids") != observed_ids
        or result.get("observed_cves") != observed_cves
    ):
        raise ValueError("gosu reproduction summary disagrees with raw govulncheck output")
    expected = evidence.get("reachable_findings")
    if expected is None:
        reviewed = evidence.get("result")
        expected = reviewed.get("reachable_findings") if isinstance(reviewed, dict) else None
    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        raise ValueError("committed reachability evidence must list reachable findings")
    if sorted(expected) != result.get("reachable_findings"):
        raise ValueError("govulncheck reachable findings disagree with committed evidence")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module-metadata", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--govulncheck-version", required=True)
    parser.add_argument("--vulnerability-database", required=True)
    args = parser.parse_args()

    metadata = load_module_metadata(args.module_metadata)
    validate_module_metadata(metadata)
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        raise TypeError("committed reachability evidence must be a JSON object")
    finding_ids, mappings, observed_ids, observed_cves = validate_raw(load_events(args.raw))
    require_reviewed_cve_coverage(observed_cves, evidence)
    result = write_result(
        args.output,
        module_metadata_path=args.module_metadata,
        raw_path=args.raw,
        metadata=metadata,
        tool_version=args.govulncheck_version,
        vulnerability_database=args.vulnerability_database,
        finding_ids=finding_ids,
        mappings=mappings,
        observed_ids=observed_ids,
        observed_cves=observed_cves,
    )
    compare(
        result,
        evidence,
        module_metadata_path=args.module_metadata,
        raw_path=args.raw,
    )
    print(json.dumps({"reachable_findings": [], "status": "matched"}))


if __name__ == "__main__":
    main()
