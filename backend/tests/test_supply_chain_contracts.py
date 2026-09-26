from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE_DIGEST = "57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
VEX = ROOT / "security/openvex" / f"postgres-gosu-{IMAGE_DIGEST}.json"
IMAGE = f"postgres:16.14-alpine3.24@sha256:{IMAGE_DIGEST}"
GO_IMAGE = (
    "golang:1.24.6-alpine@sha256:"
    "c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d"
)
MODULE_VERSION = "v0.0.0-20250923190938-6456aaa0f3c8"
MODULE_QUERY = "6456aaa0f3c854d199d0f037f068eb97515b7513"
MODULE_SUM = "h1:HIpXk5mGBQGfOqcaBbRT4Vnss8NPICnMGlD5xTlPBdQ="
GO_MOD_SUM = "h1:SwhRwWsO6iqXZN9CpIaU9CnOrUqpWDINW16KaaSqnrU="

spec = importlib.util.spec_from_file_location(
    "postgres_vex", ROOT / "security/validate_postgres_gosu_vex.py"
)
assert spec and spec.loader
postgres_vex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(postgres_vex)


def module_metadata_payload() -> dict[str, object]:
    return {
        "Path": "github.com/tianon/gosu",
        "Version": MODULE_VERSION,
        "Query": MODULE_QUERY,
        "Info": f"/go/pkg/mod/cache/download/github.com/tianon/gosu/@v/{MODULE_VERSION}.info",
        "GoMod": f"/go/pkg/mod/cache/download/github.com/tianon/gosu/@v/{MODULE_VERSION}.mod",
        "Zip": f"/go/pkg/mod/cache/download/github.com/tianon/gosu/@v/{MODULE_VERSION}.zip",
        "Dir": f"/go/pkg/mod/github.com/tianon/gosu@{MODULE_VERSION}",
        "Sum": MODULE_SUM,
        "GoModSum": GO_MOD_SUM,
        "Origin": {
            "VCS": "git",
            "URL": "https://github.com/tianon/gosu",
            "Hash": MODULE_QUERY,
        },
    }


def write_module_metadata(path: Path, payload: dict[str, object] | None = None) -> None:
    path.write_text(json.dumps(payload or module_metadata_payload()), encoding="utf-8")


def write_source_raw(
    path: Path,
    *,
    scan_mode: str = "source",
    finding: tuple[str, str, str] | None = None,
    include_reviewed: bool = True,
    protocol_version: str = "v1.0.0",
    scanner_name: str = "govulncheck",
    scanner_version: str = "v1.1.4",
    go_version: str = "go1.24.6",
) -> None:
    events: list[dict[str, object]] = [
        {
            "config": {
                "protocol_version": protocol_version,
                "scanner_name": scanner_name,
                "scanner_version": scanner_version,
                "db": "https://vuln.go.dev",
                "go_version": go_version,
                "scan_level": "symbol",
                "scan_mode": scan_mode,
            }
        }
    ]
    if include_reviewed:
        for index, cve in enumerate(sorted(postgres_vex.expected_ids())):
            osv_id = f"GO-TEST-{index:04d}"
            events.extend(
                [
                    {"osv": {"id": osv_id, "aliases": [cve]}},
                    {
                        "finding": {
                            "osv": osv_id,
                            "trace": [{"module": "stdlib", "version": "go1.24.6"}],
                        }
                    },
                ]
            )
    if finding is not None:
        osv_id, cve, level = finding
        trace: list[dict[str, str]] = [{"module": "stdlib", "version": "go1.24.6"}]
        if level == "function":
            trace.append(
                {
                    "module": "stdlib",
                    "version": "go1.24.6",
                    "package": "crypto/tls",
                    "function": "exampleVulnerableSymbol",
                }
            )
        events.extend(
            [
                {"osv": {"id": osv_id, "aliases": [cve]}},
                {
                    "finding": {
                        "osv": osv_id,
                        "trace": trace,
                    }
                },
            ]
        )
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def reproduction_payload(module_metadata: Path, raw: Path) -> dict[str, object]:
    metadata = json.loads(module_metadata.read_text(encoding="utf-8"))
    events = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
    aliases = {
        event["osv"]["id"]: sorted(event["osv"].get("aliases", []))
        for event in events
        if isinstance(event.get("osv"), dict)
    }
    finding_events = [
        event["finding"]
        for event in events
        if isinstance(event.get("finding"), dict)
    ]
    observed_ids = sorted({finding["osv"] for finding in finding_events})
    observed_cves = sorted({cve for identifier in observed_ids for cve in aliases[identifier]})
    reachable_ids = sorted(
        {
            finding["osv"]
            for finding in finding_events
            if any(frame.get("function") for frame in finding.get("trace", []))
        }
    )
    go_to_cve = {identifier: aliases[identifier] for identifier in reachable_ids}
    return {
        "schema_version": 2,
        "source": {
            "module_path": metadata["Path"],
            "module_query": metadata["Query"],
            "module_version": metadata["Version"],
            "module_sum": metadata["Sum"],
            "go_mod_sum": metadata["GoModSum"],
            "origin_hash": metadata["Origin"]["Hash"],
        },
        "toolchain": {
            "go_image": GO_IMAGE,
            "govulncheck": "v1.1.4",
            "scan_mode": "source",
            "vulnerability_database": "https://vuln.go.dev",
        },
        "module_download": {
            "path": module_metadata.name,
            "sha256": hashlib.sha256(module_metadata.read_bytes()).hexdigest(),
        },
        "raw_output": {
            "path": raw.name,
            "sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        },
        "observed_finding_ids": observed_ids,
        "observed_cves": observed_cves,
        "reachable_finding_ids": reachable_ids,
        "go_to_cve": go_to_cve,
        "reachable_findings": sorted(
            {cve for values in go_to_cve.values() for cve in values}
        ),
    }


def write_reproduction(path: Path, module_metadata: Path, raw: Path) -> dict[str, object]:
    payload = reproduction_payload(module_metadata, raw)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def test_scoped_postgres_vex_accepts_only_the_reviewed_image() -> None:
    postgres_vex.validate(VEX, IMAGE)
    with pytest.raises(ValueError, match="reviewed PostgreSQL image digest"):
        postgres_vex.validate(VEX, "postgres:16.14-alpine3.24@sha256:" + "0" * 64)


def test_vex_does_not_cover_new_or_missing_findings(tmp_path: Path) -> None:
    modified = json.loads(VEX.read_text(encoding="utf-8"))
    modified["statements"] = modified["statements"][:-1]
    broken_vex = tmp_path / "broken.json"
    broken_vex.write_text(json.dumps(modified), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly the reviewed CVE set"):
        postgres_vex.validate(broken_vex, IMAGE)

    report = {
        "Results": [
            {
                "Target": "usr/local/bin/gosu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-00001",
                        "Severity": "HIGH",
                        "PkgIdentifier": {"PURL": "pkg:golang/stdlib@v1.24.6"},
                    }
                ],
            }
        ]
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="raw PostgreSQL report must contain exactly"):
        postgres_vex.validate(VEX, IMAGE, report_path)


def test_all_workflow_actions_are_immutable_sha_pins() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_action_pins.py"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_aggregate_vex_is_limited_to_postgres_gosu_component(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    for component in ("api", "dashboard"):
        (reports / f"{component}.json").write_text(
            json.dumps({"findings": []}), encoding="utf-8"
        )
    allowed = next(iter(postgres_vex.expected_ids()))
    postgres_report = {
        "findings": [
            {
                "id": allowed,
                "severity": "HIGH",
                "target": "usr/local/bin/gosu",
                "purl": postgres_vex.PURL,
            }
        ]
    }
    postgres_path = reports / "postgres.json"
    postgres_path.write_text(json.dumps(postgres_report), encoding="utf-8")
    module_metadata = reports / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = reports / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw, finding=("GO-2099-0001", "CVE-2099-00001", "module"))
    write_reproduction(
        reports / "postgres-gosu-reproduction.json",
        module_metadata,
        raw,
    )
    clean = subprocess.run(
        [sys.executable, "security/aggregate_security_reports.py", str(reports)],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert clean.returncode == 0, clean.stderr + clean.stdout

    postgres_report["findings"][0]["purl"] = "pkg:apk/alpine/other@1"
    postgres_path.write_text(json.dumps(postgres_report), encoding="utf-8")
    blocked = subprocess.run(
        [sys.executable, "security/aggregate_security_reports.py", str(reports)],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert blocked.returncode != 0
    assert f"postgres:{allowed}" in blocked.stderr


def test_external_reference_advisory_is_not_the_owned_security_gate() -> None:
    owned = (ROOT / ".github" / "workflows" / "container-security.yml").read_text(
        encoding="utf-8"
    )
    advisory = (ROOT / ".github" / "workflows" / "external-dependency-advisory.yml").read_text(
        encoding="utf-8"
    )
    assert "n8nio/n8n" not in owned and "caddy:" not in owned
    assert "n8nio/n8n" in advisory and "caddy:" in advisory
    assert "without suppression" in advisory
    assert "not a FlowProof security PASS" in advisory


def test_reachability_comparison_rejects_function_trace(tmp_path: Path) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw, finding=("GO-2099-0001", "CVE-2099-00001", "function"))
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)
    with pytest.raises(ValueError, match="function-reachable findings"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


def test_module_only_findings_are_not_reachable(tmp_path: Path) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw, finding=("GO-2099-0001", "CVE-2099-00001", "module"))
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)

    postgres_vex.validate(
        VEX,
        IMAGE,
        reproduction_path=reproduction,
        module_metadata_path=module_metadata,
        raw_path=raw,
    )


def test_reproduction_rejects_missing_or_hash_mismatched_raw(tmp_path: Path) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw)
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    payload = write_reproduction(reproduction, module_metadata, raw)

    raw.unlink()
    with pytest.raises(ValueError, match="raw JSONL is missing"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )

    write_source_raw(raw)
    payload["raw_output"]["sha256"] = hashlib.sha256(b"different raw evidence").hexdigest()
    reproduction.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="raw SHA-256"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


def test_reproduction_rejects_missing_or_hash_mismatched_module_metadata(
    tmp_path: Path,
) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw)
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    payload = write_reproduction(reproduction, module_metadata, raw)

    module_metadata.unlink()
    with pytest.raises(ValueError, match="module metadata JSON is missing"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )

    write_module_metadata(module_metadata)
    payload["module_download"]["sha256"] = hashlib.sha256(
        b"different module metadata"
    ).hexdigest()
    reproduction.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="module metadata SHA-256"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("Version", "v0.0.0-20990101000000-000000000000", "field 'Version'"),
        ("Sum", "h1:not-the-reviewed-module-sum", "field 'Sum'"),
    ],
)
def test_reproduction_rejects_wrong_module_provenance(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    metadata = module_metadata_payload()
    metadata[field] = value
    write_module_metadata(module_metadata, metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw)
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)
    with pytest.raises(ValueError, match=message):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


def test_reproduction_rejects_wrong_module_origin(tmp_path: Path) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    metadata = module_metadata_payload()
    metadata["Origin"]["URL"] = "https://example.invalid/not-gosu"
    write_module_metadata(module_metadata, metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw)
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)
    with pytest.raises(ValueError, match="origin does not match"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


def test_reproduction_rejects_non_source_raw_mode(tmp_path: Path) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw, scan_mode="binary")
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)
    with pytest.raises(ValueError, match="not an exact source-mode scan"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


def test_reproduction_rejects_missing_reviewed_cve_findings(tmp_path: Path) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(
        raw,
        include_reviewed=False,
        finding=("GO-2099-0001", "CVE-2099-00001", "module"),
    )
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)
    with pytest.raises(ValueError, match="missing reviewed CVE findings"):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )


@pytest.mark.parametrize(
    ("raw_overrides", "message"),
    [
        ({"protocol_version": "v9.9.9"}, "protocol version"),
        ({"scanner_name": "other"}, "scanner name"),
        ({"scanner_version": "wrapper-v1.1.4-extra"}, "scanner version"),
        ({"go_version": "go1.24.7"}, "Go version"),
    ],
)
def test_reproduction_rejects_wrong_raw_toolchain_config(
    tmp_path: Path,
    raw_overrides: dict[str, object],
    message: str,
) -> None:
    module_metadata = tmp_path / "postgres-gosu-module-download.json"
    write_module_metadata(module_metadata)
    raw = tmp_path / "postgres-gosu-govulncheck.jsonl"
    write_source_raw(raw, **raw_overrides)
    reproduction = tmp_path / "postgres-gosu-reproduction.json"
    write_reproduction(reproduction, module_metadata, raw)
    with pytest.raises(ValueError, match=message):
        postgres_vex.validate(
            VEX,
            IMAGE,
            reproduction_path=reproduction,
            module_metadata_path=module_metadata,
            raw_path=raw,
        )
