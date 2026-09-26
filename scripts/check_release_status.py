"""Validate FlowProof's portfolio-release evidence boundaries."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from check_version_consistency import collect_versions, find_mismatches

ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "release" / "STATUS.json"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_AXES = {
    "portfolio_release": {"LOCAL_VERIFICATION_IN_PROGRESS", "LOCAL_PORTFOLIO_RELEASE_READY"},
    "real_provider": {"NOT_VERIFIED_EXTERNAL"},
    "fresh_windows": {"NOT_VERIFIED_EXTERNAL"},
    "company_production": {"NOT_CLAIMED"},
}
EXPECTED_MARKERS = [
    "PORTFOLIO_RELEASE_CANDIDATE",
    "REAL_PROVIDER_NOT_VERIFIED",
    "FRESH_WINDOWS_NOT_VERIFIED",
    "UNSIGNED_WINDOWS_ASSET",
    "COMPANY_PRODUCTION_NOT_CLAIMED",
]
EXPECTED_NEXT_GATES = {
    "PORTFOLIO_RUNTIME_AND_PUBLICATION_EVIDENCE",
    "PROFESSIONAL_GITHUB_DESTINATION_REQUIRED",
    "GITHUB_PUBLICATION_AND_RELEASE_EVIDENCE",
}


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        status = _mapping(
            json.loads((root / "release" / "STATUS.json").read_text(encoding="utf-8")),
            "status",
        )
        versions = collect_versions(root)
        errors.extend(find_mismatches(versions))
        canonical = versions["backend project.version"]

        if status.get("schema_version") != 5:
            errors.append("schema_version must be 5")
        if status.get("project") != "FlowProof":
            errors.append("project must be FlowProof")
        if status.get("package_version") != canonical:
            errors.append("release status package_version must match the project version")
        if status.get("release_track") != "portfolio_productization":
            errors.append("release_track must be portfolio_productization")
        if status.get("closure_markers") != EXPECTED_MARKERS:
            errors.append("release status must preserve the portfolio boundary markers")
        if status.get("next_gate") not in EXPECTED_NEXT_GATES:
            errors.append("next_gate is not a recognized portfolio-release gate")

        portfolio = _mapping(status.get("portfolio_release"), "portfolio_release")
        if portfolio.get("classification") != "PORTFOLIO_RELEASE_CANDIDATE":
            errors.append("portfolio release must remain an explicit candidate before publication")
        if portfolio.get("publication_state") not in {
            "PRIVATE_UNPUBLISHED",
            "BRANCH_PUBLISHED",
            "PUBLIC_RELEASE_PUBLISHED",
        }:
            errors.append("portfolio publication_state is invalid")
        if portfolio.get("repository_visibility") not in {"PRIVATE", "PUBLIC"}:
            errors.append("repository_visibility must be PRIVATE or PUBLIC")
        if portfolio.get("target_tag") != f"v{canonical}":
            errors.append("target_tag must match the package version")
        _string(portfolio.get("professional_destination"), "professional_destination")

        source = _mapping(status.get("source_state"), "source_state")
        if source.get("base_release") != "v0.5.0":
            errors.append("v0.5.0 must remain the accepted source baseline")
        if not SHA1.fullmatch(_string(source.get("base_commit"), "source_state.base_commit")):
            errors.append("source_state.base_commit must be a SHA-1")
        if source.get("branch") != "codex/showable-niche-product":
            errors.append("source_state.branch must remain the productization branch")
        if not isinstance(source.get("worktree_overlay"), bool):
            errors.append("source_state.worktree_overlay must be boolean")
        if not SHA256.fullmatch(
            _string(
                source.get("recovery_backup_manifest_sha256"),
                "source_state.recovery_backup_manifest_sha256",
            )
        ):
            errors.append("recovery backup manifest digest must be SHA-256")

        local = _mapping(status.get("local_verification"), "local_verification")
        if local.get("status") not in EXPECTED_AXES["portfolio_release"]:
            errors.append("local verification status is invalid")
        for key in (
            "backend",
            "frontend",
            "contracts",
            "secrets",
            "runtime",
            "packaging",
            "visual_qa",
        ):
            _string(local.get(key), f"local_verification.{key}")

        axes = _mapping(status.get("acceptance_axes"), "acceptance_axes")
        if set(axes) != set(EXPECTED_AXES):
            errors.append("release status must contain exactly four acceptance axes")
        for name, allowed in EXPECTED_AXES.items():
            axis = _mapping(axes.get(name), f"acceptance_axes.{name}")
            if axis.get("status") not in allowed:
                errors.append(f"acceptance axis {name} has an invalid status")
            _string(axis.get("required_evidence"), f"acceptance_axes.{name}.required_evidence")

        windows = _mapping(status.get("windows_asset"), "windows_asset")
        if windows.get("target_filename") != f"FlowProof-Windows-x86_64-{canonical}.zip":
            errors.append("Windows target filename must match the package version")
        if windows.get("code_signing") != "UNSIGNED":
            errors.append("the unsigned Windows boundary must remain explicit")
        if windows.get("fresh_machine_proof") != "NOT_VERIFIED_EXTERNAL":
            errors.append("fresh-machine proof must remain external until observed")

        current = _mapping(status.get("current_implementation"), "current_implementation")
        if current.get("architecture") != "CANONICAL_STATIC_COMPOSITION":
            errors.append("current architecture must remain canonical static composition")
        if current.get("migration_head") != "0010_release_groundwork_fencing":
            errors.append("migration head must remain 0010_release_groundwork_fencing")
        if current.get("evidence_capsule_schema") != "1.1":
            errors.append("evidence capsule schema must remain 1.1")
        if current.get("fixture_classification") != "TEST_FIXTURE_ONLY":
            errors.append("fixture evidence must remain TEST_FIXTURE_ONLY")
        if current.get("xero_classification") != "CONTRACT_TESTED_LIVE_OWNER_AUTH_REQUIRED":
            errors.append("Xero must remain contract-tested and owner-auth gated")
        if current.get("xero_recovery_write") != "NOT_IMPLEMENTED":
            errors.append("Xero recovery writes must remain unimplemented")
        if current.get("api_versioning") != "/api/v1":
            errors.append("public API versioning must remain /api/v1")

        baseline = _mapping(status.get("accepted_baseline"), "accepted_baseline")
        if baseline.get("version") != "0.5.0" or baseline.get("pull_request_state") != "MERGED":
            errors.append("accepted v0.5.0 / PR #8 baseline changed unexpectedly")
        if not SHA1.fullmatch(_string(baseline.get("main_merge_sha"), "baseline merge SHA")):
            errors.append("accepted baseline merge must be a SHA-1")
        _string(status.get("evidence_rule"), "evidence_rule")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        errors.append(str(exc))

    release_doc = root / "docs" / "RELEASE_STATUS.md"
    try:
        release_text = release_doc.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"could not read {release_doc}: {exc}")
    else:
        for heading in (
            "## Verdict",
            "## Evidence axes",
            "## Verified locally",
            "## Not verified",
            "## Publication gate",
        ):
            if heading not in release_text:
                errors.append(f"docs/RELEASE_STATUS.md is missing {heading}")
        for marker in EXPECTED_MARKERS:
            if marker not in release_text:
                errors.append(f"docs/RELEASE_STATUS.md is missing {marker}")

    for relative in (
        "backend/src/flowproof/groundwork_bootstrap.py",
        "backend/src/flowproof/groundwork_models.py",
        "backend/src/flowproof/service_v050.py",
        "backend/src/flowproof/service_v050_dispatch.py",
        "backend/src/flowproof/service_v050_ingest.py",
        "backend/src/flowproof/service_v050_reconcile.py",
        "backend/src/flowproof/service_v050_resolution.py",
    ):
        if (root / relative).exists():
            errors.append(f"removed import-time overlay path still exists: {relative}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("Release status check failed:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    axes = status["acceptance_axes"]
    print(
        "Release status check passed: "
        f"{status['package_version']} / "
        f"{status['portfolio_release']['classification']} / "
        f"{axes['portfolio_release']['status']} / "
        f"{axes['real_provider']['status']} / "
        f"{axes['fresh_windows']['status']} / "
        f"{status['portfolio_release']['publication_state']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
