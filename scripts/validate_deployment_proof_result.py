"""Validate the public, secret-free contract of a deployment proof artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import NoReturn

REQUIRED_SECTIONS = (
    "fresh_install",
    "n8n_integration",
    "business_flow",
    "backup",
    "restore",
    "upgrade",
    "rollback",
    "log_redaction",
    "credential_lifetime_policy",
    "credential_expiry_alert",
    "credential_replacement_recovery",
    "credential_replacement_crash_recovery",
    "gitleaks_exact_range",
)
FORBIDDEN_RESULT_KEYS = ("password", "token", "secret", "webhook", "dsn", "path")
FAILURE_MARKERS = ("traceback", "command failed with exit code")
CRASH_RECOVERY_ARTIFACT = "credential-crash-recovery-evidence.json"
CRASH_RECOVERY_POINTS = {
    "after_activation_state_transition",
    "after_active_token_file_switch",
    "after_superseded_credential_revoke",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"deployment proof result validation failed: {message}")


def reject_forbidden_keys(payload: object, *, context: str) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if any(part in str(key).lower() for part in FORBIDDEN_RESULT_KEYS):
                fail(f"{context} contains a forbidden secret-bearing key")
            reject_forbidden_keys(value, context=context)
    elif isinstance(payload, list):
        for value in payload:
            reject_forbidden_keys(value, context=context)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    return parser.parse_args()


def validate_result(payload: object, *, expected_head: str, expected_tree: str) -> None:
    if not isinstance(payload, dict):
        fail("result.json must contain an object")
    reject_forbidden_keys(payload, context="result.json")
    expected = {
        "status": "passed",
        "version": "0.6.0",
        "tested_head_sha": expected_head,
        "tested_tree": expected_tree,
        "volumes_retained": True,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            fail(f"result.json field {key!r} did not match the required value")
    for section in REQUIRED_SECTIONS:
        if payload.get(section) != "passed":
            fail(f"proof section {section!r} was not passed")


def validate_crash_recovery_evidence(audit_root: Path) -> None:
    evidence_files = sorted(audit_root.rglob(CRASH_RECOVERY_ARTIFACT))
    if len(evidence_files) != 1:
        fail(
            f"expected exactly one {CRASH_RECOVERY_ARTIFACT}, found {len(evidence_files)}"
        )
    try:
        payload = json.loads(evidence_files[0].read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"{CRASH_RECOVERY_ARTIFACT} is not valid JSON: {exc.msg}")
    if not isinstance(payload, dict):
        fail(f"{CRASH_RECOVERY_ARTIFACT} must contain an object")
    reject_forbidden_keys(payload, context=CRASH_RECOVERY_ARTIFACT)
    scenarios = payload.get("scenarios")
    if payload.get("result") != "passed" or not isinstance(scenarios, list):
        fail(f"{CRASH_RECOVERY_ARTIFACT} has no passed scenario list")
    seen_points: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            fail(f"{CRASH_RECOVERY_ARTIFACT} contains a non-object scenario")
        point = scenario.get("failure_injection_point")
        if point not in CRASH_RECOVERY_POINTS or point in seen_points:
            fail(f"{CRASH_RECOVERY_ARTIFACT} has an invalid or duplicate injection point")
        seen_points.add(point)
        required = {
            "recovered_after_restart": True,
            "final_operation_status": "finalized",
            "lifecycle": "finalized",
            "superseded_bearer_verification": "verified_401",
            "unexpired_unrevoked_count": 1,
            "expired_unrevoked_count": 0,
        }
        if any(scenario.get(key) != value for key, value in required.items()):
            fail(f"{CRASH_RECOVERY_ARTIFACT} scenario did not converge after restart")
        replacement = scenario.get("replacement_credential_id")
        superseded = scenario.get("superseded_credential_id")
        if (
            not isinstance(replacement, str)
            or not replacement
            or not isinstance(superseded, str)
            or not superseded
            or replacement == superseded
        ):
            fail(f"{CRASH_RECOVERY_ARTIFACT} scenario has invalid credential identifiers")
    if seen_points != CRASH_RECOVERY_POINTS:
        fail(f"{CRASH_RECOVERY_ARTIFACT} did not prove every required crash point")


def main() -> int:
    args = parse_arguments()
    if not args.log.is_file():
        fail("sanitized deployment log is missing")
    log_text = args.log.read_text(encoding="utf-8", errors="replace").lower()
    if any(marker in log_text for marker in FAILURE_MARKERS):
        fail("deployment log contains a failure marker")
    results = sorted(args.audit_root.rglob("result.json")) if args.audit_root.is_dir() else []
    if len(results) != 1:
        fail(f"expected exactly one result.json, found {len(results)}")
    try:
        payload = json.loads(results[0].read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"result.json is not valid JSON: {exc.msg}")
    validate_result(payload, expected_head=args.expected_head, expected_tree=args.expected_tree)
    validate_crash_recovery_evidence(args.audit_root)
    print(json.dumps({"deployment_proof_result": "validated", "version": "0.6.0"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
