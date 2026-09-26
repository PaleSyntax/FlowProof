"""Validate the committed n8n exports without requiring an n8n account."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / "workflows"
REQUIRED = {
    "invoice-intake.json": {"invoice.received", "invoice.validated"},
    "invoice-approval.json": {
        "invoice.approved",
        "invoice.registration_requested",
        "invoice.registration_acknowledged",
    },
    "invoice-recovery.json": {"recovery.execution_started", "recovery.executed"},
    "flowproof-error-handler.json": {"technical.workflow_failed"},
}
SECRET_VALUE = re.compile(
    r"(?:sk-[A-Za-z0-9]{12,}|gh[pous]_[A-Za-z0-9]{12,}|Bearer\s+[A-Za-z0-9._-]{12,})"
)
ABSOLUTE_USER_PATH = re.compile(r"(?:[A-Za-z]:\\Users\\|/Users/)", re.IGNORECASE)


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in strings(child)]
    return []


def validate(path: Path, expected_events: set[str]) -> list[str]:
    errors: list[str] = []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path.name}: invalid JSON: {exc}"]
    for key in ("name", "nodes", "connections", "settings"):
        if key not in document:
            errors.append(f"{path.name}: missing top-level {key}")
    if not isinstance(document.get("nodes"), list) or not document["nodes"]:
        return errors + [f"{path.name}: nodes must be a non-empty list"]
    names = [node.get("name") for node in document["nodes"]]
    if any(not isinstance(name, str) or not name for name in names):
        errors.append(f"{path.name}: every node needs a name")
    if len(names) != len(set(names)):
        errors.append(f"{path.name}: node names must be unique")
    node_names = set(names)
    for source, branches in document.get("connections", {}).items():
        if source not in node_names:
            errors.append(f"{path.name}: connection source {source!r} does not exist")
        for branch in branches.get("main", []):
            for target in branch:
                if target.get("node") not in node_names:
                    errors.append(
                        f"{path.name}: connection target {target.get('node')!r} does not exist"
                    )
    if document.get("active") is not False:
        errors.append(f"{path.name}: committed workflow must be inactive")
    if document.get("pinData"):
        errors.append(f"{path.name}: pinData is not allowed")
    all_strings = strings(document)
    for value in all_strings:
        if SECRET_VALUE.search(value):
            errors.append(f"{path.name}: contains a credential-like literal")
        if ABSOLUTE_USER_PATH.search(value):
            errors.append(f"{path.name}: contains an absolute user path")
        if "$env." in value:
            errors.append(
                f"{path.name}: environment expressions are forbidden in committed exports"
            )
    for node in document["nodes"]:
        for credential in node.get("credentials", {}).values():
            if credential.get("id") not in {None, "flowproof-api-service-account"}:
                errors.append(f"{path.name}: contains an unapproved credential ID")
        if node.get("type") == "n8n-nodes-base.webhook" and not node.get("webhookId"):
            errors.append(f"{path.name}: webhook node needs a stable webhookId")
        parameters = node.get("parameters")
        if not isinstance(parameters, dict):
            continue
        url = parameters.get("url")
        if not isinstance(url, str) or "/api/v1/" not in url:
            continue
        if parameters.get("authentication") != "genericCredentialType":
            errors.append(
                f"{path.name}: FlowProof request must use a credential-store auth type"
            )
        if parameters.get("genericAuthType") != "httpHeaderAuth":
            errors.append(f"{path.name}: FlowProof request must use HTTP Header Auth")
        credential = node.get("credentials", {}).get("httpHeaderAuth", {})
        if credential.get("name") != "FlowProof API service account":
            errors.append(
                f"{path.name}: FlowProof request lacks the provisioned service credential"
            )
        if credential.get("id") != "flowproof-api-service-account":
            errors.append(
                f"{path.name}: FlowProof credential must use the provisioned stable ID"
            )
    missing = {
        event
        for event in expected_events
        if not any(event in value for value in all_strings)
    }
    if missing:
        errors.append(f"{path.name}: missing expected events {sorted(missing)}")
    if path.name in {"invoice-intake.json", "invoice-approval.json"} and any(
        "$json.invoice" in value or "$json.idempotency_prefix" in value
        for value in all_strings
    ):
        errors.append(f"{path.name}: invoice context must reference its Normalize node")
    return errors


def main() -> int:
    errors = []
    for filename, expected_events in REQUIRED.items():
        errors.extend(validate(WORKFLOWS / filename, expected_events))
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Validated {len(REQUIRED)} n8n workflow exports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
