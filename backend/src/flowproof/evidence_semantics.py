"""Common strict semantic layer shared by all declared v1.1 proof paths."""

from __future__ import annotations

import copy
import tempfile
import zipfile
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from flowproof import evidence_legacy_v1_core as strict
from flowproof.accounting import ProviderContract
from flowproof.evidence_contract import (
    PROOF_EXTERNAL,
    PROOF_PRE_DISPATCH,
    PROOF_TYPES,
    EvidenceError,
)


@dataclass(frozen=True, slots=True)
class SemanticContext:
    manifest: dict[str, Any]
    documents: dict[str, Any]
    provider: ProviderContract
    incident: dict[str, Any]
    plan: dict[str, Any]
    policy: dict[str, Any]
    timeline: list[dict[str, Any]]
    evaluations: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    attempts: list[dict[str, Any]]
    reservations: list[dict[str, Any]]


def verify_common_semantics(
    manifest: dict[str, Any],
    documents: dict[str, Any],
    *,
    expected_git_commit: str,
    expected_git_tree: str,
    proof_type: str,
) -> SemanticContext:
    """Verify stable v1 semantics before v1.1 fencing genealogy."""

    if proof_type not in PROOF_TYPES:
        raise EvidenceError(
            "declared evidence proof type is unsupported"
        )
    coordinates = object_document(
        documents,
        "release-coordinates.json",
    )
    provider_document = object_document(
        documents,
        "provider-contract.json",
    )
    policy = object_document(documents, "policy.json")
    incident = object_document(documents, "incident.json")
    plan = object_document(documents, "recovery-plan.json")
    timeline = object_list(documents, "timeline-evidence.json")
    evaluations = object_list(documents, "evaluations.json")
    decisions = object_list(
        documents,
        "recovery-decisions.json",
    )
    attempts = object_list(
        documents,
        "recovery-attempts.json",
    )
    reservations = object_list(
        documents,
        "transport-invocations.json",
    )

    if (
        coordinates.get("git_commit") != expected_git_commit
        or coordinates.get("git_tree") != expected_git_tree
        or manifest.get("git_commit") != expected_git_commit
        or manifest.get("git_tree") != expected_git_tree
        or coordinates.get("proof_type") != proof_type
        or manifest.get("proof_type") != proof_type
    ):
        raise EvidenceError(
            "capsule does not match exact Git coordinates and proof type"
        )

    contract_digest = provider_document.get("sha256")
    if (
        not isinstance(contract_digest, str)
        or not strict.SHA256.fullmatch(contract_digest)
    ):
        raise EvidenceError("provider contract digest is invalid")
    provider_body = {
        key: value
        for key, value in provider_document.items()
        if key != "sha256"
    }
    try:
        provider = ProviderContract(**provider_body)
    except (TypeError, ValueError) as exc:
        raise EvidenceError(
            "provider contract content is invalid"
        ) from exc
    if provider.digest != contract_digest:
        raise EvidenceError(
            "provider contract content digest mismatch"
        )

    definition = policy.get("definition")
    if (
        not isinstance(definition, dict)
        or policy.get("definition_hash")
        != strict._object_sha256(definition)
        or policy.get("definition_hash")
        != manifest.get("policy_hash")
        or policy.get("name") != manifest.get("policy_name")
        or policy.get("version") != manifest.get("policy_version")
    ):
        raise EvidenceError(
            "policy identity or definition hash mismatch"
        )
    if (
        incident.get("id") != manifest.get("incident_id")
        or incident.get("id") != plan.get("incident_id")
        or incident.get("correlation_id")
        != manifest.get("correlation_id")
        or incident.get("policy_name") != policy.get("name")
        or incident.get("policy_version") != policy.get("version")
        or plan.get("provider_contract_digest") != contract_digest
        or manifest.get("provider_contract_digest") != contract_digest
    ):
        raise EvidenceError(
            "incident, policy, plan, correlation or provider identity mismatch"
        )

    strict._validate_plan_semantics(
        plan,
        incident,
        policy,
        timeline,
        provider,
        contract_digest,
    )
    expected_plan_hash = strict._object_sha256(
        {
            "action_type": plan.get("action_type"),
            "parameters": plan.get("parameters"),
            "guardrails": plan.get("guardrails"),
            "provider_contract_digest": contract_digest,
        }
    )
    if plan.get("plan_hash") != expected_plan_hash:
        raise EvidenceError(
            "recovery plan content digest mismatch"
        )

    _verify_v1_compatibility_projection(
        documents,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
        proof_type=proof_type,
    )
    return SemanticContext(
        manifest=manifest,
        documents=documents,
        provider=provider,
        incident=incident,
        plan=plan,
        policy=policy,
        timeline=timeline,
        evaluations=evaluations,
        decisions=decisions,
        attempts=attempts,
        reservations=reservations,
    )


def _verify_v1_compatibility_projection(
    documents: dict[str, Any],
    *,
    expected_git_commit: str,
    expected_git_tree: str,
    proof_type: str,
) -> None:
    projected = _legacy_projection(
        documents,
        proof_type=proof_type,
    )
    coordinates = object_document(
        projected,
        "release-coordinates.json",
    )
    incident = object_document(projected, "incident.json")
    provider = object_document(
        projected,
        "provider-contract.json",
    )
    policy = object_document(projected, "policy.json")
    declarations = [
        {
            "name": name,
            "size": len(strict._json_bytes(value)),
            "sha256": strict._sha256(
                strict._json_bytes(value)
            ),
        }
        for name, value in sorted(projected.items())
    ]
    review = [
        item
        for item in declarations
        if item["name"] not in strict.REVIEW_SUBJECT_EXCLUDED
    ]
    review_subject_sha256 = strict._sha256(
        strict._json_bytes(review)
    )
    operator_review = projected.get("operator-review.json")
    rebound_review = False
    if isinstance(operator_review, list):
        for review_entry in operator_review:
            if (
                isinstance(review_entry, dict)
                and review_entry.get("capsule_digest") is not None
            ):
                review_entry["capsule_digest"] = review_subject_sha256
                rebound_review = True
    if rebound_review:
        declarations = [
            {
                "name": name,
                "size": len(strict._json_bytes(value)),
                "sha256": strict._sha256(
                    strict._json_bytes(value)
                ),
            }
            for name, value in sorted(projected.items())
        ]
    manifest = {
        "schema_version": strict.CAPSULE_SCHEMA_VERSION,
        "package_version": coordinates["package_version"],
        "git_commit": coordinates["git_commit"],
        "git_tree": coordinates["git_tree"],
        "migration_head": strict.MIGRATION_HEAD,
        "evidence_classification": coordinates[
            "evidence_classification"
        ],
        "incident_id": incident["id"],
        "correlation_id": incident["correlation_id"],
        "policy_name": policy["name"],
        "policy_version": policy["version"],
        "policy_hash": policy["definition_hash"],
        "provider_contract_digest": provider["sha256"],
        "files": declarations,
        "review_subject_sha256": review_subject_sha256,
        "review_subject_digest_scope": (
            "canonical declared evidence members excluding the "
            "operator review and its security-audit reference"
        ),
        "bundle_sha256": strict._sha256(
            strict._json_bytes(declarations)
        ),
        "bundle_digest_scope": (
            "canonical declared evidence members; manifest is the root"
        ),
    }
    with tempfile.TemporaryDirectory(
        prefix="flowproof-v11-common-semantic-"
    ) as directory:
        path = Path(directory) / "compatibility-v1.zip"
        with zipfile.ZipFile(
            path,
            "w",
            compression=zipfile.ZIP_STORED,
            strict_timestamps=True,
        ) as archive:
            members = {
                "manifest.json": strict._json_bytes(manifest),
                **{
                    name: strict._json_bytes(value)
                    for name, value in projected.items()
                },
            }
            for name, content in sorted(members.items()):
                info = zipfile.ZipInfo(
                    name,
                    date_time=strict.FIXED_ZIP_TIME,
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o600 << 16
                archive.writestr(info, content)
        strict.verify_capsule(
            path,
            expected_bundle_sha256=manifest["bundle_sha256"],
            expected_git_commit=expected_git_commit,
            expected_git_tree=expected_git_tree,
        )


def _legacy_projection(
    documents: dict[str, Any],
    *,
    proof_type: str,
) -> dict[str, Any]:
    projected = copy.deepcopy(documents)
    coordinates = object_document(
        projected,
        "release-coordinates.json",
    )
    coordinates.pop("proof_type", None)
    coordinates["migration_head"] = strict.MIGRATION_HEAD

    incident = object_document(projected, "incident.json")
    incident["evidence"] = strict._safe_observation(
        incident.get("evidence", {})
    )
    plan = object_document(projected, "recovery-plan.json")
    plan["result"] = strict._safe_observation(
        plan.get("result", {})
    )
    for evaluation in object_list(
        projected,
        "evaluations.json",
    ):
        evaluation["evidence"] = strict._safe_observation(
            evaluation.get("evidence", {})
        )
    projected["postcondition-observations.json"] = [
        strict._safe_observation(value)
        for value in projected[
            "postcondition-observations.json"
        ]
    ]
    for event in object_list(projected, "timeline-evidence.json"):
        event.pop("payload", None)
    projected["recovery-attempts.json"] = [
        _legacy_attempt(attempt)
        for attempt in object_list(
            projected,
            "recovery-attempts.json",
        )
    ]
    projected["transport-invocations.json"] = [
        {
            key: reservation[key]
            for key in (
                "id",
                "recovery_attempt_id",
                "recovery_plan_id",
                "approval_decision_id",
                "invocation_ordinal",
                "request_digest",
                "reserved_at",
            )
        }
        for reservation in object_list(
            projected,
            "transport-invocations.json",
        )
    ]

    if proof_type == PROOF_PRE_DISPATCH:
        projected["recovery-attempts.json"] = []
        projected["transport-invocations.json"] = []
    if proof_type == PROOF_EXTERNAL:
        plan["status"] = "proposed"
        plan["result"] = {}
        plan["executed_at"] = None
        plan["verified_at"] = None
        plan["approved_at"] = None
        plan["approval_expires_at"] = None
        plan["approval_actor"] = None
        incident["status"] = "recovery_proposed"
        incident["resolved_at"] = None
        projected["recovery-attempts.json"] = []
        projected["transport-invocations.json"] = []
        projected["recovery-decisions.json"] = []
        projected["evaluations.json"] = [
            evaluation
            for evaluation in object_list(
                projected,
                "evaluations.json",
            )
            if not (
                evaluation.get("invariant_id")
                == incident.get("invariant_id")
                and evaluation.get("state") == "passed"
            )
        ]
        historical = [
            evaluation
            for evaluation in projected["evaluations.json"]
            if evaluation.get("invariant_id")
            == incident.get("invariant_id")
            and evaluation.get("state") != "passed"
            and isinstance(evaluation.get("evidence"), dict)
        ]
        if not historical:
            raise EvidenceError(
                "external resolution lacks its original incident evaluation"
            )
        incident["evidence"] = historical[-1]["evidence"]
        projected["postcondition-observations.json"] = [
            evaluation["evidence"]
            for evaluation in historical
        ]
    return projected


def _legacy_attempt(
    attempt: dict[str, Any],
) -> dict[str, Any]:
    keys = (
        "id",
        "recovery_plan_id",
        "incident_id",
        "approval_decision_id",
        "attempt_ordinal",
        "execution_idempotency_key_digest",
        "plan_hash",
        "provider_contract_digest",
        "provider_id",
        "provider_environment",
        "adapter_version",
        "request_digest",
        "precondition_observation_digest",
        "state",
        "outcome_classification",
        "provider_operation_reference",
        "retry_after_seconds",
        "semantic_attempt_count",
        "transport_invocation_count",
        "retry_permitted",
        "retry_reason",
        "safe_result",
        "created_at",
        "updated_at",
        "accepted_at",
        "reconciled_at",
    )
    projected = {
        key: (
            strict._safe_observation(
                attempt.get("safe_result", {})
            )
            if key == "safe_result"
            else attempt.get(key)
        )
        for key in keys
    }
    safe_result = projected.get("safe_result")
    if isinstance(safe_result, dict):
        history = safe_result.get("reconciliation_history")
        if isinstance(history, list):
            legacy_history = [
                {
                    key: entry.get(key)
                    for key in (
                        "observation",
                        "reconciled_at",
                        "reapproval_action",
                        "transport_invocation_count",
                        "prior_attempt_state",
                        "retry_reason",
                        "write_outcome",
                    )
                }
                for entry in history
                if isinstance(entry, dict)
                and entry.get("reapproval_action") is not None
            ]
            if legacy_history:
                safe_result["reconciliation_history"] = legacy_history
                projected["retry_reason"] = legacy_history[-1][
                    "retry_reason"
                ]
            else:
                safe_result.pop("reconciliation_history", None)
    return projected


def latest_incident_evaluation(
    context: SemanticContext,
) -> dict[str, Any]:
    candidates = [
        evaluation
        for evaluation in context.evaluations
        if evaluation.get("invariant_id")
        == context.incident.get("invariant_id")
    ]
    if not candidates:
        raise EvidenceError(
            "capsule lacks an evaluation for the incident invariant"
        )
    return max(
        candidates,
        key=lambda value: strict._evidence_time(
            value.get("evaluated_at"),
            "evaluation.evaluated_at",
        ),
    )


def validate_present_observation(
    context: SemanticContext,
    evidence: object,
    *,
    field_name: str,
) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise EvidenceError(
            f"{field_name} does not contain evidence"
        )
    observation = evidence.get("observation", evidence)
    typed = strict._validate_observation(
        observation,
        field_name=field_name,
        classification="AVAILABLE_PRESENT",
        entity_id=str(context.incident["entity_id"]),
        provider=context.provider,
    )
    record = typed["records"][0]
    parameters = context.plan["parameters"]
    record_id = record.get("invoice_id", record.get("id"))
    try:
        amount_matches = Decimal(
            str(record.get("amount"))
        ) == Decimal(str(parameters["amount"]))
    except (InvalidOperation, TypeError, ValueError):
        amount_matches = False
    if (
        str(record_id) != str(parameters["invoice_id"])
        or str(record.get("currency"))
        != str(parameters["currency"])
        or not amount_matches
    ):
        raise EvidenceError(
            f"{field_name} does not prove exact entity, amount and currency"
        )
    return typed


def object_document(
    documents: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    value = documents.get(name)
    if not isinstance(value, dict):
        raise EvidenceError(
            f"{name} must contain a JSON object"
        )
    return value


def object_list(
    documents: dict[str, Any],
    name: str,
) -> list[dict[str, Any]]:
    value = documents.get(name)
    if (
        not isinstance(value, list)
        or any(not isinstance(item, dict) for item in value)
    ):
        raise EvidenceError(
            f"{name} must contain a JSON object list"
        )
    return value
