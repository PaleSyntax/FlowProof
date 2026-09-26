"""Shared evidence capsule v1.1 constants and immutable indexes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from flowproof import evidence_legacy_v1_core as strict

CAPSULE_SCHEMA_VERSION = "1.1"
LEGACY_CAPSULE_SCHEMA_VERSION = "1.0"
MIGRATION_HEAD = "0010_release_groundwork_fencing"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
EvidenceError = strict.EvidenceError

PROOF_PRE_DISPATCH = "pre_dispatch_review"
PROOF_CHECKPOINT = "durable_nonterminal_checkpoint"
PROOF_EXTERNAL = "external_resolution_without_provider_write"
PROOF_WRITE = "fenced_provider_write_and_authoritative_reread"
PROOF_TYPES = frozenset(
    {
        PROOF_PRE_DISPATCH,
        PROOF_CHECKPOINT,
        PROOF_EXTERNAL,
        PROOF_WRITE,
    }
)

MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "proof_type",
        "package_version",
        "git_commit",
        "git_tree",
        "migration_head",
        "evidence_classification",
        "incident_id",
        "correlation_id",
        "policy_name",
        "policy_version",
        "policy_hash",
        "provider_contract_digest",
        "files",
        "review_subject_sha256",
        "review_subject_digest_scope",
        "bundle_sha256",
        "bundle_digest_scope",
    }
)
REVIEW_SUBJECT_EXCLUDED = frozenset(
    {"operator-review.json", "audit-references.json"}
)
REQUIRED_MEMBERS = frozenset(
    {
        "release-coordinates.json",
        "provider-contract.json",
        "policy.json",
        "incident.json",
        "evaluations.json",
        "timeline-evidence.json",
        "recovery-plan.json",
        "recovery-decisions.json",
        "recovery-attempts.json",
        "transport-invocations.json",
        "postcondition-observations.json",
        "audit-references.json",
        "operator-review.json",
    }
)

CHECKPOINT_ATTEMPT_STATES = frozenset(
    {
        "PREPARED",
        "DISPATCHING",
        "ACCEPTED",
        "OUTCOME_UNKNOWN",
        "PRE_ACCEPTANCE_FAILED",
        "RECONCILING",
        "RECONCILED_EFFECT_PRESENT",
        "RECONCILED_EFFECT_ABSENT",
        "RECONCILED_CONFLICT",
        "NEEDS_ATTENTION",
        "VERIFYING",
        "STILL_FAILED",
    }
)
RESERVATION_STATES = frozenset(
    {
        "OUTCOME_UNRECORDED",
        "DISPATCHING",
        "ACCEPTED",
        "OUTCOME_UNKNOWN",
        "PRE_ACCEPTANCE_FAILED",
        "RECONCILING",
        "EFFECT_PRESENT",
        "EFFECT_ABSENT",
        "CONFLICT",
    }
)
TERMINAL_RESERVATION_STATES = frozenset(
    {
        "ACCEPTED",
        "OUTCOME_UNKNOWN",
        "PRE_ACCEPTANCE_FAILED",
        "EFFECT_PRESENT",
        "EFFECT_ABSENT",
        "CONFLICT",
    }
)
WRITE_OUTCOME_STATES = frozenset(
    {
        "ACCEPTED",
        "OUTCOME_UNKNOWN",
        "PRE_ACCEPTANCE_FAILED",
        "EFFECT_PRESENT",
        "EFFECT_ABSENT",
        "CONFLICT",
    }
)


@dataclass(frozen=True, slots=True)
class ReservationIndex:
    by_id: dict[str, dict[str, Any]]
    by_attempt: dict[str, list[dict[str, Any]]]
