"""Recovery attempt, precondition and reconciliation genealogy for v1.1."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_contract import EvidenceError, ReservationIndex
from flowproof.evidence_semantics import SemanticContext

ATTEMPT_FIELDS = frozenset(
    {
        "id",
        "recovery_plan_id",
        "incident_id",
        "approval_decision_id",
        "active_transport_invocation_id",
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
        "lock_version",
    }
)


def validate_attempts(
    context: SemanticContext,
    decisions: dict[str, dict[str, Any]],
    reservations: ReservationIndex,
) -> None:
    if len(context.attempts) > 1:
        raise EvidenceError(
            "capsule exceeds the one-semantic-attempt boundary"
        )
    seen_ids: set[str] = set()
    for attempt in context.attempts:
        if set(attempt) != ATTEMPT_FIELDS:
            raise EvidenceError(
                "recovery attempt schema is incomplete"
            )
        attempt_id = attempt.get("id")
        if (
            not isinstance(attempt_id, str)
            or not attempt_id
            or attempt_id in seen_ids
            or attempt.get("recovery_plan_id")
            != context.plan.get("id")
            or attempt.get("incident_id")
            != context.incident.get("id")
            or attempt.get("plan_hash")
            != context.plan.get("plan_hash")
            or attempt.get("provider_contract_digest")
            != context.plan.get("provider_contract_digest")
            or attempt.get("provider_id")
            != context.provider.provider_id
            or attempt.get("provider_environment")
            != context.provider.environment
            or attempt.get("adapter_version")
            != context.provider.adapter_version
        ):
            raise EvidenceError(
                "recovery attempt identity is invalid"
            )
        seen_ids.add(attempt_id)

        if (
            attempt.get("attempt_ordinal") != 1
            or attempt.get("semantic_attempt_count") != 1
            or not _positive_int(attempt.get("lock_version"))
            or not strict.SHA256.fullmatch(
                str(
                    attempt.get(
                        "execution_idempotency_key_digest"
                    )
                )
            )
            or not strict.SHA256.fullmatch(
                str(attempt.get("request_digest"))
            )
        ):
            raise EvidenceError(
                "recovery attempt count, version or digest is invalid"
            )
        if attempt.get("request_digest") != strict._object_sha256(
            context.plan.get("parameters")
        ):
            raise EvidenceError(
                "attempt request digest mismatch"
            )
        if (
            attempt.get("execution_idempotency_key_digest")
            != context.plan.get("idempotency_key_digest")
        ):
            raise EvidenceError(
                "attempt idempotency binding mismatch"
            )

        approval = decisions.get(
            str(attempt.get("approval_decision_id"))
        )
        if (
            approval is None
            or approval.get("action") != "approve"
            or approval.get("decision_kind") != "human"
            or approval.get("plan_hash")
            != context.plan.get("plan_hash")
            or approval.get("provider_contract_digest")
            != context.plan.get("provider_contract_digest")
        ):
            raise EvidenceError(
                "durable attempt approval binding is invalid"
            )
        created_at = strict._evidence_time(
            attempt.get("created_at"),
            "attempt.created_at",
        )
        updated_at = strict._evidence_time(
            attempt.get("updated_at"),
            "attempt.updated_at",
        )
        approved_at = strict._evidence_time(
            approval.get("decided_at"),
            "attempt.approval.decided_at",
        )
        approval_expires_at = strict._evidence_time(
            approval.get("approval_expires_at"),
            "attempt.approval.approval_expires_at",
        )
        if not approved_at <= created_at < approval_expires_at:
            raise EvidenceError(
                "durable attempt was not prepared under active approval"
            )
        if updated_at < created_at:
            raise EvidenceError(
                "attempt update timestamp predates creation"
            )

        rows = reservations.by_attempt.get(attempt_id, [])
        invocation_count = attempt.get(
            "transport_invocation_count"
        )
        if (
            not isinstance(invocation_count, int)
            or isinstance(invocation_count, bool)
            or invocation_count < 0
            or invocation_count != len(rows)
        ):
            raise EvidenceError(
                "attempt transport count does not match reservation ledger"
            )
        active_id = attempt.get(
            "active_transport_invocation_id"
        )
        if active_id is not None and active_id not in reservations.by_id:
            raise EvidenceError(
                "attempt active reservation is missing"
            )
        if rows and active_id != rows[-1]["id"]:
            raise EvidenceError(
                "attempt active reservation is not the latest reservation"
            )
        if not rows and active_id is not None:
            raise EvidenceError(
                "zero-reservation attempt retains an active reservation"
            )

        safe_result = attempt.get("safe_result")
        if not isinstance(safe_result, dict):
            raise EvidenceError(
                "attempt safe_result is invalid"
            )
        _validate_precondition(
            context,
            attempt,
            safe_result,
        )
        _validate_reconciliation_history(
            context,
            attempt,
            reservations,
            updated_at=updated_at,
        )


def _validate_precondition(
    context: SemanticContext,
    attempt: dict[str, Any],
    safe_result: dict[str, Any],
) -> None:
    precondition = safe_result.get("precondition")
    typed = strict._validate_observation(
        precondition,
        field_name="attempt.precondition",
        classification="AVAILABLE_ABSENT",
        entity_id=str(context.incident["entity_id"]),
        provider=context.provider,
    )
    if typed.get("content_digest") != attempt.get(
        "precondition_observation_digest"
    ):
        raise EvidenceError(
            "attempt precondition observation digest mismatch"
        )
    observed_at = strict._evidence_time(
        typed.get("observed_at"),
        "attempt.precondition.observed_at",
    )
    created_at = strict._evidence_time(
        attempt.get("created_at"),
        "attempt.created_at",
    )
    if observed_at > created_at:
        raise EvidenceError(
            "attempt precondition was observed after durable intent"
        )


def _validate_reconciliation_history(
    context: SemanticContext,
    attempt: dict[str, Any],
    reservations: ReservationIndex,
    *,
    updated_at: datetime,
) -> None:
    safe_result = attempt["safe_result"]
    history = safe_result.get(
        "reconciliation_history",
        [],
    )
    if not isinstance(history, list):
        raise EvidenceError(
            "attempt reconciliation history is not append-only list data"
        )
    previous_time: datetime | None = None
    previous_generation_by_reservation: dict[str, int] = {}
    for entry in history:
        required = {
            "reservation_id",
            "observation",
            "reconciled_at",
            "prior_attempt_state",
            "prior_reservation_state",
            "transport_invocation_count",
            "reapproval_action",
            "retry_reason",
            "write_outcome",
            "reconciliation_claim",
        }
        if not isinstance(entry, dict) or set(entry) != required:
            raise EvidenceError(
                "attempt reconciliation history entry is incomplete"
            )
        reservation_id = entry.get("reservation_id")
        if (
            reservation_id is not None
            and reservation_id not in reservations.by_id
        ):
            raise EvidenceError(
                "attempt reconciliation history names unknown reservation"
            )
        reconciled_at = strict._evidence_time(
            entry.get("reconciled_at"),
            "reconciliation_history.reconciled_at",
        )
        if (
            previous_time is not None
            and reconciled_at < previous_time
        ):
            raise EvidenceError(
                "attempt reconciliation history is not chronological"
            )
        if reconciled_at > updated_at:
            raise EvidenceError(
                "attempt reconciliation history exceeds attempt update time"
            )
        previous_time = reconciled_at

        observation = entry.get("observation")
        classification = (
            observation.get("classification")
            if isinstance(observation, dict)
            else None
        )
        if not isinstance(classification, str):
            raise EvidenceError(
                "attempt reconciliation history observation is untyped"
            )
        strict._validate_observation(
            observation,
            field_name=(
                "reconciliation_history.observation"
            ),
            classification=classification,
            entity_id=str(context.incident["entity_id"]),
            provider=context.provider,
            require_authoritative=(
                classification.startswith("AVAILABLE_")
            ),
        )
        write_outcome = entry.get("write_outcome")
        if write_outcome is not None:
            if not isinstance(write_outcome, dict):
                raise EvidenceError(
                    "reconciliation history write outcome is invalid"
                )
            write_classification = write_outcome.get(
                "classification"
            )
            strict._validate_write_outcome(
                write_outcome,
                expected_classification=write_classification,
                provider=context.provider,
            )

        claim = entry.get("reconciliation_claim")
        if (
            not isinstance(claim, dict)
            or set(claim)
            != {
                "owner",
                "generation",
                "reservation_lock_version",
                "attempt_lock_version",
                "lease_expires_at",
                "reason",
            }
        ):
            raise EvidenceError(
                "attempt reconciliation claim genealogy is incomplete"
            )
        generation = claim.get("generation")
        key = str(reservation_id)
        previous_generation = (
            previous_generation_by_reservation.get(key, 0)
        )
        if (
            not _positive_int(generation)
            or generation <= previous_generation
            or not claim.get("owner")
            or not claim.get("reason")
            or not _positive_int(
                claim.get("attempt_lock_version")
            )
            or (
                reservation_id is not None
                and not _positive_int(
                    claim.get("reservation_lock_version")
                )
            )
        ):
            raise EvidenceError(
                "attempt reconciliation claim genealogy is invalid"
            )
        lease_expires_at = strict._evidence_time(
            claim.get("lease_expires_at"),
            "reconciliation_claim.lease_expires_at",
        )
        if reconciled_at > lease_expires_at:
            raise EvidenceError(
                "reconciliation observation completed after claim lease"
            )
        previous_generation_by_reservation[key] = generation


def _positive_int(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
    )
