"""Transport reservation identity, authority and outcome genealogy for v1.1."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_contract import (
    RESERVATION_STATES,
    TERMINAL_RESERVATION_STATES,
    EvidenceError,
    ReservationIndex,
)
from flowproof.evidence_semantics import SemanticContext

RESERVATION_FIELDS = frozenset(
    {
        "id",
        "recovery_attempt_id",
        "recovery_plan_id",
        "approval_decision_id",
        "invocation_ordinal",
        "request_digest",
        "reserved_at",
        "state",
        "dispatch_owner",
        "dispatch_generation",
        "dispatch_started_at",
        "dispatch_lease_expires_at",
        "abandoned_at",
        "abandoned_by",
        "abandonment_reason",
        "reconciliation_owner",
        "reconciliation_generation",
        "reconciliation_started_at",
        "reconciliation_lease_expires_at",
        "reconciliation_abandoned_at",
        "outcome_classification",
        "outcome_observed_at",
        "provider_operation_reference",
        "retry_after_seconds",
        "safe_outcome",
        "completed_at",
        "lock_version",
    }
)


def validate_reservations(
    context: SemanticContext,
    decisions: dict[str, dict[str, Any]],
) -> ReservationIndex:
    attempt_ids = {
        str(attempt.get("id"))
        for attempt in context.attempts
    }
    by_id: dict[str, dict[str, Any]] = {}
    by_attempt: dict[str, list[dict[str, Any]]] = {}
    ordinals: set[tuple[str, int]] = set()
    previous_reserved_at: datetime | None = None

    for reservation in context.reservations:
        if set(reservation) != RESERVATION_FIELDS:
            raise EvidenceError(
                "transport reservation schema is incomplete"
            )
        reservation_id = reservation.get("id")
        attempt_id = reservation.get("recovery_attempt_id")
        ordinal = reservation.get("invocation_ordinal")
        if (
            not isinstance(reservation_id, str)
            or not reservation_id
            or reservation_id in by_id
            or not isinstance(attempt_id, str)
            or attempt_id not in attempt_ids
            or reservation.get("recovery_plan_id")
            != context.plan.get("id")
            or not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal < 1
            or (attempt_id, ordinal) in ordinals
            or not strict.SHA256.fullmatch(
                str(reservation.get("request_digest"))
            )
        ):
            raise EvidenceError(
                "transport reservation identity is invalid"
            )
        state = reservation.get("state")
        if state not in RESERVATION_STATES:
            raise EvidenceError(
                "transport reservation state is invalid"
            )
        reserved_at = strict._evidence_time(
            reservation.get("reserved_at"),
            "reservation.reserved_at",
        )
        if (
            previous_reserved_at is not None
            and reserved_at < previous_reserved_at
        ):
            raise EvidenceError(
                "transport reservations are not chronological"
            )
        previous_reserved_at = reserved_at

        approval = decisions.get(
            str(reservation.get("approval_decision_id"))
        )
        if (
            approval is None
            or approval.get("action") != "approve"
            or approval.get("decision_kind") != "human"
            or approval.get("recovery_plan_id")
            != context.plan.get("id")
        ):
            raise EvidenceError(
                "transport reservation lacks exact human approval"
            )
        approved_at = strict._evidence_time(
            approval.get("decided_at"),
            "reservation.approval.decided_at",
        )
        expires_at = strict._evidence_time(
            approval.get("approval_expires_at"),
            "reservation.approval.approval_expires_at",
        )
        if not approved_at <= reserved_at < expires_at:
            raise EvidenceError(
                "transport reservation was not created under active consent"
            )

        lock_version = reservation.get("lock_version")
        dispatch_generation = reservation.get(
            "dispatch_generation"
        )
        reconciliation_generation = reservation.get(
            "reconciliation_generation"
        )
        if (
            not _positive_int(lock_version)
            or not _positive_int(dispatch_generation)
            or not _nonnegative_int(reconciliation_generation)
        ):
            raise EvidenceError(
                "transport reservation version or generation is invalid"
            )
        safe_outcome = reservation.get("safe_outcome")
        if not isinstance(safe_outcome, dict):
            raise EvidenceError(
                "transport reservation safe_outcome is invalid"
            )
        _validate_dispatch_authority(
            reservation,
            reserved_at=reserved_at,
        )
        _validate_reconciliation_authority(reservation)
        _validate_outcome(context, reservation)
        _validate_claim_history(reservation)

        by_id[reservation_id] = reservation
        by_attempt.setdefault(attempt_id, []).append(
            reservation
        )
        ordinals.add((attempt_id, ordinal))

    for rows in by_attempt.values():
        rows.sort(key=lambda item: item["invocation_ordinal"])
        if [row["invocation_ordinal"] for row in rows] != list(
            range(1, len(rows) + 1)
        ):
            raise EvidenceError(
                "transport reservation ordinals are not contiguous"
            )
    return ReservationIndex(
        by_id=by_id,
        by_attempt=by_attempt,
    )


def _validate_dispatch_authority(
    reservation: dict[str, Any],
    *,
    reserved_at: datetime,
) -> None:
    owner = reservation.get("dispatch_owner")
    started_raw = reservation.get("dispatch_started_at")
    lease_raw = reservation.get("dispatch_lease_expires_at")
    if not isinstance(owner, str) or not owner:
        raise EvidenceError(
            "transport reservation lacks dispatch owner"
        )
    started_at = strict._evidence_time(
        started_raw,
        "reservation.dispatch_started_at",
    )
    lease_expires_at = strict._evidence_time(
        lease_raw,
        "reservation.dispatch_lease_expires_at",
    )
    if not reserved_at <= started_at < lease_expires_at:
        raise EvidenceError(
            "transport reservation dispatch timestamps are invalid"
        )
    abandoned_at = reservation.get("abandoned_at")
    if abandoned_at is not None:
        abandoned = strict._evidence_time(
            abandoned_at,
            "reservation.abandoned_at",
        )
        if (
            abandoned < started_at
            or not reservation.get("abandoned_by")
            or not reservation.get("abandonment_reason")
        ):
            raise EvidenceError(
                "transport reservation abandonment is invalid"
            )
    elif (
        reservation.get("abandoned_by") is not None
        or reservation.get("abandonment_reason") is not None
    ):
        raise EvidenceError(
            "transport reservation has partial abandonment evidence"
        )


def _validate_reconciliation_authority(
    reservation: dict[str, Any],
) -> None:
    generation = reservation["reconciliation_generation"]
    owner = reservation.get("reconciliation_owner")
    started_raw = reservation.get("reconciliation_started_at")
    lease_raw = reservation.get(
        "reconciliation_lease_expires_at"
    )
    abandoned_raw = reservation.get(
        "reconciliation_abandoned_at"
    )
    if generation == 0:
        if any(
            value is not None
            for value in (
                owner,
                started_raw,
                lease_raw,
                abandoned_raw,
            )
        ):
            raise EvidenceError(
                "zero-generation reservation retains reconciliation authority"
            )
        return
    if not isinstance(owner, str) or not owner:
        raise EvidenceError(
            "reconciliation generation lacks owner"
        )
    started_at = strict._evidence_time(
        started_raw,
        "reservation.reconciliation_started_at",
    )
    lease_expires_at = strict._evidence_time(
        lease_raw,
        "reservation.reconciliation_lease_expires_at",
    )
    if started_at >= lease_expires_at:
        raise EvidenceError(
            "reconciliation lease timestamps are invalid"
        )
    if abandoned_raw is not None:
        abandoned_at = strict._evidence_time(
            abandoned_raw,
            "reservation.reconciliation_abandoned_at",
        )
        if abandoned_at < started_at:
            raise EvidenceError(
                "reconciliation abandonment predates claim"
            )


def _validate_outcome(
    context: SemanticContext,
    reservation: dict[str, Any],
) -> None:
    state = reservation["state"]
    safe_outcome = reservation["safe_outcome"]
    completed_at = reservation.get("completed_at")
    if state in TERMINAL_RESERVATION_STATES:
        strict._evidence_time(
            completed_at,
            "reservation.completed_at",
        )
    elif completed_at is not None and state != "RECONCILING":
        raise EvidenceError(
            "nonterminal reservation has terminal completion time"
        )

    write_outcome = safe_outcome.get("provider_write_outcome")
    provider_exception = safe_outcome.get("provider_exception")
    if isinstance(write_outcome, dict):
        classification = write_outcome.get("classification")
        strict._validate_write_outcome(
            write_outcome,
            expected_classification=classification,
            provider=context.provider,
        )
    elif provider_exception is not None:
        if (
            state != "OUTCOME_UNKNOWN"
            or not isinstance(provider_exception, dict)
        ):
            raise EvidenceError(
                "provider exception evidence contradicts reservation state"
            )
    elif state in {"ACCEPTED", "PRE_ACCEPTANCE_FAILED"}:
        raise EvidenceError(
            "typed terminal provider outcome is missing"
        )

    authoritative = safe_outcome.get(
        "authoritative_reconciliation"
    )
    if state in {"EFFECT_PRESENT", "EFFECT_ABSENT", "CONFLICT"}:
        expected = {
            "EFFECT_PRESENT": "AVAILABLE_PRESENT",
            "EFFECT_ABSENT": "AVAILABLE_ABSENT",
            "CONFLICT": "AVAILABLE_CONFLICT",
        }[state]
        strict._validate_observation(
            authoritative,
            field_name=(
                "reservation.authoritative_reconciliation"
            ),
            classification=expected,
            entity_id=str(context.incident["entity_id"]),
            provider=context.provider,
        )
        if reservation["reconciliation_generation"] < 1:
            raise EvidenceError(
                "reconciled terminal reservation lacks claim generation"
            )
    elif authoritative is not None:
        classification = (
            authoritative.get("classification")
            if isinstance(authoritative, dict)
            else None
        )
        if not isinstance(classification, str):
            raise EvidenceError(
                "reservation reconciliation observation is untyped"
            )
        strict._validate_observation(
            authoritative,
            field_name=(
                "reservation.authoritative_reconciliation"
            ),
            classification=classification,
            entity_id=str(context.incident["entity_id"]),
            provider=context.provider,
            require_authoritative=False,
        )


def _validate_claim_history(
    reservation: dict[str, Any],
) -> None:
    safe_outcome = reservation["safe_outcome"]
    history = safe_outcome.get(
        "reconciliation_claim_history",
        [],
    )
    if not isinstance(history, list):
        raise EvidenceError(
            "reservation reconciliation claim history is invalid"
        )
    previous_generation = 0
    for entry in history:
        required = {
            "owner",
            "generation",
            "started_at",
            "lease_expires_at",
            "abandoned_at",
            "reason",
        }
        if not isinstance(entry, dict) or set(entry) != required:
            raise EvidenceError(
                "reservation reconciliation claim history is incomplete"
            )
        generation = entry.get("generation")
        if (
            not _positive_int(generation)
            or generation <= previous_generation
            or not entry.get("owner")
            or not entry.get("reason")
        ):
            raise EvidenceError(
                "reservation reconciliation claim history is unordered"
            )
        started_at = strict._evidence_time(
            entry.get("started_at"),
            "reconciliation_claim_history.started_at",
        )
        lease_expires_at = strict._evidence_time(
            entry.get("lease_expires_at"),
            "reconciliation_claim_history.lease_expires_at",
        )
        abandoned_at = strict._evidence_time(
            entry.get("abandoned_at"),
            "reconciliation_claim_history.abandoned_at",
        )
        if not started_at < lease_expires_at <= abandoned_at:
            raise EvidenceError(
                "reservation reconciliation claim history timestamps are invalid"
            )
        previous_generation = generation
    current_generation = reservation[
        "reconciliation_generation"
    ]
    if history and previous_generation >= current_generation:
        raise EvidenceError(
            "abandoned reconciliation generation is not older than current authority"
        )


def _positive_int(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
    )


def _nonnegative_int(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )
