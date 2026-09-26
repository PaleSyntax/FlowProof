"""Explicit lifecycle proof paths for evidence capsule v1.1."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_contract import (
    CHECKPOINT_ATTEMPT_STATES,
    PROOF_CHECKPOINT,
    PROOF_EXTERNAL,
    PROOF_PRE_DISPATCH,
    PROOF_WRITE,
    EvidenceError,
    ReservationIndex,
)
from flowproof.evidence_semantics import (
    SemanticContext,
    latest_incident_evaluation,
    validate_present_observation,
)


def verify_pre_dispatch_review(
    context: SemanticContext,
    decisions: dict[str, dict[str, Any]],
    reservations: ReservationIndex,
) -> None:
    del decisions
    if (
        context.incident.get("status")
        not in {"recovery_proposed", "recovery_approved"}
        or context.plan.get("status")
        not in {"proposed", "approved"}
        or context.incident.get("resolved_at") is not None
        or context.plan.get("executed_at") is not None
        or context.plan.get("verified_at") is not None
        or reservations.by_id
        or len(context.attempts) > 1
    ):
        raise EvidenceError(
            "pre-dispatch review lifecycle is inconsistent"
        )
    if context.attempts:
        attempt = context.attempts[0]
        if (
            attempt.get("state") != "PREPARED"
            or attempt.get("transport_invocation_count") != 0
            or attempt.get("active_transport_invocation_id")
            is not None
        ):
            raise EvidenceError(
                "pre-dispatch review contains a consumed transport intent"
            )
    if context.plan.get("status") == "approved":
        if (
            context.plan.get("approval_actor") is None
            or context.plan.get("approved_at") is None
            or context.plan.get("approval_expires_at") is None
        ):
            raise EvidenceError(
                "approved pre-dispatch review lacks effective approval"
            )
    elif any(
        context.plan.get(field) is not None
        for field in (
            "approval_actor",
            "approved_at",
            "approval_expires_at",
        )
    ):
        raise EvidenceError(
            "proposed pre-dispatch review retains approval authority"
        )


def verify_durable_checkpoint(
    context: SemanticContext,
    decisions: dict[str, dict[str, Any]],
    reservations: ReservationIndex,
) -> None:
    del decisions, reservations
    if (
        context.incident.get("status") == "resolved"
        or context.plan.get("status")
        in {"verified", "superseded"}
        or context.plan.get("verified_at") is not None
        or not context.attempts
    ):
        raise EvidenceError(
            "durable checkpoint incorrectly claims a terminal lifecycle"
        )
    attempt = context.attempts[0]
    if attempt.get("state") not in CHECKPOINT_ATTEMPT_STATES:
        raise EvidenceError(
            "durable checkpoint attempt state is unsupported"
        )
    result = context.plan.get("result")
    postcondition = (
        result.get("postcondition")
        if isinstance(result, dict)
        else None
    )
    if (
        isinstance(postcondition, dict)
        and postcondition.get("status") == "resolved"
    ):
        raise EvidenceError(
            "durable checkpoint contains a resolved postcondition claim"
        )


def verify_external_resolution(
    context: SemanticContext,
    decisions: dict[str, dict[str, Any]],
    reservations: ReservationIndex,
) -> None:
    del decisions
    result = context.plan.get("result")
    external = (
        result.get("external_resolution")
        if isinstance(result, dict)
        else None
    )
    if (
        context.incident.get("status") != "resolved"
        or context.plan.get("status") != "superseded"
        or context.plan.get("executed_at") is not None
        or context.plan.get("verified_at") is not None
        or context.plan.get("approved_at") is not None
        or context.plan.get("approval_expires_at") is not None
        or context.plan.get("approval_actor") is not None
        or reservations.by_id
        or not isinstance(external, dict)
        or external.get("transport_invocation_count") != 0
        or external.get("reservation_id") is not None
    ):
        raise EvidenceError(
            "external-resolution zero-write lifecycle is inconsistent"
        )
    if len(context.attempts) > 1:
        raise EvidenceError(
            "external resolution contains multiple semantic attempts"
        )
    if context.attempts:
        attempt = context.attempts[0]
        if (
            attempt.get("state")
            != "SUPERSEDED_EXTERNAL_RESOLUTION"
            or attempt.get("transport_invocation_count") != 0
            or attempt.get("active_transport_invocation_id")
            is not None
        ):
            raise EvidenceError(
                "prepared intent was not superseded as zero-write resolution"
            )
    evaluation = latest_incident_evaluation(context)
    if evaluation.get("state") != "passed":
        raise EvidenceError(
            "external resolution lacks final invariant PASS"
        )
    typed = validate_present_observation(
        context,
        evaluation.get("evidence"),
        field_name="external resolution evaluation",
    )
    external_evidence = external.get("observation")
    if (
        not isinstance(external_evidence, dict)
        or external_evidence.get("observation")
        != evaluation.get("evidence", {}).get("observation")
    ):
        raise EvidenceError(
            "external resolution is not bound to exact final observation"
        )
    resolved_at = strict._evidence_time(
        context.incident.get("resolved_at"),
        "incident.resolved_at",
    )
    evaluated_at = strict._evidence_time(
        evaluation.get("evaluated_at"),
        "evaluation.evaluated_at",
    )
    observed_at = strict._evidence_time(
        typed.get("observed_at"),
        "external_resolution.observed_at",
    )
    if not observed_at <= evaluated_at <= resolved_at:
        raise EvidenceError(
            "external resolution timestamps are not causal"
        )


def verify_resolved_after_write(
    context: SemanticContext,
    decisions: dict[str, dict[str, Any]],
    reservations: ReservationIndex,
) -> None:
    del decisions
    if (
        context.incident.get("status") != "resolved"
        or context.plan.get("status") != "verified"
        or len(context.attempts) != 1
    ):
        raise EvidenceError(
            "resolved-after-write lifecycle is incomplete"
        )
    attempt = context.attempts[0]
    active_id = attempt.get("active_transport_invocation_id")
    reservation = reservations.by_id.get(str(active_id))
    if (
        attempt.get("state") != "VERIFIED"
        or reservation is None
        or reservation.get("state") != "EFFECT_PRESENT"
        or reservation.get("completed_at") is None
    ):
        raise EvidenceError(
            "resolved-after-write proof lacks exact terminal reservation"
        )
    safe_outcome = reservation.get("safe_outcome")
    if not isinstance(safe_outcome, dict):
        raise EvidenceError(
            "resolved-after-write reservation outcome is invalid"
        )
    write_outcome = safe_outcome.get("provider_write_outcome")
    if not isinstance(write_outcome, dict):
        raise EvidenceError(
            "resolved-after-write proof lacks typed provider outcome"
        )
    write_classification = write_outcome.get("classification")
    strict._validate_write_outcome(
        write_outcome,
        expected_classification=write_classification,
        provider=context.provider,
    )
    authoritative = safe_outcome.get(
        "authoritative_reconciliation"
    )
    typed = validate_present_observation(
        context,
        authoritative,
        field_name="resolved-after-write reconciliation",
    )

    evaluation = latest_incident_evaluation(context)
    if evaluation.get("state") != "passed":
        raise EvidenceError(
            "resolved-after-write proof lacks final PolicyEvaluation PASS"
        )
    evaluation_typed = validate_present_observation(
        context,
        evaluation.get("evidence"),
        field_name="resolved-after-write final evaluation",
    )
    if typed.get("content_digest") != evaluation_typed.get(
        "content_digest"
    ):
        raise EvidenceError(
            "final PolicyEvaluation does not reuse exact fenced observation"
        )

    verified_events = [
        event
        for event in context.timeline
        if event.get("event_type") == "invoice.verified"
        and event.get("entity_type")
        == context.incident.get("entity_type")
        and event.get("entity_id")
        == context.incident.get("entity_id")
    ]
    if len(verified_events) != 1:
        raise EvidenceError(
            "resolved-after-write proof lacks one verified timeline fact"
        )
    verified_event = verified_events[0]
    payload = verified_event.get("payload")
    if not isinstance(payload, dict):
        raise EvidenceError(
            "verified timeline payload is invalid"
        )
    parameters = context.plan["parameters"]
    try:
        amount_matches = Decimal(
            str(payload.get("amount"))
        ) == Decimal(str(parameters["amount"]))
    except (InvalidOperation, TypeError, ValueError):
        amount_matches = False
    if (
        payload.get("reservation_id") != reservation.get("id")
        or payload.get("observation_content_digest")
        != typed.get("content_digest")
        or str(payload.get("currency"))
        != str(parameters["currency"])
        or not amount_matches
    ):
        raise EvidenceError(
            "verified timeline fact does not match exact reservation and plan"
        )

    result = context.plan.get("result")
    postcondition = (
        result.get("postcondition")
        if isinstance(result, dict)
        else None
    )
    if (
        not isinstance(postcondition, dict)
        or postcondition.get("status") != "resolved"
        or postcondition.get("reservation_id")
        != reservation.get("id")
        or postcondition.get("policy_evaluation_id")
        != evaluation.get("id")
        or postcondition.get("observation_content_digest")
        != typed.get("content_digest")
    ):
        raise EvidenceError(
            "resolved-after-write postcondition binding is incomplete"
        )
    _validate_write_causal_times(
        context,
        reservation,
        write_outcome,
        typed,
        verified_event,
        evaluation,
        postcondition,
    )


def _validate_write_causal_times(
    context: SemanticContext,
    reservation: dict[str, Any],
    write_outcome: dict[str, Any],
    observation: dict[str, Any],
    verified_event: dict[str, Any],
    evaluation: dict[str, Any],
    postcondition: dict[str, Any],
) -> None:
    reserved_at = strict._evidence_time(
        reservation.get("reserved_at"),
        "reservation.reserved_at",
    )
    dispatch_started_at = strict._evidence_time(
        reservation.get("dispatch_started_at"),
        "reservation.dispatch_started_at",
    )
    executed_at = strict._evidence_time(
        context.plan.get("executed_at"),
        "plan.executed_at",
    )
    write_at = strict._evidence_time(
        write_outcome.get("observed_at"),
        "provider_write_outcome.observed_at",
    )
    observed_at = strict._evidence_time(
        observation.get("observed_at"),
        "authoritative_reconciliation.observed_at",
    )
    verified_at = strict._evidence_time(
        verified_event.get("occurred_at"),
        "invoice.verified.occurred_at",
    )
    evaluated_at = strict._evidence_time(
        evaluation.get("evaluated_at"),
        "PolicyEvaluation.evaluated_at",
    )
    checked_at = strict._evidence_time(
        postcondition.get("checked_at"),
        "postcondition.checked_at",
    )
    outcome_classification = reservation.get(
        "outcome_classification"
    )
    if outcome_classification == "ACCEPTED":
        prefix_is_causal = (
            reserved_at
            <= dispatch_started_at
            <= write_at
            <= executed_at
            <= observed_at
        )
    else:
        prefix_is_causal = (
            reserved_at
            <= dispatch_started_at
            == executed_at
            <= write_at
            <= observed_at
        )
    if not (
        prefix_is_causal
        and observed_at
        <= verified_at
        <= evaluated_at
        <= checked_at
    ):
        raise EvidenceError(
            "resolved-after-write causal timestamps are inconsistent"
        )


PATH_VALIDATORS = {
    PROOF_PRE_DISPATCH: verify_pre_dispatch_review,
    PROOF_CHECKPOINT: verify_durable_checkpoint,
    PROOF_EXTERNAL: verify_external_resolution,
    PROOF_WRITE: verify_resolved_after_write,
}
