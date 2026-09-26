"""Build deterministic evidence v1.1 documents without global mutation."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_contract import (
    MIGRATION_HEAD,
    PROOF_CHECKPOINT,
    PROOF_EXTERNAL,
    PROOF_PRE_DISPATCH,
    PROOF_WRITE,
    EvidenceError,
)
from flowproof.evidence_projection import project_safe_value
from flowproof.models import (
    BusinessEvent,
    Incident,
    PolicyEvaluation,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)


def _attempt_document(row: RecoveryAttempt) -> dict[str, Any]:
    return {
        "id": row.id,
        "recovery_plan_id": row.recovery_plan_id,
        "incident_id": row.incident_id,
        "approval_decision_id": row.approval_decision_id,
        "active_transport_invocation_id": (
            row.active_transport_invocation_id
        ),
        "attempt_ordinal": row.attempt_ordinal,
        "execution_idempotency_key_digest": strict._sha256(
            row.execution_idempotency_key.encode("utf-8")
        ),
        "plan_hash": row.plan_hash,
        "provider_contract_digest": row.provider_contract_digest,
        "provider_id": row.provider_id,
        "provider_environment": row.provider_environment,
        "adapter_version": row.adapter_version,
        "request_digest": row.request_digest,
        "precondition_observation_digest": (
            row.precondition_observation_digest
        ),
        "state": row.state,
        "outcome_classification": row.outcome_classification,
        "provider_operation_reference": (
            row.provider_operation_reference
        ),
        "retry_after_seconds": row.retry_after_seconds,
        "semantic_attempt_count": row.semantic_attempt_count,
        "transport_invocation_count": (
            row.transport_invocation_count
        ),
        "retry_permitted": row.retry_permitted,
        "retry_reason": row.retry_reason,
        "safe_result": project_safe_value(
            row.safe_result,
            path=f"attempt[{row.id}].safe_result",
        ),
        "created_at": strict._time(row.created_at),
        "updated_at": strict._time(row.updated_at),
        "accepted_at": strict._time(row.accepted_at),
        "reconciled_at": strict._time(row.reconciled_at),
        "lock_version": row.lock_version,
    }


def _transport_document(
    row: RecoveryTransportInvocation,
) -> dict[str, Any]:
    return {
        "id": row.id,
        "recovery_attempt_id": row.recovery_attempt_id,
        "recovery_plan_id": row.recovery_plan_id,
        "approval_decision_id": row.approval_decision_id,
        "invocation_ordinal": row.invocation_ordinal,
        "request_digest": row.request_digest,
        "reserved_at": strict._time(row.reserved_at),
        "state": row.state,
        "dispatch_owner": row.dispatch_owner,
        "dispatch_generation": row.dispatch_generation,
        "dispatch_started_at": strict._time(
            row.dispatch_started_at
        ),
        "dispatch_lease_expires_at": strict._time(
            row.dispatch_lease_expires_at
        ),
        "abandoned_at": strict._time(row.abandoned_at),
        "abandoned_by": row.abandoned_by,
        "abandonment_reason": row.abandonment_reason,
        "reconciliation_owner": row.reconciliation_owner,
        "reconciliation_generation": (
            row.reconciliation_generation
        ),
        "reconciliation_started_at": strict._time(
            row.reconciliation_started_at
        ),
        "reconciliation_lease_expires_at": strict._time(
            row.reconciliation_lease_expires_at
        ),
        "reconciliation_abandoned_at": strict._time(
            row.reconciliation_abandoned_at
        ),
        "outcome_classification": row.outcome_classification,
        "outcome_observed_at": strict._time(
            row.outcome_observed_at
        ),
        "provider_operation_reference": (
            row.provider_operation_reference
        ),
        "retry_after_seconds": row.retry_after_seconds,
        "safe_outcome": project_safe_value(
            row.safe_outcome,
            path=f"reservation[{row.id}].safe_outcome",
        ),
        "completed_at": strict._time(row.completed_at),
        "lock_version": row.lock_version,
    }


def _plan_document(
    base: dict[str, Any],
    row: RecoveryPlan,
) -> dict[str, Any]:
    return {
        **base,
        "status": row.status,
        "plan_hash": row.plan_hash,
        "provider_id": row.provider_id,
        "provider_environment": row.provider_environment,
        "adapter_version": row.adapter_version,
        "provider_contract_digest": row.provider_contract_digest,
        "guardrails": row.guardrails,
        "approved_at": strict._time(row.approved_at),
        "approval_expires_at": strict._time(
            row.approval_expires_at
        ),
        "executed_at": strict._time(row.executed_at),
        "verified_at": strict._time(row.verified_at),
        "result": project_safe_value(
            row.result,
            path=f"plan[{row.id}].result",
        ),
    }


def _proof_type(
    incident: Incident,
    plan: RecoveryPlan,
    attempts: list[RecoveryAttempt],
    reservations: list[RecoveryTransportInvocation],
) -> str:
    result = plan.result if isinstance(plan.result, dict) else {}
    if (
        incident.status == "resolved"
        and plan.status == "superseded"
        and isinstance(result.get("external_resolution"), dict)
    ):
        return PROOF_EXTERNAL
    if incident.status == "resolved" and plan.status == "verified":
        return PROOF_WRITE
    if (
        incident.status in {"recovery_proposed", "recovery_approved"}
        and plan.status in {"proposed", "approved"}
        and not reservations
        and (
            not attempts
            or (
                len(attempts) == 1
                and attempts[0].state == "PREPARED"
                and attempts[0].transport_invocation_count == 0
                and attempts[0].active_transport_invocation_id is None
            )
        )
        and plan.executed_at is None
        and incident.resolved_at is None
    ):
        return PROOF_PRE_DISPATCH
    return PROOF_CHECKPOINT


def build_documents(
    session: Session,
    incident_id: str,
    *,
    private_identity: bool = False,
) -> dict[str, bytes]:
    """Build v1.1 documents from immutable legacy primitives and exact rows."""

    raw = strict.build_documents(
        session,
        incident_id,
        private_identity=private_identity,
    )
    documents: dict[str, Any] = {
        name: json.loads(content)
        for name, content in raw.items()
    }
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise EvidenceError("incident not found")
    plan = session.scalar(
        select(RecoveryPlan).where(
            RecoveryPlan.incident_id == incident.id
        )
    )
    if plan is None:
        raise EvidenceError("incident has no recovery plan")
    attempts = list(
        session.scalars(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.recovery_plan_id == plan.id)
            .order_by(
                RecoveryAttempt.attempt_ordinal,
                RecoveryAttempt.created_at,
            )
        ).all()
    )
    attempt_ids = [attempt.id for attempt in attempts]
    reservations = (
        list(
            session.scalars(
                select(RecoveryTransportInvocation)
                .where(
                    RecoveryTransportInvocation.recovery_attempt_id.in_(
                        attempt_ids
                    )
                )
                .order_by(
                    RecoveryTransportInvocation.invocation_ordinal,
                    RecoveryTransportInvocation.reserved_at,
                )
            ).all()
        )
        if attempt_ids
        else []
    )
    evaluations = list(
        session.scalars(
            select(PolicyEvaluation)
            .where(
                PolicyEvaluation.correlation_id
                == incident.correlation_id
            )
            .order_by(
                PolicyEvaluation.evaluated_at,
                PolicyEvaluation.id,
            )
        ).all()
    )
    proof_type = _proof_type(
        incident,
        plan,
        attempts,
        reservations,
    )

    coordinates = documents["release-coordinates.json"]
    coordinates["migration_head"] = MIGRATION_HEAD
    coordinates["evidence_classification"] = (
        "IMPLEMENTED_UNVERIFIED"
    )
    coordinates["proof_type"] = proof_type

    incident_document = documents["incident.json"]
    incident_document["status"] = incident.status
    incident_document["summary"] = incident.summary
    incident_document["evidence"] = project_safe_value(
        incident.evidence,
        path=f"incident[{incident.id}].evidence",
    )
    incident_document["resolved_at"] = strict._time(
        incident.resolved_at
    )

    evaluation_documents = [
        {
            "id": row.id,
            "policy_id": row.policy_id,
            "correlation_id": row.correlation_id,
            "invariant_id": row.invariant_id,
            "state": row.state,
            "evidence": project_safe_value(
                row.evidence,
                path=f"evaluation[{row.id}].evidence",
            ),
            "evaluated_at": strict._time(row.evaluated_at),
        }
        for row in evaluations
    ]
    documents["evaluations.json"] = evaluation_documents
    documents["postcondition-observations.json"] = [
        item["evidence"]
        for item in evaluation_documents
        if item["invariant_id"] == incident.invariant_id
        and item["evidence"]
    ]
    for event in documents["timeline-evidence.json"]:
        if event.get("event_type") != "invoice.verified":
            continue
        row = session.get(BusinessEvent, event.get("id"))
        if row is None or row.correlation_id != incident.correlation_id:
            raise EvidenceError(
                "verified timeline fact is not bound to its persisted event"
            )
        event["payload"] = project_safe_value(
            row.payload,
            path=f"event[{row.id}].payload",
        )
    documents["recovery-plan.json"] = _plan_document(
        documents["recovery-plan.json"],
        plan,
    )
    documents["recovery-attempts.json"] = [
        _attempt_document(row)
        for row in attempts
    ]
    documents["transport-invocations.json"] = [
        _transport_document(row)
        for row in reservations
    ]

    for name, value in documents.items():
        strict._assert_secret_free(value, name)
    return {
        name: strict._json_bytes(value)
        for name, value in documents.items()
    }
