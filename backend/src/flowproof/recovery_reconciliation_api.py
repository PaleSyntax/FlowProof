"""Public reconciliation orchestration and bounded recovery views."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from flowproof.accounting import ObservationState, coerce_observation
from flowproof.models import (
    Incident,
    Policy,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_postcondition_evaluation import (
    _FencedObservationContext,
)
from flowproof.recovery_reconciliation_claims import (
    ATTEMPT_RECONCILABLE_STATES,
    RESERVATION_TERMINAL_STATES,
)
from flowproof.service_core import RecoveryGateError, as_json


class ReconciliationApiBehavior:
    """Select one reconciliation subject, claim it, reread once and complete."""

    def reconcile(
        self,
        plan_id: str,
        *,
        submitted_hash: str,
    ) -> RecoveryPlan:
        plan = self._locked_plan(plan_id)
        self._validate_current_plan(plan, submitted_hash)
        incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == plan.incident_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.recovery_plan_id == plan.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if incident is None or attempt is None:
            raise RecoveryGateError("durable recovery attempt is missing")

        reservation = self._active_reservation(attempt)
        prepared_observation = None
        if reservation is None:
            if attempt.state not in ATTEMPT_RECONCILABLE_STATES:
                return plan
            if (
                attempt.state == "PREPARED"
                and attempt.active_transport_invocation_id is None
                and attempt.transport_invocation_count == 0
            ):
                prepared_observation = coerce_observation(
                    self.accounting,
                    str(plan.parameters["invoice_id"]),
                )
                if (
                    prepared_observation.state
                    == ObservationState.AVAILABLE_PRESENT
                ):
                    return self._converge_prepared_effect_present(
                        plan,
                        incident,
                        attempt,
                        prepared_observation,
                    )
            claim = self._claim_prepared_reconciliation(
                plan,
                incident,
                attempt,
                reason="explicit_reconcile",
            )
        else:
            if reservation.state in RESERVATION_TERMINAL_STATES:
                if reservation.state != "EFFECT_ABSENT":
                    return self._apply_terminal_reservation(
                        plan,
                        incident,
                        attempt,
                        reservation,
                    )
                if plan.status == "approved":
                    raise RecoveryGateError(
                        "retry approval is active; execute it or wait for authority to clear"
                    )
                if not (
                    plan.status == "needs_attention"
                    and incident.status == "needs_attention"
                    and attempt.state == "NEEDS_ATTENTION"
                ):
                    return plan
                claim = self._claim_reservation_reconciliation(
                    plan,
                    incident,
                    attempt,
                    reservation,
                    reason="terminal_effect_absent_recheck",
                )
            else:
                claim = self._claim_reservation_reconciliation(
                    plan,
                    incident,
                    attempt,
                    reservation,
                    reason="explicit_reconcile",
                )

        observation = prepared_observation or coerce_observation(
            self.accounting,
            str(plan.parameters["invoice_id"]),
        )
        return self._complete_reconciliation(claim, observation)

    def _converge_prepared_effect_present(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        observation: Any,
    ) -> RecoveryPlan:
        policy = self.session.scalar(
            select(Policy).where(
                Policy.name == incident.policy_name,
                Policy.version == incident.policy_version,
            )
        )
        if policy is None:
            raise RecoveryGateError("incident policy snapshot is missing")
        context = _FencedObservationContext(
            entity_reference=incident.entity_id,
            observation=observation,
            reservation_id=None,
        )
        if self._fenced_observation_context is not None:
            raise RecoveryGateError("another fenced observation is already active")
        self._fenced_observation_context = context
        try:
            self.evaluate(incident.correlation_id, policy.id)
        finally:
            self._fenced_observation_context = None
        if context.consumed != 1:
            raise RecoveryGateError(
                "prepared external resolution did not consume one fenced observation"
            )

        current_plan = self.session.scalar(
            select(RecoveryPlan)
            .where(RecoveryPlan.id == plan.id)
            .execution_options(populate_existing=True)
        )
        current_incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == incident.id)
            .execution_options(populate_existing=True)
        )
        current_attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == attempt.id)
            .execution_options(populate_existing=True)
        )
        if (
            current_plan is None
            or current_incident is None
            or current_attempt is None
            or current_attempt.state
            != "SUPERSEDED_EXTERNAL_RESOLUTION"
            or current_plan.status != "superseded"
            or current_plan.executed_at is not None
            or current_incident.status != "resolved"
        ):
            raise RecoveryGateError(
                "prepared effect-present observation did not converge as "
                "zero-write external resolution"
            )
        return current_plan

    def _active_reservation(
        self,
        attempt: RecoveryAttempt | None,
    ) -> RecoveryTransportInvocation | None:
        if attempt is None:
            return None
        active_id = attempt.active_transport_invocation_id
        if isinstance(active_id, str):
            return self.session.scalar(
                select(RecoveryTransportInvocation)
                .where(RecoveryTransportInvocation.id == active_id)
                .execution_options(populate_existing=True)
            )
        return self.session.scalar(
            select(RecoveryTransportInvocation)
            .where(
                RecoveryTransportInvocation.recovery_attempt_id
                == attempt.id
            )
            .order_by(
                RecoveryTransportInvocation.invocation_ordinal.desc(),
                RecoveryTransportInvocation.reserved_at.desc(),
            )
            .execution_options(populate_existing=True)
        )

    def list_attempts(
        self,
        plan_id: str,
    ) -> list[dict[str, Any]]:
        self._required_plan(plan_id)
        attempts = self.session.scalars(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.recovery_plan_id == plan_id)
            .order_by(
                RecoveryAttempt.attempt_ordinal,
                RecoveryAttempt.created_at,
            )
        ).all()
        result: list[dict[str, Any]] = []
        for attempt in attempts:
            item = self.attempt_view(attempt)
            reservations = self.session.scalars(
                select(RecoveryTransportInvocation)
                .where(
                    RecoveryTransportInvocation.recovery_attempt_id
                    == attempt.id
                )
                .order_by(
                    RecoveryTransportInvocation.invocation_ordinal,
                    RecoveryTransportInvocation.reserved_at,
                )
            ).all()
            item["transport_invocations"] = [
                self.transport_invocation_view(row)
                for row in reservations
            ]
            result.append(item)
        return result

    @staticmethod
    def transport_invocation_view(
        row: RecoveryTransportInvocation,
    ) -> dict[str, Any]:
        return as_json(
            {
                "id": row.id,
                "recovery_attempt_id": row.recovery_attempt_id,
                "recovery_plan_id": row.recovery_plan_id,
                "approval_decision_id": row.approval_decision_id,
                "invocation_ordinal": row.invocation_ordinal,
                "request_digest": row.request_digest,
                "reserved_at": row.reserved_at,
                "state": row.state,
                "dispatch_owner": row.dispatch_owner,
                "dispatch_generation": row.dispatch_generation,
                "dispatch_started_at": row.dispatch_started_at,
                "dispatch_lease_expires_at": row.dispatch_lease_expires_at,
                "abandoned_at": row.abandoned_at,
                "abandoned_by": row.abandoned_by,
                "abandonment_reason": row.abandonment_reason,
                "reconciliation_owner": row.reconciliation_owner,
                "reconciliation_generation": row.reconciliation_generation,
                "reconciliation_started_at": row.reconciliation_started_at,
                "reconciliation_lease_expires_at": (
                    row.reconciliation_lease_expires_at
                ),
                "reconciliation_abandoned_at": (
                    row.reconciliation_abandoned_at
                ),
                "outcome_classification": row.outcome_classification,
                "outcome_observed_at": row.outcome_observed_at,
                "provider_operation_reference": (
                    row.provider_operation_reference
                ),
                "retry_after_seconds": row.retry_after_seconds,
                "safe_outcome": row.safe_outcome,
                "completed_at": row.completed_at,
                "lock_version": row.lock_version,
            }
        )
