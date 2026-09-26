"""Complete reconciliation from fresh persisted state and typed observations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm.exc import StaleDataError

from flowproof.accounting import (
    ObservationState,
    WriteOutcomeState,
    client_contract,
)
from flowproof.models import (
    Incident,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_dispatch import ReconciliationRequired
from flowproof.recovery_reconciliation_claims import ReconciliationClaim
from flowproof.service_core import (
    RecoveryGateError,
    as_json,
    normalize_utc,
)


class ReconciliationCompletionBehavior:
    """Merge terminal evidence only from database-current genealogy."""

    def _complete_reconciliation(
        self,
        claim: ReconciliationClaim,
        observation: Any,
    ) -> RecoveryPlan:
        now = self.now()
        if now >= normalize_utc(claim.lease_expires_at):
            raise ReconciliationRequired(
                "authoritative reconciliation lease expired before completion"
            )

        plan = self.session.scalar(
            select(RecoveryPlan)
            .where(RecoveryPlan.id == claim.plan_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == claim.incident_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == claim.attempt_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        reservation = (
            self.session.scalar(
                select(RecoveryTransportInvocation)
                .where(
                    RecoveryTransportInvocation.id == claim.reservation_id
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if claim.reservation_id is not None
            else None
        )
        if plan is None or incident is None or attempt is None:
            self.session.rollback()
            raise ReconciliationRequired("reconciliation subject disappeared")
        if (
            attempt.state != "RECONCILING"
            or attempt.lock_version != claim.attempt_lock_version
            or attempt.active_transport_invocation_id != claim.reservation_id
        ):
            self.session.rollback()
            raise ReconciliationRequired(
                "reconciliation attempt no longer matches its claim"
            )
        if claim.reservation_id is not None and (
            reservation is None
            or reservation.state != "RECONCILING"
            or reservation.reconciliation_owner != claim.owner
            or reservation.reconciliation_generation != claim.generation
            or reservation.lock_version != claim.reservation_lock_version
        ):
            self.session.rollback()
            raise ReconciliationRequired(
                "reconciliation reservation no longer matches its claim"
            )

        evidence = observation.to_evidence()
        classification = self._reconciliation_classification(observation, plan)
        reapproval_action: str | None = None
        retry_reason: str | None = None

        if classification == "OUTCOME_UNKNOWN":
            reservation_state = "OUTCOME_UNKNOWN"
            next_attempt_state = "OUTCOME_UNKNOWN"
            next_plan_state = "needs_attention"
            next_incident_state = "needs_attention"
        elif classification == "EFFECT_PRESENT":
            if reservation is None:
                self.session.rollback()
                raise ReconciliationRequired(
                    "zero-reservation effect-present must converge through external resolution"
                )
            reservation_state = "EFFECT_PRESENT"
            next_attempt_state = "VERIFYING"
            next_plan_state = "verifying"
            next_incident_state = "verifying"
        elif classification == "EFFECT_ABSENT":
            reservation_state = "EFFECT_ABSENT"
            retry_reason = self._retry_reason(plan, attempt)
            invocation_room = attempt.transport_invocation_count < int(
                plan.guardrails.get("maximum_transport_invocations", 1)
            )
            if retry_reason is not None and invocation_room:
                reapproval_action = (
                    "prepared_reapproval_required"
                    if attempt.transport_invocation_count == 0
                    else "retry_reapproval_required"
                )
                next_attempt_state = "RECONCILED_EFFECT_ABSENT"
                next_plan_state = "proposed"
                next_incident_state = "recovery_proposed"
            else:
                next_attempt_state = "NEEDS_ATTENTION"
                next_plan_state = "needs_attention"
                next_incident_state = "needs_attention"
        else:
            reservation_state = "CONFLICT"
            next_attempt_state = "RECONCILED_CONFLICT"
            next_plan_state = "needs_attention"
            next_incident_state = "needs_attention"

        safe_result = (
            dict(attempt.safe_result)
            if isinstance(attempt.safe_result, dict)
            else {}
        )
        history = safe_result.get("reconciliation_history", [])
        if not isinstance(history, list):
            raise RecoveryGateError("reconciliation history is invalid")
        reservation_safe_outcome = (
            dict(reservation.safe_outcome)
            if reservation is not None
            and isinstance(reservation.safe_outcome, dict)
            else {}
        )
        write_outcome = reservation_safe_outcome.get(
            "provider_write_outcome",
            safe_result.get("write_outcome"),
        )
        history_entry = {
            "reservation_id": claim.reservation_id,
            "observation": evidence,
            "reconciled_at": as_json(now),
            "prior_attempt_state": claim.prior_attempt_state,
            "prior_reservation_state": claim.prior_reservation_state,
            "transport_invocation_count": claim.transport_invocation_count,
            "reapproval_action": reapproval_action,
            "retry_reason": retry_reason,
            "write_outcome": write_outcome,
            "reconciliation_claim": {
                "owner": claim.owner,
                "generation": claim.generation,
                "reservation_lock_version": claim.reservation_lock_version,
                "attempt_lock_version": claim.attempt_lock_version,
                "lease_expires_at": as_json(claim.lease_expires_at),
                "reason": claim.reason,
            },
        }
        next_safe_result = {
            **safe_result,
            "reconciliation_observation": evidence,
            "reconciliation_history": [*history, history_entry],
        }

        executed_at: datetime | None = None
        if classification == "EFFECT_PRESENT":
            assert reservation is not None
            executed_at = self._effect_present_execution_time(
                plan,
                reservation,
                observation,
            )

        if reservation is not None:
            reservation_cas = self.session.execute(
                update(RecoveryTransportInvocation)
                .where(
                    RecoveryTransportInvocation.id == claim.reservation_id,
                    RecoveryTransportInvocation.state == "RECONCILING",
                    RecoveryTransportInvocation.reconciliation_owner
                    == claim.owner,
                    RecoveryTransportInvocation.reconciliation_generation
                    == claim.generation,
                    RecoveryTransportInvocation.lock_version
                    == claim.reservation_lock_version,
                    RecoveryTransportInvocation.reconciliation_abandoned_at.is_(
                        None
                    ),
                    RecoveryTransportInvocation.reconciliation_lease_expires_at
                    > now,
                )
                .values(
                    state=reservation_state,
                    outcome_observed_at=now,
                    safe_outcome={
                        **reservation_safe_outcome,
                        "authoritative_reconciliation": evidence,
                    },
                    completed_at=now,
                    lock_version=(
                        RecoveryTransportInvocation.lock_version + 1
                    ),
                )
                .execution_options(synchronize_session=False)
            )
            if reservation_cas.rowcount != 1:
                self.session.rollback()
                raise ReconciliationRequired(
                    "stale reconciliation observation was discarded"
                )

        attempt_cas = self.session.execute(
            update(RecoveryAttempt)
            .where(
                RecoveryAttempt.id == claim.attempt_id,
                RecoveryAttempt.state == "RECONCILING",
                RecoveryAttempt.lock_version == claim.attempt_lock_version,
                (
                    RecoveryAttempt.active_transport_invocation_id
                    == claim.reservation_id
                    if claim.reservation_id is not None
                    else RecoveryAttempt.active_transport_invocation_id.is_(
                        None
                    )
                ),
            )
            .values(
                state=next_attempt_state,
                retry_permitted=(
                    next_attempt_state == "RECONCILED_EFFECT_ABSENT"
                ),
                retry_reason=retry_reason,
                safe_result=next_safe_result,
                reconciled_at=now,
                updated_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if attempt_cas.rowcount != 1:
            self.session.rollback()
            raise ReconciliationRequired(
                "stale reconciliation observation lost its attempt CAS"
            )

        previous_plan_state = plan.status
        previous_incident_state = incident.status
        plan.status = next_plan_state
        incident.status = next_incident_state
        if classification == "EFFECT_PRESENT":
            plan.executed_at = executed_at
        if next_attempt_state == "RECONCILED_EFFECT_ABSENT":
            self._clear_approval(plan)
            self._append_system_decision(
                plan,
                incident,
                action=reapproval_action or "retry_reapproval_required",
                reason_code=(
                    "prepared_intent_effect_absent"
                    if claim.transport_invocation_count == 0
                    else "effect_absent_after_reconciliation"
                ),
                previous_plan_state=previous_plan_state,
                previous_incident_state=previous_incident_state,
            )

        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "reconciliation result lost plan convergence authority"
            ) from exc

        self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == claim.attempt_id)
            .execution_options(populate_existing=True)
        )
        if claim.reservation_id is not None:
            self.session.scalar(
                select(RecoveryTransportInvocation)
                .where(
                    RecoveryTransportInvocation.id == claim.reservation_id
                )
                .execution_options(populate_existing=True)
            )
        return plan

    def _effect_present_execution_time(
        self,
        plan: RecoveryPlan,
        reservation: RecoveryTransportInvocation,
        observation: Any,
    ) -> datetime:
        dispatch_boundary = (
            reservation.dispatch_started_at or reservation.reserved_at
        )
        if dispatch_boundary is None:
            raise ReconciliationRequired(
                "effect-present reservation lacks a durable dispatch boundary"
            )
        boundary = normalize_utc(dispatch_boundary)
        observed_at = normalize_utc(observation.observed_at)
        if boundary > observed_at:
            raise ReconciliationRequired(
                "authoritative observation predates its durable dispatch boundary"
            )

        safe_outcome = (
            reservation.safe_outcome
            if isinstance(reservation.safe_outcome, dict)
            else {}
        )
        write_outcome = safe_outcome.get("provider_write_outcome")
        if isinstance(write_outcome, dict):
            write_time = self._parse_evidence_time(
                write_outcome.get("observed_at")
            )
            if write_time is None or not boundary <= write_time <= observed_at:
                raise ReconciliationRequired(
                    "typed provider outcome is not causally ordered"
                )

        if plan.executed_at is not None:
            existing = normalize_utc(plan.executed_at)
            if not boundary <= existing <= observed_at:
                raise ReconciliationRequired(
                    "existing execution timestamp is outside the causal boundary"
                )
            return existing
        return boundary

    @staticmethod
    def _parse_evidence_time(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return normalize_utc(parsed)

    def _reconciliation_classification(
        self,
        observation: Any,
        plan: RecoveryPlan,
    ) -> str:
        if not observation.available:
            return "OUTCOME_UNKNOWN"
        if (
            observation.state == ObservationState.AVAILABLE_PRESENT
            and self._record_matches_plan(observation.records[0], plan)
        ):
            return "EFFECT_PRESENT"
        if observation.state == ObservationState.AVAILABLE_ABSENT:
            return "EFFECT_ABSENT"
        return "CONFLICT"

    def _retry_reason(
        self,
        plan: RecoveryPlan,
        attempt: RecoveryAttempt,
    ) -> str | None:
        del plan
        pre_acceptance_proven = attempt.outcome_classification in {
            WriteOutcomeState.PRE_ACCEPTANCE_FAILURE.value,
            WriteOutcomeState.AUTHENTICATION_FAILED.value,
            WriteOutcomeState.RATE_LIMITED.value,
        }
        contract = client_contract(self.accounting)
        tested_idempotency = (
            contract.idempotency.get("support") == "CONTRACT_TESTED"
        )
        if pre_acceptance_proven:
            return "pre_acceptance_failure_proven"
        if tested_idempotency:
            return "contract_tested_same_key_idempotency"
        return None

    def _apply_terminal_reservation(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        reservation: RecoveryTransportInvocation,
    ) -> RecoveryPlan:
        if reservation.state == "EFFECT_PRESENT":
            attempt.state = "VERIFYING"
            plan.status = "verifying"
            incident.status = "verifying"
        elif reservation.state == "EFFECT_ABSENT":
            if attempt.retry_permitted:
                plan.status = "proposed"
                incident.status = "recovery_proposed"
            else:
                attempt.state = "NEEDS_ATTENTION"
                plan.status = "needs_attention"
                incident.status = "needs_attention"
        else:
            attempt.state = "RECONCILED_CONFLICT"
            plan.status = "needs_attention"
            incident.status = "needs_attention"
        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "terminal reservation convergence changed concurrently"
            ) from exc
        return plan
