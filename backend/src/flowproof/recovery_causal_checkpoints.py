"""Causal provider-dispatch checkpoints on the canonical reservation ledger."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm.exc import StaleDataError

from flowproof.accounting import (
    WriteOutcomeState,
    coerce_write_outcome,
)
from flowproof.alerts import Alert, enqueue_alert
from flowproof.models import (
    Incident,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_dispatch import (
    DispatchClaim,
    ReconciliationRequired,
)
from flowproof.service_core import RecoveryGateError


class CausalDispatchCheckpointBehavior:
    """Preserve accepted/unknown checkpoints without weakening CAS authority."""

    def _dispatch_attempt(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
    ) -> RecoveryPlan:
        if not self.recovery_writes_enabled:
            raise RecoveryGateError(
                "new external recovery reservations are disabled in this environment"
            )
        approval = self._active_dispatch_approval(plan)
        claim = self._reserve_transport(
            plan,
            incident,
            attempt,
            approval,
        )
        try:
            outcome = coerce_write_outcome(
                self.accounting,
                plan.parameters,
                plan.idempotency_key,
            )
        except Exception as exc:
            self._abandon_dispatch_after_exception(
                claim,
                exc,
            )
            raise ReconciliationRequired(
                "provider dispatch raised after durable reservation; "
                "authoritative reconciliation is required"
            ) from exc
        return self._complete_reserved_transport(
            claim,
            outcome,
        )

    def _abandon_dispatch_after_exception(
        self,
        claim: DispatchClaim,
        exc: Exception,
    ) -> None:
        now = self.now()
        reservation_cas = self.session.execute(
            update(RecoveryTransportInvocation)
            .where(
                RecoveryTransportInvocation.id
                == claim.reservation_id,
                RecoveryTransportInvocation.state
                == "DISPATCHING",
                RecoveryTransportInvocation.dispatch_owner
                == claim.owner,
                RecoveryTransportInvocation.dispatch_generation
                == claim.generation,
                RecoveryTransportInvocation.lock_version
                == claim.reservation_lock_version,
                RecoveryTransportInvocation.abandoned_at.is_(
                    None
                ),
            )
            .values(
                state="OUTCOME_UNKNOWN",
                abandoned_at=now,
                abandoned_by=claim.owner,
                abandonment_reason=(
                    "provider_call_raised_after_reservation"
                ),
                outcome_classification=(
                    "UNRECORDED_PROVIDER_EXCEPTION"
                ),
                outcome_observed_at=now,
                safe_outcome={
                    "provider_exception": {
                        "error_type": type(exc).__name__,
                        "classification": (
                            "OUTCOME_UNKNOWN_REQUIRES_REREAD"
                        ),
                    }
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
            raise self._dispatch_cas_loss(claim)
        try:
            self.session.commit()
        except StaleDataError as stale:
            self.session.rollback()
            raise ReconciliationRequired(
                "dispatch exception abandonment lost authority"
            ) from stale

    def _complete_reserved_transport(
        self,
        claim: DispatchClaim,
        outcome: Any,
    ) -> RecoveryPlan:
        now = self.now()
        outcome_evidence = outcome.to_evidence()
        if outcome.state == WriteOutcomeState.ACCEPTED:
            reservation_state = "ACCEPTED"
            attempt_state = "ACCEPTED"
        elif outcome.state in {
            WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN,
            WriteOutcomeState.MALFORMED_RESPONSE,
        }:
            reservation_state = "OUTCOME_UNKNOWN"
            attempt_state = "OUTCOME_UNKNOWN"
        else:
            reservation_state = "PRE_ACCEPTANCE_FAILED"
            attempt_state = "PRE_ACCEPTANCE_FAILED"

        plan = self.session.scalar(
            select(RecoveryPlan)
            .where(RecoveryPlan.id == claim.plan_id)
            .with_for_update()
        )
        incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == claim.incident_id)
            .with_for_update()
        )
        attempt = self.session.get(
            RecoveryAttempt,
            claim.attempt_id,
        )
        if plan is None or incident is None or attempt is None:
            self.session.rollback()
            raise ReconciliationRequired(
                "dispatch completion lost its durable subject"
            )

        reservation_cas = self.session.execute(
            update(RecoveryTransportInvocation)
            .where(
                RecoveryTransportInvocation.id
                == claim.reservation_id,
                RecoveryTransportInvocation.state
                == "DISPATCHING",
                RecoveryTransportInvocation.dispatch_owner
                == claim.owner,
                RecoveryTransportInvocation.dispatch_generation
                == claim.generation,
                RecoveryTransportInvocation.lock_version
                == claim.reservation_lock_version,
                RecoveryTransportInvocation.abandoned_at.is_(
                    None
                ),
                RecoveryTransportInvocation.dispatch_lease_expires_at
                > now,
            )
            .values(
                state=reservation_state,
                outcome_classification=outcome.state.value,
                outcome_observed_at=now,
                provider_operation_reference=(
                    outcome.operation_reference
                ),
                retry_after_seconds=outcome.retry_after_seconds,
                safe_outcome={
                    "provider_write_outcome": outcome_evidence
                },
                completed_at=now,
                lock_version=(
                    RecoveryTransportInvocation.lock_version + 1
                ),
            )
            .execution_options(synchronize_session=False)
        )
        attempt_cas = self.session.execute(
            update(RecoveryAttempt)
            .where(
                RecoveryAttempt.id == claim.attempt_id,
                RecoveryAttempt.state == "DISPATCHING",
                RecoveryAttempt.active_transport_invocation_id
                == claim.reservation_id,
                RecoveryAttempt.lock_version
                == claim.attempt_lock_version,
            )
            .values(
                state=attempt_state,
                outcome_classification=outcome.state.value,
                provider_operation_reference=(
                    outcome.operation_reference
                ),
                retry_after_seconds=outcome.retry_after_seconds,
                safe_result={
                    **attempt.safe_result,
                    "write_outcome": outcome_evidence,
                    "transport_reservation_id": (
                        claim.reservation_id
                    ),
                },
                accepted_at=(
                    now
                    if outcome.state
                    == WriteOutcomeState.ACCEPTED
                    else None
                ),
                updated_at=now,
                lock_version=(
                    RecoveryAttempt.lock_version + 1
                ),
            )
            .execution_options(synchronize_session=False)
        )
        if (
            reservation_cas.rowcount != 1
            or attempt_cas.rowcount != 1
        ):
            self.session.rollback()
            raise self._dispatch_cas_loss(claim)

        plan.result = {
            "attempt_id": claim.attempt_id,
            "transport_reservation_id": (
                claim.reservation_id
            ),
            "write_outcome": outcome_evidence,
        }
        if outcome.state == WriteOutcomeState.ACCEPTED:
            plan.executed_at = now
            plan.status = "executing"
            incident.status = "recovery_running"
            try:
                self.session.commit()
            except StaleDataError as exc:
                self.session.rollback()
                raise ReconciliationRequired(
                    "accepted provider outcome lost durable convergence"
                ) from exc
            return self._advance_accepted_to_verifying(
                claim,
            )

        plan.status = "needs_attention"
        incident.status = "needs_attention"
        enqueue_alert(
            self.session,
            Alert(
                condition="recovery_needs_attention",
                severity="high",
                summary=(
                    "A recovery reservation requires authoritative reconciliation"
                ),
                occurred_at=now,
            ),
            dedupe_key=(
                f"recovery_needs_attention:{plan.id}:"
                f"{claim.reservation_id}"
            ),
        )
        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "provider outcome was recorded but plan convergence lost authority"
            ) from exc
        raise RecoveryGateError(
            "recovery outcome requires authoritative reconciliation"
        )

    def _advance_accepted_to_verifying(
        self,
        claim: DispatchClaim,
    ) -> RecoveryPlan:
        now = self.now()
        plan = self.session.scalar(
            select(RecoveryPlan)
            .where(RecoveryPlan.id == claim.plan_id)
            .with_for_update()
        )
        incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == claim.incident_id)
            .with_for_update()
        )
        if plan is None or incident is None:
            self.session.rollback()
            raise ReconciliationRequired(
                "accepted reservation lost plan convergence subject"
            )
        advanced = self.session.execute(
            update(RecoveryAttempt)
            .where(
                RecoveryAttempt.id == claim.attempt_id,
                RecoveryAttempt.state == "ACCEPTED",
                RecoveryAttempt.active_transport_invocation_id
                == claim.reservation_id,
                RecoveryAttempt.lock_version
                == claim.attempt_lock_version + 1,
            )
            .values(
                state="VERIFYING",
                updated_at=now,
                lock_version=(
                    RecoveryAttempt.lock_version + 1
                ),
            )
            .execution_options(synchronize_session=False)
        )
        if advanced.rowcount != 1:
            self.session.rollback()
            raise ReconciliationRequired(
                "accepted reservation requires reread before reporting execution"
            )
        plan.status = "verifying"
        incident.status = "verifying"
        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "accepted reservation lost verification convergence authority"
            ) from exc
        return plan
