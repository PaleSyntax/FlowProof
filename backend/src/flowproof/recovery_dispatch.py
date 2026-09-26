"""Durable dispatch reservation ownership and completion fencing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError

from flowproof.accounting import (
    WriteOutcomeState,
    coerce_write_outcome,
)
from flowproof.alerts import Alert, enqueue_alert
from flowproof.models import (
    Incident,
    RecoveryAttempt,
    RecoveryDecision,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.service_core import (
    RECOVERY_APPROVAL_SCOPE,
    RecoveryGateError,
    normalize_utc,
)


class ReconciliationRequired(RecoveryGateError):
    """The caller lost durable authority and must reread/reconcile."""


@dataclass(frozen=True, slots=True)
class DispatchClaim:
    reservation_id: str
    attempt_id: str
    plan_id: str
    incident_id: str
    owner: str
    generation: int
    reservation_lock_version: int
    attempt_lock_version: int
    lease_expires_at: datetime


class DispatchFencingBehavior:
    """Bind every provider write and completion to one durable reservation."""

    def _require_recovery_writes_enabled(self) -> None:
        """Planning, approval, reconciliation and verification remain available."""
        return None

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
        claim = self._reserve_transport(plan, incident, attempt, approval)
        try:
            outcome = coerce_write_outcome(
                self.accounting,
                plan.parameters,
                plan.idempotency_key,
            )
        except Exception as exc:
            raise ReconciliationRequired(
                "provider dispatch ended without a durable outcome; "
                "reconcile the reservation after its lease expires"
            ) from exc
        return self._complete_reserved_transport(claim, outcome)

    def _active_dispatch_approval(
        self,
        plan: RecoveryPlan,
    ) -> RecoveryDecision:
        context = plan.approval_context if isinstance(plan.approval_context, dict) else {}
        approval_id = context.get("approval_decision_id")
        approval = (
            self.session.get(RecoveryDecision, approval_id)
            if isinstance(approval_id, str)
            else None
        )
        now = self.now()
        if (
            approval is None
            or approval.action != "approve"
            or approval.decision_kind != "human"
            or approval.recovery_plan_id != plan.id
            or approval.authorization_scope != RECOVERY_APPROVAL_SCOPE
            or approval.approval_expires_at is None
            or now >= normalize_utc(approval.approval_expires_at)
        ):
            raise RecoveryGateError("transport approval is missing or expired")
        return approval

    def _reserve_transport(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        approval: RecoveryDecision,
    ) -> DispatchClaim:
        expected_state = attempt.state
        attempt_conditions = [
            RecoveryAttempt.id == attempt.id,
            RecoveryAttempt.state == expected_state,
            RecoveryAttempt.lock_version == attempt.lock_version,
        ]
        if expected_state == "RECONCILED_EFFECT_ABSENT":
            attempt_conditions.append(RecoveryAttempt.retry_permitted.is_(True))
        elif expected_state != "PREPARED":
            raise RecoveryGateError(
                "recovery attempt is not dispatchable; reconcile first"
            )

        now = self.now()
        lease_expires_at = now + timedelta(seconds=self.dispatch_lease_seconds)
        reservation_id = str(uuid4())
        generation = 1
        reservation = RecoveryTransportInvocation(
            id=reservation_id,
            recovery_attempt_id=attempt.id,
            recovery_plan_id=plan.id,
            approval_decision_id=approval.id,
            invocation_ordinal=attempt.transport_invocation_count + 1,
            request_digest=attempt.request_digest,
            reserved_at=now,
            state="DISPATCHING",
            dispatch_owner=self.dispatch_owner,
            dispatch_generation=generation,
            dispatch_started_at=now,
            dispatch_lease_expires_at=lease_expires_at,
            abandoned_at=None,
            abandoned_by=None,
            abandonment_reason=None,
            reconciliation_owner=None,
            reconciliation_generation=0,
            reconciliation_started_at=None,
            reconciliation_lease_expires_at=None,
            reconciliation_abandoned_at=None,
            outcome_classification=None,
            outcome_observed_at=None,
            provider_operation_reference=None,
            retry_after_seconds=None,
            safe_outcome={},
            completed_at=None,
            lock_version=1,
        )
        try:
            self.session.add(reservation)
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "transport reservation was created concurrently; reread the attempt"
            ) from exc

        claimed = self.session.execute(
            update(RecoveryAttempt)
            .where(*attempt_conditions)
            .values(
                state="DISPATCHING",
                transport_invocation_count=(
                    RecoveryAttempt.transport_invocation_count + 1
                ),
                retry_permitted=False,
                active_transport_invocation_id=reservation_id,
                updated_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            self.session.rollback()
            raise ReconciliationRequired(
                "recovery dispatch was claimed concurrently; reread the durable attempt"
            )

        plan.status = "executing"
        incident.status = "recovery_running"
        try:
            self.session.commit()
        except (IntegrityError, StaleDataError) as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "transport reservation lost its atomic attempt claim"
            ) from exc

        return DispatchClaim(
            reservation_id=reservation_id,
            attempt_id=attempt.id,
            plan_id=plan.id,
            incident_id=incident.id,
            owner=self.dispatch_owner,
            generation=generation,
            reservation_lock_version=1,
            attempt_lock_version=attempt.lock_version + 1,
            lease_expires_at=lease_expires_at,
        )

    def _complete_reserved_transport(
        self,
        claim: DispatchClaim,
        outcome: Any,
    ) -> RecoveryPlan:
        now = self.now()
        outcome_evidence = outcome.to_evidence()
        if outcome.state == WriteOutcomeState.ACCEPTED:
            reservation_state = "ACCEPTED"
            attempt_state = "VERIFYING"
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
        attempt = self.session.get(RecoveryAttempt, claim.attempt_id)
        if plan is None or incident is None or attempt is None:
            self.session.rollback()
            raise ReconciliationRequired(
                "dispatch completion lost its durable plan, incident or attempt"
            )

        reservation_cas = self.session.execute(
            update(RecoveryTransportInvocation)
            .where(
                RecoveryTransportInvocation.id == claim.reservation_id,
                RecoveryTransportInvocation.state == "DISPATCHING",
                RecoveryTransportInvocation.dispatch_owner == claim.owner,
                RecoveryTransportInvocation.dispatch_generation == claim.generation,
                RecoveryTransportInvocation.lock_version
                == claim.reservation_lock_version,
                RecoveryTransportInvocation.abandoned_at.is_(None),
                RecoveryTransportInvocation.dispatch_lease_expires_at > now,
            )
            .values(
                state=reservation_state,
                outcome_classification=outcome.state.value,
                outcome_observed_at=now,
                provider_operation_reference=outcome.operation_reference,
                retry_after_seconds=outcome.retry_after_seconds,
                safe_outcome={"provider_write_outcome": outcome_evidence},
                completed_at=now,
                lock_version=RecoveryTransportInvocation.lock_version + 1,
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
                RecoveryAttempt.lock_version == claim.attempt_lock_version,
            )
            .values(
                state=attempt_state,
                outcome_classification=outcome.state.value,
                provider_operation_reference=outcome.operation_reference,
                retry_after_seconds=outcome.retry_after_seconds,
                safe_result={
                    **attempt.safe_result,
                    "write_outcome": outcome_evidence,
                    "transport_reservation_id": claim.reservation_id,
                },
                accepted_at=(
                    now if outcome.state == WriteOutcomeState.ACCEPTED else None
                ),
                updated_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if reservation_cas.rowcount != 1 or attempt_cas.rowcount != 1:
            self.session.rollback()
            raise self._dispatch_cas_loss(claim)

        plan.result = {
            "attempt_id": claim.attempt_id,
            "transport_reservation_id": claim.reservation_id,
            "write_outcome": outcome_evidence,
        }
        if outcome.state == WriteOutcomeState.ACCEPTED:
            plan.executed_at = now
            plan.status = "verifying"
            incident.status = "verifying"
            try:
                self.session.commit()
            except StaleDataError as exc:
                self.session.rollback()
                raise ReconciliationRequired(
                    "accepted provider outcome lost plan convergence authority"
                ) from exc
            return plan

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
                f"recovery_needs_attention:{plan.id}:{claim.reservation_id}"
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

    def _dispatch_cas_loss(
        self,
        claim: DispatchClaim,
    ) -> ReconciliationRequired:
        self.session.expire_all()
        reservation = self.session.get(
            RecoveryTransportInvocation,
            claim.reservation_id,
        )
        state = reservation.state if reservation is not None else "missing"
        return ReconciliationRequired(
            "dispatch completion lost exact reservation authority "
            f"(reservation={claim.reservation_id}, state={state}); "
            "reread and reconcile before reporting execution success"
        )
