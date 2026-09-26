"""Exact fresh-read boundaries around bulk dispatch and reconciliation claims."""

from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from flowproof.models import (
    Incident,
    RecoveryAttempt,
    RecoveryDecision,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_dispatch import (
    DispatchClaim,
    ReconciliationRequired,
)
from flowproof.recovery_reconciliation import ReconciliationClaim
from flowproof.service_core import as_json

ModelT = TypeVar("ModelT")


class FreshReadBoundaryBehavior:
    """Use database-current rows after every synchronize_session=False claim."""

    @staticmethod
    def _expire_claimed(
        session: Session,
        *rows: object | None,
    ) -> None:
        for row in rows:
            if row is not None and inspect(row).persistent:
                session.expire(row)

    def _fresh_row(
        self,
        model: type[ModelT],
        row_id: str,
        *,
        lock: bool = False,
    ) -> ModelT | None:
        statement = (
            select(model)
            .where(model.id == row_id)
            .execution_options(populate_existing=True)
        )
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def _fresh_dispatch_claim(
        self,
        claim: DispatchClaim,
        *,
        lock: bool = False,
    ) -> tuple[
        RecoveryPlan,
        Incident,
        RecoveryAttempt,
        RecoveryTransportInvocation,
    ]:
        plan = self._fresh_row(RecoveryPlan, claim.plan_id, lock=lock)
        incident = self._fresh_row(Incident, claim.incident_id, lock=lock)
        attempt = self._fresh_row(
            RecoveryAttempt,
            claim.attempt_id,
            lock=lock,
        )
        reservation = self._fresh_row(
            RecoveryTransportInvocation,
            claim.reservation_id,
            lock=lock,
        )
        if (
            plan is None
            or incident is None
            or attempt is None
            or reservation is None
            or attempt.active_transport_invocation_id != reservation.id
            or attempt.lock_version != claim.attempt_lock_version
            or reservation.lock_version != claim.reservation_lock_version
            or reservation.dispatch_owner != claim.owner
            or reservation.dispatch_generation != claim.generation
        ):
            raise ReconciliationRequired(
                "dispatch claim no longer names the exact persisted rows"
            )
        return plan, incident, attempt, reservation

    def _fresh_reconciliation_claim(
        self,
        claim: ReconciliationClaim,
        *,
        lock: bool = False,
    ) -> tuple[
        RecoveryPlan,
        Incident,
        RecoveryAttempt,
        RecoveryTransportInvocation | None,
    ]:
        plan = self._fresh_row(RecoveryPlan, claim.plan_id, lock=lock)
        incident = self._fresh_row(Incident, claim.incident_id, lock=lock)
        attempt = self._fresh_row(
            RecoveryAttempt,
            claim.attempt_id,
            lock=lock,
        )
        reservation = (
            self._fresh_row(
                RecoveryTransportInvocation,
                claim.reservation_id,
                lock=lock,
            )
            if claim.reservation_id is not None
            else None
        )
        exact_attempt = (
            attempt is not None
            and attempt.lock_version == claim.attempt_lock_version
            and attempt.state == "RECONCILING"
            and attempt.active_transport_invocation_id
            == claim.reservation_id
        )
        exact_reservation = (
            claim.reservation_id is None
            or (
                reservation is not None
                and reservation.lock_version
                == claim.reservation_lock_version
                and reservation.state == "RECONCILING"
                and reservation.reconciliation_owner == claim.owner
                and reservation.reconciliation_generation
                == claim.generation
            )
        )
        if (
            plan is None
            or incident is None
            or not exact_attempt
            or not exact_reservation
        ):
            raise ReconciliationRequired(
                "stale reconciliation claim no longer names the exact persisted rows"
            )
        assert attempt is not None
        return plan, incident, attempt, reservation

    def _reserve_transport(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        approval: RecoveryDecision,
    ) -> DispatchClaim:
        claim = super()._reserve_transport(
            plan,
            incident,
            attempt,
            approval,
        )
        self._expire_claimed(
            self.session,
            plan,
            incident,
            attempt,
        )
        self._fresh_dispatch_claim(claim)
        return claim

    def _complete_reserved_transport(
        self,
        claim: DispatchClaim,
        outcome: Any,
    ) -> RecoveryPlan:
        self._fresh_dispatch_claim(claim, lock=True)
        return super()._complete_reserved_transport(claim, outcome)

    def _claim_prepared_reconciliation(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        *,
        reason: str,
    ) -> ReconciliationClaim:
        claim = super()._claim_prepared_reconciliation(
            plan,
            incident,
            attempt,
            reason=reason,
        )
        self._expire_claimed(
            self.session,
            plan,
            incident,
            attempt,
        )
        self._fresh_reconciliation_claim(claim)
        return claim

    def _claim_reservation_reconciliation(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        reservation: RecoveryTransportInvocation,
        *,
        reason: str,
    ) -> ReconciliationClaim:
        claim = super()._claim_reservation_reconciliation(
            plan,
            incident,
            attempt,
            reservation,
            reason=reason,
        )
        self._expire_claimed(
            self.session,
            plan,
            incident,
            attempt,
            reservation,
        )
        self._fresh_reconciliation_claim(claim)
        return claim

    def _complete_reconciliation(
        self,
        claim: ReconciliationClaim,
        observation: Any,
    ) -> RecoveryPlan:
        self._fresh_reconciliation_claim(claim, lock=True)
        return super()._complete_reconciliation(claim, observation)

    def _apply_terminal_reservation(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        reservation: RecoveryTransportInvocation,
    ) -> RecoveryPlan:
        self._expire_claimed(
            self.session,
            plan,
            incident,
            attempt,
            reservation,
        )
        fresh_plan = self._fresh_row(RecoveryPlan, plan.id, lock=True)
        fresh_incident = self._fresh_row(Incident, incident.id, lock=True)
        fresh_attempt = self._fresh_row(
            RecoveryAttempt,
            attempt.id,
            lock=True,
        )
        fresh_reservation = self._fresh_row(
            RecoveryTransportInvocation,
            reservation.id,
            lock=True,
        )
        if any(
            value is None
            for value in (
                fresh_plan,
                fresh_incident,
                fresh_attempt,
                fresh_reservation,
            )
        ):
            raise ReconciliationRequired(
                "terminal reservation subject disappeared during fresh read"
            )
        assert fresh_plan is not None
        assert fresh_incident is not None
        assert fresh_attempt is not None
        assert fresh_reservation is not None
        return super()._apply_terminal_reservation(
            fresh_plan,
            fresh_incident,
            fresh_attempt,
            fresh_reservation,
        )

    @staticmethod
    def attempt_view(row: RecoveryAttempt) -> dict[str, Any]:
        """Project the canonical attempt without importing an alternate runtime."""

        return as_json(
            {
                "id": row.id,
                "recovery_plan_id": row.recovery_plan_id,
                "incident_id": row.incident_id,
                "approval_decision_id": row.approval_decision_id,
                "attempt_ordinal": row.attempt_ordinal,
                "execution_idempotency_key": (
                    row.execution_idempotency_key
                ),
                "plan_hash": row.plan_hash,
                "provider_contract_digest": (
                    row.provider_contract_digest
                ),
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
                "active_transport_invocation_id": (
                    row.active_transport_invocation_id
                ),
                "safe_result": row.safe_result,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "accepted_at": row.accepted_at,
                "reconciled_at": row.reconciled_at,
                "lock_version": row.lock_version,
            }
        )
