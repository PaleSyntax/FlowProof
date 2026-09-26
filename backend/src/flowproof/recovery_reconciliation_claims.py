"""Acquire exact owner/generation/lease claims for recovery reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm.exc import StaleDataError

from flowproof.models import (
    Incident,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_dispatch import ReconciliationRequired
from flowproof.service_core import (
    RecoveryGateError,
    as_json,
    normalize_utc,
)

RESERVATION_TERMINAL_STATES = {
    "EFFECT_PRESENT",
    "EFFECT_ABSENT",
    "CONFLICT",
}
RESERVATION_RECONCILABLE_STATES = {
    "OUTCOME_UNRECORDED",
    "DISPATCHING",
    "ACCEPTED",
    "OUTCOME_UNKNOWN",
    "PRE_ACCEPTANCE_FAILED",
    "RECONCILING",
    "EFFECT_ABSENT",
}
ATTEMPT_RECONCILABLE_STATES = {
    "PREPARED",
    "DISPATCHING",
    "ACCEPTED",
    "OUTCOME_UNKNOWN",
    "PRE_ACCEPTANCE_FAILED",
    "RECONCILING",
    "RECONCILED_EFFECT_ABSENT",
}


@dataclass(frozen=True, slots=True)
class ReconciliationClaim:
    plan_id: str
    incident_id: str
    attempt_id: str
    reservation_id: str | None
    owner: str
    generation: int
    reservation_lock_version: int | None
    attempt_lock_version: int
    lease_expires_at: datetime
    prior_attempt_state: str
    prior_reservation_state: str | None
    transport_invocation_count: int
    reason: str


class ReconciliationClaimBehavior:
    """Persist append-only claim genealogy before any provider reread."""

    def _claim_prepared_reconciliation(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        *,
        reason: str,
    ) -> ReconciliationClaim:
        attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == attempt.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if attempt is None:
            raise ReconciliationRequired(
                "prepared reconciliation attempt disappeared"
            )
        now = self.now()
        lease_expires_at = now + timedelta(
            seconds=self.reconciliation_lease_seconds
        )
        prior_attempt_state = attempt.state
        next_attempt_lock = attempt.lock_version + 1
        claimed = self.session.execute(
            update(RecoveryAttempt)
            .where(
                RecoveryAttempt.id == attempt.id,
                RecoveryAttempt.state == prior_attempt_state,
                RecoveryAttempt.active_transport_invocation_id.is_(None),
                RecoveryAttempt.lock_version == attempt.lock_version,
            )
            .values(
                state="RECONCILING",
                updated_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            self.session.rollback()
            raise ReconciliationRequired(
                "prepared reconciliation lost its attempt claim"
            )
        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "prepared reconciliation lost plan authority"
            ) from exc
        return ReconciliationClaim(
            plan_id=plan.id,
            incident_id=incident.id,
            attempt_id=attempt.id,
            reservation_id=None,
            owner=self.reconciliation_owner,
            generation=next_attempt_lock,
            reservation_lock_version=None,
            attempt_lock_version=next_attempt_lock,
            lease_expires_at=lease_expires_at,
            prior_attempt_state=prior_attempt_state,
            prior_reservation_state=None,
            transport_invocation_count=attempt.transport_invocation_count,
            reason=reason,
        )

    def _claim_reservation_reconciliation(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        attempt: RecoveryAttempt,
        reservation: RecoveryTransportInvocation,
        *,
        reason: str,
    ) -> ReconciliationClaim:
        attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == attempt.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        reservation = self.session.scalar(
            select(RecoveryTransportInvocation)
            .where(RecoveryTransportInvocation.id == reservation.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if attempt is None or reservation is None:
            raise ReconciliationRequired(
                "reconciliation subject disappeared before claim"
            )
        now = self.now()
        prior_reservation_state = reservation.state
        prior_attempt_state = attempt.state

        if prior_reservation_state == "DISPATCHING":
            if (
                reservation.abandoned_at is None
                and reservation.dispatch_lease_expires_at is not None
                and now < normalize_utc(
                    reservation.dispatch_lease_expires_at
                )
            ):
                raise ReconciliationRequired(
                    "transport dispatch lease is still live"
                )
        elif prior_reservation_state == "RECONCILING":
            if (
                reservation.reconciliation_abandoned_at is None
                and reservation.reconciliation_lease_expires_at is not None
                and now < normalize_utc(
                    reservation.reconciliation_lease_expires_at
                )
            ):
                raise ReconciliationRequired(
                    "authoritative reconciliation lease is still live"
                )
        elif prior_reservation_state not in RESERVATION_RECONCILABLE_STATES:
            raise RecoveryGateError(
                "transport reservation is not reconcilable"
            )

        generation = reservation.reconciliation_generation + 1
        lease_expires_at = now + timedelta(
            seconds=self.reconciliation_lease_seconds
        )
        safe_outcome = (
            dict(reservation.safe_outcome)
            if isinstance(reservation.safe_outcome, dict)
            else {}
        )
        claim_history = safe_outcome.get(
            "reconciliation_claim_history",
            [],
        )
        if not isinstance(claim_history, list):
            raise RecoveryGateError(
                "reservation reconciliation claim history is invalid"
            )
        next_claim_history = list(claim_history)
        if prior_reservation_state == "RECONCILING":
            next_claim_history.append(
                {
                    "owner": reservation.reconciliation_owner,
                    "generation": reservation.reconciliation_generation,
                    "started_at": as_json(
                        reservation.reconciliation_started_at
                    ),
                    "lease_expires_at": as_json(
                        reservation.reconciliation_lease_expires_at
                    ),
                    "abandoned_at": as_json(now),
                    "reason": "reconciliation_lease_expired",
                }
            )

        values: dict[str, Any] = {
            "state": "RECONCILING",
            "reconciliation_owner": self.reconciliation_owner,
            "reconciliation_generation": generation,
            "reconciliation_started_at": now,
            "reconciliation_lease_expires_at": lease_expires_at,
            "reconciliation_abandoned_at": None,
            "safe_outcome": {
                **safe_outcome,
                "reconciliation_claim_history": next_claim_history,
            },
            "lock_version": RecoveryTransportInvocation.lock_version + 1,
        }
        if prior_reservation_state == "DISPATCHING":
            values.update(
                {
                    "abandoned_at": now,
                    "abandoned_by": self.reconciliation_owner,
                    "abandonment_reason": "dispatch_lease_expired",
                }
            )

        reservation_lock = reservation.lock_version
        attempt_lock = attempt.lock_version
        reservation_claim = self.session.execute(
            update(RecoveryTransportInvocation)
            .where(
                RecoveryTransportInvocation.id == reservation.id,
                RecoveryTransportInvocation.state
                == prior_reservation_state,
                RecoveryTransportInvocation.lock_version
                == reservation_lock,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        attempt_claim = self.session.execute(
            update(RecoveryAttempt)
            .where(
                RecoveryAttempt.id == attempt.id,
                RecoveryAttempt.active_transport_invocation_id
                == reservation.id,
                RecoveryAttempt.state == prior_attempt_state,
                RecoveryAttempt.lock_version == attempt_lock,
            )
            .values(
                state="RECONCILING",
                updated_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if reservation_claim.rowcount != 1 or attempt_claim.rowcount != 1:
            self.session.rollback()
            raise ReconciliationRequired(
                "authoritative reconciliation claim changed concurrently"
            )
        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise ReconciliationRequired(
                "authoritative reconciliation lost plan authority"
            ) from exc

        return ReconciliationClaim(
            plan_id=plan.id,
            incident_id=incident.id,
            attempt_id=attempt.id,
            reservation_id=reservation.id,
            owner=self.reconciliation_owner,
            generation=generation,
            reservation_lock_version=reservation_lock + 1,
            attempt_lock_version=attempt_lock + 1,
            lease_expires_at=lease_expires_at,
            prior_attempt_state=prior_attempt_state,
            prior_reservation_state=prior_reservation_state,
            transport_invocation_count=attempt.transport_invocation_count,
            reason=reason,
        )
