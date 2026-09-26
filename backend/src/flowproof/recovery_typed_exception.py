"""Persist a typed unknown provider outcome after a durable reservation."""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm.exc import StaleDataError

from flowproof.accounting import (
    RecoveryWriteOutcome,
    WriteOutcomeState,
    client_contract,
)
from flowproof.models import (
    RecoveryAttempt,
    RecoveryTransportInvocation,
)
from flowproof.recovery_dispatch import (
    DispatchClaim,
    ReconciliationRequired,
)


class TypedDispatchExceptionBehavior:
    """Never persist an untyped exception fragment as provider evidence."""

    def _abandon_dispatch_after_exception(
        self,
        claim: DispatchClaim,
        exc: Exception,
    ) -> None:
        now = self.now()
        contract = client_contract(self.accounting)
        outcome = RecoveryWriteOutcome(
            state=WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN,
            provider_id=contract.provider_id,
            environment=contract.environment,
            adapter_version=contract.adapter_version,
            observed_at=now,
            safe_result={"status": "provider_exception"},
            error_code=type(exc).__name__[:64],
        )
        evidence = outcome.to_evidence()

        plan, incident, attempt, reservation = self._fresh_dispatch_claim(
            claim,
            lock=True,
        )
        reservation_cas = self.session.execute(
            update(RecoveryTransportInvocation)
            .where(
                RecoveryTransportInvocation.id == reservation.id,
                RecoveryTransportInvocation.state == "DISPATCHING",
                RecoveryTransportInvocation.dispatch_owner == claim.owner,
                RecoveryTransportInvocation.dispatch_generation
                == claim.generation,
                RecoveryTransportInvocation.lock_version
                == claim.reservation_lock_version,
                RecoveryTransportInvocation.abandoned_at.is_(None),
            )
            .values(
                state="OUTCOME_UNKNOWN",
                abandoned_at=now,
                abandoned_by=claim.owner,
                abandonment_reason=(
                    "provider_call_raised_after_reservation"
                ),
                outcome_classification=outcome.state.value,
                outcome_observed_at=now,
                safe_outcome={
                    **reservation.safe_outcome,
                    "provider_write_outcome": evidence,
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
                RecoveryAttempt.id == attempt.id,
                RecoveryAttempt.state == "DISPATCHING",
                RecoveryAttempt.active_transport_invocation_id
                == reservation.id,
                RecoveryAttempt.lock_version == claim.attempt_lock_version,
            )
            .values(
                state="OUTCOME_UNKNOWN",
                outcome_classification=outcome.state.value,
                safe_result={
                    **attempt.safe_result,
                    "write_outcome": evidence,
                    "transport_reservation_id": reservation.id,
                },
                updated_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if reservation_cas.rowcount != 1 or attempt_cas.rowcount != 1:
            self.session.rollback()
            raise self._dispatch_cas_loss(claim)

        plan.status = "needs_attention"
        incident.status = "needs_attention"
        plan.result = {
            **plan.result,
            "attempt_id": attempt.id,
            "transport_reservation_id": reservation.id,
            "write_outcome": evidence,
        }
        try:
            self.session.commit()
        except StaleDataError as stale:
            self.session.rollback()
            raise ReconciliationRequired(
                "typed dispatch exception outcome lost convergence authority"
            ) from stale

        fresh_reservation = self.session.scalar(
            select(RecoveryTransportInvocation)
            .where(RecoveryTransportInvocation.id == reservation.id)
            .execution_options(populate_existing=True)
        )
        fresh_attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == attempt.id)
            .execution_options(populate_existing=True)
        )
        if (
            fresh_reservation is None
            or fresh_attempt is None
            or fresh_reservation.safe_outcome.get(
                "provider_write_outcome"
            )
            != evidence
            or fresh_attempt.safe_result.get("write_outcome")
            != evidence
        ):
            raise ReconciliationRequired(
                "typed dispatch exception evidence was not durably preserved"
            )
