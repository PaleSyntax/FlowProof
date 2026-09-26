"""Fenced authoritative reconciliation composed from claim, completion and API layers."""

from flowproof.recovery_reconciliation_api import ReconciliationApiBehavior
from flowproof.recovery_reconciliation_claims import (
    ATTEMPT_RECONCILABLE_STATES,
    RESERVATION_RECONCILABLE_STATES,
    RESERVATION_TERMINAL_STATES,
    ReconciliationClaim,
    ReconciliationClaimBehavior,
)
from flowproof.recovery_reconciliation_completion import (
    ReconciliationCompletionBehavior,
)


class ReservationReconciliationBehavior(
    ReconciliationApiBehavior,
    ReconciliationClaimBehavior,
    ReconciliationCompletionBehavior,
):
    """Fence each reread and preserve append-only attempt/reservation genealogy."""


__all__ = [
    "ATTEMPT_RECONCILABLE_STATES",
    "RESERVATION_RECONCILABLE_STATES",
    "RESERVATION_TERMINAL_STATES",
    "ReconciliationClaim",
    "ReservationReconciliationBehavior",
]
