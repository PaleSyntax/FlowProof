"""Canonical FlowProof service with explicit v0.6.0 behaviors."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flowproof._service_runtime_base import (
    AMBIGUOUS_ATTEMPT_STATES,
    RECOVERY_APPROVABLE_INCIDENT_STATUS,
    RECOVERY_APPROVAL_SCOPE,
    IdempotencyConflict,
    PayloadRejected,
    RecoveryGateError,
    _FlowProofRuntimeBase,
    as_json,
    decision_note_digest,
    normalize_utc,
    redact,
    utc_now,
)
from flowproof.ingest_binding import AtomicIngestBehavior
from flowproof.recovery_causal_checkpoints import (
    CausalDispatchCheckpointBehavior,
)
from flowproof.recovery_dispatch import (
    DispatchFencingBehavior,
    ReconciliationRequired,
)
from flowproof.recovery_fresh_read import FreshReadBoundaryBehavior
from flowproof.recovery_planning import RecoveryPlanningBehavior
from flowproof.recovery_postcondition import CanonicalPostconditionBehavior
from flowproof.recovery_reconciliation import (
    ReservationReconciliationBehavior,
)
from flowproof.recovery_resolution import ExternalResolutionBehavior
from flowproof.recovery_typed_exception import TypedDispatchExceptionBehavior


class FlowProofService(
    AtomicIngestBehavior,
    RecoveryPlanningBehavior,
    CanonicalPostconditionBehavior,
    ExternalResolutionBehavior,
    FreshReadBoundaryBehavior,
    TypedDispatchExceptionBehavior,
    CausalDispatchCheckpointBehavior,
    DispatchFencingBehavior,
    ReservationReconciliationBehavior,
    _FlowProofRuntimeBase,
):
    """Single executable state machine for planning, dispatch and verification."""

    def __init__(
        self,
        *args: Any,
        dispatch_owner: str | None = None,
        reconciliation_owner: str | None = None,
        dispatch_lease_seconds: int = 60,
        reconciliation_lease_seconds: int = 60,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        if dispatch_lease_seconds <= 0:
            raise ValueError(
                "dispatch_lease_seconds must be positive"
            )
        if reconciliation_lease_seconds <= 0:
            raise ValueError(
                "reconciliation_lease_seconds must be positive"
            )
        identity = str(uuid4())
        self.dispatch_owner = (
            dispatch_owner
            or f"flowproof-dispatch:{identity}"
        )
        self.reconciliation_owner = (
            reconciliation_owner
            or f"flowproof-reconcile:{identity}"
        )
        self.dispatch_lease_seconds = dispatch_lease_seconds
        self.reconciliation_lease_seconds = (
            reconciliation_lease_seconds
        )


__all__ = [
    "AMBIGUOUS_ATTEMPT_STATES",
    "RECOVERY_APPROVAL_SCOPE",
    "RECOVERY_APPROVABLE_INCIDENT_STATUS",
    "FlowProofService",
    "IdempotencyConflict",
    "PayloadRejected",
    "ReconciliationRequired",
    "RecoveryGateError",
    "as_json",
    "decision_note_digest",
    "normalize_utc",
    "redact",
    "utc_now",
]
