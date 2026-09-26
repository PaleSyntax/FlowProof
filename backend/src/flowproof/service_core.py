"""Shared FlowProof primitives without an executable service state machine."""

from __future__ import annotations

from flowproof._service_runtime_base import (
    AMBIGUOUS_ATTEMPT_STATES,
    RECOVERY_APPROVABLE_INCIDENT_STATUS,
    RECOVERY_APPROVAL_SCOPE,
    IdempotencyConflict,
    PayloadRejected,
    RecoveryGateError,
    as_json,
    decision_note_digest,
    event_ids,
    first_event,
    json_path,
    normalize_utc,
    parse_duration,
    redact,
    utc_now,
)

__all__ = [
    "AMBIGUOUS_ATTEMPT_STATES",
    "RECOVERY_APPROVAL_SCOPE",
    "RECOVERY_APPROVABLE_INCIDENT_STATUS",
    "IdempotencyConflict",
    "PayloadRejected",
    "RecoveryGateError",
    "as_json",
    "decision_note_digest",
    "event_ids",
    "first_event",
    "json_path",
    "normalize_utc",
    "parse_duration",
    "redact",
    "utc_now",
]


def __getattr__(name: str) -> object:
    if name == "FlowProofService":
        raise AttributeError(
            "flowproof.service_core has no executable FlowProofService; "
            "use flowproof.service.FlowProofService"
        )
    raise AttributeError(name)
