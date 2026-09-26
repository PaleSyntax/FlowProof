"""Non-executable base for the single public FlowProof service runtime.

The implementation payload is private and is imported only so the canonical
``flowproof.service.FlowProofService`` can inherit the established primitives.
Neither this module nor ``flowproof.service_core`` exposes an executable
``FlowProofService`` symbol.
"""

from __future__ import annotations

from typing import Any

from flowproof._service_runtime_implementation import (
    AMBIGUOUS_ATTEMPT_STATES,
    RECOVERY_APPROVABLE_INCIDENT_STATUS,
    RECOVERY_APPROVAL_SCOPE,
    IdempotencyConflict,
    PayloadRejected,
    RecoveryGateError,
    _FlowProofRuntimeImplementation,
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


class _FlowProofRuntimeBase(_FlowProofRuntimeImplementation):
    """Inheritance-only runtime base; direct construction fails closed."""

    def __new__(cls, *args: Any, **kwargs: Any) -> _FlowProofRuntimeBase:
        del args, kwargs
        if cls is _FlowProofRuntimeBase:
            raise TypeError(
                "_FlowProofRuntimeBase is inheritance-only; "
                "use flowproof.service.FlowProofService"
            )
        if cls.__module__ != "flowproof.service" or cls.__name__ != "FlowProofService":
            raise TypeError(
                "only flowproof.service.FlowProofService may execute the runtime base"
            )
        return object.__new__(cls)

__all__ = [
    "AMBIGUOUS_ATTEMPT_STATES",
    "RECOVERY_APPROVAL_SCOPE",
    "RECOVERY_APPROVABLE_INCIDENT_STATUS",
    "_FlowProofRuntimeBase",
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
            "flowproof._service_runtime_base has no executable FlowProofService; "
            "use flowproof.service.FlowProofService"
        )
    raise AttributeError(name)
