"""Explicit immutable safe projection for evidence capsule v1.1."""

from __future__ import annotations

import math
from typing import Any

from flowproof import evidence_legacy_v1_core as strict

V11_SAFE_KEYS = frozenset(
    {
        "abandoned_at",
        "accepted",
        "actual",
        "active_reservation_id",
        "adapter_version",
        "after",
        "amount",
        "attempt_id",
        "attempt_lock_version",
        "authority",
        "authoritative_reconciliation",
        "available",
        "causal_dispatch_boundary",
        "checked_at",
        "classification",
        "content_digest",
        "count",
        "currency",
        "duplicate",
        "entity_reference",
        "environment",
        "equals_event",
        "error_code",
        "error_type",
        "event",
        "event_ids",
        "evidence",
        "executed_at",
        "exists",
        "expect",
        "expected",
        "external_resolution",
        "field_checks",
        "fields",
        "generation",
        "id",
        "incident_id",
        "invariant_id",
        "invoice_id",
        "lease_expires_at",
        "message",
        "migration_head",
        "observation",
        "observation_content_digest",
        "observed_at",
        "operation_reference",
        "outcome_classification",
        "owner",
        "path",
        "pending_external_pass",
        "plan_state",
        "policy_evaluation_id",
        "postcondition",
        "precondition",
        "presence_count",
        "previous_state",
        "prior_attempt_state",
        "prior_reservation_state",
        "provider_exception",
        "provider_id",
        "provider_operation_reference",
        "provider_write_outcome",
        "reapproval_action",
        "reason",
        "reconciled_at",
        "reconciliation_claim",
        "reconciliation_claim_history",
        "reconciliation_generation",
        "reconciliation_history",
        "reconciliation_method",
        "reconciliation_observation",
        "records",
        "recovery_blocked",
        "reservation_id",
        "reservation_lock_version",
        "reservation_state",
        "resolved_at",
        "retry_after_seconds",
        "retry_permitted",
        "retry_reason",
        "safe_outcome",
        "safe_result",
        "started_at",
        "status",
        "status_code",
        "tolerance",
        "transport_invocation_count",
        "transport_reservation_id",
        "unique",
        "within",
        "write_outcome",
    }
)


def project_safe_value(value: object, *, path: str = "$") -> object:
    """Project bounded evidence without process-global substitutions."""

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if strict.SECRET_KEY.search(key):
                raise strict.EvidenceError(
                    f"forbidden evidence field at {path}.{key}"
                )
            if key not in V11_SAFE_KEYS:
                raise strict.EvidenceError(
                    f"unsupported v1.1 evidence key at {path}.{key}"
                )
            result[key] = project_safe_value(
                item,
                path=f"{path}.{key}",
            )
        return result
    if isinstance(value, list):
        if len(value) > 256:
            raise strict.EvidenceError(
                f"evidence list exceeds its safe bound at {path}"
            )
        return [
            project_safe_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        if len(value) > 2_048:
            raise strict.EvidenceError(
                f"evidence string exceeds its safe bound at {path}"
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise strict.EvidenceError(
                f"non-finite evidence value at {path}"
            )
        return value
    if isinstance(value, (bool, int)) or value is None:
        return value
    raise strict.EvidenceError(f"unsupported evidence value at {path}")
