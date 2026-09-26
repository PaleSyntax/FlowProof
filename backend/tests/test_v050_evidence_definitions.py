from __future__ import annotations

import inspect
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from flowproof.evidence import (
    CAPSULE_SCHEMA_VERSION,
    MIGRATION_HEAD,
    EvidenceError,
    verify_capsule,
)
from flowproof.evidence_attempt_genealogy import ATTEMPT_FIELDS
from flowproof.evidence_contract import (
    PROOF_EXTERNAL,
    PROOF_WRITE,
)
from flowproof.evidence_proof_paths import (
    PATH_VALIDATORS,
    verify_external_resolution,
    verify_resolved_after_write,
)
from flowproof.evidence_reservation_genealogy import (
    RESERVATION_FIELDS,
)


def _reservation(
    *,
    reservation_id: str,
    attempt_id: str,
    plan_id: str,
    state: str = "EFFECT_PRESENT",
) -> dict[str, object]:
    now = datetime.now(UTC)
    safe_outcome: dict[str, object] = {}
    if state == "EFFECT_PRESENT":
        safe_outcome = {
            "provider_write_outcome": {
                "classification": "ACCEPTED"
            },
            "authoritative_reconciliation": {
                "classification": "AVAILABLE_PRESENT"
            },
        }
    return {
        "id": reservation_id,
        "recovery_attempt_id": attempt_id,
        "recovery_plan_id": plan_id,
        "approval_decision_id": str(uuid4()),
        "invocation_ordinal": 1,
        "request_digest": "a" * 64,
        "reserved_at": now.isoformat(),
        "state": state,
        "dispatch_owner": "dispatcher-a",
        "dispatch_generation": 1,
        "dispatch_started_at": now.isoformat(),
        "dispatch_lease_expires_at": (
            now + timedelta(seconds=60)
        ).isoformat(),
        "abandoned_at": None,
        "abandoned_by": None,
        "abandonment_reason": None,
        "reconciliation_owner": "reconciler-a",
        "reconciliation_generation": 1,
        "reconciliation_started_at": now.isoformat(),
        "reconciliation_lease_expires_at": (
            now + timedelta(seconds=60)
        ).isoformat(),
        "reconciliation_abandoned_at": None,
        "outcome_classification": "ACCEPTED",
        "outcome_observed_at": now.isoformat(),
        "provider_operation_reference": "operation-1",
        "retry_after_seconds": None,
        "safe_outcome": safe_outcome,
        "completed_at": now.isoformat(),
        "lock_version": 4,
    }


def _attempt(
    *,
    attempt_id: str,
    plan_id: str,
    reservation_id: str | None,
    state: str = "VERIFIED",
) -> dict[str, object]:
    now = datetime.now(UTC)
    history: list[dict[str, object]] = []
    if reservation_id is not None:
        history = [
            {
                "reservation_id": reservation_id,
                "observation": {
                    "classification": "AVAILABLE_PRESENT"
                },
                "reconciled_at": now.isoformat(),
                "prior_attempt_state": "OUTCOME_UNKNOWN",
                "prior_reservation_state": "OUTCOME_UNKNOWN",
                "transport_invocation_count": 1,
                "reapproval_action": None,
                "retry_reason": None,
                "write_outcome": {
                    "classification": "ACCEPTED"
                },
                "reconciliation_claim": {
                    "owner": "reconciler-a",
                    "generation": 1,
                    "reservation_lock_version": 2,
                    "attempt_lock_version": 2,
                    "lease_expires_at": (
                        now + timedelta(seconds=60)
                    ).isoformat(),
                    "reason": "explicit_reconcile",
                },
            }
        ]
    return {
        "id": attempt_id,
        "recovery_plan_id": plan_id,
        "incident_id": str(uuid4()),
        "approval_decision_id": str(uuid4()),
        "active_transport_invocation_id": reservation_id,
        "attempt_ordinal": 1,
        "execution_idempotency_key_digest": "b" * 64,
        "plan_hash": "c" * 64,
        "provider_contract_digest": "d" * 64,
        "provider_id": "mock-accounting",
        "provider_environment": "sandbox",
        "adapter_version": "fixture",
        "request_digest": "e" * 64,
        "precondition_observation_digest": "f" * 64,
        "state": state,
        "outcome_classification": "ACCEPTED",
        "provider_operation_reference": "operation-1",
        "retry_after_seconds": None,
        "semantic_attempt_count": 1,
        "transport_invocation_count": (
            1 if reservation_id is not None else 0
        ),
        "retry_permitted": False,
        "retry_reason": None,
        "safe_result": {
            "reconciliation_history": history
        },
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "accepted_at": now.isoformat(),
        "reconciled_at": now.isoformat(),
        "lock_version": 4,
    }


def test_evidence_capsule_declares_v11_and_migration_0010() -> None:
    assert CAPSULE_SCHEMA_VERSION == "1.1"
    assert MIGRATION_HEAD == "0010_release_groundwork_fencing"


def test_full_reservation_and_reconciliation_claim_genealogy_is_required() -> None:
    plan_id = str(uuid4())
    attempt_id = str(uuid4())
    reservation_id = str(uuid4())
    attempt = _attempt(
        attempt_id=attempt_id,
        plan_id=plan_id,
        reservation_id=reservation_id,
    )
    reservation = _reservation(
        reservation_id=reservation_id,
        attempt_id=attempt_id,
        plan_id=plan_id,
    )
    assert set(reservation) == RESERVATION_FIELDS
    assert set(attempt) == ATTEMPT_FIELDS
    assert reservation["dispatch_generation"] == 1
    assert reservation["reconciliation_generation"] == 1
    assert attempt["safe_result"]["reconciliation_history"]


def test_superseded_external_resolution_has_a_strict_zero_write_path() -> None:
    assert (
        PATH_VALIDATORS[PROOF_EXTERNAL]
        is verify_external_resolution
    )
    source = inspect.getsource(verify_external_resolution)
    for required_boundary in (
        "context.plan.get(\"executed_at\") is not None",
        "reservations.by_id",
        "external.get(\"transport_invocation_count\") != 0",
        "external.get(\"reservation_id\") is not None",
    ):
        assert required_boundary in source


def test_resolved_after_write_requires_same_reservation_outcome_and_reread() -> None:
    assert (
        PATH_VALIDATORS[PROOF_WRITE]
        is verify_resolved_after_write
    )
    source = inspect.getsource(verify_resolved_after_write)
    for required_boundary in (
        "reservation.get(\"state\") != \"EFFECT_PRESENT\"",
        "authoritative_reconciliation",
        "latest_incident_evaluation(context)",
        "_validate_write_causal_times",
    ):
        assert required_boundary in source


def test_legacy_capsule_requires_explicit_version_policy(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-v1.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "manifest.json",
            json.dumps({"schema_version": "1.0"}),
        )
    with pytest.raises(
        EvidenceError,
        match="requires explicit allow_legacy_v1 policy",
    ):
        verify_capsule(
            path,
            expected_bundle_sha256="a" * 64,
            expected_git_commit="b" * 40,
            expected_git_tree="c" * 40,
        )
