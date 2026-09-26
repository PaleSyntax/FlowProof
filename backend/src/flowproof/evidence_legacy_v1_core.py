"""Deterministic, sanitized, provider-neutral lifecycle evidence capsules."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from flowproof.accounting import ProviderContract
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory
from flowproof.models import (
    BusinessEvent,
    Incident,
    OperatorReview,
    Policy,
    PolicyEvaluation,
    RecoveryAttempt,
    RecoveryDecision,
    RecoveryPlan,
    RecoveryTransportInvocation,
    SecurityAuditEvent,
)

EVIDENCE_PACKAGE_VERSION = "0.6.0"
CAPSULE_SCHEMA_VERSION = "1.0"
MIGRATION_HEAD = "0009_outcome_assured_recovery"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
SECRET_KEY = re.compile(
    r"password|secret(?!_reference)|(?<!idempotency_)token|"
    r"authorization(?!_scope)|cookie|api[_-]?key|private[_-]?key|csrf",
    re.I,
)
SECRET_VALUE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/=-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)",
    re.I,
)
REVIEW_SUBJECT_EXCLUDED = frozenset({"operator-review.json", "audit-references.json"})
MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "package_version",
        "git_commit",
        "git_tree",
        "migration_head",
        "evidence_classification",
        "incident_id",
        "correlation_id",
        "policy_name",
        "policy_version",
        "policy_hash",
        "provider_contract_digest",
        "files",
        "review_subject_sha256",
        "review_subject_digest_scope",
        "bundle_sha256",
        "bundle_digest_scope",
    }
)


class EvidenceError(ValueError):
    pass


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _object_sha256(value: object) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    )


def _time(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat().replace("+00:00", "Z")


def _evidence_time(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{field_name} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{field_name} is not a timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{field_name} is not timezone-aware")
    return parsed.astimezone(UTC)


def _strict_int(value: object, field_name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise EvidenceError(f"{field_name} is not a bounded integer")
    return value


def _human_actor_is_bounded(actor: object) -> bool:
    if not isinstance(actor, dict):
        return False
    if set(actor) == {"bundle_scoped_digest"}:
        return bool(SHA256.fullmatch(str(actor.get("bundle_scoped_digest"))))
    if set(actor) == {"principal_id", "display_name"}:
        try:
            UUID(str(actor.get("principal_id")))
        except (TypeError, ValueError):
            return False
        return isinstance(actor.get("display_name"), str) and bool(actor["display_name"])
    return False


OBSERVATION_KEYS = frozenset(
    {
        "classification",
        "provider_id",
        "environment",
        "adapter_version",
        "entity_reference",
        "observed_at",
        "presence_count",
        "records",
        "operation_reference",
        "retry_after_seconds",
        "error_code",
        "content_digest",
    }
)
WRITE_OUTCOME_KEYS = frozenset(
    {
        "classification",
        "provider_id",
        "environment",
        "adapter_version",
        "observed_at",
        "operation_reference",
        "retry_after_seconds",
        "safe_result",
        "error_code",
        "content_digest",
    }
)


def _validate_observation(
    value: object,
    *,
    field_name: str,
    classification: str,
    entity_id: str,
    provider: ProviderContract,
    require_authoritative: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS:
        raise EvidenceError(f"{field_name} is missing its typed observation")
    body = {key: item for key, item in value.items() if key != "content_digest"}
    if value.get("content_digest") != _object_sha256(body):
        raise EvidenceError(f"{field_name} content digest mismatch")
    records = value.get("records")
    presence_count = value.get("presence_count")
    if classification == "AVAILABLE_PRESENT":
        count_matches = presence_count == 1 and isinstance(records, list) and len(records) == 1
    elif classification == "AVAILABLE_CONFLICT":
        count_matches = (
            isinstance(presence_count, int)
            and not isinstance(presence_count, bool)
            and presence_count >= 2
            and isinstance(records, list)
            and len(records) == presence_count
        )
    else:
        count_matches = presence_count == 0 and isinstance(records, list) and not records
    if (
        value.get("classification") != classification
        or value.get("provider_id") != provider.provider_id
        or value.get("environment") != provider.environment
        or value.get("adapter_version") != provider.adapter_version
        or value.get("entity_reference") != entity_id
        or not count_matches
        or any(not isinstance(record, dict) for record in records)
        or (
            require_authoritative
            and (
                value.get("retry_after_seconds") is not None
                or value.get("error_code") is not None
            )
        )
    ):
        raise EvidenceError(f"{field_name} does not prove the required authoritative state")
    _evidence_time(value.get("observed_at"), f"{field_name}.observed_at")
    operation_reference = value.get("operation_reference")
    if operation_reference is not None and (
        not isinstance(operation_reference, str) or not operation_reference
    ):
        raise EvidenceError(f"{field_name} operation reference is invalid")
    retry_after_seconds = value.get("retry_after_seconds")
    if retry_after_seconds is not None and (
        not isinstance(retry_after_seconds, int)
        or isinstance(retry_after_seconds, bool)
        or not 0 <= retry_after_seconds <= 86_400
    ):
        raise EvidenceError(f"{field_name} retry-after value is invalid")
    error_code = value.get("error_code")
    if error_code is not None and (
        not isinstance(error_code, str) or not error_code or len(error_code) > 64
    ):
        raise EvidenceError(f"{field_name} error code is invalid")
    return value


def _validate_write_outcome(
    value: object,
    *,
    expected_classification: object,
    provider: ProviderContract,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != WRITE_OUTCOME_KEYS:
        raise EvidenceError("attempt lacks its typed provider write outcome")
    body = {key: item for key, item in value.items() if key != "content_digest"}
    if value.get("content_digest") != _object_sha256(body):
        raise EvidenceError("provider write outcome content digest mismatch")
    if (
        value.get("classification") != expected_classification
        or value.get("provider_id") != provider.provider_id
        or value.get("environment") != provider.environment
        or value.get("adapter_version") != provider.adapter_version
        or not isinstance(value.get("safe_result"), dict)
    ):
        raise EvidenceError("provider write outcome binding is invalid")
    _evidence_time(value.get("observed_at"), "write_outcome.observed_at")
    return value


def _validate_plan_semantics(
    plan: dict[str, Any],
    incident: dict[str, Any],
    policy: dict[str, Any],
    timeline: list[dict[str, Any]],
    provider: ProviderContract,
    contract_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    parameters = plan.get("parameters")
    guardrails = plan.get("guardrails")
    expected_guardrail_keys = {
        "provider_id",
        "environment",
        "sandbox_only",
        "entity_type",
        "entity_id",
        "action_type",
        "allowed_currencies",
        "maximum_amount_minor",
        "amount_scale",
        "observed_amount_minor",
        "maximum_semantic_write_attempts",
        "maximum_transport_invocations",
        "approval_ttl_seconds",
        "provider_contract_digest",
        "reconciliation_method",
        "batch_allowed",
        "wildcards_allowed",
    }
    if (
        not isinstance(parameters, dict)
        or set(parameters) != {"invoice_id", "amount", "currency"}
        or not isinstance(guardrails, dict)
        or set(guardrails) != expected_guardrail_keys
    ):
        raise EvidenceError("recovery parameters or immutable guardrails are incomplete")
    invoice_id = parameters.get("invoice_id")
    if (
        plan.get("action_type") != "register_missing_invoice"
        or plan.get("risk_level") != "bounded_sandbox_write"
        or plan.get("requires_approval") is not True
        or incident.get("entity_type") != "invoice"
        or not isinstance(invoice_id, str)
        or not invoice_id
        or invoice_id != incident.get("entity_id")
        or guardrails.get("entity_type") != "invoice"
        or guardrails.get("entity_id") != invoice_id
        or guardrails.get("action_type") != plan.get("action_type")
    ):
        raise EvidenceError("recovery parameters do not name the exact incident subject")
    if (
        guardrails.get("provider_id") != provider.provider_id
        or guardrails.get("environment") != provider.environment
        or guardrails.get("sandbox_only") is not True
        or guardrails.get("provider_contract_digest") != contract_digest
        or not isinstance(provider.authoritative_read, dict)
        or guardrails.get("reconciliation_method") != "authoritative_invoice_reread"
        or guardrails.get("batch_allowed") is not False
        or guardrails.get("wildcards_allowed") is not False
        or provider.authoritative_read.get("not_found") != "AVAILABLE_ABSENT"
    ):
        raise EvidenceError("recovery guardrails do not derive from the provider contract")
    if guardrails.get("maximum_transport_invocations") != _strict_int(
        provider.maximum_safe_write_attempts,
        "provider maximum_safe_write_attempts",
        minimum=1,
    ):
        raise EvidenceError("transport invocation limit does not derive from the provider contract")
    if _strict_int(
        guardrails.get("maximum_semantic_write_attempts"),
        "maximum_semantic_write_attempts",
        minimum=1,
    ) != 1:
        raise EvidenceError("recovery exceeds the one-semantic-attempt boundary")
    _strict_int(guardrails.get("approval_ttl_seconds"), "approval_ttl_seconds", minimum=1)
    scale = _strict_int(guardrails.get("amount_scale"), "amount_scale")
    if scale > 9:
        raise EvidenceError("amount_scale exceeds the verifier precision bound")
    maximum_minor = _strict_int(guardrails.get("maximum_amount_minor"), "maximum_amount_minor")
    observed_minor = _strict_int(guardrails.get("observed_amount_minor"), "observed_amount_minor")
    allowed_currencies = guardrails.get("allowed_currencies")
    if (
        not isinstance(allowed_currencies, list)
        or not allowed_currencies
        or any(not isinstance(item, str) or not item for item in allowed_currencies)
        or len(set(allowed_currencies)) != len(allowed_currencies)
        or parameters.get("currency") not in allowed_currencies
    ):
        raise EvidenceError("recovery currency is outside the immutable guardrail")
    try:
        amount = Decimal(str(parameters.get("amount")))
        quantum = Decimal(1).scaleb(-scale)
        if not amount.is_finite() or amount != amount.quantize(quantum):
            raise EvidenceError("recovery amount violates the immutable precision guardrail")
        derived_minor = int(amount * (Decimal(10) ** scale))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise EvidenceError("recovery amount is invalid") from exc
    if amount < 0 or derived_minor != observed_minor or observed_minor > maximum_minor:
        raise EvidenceError("recovery amount is outside the immutable guardrail")
    definition = policy.get("definition")
    recovery = definition.get("recovery") if isinstance(definition, dict) else None
    impact = definition.get("impact") if isinstance(definition, dict) else None
    configured = recovery.get("guardrails") if isinstance(recovery, dict) else None
    invariants = definition.get("invariants") if isinstance(definition, dict) else None
    invariant = next(
        (
            item
            for item in invariants or []
            if isinstance(item, dict) and item.get("id") == incident.get("invariant_id")
        ),
        None,
    )
    configured_fields = {
        "provider_id",
        "environment",
        "sandbox_only",
        "allowed_currencies",
        "maximum_amount_minor",
        "amount_scale",
        "maximum_semantic_write_attempts",
        "approval_ttl_seconds",
        "reconciliation_method",
    }
    if (
        not isinstance(recovery, dict)
        or recovery.get("action_type") != plan.get("action_type")
        or not isinstance(configured, dict)
        or any(configured.get(key) != guardrails.get(key) for key in configured_fields)
        or not isinstance(invariant, dict)
        or invariant.get("recovery_action") != plan.get("action_type")
        or definition.get("entity_type") != incident.get("entity_type")
    ):
        raise EvidenceError("recovery guardrails do not derive from the policy snapshot")
    expected_fields = invariant.get("expect", {}).get("fields", {})
    amount_rule = expected_fields.get("amount", {}).get("equals_event", {})
    currency_rule = expected_fields.get("currency", {}).get("equals_event", {})
    if (
        not isinstance(impact, dict)
        or set(impact) != {"amount_event", "amount_path", "currency_path"}
        or impact.get("amount_path") != "$.amount"
        or impact.get("currency_path") != "$.currency"
        or amount_rule
        != {"event": impact.get("amount_event"), "path": impact.get("amount_path")}
        or currency_rule
        != {"event": impact.get("amount_event"), "path": impact.get("currency_path")}
    ):
        raise EvidenceError("recovery source fields do not derive from the policy snapshot")
    source_events = [
        event for event in timeline if event.get("event_type") == impact.get("amount_event")
    ]
    if len(source_events) != 1:
        raise EvidenceError("capsule lacks exactly one policy-selected recovery source event")
    source_projection = source_events[0].get("payload_projection")
    if (
        not isinstance(source_projection, dict)
        or set(source_projection) != {"amount", "currency"}
        or not isinstance(source_projection.get("currency"), str)
        or source_projection.get("currency") != parameters.get("currency")
    ):
        raise EvidenceError("recovery parameters contradict the policy-selected source event")
    try:
        source_amount = Decimal(str(source_projection.get("amount")))
        source_minor = int(source_amount * (Decimal(10) ** scale))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise EvidenceError("policy-selected recovery source amount is invalid") from exc
    if source_amount != amount or source_minor != observed_minor:
        raise EvidenceError("recovery parameters contradict the policy-selected source event")
    return parameters, guardrails


def _operator_digest(incident_id: str, principal_id: str) -> str:
    return _sha256(f"flowproof-capsule:{incident_id}:{principal_id}".encode())


def _package_version() -> str:
    explicit = os.getenv("FLOWPROOF_PACKAGE_VERSION")
    if explicit:
        return explicit
    # A source checkout may contain stale generated ``*.egg-info`` metadata.
    # Evidence must follow the reviewed source version unless a package builder
    # deliberately supplies its exact version through the environment.
    return EVIDENCE_PACKAGE_VERSION


def _safe_event(row: BusinessEvent) -> dict[str, Any]:
    for key, value in row.payload.items():
        if SECRET_KEY.search(str(key)) and value != "[REDACTED]":
            raise EvidenceError(f"raw secret-like event field cannot be exported: {key}")
    payload = {
        key: row.payload[key]
        for key in ("amount", "currency")
        if key in row.payload and isinstance(row.payload[key], (str, int, float, bool))
    }
    return {
        "id": row.id,
        "idempotency_key_digest": _sha256(row.idempotency_key.encode("utf-8")),
        "correlation_id": row.correlation_id,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "event_type": row.event_type,
        "occurred_at": _time(row.occurred_at),
        "ingested_at": _time(row.ingested_at),
        "source_system": row.source_system,
        "workflow_id": row.workflow_id,
        "workflow_version": row.workflow_version,
        "execution_id_digest": (
            _sha256(row.execution_id.encode("utf-8")) if row.execution_id else None
        ),
        "payload_projection": payload,
        "content_hash": row.content_hash,
    }


def _safe_observation(value: object) -> object:
    if isinstance(value, list):
        return [_safe_observation(item) for item in value]
    if not isinstance(value, dict):
        return value if isinstance(value, (str, int, float, bool)) or value is None else None
    allowed = {
        "classification",
        "provider_id",
        "environment",
        "adapter_version",
        "entity_reference",
        "observed_at",
        "presence_count",
        "records",
        "operation_reference",
        "retry_after_seconds",
        "error_code",
        "content_digest",
        "expected",
        "actual",
        "field_checks",
        "event_ids",
        "status",
        "status_code",
        "checked_at",
        "incident_id",
        "evidence",
        "safe_result",
        "attempt_id",
        "write_outcome",
        "postcondition",
        "precondition",
        "reconciliation_observation",
        "reconciliation_history",
        "reconciled_at",
        "reapproval_action",
        "transport_invocation_count",
        "prior_attempt_state",
        "retry_reason",
        "observation",
        "accepted",
        "duplicate",
        "invoice_id",
        "id",
        "amount",
        "currency",
    }
    result: dict[str, Any] = {}
    for key in value:
        if SECRET_KEY.search(str(key)):
            raise EvidenceError(f"forbidden evidence field: {key}")
    for key in sorted(allowed.intersection(value)):
        result[key] = _safe_observation(value[key])
    return result


def _assert_secret_free(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY.search(str(key)):
                raise EvidenceError(f"secret-like key at {path}.{key}")
            _assert_secret_free(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_secret_free(item, f"{path}[{index}]")
        return
    if isinstance(value, str) and SECRET_VALUE.search(value):
        raise EvidenceError(f"secret-like value at {path}")


def _plan_document(plan: RecoveryPlan, incident_id: str, private_identity: bool) -> dict[str, Any]:
    approval_actor = None
    context = plan.approval_context if isinstance(plan.approval_context, dict) else {}
    principal_id = context.get("actor_principal_id")
    if principal_id:
        approval_actor = (
            {"principal_id": principal_id, "display_name": context.get("actor_name")}
            if private_identity
            else {"bundle_scoped_digest": _operator_digest(incident_id, str(principal_id))}
        )
    return {
        "id": plan.id,
        "incident_id": plan.incident_id,
        "action_type": plan.action_type,
        "parameters": {
            key: plan.parameters.get(key) for key in ("invoice_id", "amount", "currency")
        },
        "idempotency_key_digest": _sha256(plan.idempotency_key.encode("utf-8")),
        "risk_level": plan.risk_level,
        "requires_approval": plan.requires_approval,
        "status": plan.status,
        "plan_hash": plan.plan_hash,
        "provider_id": plan.provider_id,
        "provider_environment": plan.provider_environment,
        "adapter_version": plan.adapter_version,
        "provider_contract_digest": plan.provider_contract_digest,
        "guardrails": plan.guardrails,
        "approval_actor": approval_actor,
        "approved_at": _time(plan.approved_at),
        "approval_expires_at": _time(plan.approval_expires_at),
        "executed_at": _time(plan.executed_at),
        "verified_at": _time(plan.verified_at),
        "result": _safe_observation(plan.result),
    }


def _decision_document(
    row: RecoveryDecision, incident_id: str, private_identity: bool
) -> dict[str, Any]:
    actor = (
        {"system": "flowproof"}
        if row.actor_principal_id is None
        else {"principal_id": row.actor_principal_id, "display_name": row.actor_display_name}
        if private_identity
        else {"bundle_scoped_digest": _operator_digest(incident_id, row.actor_principal_id)}
    )
    return {
        "id": row.id,
        "recovery_plan_id": row.recovery_plan_id,
        "incident_id": row.incident_id,
        "request_id_digest": _sha256(row.request_id.encode("utf-8")),
        "action": row.action,
        "decision_kind": row.decision_kind,
        "actor": actor,
        "authorization_scope": row.authorization_scope,
        "plan_hash": row.plan_hash,
        "provider_contract_digest": row.provider_contract_digest,
        "incident_state_observed": row.incident_state_observed,
        "plan_state_observed": row.plan_state_observed,
        "reason_code": row.reason_code,
        "note_digest": row.note_digest,
        "previous_plan_state": row.previous_plan_state,
        "resulting_plan_state": row.resulting_plan_state,
        "previous_incident_state": row.previous_incident_state,
        "resulting_incident_state": row.resulting_incident_state,
        "decided_at": _time(row.decided_at),
        "approval_expires_at": _time(row.approval_expires_at),
    }


def _attempt_document(row: RecoveryAttempt) -> dict[str, Any]:
    return {
        "id": row.id,
        "recovery_plan_id": row.recovery_plan_id,
        "incident_id": row.incident_id,
        "approval_decision_id": row.approval_decision_id,
        "attempt_ordinal": row.attempt_ordinal,
        "execution_idempotency_key_digest": _sha256(row.execution_idempotency_key.encode("utf-8")),
        "plan_hash": row.plan_hash,
        "provider_contract_digest": row.provider_contract_digest,
        "provider_id": row.provider_id,
        "provider_environment": row.provider_environment,
        "adapter_version": row.adapter_version,
        "request_digest": row.request_digest,
        "precondition_observation_digest": row.precondition_observation_digest,
        "state": row.state,
        "outcome_classification": row.outcome_classification,
        "provider_operation_reference": row.provider_operation_reference,
        "retry_after_seconds": row.retry_after_seconds,
        "semantic_attempt_count": row.semantic_attempt_count,
        "transport_invocation_count": row.transport_invocation_count,
        "retry_permitted": row.retry_permitted,
        "retry_reason": row.retry_reason,
        "safe_result": _safe_observation(row.safe_result),
        "created_at": _time(row.created_at),
        "updated_at": _time(row.updated_at),
        "accepted_at": _time(row.accepted_at),
        "reconciled_at": _time(row.reconciled_at),
    }


def _transport_invocation_document(row: RecoveryTransportInvocation) -> dict[str, Any]:
    return {
        "id": row.id,
        "recovery_attempt_id": row.recovery_attempt_id,
        "recovery_plan_id": row.recovery_plan_id,
        "approval_decision_id": row.approval_decision_id,
        "invocation_ordinal": row.invocation_ordinal,
        "request_digest": row.request_digest,
        "reserved_at": _time(row.reserved_at),
    }


def _review_document(
    row: OperatorReview, incident_id: str, private_identity: bool
) -> dict[str, Any]:
    actor = (
        {"principal_id": row.actor_principal_id, "display_name": row.actor_display_name}
        if private_identity
        else {"bundle_scoped_digest": _operator_digest(incident_id, row.actor_principal_id)}
    )
    return {
        "id": row.id,
        "incident_id": row.incident_id,
        "recovery_plan_id": row.recovery_plan_id,
        "request_id_digest": _sha256(row.request_id.encode("utf-8")),
        "actor": actor,
        "plan_hash": row.plan_hash,
        "capsule_digest": row.capsule_digest,
        "evidence_understood": row.evidence_understood,
        "authoritative_source_understood": row.authoritative_source_understood,
        "blast_radius_understood": row.blast_radius_understood,
        "proposed_action_understood": row.proposed_action_understood,
        "reject_path_available": row.reject_path_available,
        "revoke_path_available": row.revoke_path_available,
        "reconciliation_path_understood": row.reconciliation_path_understood,
        "final_decision": row.final_decision,
        "note_digest": row.note_digest,
        "verdict": row.verdict,
        "reviewed_at": _time(row.reviewed_at),
    }


def build_documents(
    session: Session, incident_id: str, *, private_identity: bool = False
) -> dict[str, bytes]:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise EvidenceError("incident not found")
    plan = session.scalar(select(RecoveryPlan).where(RecoveryPlan.incident_id == incident.id))
    if plan is None:
        raise EvidenceError("incident has no recovery plan")
    policy = session.scalar(
        select(Policy).where(
            Policy.name == incident.policy_name, Policy.version == incident.policy_version
        )
    )
    if policy is None:
        raise EvidenceError("incident policy snapshot not found")
    events = session.scalars(
        select(BusinessEvent)
        .where(BusinessEvent.correlation_id == incident.correlation_id)
        .order_by(BusinessEvent.occurred_at, BusinessEvent.id)
    ).all()
    evaluations = session.scalars(
        select(PolicyEvaluation)
        .where(PolicyEvaluation.correlation_id == incident.correlation_id)
        .order_by(PolicyEvaluation.evaluated_at, PolicyEvaluation.id)
    ).all()
    decisions = session.scalars(
        select(RecoveryDecision)
        .where(RecoveryDecision.recovery_plan_id == plan.id)
        .order_by(RecoveryDecision.decided_at, RecoveryDecision.id)
    ).all()
    attempts = session.scalars(
        select(RecoveryAttempt)
        .where(RecoveryAttempt.recovery_plan_id == plan.id)
        .order_by(RecoveryAttempt.attempt_ordinal, RecoveryAttempt.created_at)
    ).all()
    attempt_ids = [attempt.id for attempt in attempts]
    transport_invocations = (
        session.scalars(
            select(RecoveryTransportInvocation)
            .where(RecoveryTransportInvocation.recovery_attempt_id.in_(attempt_ids))
            .order_by(
                RecoveryTransportInvocation.invocation_ordinal,
                RecoveryTransportInvocation.reserved_at,
            )
        ).all()
        if attempt_ids
        else []
    )
    reviews = session.scalars(
        select(OperatorReview)
        .where(OperatorReview.recovery_plan_id == plan.id)
        .order_by(OperatorReview.reviewed_at, OperatorReview.id)
    ).all()
    audits = session.scalars(
        select(SecurityAuditEvent)
        .where(
            or_(
                SecurityAuditEvent.correlation_id == incident.correlation_id,
                SecurityAuditEvent.target_id.in_([incident.id, plan.id]),
            )
        )
        .order_by(SecurityAuditEvent.occurred_at, SecurityAuditEvent.id)
    ).all()

    incident_document = {
        "id": incident.id,
        "correlation_id": incident.correlation_id,
        "entity_type": incident.entity_type,
        "entity_id": incident.entity_id,
        "policy_name": incident.policy_name,
        "policy_version": incident.policy_version,
        "invariant_id": incident.invariant_id,
        "severity": incident.severity,
        "status": incident.status,
        "summary": incident.summary,
        "evidence": _safe_observation(incident.evidence),
        "opened_at": _time(incident.opened_at),
        "resolved_at": _time(incident.resolved_at),
    }
    evaluation_documents = [
        {
            "id": row.id,
            "policy_id": row.policy_id,
            "correlation_id": row.correlation_id,
            "invariant_id": row.invariant_id,
            "state": row.state,
            "evidence": _safe_observation(row.evidence),
            "evaluated_at": _time(row.evaluated_at),
        }
        for row in evaluations
    ]
    postconditions = [
        item
        for item in (
            _safe_observation(row.evidence)
            for row in evaluations
            if row.invariant_id == incident.invariant_id
        )
        if item
    ]
    audit_documents = [
        {
            "id": row.id,
            "occurred_at": _time(row.occurred_at),
            "action": row.action,
            "outcome": row.outcome,
            "actor": (
                {"principal_id": row.actor_principal_id}
                if private_identity and row.actor_principal_id
                else {"bundle_scoped_digest": _operator_digest(incident.id, row.actor_principal_id)}
                if row.actor_principal_id
                else None
            ),
            "target_type": row.target_type,
            "target_id": row.target_id,
            "request_id_digest": (
                _sha256(row.request_id.encode("utf-8")) if row.request_id else None
            ),
        }
        for row in audits
    ]
    git_commit = os.getenv("FLOWPROOF_GIT_COMMIT", "").strip().lower()
    git_tree = os.getenv("FLOWPROOF_GIT_TREE", "").strip().lower()
    if not GIT_OBJECT_ID.fullmatch(git_commit) or not GIT_OBJECT_ID.fullmatch(git_tree):
        raise EvidenceError(
            "exact FLOWPROOF_GIT_COMMIT and FLOWPROOF_GIT_TREE are required for export"
        )
    coordinates = {
        "package_version": _package_version(),
        "git_commit": git_commit,
        "git_tree": git_tree,
        "migration_head": MIGRATION_HEAD,
        "evidence_classification": "IMPLEMENTED_UNVERIFIED",
    }
    documents: dict[str, object] = {
        "release-coordinates.json": coordinates,
        "provider-contract.json": plan.provider_contract_snapshot,
        "policy.json": {
            "name": policy.name,
            "version": policy.version,
            "definition_hash": policy.definition_hash,
            "definition": policy.definition,
        },
        "incident.json": incident_document,
        "evaluations.json": evaluation_documents,
        "timeline-evidence.json": [_safe_event(row) for row in events],
        "recovery-plan.json": _plan_document(plan, incident.id, private_identity),
        "recovery-decisions.json": [
            _decision_document(row, incident.id, private_identity) for row in decisions
        ],
        "recovery-attempts.json": [_attempt_document(row) for row in attempts],
        "transport-invocations.json": [
            _transport_invocation_document(row) for row in transport_invocations
        ],
        "postcondition-observations.json": postconditions,
        "audit-references.json": audit_documents,
        "operator-review.json": [
            _review_document(row, incident.id, private_identity) for row in reviews
        ],
    }
    for name, value in documents.items():
        _assert_secret_free(value, name)
    return {name: _json_bytes(value) for name, value in documents.items()}


def _manifest(documents: dict[str, bytes], incident_id: str) -> dict[str, Any]:
    files = [
        {"name": name, "size": len(content), "sha256": _sha256(content)}
        for name, content in sorted(documents.items())
    ]
    content_root = _sha256(_json_bytes(files))
    review_subject_files = [item for item in files if item["name"] not in REVIEW_SUBJECT_EXCLUDED]
    review_subject_root = _sha256(_json_bytes(review_subject_files))
    provider = json.loads(documents["provider-contract.json"])
    policy = json.loads(documents["policy.json"])
    coordinates = json.loads(documents["release-coordinates.json"])
    return {
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "package_version": coordinates["package_version"],
        "git_commit": coordinates["git_commit"],
        "git_tree": coordinates["git_tree"],
        "migration_head": coordinates["migration_head"],
        "evidence_classification": coordinates["evidence_classification"],
        "incident_id": incident_id,
        "correlation_id": json.loads(documents["incident.json"])["correlation_id"],
        "policy_name": policy["name"],
        "policy_version": policy["version"],
        "policy_hash": policy["definition_hash"],
        "provider_contract_digest": provider["sha256"],
        "files": files,
        "review_subject_sha256": review_subject_root,
        "review_subject_digest_scope": (
            "canonical declared evidence members excluding the operator review and its "
            "security-audit reference"
        ),
        "bundle_sha256": content_root,
        "bundle_digest_scope": "canonical declared evidence members; manifest is the root",
    }


def export_capsule(
    session: Session,
    incident_id: str,
    output: Path,
    *,
    private_identity: bool = False,
) -> dict[str, str]:
    documents = build_documents(session, incident_id, private_identity=private_identity)
    manifest = _manifest(documents, incident_id)
    manifest_bytes = _json_bytes(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True
    ) as archive:
        for name, content in sorted({"manifest.json": manifest_bytes, **documents}.items()):
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)
    return {
        "path": str(output),
        "bundle_sha256": manifest["bundle_sha256"],
        "review_subject_sha256": manifest["review_subject_sha256"],
        "zip_sha256": _sha256(output.read_bytes()),
        "identity_mode": "owner-private" if private_identity else "sanitized",
    }


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _document_object(documents: dict[str, Any], name: str) -> dict[str, Any]:
    value = documents[name]
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must contain a JSON object")
    return value


def _document_list(documents: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = documents[name]
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise EvidenceError(f"{name} must contain a JSON object list")
    return value


def verify_capsule(
    path: Path,
    *,
    expected_bundle_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> dict[str, str]:
    if not SHA256.fullmatch(expected_bundle_sha256):
        raise EvidenceError("expected bundle trust anchor is not a SHA-256 digest")
    if not GIT_OBJECT_ID.fullmatch(expected_git_commit) or not GIT_OBJECT_ID.fullmatch(
        expected_git_tree
    ):
        raise EvidenceError("expected Git commit/tree trust anchors are invalid")
    if not path.is_file():
        raise EvidenceError("capsule file is missing")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or any(not _safe_member(name) for name in names):
                raise EvidenceError("capsule contains duplicate or unsafe member names")
            if "manifest.json" not in names:
                raise EvidenceError("manifest.json is missing")
            try:
                manifest = json.loads(archive.read("manifest.json"))
            except (json.JSONDecodeError, KeyError) as exc:
                raise EvidenceError("manifest is invalid") from exc
            if manifest.get("schema_version") != CAPSULE_SCHEMA_VERSION:
                raise EvidenceError("unsupported capsule schema version")
            if set(manifest) != MANIFEST_KEYS:
                raise EvidenceError("manifest schema contains missing or unknown fields")
            try:
                UUID(str(manifest["incident_id"]))
            except (ValueError, TypeError) as exc:
                raise EvidenceError("manifest incident identity is invalid") from exc
            for field_name in (
                "package_version",
                "git_commit",
                "git_tree",
                "migration_head",
                "evidence_classification",
                "correlation_id",
                "policy_name",
                "policy_version",
                "review_subject_digest_scope",
                "bundle_digest_scope",
            ):
                value = manifest.get(field_name)
                if not isinstance(value, str) or not value or len(value) > 255:
                    raise EvidenceError(f"manifest field {field_name} is invalid")
            for field_name in (
                "policy_hash",
                "provider_contract_digest",
                "review_subject_sha256",
                "bundle_sha256",
            ):
                if not isinstance(manifest.get(field_name), str) or not SHA256.fullmatch(
                    manifest[field_name]
                ):
                    raise EvidenceError(f"manifest field {field_name} is not a SHA-256 digest")
            declarations = manifest.get("files")
            if not isinstance(declarations, list):
                raise EvidenceError("manifest files declaration is invalid")
            declared_names = [item.get("name") for item in declarations if isinstance(item, dict)]
            if len(declared_names) != len(declarations) or len(declared_names) != len(
                set(declared_names)
            ):
                raise EvidenceError("manifest contains invalid or duplicate declarations")
            if set(names) != {"manifest.json", *declared_names}:
                raise EvidenceError("capsule has a missing or undeclared file")
            documents: dict[str, Any] = {}
            canonical_declarations: list[dict[str, Any]] = []
            for declaration in declarations:
                if set(declaration) != {"name", "size", "sha256"}:
                    raise EvidenceError("manifest file declaration schema is invalid")
                name = declaration["name"]
                if not _safe_member(name) or name == "manifest.json":
                    raise EvidenceError("manifest declares an unsafe member")
                content = archive.read(name)
                expected_size = declaration.get("size")
                expected_digest = declaration.get("sha256")
                if (
                    not isinstance(expected_size, int)
                    or isinstance(expected_size, bool)
                    or expected_size < 1
                    or not isinstance(expected_digest, str)
                    or not SHA256.fullmatch(expected_digest)
                    or len(content) != expected_size
                    or _sha256(content) != expected_digest
                ):
                    raise EvidenceError(f"digest or size mismatch for {name}")
                try:
                    documents[name] = json.loads(content)
                except json.JSONDecodeError as exc:
                    raise EvidenceError(f"invalid JSON member: {name}") from exc
                canonical_declarations.append(
                    {"name": name, "size": len(content), "sha256": _sha256(content)}
                )
            declared_root = _sha256(
                _json_bytes(sorted(canonical_declarations, key=lambda item: item["name"]))
            )
            if declared_root != manifest.get("bundle_sha256"):
                raise EvidenceError("bundle content digest mismatch")
            if declared_root != expected_bundle_sha256:
                raise EvidenceError("external bundle trust anchor mismatch")
            review_subject_declarations = [
                item
                for item in sorted(canonical_declarations, key=lambda item: item["name"])
                if item["name"] not in REVIEW_SUBJECT_EXCLUDED
            ]
            review_subject_root = _sha256(_json_bytes(review_subject_declarations))
            if review_subject_root != manifest.get("review_subject_sha256"):
                raise EvidenceError("operator review subject digest mismatch")
    except zipfile.BadZipFile as exc:
        raise EvidenceError("capsule is not a valid ZIP") from exc

    required = {
        "release-coordinates.json",
        "provider-contract.json",
        "policy.json",
        "incident.json",
        "evaluations.json",
        "timeline-evidence.json",
        "recovery-plan.json",
        "recovery-decisions.json",
        "recovery-attempts.json",
        "transport-invocations.json",
        "postcondition-observations.json",
        "audit-references.json",
        "operator-review.json",
    }
    if set(documents) != required:
        raise EvidenceError("capsule member set is not the required schema")
    for name, value in documents.items():
        _assert_secret_free(value, name)
    incident = _document_object(documents, "incident.json")
    plan = _document_object(documents, "recovery-plan.json")
    provider = _document_object(documents, "provider-contract.json")
    policy = _document_object(documents, "policy.json")
    coordinates = _document_object(documents, "release-coordinates.json")
    evaluations = _document_list(documents, "evaluations.json")
    timeline = _document_list(documents, "timeline-evidence.json")
    decisions = _document_list(documents, "recovery-decisions.json")
    attempts = _document_list(documents, "recovery-attempts.json")
    transport_invocations = _document_list(documents, "transport-invocations.json")
    postcondition_observations = _document_list(
        documents, "postcondition-observations.json"
    )
    reviews = _document_list(documents, "operator-review.json")
    _document_list(documents, "audit-references.json")
    if not evaluations:
        raise EvidenceError("capsule has no policy evaluations")
    if not timeline:
        raise EvidenceError("capsule has no timeline evidence")
    if any(
        coordinates.get(field) != manifest.get(field)
        for field in (
            "package_version",
            "git_commit",
            "git_tree",
            "migration_head",
            "evidence_classification",
        )
    ):
        raise EvidenceError("release coordinates do not match the manifest")
    if (
        coordinates.get("git_commit") != expected_git_commit
        or coordinates.get("git_tree") != expected_git_tree
        or not GIT_OBJECT_ID.fullmatch(str(coordinates.get("git_commit")))
        or not GIT_OBJECT_ID.fullmatch(str(coordinates.get("git_tree")))
    ):
        raise EvidenceError("capsule does not match the expected exact Git coordinates")
    if (
        policy.get("name") != manifest.get("policy_name")
        or policy.get("version") != manifest.get("policy_version")
        or policy.get("definition_hash") != manifest.get("policy_hash")
        or policy.get("definition_hash") != _object_sha256(policy.get("definition"))
    ):
        raise EvidenceError("policy identity or content digest mismatch")
    if incident.get("id") != plan.get("incident_id") or incident.get("id") != manifest.get(
        "incident_id"
    ):
        raise EvidenceError("incident/plan identity mismatch")
    if (
        incident.get("correlation_id") != manifest.get("correlation_id")
        or incident.get("policy_name") != manifest.get("policy_name")
        or incident.get("policy_version") != manifest.get("policy_version")
        or plan.get("guardrails", {}).get("entity_id") != incident.get("entity_id")
    ):
        raise EvidenceError("incident correlation, policy, or guardrail identity mismatch")
    if not any(
        evaluation.get("invariant_id") == incident.get("invariant_id")
        for evaluation in evaluations
    ):
        raise EvidenceError("capsule lacks an evaluation for the incident invariant")
    previous_evaluated_at: datetime | None = None
    for evaluation in evaluations:
        if evaluation.get("correlation_id") != incident.get("correlation_id"):
            raise EvidenceError("evaluation names a different correlation")
        evaluated_at = _evidence_time(evaluation.get("evaluated_at"), "evaluation.evaluated_at")
        if previous_evaluated_at is not None and evaluated_at < previous_evaluated_at:
            raise EvidenceError("policy evaluations are not in chronological order")
        previous_evaluated_at = evaluated_at
        if evaluation.get("state") not in {"pending", "passed", "violated", "error"}:
            raise EvidenceError("policy evaluation has an invalid state")
    for event in timeline:
        if (
            event.get("correlation_id") != incident.get("correlation_id")
            or event.get("entity_type") != incident.get("entity_type")
            or event.get("entity_id") != incident.get("entity_id")
            or not SHA256.fullmatch(str(event.get("content_hash")))
        ):
            raise EvidenceError("timeline event names a different incident subject")
    contract_digest = provider.get("sha256")
    if not isinstance(contract_digest, str) or not SHA256.fullmatch(contract_digest):
        raise EvidenceError("provider contract digest is invalid")
    try:
        provider_body = {key: value for key, value in provider.items() if key != "sha256"}
        parsed_contract = ProviderContract(**provider_body)
    except (TypeError, ValueError) as exc:
        raise EvidenceError("provider contract content is invalid") from exc
    if parsed_contract.digest != contract_digest:
        raise EvidenceError("provider contract content digest mismatch")
    if contract_digest != plan.get("provider_contract_digest") or contract_digest != manifest.get(
        "provider_contract_digest"
    ):
        raise EvidenceError("provider contract identity mismatch")
    parameters, guardrails = _validate_plan_semantics(
        plan, incident, policy, timeline, parsed_contract, contract_digest
    )
    expected_plan_hash = _object_sha256(
        {
            "action_type": plan.get("action_type"),
            "parameters": plan.get("parameters"),
            "guardrails": plan.get("guardrails"),
            "provider_contract_digest": contract_digest,
        }
    )
    if expected_plan_hash != plan.get("plan_hash"):
        raise EvidenceError("recovery plan content digest mismatch")
    if (
        plan.get("provider_id") != provider.get("provider_id")
        or plan.get("provider_environment") != provider.get("environment")
        or plan.get("adapter_version") != provider.get("adapter_version")
        or plan.get("guardrails", {}).get("provider_contract_digest") != contract_digest
    ):
        raise EvidenceError("recovery plan provider binding mismatch")
    decision_transitions = {
        "approve": {
            ("proposed", "approved", "recovery_proposed", "recovery_approved")
        },
        "reject": {
            ("proposed", "rejected", "recovery_proposed", "recovery_rejected")
        },
        "revoke_approval": {
            ("approved", "proposed", "recovery_approved", "recovery_proposed")
        },
        "approval_expired": {
            ("approved", "proposed", "recovery_approved", "recovery_proposed")
        },
        "approval_invalidated": {
            ("approved", "proposed", "recovery_approved", "recovery_proposed")
        },
        "retry_reapproval_required": {
            ("needs_attention", "proposed", "needs_attention", "recovery_proposed"),
            ("executing", "proposed", "recovery_running", "recovery_proposed"),
        },
        "prepared_reapproval_required": {
            ("executing", "proposed", "recovery_running", "recovery_proposed"),
        },
        "plan_binding_superseded": {
            ("proposed", "proposed", "recovery_proposed", "recovery_proposed")
        },
    }
    previous_by_binding: dict[tuple[str, str], dict[str, Any]] = {}
    decision_by_id: dict[str, dict[str, Any]] = {}
    seen_request_digests: set[str] = set()
    seen_approval_bindings: set[tuple[str, str]] = set()
    previous_decided_at: datetime | None = None
    for index, decision in enumerate(decisions):
        decision_id = decision.get("id")
        request_digest = decision.get("request_id_digest")
        if not isinstance(decision_id, str) or not decision_id or decision_id in decision_by_id:
            raise EvidenceError("recovery decision IDs are missing or duplicated")
        if (
            not SHA256.fullmatch(str(request_digest))
            or request_digest in seen_request_digests
        ):
            raise EvidenceError("recovery decision request digests are invalid or duplicated")
        decision_by_id[decision_id] = decision
        seen_request_digests.add(str(request_digest))
        if (
            decision.get("recovery_plan_id") != plan.get("id")
            or decision.get("incident_id") != incident.get("id")
        ):
            raise EvidenceError("decision names a different recovery plan")
        if not SHA256.fullmatch(str(decision.get("plan_hash"))) or not SHA256.fullmatch(
            str(decision.get("provider_contract_digest"))
        ):
            raise EvidenceError("decision binding digests are invalid")
        current_binding = (
            decision.get("plan_hash") == plan.get("plan_hash")
            and decision.get("provider_contract_digest") == contract_digest
        )
        if not current_binding:
            later_invalidation = any(
                later.get("action") in {
                    "approval_invalidated",
                    "plan_binding_superseded",
                }
                and later.get("plan_hash") == decision.get("plan_hash")
                and later.get("provider_contract_digest")
                == decision.get("provider_contract_digest")
                for later in decisions[index + 1 :]
            )
            if decision.get("action") not in {
                "approval_invalidated",
                "plan_binding_superseded",
            } and not later_invalidation:
                raise EvidenceError("decision names an unaccounted historical plan binding")
        decided_at = _evidence_time(decision.get("decided_at"), "decision.decided_at")
        if previous_decided_at is not None and decided_at < previous_decided_at:
            raise EvidenceError("recovery decisions are not in chronological order")
        previous_decided_at = decided_at
        transition = decision_transitions.get(decision.get("action"))
        if transition is None or (
            decision.get("previous_plan_state"),
            decision.get("resulting_plan_state"),
            decision.get("previous_incident_state"),
            decision.get("resulting_incident_state"),
        ) not in transition:
            raise EvidenceError("decision contains an invalid lifecycle transition")
        if decision.get("action") in {
            "approval_expired",
            "approval_invalidated",
            "retry_reapproval_required",
            "prepared_reapproval_required",
            "plan_binding_superseded",
        }:
            if decision.get("decision_kind") != "system" or decision.get("actor") != {
                "system": "flowproof"
            } or decision.get("authorization_scope") != "system:approval_lifecycle":
                raise EvidenceError("automatic approval transition lacks system provenance")
        elif (
            decision.get("decision_kind") != "human"
            or decision.get("authorization_scope") != "recovery:approve"
            or not _human_actor_is_bounded(decision.get("actor"))
        ):
            raise EvidenceError("human recovery decision has invalid provenance")
        approval_expires_at = decision.get("approval_expires_at")
        if decision.get("action") == "approve":
            expires_at = _evidence_time(
                approval_expires_at, "decision.approval_expires_at"
            )
            if (
                expires_at <= decided_at
                or (expires_at - decided_at).total_seconds()
                != guardrails["approval_ttl_seconds"]
            ):
                raise EvidenceError("approval expiry does not derive from its decision TTL")
        elif approval_expires_at is not None:
            raise EvidenceError("non-approval decision declares an approval expiry")
        binding = (
            str(decision.get("plan_hash")),
            str(decision.get("provider_contract_digest")),
        )
        previous = previous_by_binding.get(binding)
        if previous is not None:
            chained = (
                previous.get("resulting_plan_state") == decision.get("previous_plan_state")
                and previous.get("resulting_incident_state")
                == decision.get("previous_incident_state")
            )
            operational_gap = (
                previous.get("resulting_plan_state") == "approved"
                and previous.get("resulting_incident_state") == "recovery_approved"
                and (
                    (
                        decision.get("action") == "prepared_reapproval_required"
                        and decision.get("previous_plan_state") == "executing"
                        and decision.get("previous_incident_state") == "recovery_running"
                    )
                    or (
                        decision.get("action") == "retry_reapproval_required"
                        and (
                            decision.get("previous_plan_state"),
                            decision.get("previous_incident_state"),
                        )
                        in {
                            ("executing", "recovery_running"),
                            ("needs_attention", "needs_attention"),
                        }
                    )
                )
            )
            if not chained and not operational_gap:
                raise EvidenceError("recovery decision genealogy does not form a valid chain")
        action = decision.get("action")
        if action in {
            "revoke_approval",
            "approval_expired",
            "approval_invalidated",
            "retry_reapproval_required",
            "prepared_reapproval_required",
        } and binding not in seen_approval_bindings:
            raise EvidenceError("approval lifecycle transition has no prior approval")
        if action == "approve":
            seen_approval_bindings.add(binding)
        previous_by_binding[binding] = decision

    current_decisions = [
        decision
        for decision in decisions
        if decision.get("plan_hash") == plan.get("plan_hash")
        and decision.get("provider_contract_digest") == contract_digest
    ]
    latest_current_decision = current_decisions[-1] if current_decisions else None
    current_state_pairs = {
        "approve": {
            ("approved", "recovery_approved"),
            ("executing", "recovery_running"),
            ("verifying", "verifying"),
            ("still_failed", "still_failed"),
            ("verified", "resolved"),
            ("needs_attention", "needs_attention"),
        },
        "reject": {("rejected", "recovery_rejected")},
        "revoke_approval": {("proposed", "recovery_proposed")},
        "approval_expired": {("proposed", "recovery_proposed")},
        "approval_invalidated": {("proposed", "recovery_proposed")},
        "retry_reapproval_required": {("proposed", "recovery_proposed")},
        "prepared_reapproval_required": {("proposed", "recovery_proposed")},
        "plan_binding_superseded": {("proposed", "recovery_proposed")},
    }
    current_state_pair = (plan.get("status"), incident.get("status"))
    if latest_current_decision is None:
        if current_state_pair != ("proposed", "recovery_proposed"):
            raise EvidenceError("current recovery state has no decision genealogy")
    elif current_state_pair not in current_state_pairs.get(
        str(latest_current_decision.get("action")), set()
    ):
        raise EvidenceError("latest recovery decision is inconsistent with current state")
    prior_approval = any(decision.get("action") == "approve" for decision in current_decisions)
    decision_required = {
        "approved",
        "executing",
        "verifying",
        "still_failed",
        "verified",
        "needs_attention",
    }
    if plan.get("status") in decision_required and not prior_approval:
        raise EvidenceError("recovery lifecycle lacks a human approval decision")
    if plan.get("status") == "rejected" and (
        not decisions or decisions[-1].get("action") != "reject"
    ):
        raise EvidenceError("rejected recovery lacks its terminal rejection decision")
    approval_active_states = {
        "approved",
        "executing",
        "verifying",
        "still_failed",
        "verified",
        "needs_attention",
    }
    latest_approval = next(
        (
            decision
            for decision in reversed(current_decisions)
            if decision.get("action") == "approve"
        ),
        None,
    )
    if plan.get("status") in approval_active_states:
        if (
            latest_approval is None
            or plan.get("approved_at") != latest_approval.get("decided_at")
            or plan.get("approval_expires_at")
            != latest_approval.get("approval_expires_at")
            or plan.get("approval_actor") != latest_approval.get("actor")
        ):
            raise EvidenceError("recovery plan does not bind its effective approval decision")
    elif any(
        plan.get(field) is not None
        for field in ("approved_at", "approval_expires_at", "approval_actor")
    ):
        raise EvidenceError("inactive recovery plan retains stale approval authority")
    retry_decisions = [
        decision
        for decision in current_decisions
        if decision.get("action")
        in {"retry_reapproval_required", "prepared_reapproval_required"}
    ]
    if retry_decisions and not attempts:
        raise EvidenceError("retry reapproval transition requires a durable attempt")
    invocation_ids: set[str] = set()
    invocation_approval_bindings: set[tuple[str, str]] = set()
    previous_reservation_at: datetime | None = None
    for invocation in transport_invocations:
        invocation_id = invocation.get("id")
        if (
            not isinstance(invocation_id, str)
            or not invocation_id
            or invocation_id in invocation_ids
        ):
            raise EvidenceError("transport invocation IDs are missing or duplicated")
        invocation_ids.add(invocation_id)
        reserved_at = _evidence_time(invocation.get("reserved_at"), "invocation.reserved_at")
        if previous_reservation_at is not None and reserved_at < previous_reservation_at:
            raise EvidenceError("transport invocations are not in chronological order")
        previous_reservation_at = reserved_at
        binding = (
            str(invocation.get("recovery_attempt_id")),
            str(invocation.get("approval_decision_id")),
        )
        if binding in invocation_approval_bindings:
            raise EvidenceError("one approval authorizes more than one transport invocation")
        invocation_approval_bindings.add(binding)
    for attempt in attempts:
        if (
            attempt.get("recovery_plan_id") != plan.get("id")
            or attempt.get("incident_id") != incident.get("id")
            or attempt.get("plan_hash") != plan.get("plan_hash")
        ):
            raise EvidenceError("attempt names a different recovery plan")
        if attempt.get("provider_contract_digest") != contract_digest:
            raise EvidenceError("attempt names a different provider contract")
        attempt_created_at = _evidence_time(attempt.get("created_at"), "attempt.created_at")
        approval_decision = decision_by_id.get(str(attempt.get("approval_decision_id")))
        if (
            approval_decision is None
            or approval_decision.get("action") != "approve"
            or approval_decision.get("decision_kind") != "human"
            or approval_decision.get("plan_hash") != plan.get("plan_hash")
            or approval_decision.get("provider_contract_digest") != contract_digest
        ):
            raise EvidenceError("durable attempt approval binding is invalid")
        decisions_at_creation = [
            decision
            for decision in current_decisions
            if _evidence_time(decision.get("decided_at"), "decision.decided_at")
            <= attempt_created_at
        ]
        if not decisions_at_creation or decisions_at_creation[-1].get("id") != attempt.get(
            "approval_decision_id"
        ):
            raise EvidenceError("durable attempt was not created under its bound approval")
        attempt_approval_time = _evidence_time(
            approval_decision.get("decided_at"), "decision.decided_at"
        )
        attempt_approval_expiry = _evidence_time(
            approval_decision.get("approval_expires_at"),
            "decision.approval_expires_at",
        )
        if not attempt_approval_time <= attempt_created_at < attempt_approval_expiry:
            raise EvidenceError("durable attempt was not prepared under unexpired consent")
        approval_index = current_decisions.index(approval_decision)
        later_decisions = current_decisions[approval_index + 1 :]
        reapproval_transitions: list[dict[str, Any]] = []
        reapproval_state = "none"
        for later_index, later in enumerate(later_decisions):
            if _evidence_time(later.get("decided_at"), "decision.decided_at") < attempt_created_at:
                raise EvidenceError("durable attempt approval was superseded before creation")
            later_action = later.get("action")
            if later_action in {
                "retry_reapproval_required",
                "prepared_reapproval_required",
            }:
                if reapproval_state not in {"none", "authorized"}:
                    raise EvidenceError("post-attempt retry grant genealogy is invalid")
                if later_action == "prepared_reapproval_required" and reapproval_transitions:
                    raise EvidenceError("prepared reapproval is not the first recovery grant")
                reapproval_transitions.append(later)
                reapproval_state = "awaiting_decision"
            elif later_action == "approve":
                if reapproval_state != "awaiting_decision":
                    raise EvidenceError("post-attempt retry grant genealogy is invalid")
                reapproval_state = "authorized"
            elif later_action in {"approval_expired", "approval_invalidated"}:
                if reapproval_state != "authorized":
                    raise EvidenceError("post-attempt retry grant genealogy is invalid")
                reapproval_state = "awaiting_decision"
            elif later_action == "revoke_approval":
                if reapproval_state != "authorized":
                    raise EvidenceError("post-attempt retry grant genealogy is invalid")
                reapproval_state = "awaiting_decision"
            elif later_action == "reject":
                if (
                    reapproval_state != "awaiting_decision"
                    or later_index != len(later_decisions) - 1
                ):
                    raise EvidenceError("post-attempt retry grant genealogy is invalid")
                reapproval_state = "rejected"
            else:
                raise EvidenceError("post-attempt approval genealogy is invalid")
        if (
            attempt.get("provider_id") != provider.get("provider_id")
            or attempt.get("provider_environment") != provider.get("environment")
            or attempt.get("adapter_version") != provider.get("adapter_version")
        ):
            raise EvidenceError("attempt provider identity mismatch")
        if attempt.get("request_digest") != _object_sha256(plan.get("parameters")):
            raise EvidenceError("attempt request digest mismatch")
        if attempt.get("execution_idempotency_key_digest") != plan.get(
            "idempotency_key_digest"
        ):
            raise EvidenceError("attempt idempotency binding mismatch")
        if attempt.get("semantic_attempt_count") != 1 or attempt.get("attempt_ordinal") != 1:
            raise EvidenceError("attempt violates the one-semantic-attempt boundary")
        invocation_count = attempt.get("transport_invocation_count")
        invocation_limit = plan.get("guardrails", {}).get("maximum_transport_invocations")
        if (
            not isinstance(invocation_count, int)
            or isinstance(invocation_count, bool)
            or not isinstance(invocation_limit, int)
            or isinstance(invocation_limit, bool)
            or not 0 <= invocation_count <= invocation_limit
        ):
            raise EvidenceError("attempt transport invocation count violates the guardrail")
        attempt_invocations = [
            invocation
            for invocation in transport_invocations
            if invocation.get("recovery_attempt_id") == attempt.get("id")
        ]
        if len(attempt_invocations) != invocation_count or [
            invocation.get("invocation_ordinal") for invocation in attempt_invocations
        ] != list(range(1, invocation_count + 1)):
            raise EvidenceError("transport reservation ledger does not match the attempt count")
        for invocation in attempt_invocations:
            approval_id = invocation.get("approval_decision_id")
            invocation_approval = decision_by_id.get(str(approval_id))
            reserved_at = _evidence_time(
                invocation.get("reserved_at"), "invocation.reserved_at"
            )
            if (
                invocation.get("recovery_plan_id") != plan.get("id")
                or invocation.get("request_digest") != attempt.get("request_digest")
                or invocation_approval is None
                or invocation_approval.get("action") != "approve"
                or invocation_approval.get("decision_kind") != "human"
                or invocation_approval.get("plan_hash") != plan.get("plan_hash")
                or invocation_approval.get("provider_contract_digest") != contract_digest
            ):
                raise EvidenceError("transport reservation approval binding is invalid")
            approval_time = _evidence_time(
                invocation_approval.get("decided_at"), "decision.decided_at"
            )
            approval_expiry = _evidence_time(
                invocation_approval.get("approval_expires_at"),
                "decision.approval_expires_at",
            )
            effective_decisions = [
                decision
                for decision in current_decisions
                if _evidence_time(decision.get("decided_at"), "decision.decided_at")
                <= reserved_at
            ]
            if (
                reserved_at < attempt_created_at
                or not approval_time <= reserved_at < approval_expiry
                or not effective_decisions
                or effective_decisions[-1].get("id") != approval_id
            ):
                raise EvidenceError("transport invocation was not reserved under active consent")
        attempt_state = attempt.get("state")
        if attempt_state == "PREPARED" and invocation_count != 0:
            raise EvidenceError("prepared attempt cannot contain a transport invocation")
        if attempt_state in {
            "DISPATCHING",
            "ACCEPTED",
            "PRE_ACCEPTANCE_FAILED",
            "VERIFYING",
            "VERIFIED",
            "STILL_FAILED",
        } and invocation_count < 1:
            raise EvidenceError("attempt state requires a reserved transport invocation")
        prepared_transitions = [
            transition
            for transition in reapproval_transitions
            if transition.get("action") == "prepared_reapproval_required"
        ]
        if len(prepared_transitions) > 1 or (
            prepared_transitions and reapproval_transitions[0] is not prepared_transitions[0]
        ):
            raise EvidenceError("prepared reapproval genealogy is invalid")
        initial_invocation_capacity = 0 if prepared_transitions else 1
        if attempt_state == "RECONCILED_EFFECT_ABSENT":
            expected_reapproval_state = {
                "proposed": "awaiting_decision",
                "approved": "authorized",
                "rejected": "rejected",
            }.get(str(plan.get("status")))
            expected_invocations = initial_invocation_capacity + len(
                reapproval_transitions
            ) - 1
            if (
                not reapproval_transitions
                or reapproval_state != expected_reapproval_state
                or invocation_count != expected_invocations
            ):
                raise EvidenceError("effect-absent attempt lacks its active reapproval genealogy")
        elif reapproval_transitions and invocation_count != (
            initial_invocation_capacity + len(reapproval_transitions)
        ):
            raise EvidenceError("transport invocation lacks its reapproval grant")
        if (
            attempt_state == "RECONCILED_EFFECT_ABSENT"
            and reapproval_state != "rejected"
            and invocation_count >= invocation_limit
        ):
            raise EvidenceError("reapproval exceeds the transport invocation guardrail")
        safe_result = attempt.get("safe_result")
        precondition = safe_result.get("precondition") if isinstance(safe_result, dict) else None
        validated_precondition = _validate_observation(
            precondition,
            field_name="attempt precondition",
            classification="AVAILABLE_ABSENT",
            entity_id=str(parameters["invoice_id"]),
            provider=parsed_contract,
        )
        precondition_time = _evidence_time(
            validated_precondition.get("observed_at"),
            "attempt precondition.observed_at",
        )
        if (
            attempt.get("precondition_observation_digest")
            != validated_precondition.get("content_digest")
        ):
            raise EvidenceError("attempt precondition digest mismatch")
        if not attempt_approval_time <= precondition_time <= attempt_created_at:
            raise EvidenceError("attempt precondition was not observed before durable intent")
        reconciliation_history = (
            safe_result.get("reconciliation_history")
            if isinstance(safe_result, dict)
            else None
        )
        if reapproval_transitions:
            if not isinstance(reconciliation_history, list) or len(
                reconciliation_history
            ) != len(reapproval_transitions):
                raise EvidenceError("reapproval lifecycle lacks complete reconciliation history")
        elif reconciliation_history not in (None, []):
            raise EvidenceError("reconciliation history has no reapproval genealogy")
        retry_ordinal = 0
        last_reconciliation: dict[str, Any] | None = None
        last_reconciled_at: datetime | None = None
        last_retry_reason: str | None = None
        history_keys = {
            "observation",
            "reconciled_at",
            "reapproval_action",
            "transport_invocation_count",
            "prior_attempt_state",
            "retry_reason",
            "write_outcome",
        }
        for transition, history_entry in zip(
            reapproval_transitions, reconciliation_history or [], strict=True
        ):
            if not isinstance(history_entry, dict) or set(history_entry) != history_keys:
                raise EvidenceError("reconciliation history entry is incomplete")
            action = transition.get("action")
            if history_entry.get("reapproval_action") != action:
                raise EvidenceError("reconciliation history action mismatch")
            if action == "prepared_reapproval_required":
                expected_prior_count = 0
                if history_entry.get("prior_attempt_state") not in {
                    "PREPARED",
                    "RECONCILING",
                }:
                    raise EvidenceError("prepared reapproval lacks its crash checkpoint")
            else:
                retry_ordinal += 1
                expected_prior_count = retry_ordinal
                if history_entry.get("prior_attempt_state") not in {
                    "DISPATCHING",
                    "ACCEPTED",
                    "OUTCOME_UNKNOWN",
                    "PRE_ACCEPTANCE_FAILED",
                    "RECONCILING",
                }:
                    raise EvidenceError("transport retry lacks its ambiguous prior state")
            if history_entry.get("transport_invocation_count") != expected_prior_count:
                raise EvidenceError("reconciliation history erases a transport reservation")
            lower_bound = (
                attempt_created_at
                if expected_prior_count == 0
                else _evidence_time(
                    attempt_invocations[expected_prior_count - 1].get("reserved_at"),
                    "invocation.reserved_at",
                )
            )
            reconciliation = _validate_observation(
                history_entry.get("observation"),
                field_name="effect-absent reconciliation history",
                classification="AVAILABLE_ABSENT",
                entity_id=str(parameters["invoice_id"]),
                provider=parsed_contract,
            )
            reconciliation_time = _evidence_time(
                reconciliation.get("observed_at"),
                "reconciliation_history.observation.observed_at",
            )
            reconciled_at = _evidence_time(
                history_entry.get("reconciled_at"),
                "reconciliation_history.reconciled_at",
            )
            transition_time = _evidence_time(
                transition.get("decided_at"), "decision.decided_at"
            )
            if not lower_bound <= reconciliation_time <= reconciled_at <= transition_time:
                raise EvidenceError("reapproval lacks ordered reconciliation proof")
            retry_reason = history_entry.get("retry_reason")
            write_outcome = history_entry.get("write_outcome")
            if retry_reason == "pre_acceptance_failure_proven":
                if expected_prior_count == 0 or not isinstance(write_outcome, dict):
                    raise EvidenceError("provider-proven retry lacks its transport outcome")
                classification = write_outcome.get("classification")
                if classification not in {
                    "PRE_ACCEPTANCE_FAILURE",
                    "AUTHENTICATION_FAILED",
                    "RATE_LIMITED",
                }:
                    raise EvidenceError("provider-proven retry classification is invalid")
                validated_outcome = _validate_write_outcome(
                    write_outcome,
                    expected_classification=classification,
                    provider=parsed_contract,
                )
                write_outcome_time = _evidence_time(
                    validated_outcome.get("observed_at"), "write_outcome.observed_at"
                )
                if not lower_bound <= write_outcome_time <= reconciliation_time:
                    raise EvidenceError(
                        "provider-proven retry outcome is not causally ordered"
                    )
            elif retry_reason == "contract_tested_same_key_idempotency":
                if (
                    not isinstance(parsed_contract.idempotency, dict)
                    or parsed_contract.idempotency.get("support") != "CONTRACT_TESTED"
                    or (expected_prior_count == 0 and write_outcome is not None)
                ):
                    raise EvidenceError("effect-absent retry lacks tested idempotency proof")
                if isinstance(write_outcome, dict):
                    classification = write_outcome.get("classification")
                    validated_outcome = _validate_write_outcome(
                        write_outcome,
                        expected_classification=classification,
                        provider=parsed_contract,
                    )
                    write_outcome_time = _evidence_time(
                        validated_outcome.get("observed_at"), "write_outcome.observed_at"
                    )
                    if not lower_bound <= write_outcome_time <= reconciliation_time:
                        raise EvidenceError("retry outcome is not causally ordered")
            else:
                raise EvidenceError("effect-absent retry reason is invalid")
            target_invocation_index = expected_prior_count
            if target_invocation_index < len(attempt_invocations):
                target_invocation = attempt_invocations[target_invocation_index]
                target_approval = decision_by_id.get(
                    str(target_invocation.get("approval_decision_id"))
                )
                if target_approval is None or transition_time > _evidence_time(
                    target_approval.get("decided_at"), "decision.decided_at"
                ):
                    raise EvidenceError("transport invocation predates its reapproval grant")
            last_reconciliation = reconciliation
            last_reconciled_at = reconciled_at
            last_retry_reason = str(retry_reason)
        if reapproval_transitions:
            current_reconciled_at = _evidence_time(
                attempt.get("reconciled_at"), "attempt.reconciled_at"
            )
            latest_observation = safe_result.get("reconciliation_observation")
            if (
                attempt.get("retry_reason") != last_retry_reason
                or attempt.get("retry_permitted")
                != (attempt_state == "RECONCILED_EFFECT_ABSENT")
                or last_reconciled_at is None
                or current_reconciled_at < last_reconciled_at
                or (
                    attempt_state == "RECONCILED_EFFECT_ABSENT"
                    and (
                        latest_observation != last_reconciliation
                        or current_reconciled_at != last_reconciled_at
                    )
                )
            ):
                raise EvidenceError("attempt does not preserve its latest reconciliation proof")
            if latest_observation != last_reconciliation:
                if not isinstance(latest_observation, dict) or latest_observation.get(
                    "classification"
                ) not in {
                    "AVAILABLE_PRESENT",
                    "AVAILABLE_ABSENT",
                    "AVAILABLE_CONFLICT",
                    "AUTHENTICATION_FAILED",
                    "RATE_LIMITED",
                    "TEMPORARILY_UNAVAILABLE",
                    "MALFORMED_RESPONSE",
                    "PERMANENT_PROVIDER_ERROR",
                }:
                    raise EvidenceError("later reconciliation state is invalid")
                latest_classification = str(latest_observation["classification"])
                latest_is_authoritative = latest_classification.startswith("AVAILABLE_")
                validated_latest = _validate_observation(
                    latest_observation,
                    field_name="later authoritative reconciliation",
                    classification=latest_classification,
                    entity_id=str(parameters["invoice_id"]),
                    provider=parsed_contract,
                    require_authoritative=latest_is_authoritative,
                )
                latest_observed_at = _evidence_time(
                    validated_latest.get("observed_at"),
                    "later reconciliation.observed_at",
                )
                attempt_updated_at = _evidence_time(
                    attempt.get("updated_at"), "attempt.updated_at"
                )
                if not last_reconciled_at <= latest_observed_at <= attempt_updated_at:
                    raise EvidenceError("later reconciliation is not causally ordered")
                if latest_classification == "AVAILABLE_PRESENT":
                    latest_record = validated_latest["records"][0]
                    latest_record_id = latest_record.get(
                        "invoice_id", latest_record.get("id")
                    )
                    try:
                        latest_amount_matches = Decimal(
                            str(latest_record.get("amount"))
                        ) == Decimal(str(parameters["amount"]))
                    except InvalidOperation:
                        latest_amount_matches = False
                    if (
                        attempt_state
                        not in {
                            "RECONCILED_EFFECT_PRESENT",
                            "VERIFYING",
                            "VERIFIED",
                            "STILL_FAILED",
                        }
                        or str(latest_record_id) != parameters["invoice_id"]
                        or not latest_amount_matches
                        or latest_record.get("currency") != parameters["currency"]
                    ):
                        raise EvidenceError("later reconciliation effect does not match the plan")
                elif latest_is_authoritative and attempt_state not in {
                    "NEEDS_ATTENTION",
                    "RECONCILED_CONFLICT",
                }:
                    raise EvidenceError("later reconciliation contradicts the attempt state")
                elif not latest_is_authoritative and attempt_state != "OUTCOME_UNKNOWN":
                    raise EvidenceError("unavailable reconciliation contradicts the attempt state")
        if not prepared_transitions and attempt_invocations and attempt_invocations[0].get(
            "approval_decision_id"
        ) != attempt.get("approval_decision_id"):
            raise EvidenceError("first transport invocation lost its initial approval binding")
    if any(
        invocation.get("recovery_attempt_id")
        not in {attempt.get("id") for attempt in attempts}
        for invocation in transport_invocations
    ):
        raise EvidenceError("transport reservation names an unknown durable attempt")
    executed_plan_states = {"executing", "verifying", "still_failed", "verified", "needs_attention"}
    executed_incident_states = {
        "recovery_running",
        "verifying",
        "still_failed",
        "resolved",
        "needs_attention",
    }
    if (
        plan.get("status") in executed_plan_states
        or incident.get("status") in executed_incident_states
    ):
        if len(attempts) != 1:
            raise EvidenceError("executed recovery lifecycle requires exactly one durable attempt")
        if not prior_approval:
            raise EvidenceError("durable recovery attempt lacks prior human approval")
    if attempts and not prior_approval:
        raise EvidenceError("durable recovery attempt lacks prior human approval")
    if len(attempts) > 1:
        raise EvidenceError("capsule exceeds the one-semantic-attempt boundary")
    if attempts:
        expected_attempt_states = {
            "executing": {
                "PREPARED",
                "DISPATCHING",
                "ACCEPTED",
                "RECONCILING",
                "RECONCILED_EFFECT_PRESENT",
            },
            "verifying": {"VERIFYING"},
            "still_failed": {"STILL_FAILED"},
            "verified": {"VERIFIED"},
            "needs_attention": {
                "OUTCOME_UNKNOWN",
                "PRE_ACCEPTANCE_FAILED",
                "NEEDS_ATTENTION",
                "RECONCILED_CONFLICT",
                "RECONCILING",
                "RECONCILED_EFFECT_PRESENT",
            },
            "proposed": {"RECONCILED_EFFECT_ABSENT"},
            "approved": {"RECONCILED_EFFECT_ABSENT"},
            "rejected": {"RECONCILED_EFFECT_ABSENT"},
        }
        allowed_attempt_states = expected_attempt_states.get(plan.get("status"))
        if (
            allowed_attempt_states is not None
            and attempts[0].get("state") not in allowed_attempt_states
        ):
            raise EvidenceError("plan and durable attempt lifecycle states are inconsistent")
    for review in reviews:
        if (
            review.get("recovery_plan_id") != plan.get("id")
            or review.get("incident_id") != incident.get("id")
            or review.get("plan_hash") != plan.get("plan_hash")
        ):
            raise EvidenceError("operator review names a different recovery plan")
        if review.get("capsule_digest") != manifest.get("review_subject_sha256"):
            raise EvidenceError("operator review does not bind the reviewed evidence subject")
    if incident.get("status") == "resolved":
        postcondition = plan.get("result", {}).get("postcondition", {})
        matching_evaluations = [
            evaluation
            for evaluation in evaluations
            if evaluation.get("invariant_id") == incident.get("invariant_id")
        ]
        expected_postconditions = [
            evaluation.get("evidence")
            for evaluation in matching_evaluations
            if evaluation.get("evidence")
        ]
        if (
            plan.get("status") != "verified"
            or postcondition.get("status") != "resolved"
            or postcondition.get("incident_id") != incident.get("id")
            or postcondition_observations != expected_postconditions
            or not matching_evaluations
            or matching_evaluations[-1].get("state") != "passed"
            or not attempts
            or attempts[0].get("state") != "VERIFIED"
        ):
            raise EvidenceError("claimed resolution lacks a verified postcondition")
        final_evidence = matching_evaluations[-1].get("evidence")
        final_observation = (
            final_evidence.get("observation") if isinstance(final_evidence, dict) else None
        )
        validated_postcondition = _validate_observation(
            final_observation,
            field_name="final invariant observation",
            classification="AVAILABLE_PRESENT",
            entity_id=str(parameters["invoice_id"]),
            provider=parsed_contract,
        )
        final_record = validated_postcondition["records"][0]
        record_id = final_record.get("invoice_id", final_record.get("id"))
        try:
            amount_matches = Decimal(str(final_record.get("amount"))) == Decimal(
                str(parameters["amount"])
            )
        except InvalidOperation:
            amount_matches = False
        if (
            str(record_id) != parameters["invoice_id"]
            or not amount_matches
            or final_record.get("currency") != parameters["currency"]
        ):
            raise EvidenceError("final invariant observation does not match the recovery plan")
        verified_at = _evidence_time(plan.get("verified_at"), "plan.verified_at")
        executed_at = _evidence_time(plan.get("executed_at"), "plan.executed_at")
        checked_at = _evidence_time(postcondition.get("checked_at"), "postcondition.checked_at")
        final_observed_at = _evidence_time(
            validated_postcondition.get("observed_at"),
            "final invariant observation.observed_at",
        )
        final_evaluated_at = _evidence_time(
            matching_evaluations[-1].get("evaluated_at"), "evaluation.evaluated_at"
        )
        last_reserved_at = _evidence_time(
            transport_invocations[-1].get("reserved_at"),
            "invocation.reserved_at",
        )
        if (
            checked_at != verified_at
            or not last_reserved_at
            <= executed_at
            <= final_observed_at
            <= final_evaluated_at
            <= verified_at
        ):
            raise EvidenceError("verified postcondition timestamps are inconsistent")
    return {
        "status": "VALID",
        "bundle_sha256": manifest["bundle_sha256"],
        "review_subject_sha256": manifest["review_subject_sha256"],
        "zip_sha256": _sha256(path.read_bytes()),
        "proof_boundary": (
            "externally anchored integrity and lifecycle consistency; not a signer identity, "
            "trusted timestamp, or production-readiness certificate"
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m flowproof.evidence")
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--incident-id", required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument(
        "--include-private-identity",
        action="store_true",
        help="owner-private export: includes direct operator identity; never the default",
    )
    verify = commands.add_parser("verify")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--expected-bundle-sha256", required=True)
    verify.add_argument("--expected-git-commit", required=True)
    verify.add_argument("--expected-git-tree", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_capsule(
                args.input,
                expected_bundle_sha256=args.expected_bundle_sha256,
                expected_git_commit=args.expected_git_commit,
                expected_git_tree=args.expected_git_tree,
            )
        else:
            settings = Settings.from_environment()
            factory = make_session_factory(make_engine(settings.database_url))
            with factory() as session:
                result = export_capsule(
                    session,
                    args.incident_id,
                    args.output,
                    private_identity=args.include_private_identity,
                )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (EvidenceError, OSError, ValueError) as exc:
        print(json.dumps({"status": "INVALID", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
