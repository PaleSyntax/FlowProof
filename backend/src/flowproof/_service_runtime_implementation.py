from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

from sqlalchemy import Select, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from flowproof.accounting import (
    AccountingClient,
    MockChaosControl,
    ObservationState,
    WriteOutcomeState,
    client_contract,
    coerce_observation,
    coerce_write_outcome,
)
from flowproof.alerts import Alert, enqueue_alert
from flowproof.clock import monotonic_utc_now
from flowproof.models import (
    BusinessEvent,
    ChaosRun,
    DeadlineJob,
    Incident,
    OperatorReview,
    Policy,
    PolicyEvaluation,
    RecoveryAttempt,
    RecoveryDecision,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.policy import canonical_hash, load_policy
from flowproof.schemas import BusinessEventIn

DENY_KEY = re.compile(
    r"password|secret|token|authorization|cookie|api[_-]?key|private[_-]?key", re.I
)
DURATION = re.compile(r"^(?P<value>\d+)(?P<unit>[smhd])$")
DEADLINE_INVARIANT_TYPES = {"eventually", "external_assertion"}
RECOVERY_APPROVAL_SCOPE = "recovery:approve"
RECOVERY_APPROVABLE_INCIDENT_STATUS = "recovery_proposed"
DECISION_NOTE_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
AMBIGUOUS_ATTEMPT_STATES = {
    "PREPARED",
    "DISPATCHING",
    "ACCEPTED",
    "OUTCOME_UNKNOWN",
    "RECONCILING",
}


class IdempotencyConflict(Exception):
    pass


class PayloadRejected(ValueError):
    pass


class RecoveryGateError(ValueError):
    pass


def decision_note_digest(note: str | None) -> str | None:
    if note is None:
        return None
    normalized = " ".join(note.strip().split())
    if not normalized or len(normalized) > 500:
        raise RecoveryGateError("decision note is empty or too long")
    if DENY_KEY.search(normalized) or DECISION_NOTE_EMAIL.search(normalized):
        raise RecoveryGateError("decision note contains secret-like or direct identity material")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return monotonic_utc_now()


def normalize_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes; PostgreSQL preserves the offset."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def as_json(value: Any) -> Any:
    if isinstance(value, datetime):
        return normalize_utc(value).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): as_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [as_json(item) for item in value]
    return value


def redact(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        raise PayloadRejected("payload nesting exceeds five levels")
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if DENY_KEY.search(str(key)) else redact(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        if len(value) > 64:
            raise PayloadRejected("payload list exceeds 64 items")
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, str):
        return value[:2_048]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    raise PayloadRejected("payload contains an unsupported value type")


def parse_duration(raw: str) -> timedelta:
    match = DURATION.fullmatch(raw)
    if not match:
        raise ValueError(f"invalid duration: {raw}")
    unit = match.group("unit")
    value = int(match.group("value"))
    return timedelta(seconds=value * {"s": 1, "m": 60, "h": 3_600, "d": 86_400}[unit])


def json_path(value: dict[str, Any], path: str) -> Any:
    if not path.startswith("$."):
        raise ValueError(f"unsupported JSON path: {path}")
    current: Any = value
    for part in path[2:].split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def first_event(events: Iterable[BusinessEvent], event_type: str) -> BusinessEvent | None:
    return next((event for event in events if event.event_type == event_type), None)


def event_ids(*events: BusinessEvent | None) -> list[str]:
    return [event.id for event in events if event is not None]


class _FlowProofRuntimeImplementation:
    """Private implementation payload; only the canonical service may execute it."""

    def __new__(
        cls,
        *args: Any,
        **kwargs: Any,
    ) -> _FlowProofRuntimeImplementation:
        del args, kwargs
        if (
            cls.__module__ != "flowproof.service"
            or cls.__name__ != "FlowProofService"
        ):
            raise TypeError(
                "private runtime implementation is not executable; "
                "use flowproof.service.FlowProofService"
            )
        return object.__new__(cls)

    def __init__(
        self,
        session: Session,
        policy_path: str,
        accounting: AccountingClient,
        now: Callable[[], datetime] = utc_now,
        max_payload_bytes: int = 16_384,
        recovery_writes_enabled: bool = True,
    ) -> None:
        self.session = session
        self.policy_path = policy_path
        self.accounting = accounting
        self.now = now
        self.max_payload_bytes = max_payload_bytes
        self.recovery_writes_enabled = recovery_writes_enabled

    def ensure_policy(self) -> Policy:
        path = self._path(self.policy_path)
        definition = load_policy(path, path.with_name("policy.schema.json"))
        definition_hash = canonical_hash(definition)
        policy = self.session.scalar(
            select(Policy).where(Policy.definition_hash == definition_hash)
        )
        if policy:
            return policy
        policy = Policy(
            id=str(uuid4()),
            name=definition["name"],
            version=definition["version"],
            entity_type=definition["entity_type"],
            definition=definition,
            definition_hash=definition_hash,
            enabled=True,
        )
        self.session.add(policy)
        self.session.commit()
        return policy

    @staticmethod
    def _path(raw: str):
        from pathlib import Path

        return Path(raw)

    def ingest(self, event: BusinessEventIn) -> tuple[BusinessEvent, bool]:
        payload = redact(event.payload)
        if (
            len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            > self.max_payload_bytes
        ):
            raise PayloadRejected("redacted payload exceeds the configured size limit")
        canonical = event.model_dump(mode="json")
        canonical["payload"] = payload
        content_hash = canonical_hash(canonical)
        existing = self.session.scalar(
            select(BusinessEvent).where(BusinessEvent.idempotency_key == event.idempotency_key)
        )
        if existing:
            if not secrets.compare_digest(existing.content_hash, content_hash):
                raise IdempotencyConflict("idempotency key is already bound to different content")
            return existing, True

        bound_entity = self.session.execute(
            select(BusinessEvent.entity_type, BusinessEvent.entity_id)
            .where(BusinessEvent.correlation_id == event.correlation_id)
            .limit(1)
        ).first()
        if bound_entity is not None and tuple(bound_entity) != (
            event.entity_type,
            event.entity_id,
        ):
            raise PayloadRejected("correlation_id is already bound to a different entity")

        policy = self.ensure_policy()
        row = BusinessEvent(
            id=str(uuid4()),
            idempotency_key=event.idempotency_key,
            correlation_id=event.correlation_id,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            event_type=event.event_type,
            occurred_at=event.occurred_at,
            source_system=event.source.system,
            workflow_id=event.source.workflow_id,
            workflow_version=event.source.workflow_version,
            execution_id=event.source.execution_id,
            node_name=event.source.node_name,
            payload=payload,
            content_hash=content_hash,
        )
        self.session.add(row)
        self.session.flush()
        self._schedule_deadline_jobs(policy, row)
        self.session.commit()
        return row, False

    def _schedule_deadline_jobs(self, policy: Policy, event: BusinessEvent) -> None:
        """Persist one semantic deadline job for each invariant triggered by this event."""
        if not policy.enabled or event.entity_type != policy.entity_type:
            return
        for invariant in policy.definition["invariants"]:
            if (
                invariant["type"] not in DEADLINE_INVARIANT_TYPES
                or invariant.get("after") != event.event_type
            ):
                continue
            due_at = normalize_utc(event.occurred_at) + parse_duration(invariant["within"])
            job = DeadlineJob(
                id=str(uuid4()),
                policy_id=policy.id,
                correlation_id=event.correlation_id,
                invariant_id=invariant["id"],
                trigger_event_id=event.id,
                due_at=due_at,
                state="pending",
                attempt_count=0,
                next_attempt_at=due_at,
            )
            try:
                with self.session.begin_nested():
                    self.session.add(job)
                    self.session.flush()
            except IntegrityError:
                duplicate = self.session.scalar(
                    select(DeadlineJob).where(
                        DeadlineJob.policy_id == policy.id,
                        DeadlineJob.correlation_id == event.correlation_id,
                        DeadlineJob.invariant_id == invariant["id"],
                        DeadlineJob.trigger_event_id == event.id,
                        DeadlineJob.due_at == due_at,
                    )
                )
                if duplicate is None:
                    raise

    def timeline(self, entity_type: str, entity_id: str) -> list[dict[str, Any]]:
        rows = self.session.scalars(
            select(BusinessEvent)
            .where(BusinessEvent.entity_type == entity_type, BusinessEvent.entity_id == entity_id)
            .order_by(BusinessEvent.occurred_at, BusinessEvent.id)
        ).all()
        return [self.event_view(row) for row in rows]

    @staticmethod
    def event_view(row: BusinessEvent) -> dict[str, Any]:
        return {
            "id": row.id,
            "idempotency_key": row.idempotency_key,
            "correlation_id": row.correlation_id,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "event_type": row.event_type,
            "occurred_at": row.occurred_at,
            "ingested_at": row.ingested_at,
            "source": {
                "system": row.source_system,
                "workflow_id": row.workflow_id,
                "workflow_version": row.workflow_version,
                "execution_id": row.execution_id,
                "node_name": row.node_name,
            },
            "payload": row.payload,
            "content_hash": row.content_hash,
        }

    def evaluate(self, correlation_id: str, policy_id: str | None = None) -> list[dict[str, Any]]:
        policy = self.session.get(Policy, policy_id) if policy_id else self.ensure_policy()
        if policy is None:
            raise ValueError("scheduled policy is missing")
        events = self.session.scalars(
            select(BusinessEvent)
            .where(BusinessEvent.correlation_id == correlation_id)
            .order_by(BusinessEvent.occurred_at, BusinessEvent.id)
        ).all()
        if not events:
            return []
        entity_bindings = {(event.entity_type, event.entity_id) for event in events}
        if len(entity_bindings) != 1:
            raise PayloadRejected("correlation_id contains events for multiple entities")
        results: list[dict[str, Any]] = []
        for invariant in policy.definition["invariants"]:
            result = self._evaluate_invariant(invariant, events)
            result["invariant_id"] = invariant["id"]
            self.session.add(
                PolicyEvaluation(
                    id=str(uuid4()),
                    policy_id=policy.id,
                    correlation_id=correlation_id,
                    invariant_id=invariant["id"],
                    state=result["state"],
                    evidence=result["evidence"],
                    evaluated_at=self.now(),
                )
            )
            self._sync_incident(policy, invariant, events[0], result)
            results.append(result)
        self.session.commit()
        return results

    def list_deadline_jobs(
        self, state: str | None = None, correlation_id: str | None = None
    ) -> list[dict[str, Any]]:
        statement: Select[tuple[DeadlineJob]] = select(DeadlineJob).order_by(
            DeadlineJob.due_at, DeadlineJob.id
        )
        if state:
            statement = statement.where(DeadlineJob.state == state)
        if correlation_id:
            statement = statement.where(DeadlineJob.correlation_id == correlation_id)
        return [self.deadline_job_view(row) for row in self.session.scalars(statement).all()]

    def get_deadline_job(self, job_id: str) -> dict[str, Any] | None:
        job = self.session.get(DeadlineJob, job_id)
        return self.deadline_job_view(job) if job else None

    @staticmethod
    def deadline_job_view(job: DeadlineJob) -> dict[str, Any]:
        return as_json(
            {
                "id": job.id,
                "policy_id": job.policy_id,
                "correlation_id": job.correlation_id,
                "invariant_id": job.invariant_id,
                "trigger_event_id": job.trigger_event_id,
                "due_at": job.due_at,
                "state": job.state,
                "attempt_count": job.attempt_count,
                "next_attempt_at": job.next_attempt_at,
                "lease_owner": job.lease_owner,
                "lease_expires_at": job.lease_expires_at,
                "last_error": job.last_error,
                "created_at": job.created_at,
                "updated_at": job.updated_at,
                "completed_at": job.completed_at,
            }
        )

    def _evaluate_invariant(
        self, invariant: dict[str, Any], events: list[BusinessEvent]
    ) -> dict[str, Any]:
        kind = invariant["type"]
        if kind == "ordering":
            return self._ordering(invariant, events)
        if kind == "exactly_once":
            return self._exactly_once(invariant, events)
        if kind == "eventually":
            return self._eventually(invariant, events)
        if kind == "value_matches":
            return self._value_matches(invariant, events)
        if kind == "external_assertion":
            return self._external_assertion(invariant, events)
        return {"state": "error", "message": "unsupported invariant", "evidence": {}}

    def _ordering(self, invariant: dict[str, Any], events: list[BusinessEvent]) -> dict[str, Any]:
        before = first_event(events, invariant["before"])
        after = first_event(events, invariant["after"])
        evidence = {"event_ids": event_ids(before, after), "expected": invariant["before"]}
        if after is None:
            return {
                "state": "pending",
                "message": "successor event has not occurred",
                "evidence": evidence,
            }
        if before is None or normalize_utc(before.occurred_at) > normalize_utc(after.occurred_at):
            return {
                "state": "violated",
                "message": "required approval is absent or late",
                "evidence": evidence,
            }
        return {"state": "passed", "message": "event ordering is valid", "evidence": evidence}

    def _exactly_once(
        self, invariant: dict[str, Any], events: list[BusinessEvent]
    ) -> dict[str, Any]:
        matches = [event for event in events if event.event_type == invariant["event"]]
        trigger = first_event(events, invariant.get("after", ""))
        evidence = {"event_ids": [event.id for event in matches], "count": len(matches)}
        if len(matches) == 1:
            return {
                "state": "passed",
                "message": "event occurred exactly once",
                "evidence": evidence,
            }
        if len(matches) > 1:
            return {
                "state": "violated",
                "message": "event occurred more than once",
                "evidence": evidence,
            }
        if trigger and self.now() - normalize_utc(trigger.occurred_at) >= parse_duration(
            invariant["within"]
        ):
            return {
                "state": "violated",
                "message": "expected event missed its deadline",
                "evidence": evidence,
            }
        return {"state": "pending", "message": "waiting for expected event", "evidence": evidence}

    def _eventually(self, invariant: dict[str, Any], events: list[BusinessEvent]) -> dict[str, Any]:
        trigger = first_event(events, invariant["after"])
        expected = first_event(events, invariant["expect"])
        evidence = {"event_ids": event_ids(trigger, expected), "expected": invariant["expect"]}
        if trigger is None:
            return {"state": "pending", "message": "trigger has not occurred", "evidence": evidence}
        if expected and normalize_utc(expected.occurred_at) >= normalize_utc(trigger.occurred_at):
            return {"state": "passed", "message": "expected event occurred", "evidence": evidence}
        if self.now() - normalize_utc(trigger.occurred_at) >= parse_duration(invariant["within"]):
            return {
                "state": "violated",
                "message": "expected event missed its deadline",
                "evidence": evidence,
            }
        return {"state": "pending", "message": "within allowed deadline", "evidence": evidence}

    def _value_matches(
        self, invariant: dict[str, Any], events: list[BusinessEvent]
    ) -> dict[str, Any]:
        left_event = first_event(events, invariant["left"]["event"])
        right_event = first_event(events, invariant["right"]["event"])
        evidence = {"event_ids": event_ids(left_event, right_event)}
        if not left_event or not right_event:
            return {
                "state": "pending",
                "message": "both values are not available",
                "evidence": evidence,
            }
        left = json_path(left_event.payload, invariant["left"]["path"])
        right = json_path(right_event.payload, invariant["right"]["path"])
        evidence.update({"expected": left, "actual": right})
        if left is None or right is None:
            return {
                "state": "inconclusive",
                "message": "value path is missing",
                "evidence": evidence,
            }
        tolerance = float(invariant.get("tolerance", 0))
        try:
            matches = abs(float(left) - float(right)) <= tolerance
        except (TypeError, ValueError):
            matches = left == right
        return {
            "state": "passed" if matches else "violated",
            "message": "values match" if matches else "values differ",
            "evidence": evidence,
        }

    def _external_assertion(
        self, invariant: dict[str, Any], events: list[BusinessEvent]
    ) -> dict[str, Any]:
        acknowledgement = first_event(events, invariant["after"])
        validated = first_event(events, "invoice.validated")
        evidence: dict[str, Any] = {"event_ids": event_ids(acknowledgement, validated)}
        if acknowledgement is None:
            return {
                "state": "pending",
                "message": "waiting for acknowledgement",
                "evidence": evidence,
            }
        typed_observation = coerce_observation(self.accounting, acknowledgement.entity_id)
        observation = typed_observation.to_evidence()
        evidence["observation"] = observation
        if not typed_observation.available:
            return {
                "state": "error",
                "message": f"external verifier unavailable: {typed_observation.state.value}",
                "evidence": evidence,
            }
        records = list(typed_observation.records)
        expected = invariant.get("expect", {})
        if typed_observation.state == ObservationState.AVAILABLE_ABSENT:
            evidence["expected"] = expected
            deadline = parse_duration(invariant["within"])
            if self.now() - normalize_utc(acknowledgement.occurred_at) < deadline:
                return {
                    "state": "pending",
                    "message": "external record has not appeared within the allowed deadline",
                    "evidence": evidence,
                }
            return {
                "state": "violated",
                "message": "missing_external_invoice",
                "evidence": evidence,
            }
        if expected.get("unique") and len(records) != 1:
            return {
                "state": "violated",
                "message": "external invoice is not unique",
                "evidence": evidence,
            }
        record = records[0]
        record_id = record.get("invoice_id", record.get("id"))
        evidence.setdefault("field_checks", {})["invoice_id"] = {
            "expected": acknowledgement.entity_id,
            "actual": record_id,
        }
        if record_id is None or str(record_id) != str(acknowledgement.entity_id):
            return {
                "state": "violated",
                "message": "external invoice identity mismatch",
                "evidence": evidence,
            }
        for field, rule in expected.get("fields", {}).items():
            expected_event = first_event(events, rule["equals_event"]["event"])
            expected_value = (
                json_path(expected_event.payload, rule["equals_event"]["path"])
                if expected_event
                else None
            )
            actual_value = record.get(field)
            evidence.setdefault("field_checks", {})[field] = {
                "expected": expected_value,
                "actual": actual_value,
            }
            if field == "amount":
                try:
                    matches = expected_value is not None and abs(
                        float(expected_value) - float(actual_value)
                    ) <= float(rule.get("tolerance", 0))
                except (TypeError, ValueError):
                    matches = False
                if not matches:
                    return {
                        "state": "violated",
                        "message": "external amount mismatch",
                        "evidence": evidence,
                    }
            elif expected_value != actual_value:
                return {
                    "state": "violated",
                    "message": f"external {field} mismatch",
                    "evidence": evidence,
                }
        self._ensure_verified_event(acknowledgement, record, events)
        return {
            "state": "passed",
            "message": "external assertion is satisfied",
            "evidence": evidence,
        }

    def _ensure_verified_event(
        self, acknowledgement: BusinessEvent, record: dict[str, Any], events: list[BusinessEvent]
    ) -> None:
        key = f"verification:{acknowledgement.id}"
        if self.session.scalar(select(BusinessEvent).where(BusinessEvent.idempotency_key == key)):
            return
        payload = redact({"amount": record.get("amount"), "currency": record.get("currency")})
        canonical = {
            "idempotency_key": key,
            "correlation_id": acknowledgement.correlation_id,
            "entity_type": acknowledgement.entity_type,
            "entity_id": acknowledgement.entity_id,
            "event_type": "invoice.verified",
            "occurred_at": as_json(self.now()),
            "source": {"system": "flowproof"},
            "payload": payload,
        }
        verified = BusinessEvent(
            id=str(uuid4()),
            idempotency_key=key,
            correlation_id=acknowledgement.correlation_id,
            entity_type=acknowledgement.entity_type,
            entity_id=acknowledgement.entity_id,
            event_type="invoice.verified",
            occurred_at=self.now(),
            source_system="flowproof",
            payload=payload,
            content_hash=canonical_hash(canonical),
        )
        self.session.add(verified)
        self.session.flush()
        events.append(verified)

    def _sync_incident(
        self,
        policy: Policy,
        invariant: dict[str, Any],
        entity_event: BusinessEvent,
        result: dict[str, Any],
    ) -> None:
        incident = self.session.scalar(
            select(Incident).where(
                Incident.correlation_id == entity_event.correlation_id,
                Incident.policy_version == policy.version,
                Incident.invariant_id == invariant["id"],
            )
        )
        if result["state"] == "violated":
            if incident is None:
                incident = Incident(
                    id=str(uuid4()),
                    correlation_id=entity_event.correlation_id,
                    entity_type=entity_event.entity_type,
                    entity_id=entity_event.entity_id,
                    policy_name=policy.name,
                    policy_version=policy.version,
                    invariant_id=invariant["id"],
                    severity=invariant["severity"],
                    status="open",
                    summary=result["message"],
                    evidence=result["evidence"],
                    opened_at=self.now(),
                )
                self.session.add(incident)
                self.session.flush()
                enqueue_alert(
                    self.session,
                    Alert(
                        condition="incident_opened",
                        severity=incident.severity,
                        summary=incident.summary,
                        occurred_at=incident.opened_at,
                    ),
                    dedupe_key=(
                        f"incident:{incident.policy_version}:{incident.correlation_id}:"
                        f"{incident.invariant_id}"
                    ),
                )
            else:
                if incident.status in {"resolved", "open", "acknowledged"}:
                    incident.status = "open"
                    incident.resolved_at = None
                incident.summary = result["message"]
                incident.evidence = result["evidence"]
            if (
                invariant.get("recovery_action") == "register_missing_invoice"
                and result["message"] == "missing_external_invoice"
            ):
                self._ensure_missing_invoice_plan(policy, incident, entity_event)
        elif result["state"] == "passed" and incident and incident.status != "resolved":
            incident.status = "resolved"
            incident.resolved_at = self.now()

    def _ensure_missing_invoice_plan(
        self, policy: Policy, incident: Incident, entity_event: BusinessEvent
    ) -> None:
        if not self.recovery_writes_enabled:
            incident.evidence = {
                **incident.evidence,
                "recovery_blocked": "recovery writes are disabled in this environment",
            }
            return
        existing = self.session.scalar(
            select(RecoveryPlan).where(RecoveryPlan.incident_id == incident.id)
        )
        validated = self.session.scalar(
            select(BusinessEvent)
            .where(
                BusinessEvent.correlation_id == entity_event.correlation_id,
                BusinessEvent.entity_type == entity_event.entity_type,
                BusinessEvent.entity_id == entity_event.entity_id,
                BusinessEvent.event_type == "invoice.validated",
            )
            .order_by(BusinessEvent.occurred_at)
        )
        if not validated:
            return
        parameters = {
            "invoice_id": entity_event.entity_id,
            "amount": validated.payload.get("amount"),
            "currency": validated.payload.get("currency"),
        }
        contract = client_contract(self.accounting)
        recovery = policy.definition.get("recovery", {})
        configured = recovery.get("guardrails", {}) if isinstance(recovery, dict) else {}
        try:
            guardrails = self._guardrail_snapshot(configured, parameters, contract)
        except RecoveryGateError as exc:
            incident.evidence = {**incident.evidence, "recovery_blocked": str(exc)}
            return
        plan_hash = canonical_hash(
            {
                "action_type": "register_missing_invoice",
                "parameters": parameters,
                "guardrails": guardrails,
                "provider_contract_digest": contract.digest,
            }
        )
        if existing:
            attempt = self._attempt_for_plan(existing.id)
            if existing.status == "rejected" or attempt is not None:
                return
            changed = any(
                (
                    existing.parameters != parameters,
                    existing.provider_contract_digest != contract.digest,
                    existing.guardrails != guardrails,
                    existing.plan_hash != plan_hash,
                )
            )
            if changed:
                has_decision_history = (
                    self.session.scalar(
                        select(RecoveryDecision.id)
                        .where(RecoveryDecision.recovery_plan_id == existing.id)
                        .limit(1)
                    )
                    is not None
                )
                previous_plan_state = existing.status
                previous_incident_state = incident.status
                previous_plan_hash = existing.plan_hash
                previous_contract_digest = existing.provider_contract_digest
                existing.parameters = parameters
                existing.provider_id = contract.provider_id
                existing.provider_environment = contract.environment
                existing.adapter_version = contract.adapter_version
                existing.provider_contract_digest = contract.digest
                existing.provider_contract_snapshot = contract.to_manifest()
                existing.guardrails = guardrails
                existing.plan_hash = plan_hash
                existing.risk_level = "bounded_sandbox_write"
                existing.status = "proposed"
                self._clear_approval(existing)
                if incident.status in {"open", "recovery_approved"}:
                    incident.status = "recovery_proposed"
                if previous_plan_state == "approved":
                    self._append_system_decision(
                        existing,
                        incident,
                        action="approval_invalidated",
                        reason_code="plan_or_contract_changed",
                        previous_plan_state=previous_plan_state,
                        previous_incident_state=previous_incident_state,
                        bound_plan_hash=previous_plan_hash,
                        bound_contract_digest=previous_contract_digest,
                    )
                elif has_decision_history:
                    self._append_system_decision(
                        existing,
                        incident,
                        action="plan_binding_superseded",
                        reason_code="plan_or_contract_changed",
                        previous_plan_state=previous_plan_state,
                        previous_incident_state=previous_incident_state,
                        bound_plan_hash=previous_plan_hash,
                        bound_contract_digest=previous_contract_digest,
                    )
            if incident.status in {"open", "recovery_approved"}:
                incident.status = "recovery_proposed"
            return
        self.session.add(
            RecoveryPlan(
                id=str(uuid4()),
                incident_id=incident.id,
                action_type="register_missing_invoice",
                parameters=parameters,
                idempotency_key=f"recovery:{incident.id}:register_missing_invoice",
                requires_approval=True,
                status="proposed",
                plan_hash=plan_hash,
                risk_level="bounded_sandbox_write",
                provider_id=contract.provider_id,
                provider_environment=contract.environment,
                adapter_version=contract.adapter_version,
                provider_contract_digest=contract.digest,
                provider_contract_snapshot=contract.to_manifest(),
                guardrails=guardrails,
            )
        )
        incident.status = "recovery_proposed"

    @staticmethod
    def _guardrail_snapshot(
        configured: object, parameters: dict[str, Any], contract: Any
    ) -> dict[str, Any]:
        if not isinstance(configured, dict):
            raise RecoveryGateError("recovery guardrails are missing")
        required = {
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
        if not required <= set(configured):
            raise RecoveryGateError("recovery guardrails are incomplete")
        if configured["provider_id"] != contract.provider_id:
            raise RecoveryGateError("guardrail provider does not match the configured contract")
        if configured["environment"] != contract.environment:
            raise RecoveryGateError("guardrail environment does not match the configured contract")
        if not configured["sandbox_only"] or not contract.sandbox_only:
            raise RecoveryGateError("real-mode recovery is disabled for this gate")
        currency = str(parameters.get("currency", ""))
        allowed_currencies = tuple(str(item) for item in configured["allowed_currencies"])
        if currency not in allowed_currencies:
            raise RecoveryGateError("invoice currency is outside the recovery guardrail")
        try:
            scale = int(configured["amount_scale"])
            amount = Decimal(str(parameters["amount"]))
            if not amount.is_finite():
                raise RecoveryGateError("invoice amount must be finite")
            quantum = Decimal(1).scaleb(-scale)
            if amount != amount.quantize(quantum):
                raise RecoveryGateError("invoice amount exceeds the configured precision")
            amount_minor = int(amount * (10**scale))
            maximum_minor = int(configured["maximum_amount_minor"])
        except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
            raise RecoveryGateError("invoice amount guardrail is invalid") from exc
        if amount_minor < 0 or amount_minor > maximum_minor:
            raise RecoveryGateError("invoice amount is outside the recovery guardrail")
        max_semantic = int(configured["maximum_semantic_write_attempts"])
        ttl = int(configured["approval_ttl_seconds"])
        if max_semantic != 1 or ttl <= 0:
            raise RecoveryGateError("recovery attempt or approval TTL guardrail is invalid")
        return {
            "provider_id": contract.provider_id,
            "environment": contract.environment,
            "sandbox_only": True,
            "entity_type": "invoice",
            "entity_id": str(parameters["invoice_id"]),
            "action_type": "register_missing_invoice",
            "allowed_currencies": list(allowed_currencies),
            "maximum_amount_minor": maximum_minor,
            "amount_scale": scale,
            "observed_amount_minor": amount_minor,
            "maximum_semantic_write_attempts": 1,
            "maximum_transport_invocations": contract.maximum_safe_write_attempts,
            "approval_ttl_seconds": ttl,
            "provider_contract_digest": contract.digest,
            "reconciliation_method": str(configured["reconciliation_method"]),
            "batch_allowed": False,
            "wildcards_allowed": False,
        }

    def list_incidents(self, status: str | None = None) -> list[dict[str, Any]]:
        statement: Select[tuple[Incident]] = select(Incident).order_by(Incident.opened_at.desc())
        if status:
            statement = statement.where(Incident.status == status)
        return [self.incident_view(row) for row in self.session.scalars(statement).all()]

    def incident_view(self, incident: Incident) -> dict[str, Any]:
        plan = self.session.scalar(
            select(RecoveryPlan).where(RecoveryPlan.incident_id == incident.id)
        )
        return {
            "id": incident.id,
            "correlation_id": incident.correlation_id,
            "entity_type": incident.entity_type,
            "entity_id": incident.entity_id,
            "policy": {"name": incident.policy_name, "version": incident.policy_version},
            "invariant_id": incident.invariant_id,
            "severity": incident.severity,
            "status": incident.status,
            "summary": incident.summary,
            "evidence": incident.evidence,
            "opened_at": incident.opened_at,
            "resolved_at": incident.resolved_at,
            "recovery_plan": self.plan_view(plan) if plan else None,
        }

    @staticmethod
    def plan_view(plan: RecoveryPlan) -> dict[str, Any]:
        return {
            "id": plan.id,
            "incident_id": plan.incident_id,
            "action_type": plan.action_type,
            "parameters": plan.parameters,
            "idempotency_key": plan.idempotency_key,
            "risk_level": plan.risk_level,
            "requires_approval": plan.requires_approval,
            "status": plan.status,
            "plan_hash": plan.plan_hash,
            "provider_id": plan.provider_id,
            "provider_environment": plan.provider_environment,
            "adapter_version": plan.adapter_version,
            "provider_contract_digest": plan.provider_contract_digest,
            "provider_contract_snapshot": plan.provider_contract_snapshot,
            "guardrails": plan.guardrails,
            "approved_by": plan.approved_by,
            "approval_context": plan.approval_context,
            "approved_at": plan.approved_at,
            "approval_expires_at": plan.approval_expires_at,
            "executed_at": plan.executed_at,
            "verified_at": plan.verified_at,
            "result": plan.result,
        }

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.session.get(Incident, incident_id)
        return self.incident_view(row) if row else None

    def get_plan(self, plan_id: str) -> RecoveryPlan | None:
        return self.session.get(RecoveryPlan, plan_id)

    def approve(
        self,
        plan_id: str,
        *,
        actor_id: str,
        actor_name: str,
        approval_scope: str,
        submitted_hash: str,
        submitted_incident_status: str,
        request_id: str | None = None,
        reason_code: str = "approved_by_operator",
        note: str | None = None,
    ) -> RecoveryPlan:
        self._require_recovery_writes_enabled()
        plan = self._locked_plan(plan_id)
        request_id = request_id or str(uuid4())
        if self._decision_replay(
            plan,
            request_id=request_id,
            action="approve",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=approval_scope,
            reason_code=reason_code,
            note=note,
        ):
            return plan
        if plan.status != "proposed" or not plan.requires_approval:
            raise RecoveryGateError("only a proposed approval-gated plan can be approved")
        self._validate_current_plan(plan, submitted_hash)
        if approval_scope != RECOVERY_APPROVAL_SCOPE:
            raise RecoveryGateError("approval scope is invalid")
        incident = self.session.scalar(
            select(Incident).where(Incident.id == plan.incident_id).with_for_update()
        )
        if incident is None:
            raise RecoveryGateError("incident is missing")
        if submitted_incident_status != RECOVERY_APPROVABLE_INCIDENT_STATUS:
            raise RecoveryGateError("submitted incident state is not approvable")
        if incident.status != submitted_incident_status:
            raise RecoveryGateError("incident state changed; review the incident again")
        ttl = int(plan.guardrails.get("approval_ttl_seconds", 0))
        if ttl <= 0:
            raise RecoveryGateError("approval TTL guardrail is missing")
        now = self.now()
        previous_plan_state = plan.status
        previous_incident_state = incident.status
        plan.status = "approved"
        plan.approved_plan_hash = plan.plan_hash
        plan.approved_by = actor_name
        plan.approval_expires_at = now + timedelta(seconds=ttl)
        plan.approval_context = {
            "actor_principal_id": actor_id,
            "actor_name": actor_name,
            "scope": approval_scope,
            "incident_id": incident.id,
            "incident_status": incident.status,
            "plan_hash": plan.plan_hash,
            "provider_contract_digest": plan.provider_contract_digest,
            "guardrail_digest": canonical_hash(plan.guardrails),
            "approval_expires_at": as_json(plan.approval_expires_at),
        }
        plan.approved_at = now
        incident.status = "recovery_approved"
        approval_decision = self._append_decision(
            plan,
            incident,
            action="approve",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=approval_scope,
            request_id=request_id,
            reason_code=reason_code,
            note=note,
            previous_plan_state=previous_plan_state,
            previous_incident_state=previous_incident_state,
        )
        approval_decision.decided_at = now
        approval_decision.approval_expires_at = plan.approval_expires_at
        plan.approval_context = {
            **plan.approval_context,
            "approval_decision_id": approval_decision.id,
        }
        return self._commit_human_decision(
            plan,
            request_id=request_id,
            action="approve",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=approval_scope,
            reason_code=reason_code,
            note=note,
        )

    def reject(
        self,
        plan_id: str,
        *,
        actor_id: str,
        actor_name: str,
        authorization_scope: str,
        submitted_hash: str,
        submitted_incident_status: str,
        request_id: str,
        reason_code: str,
        note: str | None,
    ) -> RecoveryPlan:
        self._require_recovery_writes_enabled()
        plan = self._locked_plan(plan_id)
        if self._decision_replay(
            plan,
            request_id=request_id,
            action="reject",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=authorization_scope,
            reason_code=reason_code,
            note=note,
        ):
            return plan
        if plan.status != "proposed":
            raise RecoveryGateError("only a proposed recovery can be rejected")
        self._validate_stored_plan_integrity(plan, submitted_hash)
        incident = self.session.scalar(
            select(Incident).where(Incident.id == plan.incident_id).with_for_update()
        )
        if incident is None:
            raise RecoveryGateError("incident is missing")
        if submitted_incident_status != incident.status or incident.status != "recovery_proposed":
            raise RecoveryGateError("incident state changed; review the incident again")
        previous_plan_state = plan.status
        previous_incident_state = incident.status
        plan.status = "rejected"
        incident.status = "recovery_rejected"
        self._clear_approval(plan)
        self._append_decision(
            plan,
            incident,
            action="reject",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=authorization_scope,
            request_id=request_id,
            reason_code=reason_code,
            note=note,
            previous_plan_state=previous_plan_state,
            previous_incident_state=previous_incident_state,
        )
        return self._commit_human_decision(
            plan,
            request_id=request_id,
            action="reject",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=authorization_scope,
            reason_code=reason_code,
            note=note,
        )

    def revoke_approval(
        self,
        plan_id: str,
        *,
        actor_id: str,
        actor_name: str,
        authorization_scope: str,
        submitted_hash: str,
        submitted_incident_status: str,
        request_id: str,
        reason_code: str,
        note: str | None,
    ) -> RecoveryPlan:
        self._require_recovery_writes_enabled()
        plan = self._locked_plan(plan_id)
        if self._decision_replay(
            plan,
            request_id=request_id,
            action="revoke_approval",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=authorization_scope,
            reason_code=reason_code,
            note=note,
        ):
            return plan
        if plan.status != "approved":
            raise RecoveryGateError("only an approved undispatched recovery can be revoked")
        self._validate_current_plan(plan, submitted_hash)
        incident = self.session.scalar(
            select(Incident).where(Incident.id == plan.incident_id).with_for_update()
        )
        if incident is None:
            raise RecoveryGateError("incident is missing")
        if submitted_incident_status != incident.status or incident.status != "recovery_approved":
            raise RecoveryGateError("incident state changed; reconcile before revocation")
        attempt = self._attempt_for_plan(plan.id, lock=True)
        if attempt is not None:
            active_approval_id = plan.approval_context.get("approval_decision_id")
            retry_is_unconsumed = (
                attempt.state == "RECONCILED_EFFECT_ABSENT"
                and attempt.retry_permitted
                and isinstance(active_approval_id, str)
                and self.session.scalar(
                    select(RecoveryTransportInvocation.id).where(
                        RecoveryTransportInvocation.recovery_attempt_id == attempt.id,
                        RecoveryTransportInvocation.approval_decision_id == active_approval_id,
                    )
                )
                is None
            )
            if not retry_is_unconsumed:
                raise RecoveryGateError(
                    "external dispatch may have started; reconcile before deciding"
                )
        previous_plan_state = plan.status
        previous_incident_state = incident.status
        plan.status = "proposed"
        incident.status = "recovery_proposed"
        self._clear_approval(plan)
        self._append_decision(
            plan,
            incident,
            action="revoke_approval",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=authorization_scope,
            request_id=request_id,
            reason_code=reason_code,
            note=note,
            previous_plan_state=previous_plan_state,
            previous_incident_state=previous_incident_state,
        )
        return self._commit_human_decision(
            plan,
            request_id=request_id,
            action="revoke_approval",
            actor_id=actor_id,
            actor_name=actor_name,
            authorization_scope=authorization_scope,
            reason_code=reason_code,
            note=note,
        )

    def execute(self, plan_id: str) -> RecoveryPlan:
        self._require_recovery_writes_enabled()
        plan = self._locked_plan(plan_id)
        if plan.action_type != "register_missing_invoice":
            raise RecoveryGateError("action is not allowlisted")
        if plan.status in {"verifying", "still_failed", "verified"}:
            return plan
        if plan.status != "approved" or not plan.approved_plan_hash:
            raise RecoveryGateError("human approval is required before execution")
        self._validate_current_plan(plan, plan.plan_hash)
        if not secrets.compare_digest(plan.plan_hash, plan.approved_plan_hash):
            raise RecoveryGateError("plan changed after approval")
        if plan.approval_expires_at is None or self.now() >= normalize_utc(
            plan.approval_expires_at
        ):
            expired_incident = self.session.scalar(
                select(Incident).where(Incident.id == plan.incident_id).with_for_update()
            )
            previous_plan_state = plan.status
            previous_incident_state = (
                expired_incident.status if expired_incident is not None else "missing"
            )
            plan.status = "proposed"
            self._clear_approval(plan)
            if expired_incident is not None and expired_incident.status == "recovery_approved":
                expired_incident.status = "recovery_proposed"
                self._append_system_decision(
                    plan,
                    expired_incident,
                    action="approval_expired",
                    reason_code="approval_ttl_elapsed",
                    previous_plan_state=previous_plan_state,
                    previous_incident_state=previous_incident_state,
                )
            self.session.commit()
            raise RecoveryGateError("human approval expired; review and approve again")
        incident = self.session.scalar(
            select(Incident).where(Incident.id == plan.incident_id).with_for_update()
        )
        if incident is None:
            raise RecoveryGateError("incident is missing")
        context = plan.approval_context if isinstance(plan.approval_context, dict) else {}
        expected_context = {
            "scope": RECOVERY_APPROVAL_SCOPE,
            "incident_id": incident.id,
            "incident_status": RECOVERY_APPROVABLE_INCIDENT_STATUS,
            "plan_hash": plan.plan_hash,
            "provider_contract_digest": plan.provider_contract_digest,
            "guardrail_digest": canonical_hash(plan.guardrails),
            "approval_expires_at": as_json(plan.approval_expires_at),
        }
        if (
            not context.get("actor_principal_id")
            or not context.get("actor_name")
            or not plan.approved_by
            or plan.approved_at is None
        ):
            raise RecoveryGateError("approval context is incomplete; review and approve again")
        if context.get("actor_name") != plan.approved_by:
            raise RecoveryGateError("approval identity changed; review and approve again")
        if any(context.get(key) != value for key, value in expected_context.items()):
            raise RecoveryGateError("approval context changed; review and approve again")
        approval_decision_id = context.get("approval_decision_id")
        approval_decision = (
            self.session.get(RecoveryDecision, approval_decision_id)
            if isinstance(approval_decision_id, str)
            else None
        )
        if (
            approval_decision is None
            or approval_decision.recovery_plan_id != plan.id
            or approval_decision.incident_id != incident.id
            or approval_decision.action != "approve"
            or approval_decision.decision_kind != "human"
            or approval_decision.actor_principal_id != context.get("actor_principal_id")
            or approval_decision.actor_display_name != context.get("actor_name")
            or approval_decision.authorization_scope != RECOVERY_APPROVAL_SCOPE
            or approval_decision.plan_hash != plan.plan_hash
            or approval_decision.provider_contract_digest != plan.provider_contract_digest
            or normalize_utc(approval_decision.decided_at) != normalize_utc(plan.approved_at)
        ):
            raise RecoveryGateError(
                "approval decision lineage is invalid; review and approve again"
            )
        if incident.status != "recovery_approved":
            raise RecoveryGateError("incident state changed after approval; do not execute")
        invoice_id = str(plan.parameters["invoice_id"])
        observation = coerce_observation(self.accounting, invoice_id)
        if not observation.available:
            raise RecoveryGateError("cannot verify external precondition")
        if observation.state != ObservationState.AVAILABLE_ABSENT:
            raise RecoveryGateError("invoice already exists; compensation is no longer safe")
        attempt = self._attempt_for_plan(plan.id, lock=True)
        if attempt is None:
            now = self.now()
            attempt = RecoveryAttempt(
                id=str(uuid4()),
                recovery_plan_id=plan.id,
                incident_id=incident.id,
                approval_decision_id=approval_decision.id,
                attempt_ordinal=1,
                execution_idempotency_key=plan.idempotency_key,
                plan_hash=plan.plan_hash,
                provider_contract_digest=plan.provider_contract_digest,
                provider_id=plan.provider_id,
                provider_environment=plan.provider_environment,
                adapter_version=plan.adapter_version,
                request_digest=canonical_hash(plan.parameters),
                precondition_observation_digest=observation.to_evidence()["content_digest"],
                state="PREPARED",
                semantic_attempt_count=1,
                transport_invocation_count=0,
                retry_permitted=False,
                safe_result={"precondition": observation.to_evidence()},
                created_at=now,
                updated_at=now,
            )
            self.session.add(attempt)
            plan.status = "executing"
            incident.status = "recovery_running"
            try:
                self.session.commit()
            except (IntegrityError, StaleDataError) as exc:
                self.session.rollback()
                raise RecoveryGateError(
                    "another execution prepared this semantic attempt; reload before retrying"
                ) from exc
        elif attempt.state == "RECONCILED_EFFECT_ABSENT" and attempt.retry_permitted:
            if attempt.transport_invocation_count >= int(
                plan.guardrails.get("maximum_transport_invocations", 1)
            ):
                raise RecoveryGateError("bounded transport invocation limit is exhausted")
        else:
            raise RecoveryGateError("a durable attempt already exists; reconcile before execution")
        return self._dispatch_attempt(plan, incident, attempt)

    def _dispatch_attempt(
        self, plan: RecoveryPlan, incident: Incident, attempt: RecoveryAttempt
    ) -> RecoveryPlan:
        active_approval_id = plan.approval_context.get("approval_decision_id")
        approval_decision = (
            self.session.get(RecoveryDecision, active_approval_id)
            if isinstance(active_approval_id, str)
            else None
        )
        reserved_at = self.now()
        if (
            approval_decision is None
            or approval_decision.action != "approve"
            or approval_decision.recovery_plan_id != plan.id
            or approval_decision.approval_expires_at is None
            or reserved_at >= normalize_utc(approval_decision.approval_expires_at)
        ):
            raise RecoveryGateError("transport approval is missing or expired")
        expected_state = attempt.state
        claim_conditions = [
            RecoveryAttempt.id == attempt.id,
            RecoveryAttempt.state == expected_state,
        ]
        if expected_state == "RECONCILED_EFFECT_ABSENT":
            claim_conditions.append(RecoveryAttempt.retry_permitted.is_(True))
        elif expected_state != "PREPARED":
            raise RecoveryGateError("recovery attempt is not dispatchable; reconcile first")
        claimed = self.session.execute(
            update(RecoveryAttempt)
            .where(*claim_conditions)
            .values(
                state="DISPATCHING",
                transport_invocation_count=RecoveryAttempt.transport_invocation_count + 1,
                retry_permitted=False,
                updated_at=self.now(),
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            self.session.rollback()
            raise RecoveryGateError("recovery dispatch was claimed concurrently; reload state")
        self.session.add(
            RecoveryTransportInvocation(
                id=str(uuid4()),
                recovery_attempt_id=attempt.id,
                recovery_plan_id=plan.id,
                approval_decision_id=approval_decision.id,
                invocation_ordinal=attempt.transport_invocation_count + 1,
                request_digest=attempt.request_digest,
                reserved_at=reserved_at,
            )
        )
        plan.status = "executing"
        incident.status = "recovery_running"
        self.session.commit()
        self.session.refresh(attempt)
        outcome = coerce_write_outcome(self.accounting, plan.parameters, plan.idempotency_key)
        now = self.now()
        attempt.outcome_classification = outcome.state.value
        attempt.provider_operation_reference = outcome.operation_reference
        attempt.retry_after_seconds = outcome.retry_after_seconds
        attempt.updated_at = now
        attempt.safe_result = {
            **attempt.safe_result,
            "write_outcome": outcome.to_evidence(),
        }
        plan.result = {"attempt_id": attempt.id, "write_outcome": outcome.to_evidence()}
        if outcome.state == WriteOutcomeState.ACCEPTED:
            # Persist the typed provider outcome before advancing the plan. A crash after
            # this commit is reconciled by authoritative read, never by a blind write.
            attempt.state = "ACCEPTED"
            attempt.accepted_at = now
            plan.executed_at = now
            self.session.commit()
            attempt.state = "VERIFYING"
            attempt.updated_at = self.now()
            plan.status = "verifying"
            incident.status = "verifying"
            self.session.commit()
            return plan
        if outcome.state in {
            WriteOutcomeState.POST_ACCEPTANCE_OUTCOME_UNKNOWN,
            WriteOutcomeState.MALFORMED_RESPONSE,
        }:
            attempt.state = "OUTCOME_UNKNOWN"
        else:
            attempt.state = "PRE_ACCEPTANCE_FAILED"
        plan.status = "needs_attention"
        incident.status = "needs_attention"
        enqueue_alert(
            self.session,
            Alert(
                condition="recovery_needs_attention",
                severity="high",
                summary="A recovery attempt requires authoritative reconciliation",
                occurred_at=now,
            ),
            dedupe_key=f"recovery_needs_attention:{plan.id}",
        )
        self.session.commit()
        raise RecoveryGateError("recovery outcome requires authoritative reconciliation")

    def reconcile(self, plan_id: str, *, submitted_hash: str) -> RecoveryPlan:
        self._require_recovery_writes_enabled()
        plan = self._locked_plan(plan_id)
        self._validate_current_plan(plan, submitted_hash)
        incident = self.session.scalar(
            select(Incident).where(Incident.id == plan.incident_id).with_for_update()
        )
        attempt = self._attempt_for_plan(plan.id, lock=True)
        if incident is None or attempt is None:
            raise RecoveryGateError("durable recovery attempt is missing")
        if attempt.state == "RECONCILED_EFFECT_ABSENT":
            if plan.status == "approved":
                raise RecoveryGateError(
                    "retry approval is active; execute it or wait for authority to clear"
                )
            if plan.status in {"proposed", "rejected"}:
                return plan
        if attempt.state == "RECONCILED_EFFECT_PRESENT":
            attempt.state = "VERIFYING"
            attempt.updated_at = self.now()
            plan.status = "verifying"
            incident.status = "verifying"
            self.session.commit()
            return plan
        if attempt.state not in AMBIGUOUS_ATTEMPT_STATES | {
            "PRE_ACCEPTANCE_FAILED",
            "RECONCILED_EFFECT_ABSENT",
        }:
            return plan
        prior_attempt_state = attempt.state
        attempt.state = "RECONCILING"
        attempt.updated_at = self.now()
        try:
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise RecoveryGateError(
                "recovery attempt changed concurrently; reload before reconciling"
            ) from exc
        observation = coerce_observation(self.accounting, str(plan.parameters["invoice_id"]))
        evidence = observation.to_evidence()
        attempt.safe_result = {**attempt.safe_result, "reconciliation_observation": evidence}
        attempt.updated_at = self.now()
        if not observation.available:
            attempt.state = "OUTCOME_UNKNOWN"
            plan.status = "needs_attention"
            incident.status = "needs_attention"
            self.session.commit()
            return plan
        if observation.state == ObservationState.AVAILABLE_PRESENT and self._record_matches_plan(
            observation.records[0], plan
        ):
            attempt.state = "RECONCILED_EFFECT_PRESENT"
            attempt.reconciled_at = self.now()
            plan.executed_at = plan.executed_at or self.now()
            self.session.commit()
            attempt.state = "VERIFYING"
            attempt.updated_at = self.now()
            plan.status = "verifying"
            incident.status = "verifying"
            self.session.commit()
            return plan
        if observation.state == ObservationState.AVAILABLE_ABSENT:
            authoritative_reconciled_at = self.now()
            attempt.reconciled_at = authoritative_reconciled_at
            contract = client_contract(self.accounting)
            pre_acceptance_proven = attempt.outcome_classification in {
                WriteOutcomeState.PRE_ACCEPTANCE_FAILURE.value,
                WriteOutcomeState.AUTHENTICATION_FAILED.value,
                WriteOutcomeState.RATE_LIMITED.value,
            }
            tested_idempotency = contract.idempotency.get("support") == "CONTRACT_TESTED"
            invocation_room = attempt.transport_invocation_count < int(
                plan.guardrails.get("maximum_transport_invocations", 1)
            )
            if invocation_room and (pre_acceptance_proven or tested_idempotency):
                previous_plan_state = plan.status
                previous_incident_state = incident.status
                reconciled_at = authoritative_reconciled_at
                retry_reason = (
                    "pre_acceptance_failure_proven"
                    if pre_acceptance_proven
                    else "contract_tested_same_key_idempotency"
                )
                reapproval_action = (
                    "prepared_reapproval_required"
                    if attempt.transport_invocation_count == 0
                    else "retry_reapproval_required"
                )
                history = attempt.safe_result.get("reconciliation_history", [])
                if not isinstance(history, list):
                    raise RecoveryGateError("reconciliation history is invalid")
                history_entry = {
                    "observation": evidence,
                    "reconciled_at": as_json(reconciled_at),
                    "reapproval_action": reapproval_action,
                    "transport_invocation_count": attempt.transport_invocation_count,
                    "prior_attempt_state": prior_attempt_state,
                    "retry_reason": retry_reason,
                    "write_outcome": attempt.safe_result.get("write_outcome"),
                }
                attempt.safe_result = {
                    **attempt.safe_result,
                    "reconciliation_observation": evidence,
                    "reconciliation_history": [*history, history_entry],
                }
                attempt.state = "RECONCILED_EFFECT_ABSENT"
                attempt.reconciled_at = reconciled_at
                attempt.retry_permitted = True
                attempt.retry_reason = retry_reason
                plan.status = "proposed"
                incident.status = "recovery_proposed"
                self._clear_approval(plan)
                self._append_system_decision(
                    plan,
                    incident,
                    action=reapproval_action,
                    reason_code=(
                        "prepared_intent_effect_absent"
                        if attempt.transport_invocation_count == 0
                        else "effect_absent_after_reconciliation"
                    ),
                    previous_plan_state=previous_plan_state,
                    previous_incident_state=previous_incident_state,
                )
            else:
                attempt.state = "NEEDS_ATTENTION"
                plan.status = "needs_attention"
                incident.status = "needs_attention"
            self.session.commit()
            return plan
        attempt.state = "RECONCILED_CONFLICT"
        attempt.reconciled_at = self.now()
        plan.status = "needs_attention"
        incident.status = "needs_attention"
        self.session.commit()
        return plan

    def verify_recovery(self, plan_id: str) -> RecoveryPlan:
        self._require_recovery_writes_enabled()
        plan = self._locked_plan(plan_id)
        if plan.status not in {"verifying", "still_failed"} or plan.executed_at is None:
            raise RecoveryGateError("execute an approved plan before verification")
        incident = self.session.get(Incident, plan.incident_id)
        if incident is None:
            raise RecoveryGateError("incident is missing")
        self.evaluate(incident.correlation_id)
        self.session.refresh(plan)
        self.session.refresh(incident)
        if incident.status == "resolved":
            plan.status = "verified"
            plan.verified_at = self.now()
            plan.result = {
                **plan.result,
                "postcondition": {
                    "status": "resolved",
                    "checked_at": as_json(plan.verified_at),
                    "incident_id": incident.id,
                    "evidence": incident.evidence,
                },
            }
            attempt = self._attempt_for_plan(plan.id, lock=True)
            if attempt is not None:
                attempt.state = "VERIFIED"
                attempt.updated_at = self.now()
        else:
            checked_at = self.now()
            plan.status = "still_failed"
            incident.status = "still_failed"
            plan.result = {
                **plan.result,
                "postcondition": {
                    "status": "still_failed",
                    "checked_at": as_json(checked_at),
                    "incident_id": incident.id,
                    "evidence": incident.evidence,
                },
            }
            attempt = self._attempt_for_plan(plan.id, lock=True)
            if attempt is not None:
                attempt.state = "STILL_FAILED"
                attempt.updated_at = checked_at
        self.session.commit()
        return plan

    def list_attempts(self, plan_id: str) -> list[dict[str, Any]]:
        self._required_plan(plan_id)
        rows = self.session.scalars(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.recovery_plan_id == plan_id)
            .order_by(RecoveryAttempt.attempt_ordinal, RecoveryAttempt.created_at)
        ).all()
        return [self.attempt_view(row) for row in rows]

    def list_decisions(self, plan_id: str) -> list[dict[str, Any]]:
        self._required_plan(plan_id)
        rows = self.session.scalars(
            select(RecoveryDecision)
            .where(RecoveryDecision.recovery_plan_id == plan_id)
            .order_by(RecoveryDecision.decided_at, RecoveryDecision.id)
        ).all()
        return [self.decision_view(row) for row in rows]

    def record_operator_review(
        self,
        plan_id: str,
        *,
        actor_id: str,
        actor_name: str,
        request_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        plan = self._locked_plan(plan_id)
        if not secrets.compare_digest(plan.plan_hash, str(payload["plan_hash"])):
            raise RecoveryGateError("operator review names a different plan hash")
        incident = self.session.get(Incident, plan.incident_id)
        if incident is None:
            raise RecoveryGateError("incident is missing")
        checks = (
            "evidence_understood",
            "authoritative_source_understood",
            "blast_radius_understood",
            "proposed_action_understood",
            "reject_path_available",
            "revoke_path_available",
            "reconciliation_path_understood",
        )
        complete = all(payload[name] is True for name in checks)
        contract_classification = plan.provider_contract_snapshot.get(
            "evidence_classification", {}
        ).get("overall")
        latest_decision = self.session.scalar(
            select(RecoveryDecision)
            .where(RecoveryDecision.recovery_plan_id == plan.id)
            .order_by(RecoveryDecision.decided_at.desc(), RecoveryDecision.id.desc())
        )
        decision_matches = payload["final_decision"] == "observe_only" or (
            latest_decision is not None and payload["final_decision"] == latest_decision.action
        )
        current_decision_states = {
            "approve": {
                "approved",
                "executing",
                "verifying",
                "still_failed",
                "verified",
                "needs_attention",
            },
            "reject": {"rejected"},
            "revoke_approval": {"proposed"},
        }
        if payload["final_decision"] != "observe_only":
            decision_matches = decision_matches and plan.status in current_decision_states.get(
                str(payload["final_decision"]), set()
            )
        verdict = (
            "BLOCKED_EXTERNAL"
            if plan.provider_id == "mock-accounting"
            or contract_classification != "LIVE_SANDBOX_OBSERVED"
            else "PENDING_FINAL_CAPSULE_VERIFICATION"
            if complete and payload.get("capsule_digest") and decision_matches
            else "OPERATOR_CONTESTABILITY_FAILED"
        )
        note_digest = decision_note_digest(payload.get("note"))
        row = OperatorReview(
            id=str(uuid4()),
            incident_id=incident.id,
            recovery_plan_id=plan.id,
            request_id=request_id,
            actor_principal_id=actor_id,
            actor_display_name=actor_name,
            plan_hash=plan.plan_hash,
            capsule_digest=payload.get("capsule_digest"),
            final_decision=str(payload["final_decision"]),
            note_digest=note_digest,
            verdict=verdict,
            reviewed_at=self.now(),
            **{name: bool(payload[name]) for name in checks},
        )
        self.session.add(row)
        try:
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            existing = self.session.scalar(
                select(OperatorReview).where(OperatorReview.request_id == request_id)
            )
            if existing is None or existing.recovery_plan_id != plan.id:
                raise RecoveryGateError("operator review request ID is already bound") from exc
            expected = (
                actor_id,
                actor_name,
                plan.plan_hash,
                payload.get("capsule_digest"),
                *(bool(payload[name]) for name in checks),
                str(payload["final_decision"]),
                note_digest,
                verdict,
            )
            actual = (
                existing.actor_principal_id,
                existing.actor_display_name,
                existing.plan_hash,
                existing.capsule_digest,
                *(bool(getattr(existing, name)) for name in checks),
                existing.final_decision,
                existing.note_digest,
                existing.verdict,
            )
            if actual != expected:
                raise RecoveryGateError(
                    "operator review request ID is already bound to different content"
                ) from exc
            row = existing
        return self.operator_review_view(row)

    @staticmethod
    def attempt_view(row: RecoveryAttempt) -> dict[str, Any]:
        return as_json(
            {
                "id": row.id,
                "recovery_plan_id": row.recovery_plan_id,
                "incident_id": row.incident_id,
                "approval_decision_id": row.approval_decision_id,
                "attempt_ordinal": row.attempt_ordinal,
                "execution_idempotency_key": row.execution_idempotency_key,
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
                "safe_result": row.safe_result,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "accepted_at": row.accepted_at,
                "reconciled_at": row.reconciled_at,
            }
        )

    @staticmethod
    def decision_view(row: RecoveryDecision) -> dict[str, Any]:
        return as_json(
            {
                "id": row.id,
                "recovery_plan_id": row.recovery_plan_id,
                "incident_id": row.incident_id,
                "request_id": row.request_id,
                "action": row.action,
                "decision_kind": row.decision_kind,
                "actor_principal_id": row.actor_principal_id,
                "actor_display_name": row.actor_display_name,
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
                "decided_at": row.decided_at,
                "approval_expires_at": row.approval_expires_at,
            }
        )

    @staticmethod
    def operator_review_view(row: OperatorReview) -> dict[str, Any]:
        return as_json(
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "recovery_plan_id": row.recovery_plan_id,
                "request_id": row.request_id,
                "actor_principal_id": row.actor_principal_id,
                "actor_display_name": row.actor_display_name,
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
                "reviewed_at": row.reviewed_at,
            }
        )

    def _append_decision(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        *,
        action: str,
        actor_id: str,
        actor_name: str,
        authorization_scope: str,
        request_id: str,
        reason_code: str,
        note: str | None,
        previous_plan_state: str,
        previous_incident_state: str,
    ) -> RecoveryDecision:
        decision = RecoveryDecision(
            id=str(uuid4()),
            recovery_plan_id=plan.id,
            incident_id=incident.id,
            request_id=request_id,
            action=action,
            decision_kind="human",
            actor_principal_id=actor_id,
            actor_display_name=actor_name,
            authorization_scope=authorization_scope,
            plan_hash=plan.plan_hash,
            provider_contract_digest=plan.provider_contract_digest,
            incident_state_observed=previous_incident_state,
            plan_state_observed=previous_plan_state,
            reason_code=reason_code,
            note_digest=decision_note_digest(note),
            previous_plan_state=previous_plan_state,
            resulting_plan_state=plan.status,
            previous_incident_state=previous_incident_state,
            resulting_incident_state=incident.status,
            decided_at=self.now(),
        )
        self.session.add(decision)
        return decision

    def _append_system_decision(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        *,
        action: str,
        reason_code: str,
        previous_plan_state: str,
        previous_incident_state: str,
        bound_plan_hash: str | None = None,
        bound_contract_digest: str | None = None,
    ) -> None:
        self.session.add(
            RecoveryDecision(
                id=str(uuid4()),
                recovery_plan_id=plan.id,
                incident_id=incident.id,
                request_id=f"system:{action}:{uuid4()}",
                action=action,
                decision_kind="system",
                actor_principal_id=None,
                actor_display_name="flowproof-system",
                authorization_scope="system:approval_lifecycle",
                plan_hash=bound_plan_hash or plan.plan_hash,
                provider_contract_digest=(
                    bound_contract_digest or plan.provider_contract_digest
                ),
                incident_state_observed=previous_incident_state,
                plan_state_observed=previous_plan_state,
                reason_code=reason_code,
                note_digest=None,
                previous_plan_state=previous_plan_state,
                resulting_plan_state=plan.status,
                previous_incident_state=previous_incident_state,
                resulting_incident_state=incident.status,
                decided_at=self.now(),
            )
        )

    def _decision_replay(
        self,
        plan: RecoveryPlan,
        *,
        request_id: str,
        action: str,
        actor_id: str,
        actor_name: str,
        authorization_scope: str,
        reason_code: str,
        note: str | None,
    ) -> bool:
        existing = self.session.scalar(
            select(RecoveryDecision).where(
                RecoveryDecision.recovery_plan_id == plan.id,
                RecoveryDecision.request_id == request_id,
            )
        )
        if existing is None:
            return False
        expected = (
            action,
            actor_id,
            actor_name,
            authorization_scope,
            plan.plan_hash,
            reason_code,
            decision_note_digest(note),
        )
        actual = (
            existing.action,
            existing.actor_principal_id,
            existing.actor_display_name,
            existing.authorization_scope,
            existing.plan_hash,
            existing.reason_code,
            existing.note_digest,
        )
        if actual != expected:
            raise RecoveryGateError("decision request ID is already bound to different content")
        return True

    def _commit_human_decision(
        self,
        plan: RecoveryPlan,
        *,
        request_id: str,
        action: str,
        actor_id: str,
        actor_name: str,
        authorization_scope: str,
        reason_code: str,
        note: str | None,
    ) -> RecoveryPlan:
        plan_id = plan.id
        try:
            self.session.commit()
            return plan
        except (IntegrityError, StaleDataError) as exc:
            self.session.rollback()
            current = self._required_plan(plan_id)
            if self._decision_replay(
                current,
                request_id=request_id,
                action=action,
                actor_id=actor_id,
                actor_name=actor_name,
                authorization_scope=authorization_scope,
                reason_code=reason_code,
                note=note,
            ):
                return current
            raise RecoveryGateError(
                "recovery decision lost a concurrent state race; reload before retrying"
            ) from exc

    @staticmethod
    def _clear_approval(plan: RecoveryPlan) -> None:
        plan.approved_plan_hash = None
        plan.approved_by = None
        plan.approval_context = {}
        plan.approved_at = None
        plan.approval_expires_at = None

    def _validate_current_plan(self, plan: RecoveryPlan, submitted_hash: str) -> None:
        self._validate_stored_plan_integrity(plan, submitted_hash)
        contract = client_contract(self.accounting)
        if not secrets.compare_digest(plan.provider_contract_digest, contract.digest):
            self._invalidate_changed_approval(plan)
            raise RecoveryGateError("provider contract changed; create and review a new plan")
        if plan.guardrails.get("provider_contract_digest") != contract.digest:
            self._invalidate_changed_approval(plan)
            raise RecoveryGateError("guardrail contract binding changed")

    def _validate_stored_plan_integrity(
        self, plan: RecoveryPlan, submitted_hash: str
    ) -> None:
        if not secrets.compare_digest(plan.plan_hash, submitted_hash):
            raise RecoveryGateError("plan hash changed; review the plan again")
        current_hash = canonical_hash(
            {
                "action_type": plan.action_type,
                "parameters": plan.parameters,
                "guardrails": plan.guardrails,
                "provider_contract_digest": plan.provider_contract_digest,
            }
        )
        if not secrets.compare_digest(plan.plan_hash, current_hash):
            self._invalidate_changed_approval(plan)
            raise RecoveryGateError("plan content changed, or guardrails/contract binding changed")

    def _invalidate_changed_approval(self, plan: RecoveryPlan) -> None:
        if plan.status != "approved":
            return
        attempt = self._attempt_for_plan(plan.id, lock=True)
        if attempt is not None and attempt.state != "RECONCILED_EFFECT_ABSENT":
            return
        incident = self.session.scalar(
            select(Incident).where(Incident.id == plan.incident_id).with_for_update()
        )
        previous_plan_state = plan.status
        previous_incident_state = incident.status if incident is not None else "missing"
        plan.status = "proposed"
        self._clear_approval(plan)
        if incident is not None and incident.status == "recovery_approved":
            incident.status = "recovery_proposed"
            self._append_system_decision(
                plan,
                incident,
                action="approval_invalidated",
                reason_code="plan_or_contract_changed",
                previous_plan_state=previous_plan_state,
                previous_incident_state=previous_incident_state,
            )
        self.session.commit()

    def _attempt_for_plan(self, plan_id: str, *, lock: bool = False) -> RecoveryAttempt | None:
        statement = select(RecoveryAttempt).where(RecoveryAttempt.recovery_plan_id == plan_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def _locked_plan(self, plan_id: str) -> RecoveryPlan:
        plan = self.session.scalar(
            select(RecoveryPlan).where(RecoveryPlan.id == plan_id).with_for_update()
        )
        if plan is None:
            raise RecoveryGateError("recovery plan was not found")
        return plan

    def _require_recovery_writes_enabled(self) -> None:
        if not self.recovery_writes_enabled:
            raise RecoveryGateError("recovery writes are disabled in this environment")

    @staticmethod
    def _record_matches_plan(record: dict[str, Any], plan: RecoveryPlan) -> bool:
        record_id = record.get("invoice_id", record.get("id"))
        if record_id is not None and str(record_id) != str(plan.parameters["invoice_id"]):
            return False
        if str(record.get("currency")) != str(plan.parameters.get("currency")):
            return False
        try:
            return Decimal(str(record.get("amount"))) == Decimal(str(plan.parameters.get("amount")))
        except InvalidOperation:
            return False

    def configure_chaos(self, mode: str, correlation_id: str | None) -> dict[str, Any]:
        if not isinstance(self.accounting, MockChaosControl):
            raise RecoveryGateError("the configured provider does not expose mock chaos control")
        result = self.accounting.set_chaos_mode(mode)
        now = self.now()
        run = ChaosRun(
            id=str(uuid4()),
            scenario_id=mode,
            correlation_id=correlation_id,
            status="configured",
            started_at=now,
            finished_at=now,
            expected_invariants=["external_invoice_exists"] if mode == "false_200" else [],
            result=result,
        )
        self.session.add(run)
        self.session.commit()
        return {"id": run.id, "mode": mode, "result": result}

    def blast_radius(self) -> list[dict[str, Any]]:
        rows = self.session.scalars(
            select(Incident)
            .where(Incident.status != "resolved")
            .order_by(Incident.opened_at.desc())
        ).all()
        groups: dict[str, dict[str, Any]] = {}
        for incident in rows:
            group = groups.setdefault(
                incident.correlation_id,
                {
                    "correlation_id": incident.correlation_id,
                    "affected_count": 0,
                    "affected_amount": 0.0,
                    "incident_ids": [],
                },
            )
            group["affected_count"] += 1
            group["incident_ids"].append(incident.id)
            validated = self.session.scalar(
                select(BusinessEvent).where(
                    BusinessEvent.correlation_id == incident.correlation_id,
                    BusinessEvent.event_type == "invoice.validated",
                )
            )
            if validated:
                try:
                    group["affected_amount"] += float(validated.payload.get("amount", 0))
                except (TypeError, ValueError):
                    pass
        return list(groups.values())

    def _required_plan(self, plan_id: str) -> RecoveryPlan:
        plan = self.get_plan(plan_id)
        if not plan:
            raise RecoveryGateError("recovery plan was not found")
        return plan
