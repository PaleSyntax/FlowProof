"""Canonical external assertion evaluation with optional fenced observation reuse."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from flowproof.accounting import (
    InvoiceObservation,
    ObservationState,
    coerce_observation,
)
from flowproof.models import BusinessEvent
from flowproof.policy import canonical_hash
from flowproof.service_core import (
    RecoveryGateError,
    as_json,
    event_ids,
    first_event,
    json_path,
    normalize_utc,
    parse_duration,
    redact,
)


@dataclass(slots=True)
class _FencedObservationContext:
    entity_reference: str
    observation: InvoiceObservation
    reservation_id: str | None
    consumed: int = 0


class PostconditionEvaluationBehavior:
    """Evaluate one external assertion through normal or fenced observation input."""

    _fenced_observation_context: _FencedObservationContext | None = None

    def _external_assertion(
        self,
        invariant: dict[str, Any],
        events: list[BusinessEvent],
    ) -> dict[str, Any]:
        acknowledgement = first_event(events, invariant["after"])
        validated = first_event(events, "invoice.validated")
        evidence: dict[str, Any] = {
            "event_ids": event_ids(acknowledgement, validated)
        }
        if acknowledgement is None:
            return {
                "state": "pending",
                "message": "waiting for acknowledgement",
                "evidence": evidence,
            }

        fenced = self._fenced_observation_context
        if fenced is None:
            observation = coerce_observation(
                self.accounting,
                acknowledgement.entity_id,
            )
        else:
            if (
                fenced.entity_reference != acknowledgement.entity_id
                or fenced.consumed != 0
            ):
                raise RecoveryGateError(
                    "fenced observation does not match exactly one invariant subject"
                )
            observation = fenced.observation
            fenced.consumed += 1

        observation_evidence = observation.to_evidence()
        evidence["observation"] = observation_evidence
        if not observation.available:
            return {
                "state": "error",
                "message": (
                    "external verifier unavailable: "
                    f"{observation.state.value}"
                ),
                "evidence": evidence,
            }

        records = list(observation.records)
        expected = invariant.get("expect", {})
        if observation.state == ObservationState.AVAILABLE_ABSENT:
            evidence["expected"] = expected
            deadline = parse_duration(invariant["within"])
            if self.now() - normalize_utc(acknowledgement.occurred_at) < deadline:
                return {
                    "state": "pending",
                    "message": (
                        "external record has not appeared within the allowed deadline"
                    ),
                    "evidence": evidence,
                }
            return {
                "state": "violated",
                "message": "missing_external_invoice",
                "evidence": evidence,
            }
        if observation.state != ObservationState.AVAILABLE_PRESENT:
            return {
                "state": "violated",
                "message": "external invoice observation is conflicting",
                "evidence": evidence,
            }
        if expected.get("unique") and len(records) != 1:
            return {
                "state": "violated",
                "message": "external invoice is not unique",
                "evidence": evidence,
            }
        if len(records) != 1:
            return {
                "state": "violated",
                "message": "external invoice observation has invalid cardinality",
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
            expected_event = first_event(
                events,
                rule["equals_event"]["event"],
            )
            expected_value = (
                json_path(
                    expected_event.payload,
                    rule["equals_event"]["path"],
                )
                if expected_event is not None
                else None
            )
            actual_value = record.get(field)
            evidence.setdefault("field_checks", {})[field] = {
                "expected": expected_value,
                "actual": actual_value,
            }
            if field == "amount":
                try:
                    difference = abs(
                        Decimal(str(expected_value))
                        - Decimal(str(actual_value))
                    )
                    tolerance = Decimal(str(rule.get("tolerance", 0)))
                    matches = expected_value is not None and difference <= tolerance
                except (InvalidOperation, TypeError, ValueError):
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
        self,
        acknowledgement: BusinessEvent,
        record: dict[str, Any],
        events: list[BusinessEvent],
    ) -> None:
        fenced = self._fenced_observation_context
        if fenced is None:
            super()._ensure_verified_event(acknowledgement, record, events)
            return

        evidence = fenced.observation.to_evidence()
        digest = str(evidence["content_digest"])
        key = f"verification:{acknowledgement.id}:{digest}"
        existing = self.session.scalar(
            select(BusinessEvent).where(BusinessEvent.idempotency_key == key)
        )
        if existing is not None:
            if all(event.id != existing.id for event in events):
                events.append(existing)
            return

        occurred_at = self.now()
        if normalize_utc(occurred_at) < normalize_utc(
            fenced.observation.observed_at
        ):
            raise RecoveryGateError(
                "verified timeline fact cannot precede its authoritative observation"
            )
        payload = redact(
            {
                "amount": record.get("amount"),
                "currency": record.get("currency"),
                "observation_content_digest": digest,
                "reservation_id": fenced.reservation_id,
            }
        )
        canonical = {
            "idempotency_key": key,
            "correlation_id": acknowledgement.correlation_id,
            "entity_type": acknowledgement.entity_type,
            "entity_id": acknowledgement.entity_id,
            "event_type": "invoice.verified",
            "occurred_at": as_json(occurred_at),
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
            occurred_at=occurred_at,
            source_system="flowproof",
            payload=payload,
            content_hash=canonical_hash(canonical),
        )
        self.session.add(verified)
        self.session.flush()
        events.append(verified)
