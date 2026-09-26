"""Explicitly local, deterministic first-value fixture orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from flowproof.accounting import (
    ObservationState,
    WriteOutcomeState,
    coerce_observation,
    coerce_write_outcome,
)
from flowproof.schemas import BusinessEventIn, SourceIn
from flowproof.service import FlowProofService


class FixtureDemoError(RuntimeError):
    """A bounded fixture setup failure that must never become product truth."""


@dataclass(frozen=True, slots=True)
class FixtureDemoResult:
    correlation_id: str
    entity_id: str
    incident_id: str
    recovery_plan_id: str
    timeline_event_ids: tuple[str, ...]
    provider_id: str
    provider_environment: str
    adapter_version: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_classification": "TEST_FIXTURE_ONLY",
            "scenario": "invoice_false_200_missing_outcome",
            "correlation_id": self.correlation_id,
            "entity_type": "invoice",
            "entity_id": self.entity_id,
            "incident_id": self.incident_id,
            "recovery_plan_id": self.recovery_plan_id,
            "timeline_event_ids": list(self.timeline_event_ids),
            "execution": {
                "classification": "FIXTURE_TRANSPORT_ACCEPTED",
                "transport_accepted": True,
                "real_n8n_execution_proven": False,
                "source": "flowproof-safe-fixture",
            },
            "outcome": {
                "classification": "INDEPENDENT_READ_MISSING",
                "invariant_id": "external_invoice_exists",
                "state": "FAILED",
                "provider_id": self.provider_id,
                "provider_environment": self.provider_environment,
                "adapter_version": self.adapter_version,
            },
            "next_action": "REVIEW_INCIDENT_AND_HUMAN_APPROVE_NARROW_RECOVERY",
        }


class FixtureDemoService:
    """Create one bounded false-200 case through the real domain services."""

    def __init__(
        self,
        service: FlowProofService,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.service = service
        self.clock = clock or service.now

    def start_false_200(self) -> FixtureDemoResult:
        now = self.clock().astimezone(UTC)
        suffix = uuid4().hex
        correlation_id = f"fixture-demo-{suffix}"
        entity_id = f"INV-DEMO-{suffix[:10].upper()}"
        execution_id = f"fixture-execution-{suffix[:12]}"
        source = SourceIn(
            system="flowproof-safe-fixture",
            workflow_id="invoice-intake-fixture",
            workflow_version="1.0",
            execution_id=execution_id,
        )
        # The authoritative deadline is already due when evaluation starts, so
        # the first-value flow remains fast without changing the policy itself.
        base_time = now - timedelta(seconds=36)
        amount = 18_000.0
        payload = {"amount": amount, "currency": "RUB"}
        event_rows = []

        try:
            self.service.configure_chaos("false_200", correlation_id)
        except Exception as exc:
            raise FixtureDemoError("mock fixture control is unavailable") from exc

        for ordinal, event_type in enumerate(
            (
                "invoice.received",
                "invoice.validated",
                "invoice.approved",
                "invoice.registration_requested",
            )
        ):
            row, _ = self.service.ingest(
                BusinessEventIn(
                    idempotency_key=f"fixture-demo:{suffix}:{event_type}",
                    correlation_id=correlation_id,
                    entity_type="invoice",
                    entity_id=entity_id,
                    event_type=event_type,
                    occurred_at=base_time + timedelta(seconds=ordinal),
                    source=source,
                    payload=payload,
                )
            )
            event_rows.append(row)

        try:
            write_outcome = coerce_write_outcome(
                self.service.accounting,
                {"invoice_id": entity_id, **payload},
                f"fixture-demo:{suffix}:accounting-write",
            )
        except Exception as exc:
            raise FixtureDemoError("fixture transport is unavailable") from exc
        if write_outcome.state is not WriteOutcomeState.ACCEPTED:
            raise FixtureDemoError("fixture transport did not return an accepted result")

        try:
            observation = coerce_observation(self.service.accounting, entity_id)
        except Exception as exc:
            raise FixtureDemoError("fixture authoritative read is unavailable") from exc
        if observation.state is not ObservationState.AVAILABLE_ABSENT:
            raise FixtureDemoError("fixture did not produce the expected missing outcome")

        acknowledged, _ = self.service.ingest(
            BusinessEventIn(
                idempotency_key=f"fixture-demo:{suffix}:invoice.registration_acknowledged",
                correlation_id=correlation_id,
                entity_type="invoice",
                entity_id=entity_id,
                event_type="invoice.registration_acknowledged",
                occurred_at=base_time + timedelta(seconds=4),
                source=source,
                payload=payload,
            )
        )
        event_rows.append(acknowledged)
        self.service.evaluate(correlation_id)
        incident = next(
            (
                item
                for item in self.service.list_incidents()
                if item["correlation_id"] == correlation_id
                and item["invariant_id"] == "external_invoice_exists"
            ),
            None,
        )
        if incident is None or not isinstance(incident.get("recovery_plan"), dict):
            raise FixtureDemoError("fixture evaluation did not create a recovery incident")
        plan = incident["recovery_plan"]
        return FixtureDemoResult(
            correlation_id=correlation_id,
            entity_id=entity_id,
            incident_id=str(incident["id"]),
            recovery_plan_id=str(plan["id"]),
            timeline_event_ids=tuple(row.id for row in event_rows),
            provider_id=observation.provider_id,
            provider_environment=observation.environment,
            adapter_version=observation.adapter_version,
        )
