"""Recovery planning that remains available when external writes are disabled."""

from __future__ import annotations

from sqlalchemy import select

from flowproof.accounting import client_contract
from flowproof.models import BusinessEvent, Incident, RecoveryDecision, RecoveryPlan
from flowproof.policy import canonical_hash
from flowproof.service_core import RecoveryGateError


class RecoveryPlanningBehavior:
    """Separate bounded plan construction from provider-write authorization."""

    def _ensure_missing_invoice_plan(
        self,
        policy: object,
        incident: Incident,
        entity_event: BusinessEvent,
    ) -> None:
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
        if validated is None:
            return

        parameters = {
            "invoice_id": entity_event.entity_id,
            "amount": validated.payload.get("amount"),
            "currency": validated.payload.get("currency"),
        }
        contract = client_contract(self.accounting)
        definition = getattr(policy, "definition", {})
        recovery = definition.get("recovery", {}) if isinstance(definition, dict) else {}
        configured = recovery.get("guardrails", {}) if isinstance(recovery, dict) else {}
        try:
            guardrails = self._guardrail_snapshot(configured, parameters, contract)
        except RecoveryGateError as exc:
            incident.evidence = {
                **incident.evidence,
                "recovery_blocked": str(exc),
            }
            return

        plan_hash = canonical_hash(
            {
                "action_type": "register_missing_invoice",
                "parameters": parameters,
                "guardrails": guardrails,
                "provider_contract_digest": contract.digest,
            }
        )
        if existing is not None:
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
            if existing.status == "approved" and incident.status in {
                "open",
                "recovery_proposed",
                "recovery_approved",
            }:
                incident.status = "recovery_approved"
            elif existing.status == "proposed" and incident.status in {
                "open",
                "recovery_approved",
            }:
                incident.status = "recovery_proposed"
            return

        self.session.add(
            RecoveryPlan(
                id=self._new_id(),
                incident_id=incident.id,
                action_type="register_missing_invoice",
                parameters=parameters,
                idempotency_key=(
                    f"recovery:{incident.id}:register_missing_invoice"
                ),
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
    def _new_id() -> str:
        from uuid import uuid4

        return str(uuid4())
