"""Orchestrate final recovery convergence from one fenced observation."""

from __future__ import annotations

from sqlalchemy import select

from flowproof.accounting import ObservationState, client_contract
from flowproof.fenced_observation import (
    provider_contract_from_snapshot,
    typed_observation_from_evidence,
)
from flowproof.models import (
    BusinessEvent,
    Incident,
    Policy,
    PolicyEvaluation,
    RecoveryAttempt,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_postcondition_evaluation import (
    _FencedObservationContext,
)
from flowproof.service_core import RecoveryGateError, as_json


class PostconditionVerificationBehavior:
    """Resolve only after persisted exact policy and timeline provenance."""

    def verify_recovery(self, plan_id: str) -> RecoveryPlan:
        plan = self._locked_plan(plan_id)
        if plan.status not in {"verifying", "still_failed"}:
            raise RecoveryGateError(
                "recovery must reach verifying before postcondition evaluation"
            )
        if plan.executed_at is None:
            raise RecoveryGateError(
                "postcondition evaluation requires a durable causal boundary"
            )
        incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == plan.incident_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.recovery_plan_id == plan.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if incident is None or attempt is None:
            raise RecoveryGateError("durable recovery subject is missing")
        if incident.status == "resolved":
            raise RecoveryGateError(
                "incident was resolved before canonical postcondition provenance"
            )
        active_id = attempt.active_transport_invocation_id
        reservation = (
            self.session.scalar(
                select(RecoveryTransportInvocation)
                .where(RecoveryTransportInvocation.id == active_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if isinstance(active_id, str)
            else None
        )
        if reservation is None:
            raise RecoveryGateError(
                "authoritative EFFECT_PRESENT reconciliation is required before verification"
            )
        if reservation.state != "EFFECT_PRESENT":
            if (
                reservation.state != "ACCEPTED"
                or attempt.state != "VERIFYING"
                or attempt.active_transport_invocation_id != reservation.id
            ):
                raise RecoveryGateError(
                    "authoritative EFFECT_PRESENT reconciliation is required "
                    "before verification"
                )
            submitted_hash = plan.plan_hash
            self.session.rollback()
            reconciled = self.reconcile(
                plan_id,
                submitted_hash=submitted_hash,
            )
            if reconciled.status != "verifying":
                return reconciled
            return self.verify_recovery(plan_id)
        if not isinstance(reservation.safe_outcome, dict):
            raise RecoveryGateError(
                "terminal reservation lacks a typed authoritative outcome"
            )
        raw_observation = reservation.safe_outcome.get(
            "authoritative_reconciliation"
        )
        try:
            contract = provider_contract_from_snapshot(
                plan.provider_contract_snapshot
            )
            current_contract = client_contract(self.accounting)
            if (
                contract.digest != plan.provider_contract_digest
                or current_contract.digest != plan.provider_contract_digest
            ):
                raise ValueError("provider contract binding changed")
            observation = typed_observation_from_evidence(
                raw_observation,
                contract=contract,
                expected_entity_reference=str(plan.parameters["invoice_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RecoveryGateError(
                "terminal reservation authoritative observation is invalid"
            ) from exc
        if observation.state != ObservationState.AVAILABLE_PRESENT:
            raise RecoveryGateError(
                "terminal reservation does not prove an exact present postcondition"
            )

        policy = self.session.scalar(
            select(Policy).where(
                Policy.name == incident.policy_name,
                Policy.version == incident.policy_version,
            )
        )
        if policy is None:
            raise RecoveryGateError("incident policy snapshot is missing")

        context = _FencedObservationContext(
            entity_reference=incident.entity_id,
            observation=observation,
            reservation_id=reservation.id,
        )
        if self._fenced_observation_context is not None:
            raise RecoveryGateError("another fenced observation is already active")
        self._fenced_observation_context = context
        try:
            self.evaluate(incident.correlation_id, policy.id)
        finally:
            self._fenced_observation_context = None
        if context.consumed != 1:
            raise RecoveryGateError(
                "canonical invariant evaluation did not consume exactly one fenced observation"
            )

        plan = self.session.scalar(
            select(RecoveryPlan)
            .where(RecoveryPlan.id == plan.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        incident = self.session.scalar(
            select(Incident)
            .where(Incident.id == incident.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        attempt = self.session.scalar(
            select(RecoveryAttempt)
            .where(RecoveryAttempt.id == attempt.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        reservation = self.session.scalar(
            select(RecoveryTransportInvocation)
            .where(RecoveryTransportInvocation.id == reservation.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if any(value is None for value in (plan, incident, attempt, reservation)):
            raise RecoveryGateError(
                "postcondition subject disappeared after canonical evaluation"
            )
        assert plan is not None
        assert incident is not None
        assert attempt is not None
        assert reservation is not None

        evaluation = self.session.scalar(
            select(PolicyEvaluation)
            .where(
                PolicyEvaluation.policy_id == policy.id,
                PolicyEvaluation.correlation_id == incident.correlation_id,
                PolicyEvaluation.invariant_id == incident.invariant_id,
            )
            .order_by(
                PolicyEvaluation.evaluated_at.desc(),
                PolicyEvaluation.id.desc(),
            )
        )
        verified_event = self.session.scalar(
            select(BusinessEvent)
            .where(
                BusinessEvent.correlation_id == incident.correlation_id,
                BusinessEvent.entity_type == incident.entity_type,
                BusinessEvent.entity_id == incident.entity_id,
                BusinessEvent.event_type == "invoice.verified",
            )
            .order_by(
                BusinessEvent.occurred_at.desc(),
                BusinessEvent.id.desc(),
            )
        )
        evaluation_observation = (
            evaluation.evidence.get("observation")
            if evaluation is not None
            and isinstance(evaluation.evidence, dict)
            else None
        )
        checked_at = self.now()
        dependent_pass = self._dependent_invariants_passed(
            policy,
            incident.correlation_id,
        )
        exact_pass = (
            evaluation is not None
            and evaluation.state == "passed"
            and isinstance(evaluation_observation, dict)
            and evaluation_observation.get("content_digest")
            == observation.to_evidence()["content_digest"]
            and self._evaluation_matches_plan(evaluation, plan)
            and verified_event is not None
            and self._verified_event_matches_plan(
                verified_event,
                plan,
                observation,
                reservation,
            )
            and dependent_pass
            and plan.status in {"verifying", "still_failed"}
            and incident.status in {"verifying", "still_failed"}
            and attempt.state == "VERIFYING"
            and attempt.active_transport_invocation_id == reservation.id
            and reservation.state == "EFFECT_PRESENT"
            and self._postcondition_times_are_causal(
                plan,
                reservation,
                observation,
                evaluation,
                verified_event,
                checked_at,
            )
        )

        postcondition = {
            "status": "resolved" if exact_pass else "still_failed",
            "checked_at": as_json(checked_at),
            "incident_id": incident.id,
            "reservation_id": reservation.id,
            "policy_evaluation_id": evaluation.id if evaluation else None,
            "observation_content_digest": observation.to_evidence()[
                "content_digest"
            ],
            "causal_dispatch_boundary": as_json(plan.executed_at),
            "evidence": evaluation.evidence if evaluation else {},
        }
        plan.result = {**plan.result, "postcondition": postcondition}
        if exact_pass:
            attempt.state = "VERIFIED"
            attempt.updated_at = checked_at
            plan.status = "verified"
            plan.verified_at = checked_at
            incident.status = "resolved"
            incident.resolved_at = checked_at
            incident.summary = "external assertion is satisfied"
            incident.evidence = evaluation.evidence
        else:
            attention = evaluation is None or evaluation.state in {
                "error",
                "inconclusive",
            }
            attempt.state = "NEEDS_ATTENTION" if attention else "STILL_FAILED"
            attempt.updated_at = checked_at
            plan.status = "needs_attention" if attention else "still_failed"
            incident.status = "needs_attention" if attention else "still_failed"
            incident.resolved_at = None
        self.session.commit()
        return plan
