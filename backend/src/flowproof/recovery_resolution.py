"""Converge external resolution without bypassing postcondition provenance."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select, update

from flowproof.models import (
    BusinessEvent,
    Incident,
    RecoveryAttempt,
    RecoveryDecision,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.recovery_dispatch import ReconciliationRequired
from flowproof.service_core import as_json


class ExternalResolutionBehavior:
    """Resolve zero-write paths and fence active recovery postconditions."""

    def _sync_incident(
        self,
        policy: Any,
        invariant: dict[str, Any],
        entity_event: BusinessEvent,
        result: dict[str, Any],
    ) -> None:
        if result.get("state") != "passed":
            super()._sync_incident(
                policy,
                invariant,
                entity_event,
                result,
            )
            return

        incident = self.session.scalar(
            select(Incident)
            .where(
                Incident.correlation_id == entity_event.correlation_id,
                Incident.policy_version == policy.version,
                Incident.invariant_id == invariant["id"],
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if incident is None:
            return
        incident.summary = result["message"]
        incident.evidence = result["evidence"]

        plan = self.session.scalar(
            select(RecoveryPlan)
            .where(RecoveryPlan.incident_id == incident.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if plan is None:
            incident.status = "resolved"
            incident.resolved_at = self.now()
            return
        if incident.status == "resolved" and plan.status in {
            "verified",
            "superseded",
        }:
            return

        attempt = self._attempt_for_plan(plan.id, lock=True)
        reservation_count = (
            self.session.scalar(
                select(func.count(RecoveryTransportInvocation.id)).where(
                    RecoveryTransportInvocation.recovery_plan_id == plan.id
                )
            )
            or 0
        )
        if (
            reservation_count == 0
            and attempt is None
            and plan.status in {"proposed", "approved"}
        ):
            self._supersede_without_dispatch(
                incident,
                plan,
                invariant_id=str(invariant["id"]),
                observation=result["evidence"],
            )
            return

        if (
            reservation_count == 0
            and attempt is not None
            and attempt.state == "PREPARED"
            and attempt.active_transport_invocation_id is None
        ):
            self._supersede_prepared_attempt(
                incident,
                plan,
                attempt,
                invariant_id=str(invariant["id"]),
                observation=result["evidence"],
            )
            return

        active_reservation = self._active_reservation(attempt)
        classification = (
            "FENCED_EFFECT_PRESENT_REQUIRES_PERSISTED_PASS"
            if (
                attempt is not None
                and active_reservation is not None
                and active_reservation.state == "EFFECT_PRESENT"
                and attempt.state == "VERIFYING"
            )
            else "ACTIVE_RECOVERY_REQUIRES_FENCED_CONVERGENCE"
        )
        incident.evidence = {
            **incident.evidence,
            "pending_external_pass": {
                "classification": classification,
                "invariant_id": str(invariant["id"]),
                "attempt_id": attempt.id if attempt is not None else None,
                "reservation_id": (
                    active_reservation.id
                    if active_reservation is not None
                    else None
                ),
                "reservation_state": (
                    active_reservation.state
                    if active_reservation is not None
                    else None
                ),
                "plan_state": plan.status,
                "observed_at": as_json(self.now()),
            },
        }
        # The canonical verification boundary finalizes the attempt, plan and
        # incident only after the PolicyEvaluation PASS has been committed.

    def _supersede_without_dispatch(
        self,
        incident: Incident,
        plan: RecoveryPlan,
        *,
        invariant_id: str,
        observation: dict[str, Any],
    ) -> None:
        previous_plan_state = plan.status
        previous_incident_state = incident.status
        plan.status = "superseded"
        self._clear_approval(plan)
        resolved_at = self.now()
        plan.result = {
            **plan.result,
            "external_resolution": {
                "classification": (
                    "INVARIANT_PASS_WITHOUT_RECOVERY_EXECUTION"
                ),
                "invariant_id": invariant_id,
                "resolved_at": as_json(resolved_at),
                "attempt_id": None,
                "reservation_id": None,
                "transport_invocation_count": 0,
                "observation": observation,
            },
        }
        incident.status = "resolved"
        incident.resolved_at = resolved_at
        self._append_external_resolution_decision(
            plan,
            incident,
            previous_plan_state=previous_plan_state,
            previous_incident_state=previous_incident_state,
        )

    def _supersede_prepared_attempt(
        self,
        incident: Incident,
        plan: RecoveryPlan,
        attempt: RecoveryAttempt,
        *,
        invariant_id: str,
        observation: dict[str, Any],
    ) -> None:
        now = self.now()
        safe_result = (
            dict(attempt.safe_result)
            if isinstance(attempt.safe_result, dict)
            else {}
        )
        attempt_cas = self.session.execute(
            update(RecoveryAttempt)
            .where(
                RecoveryAttempt.id == attempt.id,
                RecoveryAttempt.state == "PREPARED",
                RecoveryAttempt.active_transport_invocation_id.is_(None),
                RecoveryAttempt.lock_version == attempt.lock_version,
            )
            .values(
                state="SUPERSEDED_EXTERNAL_RESOLUTION",
                retry_permitted=False,
                retry_reason=None,
                safe_result={
                    **safe_result,
                    "external_resolution": {
                        "classification": (
                            "PREPARED_INTENT_SUPERSEDED_BY_INVARIANT_PASS"
                        ),
                        "observation": observation,
                        "resolved_at": as_json(now),
                    },
                },
                updated_at=now,
                reconciled_at=now,
                lock_version=RecoveryAttempt.lock_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if attempt_cas.rowcount != 1:
            self.session.rollback()
            raise ReconciliationRequired(
                "prepared external resolution lost its attempt CAS"
            )

        previous_plan_state = plan.status
        previous_incident_state = incident.status
        plan.status = "superseded"
        self._clear_approval(plan)
        plan.result = {
            **plan.result,
            "external_resolution": {
                "classification": (
                    "INVARIANT_PASS_WITH_PREPARED_INTENT_ONLY"
                ),
                "invariant_id": invariant_id,
                "resolved_at": as_json(now),
                "attempt_id": attempt.id,
                "reservation_id": None,
                "transport_invocation_count": 0,
                "observation": observation,
            },
        }
        incident.status = "resolved"
        incident.resolved_at = now
        self._append_external_resolution_decision(
            plan,
            incident,
            previous_plan_state=previous_plan_state,
            previous_incident_state=previous_incident_state,
        )

    def _append_external_resolution_decision(
        self,
        plan: RecoveryPlan,
        incident: Incident,
        *,
        previous_plan_state: str,
        previous_incident_state: str,
    ) -> None:
        existing = self.session.scalar(
            select(RecoveryDecision.id)
            .where(
                RecoveryDecision.recovery_plan_id == plan.id,
                RecoveryDecision.action == "external_resolution",
            )
            .limit(1)
        )
        if existing is not None:
            return
        self._append_system_decision(
            plan,
            incident,
            action="external_resolution",
            reason_code=(
                "authoritative_invariant_pass_without_provider_write"
            ),
            previous_plan_state=previous_plan_state,
            previous_incident_state=previous_incident_state,
        )
