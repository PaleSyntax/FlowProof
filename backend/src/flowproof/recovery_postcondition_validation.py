"""Pure postcondition identity, dependency and causal-time checks."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select

from flowproof.accounting import InvoiceObservation
from flowproof.models import (
    BusinessEvent,
    Policy,
    PolicyEvaluation,
    RecoveryPlan,
    RecoveryTransportInvocation,
)
from flowproof.service_core import normalize_utc


class PostconditionValidationBehavior:
    """Validate exact entity, amount, currency, dependencies and timestamps."""

    @staticmethod
    def _verified_event_matches_plan(
        event: BusinessEvent,
        plan: RecoveryPlan,
        observation: InvoiceObservation,
        reservation: RecoveryTransportInvocation,
    ) -> bool:
        if event.entity_id != str(plan.parameters.get("invoice_id")):
            return False
        if str(event.payload.get("currency")) != str(
            plan.parameters.get("currency")
        ):
            return False
        if event.payload.get("observation_content_digest") != (
            observation.to_evidence()["content_digest"]
        ):
            return False
        if event.payload.get("reservation_id") != reservation.id:
            return False
        try:
            return Decimal(str(event.payload.get("amount"))) == Decimal(
                str(plan.parameters.get("amount"))
            )
        except (InvalidOperation, TypeError, ValueError):
            return False

    def _dependent_invariants_passed(
        self,
        policy: Policy,
        correlation_id: str,
    ) -> bool:
        invariants = policy.definition.get("invariants", [])
        dependent_ids = {
            str(invariant["id"])
            for invariant in invariants
            if isinstance(invariant, dict)
            and self._invariant_references_verified_event(invariant)
        }
        if not dependent_ids:
            return True
        rows = self.session.scalars(
            select(PolicyEvaluation)
            .where(
                PolicyEvaluation.policy_id == policy.id,
                PolicyEvaluation.correlation_id == correlation_id,
                PolicyEvaluation.invariant_id.in_(dependent_ids),
            )
            .order_by(
                PolicyEvaluation.evaluated_at,
                PolicyEvaluation.id,
            )
        ).all()
        latest = {row.invariant_id: row for row in rows}
        return set(latest) == dependent_ids and all(
            row.state == "passed" for row in latest.values()
        )

    @staticmethod
    def _invariant_references_verified_event(
        invariant: dict[str, Any],
    ) -> bool:
        references = [
            invariant.get("event"),
            invariant.get("before"),
            invariant.get("after"),
            invariant.get("expect"),
        ]
        for side in ("left", "right"):
            value = invariant.get(side)
            if isinstance(value, dict):
                references.append(value.get("event"))
        return any(
            value == "invoice.verified"
            for value in references
            if isinstance(value, str)
        )

    @staticmethod
    def _evaluation_matches_plan(
        evaluation: PolicyEvaluation,
        plan: RecoveryPlan,
    ) -> bool:
        if not isinstance(evaluation.evidence, dict):
            return False
        checks = evaluation.evidence.get("field_checks")
        if not isinstance(checks, dict):
            return False
        expected = {
            "invoice_id": str(plan.parameters.get("invoice_id")),
            "amount": plan.parameters.get("amount"),
            "currency": plan.parameters.get("currency"),
        }
        for field, expected_value in expected.items():
            check = checks.get(field)
            if not isinstance(check, dict):
                return False
            if field == "amount":
                try:
                    matches = Decimal(str(check.get("expected"))) == Decimal(
                        str(expected_value)
                    ) and Decimal(str(check.get("actual"))) == Decimal(
                        str(expected_value)
                    )
                except (InvalidOperation, TypeError, ValueError):
                    return False
                if not matches:
                    return False
            elif (
                str(check.get("expected")) != str(expected_value)
                or str(check.get("actual")) != str(expected_value)
            ):
                return False
        return True

    @classmethod
    def _postcondition_times_are_causal(
        cls,
        plan: RecoveryPlan,
        reservation: RecoveryTransportInvocation,
        observation: InvoiceObservation,
        evaluation: PolicyEvaluation,
        verified_event: BusinessEvent,
        checked_at: Any,
    ) -> bool:
        dispatch_boundary = (
            reservation.dispatch_started_at or reservation.reserved_at
        )
        if plan.executed_at is None or dispatch_boundary is None:
            return False
        boundary = normalize_utc(dispatch_boundary)
        executed_at = normalize_utc(plan.executed_at)
        observed_at = normalize_utc(observation.observed_at)
        if not boundary <= executed_at <= observed_at:
            return False

        write_outcome = (
            reservation.safe_outcome.get("provider_write_outcome")
            if isinstance(reservation.safe_outcome, dict)
            else None
        )
        if isinstance(write_outcome, dict):
            write_time = cls._parse_evidence_time(
                write_outcome.get("observed_at")
            )
            if write_time is None or not boundary <= write_time <= observed_at:
                return False
        if reservation.outcome_classification not in {None, "ACCEPTED"}:
            if executed_at != boundary:
                return False

        return (
            observed_at
            <= normalize_utc(verified_event.occurred_at)
            <= normalize_utc(evaluation.evaluated_at)
            <= normalize_utc(checked_at)
        )

    @staticmethod
    def _parse_evidence_time(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return normalize_utc(parsed)
