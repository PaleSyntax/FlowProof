"""Canonical postcondition behavior composed from one strict policy boundary."""

from flowproof.recovery_postcondition_evaluation import (
    PostconditionEvaluationBehavior,
)
from flowproof.recovery_postcondition_validation import (
    PostconditionValidationBehavior,
)
from flowproof.recovery_postcondition_verification import (
    PostconditionVerificationBehavior,
)


class CanonicalPostconditionBehavior(
    PostconditionEvaluationBehavior,
    PostconditionVerificationBehavior,
    PostconditionValidationBehavior,
):
    """Reuse one fenced observation, persist policy PASS, then converge recovery."""


__all__ = ["CanonicalPostconditionBehavior"]
