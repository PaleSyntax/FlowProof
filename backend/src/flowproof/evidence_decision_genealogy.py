"""Recovery decision and approval genealogy validation for evidence v1.1."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_contract import PROOF_EXTERNAL, EvidenceError
from flowproof.evidence_semantics import SemanticContext


def validate_decisions(
    context: SemanticContext,
    *,
    proof_type: str,
) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    request_digests: set[str] = set()
    previous_time: datetime | None = None
    external_decisions: list[dict[str, Any]] = []

    for decision in context.decisions:
        decision_id = decision.get("id")
        request_digest = decision.get("request_id_digest")
        if (
            not isinstance(decision_id, str)
            or not decision_id
            or decision_id in by_id
            or not isinstance(request_digest, str)
            or not strict.SHA256.fullmatch(request_digest)
            or request_digest in request_digests
        ):
            raise EvidenceError(
                "recovery decision identity is invalid"
            )
        if (
            decision.get("recovery_plan_id")
            != context.plan.get("id")
            or decision.get("incident_id")
            != context.incident.get("id")
            or not strict.SHA256.fullmatch(
                str(decision.get("plan_hash"))
            )
            or not strict.SHA256.fullmatch(
                str(decision.get("provider_contract_digest"))
            )
        ):
            raise EvidenceError(
                "recovery decision binding is invalid"
            )
        decided_at = strict._evidence_time(
            decision.get("decided_at"),
            "decision.decided_at",
        )
        if previous_time is not None and decided_at < previous_time:
            raise EvidenceError(
                "recovery decisions are not chronological"
            )
        previous_time = decided_at

        kind = decision.get("decision_kind")
        actor = decision.get("actor")
        action = decision.get("action")
        scope = decision.get("authorization_scope")
        approval_expires_at = decision.get(
            "approval_expires_at"
        )
        if kind == "human":
            if (
                not strict._human_actor_is_bounded(actor)
                or scope != "recovery:approve"
                or action
                not in {
                    "approve",
                    "reject",
                    "revoke_approval",
                }
            ):
                raise EvidenceError(
                    "human recovery decision provenance is invalid"
                )
            if action == "approve":
                expires_at = strict._evidence_time(
                    approval_expires_at,
                    "decision.approval_expires_at",
                )
                ttl = context.plan.get("guardrails", {}).get(
                    "approval_ttl_seconds"
                )
                if (
                    expires_at <= decided_at
                    or not isinstance(ttl, int)
                    or isinstance(ttl, bool)
                    or (
                        expires_at - decided_at
                    ).total_seconds()
                    != ttl
                ):
                    raise EvidenceError(
                        "approval expiry does not derive from its TTL"
                    )
            elif approval_expires_at is not None:
                raise EvidenceError(
                    "non-approval decision declares approval expiry"
                )
        elif kind == "system":
            if (
                actor != {"system": "flowproof"}
                or scope != "system:approval_lifecycle"
            ):
                raise EvidenceError(
                    "system recovery decision provenance is invalid"
                )
            if action == "external_resolution":
                external_decisions.append(decision)
        else:
            raise EvidenceError(
                "recovery decision kind is invalid"
            )

        by_id[decision_id] = decision
        request_digests.add(request_digest)

    if proof_type == PROOF_EXTERNAL and len(external_decisions) != 1:
        raise EvidenceError(
            "external resolution requires exactly one system decision"
        )
    if proof_type != PROOF_EXTERNAL and external_decisions:
        raise EvidenceError(
            "non-external proof path contains external-resolution authority"
        )
    return by_id
