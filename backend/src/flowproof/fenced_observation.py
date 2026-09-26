"""Strict reconstruction of a typed authoritative provider observation."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from flowproof.accounting import (
    InvoiceObservation,
    ObservationState,
    ProviderContract,
)

OBSERVATION_EVIDENCE_KEYS = frozenset(
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


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("authoritative observation timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("authoritative observation timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("authoritative observation timestamp lacks timezone")
    return parsed


def provider_contract_from_snapshot(value: object) -> ProviderContract:
    """Rebuild and digest-check the immutable provider contract snapshot."""

    if not isinstance(value, dict):
        raise ValueError("provider contract snapshot is invalid")
    expected_digest = value.get("sha256")
    if not isinstance(expected_digest, str):
        raise ValueError("provider contract snapshot lacks its digest")
    body = {key: item for key, item in value.items() if key != "sha256"}
    try:
        contract = ProviderContract(**body)
    except (TypeError, ValueError) as exc:
        raise ValueError("provider contract snapshot content is invalid") from exc
    if contract.digest != expected_digest:
        raise ValueError("provider contract snapshot digest mismatch")
    return contract


def typed_observation_from_evidence(
    value: object,
    *,
    contract: ProviderContract,
    expected_entity_reference: str,
) -> InvoiceObservation:
    """Reject any observation whose type, digest, identity or shape is not exact."""

    if not isinstance(value, dict) or set(value) != OBSERVATION_EVIDENCE_KEYS:
        raise ValueError("authoritative observation evidence schema is invalid")
    content_digest = value.get("content_digest")
    if not isinstance(content_digest, str) or len(content_digest) != 64:
        raise ValueError("authoritative observation content digest is invalid")
    projection = {
        key: item
        for key, item in value.items()
        if key != "content_digest"
    }
    if _digest(projection) != content_digest:
        raise ValueError("authoritative observation content digest mismatch")

    records = value.get("records")
    if not isinstance(records, list) or any(
        not isinstance(record, dict) for record in records
    ):
        raise ValueError("authoritative observation records are invalid")
    try:
        observation = InvoiceObservation(
            state=ObservationState(str(value.get("classification"))),
            provider_id=str(value.get("provider_id")),
            environment=str(value.get("environment")),
            adapter_version=str(value.get("adapter_version")),
            entity_reference=str(value.get("entity_reference")),
            observed_at=_parse_time(value.get("observed_at")),
            records=tuple(dict(record) for record in records),
            operation_reference=(
                str(value["operation_reference"])
                if value.get("operation_reference") is not None
                else None
            ),
            retry_after_seconds=(
                int(value["retry_after_seconds"])
                if value.get("retry_after_seconds") is not None
                else None
            ),
            error_code=(
                str(value["error_code"])
                if value.get("error_code") is not None
                else None
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("authoritative observation type is invalid") from exc

    if (
        observation.provider_id != contract.provider_id
        or observation.environment != contract.environment
        or observation.adapter_version != contract.adapter_version
        or observation.entity_reference != expected_entity_reference
        or observation.to_evidence() != value
    ):
        raise ValueError("authoritative observation identity is not exact")
    return observation
