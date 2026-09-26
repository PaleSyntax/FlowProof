"""Atomic correlation and idempotency ingress helpers."""

from __future__ import annotations

import json
import secrets
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from flowproof.models import BusinessEvent, CorrelationBinding
from flowproof.policy import canonical_hash
from flowproof.schemas import BusinessEventIn
from flowproof.service_core import IdempotencyConflict, PayloadRejected, redact


class AtomicIngestBehavior:
    """Make first-ingest subject binding and idempotency races deterministic."""

    def ingest(self, event: BusinessEventIn) -> tuple[BusinessEvent, bool]:
        payload = redact(event.payload)
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > self.max_payload_bytes:
            raise PayloadRejected("redacted payload exceeds the configured size limit")

        canonical = event.model_dump(mode="json")
        canonical["payload"] = payload
        content_hash = canonical_hash(canonical)
        policy = self.ensure_policy()

        self._claim_correlation_binding(
            event.correlation_id,
            event.entity_type,
            event.entity_id,
        )
        existing = self.session.scalar(
            select(BusinessEvent).where(
                BusinessEvent.idempotency_key == event.idempotency_key
            )
        )
        if existing is not None:
            return self._idempotency_result(existing, content_hash)

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
        try:
            with self.session.begin_nested():
                self.session.add(row)
                self.session.flush()
        except IntegrityError as exc:
            self.session.expire_all()
            winner = self.session.scalar(
                select(BusinessEvent).where(
                    BusinessEvent.idempotency_key == event.idempotency_key
                )
            )
            if winner is None:
                raise IdempotencyConflict(
                    "concurrent idempotency race requires a deterministic retry"
                ) from exc
            return self._idempotency_result(winner, content_hash)

        self._schedule_deadline_jobs(policy, row)
        self.session.commit()
        return row, False

    def _claim_correlation_binding(
        self,
        correlation_id: str,
        entity_type: str,
        entity_id: str,
    ) -> CorrelationBinding:
        expected = (entity_type, entity_id)
        existing = self.session.get(CorrelationBinding, correlation_id)
        if existing is not None:
            if (existing.entity_type, existing.entity_id) != expected:
                raise PayloadRejected(
                    "correlation_id is already bound to a different entity"
                )
            return existing

        candidate = CorrelationBinding(
            correlation_id=correlation_id,
            entity_type=entity_type,
            entity_id=entity_id,
            created_at=self.now(),
        )
        try:
            with self.session.begin_nested():
                self.session.add(candidate)
                self.session.flush()
            return candidate
        except IntegrityError as exc:
            self.session.expire_all()
            winner = self.session.get(CorrelationBinding, correlation_id)
            if winner is None:
                raise IdempotencyConflict(
                    "concurrent correlation binding requires a deterministic retry"
                ) from exc
            if (winner.entity_type, winner.entity_id) != expected:
                raise PayloadRejected(
                    "correlation_id is already bound to a different entity"
                ) from exc
            return winner

    @staticmethod
    def _idempotency_result(
        existing: BusinessEvent,
        content_hash: str,
    ) -> tuple[BusinessEvent, bool]:
        if not secrets.compare_digest(existing.content_hash, content_hash):
            raise IdempotencyConflict(
                "idempotency key is already bound to different content"
            )
        return existing, True
