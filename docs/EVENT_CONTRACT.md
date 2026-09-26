# Business event contract

## Endpoint

`POST /api/v1/events`

Header:

`Authorization: Bearer <scoped-service-token>`

The primary n8n credential must have `events:write`. Deprecated `X-FlowProof-*` aliases are development-only DB-resolved compatibility paths and are rejected in production.

## Example

```json
{
  "idempotency_key": "invoice-142:registration-ack:v1",
  "correlation_id": "order-8841",
  "entity_type": "invoice",
  "entity_id": "INV-2026-00142",
  "event_type": "invoice.registration_acknowledged",
  "occurred_at": "2026-07-30T20:10:00Z",
  "source": {
    "system": "n8n",
    "workflow_id": "invoice-intake",
    "workflow_version": "git:abc1234",
    "execution_id": "551",
    "node_name": "Register invoice"
  },
  "payload": {
    "amount": 18000.0,
    "currency": "RUB",
    "external_request_id": "req-9001"
  }
}
```

## Idempotency

### Same key, same content

Return existing event:

- HTTP 200 or 201 with `duplicate=true`;
- no second row;
- no duplicated incident.

### Same key, different content

Return `409 Conflict`.

## Content hash

Canonicalize stable fields before hashing:

- sorted object keys;
- normalized timestamp;
- exclude `ingested_at`;
- include payload after redaction.

## Payload controls

- maximum serialized size;
- maximum nesting;
- accepted scalar/list/object types;
- deny keys matching:
  - password
  - secret
  - token
  - authorization
  - cookie
  - api_key
  - private_key
- configurable allowlist per event type;
- redact before logging and persistence.

## Event naming

Use past-tense facts:

- `invoice.received`
- `invoice.validated`
- `invoice.approved`
- `invoice.registration_requested`
- `invoice.registration_acknowledged`
- `invoice.registered`
- `recovery.approved`
- `recovery.executed`

Avoid imperative names such as `create_invoice`.

## Time semantics

- `occurred_at`: reported business occurrence;
- `ingested_at`: server receipt time.

Reject timestamps unreasonably far in the future. Preserve late-arriving events.

## Source provenance

`workflow_version` should ideally contain Git commit or a stable exported workflow hash.

FlowProof must not rely on mutable workflow name alone.
