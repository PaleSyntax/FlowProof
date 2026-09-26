# invoice-intake workflow spec

## Purpose

Receive a synthetic invoice request, validate it, emit business events, and request registration from Mock Accounting.

## Trigger

Webhook:

`POST /webhook/invoice-intake`

## Required input

- `delivery_id`
- `correlation_id`
- `invoice.invoice_id`
- `invoice.amount`
- `invoice.currency`
- `invoice.approved`

## Nodes/logic

1. Webhook
2. Normalize input
3. Validate schema
4. Emit `invoice.received`
5. If invalid:
   - emit `invoice.validation_failed`
   - return validation response
6. Emit `invoice.validated`
7. If not approved:
   - stop before registration and return `pending_approval`
8. Emit `invoice.registration_requested`
9. POST to Mock Accounting with idempotency key
10. On accepted HTTP response emit `invoice.registration_acknowledged`
11. Return response

## Important demo behavior

In `false_200`, step 9 returns success while no invoice is stored.

The workflow must not independently detect this. FlowProof external verifier detects it, proving the product boundary.

## Safe retry

- registration POST uses external idempotency key;
- retries allowed only because create is idempotent;
- event ingestion is idempotent.

## Output

- correlation ID;
- invoice ID;
- acknowledged status;
- execution metadata where available.
