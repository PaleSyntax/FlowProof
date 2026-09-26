# invoice-approval workflow spec

## Purpose

Model a separate approval workflow to prove cross-workflow correlation.

## Trigger

Webhook:

`POST /webhook/invoice-approve`

## Input

- `correlation_id`
- `invoice_id`
- `decision`
- `actor`

## Logic

1. Validate decision.
2. If approved:
   - emit `invoice.approved`;
   - call registration sub-flow or return approval for queued registration.
3. If rejected:
   - emit `invoice.rejected`;
   - do not call accounting.

## Requirements

- same correlation ID as intake;
- independent execution ID;
- actor is a safe label;
- duplicate approval is idempotent;
- registration cannot precede approval in normal path.
