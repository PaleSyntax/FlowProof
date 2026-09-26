# invoice-recovery workflow spec

## Purpose

Execute only an approved, allowlisted compensation.

## Trigger

Webhook:

`POST /webhook/flowproof-recovery`

## Input

- recovery plan ID;
- incident ID;
- action type;
- plan hash;
- idempotency key;
- invoice fields required for compensation.

## Guard conditions

1. Fetch plan from FlowProof.
2. Plan status is `approved`.
3. Action equals `register_missing_invoice`.
4. Plan hash matches.
5. Verifier still reports invoice absent.
6. Use supplied idempotency key.

## Logic

- emit `recovery.execution_started`;
- create invoice;
- emit `recovery.executed`;
- request verification;
- return result.

## Forbidden

- rerun original intake wholesale;
- execute arbitrary URL/action;
- accept mutable amount from browser without plan validation;
- bypass approval.
