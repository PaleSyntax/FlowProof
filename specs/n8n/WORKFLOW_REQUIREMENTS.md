# n8n workflow requirements

## Target version

Baseline import target:

`n8n 2.30.5`

If Codex validates against a newer stable version, record the exact version and retain 2.30.5 compatibility where practical.

## Required files

- `workflows/invoice-intake.json`
- `workflows/invoice-approval.json`
- `workflows/invoice-recovery.json`
- `workflows/flowproof-error-handler.json`
- optional `workflows/chaos-demo-runner.json`

## General requirements

Every workflow:

- has a clear English name;
- has unique node names;
- uses deterministic positions;
- contains no real credentials;
- contains no personal pinned data;
- preserves `correlation_id`;
- sets explicit `idempotency_key`;
- uses bounded timeout;
- retries only idempotent operations;
- sends only allowlisted event payload;
- has notes/sticky notes for setup;
- references environment/config placeholders;
- is inactive in committed export unless activation is explicitly safe.

## FlowProof event call

Use HTTP Request:

- POST `${FLOWPROOF_BASE_URL}/api/v1/events`
- header auth credential placeholder;
- body matches schema;
- timeout;
- `continueOnFail` must not silently hide required event loss.

If event emission fails, route to error handling or stop explicitly depending on stage.

## Credentials

Committed JSON may reference credential type/name placeholder, but never an actual private instance ID.

Document manual credential mapping.

## Validation script

Codex creates a script that verifies:

- JSON parse;
- top-level name/nodes/connections/settings;
- node name uniqueness;
- every connection source/target exists;
- no secret-like string;
- no real credential ID;
- no pinned data;
- no absolute user path;
- expected event types present.

If local n8n is usable, additionally run import smoke.
