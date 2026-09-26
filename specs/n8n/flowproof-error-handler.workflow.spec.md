# flowproof-error-handler workflow spec

## Purpose

Capture technical n8n failures as safe telemetry.

## Trigger

Error Trigger.

## Event

`technical.workflow_failed`

Safe payload:

- workflow ID/name;
- execution ID;
- last node;
- normalized error class;
- truncated error message;
- correlation ID if present.

Do not send:

- credential values;
- full node input/output;
- authorization headers;
- raw secret-bearing stack.

## Behavior

- bounded retry posting telemetry;
- local log/alert if FlowProof unavailable;
- must not mask original business failure.
