# Chaos Lab

## Goal

Prove that an automation detects and safely handles business-level failure modes.

Chaos Lab is not infrastructure chaos engineering. It targets workflow and integration semantics.

## Required scenarios

### `duplicate_webhook`

Send the same request twice with the same delivery ID.

Expected:

- one side effect;
- duplicate event ingestion is idempotent;
- no duplicate invoice;
- no false incident.

### `false_200`

Mock Accounting returns `200 OK` but does not persist.

Expected:

- n8n request path appears successful;
- external assertion fails;
- incident opens.

### `delayed_callback`

Persistence happens after verifier deadline.

Expected:

- incident opens after SLA;
- later observation may resolve or transition;
- history remains visible.

### `amount_mismatch`

Persisted amount differs from validated amount.

Expected:

- value/external assertion violation;
- evidence shows expected and actual.

### `partial_side_effect`

Invoice persists, downstream action fails.

Expected:

- recovery plan must not create invoice again;
- only missing side effect is proposed.

### `malformed_llm_output`

Extraction returns wrong types or missing fields.

Expected:

- deterministic validation blocks downstream side effect;
- `invoice.validation_failed`;
- no registration request.

## Resilience score

Optional deterministic score:

- detection;
- duplicate prevention;
- safe recovery;
- post-recovery verification.

Do not use a black-box LLM score.

## Repeatability

Each scenario specifies:

- setup;
- input;
- expected events;
- expected incidents;
- forbidden side effects;
- cleanup.

A run produces a stored `ChaosRun`.
