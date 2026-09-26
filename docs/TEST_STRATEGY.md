# Test strategy

## Unit tests

### Domain

- event canonical hash;
- redaction;
- invariant evaluation;
- duration parsing;
- JSON path resolution;
- violation fingerprint;
- recovery state machine.

### Edge cases

- identical events;
- different events with same key;
- late event;
- equal timestamps;
- missing path;
- numeric string vs number;
- tolerance boundary;
- verifier timeout;
- verifier 404;
- duplicate external records;
- recovery double execution.

## Repository/API tests

- migrations from empty database;
- event persistence;
- incident uniqueness;
- list filters;
- auth;
- body size;
- CORS;
- safe errors.

## Mock Accounting tests

- normal persists;
- false_200 does not;
- delayed write eventually persists;
- amount mismatch deterministic;
- idempotency prevents duplicate create.

## Contract tests

- JSON schemas;
- OpenAPI parse;
- policy YAML/schema;
- n8n JSON parse;
- node name uniqueness;
- every connection target exists;
- no secret patterns;
- no pinned data.

## Integration tests

### False 200

- configure fault;
- issue command;
- ingest acknowledgement;
- verifier checks absence;
- incident appears.

### Recovery

- approve plan;
- execute;
- verify one record;
- incident resolved.

### Duplicate webhook

- same delivery twice;
- one external invoice;
- no duplicate incident.

## Frontend

Minimum:

- component render;
- incident detail states;
- API error state;
- approval confirmation;
- no secret env values in client config.

## Docker smoke

- build;
- start;
- healthchecks;
- demo script;
- clean stop.

## Truthfulness

A test listed as passing must have been run.

If blocked, mark `not run`, not `passed`.
