# Architecture

## Context

```text
n8n workflows
    |
    | POST business events
    v
FlowProof API
    |
    +--> Event Store (PostgreSQL)
    |
    +--> Invariant Engine
    |       |
    |       +--> External Verifier
    |
    +--> Incident Store
    |
    +--> Recovery Planner
    |
    +--> Read API --> React UI

Deadline Scheduler ----> persisted deadline jobs ----> deterministic evaluation
Alert Worker ----------> durable alert outbox --------> configured webhook
Operations Watcher ----> service/provider health -----> durable operational alerts

Mock Accounting API
    ^
    |
n8n commands / FlowProof verification
```

## Services

### `api`

FastAPI application:

- event ingestion;
- timeline queries;
- policy evaluation;
- incidents;
- blast radius;
- recovery plan lifecycle;
- chaos orchestration facade.

### Evaluation and recovery services

Deterministic evaluation can run explicitly through
`POST /api/v1/correlations/{correlation_id}/evaluate`, through the recovery
verification path, or from the database-backed deadline scheduler. The
scheduler claims persisted deadline jobs with leases and delegates invariant
truth to the same service layer; it cannot approve or execute recovery.

The alert worker claims the durable alert outbox with bounded retry behavior.
The operations watcher records scheduler/provider degradation and recovery in
durable operational-alert state. These remain single-host workers, not a
distributed queue or HA control plane.

### `postgres`

Authoritative local state.

### `web`

React/TypeScript UI.

### `mock-accounting`

Deterministic demo API with selectable fault modes.

### `n8n`

Pinned local instance used to import and run workflow JSON.

## Trust boundaries

### Untrusted inputs

- webhook payloads;
- n8n event payloads;
- external verifier responses;
- policy files before validation;
- LLM output;
- browser requests.

### Trusted decisions

- validated policy engine;
- database constraints;
- explicit operator approval;
- allowlisted recovery executor;
- post-recovery verifier.

## Data flow

### Command

n8n asks an external system to perform an action.

### Acknowledgement

n8n receives a transport/application response.

### Observation

FlowProof independently queries the authoritative system.

### Assertion

Invariant engine compares observation with expected policy.

### Incident

A violation is persisted with evidence.

### Compensation

A narrow action is approved and executed.

### Verification

FlowProof observes the system again and resolves or escalates the incident.

## Dependency direction

```text
HTTP/UI adapters
      |
application services
      |
domain models + invariant engine
      |
repositories / external adapters
```

Domain code must not import FastAPI or React concerns.

## Actual layout

```text
backend/
  src/flowproof/      # HTTP adapter, domain service, persistence models
  migrations/         # additive Alembic history through 0010
  tests/
frontend/
mock-accounting/
deploy/               # production-core lifecycle and evidence scripts
workflows/
policies/
specs/                # OpenAPI, JSON Schemas and provider contracts
security/             # repository-owned supply-chain gates
scripts/
docs/
docker-compose.yml
```

## Scaling note

The current implementation assumes one tenant and one host. Deadline jobs,
alert delivery, recovery attempts, transport reservations and reconciliation
authority are durable, but there is no distributed queue, multi-region
scheduler, tenant isolation or HA credential service.

Possible future work includes event partitioning, retention policy, distributed
worker ownership and provider-specific rate-limit coordination. Do not add it
without a second real use case or design-partner evidence.
