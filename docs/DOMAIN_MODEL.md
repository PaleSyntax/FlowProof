# Domain model

## BusinessEvent

Immutable fact received by FlowProof.

Fields:

- `id`
- `idempotency_key`
- `correlation_id`
- `entity_type`
- `entity_id`
- `event_type`
- `occurred_at`
- `ingested_at`
- `source_system`
- `workflow_id`
- `workflow_version`
- `execution_id`
- `node_name`
- `payload`
- `content_hash`

## Policy

Versioned set of invariants for one process/entity type.

Fields:

- `id`
- `name`
- `version`
- `entity_type`
- `enabled`
- `definition`
- `definition_hash`
- `created_at`

A changed policy creates a new version.

## Invariant

One deterministic expectation.

Definition fields:

- `id`
- `type`
- `severity`
- parameters;
- optional recovery action;
- optional description.

## PolicyEvaluation

Result of evaluating one invariant against one correlation.

States:

- `pending`
- `passed`
- `violated`
- `inconclusive`
- `error`

`error` means evaluation infrastructure failed; it is not the same as a business violation.

## Incident

States:

- `open`
- `acknowledged`
- `recovery_proposed`
- `recovery_approved`
- `recovery_running`
- `verifying`
- `still_failed`
- `resolved`
- `rejected`
- `needs_attention`

`still_failed` means an independent postcondition reread completed and the business invariant remains violated. It is not a transport failure and it is not resolution.

Identity for MVP:

`correlation_id + policy_version + invariant_id`

Only one open incident per identity.

## Evidence

Machine-readable references:

- event IDs;
- external observation;
- expected condition;
- actual condition;
- timestamps;
- content hashes.

Evidence is structured JSON, not only prose.

## RecoveryPlan

Fields:

- `id`
- `incident_id`
- `action_type`
- `parameters`
- `idempotency_key`
- `risk_level`
- `requires_approval`
- `status`
- `approved_at`
- `executed_at`
- `verified_at`
- `result`

## ChaosRun

Fields:

- `id`
- `scenario_id`
- `correlation_id`
- `status`
- `started_at`
- `finished_at`
- `expected_invariants`
- `observed_incidents`
- `result`

## Aggregate boundary

For MVP, a correlation is the practical aggregate for evaluation.

Do not mutate events. New information is represented by new events, observations, evaluations, and incident transitions.

## Recovery approval context

A durable approval binds the human principal ID/name, exact `recovery:approve` scope, plan hash, incident ID and the incident state observed at approval. The current approvable state is `recovery_proposed`.
