# Architecture decisions

## ADR-001: Event-centric core

Store immutable business events and derive evaluations/incidents.

Why:

- cross-workflow correlation;
- auditability;
- replay;
- late events;
- evidence.

## ADR-002: Deterministic invariant engine

LLM does not decide pass/fail.

Why:

- reproducibility;
- testability;
- safety;
- explainability.

## ADR-003: Independent verifier

Command acknowledgement is not proof of outcome.

Why:

- false success;
- async processing;
- partial side effects.

## ADR-004: Human-approved compensation

No autonomous external repair in MVP.

Why:

- incomplete state knowledge;
- duplicate side-effect risk;
- responsible AI.

## ADR-005: n8n is an integration engine, not the source of truth

FlowProof does not read n8n internal DB directly.

Why:

- loose coupling;
- public contracts;
- portability.

## ADR-006: Local single-user MVP

Postpone multi-tenancy/RBAC.

Why:

- product value can be tested first.

## ADR-007: Invoice is a demo domain

Avoid hard-coding product identity around accounting.

Why:

- core should later support access, e-commerce, and data freshness.
