# Roadmap after MVP

## Increment 1 — second business domain

Add one non-invoice policy, preferably:

- SaaS access/offboarding;
- data freshness;
- e-commerce fulfillment/refund.

Goal: prove the engine is not invoice-specific.

## Increment 2 — event SDK and n8n community node

- small Python/TypeScript SDK;
- FlowProof Event node;
- signed event option;
- local schema validation.

## Increment 3 — deployment/version correlation

- workflow export hash;
- Git commit;
- compare incident rates before/after change;
- blast radius by version.

## Increment 4 — stronger recovery delivery

- transactional outbox;
- callback verification;
- recovery executor adapters;
- approval audit.

## Increment 5 — deeper uniqueness research

Review commercial:

- process mining;
- workflow assurance;
- integration observability;
- reconciliation;
- automation testing;
- SOAR/compensation tooling.

Do not start SaaS/RBAC before a second domain validates the core.
