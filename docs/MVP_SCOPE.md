# MVP scope

## Demonstration domain

Invoice registration.

This is a **demo domain**, not the final product boundary.

## Required happy path

1. Invoice is received.
2. Invoice data is validated.
3. Invoice is approved.
4. Registration is requested.
5. Accounting API persists exactly one invoice.
6. External verification finds it.
7. Amount matches.
8. Process is complete.

## Required failure path

`false_200`:

1. Registration request reaches Mock Accounting API.
2. API returns `200 OK`.
3. API does not persist the invoice.
4. n8n workflow can still finish successfully.
5. FlowProof verifier cannot find the invoice.
6. `external_assertion` fails.
7. Incident opens.
8. Recovery plan proposes only `register_missing_invoice`.
9. User approves.
10. Recovery executes with idempotency key.
11. Verification succeeds.
12. Incident resolves.

## MUST

- local Docker Compose;
- API collector;
- PostgreSQL persistence;
- policy loader;
- invariant engine;
- external verifier;
- incidents;
- timeline;
- recovery approval;
- mock accounting;
- n8n JSON exports;
- minimal frontend;
- tests;
- documentation.

## SHOULD

- blast radius;
- chaos history;
- deterministic resilience score;
- optional AI analyst interface;
- demo video script.

## WON'T in MVP

- production accounting integrations;
- multi-tenant auth;
- payments;
- automatic destructive recovery;
- full process mining;
- generic workflow editor;
- enterprise RBAC;
- Kubernetes;
- commercial SaaS billing.
