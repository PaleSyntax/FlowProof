# Specifications

These files are committed contracts for implementation.

## Contract ownership

- `openapi.yaml` owns routes, HTTP methods, authentication requirements,
  documented status codes, and operation IDs.
- Committed JSON Schemas own the detailed recovery payload shapes.
- TypeScript recovery types must mirror the committed JSON Schemas.

OpenAPI response objects may remain deliberately broad where the detailed
recovery payload is already owned by a committed JSON Schema. This ownership
split does not authorize a parallel response-model hierarchy.

Codex must:

- validate them;
- copy runtime policy files into the appropriate application directory;
- keep schemas aligned with real API/domain models;
- update version numbers when contracts change;
- add tests proving the runtime accepts/rejects the same data as the schemas.

Directories:

- `events/` — JSON schemas;
- `policies/` — policy schema and invoice policy;
- `chaos/` — deterministic fault scenarios;
- `fixtures/` — demo input;
- `n8n/` — workflow requirements;
- `openapi.yaml` — API seed.
