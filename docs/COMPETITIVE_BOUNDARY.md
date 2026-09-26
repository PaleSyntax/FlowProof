# Competitive boundary

## Important honesty rule

Do not claim “nobody has ever built this.”

The defensible claim is:

> In the reviewed n8n ecosystem, monitoring, tracing, dashboards, linting, AI-assisted workflow creation, retries, and backups are already well represented. FlowProof intentionally focuses on a different layer: cross-workflow business invariants, independent outcome verification, blast radius, chaos scenarios, and human-approved compensation.

## Existing categories

### n8n built-in capabilities

- execution history;
- retry failed execution;
- error workflows;
- security audit;
- source control environments on eligible plans.

### Technical observability

Examples:

- official `n8n-io/n8n-observability`;
- `Mohammedaljer/n8nTrace`;
- `flancast90/n8sight`;
- `parseablehq/n8n-observability`;
- `langwatch/n8n-observability`;
- `FlowMetr/FlowMetr`.

They focus on:

- success/failure;
- latency;
- node timing;
- metrics/traces/logs;
- instance health;
- errors and retries.

### n8n control planes

Example:

- `Mfrostbutter/ageniusdesk-ce`

It includes multi-instance views, errors, OpenTelemetry, silent-failure detection, AI assistance, backups, container management, and more.

FlowProof must not compete by copying these surfaces.

### Static analysis and AI building

Examples:

- `Redsf/n8n-workflow-linter`;
- `czlonkowski/n8n-mcp`;
- agentic n8n development frameworks.

They focus on workflow JSON correctness, leaked secrets, validation, node knowledge, CI, and workflow generation.

## FlowProof boundary

FlowProof owns:

- business event ingestion;
- entity timelines;
- business policy evaluation;
- independent external assertions;
- cross-workflow completeness;
- incident evidence;
- blast radius;
- safe recovery plan;
- post-recovery verification;
- chaos scenarios aimed at business correctness.

FlowProof delegates:

- infrastructure metrics → Prometheus/Grafana;
- traces → OpenTelemetry;
- workflow editing → n8n;
- workflow backup → Git/n8n tooling;
- secret storage → n8n/secret manager;
- technical alert transport → existing notification systems.

## Differentiation test

A feature belongs in FlowProof only if it helps answer:

1. Did the business outcome occur?
2. Is the resulting state valid?
3. Which entities are affected?
4. Is a retry safe?
5. What is the smallest compensation?
6. Has recovery actually fixed the outcome?
