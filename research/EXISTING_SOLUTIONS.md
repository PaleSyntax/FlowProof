# Reviewed solution landscape

Prepared as orientation, not exhaustive proof of uniqueness.

## Official n8n

- Main repository: https://github.com/n8n-io/n8n
- Executions/retry: https://docs.n8n.io/workflows/executions/all-executions/
- Security audit: https://docs.n8n.io/hosting/securing/security-audit/
- Source control environments: https://docs.n8n.io/source-control-environments/create-environments/
- Official observability: https://github.com/n8n-io/n8n-observability

## Monitoring / dashboards / control planes

- https://github.com/Mohammedaljer/n8nTrace
- https://github.com/flancast90/n8sight
- https://github.com/Mfrostbutter/ageniusdesk-ce
- https://github.com/FlowMetr/FlowMetr
- https://github.com/parseablehq/n8n-observability
- https://github.com/langwatch/n8n-observability
- https://github.com/janmaaarc/n8n-ops

## Static analysis / workflow development

- https://github.com/Redsf/n8n-workflow-linter
- https://github.com/czlonkowski/n8n-mcp
- https://github.com/TheRealJamesRussell/n8n-workflow-agentic-development-framework

## Interpretation

The ecosystem already has strong solutions for:

- technical status;
- traces;
- node timing;
- metrics/logs;
- retries;
- multi-instance views;
- secrets linting;
- AI-assisted workflow generation;
- backups and source control.

FlowProof should not reproduce them.

The reviewed gap is the integrated combination of:

- business entity correlation;
- deterministic cross-workflow invariants;
- independent authoritative-system verification;
- business blast radius;
- business chaos scenarios;
- minimal human-approved compensation;
- post-recovery proof.

A future deep research pass should search beyond GitHub and validate commercial products.
