# Importable n8n workflows

This directory contains the committed, importable n8n 2.31.0 workflow exports:

- `invoice-intake.json`
- `invoice-approval.json`
- `invoice-recovery.json`
- `flowproof-error-handler.json`

Every webhook has a stable `webhookId`, so a fresh import preserves the expected public local webhook paths. Intake and approval store invoice context in their named normalization nodes and reference those nodes explicitly after HTTP Request nodes.

FlowProof HTTP Request nodes use static internal API URLs and the fixed n8n `httpHeaderAuth` credential reference `flowproof-api-service-account`. The raw service token is never committed or injected into the n8n process environment: the owner-only secret is imported by `deploy/scripts/provision-n8n.sh` into n8n's encrypted credential store. Its account has only `events:write`, `recovery:execute`, and `recovery:verify`; it cannot approve recovery. The exports must not contain `$env` expressions, tokens, or secret values. Run `scripts/run_n8n_webhook_smoke.ps1` for the development path or `scripts/production_deployment_smoke.py` for the isolated production-like path.

Do not commit real credentials, personal webhook IDs, pinned customer data, or absolute paths.
