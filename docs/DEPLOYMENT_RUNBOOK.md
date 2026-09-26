# FlowProof production-core deployment runbook

`0.4.x` is a deployment foundation, not a production certification. This
runbook owns only the FlowProof core: API, dashboard, scheduler, alert worker,
ops watcher, migrations, PostgreSQL contract, backup/restore, metrics, logs,
identity and recovery state. DNS, TLS ingress, n8n, secret manager, off-host
backup destination and infrastructure monitoring belong to the company
environment. See [edge contract](EDGE_INGRESS_CONTRACT.md) and
[n8n contract](N8N_INTEGRATION_CONTRACT.md).

## Required input

Create an untracked owner-only environment file outside this repository. It
must set immutable `registry/repository@sha256:<64-hex>` values for
`FLOWPROOF_API_IMAGE` and `FLOWPROOF_WEB_IMAGE`, `POSTGRES_DB`,
`POSTGRES_USER`, `FLOWPROOF_CORS_ORIGIN`, `FLOWPROOF_ACCOUNTING_URL`, and paths
for `FLOWPROOF_SECRETS_DIR`, `FLOWPROOF_DEPLOY_STATE_FILE` and
`FLOWPROOF_BACKUP_DIR`. The core Compose publishes API and dashboard only to
`FLOWPROOF_API_BIND` and `FLOWPROOF_WEB_BIND` (both default to `127.0.0.1`).

`FLOWPROOF_SECRETS_DIR` contains owner-only `token_pepper`,
`postgres_password`, and `alert_webhook_url` files. Secret contents never go
in Compose environment variables, command lines, Docker labels or this
repository. `static-preflight.sh` checks files, permissions, protected state /
backup directories, Docker/Compose, image immutability, placeholders and
Compose rendering without requiring a database, backup, prior image or n8n
token.

## Fresh install

Run only against a new project and uninitialized FlowProof database:

```bash
deploy/scripts/install.sh
```

The committed order is static preflight → PostgreSQL → fresh-DB preflight →
advisory-lock migration → core services and health → first-admin bootstrap from
stdin. It never makes an empty-database backup or rollback state. A rerun is
safe only for the exact bootstrap admin; an initialized database fails closed.

For the optional environment-owned n8n integration, provide its separately
managed encryption-key directory and external hostname values, then run:

```bash
deploy/scripts/install.sh --with-n8n
```

After API startup FlowProof creates or validates the fixed `n8n-flowproof`
service principal, issues only `events:write`, `recovery:execute` and
`recovery:verify`, and writes the one-time raw token to an owner-only file.
`recovery:approve` is impossible for that account. `provision-n8n.sh` then
imports this credential and fixed workflow IDs into the environment-owned n8n.

## Upgrade and rollback

Run upgrades only against a healthy initialized database:

```bash
deploy/scripts/upgrade.sh [--with-n8n]
```

The script records resolved prior API/dashboard repository digests and image
IDs, deployment time and Alembic revision; creates and checks a database
backup; migrates under PostgreSQL advisory lock; then starts and health-checks
the candidate. It rejects a fresh database. Local Linux proof is the sole
exception that permits specially created `sha256:` image IDs with
`FLOWPROOF_ALLOW_LOCAL_IMAGE_IDS=true`; production rejects mutable tags.

Rollback is application-only and requires an explicit compatibility decision:

```bash
FLOWPROOF_SCHEMA_COMPATIBLE=true deploy/scripts/rollback.sh
```

It parses a strict state-file allowlist rather than sourcing it, restores both
recorded API/dashboard image IDs, proves the schema is unchanged, and checks
liveness/readiness. It never downgrades schema or restores a database.

## Operations and migration boundary

Watch `/health/live`, `/health/ready`, authenticated private `/metrics`, JSON
logs, alert worker delivery, scheduler heartbeat, and ops-watcher state.
`ops_watcher` deactivates resolved incident/recovery conditions and creates a
new generation on recurrence. Verifier degradation requires an active/recent
failure threshold and remains active until its configured sustained healthy
observation window passes. Terminal deadline failure is intentionally one-shot.

The watcher cannot create an alert before its table migration exists. The
deployment supervisor and CI must therefore reject migration mismatch before
declaring core health; a database outage remains an infrastructure-monitoring
responsibility.

## Secret file ownership

The production containers run without root. Before `static-preflight.sh`, place the
three FlowProof app secret files in `FLOWPROOF_SECRETS_DIR` with mode `0600` and
owner UID `10001`; place `n8n_encryption_key` in `FLOWPROOF_N8N_SECRETS_DIR`
with mode `0600` and owner UID `1000`. The scripts reject a readable-by-group
file or an owner mismatch. The n8n FlowProof bearer-token file remains an
operator-owned `0400`/`0600` host secret because only the provisioning script
reads it.
