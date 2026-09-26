# Operations runbook

## Local start

Expected final command:

```bash
cp .env.example .env
# Replace both CHANGE_ME values in .env with fresh random values before starting.
docker compose up --build
```

Document exact URLs for:

- UI;
- API docs;
- n8n;
- Mock Accounting.

## Initial n8n setup

Because n8n may require owner creation:

1. open local n8n;
2. create local owner;
3. import JSON files;
4. create a service account with the fixed n8n envelope `events:write`, `recovery:execute`, and `recovery:verify`, inject its short-lived token as `FLOWPROOF_N8N_TOKEN`, and use the Compose base URLs; committed JSON reads them through `$env` and contains no Header Auth credential;
5. keep `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` limited to the trusted local demo container;
6. activate the required workflows, or run `scripts/run_n8n_webhook_smoke.ps1` to import, publish, and exercise them.

Keep below ten manual steps.

## Demo reset

Provide script/target that:

- clears Mock Accounting demo records;
- clears FlowProof demo state or uses unique correlation;
- sets chaos mode to normal.

Avoid destructive reset outside development.

## Observability

MVP logs:

- request ID;
- correlation ID;
- event ID;
- invariant ID;
- incident ID;
- verifier latency/status;
- recovery plan ID.

Never log tokens or unrestricted payloads.

## Durable scheduler

`docker compose up --build --detach` starts the API and the separate `scheduler` service. The worker runs `python -m flowproof.scheduler` only after the API migration and Mock Accounting health checks pass. It uses these validated positive environment variables, all with local defaults in `.env.example` and Compose: `FLOWPROOF_SCHEDULER_POLL_SECONDS=1`, `FLOWPROOF_SCHEDULER_LEASE_SECONDS=30`, `FLOWPROOF_SCHEDULER_MAX_ATTEMPTS=5`, and `FLOWPROOF_SCHEDULER_RETRY_BASE_SECONDS=2`.

Only `scheduler` has the local Docker policy `restart: unless-stopped`. A process crash is restarted by Docker; `docker compose stop scheduler` is an explicit operator stop and is not treated as a crash. The scheduler has no published host port. Do not add a restart policy to another service without a separate operational need and proof.

Run the isolated restart, supervision, and PostgreSQL claim-contention proof with one command:

```powershell
.\scripts\run_scheduler_restart_smoke.ps1
```

The runner creates a unique Compose project and process-local random demo values, creates no `.env`, leaves its isolated volumes for audit, and removes only its own containers and network. Its private Compose override creates one scheduler-child crash after Docker's startup window; it then verifies automatic restart and an explicit stopped worker. Before the PostgreSQL claim-contention phase it stops the Compose scheduler and verifies that it is not running, then runs exactly two in-container worker IDs and requires claims `[0, 1]`. It leaves the primary job stopped until it is due, then starts and verifies the Compose scheduler again, requires that persisted due job to be claimed after restart, and completes the final stable restart check. This isolates the two-worker proof from the Compose scheduler without changing scheduler production logic.

Use a dedicated Bearer credential with `read:operations` to inspect, never mutate, job state:

```bash
curl -H "Authorization: Bearer $FLOWPROOF_READ_TOKEN" "http://localhost:8000/api/v1/deadline-jobs?state=retry"
```

`completed` jobs are not re-run. An expired `running` lease is intentionally eligible for another at-least-once evaluation; recovery remains human-approved and is never called by this worker.

The 0.2.0 scheduler automatically schedules trigger events ingested after migration `0002`. Existing historical trigger events are not backfilled automatically.

## Failure handling

### FlowProof unavailable

n8n event emission has bounded retry and must not repeat unrelated business side effects.

### Verifier unavailable

Evaluation becomes inconclusive/error. Do not claim business failure solely because transport failed.

### Database unavailable

Fail ingestion clearly. Do not acknowledge unpersisted event.

### Recovery timeout

Check authoritative state before retrying.

## Backup

MVP:

- PostgreSQL volume;
- workflow JSON in Git;
- policy files in Git.

Document backup command; do not build backup platform.

## Retention

Demo may retain data indefinitely locally. Document future retention; do not silently delete evidence.

## Production foundation (`0.4.x`)

Use the dedicated [deployment runbook](DEPLOYMENT_RUNBOOK.md) rather than this local-MVP procedure for the production Compose target. It defines external environment/secret-file inputs, migration/backup/rollout order and application-only rollback. Run `deploy/scripts/preflight.sh` before `deploy/scripts/deploy.sh`; do not run the local `docker compose up --build` command on a company host.

`/health/live` checks process liveness only. `/health/ready` also checks database reachability, Alembic head and policy configuration. `/metrics` is private and authenticated; use an approved in-network collector. See [incident response](INCIDENT_RESPONSE_RUNBOOK.md) for terminal jobs, backup/restore failure, migration mismatch and verifier-unavailable decisions.
