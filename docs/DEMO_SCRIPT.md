# Demo script

## Repeatable Compose demo

1. Start the stack: `docker compose up --build --detach`.
2. Confirm `http://localhost:8000/health` and `http://localhost:8001/health` return `{"status":"ok"}`.
3. Run `docker compose --profile demo run --build --rm demo`.
4. Observe the printed `upstream_transport_status: "200 false_200"`.
5. Observe the printed `incident_id`, `recovery_plan_id`, `final_recovery_status: "verified"`, and `final_incident_status: "resolved"`.
6. Open `http://localhost:5173` and refresh to inspect the resolved incident, timeline, evidence, and chaos history.

The script uses a unique correlation/invoice ID rather than deleting FlowProof evidence. It clears only Mock Accounting's explicitly non-production in-memory state, selects `false_200`, sends the same safe event sequence that the n8n workflow would emit, waits for the durable scheduler to complete the external-assertion job, creates a distinct temporary human operator, approves with its session plus CSRF, restores `normal`, executes compensation, and verifies exactly one invoice.

## Repeatable scheduler restart proof

Run the committed isolated proof:

```powershell
.\scripts\run_scheduler_restart_smoke.ps1
```

It proves `scheduler` crash supervision, an operator-controlled `docker compose stop scheduler`, a persisted overdue job processed after restart, and a second restart without duplicate incident/recovery effects. For PostgreSQL contention it stops the Compose scheduler and verifies it is stopped, runs exactly two worker IDs that must report claims `[0, 1]`, then starts and verifies the scheduler before the final stable restart check. It creates no `.env`, does not use `--volumes`, `prune`, or reset commands, and retains only the isolated volumes as audit evidence.

## Repeatable n8n webhook smoke

The committed workflow JSON uses `Authorization: Bearer {{$env.FLOWPROOF_N8N_TOKEN}}` for every FlowProof API request. The isolated runner creates a temporary service account with the fixed envelope `events:write`, `recovery:execute`, and `recovery:verify`, then injects its one-time token only into the n8n process environment. There are no committed Header Auth credentials, credential IDs, or raw tokens. `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` is limited to this trusted local-demo container so those expressions can read the value.

Run a clean import and the complete path:

```powershell
.\scripts\run_n8n_webhook_smoke.ps1
```

The runner creates a unique Compose project, starts n8n **2.30.5**, waits for its HTTP readiness, imports all four exports, publishes the intake/approval/recovery workflows, selects Mock Accounting `false_200`, and drives the following live path. It removes its containers and network only; isolated volumes remain for local audit.

1. POST an invoice to n8n `invoice-intake` (no `approved` field is accepted).
2. POST an approval decision to n8n `invoice-approve`; it emits `invoice.approved` and registration events.
3. Wait for the external-assertion deadline and confirm the scheduler completes its durable job and FlowProof opens `missing_external_invoice`.
4. Prove that the service account is denied approval, then approve through a human operator session with a current CSRF value, restore Mock Accounting, and POST the immutable plan to n8n `flowproof-recovery`.
5. Confirm a successful n8n execution, verified recovery, resolved incident, and exactly one Mock Accounting invoice.
