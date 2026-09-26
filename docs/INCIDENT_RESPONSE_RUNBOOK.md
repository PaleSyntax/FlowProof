# Incident response runbook

## First response

1. Capture the alert, UTC time, request/correlation IDs, service/image versions and current
   readiness state. Do not copy headers, cookies, raw events or secret values into tickets.
2. Classify the signal: scheduler stopped, terminal deadline failure, database unavailable,
   migration mismatch, backup/restore failure, verifier unavailable, stale open incident,
   recovery failure or storage warning.
3. Check `/health/live`, `/health/ready`, structured logs and bounded-cardinality metrics.
4. Preserve the PostgreSQL volume and deployment state. Do not delete evidence or retry a
   recovery side effect blindly.

## Decision rules

- **Database/readiness failure:** stop rollout progression; verify migration version and database
  reachability before restarting application services.
- **Verifier unavailable:** record an inconclusive verifier failure. Do not convert transport
  failure into a business violation or approve recovery automatically.
- **Terminal deadline/recovery failure:** inspect the incident evidence and authoritative external
  system. Human approval remains required for any compensating action.
- **Backup or restore-proof failure:** treat the backup as unusable, alert the owner and create a
  fresh protected backup after cause analysis.
- **Migration mismatch:** block API rollout. Do not run automatic downgrade; assess compatible
  application rollback versus an incident-led restore.

## Communication and closure

Record exact image references, migration head, affected correlation IDs, action owner and proof of
recovery. Close only after liveness/readiness, metrics and the relevant business postcondition are
verified. The alert webhook is a notification transport, not an acknowledgement or incident system.
