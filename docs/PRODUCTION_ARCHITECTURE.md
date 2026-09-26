# Production deployment architecture

## Target

One Linux host or company VM runs a pinned-image Docker Compose project. Caddy is the only
public listener. PostgreSQL, API, scheduler and n8n do not publish host ports.

```text
Internet
  |  HTTPS :443 / HTTP redirect :80
  v
Caddy (edge network)
  |-- /api, /docs, /health  -> FlowProof API (application network)
  |-- /n8n                  -> n8n (application network)
  `-- /                     -> dashboard (application network)

FlowProof API + scheduler + alert-worker --- private PostgreSQL volume
                         `--- configured external verifier/provider endpoint
```

## Service boundaries

| Service | Exposure | Persistent state | Notes |
| --- | --- | --- | --- |
| `caddy` | `80`, `443` only | Caddy certificate/config volumes | Redirects HTTP to HTTPS; production certificate issuance needs a real DNS name. |
| `web` | private | none | Static dashboard; proxy is its only ingress. |
| `api` | private | none | Runs read-only where possible; waits for one-shot migration. |
| `scheduler` | private | none | Separate lease-based evaluator, never performs approval. |
| `alert-worker` | private | none | Claims the durable alert outbox and records a heartbeat; generic webhook delivery is retried with bounded backoff. |
| `migrate` | private, one-shot | none | Takes PostgreSQL advisory lock before `alembic upgrade head`. |
| `postgres` | private | `postgres-data` | No `ports` declaration; password is mounted as a Compose secret. |
| `n8n` | private | `n8n-data` | Optional workflow runtime; encryption key is a mounted secret. Public access is only via webhook routes; editor/API requires a private/VPN source range. |

The local Mock Accounting service is deliberately absent from the production Compose file. It is
introduced only by the isolated smoke overlay to test the existing `false_200` scenario. A
production operator must configure an approved verifier endpoint; that future adapter remains
the `v0.5.0` work item.

## Image strategy

Production Compose accepts image references through required variables such as
`FLOWPROOF_API_IMAGE=ghcr.io/OWNER/flowproof-api:<commit-sha>`. It never builds source on
the host. Images are published by the separate GHCR workflow with OCI source/revision/version
labels. A semantic tag is allowed only after an actual release; it is not created by this
increment. The smoke overlay uses local SHA-like tags solely as proof and does not publish them.

## Security controls

- fixed infrastructure image versions; no `latest` tags;
- private application network and non-public PostgreSQL;
- `no-new-privileges`, dropped Linux capabilities and read-only filesystems/tmpfs where a service
  permits them;
- non-root API, scheduler, dashboard and mock-test containers; stateful services retain only
  their explicit writable volumes;
- JSON application logging omits headers, cookies, tokens and payload bodies;
- n8n workflow nodes cannot read process environment; the least-privilege FlowProof Bearer credential is stored encrypted in n8n after owner-only provisioning;
- production preflight rejects development settings, missing secret files and insecure session
  configuration.

## Availability boundary

This is a single-host deployment, not HA. Docker restart policies recover a crashed process;
they do not replace alerting, backup/restore drills, a capacity plan or operator response.
