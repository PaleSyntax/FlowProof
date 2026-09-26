# Threat model

This document describes the implemented local MVP, not a future enterprise design.

## Assets and boundaries

- Opaque `Authorization: Bearer` credentials are HMAC-SHA256 peppered before persistence; only a prefix and hash are stored. Deprecated `X-FlowProof-*` headers are optional DB-resolved aliases, never direct shared-secret comparisons.
- Human passwords use Argon2id; sessions and CSRF values are opaque, HttpOnly/SameSite cookies plus hashed server state. Idle expiry is refreshed only up to an immutable absolute expiry; password change and disable revoke sessions with sanitized per-session audit records.
- Request IDs are bounded ASCII identifiers supplied by the caller or generated server-side; they are recorded with relevant security and operational audit events without request bodies or credentials.
- Events cross an untrusted HTTP boundary; the API limits request/payload size, permits JSON-only payload shapes, redacts secret-like keys before persistence, and rejects excessive nesting.
- The verifier base URL is server configuration (`FLOWPROOF_MOCK_ACCOUNTING_URL`), never a browser-controlled URL.
- Recovery crosses an external side-effect boundary. The only implemented action is `register_missing_invoice`.
- PostgreSQL is internal to Compose. API, UI, and Mock Accounting bind host ports to `127.0.0.1` only.

## Implemented mitigations

| Threat | Mitigation |
| --- | --- |
| Forged events | Scoped service credential, exact CORS origin and schema validation. |
| Stolen or stale credential | Opaque token hash, bounded expiry, atomic rotation/revocation, disabled principals, scope-envelope enforcement, and append-only security audit. |
| Cross-site session write | SameSite HttpOnly session cookie plus required CSRF header for state-changing session requests. |
| Replay / key collision | Unique idempotency key plus canonical content hash; same key/different content is `409`. |
| Secret persistence | Recursive deny-key redaction before logging/persistence; workflow JSON has no concrete credential IDs. |
| Timeline corruption | Events are append-only facts; verifier transport failure becomes evaluation `error`, not a business violation. |
| Duplicate incident | Unique incident identity: correlation + policy version + invariant. |
| Unauthorized repair | A human `operator`/`admin` session plus `recovery:approve`, immutable plan hash, plan-content hash recheck, idempotency key, and external precondition check. Service accounts may execute/verify but cannot approve. |
| False repair success | Post-execution authoritative read is required before incident resolution. |
| SSRF | Mock verifier host is configured server-side; no external URL is accepted from UI/API input. |
| Browser secret leak | UI has no API token/localStorage secret; it restores only an HttpOnly session and keeps the transient CSRF value in memory. |

## Deliberate MVP limitations

There is no tenant isolation, SSO/MFA, mTLS, encryption-at-rest configuration, rate limiting, distributed lock, retention job, production secret manager, or real-accounting credential integration. Do not expose this Compose deployment publicly.

## 0.4.x deployment controls and residual risk

The production target restricts public ingress to Caddy, keeps PostgreSQL/API/scheduler/n8n on private networks, uses owner-protected secret files, defaults to non-root/read-only containers where supported, and fails application preflight for insecure production authentication configuration. Caddy is responsible for public TLS and HTTP-to-HTTPS redirect; metrics stay private to avoid exposing operational data.

Residual risks remain: a host administrator can read Docker secrets/volumes, a single host is a single failure domain, backup destination protection is an operator responsibility, and no claim is made for image signing or a real provider's authentication/authorization boundary.
# v0.5.0 recovery-write threats

The recovery write has its own outcome-assurance boundary. A provider may apply a mutation and then lose the response; FlowProof must not infer failure or retry blindly. A durable attempt is persisted before dispatch, and `DISPATCHING`/unknown outcomes require an authoritative reread. Only a proven pre-acceptance failure or contract-tested same-key idempotency within immutable invocation limits can make a retry reviewable. Each reapproval cycle preserves its typed observation, prior invocation count, write outcome when present and causal timestamps; terminal advancement does not erase that proof.

One correlation is bound to one entity at ingestion and checked again at evaluation. Recovery source values are selected by policy event type and the exact incident entity; offline verification independently derives the approved amount/currency from that event projection.

Approval replay is limited by exact plan, provider-contract and guardrail digests plus an explicit expiry recorded on the approval decision. Every transport invocation is reserved atomically with the attempt state and binds the approval decision and reservation time; verification requires that time to fall inside the decision TTL. A human may reject a proposal or revoke an unconsumed initial or retry approval. Service credentials cannot create these decisions. Contract, guardrail or plan mutation invalidates unexecuted consent.

The evidence capsule projects bounded fields and rejects secret-like keys/values. Default exports replace direct operator identity with a bundle-scoped digest. Its stable review-subject digest excludes only the review member and that review's separate security-audit reference, preventing a circular self-hash; the final bundle digest covers both. Offline verification requires each review to name the recomputed subject and requires the caller to supply an independently trusted bundle root plus exact Git commit/tree. A valid anchored capsule proves only its recorded lifecycle; it is not a signer identity, trusted timestamp or production-readiness certificate.
