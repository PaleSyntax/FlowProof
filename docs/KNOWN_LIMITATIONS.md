# Known limitations

## Current v0.6.0 release boundary

- `0.6.0` is a portfolio release candidate, not a production certification.
- Clean lock-based Python, fresh `npm ci`, runtime, pinned Gitleaks, visual QA,
  exact Windows packaging, extracted current-host lifecycle, source-free n8n
  onboarding, and owned-image Trivy pass locally for the current candidate.
- The clean source is public at `PaleSyntax/FlowProof`. This repository contains
  no downloadable Windows ZIP or signed installer.
- Primary `ci.yml` is configured for pushes to `main`, pull requests and manual
  dispatch. Container security, deployment proof and external dependency
  advisory workflows remain manual.
- Earlier billing-blocked Actions runs in the private source are historical
  `UNKNOWN` results; they do not describe the public repository's CI.

## Product boundaries that remain after portfolio publication

- Mock Accounting is always `TEST_FIXTURE_ONLY`; it proves the FlowProof state
  machine, not a real provider contract or customer outcome.
- Xero is feature-flagged, browser-PKCE, read-only and restricted to one Demo
  Company qualification. Tokens live only in memory. No Xero recovery write is
  implemented, and live owner-authorized evidence is `NOT_VERIFIED_EXTERNAL`.
- The Windows asset is unsigned, depends on Docker Desktop, and has no independent
  fresh-Windows proof. SmartScreen and code-signing acceptance remain external.
- Its eight-stage and guided-n8n qualifications ran on the development host from
  an extracted source-free payload. They are not an independent clean-machine
  installation and do not prove download, SmartScreen, or customer usability.
- The single-host production foundation is not HA. TLS, DNS, secret manager,
  off-host backups, infrastructure monitoring and environment acceptance remain
  responsibilities of a chosen deployment environment.
- There is one real recovery use case (`register_missing_invoice`). New provider
  writes require a separate contract, allowlist, idempotency strategy and threat review.
- Optional AI can summarize bounded evidence only. It cannot determine invariant
  truth, approve or execute recovery, or resolve an incident.

## Historical Windows productization candidate detail

- The local Windows asset is an unsigned candidate, not a GitHub Release asset.
  SmartScreen/frictionless installation is unverified and requires a trusted
  code-signing path.
- Docker Desktop/WSL2 is an external prerequisite. The candidate detects a
  missing or stopped engine but does not install Docker Desktop for the user.
- Candidate.4 passed a full lifecycle on the current host without using the
  checkout as runtime. Windows Sandbox was unavailable. The observable elevated
  probe passed, but the already-running Docker Desktop backend could not bind
  the disposable account's private `%LOCALAPPDATA%` path. Root and secret ACL
  variants produced access-denied or mount-stat failures; moving the data root
  to Public was rejected because it would not prove the product's default path.
  Cleanup left no user/profile/staging or Docker residue. Clean-machine install
  remains `FRESH_LOCAL_PROFILE_CROSS_USER_DOCKER_BIND_MOUNT_UNAVAILABLE` and
  requires a disposable VM or a real login where Docker Desktop runs as tester.
- The candidate ZIP bundles exact local image archives and verifies their
  checksum before loading. Candidate.4 is 262,575,496 bytes; download time, SmartScreen
  behavior and first cold image-load time are not independently measured.
- Update is deliberately narrow: candidate.4 accepts candidate.3 only, requires
  the exact same Alembic schema, creates a backup first and restores the prior
  service configuration on failure. Cross-schema update/downgrade and automatic
  database restore are not claimed.
- The WPF launcher is a controller, not a tray-resident outcome monitor. Its
  green service state does not prove protected business outcomes.
- The guided browser demo is permanently `TEST_FIXTURE_ONLY`. It provides no
  current-provider, customer, adoption or false-positive-rate evidence.
- A separate local n8n fixture run proves human approval and one compensation.
  Candidate.4 additionally proves the guided connection against real n8n 2.30.5
  from the extracted asset: four workflows, three published, one encrypted
  credential, no manual FlowProof token copy and no persisted n8n API key. n8n
  is not bundled, and this connection path is not clean-machine or company-n8n
  qualified.

## Outcome-pack and provider boundary

- Invoice/accounting is the only prepared niche pack. Its real mode is
  observe-only and contains no recovery action.
- No owner-authorized provider credential/safe entity was supplied. A named
  Xero Demo adapter, digest-bound contract, prefilled access request and typed
  evidence schema are ready, but there is no live provider read or operator
  review. Adapter tests are not provider acceptance.
- Mock Accounting cannot clear the real-provider gate. The exact blocker is
  `OWNER_AUTHORIZED_PROVIDER_ACCESS_REQUIRED`.
- Real-provider recovery writes remain disabled. Observe-only authorization
  cannot be reused as write authority.

## Release evidence

- This document describes the clean public source at `PaleSyntax/FlowProof`.
  Earlier validation of private-source candidates does not establish the
  behavior of a different public commit or a live accounting connection.
- Check the exact public commit, its CI result and the local demo evidence for
  claims about the published version. A Windows installer and live Xero recovery
  remain unverified.

## Provider boundary

- Registered adapters are Mock Accounting (`TEST_FIXTURE_ONLY`) and Xero Demo
  (`CONTRACT_TESTED_LIVE_OWNER_AUTH_REQUIRED`).
- Unknown provider IDs and registry entries without a constructor fail application startup.
- The Xero adapter accepts only the canonical Accounting API origin, a public
  Client ID through the human-gated PKCE start route, organisation/invoice GETs
  and an in-memory short-lived access token. It requests no refresh token and
  its write method makes no provider call. Live use still requires owner
  consent, exact active Demo Company confirmation, one safe invoice and a named
  operator.
- Credential material must not be manually copied. The registry and PKCE route
  do not accept a client secret, access token or refresh token from API requests,
  plans, database rows, reports or capsules.

## Recovery and concurrency boundary

- Provider dispatch is synchronous at the network layer, although every invocation now has a durable owner/generation/lease reservation and fenced outcome boundary.
- A process crash after reservation but before durable outcome requires authoritative reconciliation; FlowProof does not infer success.
- Dispatch completion after lease expiry, abandonment or reconciliation takeover is discarded and requires reread/reconciliation.
- Reconciliation takeover occurs only after lease expiry. A stale reconciler cannot overwrite a newer generation or terminal result.
- The external-write kill switch blocks only new reservations/provider calls. It does not cancel an already issued provider request and cannot guarantee that an external provider did not apply a timed-out request.
- `still_failed` permits another authoritative reread, not automatic compensation replay.
- One plan has one semantic attempt. This is not a generic multi-operation saga, transaction coordinator or arbitrary workflow retry engine.
- Migration 0010 does not convert populated draft-0009 recovery runtime rows. Such a local database requires manual remediation or recreation before upgrade.

## External resolution boundary

- Unused proposed/approved plans and zero-reservation PREPARED intent can be superseded by authoritative invariant PASS with cleared approval and append-only system decision.
- Active or ambiguous reservations cannot be resolved by simply writing incident status. They require fenced reservation convergence and verification.
- The system is not a general recurring-incident generation engine; the current model keeps one plan per incident.

## Evidence capsule boundary

- Capsule schema `1.1` describes the migration-0010 lifecycle. Capsule `1.0` requires explicit legacy opt-in and is not silently upgraded.
- Capsule v1.1 has no terminal proof path for draft-0009 runtime-row conversion evidence.
- Capsule verification proves consistency of one recorded lifecycle under supplied trust anchors. It is not provider-wide reliability evidence, a signer identity, trusted timestamp, company-production certification or current release PASS.
- Deterministic review-subject and bundle digests do not replace independent delivery of exact Git and bundle trust anchors.

## Operations and deployment boundary

- The `0.5.0` local deployment proof is exact-tree evidence for FlowProof-owned components
  and the bundled n8n integration fixture; it is not company-environment acceptance.
- Runtime proof volumes are intentionally retained as local audit evidence; completed proof
  containers and networks were removed.
- API/dashboard Trivy PASS covers HIGH/CRITICAL fixed findings under the recorded scanner
  policy. It is not a guarantee that no lower-severity, unfixed or newly disclosed issue exists.
- The scheduler, alert worker and operations watcher are database-backed single-host workers; no distributed queue, multi-region scheduler or HA credential service exists.
- Application rollback does not automatically downgrade the database.
- Company TLS, DNS, certificates, n8n storage/editor access, external secret manager, off-host backup replication and on-call monitoring are not accepted.

## Identity, tenancy and AI boundary

- Single tenant only; no SSO, MFA, external identity provider or tenant isolation.
- Legacy `X-FlowProof-*` headers remain development-only compatibility aliases.
- AI is outside correctness and authority. It may summarize existing evidence but cannot decide invariant truth, approve recovery or resolve incidents.
