# Implementation status

## Current verdict — v0.6.0 portfolio release candidate

- Package line: `0.6.0` (`LOCAL_PORTFOLIO_RELEASE_READY`).
- Source base: published private `v0.5.0` at commit `da9057a`; PR #8 is merged.
- Candidate source: `codex/showable-niche-product` remains in the private
  `FlowProof-archive`. The clean public `main` began at commit `7f292ac`.
- PR #7 remains a historical draft pending unique-diff review; it has not been closed by this work.
- Publication: `BRANCH_PUBLISHED`; the source repository is public, but no
  v0.6.0 tag or downloadable Windows asset has been published.
- GitHub destination: [PaleSyntax/FlowProof](https://github.com/PaleSyntax/FlowProof).
- CI: the manual run for commit `8f82fd9` passed on Ubuntu and Windows;
  subsequent pushes to `main` and pull requests run the primary CI automatically.
- Migration head: `0010_release_groundwork_fencing`.
- Evidence capsule schema: `1.1`; legacy `1.0` requires explicit opt-in.
- Portfolio readiness: clean locked backend, frontend, contracts, Gitleaks,
  false-200, real local n8n, visual proof, owned-image Trivy, exact v0.6.0
  Windows packaging, an eight-stage extracted lifecycle, and source-free guided
  n8n onboarding pass locally.
- Real Xero, independent fresh-Windows and code signing: `NOT_VERIFIED_EXTERNAL`.
- Company deployment/adoption: `NOT_CLAIMED`.

Before touching the overlay, a control copy of 97 files was created outside the
repository with a SHA-256 manifest. Manifest SHA-256:
`46e5dd21301c43a24b6ee7df0066c3a72147c38babb896c031e9783a5da0b366`.
The test/runtime `.tmp/` tree is ignored. Physical cleanup is currently blocked
by its sandbox-owned Windows ACL and is not part of the publishable Git tree.

The authoritative release boundary is [RELEASE_STATUS.md](RELEASE_STATUS.md) plus
[`release/STATUS.json`](../release/STATUS.json). Source code and agent reports do not
self-certify current-head behavior.

## Implemented v0.6.0 increment

- Windows 11 local-appliance controller, checksum-bound image loading, guided
  source-free n8n onboarding and backup-first same-schema update path.
- Permanently labelled `TEST_FIXTURE_ONLY` first-value UI and endpoint; disabled
  by default and rejected in production configuration.
- Invoice/accounting outcome pack plus explicit Xero Demo Company browser-PKCE
  read-only qualification behind a feature flag. Token storage is in memory only;
  Xero recovery writes do not exist.
- Version `0.6.0` is consistent across backend, frontend, OpenAPI, images,
  Windows manifest/builder, evidence schema and release contracts.
- Employer-facing English/Russian READMEs, plain-language Russian guide,
  HTML-cheatsheet prompt, MIT license, security policy and contribution guide.

## Current v0.6.0 packaging evidence (2026-08-24)

- The exact local Windows candidate is checksum-bound, contains 15 entries and
  four managed workflows, and contains no Python or TypeScript checkout source.
- Its extracted payload passed install/readiness, shortcut creation, backup,
  sanitized diagnostics, restart, stop/start, preserve/reinstall, and confirmed
  full deletion without using the checkout as runtime. Exact run metadata lives
  in the machine-readable qualification evidence generated with the asset.
- The extracted payload also passed guided n8n 2.30.5 qualification: four
  workflows created, three published, one encrypted credential, two n8n-origin
  timeline events, no public credential data, no manual FlowProof-token copy,
  no persisted n8n API key, and complete cleanup.
- Trivy 0.69.3 found zero fixed HIGH/CRITICAL vulnerabilities in the exact API,
  dashboard, and Mock Accounting candidate images. The pinned PostgreSQL image's
  22 unique `gosu` findings are covered only by the exact component/digest/CVE
  VEX and a source `govulncheck` result with zero reachable findings.
- This is current-host local evidence. It is not a signed asset, a downloaded
  GitHub Release, a fresh-Windows test, real Xero evidence, or production acceptance.

## Historical v0.5.0 productization evidence (2026-08-08)

The following section preserves prior candidate evidence. It must not be read as
proof for the current `0.6.0` tree.

- Windows 11 delivery is implemented as a browser-first local appliance with a
  PowerShell 5.1/WPF controller. Docker Desktop remains an external prerequisite.
- The controller covers prerequisite status, install/repair, Start/Stop/Restart,
  Open, sanitized diagnostics, backup, Start Menu shortcut and uninstall with
  data preservation by default. Full data deletion requires the exact separate
  phrase `DELETE FLOWPROOF DATA`.
- The current unsigned candidate ZIP was built locally with four bundled Docker images:
  `FlowProof-Windows-x86_64-0.5.0-productization-candidate.4.zip`, 262,575,496
  bytes, SHA-256
  `014ff3c8237240d53fdaffa48ca77f218e9facf90e81826091c813e03dcdbbd4`.
  Its self-computed 14-file/four-image source-inventory digest is
  `b545a55410eebd8176f4ca876a436151e1ce7e334c6d9e17d377531a283db7ff`.
  It is not uploaded or signed.
- After its candidate tags were removed, the extracted asset loaded its bundled
  image tar and completed an eight-stage current-host lifecycle in 178.988
  seconds without using the source checkout as runtime: API/web readiness,
  isolated shortcut, backup sidecars, sanitized diagnostics, restart,
  stop/start, preserve-data uninstall/reinstall and confirmed full deletion all
  passed. This is not fresh-machine evidence.
- The first-login UI provides a permanently labelled `TEST_FIXTURE_ONLY`
  false-200 demo. Browser evidence measured 6.062 seconds to the first missing
  outcome and 80.261 seconds through approved compensation and verified reread,
  with six user actions, one pre-outcome decision, no terminal commands, no
  manual secret handoff and no console errors.
- A separate live local n8n 2.30.5 fixture run imported four workflows, published
  the three protected paths and returned `n8n_execution=successful`, resolved
  the incident after human approval and produced exactly one Mock Accounting
  invoice. This is real n8n execution evidence but still fixture-only provider
  evidence.
- Candidate.2 also completed the controller's guided existing-n8n path without
  source runtime: an owner-created n8n API key provisioned one encrypted
  fixed-scope credential and four workflows (three published), then a real n8n
  webhook produced two n8n-origin timeline events. No FlowProof token was copied,
  the n8n API key was not persisted, and all temporary container/volume/data
  cleanup passed. This is local n8n integration proof, not provider proof.
- Candidate.4 repeated that guided existing-n8n proof source-free: n8n 2.30.5
  created four workflows, published three, stored one encrypted credential and
  emitted two n8n-origin events with no token copy or API-key persistence.
  Its explicit candidate.3-to-candidate.4 transition completed in 247.432
  seconds including controlled failure injection: installed schema was
  allowlisted, backup plus sidecars were created before switching versioned
  images, the injected missing-image failure restored candidate.3 READY, the
  clean update preserved administrator/data, and a same-version repeat was
  rejected before mutation.
- The candidate Start Here now includes the 30-second pitch, three-minute safe
  demo, supported/unsupported matrix and backup/update/uninstall instructions.
- The invoice/accounting outcome pack now has a machine-readable manifest,
  deterministic observe-only policy, event/correlation template, exact provider
  access request and real-lifecycle evidence schema. Recovery is absent from the
  observe-only policy.
- The local full backend suite passed with three environment skips after the
  bundled Git path was supplied; Ruff, version/release contracts, OpenAPI parse,
  four n8n workflow validations, frontend lint/build, full npm audit,
  diff check and pinned Gitleaks v8.18.4 passed. The final secret scan covered
  exactly 333 tracked plus non-ignored untracked files with zero findings;
  npm dependencies, including development tooling, reported zero vulnerabilities.

Productization remains `BLOCKED_EXTERNAL`, not `SHOWABLE_NICHE_PRODUCT_CANDIDATE`,
until all of these independent gates are real: owner-authorized provider access
and a named observe-only lifecycle, a fresh Windows profile/VM install, and the
documented unsigned SmartScreen/code-signing boundary. GitHub Actions, release,
deployment and customer adoption are not claimed.

The working tree now contains a source-registered `xero-demo` adapter and a
digest-bound Accounting API 2.0 contract. The adapter allowlists the canonical
Xero origin, performs browser Authorization Code consent with PKCE S256, accepts
only a public Client ID, retains the short-lived access token in process memory,
requests no refresh token, verifies exactly one active Demo Company, projects
only invoice identity/amount/currency/status, maps typed read failures and
performs no HTTP write. Its provider/route/factory tests pass, but this is
`CONTRACT_TESTED_LIVE_OWNER_AUTH_REQUIRED`, not a live provider observation.

The fresh-local-profile harness now has a non-elevated parent launcher,
schema-shaped fallback and sanitized stage diagnostics. Its elevated probe
passed administrator, LocalAccounts, `docker-users` and result-write checks.
Three install attempts then proved a narrower environment boundary: Docker
Desktop runs under the original interactive account and cannot mount the
temporary account's private `%LOCALAPPDATA%` path, even after a temporary root
ACL and qualification-only inherited secret ACL. No later product stage is
claimed. The post-attempt audit found zero `FPQual*` users/profiles/Public
staging directories and zero matching Docker containers, volumes or networks.
The exact remaining gate is
`FRESH_LOCAL_PROFILE_CROSS_USER_DOCKER_BIND_MOUNT_UNAVAILABLE`: use a disposable
Windows 11 VM, or sign in as the fresh tester and run Docker Desktop as that user.

## Canonical composition

| Coordinate | Responsibility |
| --- | --- |
| `flowproof/__init__.py` | Side-effect-free package metadata only. |
| `flowproof/models.py` | Canonical ORM metadata, including correlation binding, recovery attempt and full transport reservation authority. |
| `flowproof/service.py` | The only executable `FlowProofService`; the private implementation and inheritance-only base reject direct construction without late monkeypatching. |
| `flowproof/ingest_binding.py` | Atomic correlation and idempotency unique-race convergence. |
| `flowproof/recovery_planning.py` | Bounded plan construction independent of write enablement. |
| `flowproof/recovery_dispatch.py` | New-reservation kill switch, owner/generation/lease dispatch claim and exact CAS completion. |
| `flowproof/recovery_reconciliation.py` | Durable reconciliation owner/generation/lease claim, stale-observation discard and append-only causal history. |
| `flowproof/recovery_resolution.py` | Superseding unused plans and fenced convergence for active recovery state. |
| `flowproof/provider_factory.py` | Explicit Mock and Xero Demo registry with exact constructors; unknown or constructorless providers fail startup. |
| `flowproof/xero_demo.py` | Canonical-origin, ephemeral PKCE, active-Demo verification and GET-only Xero invoice projection; the write surface fails closed without network dispatch. |
| `flowproof/evidence.py` | Deterministic v1.1 capsule export/verification bound to migration 0010 and reservation genealogy. |

Removed import-time overlay paths:

- `groundwork_bootstrap.py`;
- `groundwork_models.py`;
- `service_v050.py`;
- `service_v050_dispatch.py`;
- `service_v050_ingest.py`;
- `service_v050_reconcile.py`;
- `service_v050_resolution.py`.

No second state machine, second outbox or separate runtime database was introduced.

## Current implementation boundary

| Area | Implemented source behavior |
| --- | --- |
| Ingestion | Durable unique correlation subject, nested-transaction unique-race handling, deterministic duplicate/conflict outcome instead of leaked `IntegrityError`. |
| Planning | Missing-invoice plan remains available while external writes are disabled. |
| Human decisions | Approve/reject/revoke remain governed by their existing human/scope/state/hash contract and are not coupled to write enablement. |
| Dispatch | New reservation and provider call alone are kill-switched. Reservation stores exact owner/generation/start/lease, explicit abandonment and durable typed outcome. |
| Completion | Provider completion must CAS the exact live, non-abandoned reservation and matching active attempt. CAS loss is reconciliation-required, not execution success. |
| Reconciliation | Live dispatch/reconciliation leases cannot be stolen. Expired claims may be taken over with incremented generation; stale observations cannot overwrite newer terminal results. |
| Causal evidence | Append-only history preserves reservation ID, observation, timestamps, prior states, invocation count, reapproval/retry reason, typed write outcome and reconciliation claim authority. |
| External resolution | Unused proposed/approved/PREPARED plans are superseded, approvals cleared and system decision appended. Active/ambiguous reservations require fenced convergence before resolution. |
| Provider startup | Only explicitly registered provider IDs with a constructor are allowed. Xero Demo additionally requires its exact API origin and PKCE/not-applicable credential contract; token material stays in memory and out of evidence. |
| Capsule | v1.1 verifies complete reservation authority and has separate strict paths for external resolution without a write and resolved-after-write. |
| Migration 0010 | Empty draft-0009 recovery tables upgrade with correlation backfill; populated recovery attempt/transport tables fail closed for manual remediation or local database recreation. `dispatch_generation` remains `NOT NULL DEFAULT 1`. |
| HTTP/schema ownership | OpenAPI owns routes/methods/auth/status/operation IDs; committed JSON Schemas own detailed recovery payloads; TypeScript mirrors schema state enums. |
| Guided fixture demo | A local-only, explicitly enabled route creates a bounded false-200 timeline through the real domain services; production configuration rejects the fixture flag. |
| Windows productization | A thin controller manages lifecycle only; Docker health never becomes business-outcome truth. A generated candidate may load a checksum-bound image archive before provisioning. |
| Outcome pack | Invoice/accounting is fixed as the first vertical. Xero Demo is the recommended GET-only adapter; live selection still fails closed until owner authorization and named review. |

## Evidence boundary

The accepted `0.4.0` baseline retains its historical exact-head evidence. Current local
evidence belongs to commit `d720f0b8a95057dfa4f0af9ef0bf7d738d5bba46`, tree
`d32fbd2477bb3ad150111fc6cbd8eeec5b3f91e4`: backend definitions `202/202`, Ruff,
Node `22.14.0` npm install/lint/build, production dependency audits, OpenAPI/schema and
workflow contracts, migration/schema `13/13`, Compose, Bash/ShellCheck `14/14`, pinned
Gitleaks, owned-image Trivy and the full production deployment proof all passed within
their recorded boundaries.

This is `LOCAL_RELEASE_READY` for the FlowProof-owned production core. The candidate branch
was published and PR #8 was observed at `28289a8eb6fb9a7bd3626b95f454f6b7ec9f5cf4` /
`9cad31f060b8800167b74c5aa108030dcd759f36` before this documentation-only successor.
GitHub Actions jobs were blocked before executing any step by account billing/quota state,
so no GitHub Actions PASS or test failure is claimed. Real-provider and company-production
acceptance remain separate.

The productization evidence is separately recorded in
`quality/productization/windows-candidate-asset-2026-08-06.json`,
`quality/productization/guided-first-value-2026-08-06.json`,
`quality/productization/n8n-safe-fixture-2026-08-06.json` and the explicit
blocked fresh-machine/provider templates. It belongs to an uncommitted working
tree based on `da9057ac21be3fa7ac7e88d19bca9abc509abac9` / tree
`f88908bf75dcd336e2df33a2907c6a53c313725d`; the Windows asset records its own
build-time candidate-source digest. Do not substitute these artifacts for a
clean-machine, real-provider, current GitHub head or signed release proof.

## Remaining gates

- no repository-defined local gate remains open for the exact tested owned-core tree;
- final GitHub PR/check/merge/tag/release coordinates remain external live evidence;
- real-provider/operator and company deployment acceptance remain external gates.
- the productization working tree additionally requires a clean Windows profile
  run and an owner-authorized observe-only provider lifecycle before its own
  showable-candidate verdict can pass.

## External gaps

- owner browser consent for the prepared Xero Demo PKCE adapter, public app
  Client ID, exact dummy invoice and expected amount/currency;
- named human operator lifecycle;
- fresh Windows Sandbox/disposable VM/fresh-profile installation and independent
  usability session;
- trusted Windows code-signing certificate if SmartScreen-frictionless delivery
  is required;
- company TLS/DNS/n8n, secret manager, off-host recovery and on-call acceptance;
- HA, SSO/MFA and tenant isolation where required.
