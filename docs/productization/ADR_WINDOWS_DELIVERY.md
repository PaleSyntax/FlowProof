# ADR: Windows delivery model for the showable niche candidate

- Status: Accepted for the bounded productization increment
- Date: 2026-08-06
- Decision owner: repository productization goal

## Context

FlowProof already has a tested FastAPI/React/PostgreSQL core, deterministic
invariants, durable workers, evidence and recovery fencing. The delivery model
must remove terminal, `.env`, SQL, Python/npm and internal-token handling from
the primary Windows 11 journey without creating a second correctness layer.

The first increment is local, single-host and Windows-only. It must keep n8n as
an external integration engine and keep real-provider recovery writes disabled
without fresh owner authorization.

## Options considered

| Criterion | A. Browser-first local appliance + thin controller | B. Native shell + bundled Python/PostgreSQL sidecars | C. Managed core + thin connector |
| --- | --- | --- | --- |
| Installation | One FlowProof asset; guided Docker Desktop prerequisite; controller provisions the appliance | One native asset, but must install/manage backend and database services directly | Smallest local install |
| Admin privileges | Needed only for prerequisite/Start Menu lifecycle where applicable | Likely needed for services, firewall and updates | Usually only connector install |
| Package size | Core images are material but existing; n8n is not bundled | Python, PostgreSQL, web assets and service wrapper must all be bundled | Small connector |
| First start | Image load/pull plus database initialization | Native process/database initialization | Fast after network/account setup |
| Update/rollback | Compose image digests and existing lifecycle concepts can be reused | New binary, service and database upgrade/rollback system | Server deployment becomes a new product surface |
| Backup/data | Controller can bind PostgreSQL to the selected folder and call bounded backup tooling | Direct filesystem ownership is familiar but requires new Windows database operations | Cloud backup/retention/security scope |
| Secret handling | Controller generates local files, restricts ACLs and mounts them; no `.env` secrets | New Windows credential/file integration required | New tenant, connector and cloud secret boundary |
| Crash recovery | Docker restart policies plus existing durable state | New Windows service supervision and sidecar crash semantics | Requires distributed connector/server recovery |
| Code signing | Controller/installer still needs a signing certificate for frictionless trust | Every native executable/installer needs signing | Connector still needs signing; server has separate trust chain |
| Support burden | Docker Desktop/WSL remains the main prerequisite burden | Highest application-owned platform burden | Highest security/operations/product-scope burden |
| Compatibility | Preserves current API, UI, migrations, Compose concepts and tests | Invalidates much of the accepted Linux/runtime evidence | Introduces SaaS, tenancy and control-plane scope |
| Goal fit | Fits the default hypothesis and bounded scope | Possible later only if A fails measured installability | Rejected by current no-SaaS scope |

## Bounded spike evidence

The spike was read-only except for one isolated PostgreSQL container and one
temporary bind-mount directory, both removed after the test.

- Host build: `22631.6060` (Windows 11 23H2 build; the legacy registry
  `ProductName` string reports Windows 10 and must not be used alone).
- Windows PowerShell: `5.1.22621.6060` Desktop.
- Built-in UI/control capabilities: WPF `Window`, WinForms `NotifyIcon`, secure
  RNG and `WScript.Shell` are available.
- Docker Desktop: `4.83.0`, status `running`.
- Docker Engine: `29.6.2`, Linux `x86_64` on WSL2.
- Docker Compose: `v5.3.1`.
- Current Compose render: PASS without starting FlowProof services.
- WSL2 and Docker Desktop distros were present and running.
- Selected-folder database risk: `postgres:16-alpine` with a bind mount under
  `C:/tmp` became healthy, returned `1` from `SELECT 1`, and exposed 24 expected
  data-root members on the Windows path.
- First bind-mount attempt used an over-aggressive health window and became
  unhealthy during initialization. A final attempt with a health start period
  passed. The controller must therefore distinguish provisioning progress from
  steady-state health.
- The temporary container and directory were removed after both attempts.

Existing unpacked image sizes observed on the host are approximately API
`373 MB`, dashboard `82 MB`, PostgreSQL `420 MB` and fixture provider `365 MB`.
The optional n8n image is about `2.47 GB` and is deliberately not bundled into
the primary FlowProof asset. Archive/download size and cold-start time remain
qualification measurements, not estimates promoted to PASS.

## Decision

Choose Option A: a browser-first local appliance managed by a thin Windows
PowerShell 5.1 controller with a WPF/Start Menu surface.

The controller owns only lifecycle and install UX:

- prerequisite detection and one bounded remediation action;
- local data-folder selection;
- generated secret files and local ACLs;
- database initialization, migrations and administrator bootstrap;
- Start, Stop, Restart and Open;
- separate service health and protected-outcome status;
- sanitized diagnostics export;
- backup;
- update hooks and safe uninstall with data preservation by default.

The existing API/domain services remain the only correctness layer. The tray
or launcher never declares a business outcome correct from container health.

The primary candidate asset will contain one launcher surface, the appliance
Compose contract and an exact image/artifact manifest. It may automatically
pull or load pinned images, but the user will not issue Docker commands. n8n is
connected by the onboarding flow and is not bundled.

Docker Desktop is an external prerequisite in this increment. The controller
must detect missing/not-running/incompatible states and present one explicit
next action. It must not silently accept a broken Docker/WSL state. Whether a
fully clean machine can complete prerequisite installation inside the 15-minute
target remains a required clean-machine measurement.

## Rejected alternatives

Option B is rejected for this increment because it creates new Python,
PostgreSQL, Windows-service, migration, backup, update and crash-recovery paths
before Option A has failed a measured journey. It can be reconsidered only with
a bounded prototype demonstrating lower install and support cost.

Option C is rejected because it introduces managed service, tenant isolation,
cloud secret handling, connector trust and operational ownership outside the
current goal.

## Guardrails and rollback

- Do not modify `docker-compose.production.yml` to masquerade the local
  appliance as company-production acceptance.
- Keep the fixture provider permanently labelled `TEST_FIXTURE_ONLY`.
- Keep real-provider writes disabled by default.
- Never place generated secrets in environment output, logs, diagnostics or
  release artifacts.
- Preserve user data on uninstall unless the user makes a separate explicit
  deletion choice.
- If clean-machine evidence shows Docker Desktop cannot be guided reliably,
  stop and revisit Option B with measured evidence rather than adding hidden
  platform layers to Option A.

## Bounded implementation plan

1. Implement testable lifecycle functions separately from WPF/tray rendering.
2. Add a product-specific Compose contract that reuses existing images/core and
   binds durable data to the selected Windows folder.
3. Add prerequisite, state, progress and plain-language remediation contracts.
4. Add install/start/stop/restart/open/diagnostics/backup/uninstall commands and
   targeted tests.
5. Add the WPF first-run/controller surface only after lifecycle tests pass.
6. Package one candidate asset and run the clean-machine protocol before any
   showable PASS claim.
