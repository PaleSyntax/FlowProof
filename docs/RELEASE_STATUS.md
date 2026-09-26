# Release status

## Verdict

`PORTFOLIO_RELEASE_CANDIDATE`

`LOCAL_PORTFOLIO_RELEASE_READY`

`REAL_PROVIDER_NOT_VERIFIED`

`FRESH_WINDOWS_NOT_VERIFIED`

`UNSIGNED_WINDOWS_ASSET`

`COMPANY_PRODUCTION_NOT_CLAIMED`

FlowProof `0.6.0` is locally ready as a portfolio release candidate. Source,
fixture runtime, real local n8n, desktop/mobile UI, owned-image security, and an
extracted source-free Windows candidate have all passed their local gates. Its
clean source branch is public at [PaleSyntax/FlowProof](https://github.com/PaleSyntax/FlowProof).
It is not yet a published v0.6.0 release: no tag or downloadable asset has been
published. The accepted private `v0.5.0` release remains the historical baseline.

This file deliberately separates a reproducible portfolio demonstration from a
real-provider pilot, clean-Windows usability proof, and company-production
certification.

## Evidence axes

| Axis | Current status | What closes it |
| --- | --- | --- |
| Portfolio release | `LOCAL_PORTFOLIO_RELEASE_READY` | Complete exact-head CI, publish the tag/assets, and download-check them. The public branch and anonymous fetch are verified. |
| Real provider | `NOT_VERIFIED_EXTERNAL` | Owner-authorized Xero Demo consent, one bounded invoice read, and one named-human review. |
| Fresh Windows | `NOT_VERIFIED_EXTERNAL` | Independent same-user Windows 11 VM or fresh interactive tester lifecycle. |
| Company production | `NOT_CLAIMED` | Company infrastructure, security, operations, and owner acceptance. |

No axis promotes another. Mock Accounting is always `TEST_FIXTURE_ONLY`. Xero
Demo is contract-tested and GET-only, but it has no live owner-authorized
observation. The Windows asset remains unsigned.

## Verified locally

Evidence recorded on 2026-08-24 for the current worktree:

- a clean Python environment installed strictly from `backend/requirements.lock`
  contains 47 exact locked distributions and passes `pip check`;
- the complete backend suite passes: `252 passed, 3 skipped`;
- canonical Ruff, version consistency, release status, generated OpenAPI/schema,
  and all four n8n workflow validators pass;
- fresh `npm ci`, frontend lint, TypeScript/Vite production build, and both the
  full and production-only dependency audits pass with zero vulnerabilities;
- pinned Gitleaks `v8.18.4` finds zero secrets in both the intended release tree
  and all 148 commits of the local history;
- the Docker false-200 lifecycle resolves the incident only after approved
  recovery and an independent reread, with exactly one invoice;
- a real local n8n `2.30.5` lifecycle imports four workflows, publishes three,
  executes the webhook path, enforces human approval and actor separation,
  resolves the incident, and leaves exactly one invoice;
- the unsigned `FlowProof-Windows-x86_64-0.6.0.zip` passes checksum and safe-path
  validation, contains 15 files and four workflows with no checkout source files,
  and passes all eight current-host appliance stages from an extracted directory;
- the same extracted candidate passes guided real n8n `2.30.5` onboarding: four
  workflows, three published, no credential data exposed, no persisted n8n API
  key, and complete temporary data/container/volume cleanup;
- Trivy `0.69.3` reports zero fixed HIGH/CRITICAL findings for the API,
  dashboard, and Mock Accounting images. The pinned PostgreSQL image has 22
  unique findings limited to its `gosu` Go standard-library component; the exact
  digest/component/CVE VEX validator and source `govulncheck` reachability proof
  pass with zero reachable findings;
- desktop and 390 px mobile fixture screenshots match the current UI; the mobile
  page has no horizontal overflow;
- `pip-audit 2.9.0` reported no known vulnerabilities for the pinned Python lock.

The Docker and n8n results are local fixture evidence. They do not prove a real
provider or a customer environment.

## Not verified

- The locally qualified Windows ZIP is unsigned and is not yet a downloaded
  GitHub Release asset. Local packaging evidence does not prove public delivery.
- No fresh-machine Windows proof, code signature, or SmartScreen acceptance exists.
- No real Xero call, owner consent, customer adoption, or company-production
  deployment is claimed.
- The clean public branch and anonymous fetch are verified. Manual CI on commit
  `8f82fd9` passed both the Ubuntu application and Windows appliance jobs.
  Pushes to `main` and pull requests now start the primary CI automatically.
  No v0.6.0 tag, Release, or downloaded asset has been verified.

Historical candidate.1-candidate.4 JSON reports remain evidence for the `0.5.0`
productization work that produced them. They are not rewritten as `0.6.0`
evidence.

## Publication gate

The local portfolio gate is closed and the source branch is public. The remaining
release steps are green CI on the release head, a v0.6.0 tag, asset upload,
and downloaded checksum verification. The original source is still private as
`FlowProof-archive`. The machine-readable counterpart is `release/STATUS.json`.
Local source tests,
runtime proof, packaging proof, GitHub publication, real-provider acceptance,
fresh-machine usability, and company-production acceptance are independent
evidence axes.
