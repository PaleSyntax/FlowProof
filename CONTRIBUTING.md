# Contributing to FlowProof

Thanks for helping improve business-outcome assurance for workflow automation.

## Before changing code

1. Read [`AGENTS.md`](AGENTS.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).
2. Keep the distinction between technical execution success and verified business outcome.
3. Open an issue before broad architecture changes, new recovery actions, provider writes, identity changes, or database migrations.
4. Never use an LLM to decide invariant truth or recovery state.

## Development setup

Backend:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.lock
$env:PYTHONPATH = "backend/src"
.\.venv\Scripts\python.exe -m pytest backend\tests
.\.venv\Scripts\python.exe -m ruff check backend\src backend\tests
```

Frontend:

```powershell
Set-Location frontend
npm ci
npm run lint
npm run build
```

Repository contracts:

```powershell
python scripts/check_version_consistency.py
python scripts/check_release_status.py
python scripts/validate_workflows.py
```

Runtime demo:

```powershell
Copy-Item .env.example .env
# Replace both CHANGE_ME values in .env with fresh random values before starting.
docker compose up --build --detach
docker compose --profile demo run --build --rm demo
```

## Change rules

- Keep domain logic out of FastAPI handlers and React components.
- Use typed domain models and dependency injection for clocks and external transports.
- Preserve `/api/v1` compatibility unless a versioned migration is explicitly agreed.
- Give every event and side effect an idempotency key.
- Centralize and test state transitions.
- Recovery must be allowlisted, narrow, human-approved, and independently verified.
- Bound and redact evidence; do not retain unlimited raw provider payloads.
- Add an abstraction only when a second real use case justifies it.
- Label fixtures and demo-only paths prominently; never mask missing production behavior with mocks.

## Tests expected for relevant changes

Add or update tests for idempotent ingestion, idempotency conflict, policy timing and ordering, value mismatch, false `200`, incident deduplication/resolution, approval gates, recovery idempotency, malformed policies, redaction, and workflow structure as applicable.

Before submitting a pull request, run the smallest relevant tests and then the full source gates. Docker, n8n, packaging, browser, and provider claims require their own runtime evidence.

## Pull requests

- Keep commits small and logical.
- Explain the business failure being prevented, the safety boundary, and the evidence run.
- Separate verified results from `NOT VERIFIED` external surfaces.
- Update `docs/IMPLEMENTATION_STATUS.md`, `docs/KNOWN_LIMITATIONS.md`, and `NIGHTLY_REPORT.md` when behavior or evidence changes.
- Do not include `.env`, databases, `node_modules`, build outputs, `.tmp`, logs, tokens, cookies, or generated private evidence.

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
