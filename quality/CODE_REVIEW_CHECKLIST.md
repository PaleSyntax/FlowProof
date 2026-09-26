# Code review checklist

## Domain

- [ ] Invariants deterministic.
- [ ] Clock injectable.
- [ ] Events immutable.
- [ ] Incident identity stable.
- [ ] Late events handled.
- [ ] Verifier errors distinguished from violations.

## Idempotency

- [ ] Event ingestion.
- [ ] External command.
- [ ] Recovery.
- [ ] Repeated evaluation.

## Recovery

- [ ] Full retry not default.
- [ ] Action allowlisted.
- [ ] Approval recorded.
- [ ] Plan hash checked.
- [ ] Postcondition verified.

## Security

- [ ] No secrets in Git.
- [ ] Tokens backend-only.
- [ ] CORS exact.
- [ ] Payload bounded.
- [ ] Logs redacted.
- [ ] No arbitrary external URL.
- [ ] Demo defaults fail closed in production mode.

## n8n

- [ ] No real credential IDs.
- [ ] Error handler present.
- [ ] HTTP retries only where safe.
- [ ] Correlation ID preserved.
- [ ] Idempotency key explicit.
- [ ] JSON importability checked.

## UX

- [ ] Expected vs actual visible.
- [ ] Evidence visible.
- [ ] Inconclusive is not shown as violation.
- [ ] Approval has confirmation.
- [ ] Error states usable.

## Documentation

- [ ] README matches code.
- [ ] Limitations explicit.
- [ ] Test results factual.
- [ ] Startup steps work.
