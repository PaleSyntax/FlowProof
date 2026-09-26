# Invariant engine

## Design rule

The engine is deterministic and testable without HTTP, database, or LLM.

Input:

- policy version;
- correlation ID;
- ordered events;
- current UTC time;
- optional external observations.

Output:

- status;
- invariant ID;
- evidence;
- expected;
- actual;
- violation fingerprint.

## `exactly_once`

```yaml
type: exactly_once
event: invoice.registered
```

States:

- 0 occurrences before deadline → pending or violated according to policy;
- exactly 1 → passed;
- more than 1 → violated.

## `eventually`

```yaml
type: eventually
after: invoice.registration_acknowledged
expect: invoice.registered
within: 30s
```

Rules:

- no trigger → not_applicable/pending;
- expected before deadline → passed;
- deadline not reached → pending;
- deadline reached without expected → violated.

Clock must be injectable.

## `ordering`

```yaml
type: ordering
before: invoice.approved
after: invoice.registration_requested
```

Violation if `after` occurs without a prior `before` for the correlation.

Late telemetry may change an initial result. Re-evaluation must resolve a false violation if policy allows.

## `value_matches`

```yaml
type: value_matches
left:
  event: invoice.validated
  path: $.amount
right:
  event: invoice.registered
  path: $.amount
tolerance: 0.01
```

Requirements:

- safe JSON path subset;
- clear missing values;
- numeric tolerance;
- no arbitrary code expressions.

## `external_assertion`

```yaml
type: external_assertion
after: invoice.registration_acknowledged
verifier: mock_accounting_invoice
within: 30s
expect:
  exists: true
  unique: true
  fields:
    amount:
      equals_event:
        event: invoice.validated
        path: $.amount
      tolerance: 0.01
```

Verifier result:

```json
{
  "status": "observed",
  "exists": false,
  "record_count": 0,
  "checked_at": "...",
  "request_id": "...",
  "safe_response_hash": "..."
}
```

Transport failure is `inconclusive/error`, not automatically a business violation, until retry/deadline policy says otherwise.

## Incident lifecycle

- violated opens/reuses incident;
- repeated identical evaluation updates `last_detected_at`;
- passed after recovery resolves incident;
- changed evidence creates history without duplicate spam.

## Severity

- `info`
- `warning`
- `high`
- `critical`

Policy defines severity. LLM cannot change it.
