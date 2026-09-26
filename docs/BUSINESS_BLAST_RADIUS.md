# Business blast radius

## Purpose

Translate a technical issue into business impact.

Instead of:

> Workflow X failed 17 times.

Show:

> 17 invoices are affected, total amount 438,700 RUB. Twelve are missing, four are duplicated, and one is already repaired.

## MVP grouping

Group open incidents by:

- invariant ID;
- workflow ID;
- workflow version;
- event time window;
- entity type.

Metrics:

- `affected_count`;
- `affected_amount` where a validated numeric amount exists;
- oldest unresolved incident;
- newest incident;
- severity distribution.

## Evidence source

Amounts come from a named business event/payload field defined by policy.

Never ask an LLM to invent impact values.

## API shape

```json
{
  "groups": [
    {
      "invariant_id": "external_invoice_exists",
      "workflow_id": "invoice-intake",
      "workflow_version": "git:abc1234",
      "affected_count": 12,
      "affected_amount": 438700,
      "currency": "RUB",
      "oldest_opened_at": "...",
      "incident_ids": ["..."]
    }
  ]
}
```

## Future

- compare deployment versions;
- anomaly windows;
- customer tier;
- SLA penalties;
- manual handling cost;
- upstream/downstream dependency graph.

Do not implement speculative financial loss calculation in MVP.
