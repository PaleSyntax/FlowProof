# Why FlowProof matters

## Typical hidden failures

### False success

An integration API acknowledges a request but processes it asynchronously or drops it later.

### Duplicate side effect

A webhook is delivered at least once. A retry creates a second invoice, lead, refund, or notification.

### Partial completion

A workflow creates a payment but fails before updating CRM and sending the required document.

### Wrong data

The workflow succeeds using an incorrect amount extracted by an LLM.

### Wrong order

A downstream action happens before approval or validation.

### Cross-workflow gap

Workflow A finishes, but workflow B is never triggered.

### Green but broken

`Continue On Fail`, empty outputs, permissive conditions, or swallowed errors allow the execution to end successfully while a required step is missing.

## Business consequences

- financial inconsistencies;
- duplicate charges or records;
- forgotten customers;
- SLA breaches;
- compliance gaps;
- manual reconciliation;
- unsafe retries;
- loss of trust in automation.

## Why correlation is essential

An invoice process may involve:

- ingestion workflow;
- approval workflow;
- accounting integration;
- notification workflow;
- reconciliation job;
- recovery workflow.

Execution IDs are different. FlowProof joins them through a stable business correlation ID.

## Why independent verification is essential

A system must not prove its own success solely from the same response that produced the side effect.

For critical outcomes:

- command: “create invoice”;
- acknowledgement: API returned `200`;
- verification: read invoice back from the authoritative system;
- assertion: record exists once and fields match.

This command/verification separation is the heart of the demo.
