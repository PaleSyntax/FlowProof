# Product Vision

## One sentence

**FlowProof verifies that automated business processes reached the correct outcome, even when every underlying workflow execution appears successful.**

## User

Primary:

- AI automation engineer;
- n8n developer;
- operations engineer;
- integration consultant;
- small team maintaining multiple business workflows.

Secondary:

- finance/operations owner who needs evidence, not workflow internals;
- technical lead reviewing automation reliability;
- auditor investigating an incident.

## Core job to be done

> When an automation spans multiple workflows and external systems, show me whether the business object reached a valid final state, what is missing or duplicated, which objects are affected, and the safest way to repair the process.

## Why normal monitoring is insufficient

Execution monitoring observes:

- status;
- duration;
- node errors;
- retries;
- infrastructure health.

It often cannot prove:

- exactly one invoice exists;
- the amount matches the source;
- approval preceded payment;
- the external system actually persisted the record;
- all required downstream effects happened;
- a retry is safe.

## Product principles

### Outcome over execution

The unit of truth is a business entity and its state, not a single workflow execution.

### Deterministic detection

Invariants are code/policy. LLM output can explain but cannot decide whether a violation exists.

### Evidence first

Every incident includes:

- triggering events;
- expected state;
- observed state;
- timestamps;
- source systems;
- workflow/execution provenance;
- verifier result.

### Minimal recovery

Never default to “retry the whole workflow.” Prefer a narrow idempotent compensation.

### Human authority

A person approves any recovery with external side effects.

### Local and inspectable

The MVP is self-hosted and transparent. It must be possible to run the full demo locally.

## Portfolio value

FlowProof demonstrates:

- n8n;
- Python;
- TypeScript;
- API/webhooks;
- PostgreSQL;
- event-driven design;
- correlation IDs;
- idempotency;
- state machines;
- policy engines;
- external verification;
- chaos testing;
- recovery/compensation;
- human-in-the-loop;
- security and redaction;
- Docker;
- automated tests.

## Success signal

A reviewer should understand the value within 30 seconds:

> “The workflow was green, but the invoice did not exist. FlowProof proved it and repaired only the missing side effect.”
