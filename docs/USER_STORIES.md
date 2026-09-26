# User stories

## Automation engineer

As an automation engineer, I want to correlate events from several n8n workflows by business entity so that I can understand the complete process instead of opening unrelated execution logs.

Acceptance:

- one invoice timeline includes intake, approval, registration, verification, and recovery;
- every event keeps workflow/execution provenance.

## Operations owner

As an operations owner, I want to see which invoices are missing or duplicated and their total amount so that I can prioritize business impact.

Acceptance:

- incident list is readable without n8n knowledge;
- blast radius uses deterministic event data.

## Incident operator

As an operator, I want a narrow recovery plan that avoids repeating completed side effects so that fixing one gap does not create a second incident.

Acceptance:

- full retry is not default;
- approval required;
- external postcondition verified.

## Automation reviewer

As a reviewer, I want repeatable chaos scenarios so that I can demonstrate whether a workflow survives duplicate delivery, false success, delay, malformed AI output, and partial completion.

Acceptance:

- scenario input and expected behavior are versioned;
- each run records pass/fail and evidence.

## Developer

As a developer, I want policy evaluation isolated from HTTP and LLM so that I can test correctness with a fake clock and deterministic fixtures.

Acceptance:

- unit tests do not require network;
- LLM disabled does not affect incident detection.
