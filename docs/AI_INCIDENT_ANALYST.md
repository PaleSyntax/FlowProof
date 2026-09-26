# AI Incident Analyst

## Status

Optional. Core product must work without an API key.

## Legitimate uses

- summarize evidence;
- explain likely failure mode;
- group similar incidents;
- point to relevant workflow nodes;
- draft a human-readable incident report;
- explain why a full retry is unsafe.

## Forbidden authority

The model must not:

- decide whether an invariant was violated;
- execute tools;
- approve recovery;
- invent missing evidence;
- change severity;
- create arbitrary recovery actions;
- expose secrets.

## Input envelope

Only sanitized data:

- invariant definition;
- evaluation result;
- evidence events;
- external observation;
- workflow metadata;
- optional workflow JSON with credentials removed;
- allowed recovery actions.

## Output

Strict JSON:

- `summary`
- `likely_causes[]`
- `evidence_refs[]`
- `uncertainties[]`
- `unsafe_actions[]`
- `recommended_registered_action`
- `operator_checks[]`

Every factual claim should reference an evidence ID.

## Provider interface

Implement:

- fake deterministic provider for tests/demo;
- optional OpenAI-compatible HTTP adapter;
- timeout;
- token/cost metadata;
- no streaming required.

## Prompt injection

Event payload and external responses are untrusted data.

Place them in a marked data section. Do not let them redefine rules or trigger tools.
