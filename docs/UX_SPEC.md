# UX specification

## Goal

Make business correctness understandable without reading n8n execution logs.

## Overview

Cards:

- Open incidents
- Affected entities
- Affected amount
- Policies active
- Chaos runs passed/failed

Sections:

- Recent violations
- Recent recovered entities
- Verifier health

## Incident list

Columns:

- severity;
- entity;
- invariant;
- status;
- first detected;
- workflow version;
- affected amount;
- action.

Filters:

- status;
- severity;
- invariant;
- workflow;
- time range.

## Incident detail

Top message:

> Workflow acknowledged invoice registration, but the authoritative accounting system has no matching invoice.

Show:

1. Expected condition
2. Actual observation
3. Entity identity
4. Business timeline
5. Evidence
6. Technical provenance
7. Recovery plan
8. Approval/execution/verification state

## Entity timeline

Chronological list:

- business events;
- verifier observations;
- policy evaluations;
- incidents;
- recovery actions.

## Chaos Lab

Scenario cards:

- description;
- failure injected;
- expected detection;
- last result;
- run button.

Run view:

- input;
- observed event sequence;
- invariant results;
- forbidden side effects;
- pass/fail.

## Policies

Read-only view:

- version;
- entity;
- invariants;
- severity;
- verifier;
- recovery action.

Policy editing UI is not required.

## Honest labels

Never show “verified” merely because an event was received.

Use:

- observed;
- pending;
- verified;
- violated;
- inconclusive.
