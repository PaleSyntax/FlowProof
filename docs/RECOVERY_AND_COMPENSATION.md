# Recovery and compensation

## Correctness boundary

FlowProof never treats HTTP success, workflow completion or a provider call return as
business resolution. The current state machine remains:

```text
EVENT_ACCEPTED
→ VERIFICATION_DUE
→ VERIFIED | INCIDENT_OPEN
→ PLAN_PREPARED
→ HUMAN_APPROVED
→ RECOVERY_EXECUTED
→ POSTCONDITION_RECHECK
→ RESOLVED | STILL_FAILED
```

Only `register_missing_invoice` is allowlisted. AI may explain evidence; it cannot decide
invariant truth, approve recovery or mark an incident resolved.

## Planning versus external dispatch

Migration `0010_release_groundwork_fencing` and the canonical service separate plan
construction from side-effect authorization.

When external writes are disabled:

- invariant evaluation and bounded plan creation remain available;
- approve, reject and revoke remain available under their human/scope/state/hash rules;
- authoritative reconciliation and verification remain available;
- evidence export and read-only history remain available;
- only creation of a new provider-write reservation and the write itself are rejected.

This boundary prevents the kill switch from stranding an existing ambiguous reservation or
blocking an operator from rejecting/revoking an unused plan.

## Approval contract

Approval is bound to:

- authenticated human principal ID and name;
- exact scope `recovery:approve`;
- incident ID and reviewed state `recovery_proposed`;
- exact plan hash;
- provider-contract and guardrail digests;
- exact append-only approval decision ID;
- approval timestamp and expiry.

Changing plan/contract/guardrails or incident state invalidates execution authority.
Service accounts cannot approve.

## Durable semantic attempt

One recovery plan has at most one semantic attempt. `PREPARED` records intent before any
provider reservation. It does not mean a write happened. A `PREPARED` attempt may be
superseded by authoritative external resolution only through exact optimistic CAS and only
when no transport reservation exists.

## Transport reservation authority

Every provider invocation has its own durable `RecoveryTransportInvocation` boundary:

- reservation and attempt IDs;
- approval decision and invocation ordinal;
- request digest and reservation timestamp;
- state;
- dispatch owner, generation, start and lease expiry;
- explicit abandonment timestamp/actor/reason;
- reconciliation owner, generation, start and lease expiry;
- reconciliation abandonment;
- typed outcome, operation reference, retry-after and safe projection;
- completion timestamp and lock version.

Dispatch completion may update the lifecycle only through CAS on the exact reservation ID,
`DISPATCHING` state, dispatch owner/generation, current lock version, live lease and
non-abandoned authority, plus the matching attempt active-reservation ID/state/version.
Late completion after lease expiry or takeover is discarded and returns
`reconciliation_required`; it is not reported as successful execution and does not produce
a `recovery_executed` audit event.

## Explicit abandonment and takeover

A live `DISPATCHING` reservation cannot be reconciled. After its dispatch lease expires, a
reconciler may claim it by atomically:

1. recording dispatch abandonment with reason `dispatch_lease_expired`;
2. switching the reservation to `RECONCILING`;
3. assigning a new reconciliation owner and incremented generation;
4. assigning a reconciliation lease;
5. CAS-transitioning the matching active attempt to `RECONCILING`.

A live reconciliation lease cannot be stolen. Expired reconciliation claims may be taken
over with another generation; the prior claim is preserved in claim history. A stale
reconciler that later returns an observation cannot overwrite the newer owner or terminal
result because completion CAS requires exact owner/generation/lock/live lease.

## Append-only reconciliation history

Each authorizing or terminal reconciliation entry preserves:

- exact reservation ID, or explicit null for a zero-dispatch PREPARED reconciliation;
- typed authoritative observation;
- reconciliation timestamp;
- prior attempt and reservation states;
- transport invocation count;
- reapproval action and retry reason;
- typed provider write outcome when one exists;
- reconciliation claim owner, generation, reservation/attempt lock versions, lease and
  reason.

History is append-only. It is not replaced by a weaker last-observation summary.

## External resolution convergence

Two paths are distinct.

### No provider reservation

```text
proposed | approved plan, no attempt/reservation
or PREPARED attempt with zero reservation
→ exact state check/CAS
→ clear unused approval
→ plan superseded
→ append external_resolution system decision
→ incident resolved
```

The prepared-attempt path records `SUPERSEDED_EXTERNAL_RESOLUTION`. It proves no provider
reservation existed and no provider write occurred.

### Active or ambiguous provider reservation

An invariant PASS does not overwrite `approved`, `executing` or `needs_attention` state.
The observation is recorded as pending convergence. Resolution requires the exact active
reservation to reach `EFFECT_PRESENT` through fenced authoritative reconciliation, followed
by postcondition verification bound to that reservation. Only then may the attempt become
`VERIFIED`, the plan `verified` and the incident `resolved`.

The forbidden state is:

```text
incident = resolved
+
plan = approved | executing | needs_attention
without explicit converged lifecycle evidence
```

## Evidence capsule policy

Capsule schema `1.1` is bound to migration `0010_release_groundwork_fencing` and exports the
full reservation lifecycle. The verifier checks dispatch/reconciliation owner, generation,
lease, abandonment, lock-version and CAS genealogy.

Two proof paths remain separate:

- external resolution without provider write: plan `superseded`, zero reservations,
  cleared approval and exactly one system `external_resolution` decision;
- resolved after provider write: verified attempt, exact active `EFFECT_PRESENT`
  reservation, typed provider outcome, authoritative reread and postcondition bound to the
  same reservation.

Capsule `1.0` is never silently reinterpreted as `1.1`; verification requires explicit
legacy opt-in. Review-subject and bundle digests remain deterministic, but neither digest
is a signer identity or readiness certificate.
