# Runtime policies

Codex should copy the validated invoice policy from:

`specs/policies/invoice-processing.yaml`

into this runtime directory, preserving schema/version metadata.

Runtime policy loading must fail clearly when:

- schema invalid;
- invariant ID duplicated;
- duration invalid;
- verifier unknown;
- recovery action unregistered.
