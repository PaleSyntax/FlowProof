# Source links and version notes

## n8n baseline

Verified release page on 2026-07-30 showed stable:

- n8n `2.30.5`, released 2026-07-15
- https://github.com/n8n-io/n8n/releases

Codex should record the exact image actually used.

## Security

Critical advisory affecting old versions:

- https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg

The pinned 2.x baseline is beyond the patched threshold, but updates/security review remain required.

## Why retry is not enough

Official retry behavior:

- https://docs.n8n.io/workflows/executions/all-executions/

Retrying a technical execution is not automatically safe after partial side effects.

## License note

n8n is fair-code/source-available under its licenses. Do not describe n8n itself as MIT/open-source without qualification.

FlowProof's license is a separate user decision. Do not copy n8n source code.
