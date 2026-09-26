# Security policy

## Supported versions

Security fixes are prepared for the latest published minor line. During the `0.6.0` portfolio release-candidate phase, only the current `0.6.x` head is in scope.

FlowProof is not a certified production service. The bundled Mock Accounting service is `TEST_FIXTURE_ONLY`, Xero is observe-only, and the Windows asset is unsigned.

## Reporting a vulnerability

Please use the repository's **Security → Report a vulnerability** private reporting flow. Do not open a public issue containing an exploit, credential, personal data, provider payload, or customer information.

Include only the minimum information needed to reproduce the issue:

- affected commit or version;
- component and deployment mode;
- reproducible steps or a minimal proof of concept;
- realistic impact and required attacker access;
- whether a secret or real provider account may have been exposed.

If private vulnerability reporting is not available, contact the repository owner through their GitHub profile without sending sensitive details. Wait for a private channel before sharing the report.

## Response expectations

The maintainer will acknowledge a valid private report when it is read, reproduce it, classify the impact, and coordinate a fix and disclosure. This project does not promise a commercial SLA.

## Security boundaries

- Never commit `.env`, credentials, databases, runtime logs, evidence containing raw secrets, or private keys.
- Rotate any credential that may have entered Git history; deleting the visible line is not sufficient.
- Recovery requires a human principal and an exact approved plan; service accounts must not gain `recovery:approve`.
- Do not weaken `TEST_FIXTURE_ONLY`, production configuration, redaction, idempotency, or independent-reread gates to simplify a demo.
- Do not report dependency scanner output as an exploitable FlowProof vulnerability without validating reachability and impact.

See [`docs/SECURITY_PRIVACY.md`](docs/SECURITY_PRIVACY.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the design boundary.
