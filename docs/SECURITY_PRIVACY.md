# Security and privacy

## Threat model summary

FlowProof receives workflow data and can trigger compensation actions. It crosses meaningful trust boundaries.

## Secrets

Never store:

- n8n credentials;
- authorization headers;
- cookies;
- OAuth refresh tokens;
- API keys;
- private keys.

The event contract supports metadata, not credential transport.

## Ingestion authentication

Implemented local MVP:

- opaque Bearer credentials HMAC-peppered before storage; only metadata and a prefix are returned;
- persistent per-service scope envelopes, bounded expiry, atomic rotation and revocation;
- fixed n8n scope envelope that cannot approve recovery;
- no raw token in workflow JSON, browser storage, URLs, logs, or audit details;
- deprecated header aliases only when explicitly enabled for development and never in production.

Still needed before shared deployment:

- mTLS or signed events and an externally managed secret system.

## Payload minimization

For invoice demo, allowed:

- invoice ID;
- amount;
- currency;
- status;
- external request ID.

Avoid:

- full PDF;
- bank details;
- personal addresses;
- raw email;
- attachments.

## Redaction

Before logs and persistence:

- recursive key denylist;
- auth header removal;
- string length limits;
- object depth limits;
- optional event-specific allowlist.

## HTTP

- body limits;
- timeouts;
- exact CORS origin;
- safe errors;
- no stack traces to browser;
- locked dependencies;
- health endpoint contains no secrets.

## Database

- least-privilege account;
- no public Postgres port unless needed locally;
- parameterized queries;
- migrations;
- unique idempotency constraints;
- retention documented.

## Recovery

- explicit allowlist;
- a human `operator`/`admin` session with `recovery:approve` and current CSRF; service credentials are denied;
- immutable plan hash;
- idempotency;
- postcondition verification;
- no arbitrary URL from browser;
- external base URLs server-configured.

## n8n workflow exports

Must not include:

- real credential IDs;
- secrets;
- pinned personal data;
- personal webhook paths;
- production hostnames.

## LLM

- optional;
- sanitized inputs;
- strict schema;
- no tools;
- no autonomous repair;
- provider key backend-only.

## Demo credentials

Any default demo credential is non-production and must fail closed under `FLOWPROOF_ENV=production`.

## Production deployment foundation

Production configuration reads `FLOWPROOF_TOKEN_PEPPER_FILE` and the database password from secret files; Compose mounts distinct files for the n8n encryption key, n8n service token and alert webhook destination. Values are not build arguments, Git-tracked files, log fields or backup filenames. The deployment preflight checks that each required file is non-empty and owner-only before services start.

The backup runner writes custom-format dumps, checksums and metadata to a protected destination. It never restores production implicitly; restore proof targets an isolated database. Operators must place the backup directory on encrypted storage or an equivalent protected destination and rotate a secret by replacing its file, restarting the affected service and revoking the prior credential where applicable.
