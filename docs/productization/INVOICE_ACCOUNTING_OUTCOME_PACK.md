# Invoice/accounting outcome pack

## Product boundary

This is the first FlowProof vertical: outcome assurance for an n8n invoice
registration workflow. It answers whether the authoritative accounting system
contains exactly one invoice with the expected identity, amount, and currency.
It does not replace the protected workflow, choose accounting truth with an
LLM, or treat a green n8n execution as a verified business outcome.

The pack is locally ready and Xero Demo is the recommended provider path, but
real-provider evidence is still `OWNER_AUTHORIZED_PROVIDER_ACCESS_REQUIRED`.
The Xero adapter is contract-tested only. Mock Accounting and the safe demo
remain `TEST_FIXTURE_ONLY` and cannot clear the live gate.

## Ready assets

- `specs/outcome-packs/invoice-accounting/pack.json` is the machine-readable
  pack contract.
- `policy.observe-only.yaml` is a loadable deterministic policy with no
  recovery section and no recovery action.
- `registration-acknowledged.event.json` is a schema-valid n8n event template;
  replace the safe placeholder identity, workflow coordinates, timestamp,
  amount, and currency with the authorized sandbox values.
- `specs/providers/xero-demo/contract.json` and
  `flowproof/xero_demo.py` define the canonical-host, GET-only Xero Demo path.
- `quality/productization/provider-access-request.xero-demo.template.json`
  prefills public API coordinates and lists the remaining owner input.
- `quality/productization/observe-only-provider-lifecycle.template.json` is the
  evidence record for the first real or partner-controlled observation.

## Correlation contract

Use the provider's exact invoice identifier as `entity_id`. Use one stable
business-process identifier as `correlation_id` across all n8n nodes and
retries. An event retry must preserve the same body and idempotency key; changed
content requires a new idempotency key. Never substitute an n8n execution ID
for the business correlation ID.

The minimum business sequence is:

1. `invoice.validated` with bounded amount and currency.
2. `invoice.approved`.
3. `invoice.registration_requested`.
4. `invoice.registration_acknowledged` after the protected workflow receives
   its normal provider response.
5. FlowProof independently rereads the provider and evaluates the policy.

## Exact adapter contract

The selected path is an owner-authorized Xero Demo Company using Accounting API
2.0 and granular `accounting.invoices.read` plus
`accounting.settings.read`. The source-registered `xero-demo` adapter accepts
only `https://api.xero.com/api.xro/2.0`. Its browser Authorization Code flow
uses PKCE S256, accepts only a public Client ID, requests no `offline_access`,
retains the short-lived access token only in process memory and persists no
token, refresh token or raw Xero payload. A browser-supplied API URL, client
secret or unknown generic provider fails closed.

For the observe-only pilot the adapter may perform only the authorized `GET`
for one exact safe invoice entity. It must map presence, absence, duplicate
records, authentication failure, rate limiting, temporary unavailability,
malformed data, and permanent provider errors into the existing typed
`InvoiceObservation`. The persisted projection is limited to invoice identity,
amount, currency, status, bounded operation/error metadata, timestamp, and a
content digest. Credentials and raw payloads are never evidence.

Contract tests cover one-time state, PKCE scope/secret boundaries, exact active
Demo Company selection, invoice normalization, entity binding, bounded
projection, credential non-disclosure, canonical-host enforcement, typed HTTP
failures and the fail-closed write method. This is not live evidence. A real run
must still complete owner consent, name the operator, bind the exact contract
SHA-256 and record zero provider mutation.

## Observe-only operator playbook

1. Complete the provider-access request with `credential_reference` kept as
   `not-applicable`; put no raw secret in it.
2. Confirm owner authorization is current, limited to `GET`, and names one
   non-customer sandbox invoice.
3. Confirm the Xero app redirect URI is exactly the documented localhost
   callback and complete browser PKCE consent from the local appliance.
4. Confirm `FLOWPROOF_RECOVERY_WRITES_ENABLED=false`.
5. Run the protected n8n lifecycle or select its already-created safe entity.
6. Perform one authoritative read through the registered adapter.
7. Review the deterministic invariant result, entity timeline, and bounded
   observation evidence.
8. Save the lifecycle JSON and prove provider mutation count `0`.

Verifier unavailability is `ERROR`, never PASS. A violated invariant is a valid
observe-only lifecycle result if it produces one deduplicated incident and the
operator can understand the bounded evidence.

## Recovery boundary

Recovery stays disabled. Enabling even one write requires a separate, immediate
owner authorization plus contract-tested provider idempotency, exact
entity/amount/currency/TTL/attempt guardrails, failure-state setup,
rollback/cleanup coordinates, and independent reads before and after the write.
The observe-only authorization cannot be reused as recovery authority.

## External input required

To continue, complete
`quality/productization/provider-access-request.xero-demo.template.json` with
one dummy-data invoice ID and expected amount/currency, authorization
owner/reference/expiry, and the named reviewing operator. Create a native Xero
test app with the exact localhost callback, enter its public Client ID in the
FlowProof UI and complete browser consent. Do not send an authorization code or
token in chat, `.env`, evidence or repository files; FlowProof does not ask the
operator to copy either value.
