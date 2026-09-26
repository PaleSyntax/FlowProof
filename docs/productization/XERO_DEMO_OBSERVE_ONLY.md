# Xero Demo observe-only qualification

## Status

The adapter, browser PKCE connection and deterministic qualification route are
implemented and contract-tested. Live qualification remains
`OWNER_AUTHORIZED_PROVIDER_ACCESS_REQUIRED`: no Xero owner consent, safe invoice
or named operator review is present in repository evidence.

## Why this provider path

Xero documents the Demo Company as a dummy-data development organisation. The
Accounting API exposes invoice and organisation reads, and the granular
`accounting.invoices.read` and `accounting.settings.read` scopes are read-only.
Xero's Authorization Code flow with PKCE is intended for clients that cannot
protect a client secret. This gives the invoice outcome pack a real provider
surface without granting FlowProof a recovery write or requiring secret copy.

Official references:

- <https://developer.xero.com/documentation/development-accounts/>
- <https://developer.xero.com/documentation/guides/oauth2/pkce-flow>
- <https://developer.xero.com/documentation/guides/oauth2/scopes>
- <https://developer.xero.com/documentation/api/accounting/invoices>

## Owner-controlled setup

1. Create or reset a Xero Demo Company and a dedicated native/desktop test app.
2. Register exactly
   `http://localhost:8000/api/v1/provider-connections/xero/callback` as its
   redirect URI. `127.0.0.1` is intentionally not used for this callback.
3. Sign in to the FlowProof local appliance and enter only the app's public
   Client ID in **Observe one invoice in Xero Demo Company**.
4. Complete Xero consent in the browser. FlowProof requests `openid`, `profile`,
   `email`, `accounting.invoices.read`, and `accounting.settings.read`; it does
   not request `offline_access` and accepts no client secret.
5. FlowProof reads the connected organisations and fails closed unless exactly
   one active organisation reports `IsDemoCompany=true`.
6. Enter one dummy invoice ID/number, expected total and currency; confirm the
   four bounded operator statements; run the observe-only check and save the
   generated lifecycle JSON.
7. Complete
   `quality/productization/provider-access-request.xero-demo.template.json`
   with the authorization reference, safe entity and named operator. It must
   keep `credential_reference` as `not-applicable`.

## Enforced safety boundary

- PKCE uses an S256 challenge, high-entropy one-time state and a five-minute
  pending authorization lifetime;
- the callback is exact-loopback, state-bound and not session-authenticated;
- no client secret, refresh token or manual access-token copy is accepted;
- the short-lived access token remains only in API process memory and is
  discarded on disconnect, process exit or expiry;
- the adapter rejects every non-Xero API origin, embedded credential, port,
  query or fragment;
- it performs organisation verification plus one percent-encoded invoice
  `GET`, with bounded timeouts and no hidden retry;
- evidence contains only provider/contract identity, expected and observed
  invoice identity/amount/currency/status, digests and named confirmations;
- `write_invoice` performs no HTTP request and returns `READ_ONLY_ADAPTER`;
- missing consent, multiple/non-demo organisations, malformed responses and
  unavailable verification fail closed and cannot become provider PASS.
