# Environment-owned edge ingress contract

FlowProof does not ship a Caddy or reverse-proxy image. The example
`deploy/examples/caddy/Caddyfile` is an input for the company ingress owner,
not a supported all-in-one topology or security approval.

The owner must configure an exact host, public certificate/TLS, HTTP-to-HTTPS
redirect, bounded request body and timeouts, and preserve `X-Request-ID`,
`X-Forwarded-For`, and `X-Forwarded-Proto` to the private FlowProof API. Route
dashboard traffic, `/api/*`, `/health/live`, and `/health/ready` deliberately.
Metrics must remain private to an approved monitoring source; public `/metrics`
must be denied. The owner also owns DNS, WAF/rate limits, certificate renewal,
network policy and edge telemetry.

Public n8n editor/admin paths are not supported by this repository. If the
company exposes webhook delivery, only explicitly reviewed production webhook
routes may be published; access to the n8n editor travels through a company
private administration path such as VPN, bastion or private bind. In particular
`/n8n/webhook-test/*` is never a public production route.

The reference Caddy image receives an advisory report in CI. Its findings are
not called FlowProof security PASS and require the selected ingress owner's
separate remediation/acceptance decision.
