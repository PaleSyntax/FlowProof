# Environment-owned n8n integration contract

`docker-compose.integration-n8n.yml` is an optional integration profile, not
part of `docker-compose.production.yml`. The company owns its n8n version,
storage, editor exposure, DNS/TLS, backups, operator access and acceptance of
its vulnerability advisory report.

After core migration and API health, run
`deploy/scripts/create-n8n-service-credential.sh`. It manages exactly one
`n8n-flowproof` service principal and an owner-only token file. The principal
and issued token are constrained to `events:write`, `recovery:execute`, and
`recovery:verify`; a service token cannot approve recovery. The raw token is
returned once, written atomically, and is neither logged nor placed in a
container environment or Docker metadata.

The normal rerun validates the existing owner file and does not create a
principal or token. To rotate, the owner sets
`FLOWPROOF_N8N_CREDENTIAL_ROTATE=true`, runs the script, and promptly runs
`deploy/scripts/provision-n8n.sh` to import the replacement into n8n's encrypted
credential store. Revoke the superseded FlowProof credential under the company
change procedure after confirming the new workflow execution. Committed n8n
exports use the fixed credential ID and contain no raw token.
