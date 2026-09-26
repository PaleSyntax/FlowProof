# Commit plan

Suggested commits:

1. `chore: bootstrap FlowProof monorepo`
2. `feat: add authenticated business event ingestion`
3. `feat: implement policy evaluation and incidents`
4. `feat: add external verification and invoice chaos demo`
5. `feat: add approved compensation workflow`
6. `feat: add operator dashboard`
7. `test: cover demo paths and validate n8n artifacts`
8. `docs: publish architecture demo and limitations`

Rules:

- no dependency folders;
- no `.env`;
- no database volumes;
- no secrets;
- each commit passes relevant checks;
- final history may have fewer commits, but not one opaque dump;
- never force-push.
