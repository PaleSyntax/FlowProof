FlowProof Windows local appliance candidate

START HERE

1. Install and start Docker Desktop for Windows.
2. Extract the complete FlowProof Windows ZIP to a normal user folder.
3. Double-click "FlowProof Launcher.vbs".
4. Choose a data folder, enter an administrator name and password, then choose
   "Install / repair local appliance".
5. Open FlowProof and run the clearly labelled TEST_FIXTURE_ONLY safe demo.

No Git, Python, Node.js, PostgreSQL, terminal command, .env editing, or manual
FlowProof token copying is required. Docker Desktop is the only external runtime
prerequisite and is not bundled.

30-SECOND PITCH

FlowProof checks whether a business-critical n8n automation produced the right
external business outcome, not merely whether its execution was green. It links
events across executions, evaluates deterministic invariants, shows causal
evidence, requires human approval for one narrow recovery action and resolves an
incident only after a new authoritative reread. It is not a workflow editor,
heartbeat dashboard or autonomous retry agent.

3-MINUTE SAFE DEMO

1. Open FlowProof and select the TEST_FIXTURE_ONLY false-200 scenario.
2. Start the scenario. The mock accounting API returns 200 while omitting the
   invoice, so the n8n-style execution is green but the business outcome is not.
3. Open the entity timeline. Inspect the source event, deterministic invariant,
   missing authoritative observation and evidence-backed incident.
4. Review the bounded recovery plan and approve it as the human operator.
5. Execute the single allowlisted compensation and verify the independent reread.
6. Confirm that the incident resolves only after the invoice is observed.

CONNECT AN EXISTING N8N INSTANCE

Enter its URL, an owner-created n8n Public API key and the FlowProof URL reachable
from n8n. FlowProof creates one encrypted least-privilege credential and four
workflow templates directly in n8n. It does not store the n8n API key, expose a
FlowProof token or grant recovery approval to the service principal.

OPTIONAL XERO DEMO OBSERVE-ONLY CHECK

Create a native/desktop Xero test app with the localhost callback documented in
the product guide. In Guided setup, enter only its public Client ID and complete
browser consent. FlowProof verifies exactly one active Demo Company, reads one
exact invoice, evaluates amount/currency deterministically and lets the named
operator save bounded JSON evidence. No client secret, access-token copy,
refresh token or provider write is part of this path. A real provider result is
not claimed until that owner-authorized check is actually completed.

SUPPORTED

- Windows 11 x86_64 with Docker Desktop using Linux containers.
- One local FlowProof appliance bound to loopback ports 8000 and 8080.
- The bundled TEST_FIXTURE_ONLY demo and guided n8n 2.30.5 provisioning.
- Start, stop, restart, sanitized diagnostics, database backup and
  preserve-by-default uninstall from the controller.
- Update only from a version explicitly named by this asset's update contract;
  the controller creates a backup before switching application images.

NOT SUPPORTED OR NOT YET PROVEN

- A real accounting provider or customer outcome without owner browser consent,
  a safe entity and a named operator.
- Provider recovery writes; real-provider onboarding is observe-only.
- Shared/multi-tenant production, high availability or an external secret manager.
- Docker Desktop installation, automatic Windows prerequisite installation or
  offline Docker Desktop distribution.
- A frictionless signed install: this candidate is unsigned and Windows
  SmartScreen may show a warning.
- Update from an unlisted version, database-schema downgrade or automatic restore
  across incompatible schemas.

BACKUP, UPDATE AND UNINSTALL

Use "Backup data" before maintenance. "Update from this asset" first verifies the
installed version and database schema, creates a custom-format PostgreSQL backup,
loads checksum-bound versioned images and preserves the data folder. A failed
same-schema update restores the previous service configuration and reports the
backup path.

"Uninstall (preserve data)" removes services and the Start Menu shortcut but keeps
the selected data folder. Full data deletion is available only through the
separate exact confirmation phrase "DELETE FLOWPROOF DATA". Export sanitized
diagnostics from the controller when a step fails; diagnostics exclude generated
secrets, database files and raw customer payloads.
