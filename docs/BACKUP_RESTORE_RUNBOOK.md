# Backup and restore runbook

## Backup contract

`deploy/scripts/backup.sh` creates a PostgreSQL `pg_dump` custom-format archive, SHA-256
checksum and timestamped JSON metadata. It requires `FLOWPROOF_BACKUP_DIR`, creates it with
owner-only permissions and deletes only files matching its own `flowproof-*.dump` retention
pattern. Failed `.partial` dumps, checksums and metadata are removed before retention can see
them. Credentials never appear in file names or normal script output.

The directory must be on encrypted storage or be protected by an equivalent company-controlled
access policy. Copying an unencrypted dump to a laptop, a ticket or source control is prohibited.

## Backup procedure

```bash
FLOWPROOF_BACKUP_DIR=/srv/flowproof-backups \
  deploy/scripts/backup.sh --retain 14
```

Verify all three artifacts exist: `.dump`, `.sha256`, `.json`. The metadata records timestamp,
format, database name, checksum and Alembic head, never a URL or password.

## Restore proof

Restore only into an isolated database/Compose project:

```bash
FLOWPROOF_RESTORE_SENTINELS_FILE=/srv/flowproof-restore-sentinels.tsv \
  deploy/scripts/restore-proof.sh --isolated /srv/flowproof-backups/flowproof-<timestamp>.dump
```

The runner refuses a destination that does not include the explicit isolated flag. It verifies:

- archive checksum;
- Alembic head;
- principals and credential metadata;
- sessions and security-audit rows;
- business events, incidents, recovery plans and deadline jobs;
- alert outbox, service heartbeats and `operational_alert_states`;
- application-level readiness against the restored database.

## Production restore guard

No script overwrites the production database by default. A real recovery needs an incident
decision, an approved maintenance window, a separately typed destructive target and an operator
record. Restore application data first in isolation, decide whether schema/image compatibility is
safe, then follow the company change procedure.
