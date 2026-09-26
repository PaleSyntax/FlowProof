"""Backfill service-account scope envelopes from active credential rows.

Revision ID: 0005_identity_scope_envelope_backfill
Revises: 0004_identity_authorization_hardening
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "0005_identity_scope_envelope_backfill"
down_revision = "0004_identity_authorization_hardening"
branch_labels = None
depends_on = None

VALID_SCOPES = frozenset(
    {
        "events:write",
        "read:operations",
        "evaluations:write",
        "recovery:approve",
        "recovery:execute",
        "recovery:verify",
        "chaos:write",
        "identity:manage",
        "audit:read",
    }
)
N8N_SCOPES = frozenset({"events:write", "recovery:execute", "recovery:verify"})


def _valid_scopes(value: object) -> set[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return set()
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    return {scope for scope in value if isinstance(scope, str) and scope in VALID_SCOPES}


def _is_n8n_account(name: str) -> bool:
    return name == "n8n" or name.startswith("n8n-")


def upgrade() -> None:
    bind = op.get_bind()
    principals = sa.table(
        "principals",
        sa.column("id", sa.String()),
        sa.column("allowed_scopes", sa.JSON()),
    )
    rows = bind.execute(sa.text("SELECT id, name, kind FROM principals")).mappings()
    for principal in rows:
        principal_id = principal["id"]
        if principal["kind"] != "service":
            allowed_scopes: list[str] = []
        else:
            credential_rows = bind.execute(
                sa.text(
                    "SELECT scopes FROM api_credentials "
                    "WHERE principal_id = :principal_id AND revoked_at IS NULL"
                ),
                {"principal_id": principal_id},
            ).mappings()
            union = set().union(
                *(_valid_scopes(credential["scopes"]) for credential in credential_rows)
            )
            if _is_n8n_account(principal["name"]) and not union <= N8N_SCOPES:
                # Do not alter or revoke legacy credentials. An empty envelope
                # fails closed once runtime authorization checks the envelope.
                allowed_scopes = []
            else:
                allowed_scopes = sorted(union)
        bind.execute(
            principals.update()
            .where(principals.c.id == principal_id)
            .values(allowed_scopes=allowed_scopes)
        )


def downgrade() -> None:
    op.execute("UPDATE principals SET allowed_scopes = '[]'")
