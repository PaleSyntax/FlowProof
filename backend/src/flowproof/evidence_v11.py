"""Thin evidence capsule v1.1 orchestration with declared proof paths."""

from __future__ import annotations

import argparse
from pathlib import Path

from sqlalchemy.orm import Session

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_attempt_genealogy import validate_attempts
from flowproof.evidence_container_v11 import (
    build_manifest,
    peek_schema_version,
    read_capsule,
    write_capsule,
)
from flowproof.evidence_contract import (
    CAPSULE_SCHEMA_VERSION,
    LEGACY_CAPSULE_SCHEMA_VERSION,
    MANIFEST_KEYS,
    MIGRATION_HEAD,
    PROOF_TYPES,
    EvidenceError,
)
from flowproof.evidence_decision_genealogy import validate_decisions
from flowproof.evidence_documents_v11 import build_documents
from flowproof.evidence_proof_paths import PATH_VALIDATORS
from flowproof.evidence_reservation_genealogy import (
    validate_reservations,
)
from flowproof.evidence_semantics import verify_common_semantics


def export_capsule(
    session: Session,
    incident_id: str,
    output: Path,
    *,
    private_identity: bool = False,
) -> dict[str, str]:
    documents = build_documents(
        session,
        incident_id,
        private_identity=private_identity,
    )
    manifest = build_manifest(documents, incident_id)
    write_capsule(output, documents, manifest)
    return {
        "path": str(output),
        "bundle_sha256": manifest["bundle_sha256"],
        "review_subject_sha256": manifest[
            "review_subject_sha256"
        ],
        "zip_sha256": strict._sha256(output.read_bytes()),
        "identity_mode": (
            "owner-private" if private_identity else "sanitized"
        ),
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "proof_type": manifest["proof_type"],
    }


def verify_capsule(
    path: Path,
    *,
    expected_bundle_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    allow_legacy_v1: bool = False,
) -> dict[str, str]:
    """Verify one declared proof path; never downgrade after failure."""

    if not strict.SHA256.fullmatch(expected_bundle_sha256):
        raise EvidenceError(
            "expected bundle trust anchor is not a SHA-256 digest"
        )
    if (
        not strict.GIT_OBJECT_ID.fullmatch(expected_git_commit)
        or not strict.GIT_OBJECT_ID.fullmatch(expected_git_tree)
    ):
        raise EvidenceError(
            "expected Git trust anchors are invalid"
        )

    schema_version = peek_schema_version(path)
    if schema_version == LEGACY_CAPSULE_SCHEMA_VERSION:
        if not allow_legacy_v1:
            raise EvidenceError(
                "legacy capsule v1.0 requires explicit allow_legacy_v1 policy"
            )
        return strict.verify_capsule(
            path,
            expected_bundle_sha256=expected_bundle_sha256,
            expected_git_commit=expected_git_commit,
            expected_git_tree=expected_git_tree,
        )
    if schema_version != CAPSULE_SCHEMA_VERSION:
        raise EvidenceError(
            "unsupported capsule schema version"
        )

    manifest, documents = read_capsule(
        path,
        expected_bundle_sha256=expected_bundle_sha256,
    )
    if set(manifest) != MANIFEST_KEYS:
        raise EvidenceError(
            "manifest schema is inconsistent"
        )
    proof_type = manifest.get("proof_type")
    if proof_type not in PROOF_TYPES:
        raise EvidenceError(
            "manifest proof type is invalid"
        )
    validator = PATH_VALIDATORS.get(str(proof_type))
    if validator is None:
        raise EvidenceError(
            "declared proof path has no verifier"
        )
    coordinates = documents.get("release-coordinates.json")
    if (
        manifest.get("migration_head") != MIGRATION_HEAD
        or not isinstance(coordinates, dict)
        or coordinates.get("migration_head") != MIGRATION_HEAD
        or coordinates.get("proof_type") != proof_type
    ):
        raise EvidenceError(
            "capsule migration head or proof type is inconsistent"
        )

    context = verify_common_semantics(
        manifest,
        documents,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
        proof_type=str(proof_type),
    )
    decisions = validate_decisions(
        context,
        proof_type=str(proof_type),
    )
    reservations = validate_reservations(
        context,
        decisions,
    )
    validate_attempts(
        context,
        decisions,
        reservations,
    )
    validator(
        context,
        decisions,
        reservations,
    )
    return {
        "status": "VALID",
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "migration_head": MIGRATION_HEAD,
        "bundle_sha256": expected_bundle_sha256,
        "git_commit": expected_git_commit,
        "git_tree": expected_git_tree,
        "proof_path": str(proof_type),
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        prog="python -m flowproof.evidence",
        description="Export or verify FlowProof evidence capsules",
    )
    commands = value.add_subparsers(
        dest="command",
        required=True,
    )
    export = commands.add_parser("export")
    export.add_argument("--incident-id", required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument(
        "--private-identity",
        action="store_true",
    )
    verify = commands.add_parser("verify")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument(
        "--expected-bundle-sha256",
        required=True,
    )
    verify.add_argument(
        "--expected-git-commit",
        required=True,
    )
    verify.add_argument(
        "--expected-git-tree",
        required=True,
    )
    verify.add_argument(
        "--allow-legacy-v1",
        action="store_true",
    )
    return value


__all__ = [
    "CAPSULE_SCHEMA_VERSION",
    "LEGACY_CAPSULE_SCHEMA_VERSION",
    "MIGRATION_HEAD",
    "EvidenceError",
    "build_documents",
    "export_capsule",
    "parser",
    "verify_capsule",
]
