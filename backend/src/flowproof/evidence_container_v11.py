"""Exact deterministic ZIP container and manifest contract for evidence v1.1."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from flowproof import evidence_legacy_v1_core as strict
from flowproof.evidence_contract import (
    CAPSULE_SCHEMA_VERSION,
    FIXED_ZIP_TIME,
    MANIFEST_KEYS,
    REQUIRED_MEMBERS,
    REVIEW_SUBJECT_EXCLUDED,
    EvidenceError,
)


def build_manifest(
    documents: dict[str, bytes],
    incident_id: str,
) -> dict[str, Any]:
    if set(documents) != REQUIRED_MEMBERS:
        raise EvidenceError("evidence document member set is incomplete")
    declarations = [
        {
            "name": name,
            "size": len(content),
            "sha256": strict._sha256(content),
        }
        for name, content in sorted(documents.items())
    ]
    coordinates = json.loads(documents["release-coordinates.json"])
    provider = json.loads(documents["provider-contract.json"])
    policy = json.loads(documents["policy.json"])
    incident = json.loads(documents["incident.json"])
    review = [
        item
        for item in declarations
        if item["name"] not in REVIEW_SUBJECT_EXCLUDED
    ]
    return {
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "proof_type": coordinates["proof_type"],
        "package_version": coordinates["package_version"],
        "git_commit": coordinates["git_commit"],
        "git_tree": coordinates["git_tree"],
        "migration_head": coordinates["migration_head"],
        "evidence_classification": coordinates[
            "evidence_classification"
        ],
        "incident_id": incident_id,
        "correlation_id": incident["correlation_id"],
        "policy_name": policy["name"],
        "policy_version": policy["version"],
        "policy_hash": policy["definition_hash"],
        "provider_contract_digest": provider["sha256"],
        "files": declarations,
        "review_subject_sha256": strict._sha256(
            strict._json_bytes(review)
        ),
        "review_subject_digest_scope": (
            "all declared non-manifest members except "
            "operator-review.json and audit-references.json"
        ),
        "bundle_sha256": strict._sha256(
            strict._json_bytes(declarations)
        ),
        "bundle_digest_scope": (
            "every declared non-manifest member exactly once; "
            "manifest.json is the root"
        ),
    }


def write_capsule(
    path: Path,
    documents: dict[str, bytes],
    manifest: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    members = {
        "manifest.json": strict._json_bytes(manifest),
        **documents,
    }
    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_STORED,
        strict_timestamps=True,
    ) as archive:
        for name, content in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)


def read_capsule(
    path: Path,
    *,
    expected_bundle_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not strict.SHA256.fullmatch(expected_bundle_sha256):
        raise EvidenceError(
            "expected bundle trust anchor is not a SHA-256 digest"
        )
    if not path.is_file():
        raise EvidenceError("capsule file is missing")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise EvidenceError("capsule contains duplicate ZIP names")
            if any(not safe_member(name) for name in names):
                raise EvidenceError("capsule contains an unsafe member name")
            if names.count("manifest.json") != 1:
                raise EvidenceError(
                    "manifest.json is missing or duplicated"
                )
            manifest = json.loads(archive.read("manifest.json"))
            if (
                not isinstance(manifest, dict)
                or set(manifest) != MANIFEST_KEYS
            ):
                raise EvidenceError(
                    "manifest schema contains missing or unknown fields"
                )
            declarations = manifest.get("files")
            if not isinstance(declarations, list):
                raise EvidenceError(
                    "manifest files declaration is invalid"
                )

            declared_names: list[str] = []
            canonical: list[dict[str, Any]] = []
            documents: dict[str, Any] = {}
            for declaration in declarations:
                if (
                    not isinstance(declaration, dict)
                    or set(declaration)
                    != {"name", "size", "sha256"}
                ):
                    raise EvidenceError(
                        "manifest file declaration schema is invalid"
                    )
                name = declaration.get("name")
                size = declaration.get("size")
                digest = declaration.get("sha256")
                if (
                    not isinstance(name, str)
                    or not safe_member(name)
                    or name == "manifest.json"
                    or not isinstance(size, int)
                    or isinstance(size, bool)
                    or size < 1
                    or not isinstance(digest, str)
                    or not strict.SHA256.fullmatch(digest)
                ):
                    raise EvidenceError(
                        "manifest contains an invalid member declaration"
                    )
                declared_names.append(name)
                content = archive.read(name)
                actual_digest = strict._sha256(content)
                if len(content) != size or actual_digest != digest:
                    raise EvidenceError(
                        f"digest or size mismatch for {name}"
                    )
                try:
                    value = json.loads(content)
                except json.JSONDecodeError as exc:
                    raise EvidenceError(
                        f"invalid JSON member: {name}"
                    ) from exc
                documents[name] = value
                canonical.append(
                    {
                        "name": name,
                        "size": len(content),
                        "sha256": actual_digest,
                    }
                )
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise EvidenceError("capsule ZIP container is invalid") from exc

    if len(declared_names) != len(set(declared_names)):
        raise EvidenceError("manifest contains duplicate declarations")
    if set(declared_names) != REQUIRED_MEMBERS:
        raise EvidenceError(
            "manifest member set is not the required schema"
        )
    if set(names) != {"manifest.json", *declared_names}:
        raise EvidenceError(
            "actual ZIP members do not exactly match manifest declarations"
        )

    canonical.sort(key=lambda item: item["name"])
    bundle = strict._sha256(strict._json_bytes(canonical))
    if (
        bundle != manifest.get("bundle_sha256")
        or bundle != expected_bundle_sha256
    ):
        raise EvidenceError(
            "bundle content digest or external bundle trust anchor mismatch"
        )
    review = [
        item
        for item in canonical
        if item["name"] not in REVIEW_SUBJECT_EXCLUDED
    ]
    if strict._sha256(strict._json_bytes(review)) != manifest.get(
        "review_subject_sha256"
    ):
        raise EvidenceError(
            "operator review subject digest mismatch"
        )
    for name, value in documents.items():
        strict._assert_secret_free(value, name)
    return manifest, documents


def peek_schema_version(path: Path) -> object:
    if not path.is_file():
        raise EvidenceError("capsule file is missing")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise EvidenceError("capsule contains duplicate ZIP names")
            if any(not safe_member(name) for name in names):
                raise EvidenceError("capsule contains an unsafe member name")
            if names.count("manifest.json") != 1:
                raise EvidenceError(
                    "manifest.json is missing or duplicated"
                )
            manifest = json.loads(archive.read("manifest.json"))
    except (
        KeyError,
        OSError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
    ) as exc:
        raise EvidenceError("capsule manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise EvidenceError("capsule manifest is invalid")
    return manifest.get("schema_version")


def safe_member(name: object) -> bool:
    if not isinstance(name, str) or not name:
        return False
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in name
        and name == path.as_posix()
    )
