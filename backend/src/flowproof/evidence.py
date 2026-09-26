"""Public deterministic evidence API and bounded CLI failure contract."""

from __future__ import annotations

import json
import sys

from flowproof import evidence_v11 as v11
from flowproof.config import Settings
from flowproof.db import make_engine, make_session_factory

CAPSULE_SCHEMA_VERSION = v11.CAPSULE_SCHEMA_VERSION
LEGACY_CAPSULE_SCHEMA_VERSION = v11.LEGACY_CAPSULE_SCHEMA_VERSION
MIGRATION_HEAD = v11.MIGRATION_HEAD
EvidenceError = v11.EvidenceError
build_documents = v11.build_documents
export_capsule = v11.export_capsule
verify_capsule = v11.verify_capsule


def _invalid_result(exc: BaseException) -> dict[str, str]:
    message = " ".join(str(exc).split())[:256]
    return {
        "status": "INVALID",
        "error_type": type(exc).__name__,
        "message": message or "evidence operation failed",
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = v11.parser().parse_args(argv)
        if args.command == "export":
            settings = Settings.from_environment()
            factory = make_session_factory(
                make_engine(settings.database_url)
            )
            with factory() as session:
                result = export_capsule(
                    session,
                    args.incident_id,
                    args.output,
                    private_identity=args.private_identity,
                )
        else:
            result = verify_capsule(
                args.input,
                expected_bundle_sha256=(
                    args.expected_bundle_sha256
                ),
                expected_git_commit=args.expected_git_commit,
                expected_git_tree=args.expected_git_tree,
                allow_legacy_v1=args.allow_legacy_v1,
            )
    except (EvidenceError, OSError, ValueError) as exc:
        print(
            json.dumps(
                _invalid_result(exc),
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CAPSULE_SCHEMA_VERSION",
    "LEGACY_CAPSULE_SCHEMA_VERSION",
    "MIGRATION_HEAD",
    "EvidenceError",
    "build_documents",
    "export_capsule",
    "main",
    "verify_capsule",
]
