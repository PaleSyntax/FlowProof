from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

ALLOWED_INVARIANTS = {
    "exactly_once",
    "eventually",
    "ordering",
    "value_matches",
    "external_assertion",
}


class PolicyValidationError(ValueError):
    pass


def canonical_hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_policy(path: Path, schema_path: Path | None = None) -> dict[str, Any]:
    try:
        definition = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyValidationError(f"cannot load policy {path}: {exc}") from exc
    if not isinstance(definition, dict):
        raise PolicyValidationError("policy must be a YAML object")

    if schema_path and schema_path.exists():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        try:
            jsonschema.Draft202012Validator(schema).validate(definition)
        except jsonschema.ValidationError as exc:
            raise PolicyValidationError(f"policy schema validation failed: {exc.message}") from exc

    invariant_ids: set[str] = set()
    for invariant in definition.get("invariants", []):
        invariant_id = invariant.get("id")
        invariant_type = invariant.get("type")
        if not invariant_id or invariant_id in invariant_ids:
            raise PolicyValidationError("invariant IDs must be unique and non-empty")
        if invariant_type not in ALLOWED_INVARIANTS:
            raise PolicyValidationError(f"unsupported invariant type: {invariant_type}")
        invariant_ids.add(invariant_id)
    return definition
