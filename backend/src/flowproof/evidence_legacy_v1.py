"""Immutable compatibility boundary for strict evidence capsule v1.0."""

from __future__ import annotations

from flowproof import evidence_legacy_v1_core as _core

CAPSULE_SCHEMA_VERSION = _core.CAPSULE_SCHEMA_VERSION
MIGRATION_HEAD = _core.MIGRATION_HEAD
FIXED_ZIP_TIME = _core.FIXED_ZIP_TIME
MANIFEST_KEYS = _core.MANIFEST_KEYS
REVIEW_SUBJECT_EXCLUDED = _core.REVIEW_SUBJECT_EXCLUDED
EvidenceError = _core.EvidenceError
GIT_OBJECT_ID = _core.GIT_OBJECT_ID
SHA256 = _core.SHA256
SECRET_KEY = _core.SECRET_KEY
Settings = _core.Settings
build_documents = _core.build_documents
make_engine = _core.make_engine
make_session_factory = _core.make_session_factory
verify_capsule = _core.verify_capsule
_assert_secret_free = _core._assert_secret_free
_evidence_time = _core._evidence_time
_human_actor_is_bounded = _core._human_actor_is_bounded
_json_bytes = _core._json_bytes
_object_sha256 = _core._object_sha256
_safe_observation = _core._safe_observation
_sha256 = _core._sha256
_time = _core._time
_validate_observation = _core._validate_observation
_validate_plan_semantics = _core._validate_plan_semantics
_validate_write_outcome = _core._validate_write_outcome
