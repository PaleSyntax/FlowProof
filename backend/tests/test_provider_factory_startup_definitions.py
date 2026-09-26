from __future__ import annotations

import json
from pathlib import Path

import pytest

from flowproof.accounting import ProviderContract
from flowproof.config import Settings
from flowproof.main import create_app
from flowproof.provider_factory import (
    PROVIDER_ADAPTER_REGISTRY,
    ProviderAdapterRegistration,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = (
    ROOT
    / "specs"
    / "providers"
    / "mock-accounting"
    / "contract.json"
)


def _settings(contract_path: Path) -> Settings:
    return Settings(
        database_url="sqlite://",
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://provider.invalid",
        policy_path=(
            ROOT
            / "specs"
            / "policies"
            / "invoice-processing.yaml"
        ),
        environment="test",
        provider_contract_path=contract_path,
        token_pepper=(
            "provider-startup-test-pepper-with-at-least-"
            "thirty-two-characters"
        ),
    )


def test_unknown_provider_contract_fails_before_application_startup(
    tmp_path: Path,
) -> None:
    base = ProviderContract.load(CONTRACT_PATH)
    contract = ProviderContract(
        **{
            **base.to_manifest(include_digest=False),
            "provider_id": "owner-coordinates-not-supplied",
        }
    )
    path = tmp_path / "unknown-provider.json"
    path.write_text(
        json.dumps(contract.to_manifest()),
        encoding="utf-8",
    )
    with pytest.raises(
        RuntimeError,
        match="provider adapter configuration is invalid",
    ):
        create_app(_settings(path))


def test_constructorless_registry_entry_fails_before_application_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = ProviderContract.load(CONTRACT_PATH)
    path = tmp_path / "constructorless-provider.json"
    path.write_text(
        json.dumps(contract.to_manifest()),
        encoding="utf-8",
    )
    monkeypatch.setitem(
        PROVIDER_ADAPTER_REGISTRY,
        contract.provider_id,
        ProviderAdapterRegistration(
            provider_id=contract.provider_id,
            constructor=None,
            adapter_kind="constructor-not-supplied",
            evidence_boundary="UNVERIFIED",
            owner_coordinates_required=True,
        ),
    )
    with pytest.raises(
        RuntimeError,
        match="provider adapter configuration is invalid",
    ):
        create_app(_settings(path))
