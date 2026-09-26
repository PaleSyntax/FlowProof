"""Explicit provider-adapter factory for the v0.6.0 safety boundary.

A provider contract is descriptive evidence. It does not authorize FlowProof to route an
unknown provider through a generic HTTP shape. Every provider ID must name a source-
registered constructor; registrations without a constructor fail before application startup.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from flowproof.accounting import (
    AccountingClient,
    HttpAccountingClient,
    HttpMockAccountingClient,
    ProviderContract,
)
from flowproof.xero_demo import XeroDemoAccountingClient

ProviderAdapterConstructor = Callable[
    [str, ProviderContract, str, float],
    AccountingClient,
]


@dataclass(frozen=True, slots=True)
class ProviderAdapterRegistration:
    provider_id: str
    constructor: ProviderAdapterConstructor | None
    adapter_kind: str
    evidence_boundary: str
    owner_coordinates_required: bool


def _mock_accounting_constructor(
    base_url: str,
    contract: ProviderContract,
    environment: str,
    timeout_seconds: float,
) -> AccountingClient:
    adapter_type = HttpMockAccountingClient if environment != "production" else HttpAccountingClient
    return adapter_type(base_url, contract, timeout_seconds=timeout_seconds)


def _xero_demo_constructor(
    base_url: str,
    contract: ProviderContract,
    environment: str,
    timeout_seconds: float,
) -> AccountingClient:
    del environment
    return XeroDemoAccountingClient(base_url, contract, timeout_seconds=timeout_seconds)


PROVIDER_ADAPTER_REGISTRY: dict[str, ProviderAdapterRegistration] = {
    "mock-accounting": ProviderAdapterRegistration(
        provider_id="mock-accounting",
        constructor=_mock_accounting_constructor,
        adapter_kind="flowproof-http-mock-v1",
        evidence_boundary="TEST_FIXTURE_ONLY",
        owner_coordinates_required=False,
    ),
    "xero-demo": ProviderAdapterRegistration(
        provider_id="xero-demo",
        constructor=_xero_demo_constructor,
        adapter_kind="xero-accounting-api-v2-observe-only",
        evidence_boundary="CONTRACT_TESTED_LIVE_OWNER_AUTH_REQUIRED",
        owner_coordinates_required=True,
    ),
}


def require_registered_provider(
    contract: ProviderContract,
) -> ProviderAdapterRegistration:
    registration = PROVIDER_ADAPTER_REGISTRY.get(contract.provider_id)
    if registration is None:
        raise ValueError(
            f"provider_id {contract.provider_id!r} has no explicit FlowProof adapter registration"
        )
    if registration.provider_id != contract.provider_id:
        raise ValueError("provider adapter registration identity is inconsistent")
    if registration.constructor is None:
        raise ValueError(
            f"provider_id {contract.provider_id!r} is registered without a constructor"
        )

    authentication = contract.authentication
    mode = authentication.get("mode")
    reference = authentication.get("credential_reference")
    if not isinstance(mode, str) or not isinstance(reference, str):
        raise ValueError("provider credential reference must remain indirect")
    if (
        not mode.startswith("none")
        and not mode.startswith("oauth2-pkce")
        and reference == "not-applicable"
    ):
        raise ValueError("authenticated providers require an indirect credential reference")
    return registration


def create_provider_adapter(
    base_url: str,
    contract: ProviderContract,
    *,
    environment: str,
    timeout_seconds: float = 5.0,
) -> AccountingClient:
    """Construct one explicitly registered adapter or fail before startup."""

    registration = require_registered_provider(contract)
    constructor = registration.constructor
    if constructor is None:
        raise ValueError(
            f"provider_id {contract.provider_id!r} is registered without a constructor"
        )
    return constructor(base_url, contract, environment, timeout_seconds)
