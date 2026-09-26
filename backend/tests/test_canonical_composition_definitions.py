from __future__ import annotations

import json
import subprocess
import sys

import pytest

from flowproof._service_runtime_base import _FlowProofRuntimeBase
from flowproof._service_runtime_implementation import (
    _FlowProofRuntimeImplementation,
)
from flowproof.accounting import HttpAccountingClient, HttpMockAccountingClient
from flowproof.models import CorrelationBinding, RecoveryAttempt, RecoveryTransportInvocation
from flowproof.service import FlowProofService


def test_package_import_is_side_effect_free() -> None:
    code = """
import json
import sys
import flowproof
print(json.dumps({
    'models': 'flowproof.models' in sys.modules,
    'service': 'flowproof.service' in sys.modules,
    'provider_factory': 'flowproof.provider_factory' in sys.modules,
    'groundwork_bootstrap': 'flowproof.groundwork_bootstrap' in sys.modules,
}, sort_keys=True))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "groundwork_bootstrap": False,
        "models": False,
        "provider_factory": False,
        "service": False,
    }


def test_public_service_and_models_are_canonical_static_symbols() -> None:
    assert FlowProofService.__name__ == "FlowProofService"
    assert FlowProofService.__module__ == "flowproof.service"
    assert CorrelationBinding.__module__ == "flowproof.models"
    assert RecoveryAttempt.__module__ == "flowproof.models"
    assert RecoveryTransportInvocation.__module__ == "flowproof.models"


def test_only_canonical_service_construction_is_permitted() -> None:
    with pytest.raises(
        TypeError,
        match="private runtime implementation is not executable",
    ):
        _FlowProofRuntimeImplementation()
    with pytest.raises(
        TypeError,
        match="_FlowProofRuntimeBase is inheritance-only",
    ):
        _FlowProofRuntimeBase()

    service = FlowProofService(
        object(),
        "policy.yaml",
        object(),
    )
    assert type(service) is FlowProofService


def test_provider_classes_are_not_monkeypatched() -> None:
    assert HttpAccountingClient.__module__ == "flowproof.accounting"
    assert HttpMockAccountingClient.__module__ == "flowproof.accounting"
