from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_OUTPUT = (
    "Release status check passed: 0.6.0 / PORTFOLIO_RELEASE_CANDIDATE / "
    "LOCAL_PORTFOLIO_RELEASE_READY / NOT_VERIFIED_EXTERNAL / "
    "NOT_VERIFIED_EXTERNAL / BRANCH_PUBLISHED"
)


def test_release_status_contract_has_independent_evidence_axes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release_status.py")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == EXPECTED_OUTPUT


def test_release_status_keeps_portfolio_and_external_claims_separate() -> None:
    status = json.loads((ROOT / "release" / "STATUS.json").read_text(encoding="utf-8"))
    assert status["schema_version"] == 5
    assert status["package_version"] == "0.6.0"
    assert status["portfolio_release"] == {
        "classification": "PORTFOLIO_RELEASE_CANDIDATE",
        "publication_state": "BRANCH_PUBLISHED",
        "repository_visibility": "PUBLIC",
        "target_tag": "v0.6.0",
        "professional_destination": "https://github.com/PaleSyntax/FlowProof",
    }
    assert {
        name: axis["status"] for name, axis in status["acceptance_axes"].items()
    } == {
        "portfolio_release": "LOCAL_PORTFOLIO_RELEASE_READY",
        "real_provider": "NOT_VERIFIED_EXTERNAL",
        "fresh_windows": "NOT_VERIFIED_EXTERNAL",
        "company_production": "NOT_CLAIMED",
    }
    assert status["current_implementation"]["migration_head"] == (
        "0010_release_groundwork_fencing"
    )
    assert status["current_implementation"]["fixture_classification"] == (
        "TEST_FIXTURE_ONLY"
    )
    assert status["current_implementation"]["xero_recovery_write"] == "NOT_IMPLEMENTED"
    assert status["accepted_baseline"]["version"] == "0.5.0"
    assert status["accepted_baseline"]["pull_request"] == 8
    assert status["accepted_baseline"]["pull_request_state"] == "MERGED"
