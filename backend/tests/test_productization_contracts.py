from __future__ import annotations

import copy
import json
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT / "quality" / "productization" / "windows-install-session.schema.json"
)
TEMPLATE_PATH = (
    ROOT / "quality" / "productization" / "windows-install-session.template.json"
)
BLOCKED_SESSION_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-install-session-2026-08-06.blocked.json"
)
UAC_BLOCKED_SESSION_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-install-session-2026-08-06.uac-blocked.json"
)
CANDIDATE_3_BLOCKED_SESSION_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-install-session-2026-08-06.candidate3-blocked.json"
)
CANDIDATE_3_ORCHESTRATION_BLOCKED_SESSION_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-install-session-2026-08-08.candidate3-orchestration-blocked.json"
)
CANDIDATE_3_CROSS_USER_BLOCKED_SESSION_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-install-session-2026-08-08.candidate3-cross-user-blocked.json"
)
FRESH_PROFILE_RUNNER_PATH = (
    ROOT / "quality" / "productization" / "run-fresh-local-profile.ps1"
)
FRESH_PROFILE_ORCHESTRATOR_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "Invoke-FreshLocalProfileProof.ps1"
)
FRESH_PROFILE_LAUNCHER_PATH = (
    ROOT / "quality" / "productization" / "Start-FreshLocalProfileProof.ps1"
)
HYPERV_PREFLIGHT_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "Get-HyperVQualificationPreflight.ps1"
)
N8N_GUIDED_SCHEMA_PATH = (
    ROOT / "quality" / "productization" / "n8n-guided-connection.schema.json"
)
N8N_GUIDED_EVIDENCE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "n8n-guided-connection-2026-08-06.json"
)
N8N_GUIDED_CANDIDATE_EVIDENCE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "n8n-guided-connection-candidate.2-2026-08-06.json"
)
N8N_GUIDED_CANDIDATE_3_EVIDENCE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "n8n-guided-connection-candidate.3-2026-08-06.json"
)
WINDOWS_CANDIDATE_2_EVIDENCE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-candidate-asset-candidate.2-2026-08-06.json"
)
WINDOWS_CANDIDATE_3_EVIDENCE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-candidate-asset-candidate.3-2026-08-06.json"
)
WINDOWS_UPDATE_EVIDENCE_PATH = (
    ROOT
    / "quality"
    / "productization"
    / "windows-update-candidate2-to-candidate3-2026-08-06.json"
)
CANDIDATE_2_SHA256 = (
    "00454dc55b27e8a05b2264733cf09ff0918d8a79df4490fb909386ee71675ac1"
)
CANDIDATE_3_SHA256 = (
    "7d46dc2905912c10619ce9badb02914021f06bc3a96f5cdb04bbb3c4ffcfcfc6"
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    schema = _load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _passing_session() -> dict[str, object]:
    session = copy.deepcopy(_load(TEMPLATE_PATH))
    session.update(
        {
            "session_id": str(uuid4()),
            "started_at": "2026-08-06T10:00:00Z",
            "completed_at": "2026-08-06T10:12:00Z",
            "tester_role": "independent Windows n8n operator",
            "result": "PASS",
        }
    )
    session["environment"].update(
        {"windows_version": "Windows 11 24H2", "architecture": "x86_64"}
    )
    session["artifact"].update(
        {
            "filename": "FlowProof-Windows-x86_64.zip",
            "sha256": "a" * 64,
            "git_commit": "b" * 40,
            "git_tree": "c" * 40,
        }
    )
    session["metrics"].update(
        {
            "download_to_running_seconds": 420,
            "running_to_first_demo_outcome_seconds": 240,
            "mandatory_decision_count": 3,
            "terminal_command_count": 0,
            "manual_secret_handoff_count": 0,
            "support_intervention_count": 0,
            "install_failure_count": 0,
        }
    )
    for stage_name, stage in session["stages"].items():
        stage.update(
            {
                "status": "PASS",
                "evidence": [f"evidence/{stage_name}.json"],
            }
        )
    session["security"].update(
        {
            "credentials_in_artifact": False,
            "env_file_in_artifact": False,
            "database_in_artifact": False,
            "raw_customer_data_in_artifact": False,
        }
    )
    return session


def test_windows_install_session_schema_accepts_unexecuted_template() -> None:
    _validator().validate(_load(TEMPLATE_PATH))


def test_windows_install_session_schema_accepts_exact_fresh_machine_blocker() -> None:
    session = _load(BLOCKED_SESSION_PATH)
    _validator().validate(session)
    assert session["result"] == "BLOCKED"
    assert session["stages"]["prerequisite_check"]["status"] == "BLOCKED"
    assert "FRESH_WINDOWS_ENVIRONMENT_REQUIRED" in session["blocker"]


def test_windows_install_session_schema_accepts_uac_blocked_profile_attempt() -> None:
    session = _load(UAC_BLOCKED_SESSION_PATH)
    _validator().validate(session)
    assert session["result"] == "BLOCKED"
    assert session["environment"]["profile_type"] == "fresh_local_profile"
    assert session["environment"]["source_checkout_present"] is False
    assert session["stages"]["prerequisite_check"]["status"] == "BLOCKED"
    assert session["metrics"]["terminal_command_count"] == 0
    assert session["metrics"]["manual_secret_handoff_count"] == 0
    assert "FRESH_LOCAL_PROFILE_UAC_APPROVAL_REQUIRED" in session["blocker"]

    candidate_3 = _load(CANDIDATE_3_BLOCKED_SESSION_PATH)
    _validator().validate(candidate_3)
    assert candidate_3["artifact"]["sha256"] == CANDIDATE_3_SHA256
    assert candidate_3["result"] == "BLOCKED"
    assert candidate_3["stages"]["install"]["status"] == "NOT_RUN"

    orchestration_blocked = _load(CANDIDATE_3_ORCHESTRATION_BLOCKED_SESSION_PATH)
    _validator().validate(orchestration_blocked)
    assert orchestration_blocked["artifact"]["sha256"] == CANDIDATE_3_SHA256
    assert orchestration_blocked["result"] == "BLOCKED"
    assert orchestration_blocked["metrics"]["install_failure_count"] == 1
    assert "ELEVATED_PROCESS_EXIT_1_NO_EVIDENCE" in orchestration_blocked["blocker"]

    cross_user_blocked = _load(CANDIDATE_3_CROSS_USER_BLOCKED_SESSION_PATH)
    _validator().validate(cross_user_blocked)
    assert cross_user_blocked["artifact"]["sha256"] == CANDIDATE_3_SHA256
    assert cross_user_blocked["stages"]["prerequisite_check"]["status"] == "PASS"
    assert cross_user_blocked["stages"]["install"]["status"] == "BLOCKED"
    assert "CROSS_USER_DOCKER_BIND_MOUNT_UNAVAILABLE" in cross_user_blocked["blocker"]


def test_windows_install_session_pass_requires_complete_golden_path() -> None:
    validator = _validator()
    session = _passing_session()
    validator.validate(session)

    for field, rejected_value in (
        ("terminal_command_count", 1),
        ("manual_secret_handoff_count", 1),
        ("install_failure_count", 1),
        ("mandatory_decision_count", 8),
        ("running_to_first_demo_outcome_seconds", 901),
    ):
        invalid = copy.deepcopy(session)
        invalid["metrics"][field] = rejected_value
        assert list(validator.iter_errors(invalid)), field

    from_checkout = copy.deepcopy(session)
    from_checkout["environment"]["source_checkout_present"] = True
    assert list(validator.iter_errors(from_checkout))

    missing_evidence = copy.deepcopy(session)
    missing_evidence["stages"]["safe_demo"]["evidence"] = []
    assert list(validator.iter_errors(missing_evidence))


def test_windows_install_session_cannot_promote_not_run_to_pass() -> None:
    validator = _validator()
    session = _load(TEMPLATE_PATH)
    session["result"] = "PASS"
    assert list(validator.iter_errors(session))


def test_fresh_profile_runner_preserves_install_session_truth_boundary() -> None:
    source = FRESH_PROFILE_RUNNER_PATH.read_text(encoding="utf-8")

    for required in (
        'profile_type = "fresh_local_profile"',
        "source_checkout_present = $false",
        "terminal_command_count = 0",
        "manual_secret_handoff_count = 0",
        'result = "PASS"',
        'blocker = $null',
        'result = $failureResult',
        'blocker = "FRESH_LOCAL_PROFILE_STAGE_FAILED: stage=$currentStage; $message"',
        'stages = $failureStages',
        'git_commit = $GitCommit',
        'git_tree = $GitTree',
        'if ($blocker.Length -gt 500)',
        '[Parameter(Mandatory)][string]$DockerDesktopOwner',
        'Security.AccessControl.FileSystemAccessRule',
        'if ($installAttempted -or $installed -or $preserved)',
        "function Initialize-QualificationAppliance",
        "New-FlowProofApplianceConfiguration -DataRoot $DataRoot -SkipAcl",
        '"up", "-d", "--wait", "postgres", "mock-accounting"',
        "Invoke-FlowProofMigration -DataRoot $layout.Root",
        'Invoke-FlowProofAdminBootstrap -DataRoot $Root',
        "Write-FlowProofState $layout.Root",
        '"/demo/false-200/start"',
        '"/recovery-plans/$($plan.id)/approve"',
        '"/recovery-plans/$($plan.id)/execute"',
        '"/recovery-plans/$($plan.id)/verify"',
        '"DELETE FLOWPROOF DATA"',
    ):
        assert required in source

    assert source.count('status = "PASS"') == 9
    assert "Get-FileHash -Algorithm SHA256" in source
    assert "credentials_in_artifact = $false" in source
    assert "raw_customer_data_in_artifact = $false" in source


def test_fresh_profile_orchestrator_is_disposable_and_does_not_persist_password() -> None:
    source = FRESH_PROFILE_ORCHESTRATOR_PATH.read_text(encoding="utf-8")

    for required in (
        "#Requires -RunAsAdministrator",
        'New-LocalUser -Name $userName',
        'Add-LocalGroupMember -Group "docker-users"',
        "-Credential $credential -LoadUserProfile",
        "Remove-LocalUser -Name $userName",
        "$profile | Remove-CimInstance",
        "$passwordText = $null",
        "[IO.Directory]::Delete($taskRoot, $true)",
        "function Write-OrchestrationFailure",
        "System.Web.Script.Serialization.JavaScriptSerializer",
        "Write-JsonPayload -Path $ResultPath",
        'blocker = "FRESH_LOCAL_PROFILE_ORCHESTRATION_FAILED: $message"',
        'git_commit = $GitCommit',
        'git_tree = $GitTree',
        '"-GitCommit", $GitCommit',
        '"-GitTree", $GitTree',
        '"-DockerDesktopOwner"',
        'Write-Diagnostic -Event "orchestrator_started"',
        'Write-Diagnostic -Event "probe_completed"',
        "$failureRecord = $_",
        "Write-OrchestrationFailure $failureRecord",
    ):
        assert required in source

    assert "ConvertTo-Json" not in source
    assert "Set-Content" not in source
    assert "password.txt" not in source.lower()
    assert len("Temporary FlowProof qualification user") <= 48


def test_fresh_profile_launcher_guarantees_parent_side_evidence() -> None:
    source = FRESH_PROFILE_LAUNCHER_PATH.read_text(encoding="utf-8")

    for required in (
        '-Verb RunAs -WindowStyle Hidden -Wait -PassThru',
        "function Write-ParentEvidence",
        "function Read-DiagnosticEvidence",
        "function Test-InstallSessionShape",
        "FRESH_LOCAL_PROFILE_ELEVATION_LAUNCH_FAILED",
        "FRESH_LOCAL_PROFILE_PROBE_ONLY_COMPLETED",
        "FRESH_LOCAL_PROFILE_ELEVATED_PROCESS_EXITED_WITHOUT_RESULT",
        "System.Web.Script.Serialization.JavaScriptSerializer",
        "[IO.File]::WriteAllText($ResultPath",
        'Move-Item -LiteralPath $ResultPath -Destination $invalidChildPath',
        "FRESH_LOCAL_PROFILE_CHILD_RESULT_CONTRACT_INVALID",
        'manual_secret_handoff_count = 0',
        "Get-Content -LiteralPath $DiagnosticsPath -Encoding UTF8",
    ):
        assert required in source

    assert "$passwordText" not in source
    assert "ConvertTo-SecureString" not in source
    assert "PSCredential" not in source
    assert "RedirectStandard" not in source


def test_hyperv_preflight_is_read_only_and_preserves_truth_boundaries() -> None:
    source = HYPERV_PREFLIGHT_PATH.read_text(encoding="utf-8")

    for required in (
        "READ_ONLY_HYPERV_FRESH_WINDOWS_QUALIFICATION_PREFLIGHT",
        "mutating_actions_performed = $false",
        "OWNER_APPROVED_WINDOWS_MEDIA_REQUIRED",
        "READY_FOR_OWNER_AUTHORIZED_BUILD",
        "Host-installed Docker Desktop is not available inside Windows Sandbox",
        "qualification experiment",
        "Get-WindowsOptionalFeature -Online",
        "Get-VM | Select-Object",
        "Get-VMSwitch | Select-Object",
        "Get-FileHash -LiteralPath $resolvedArtifactPath -Algorithm SHA256",
        "Refusing to overwrite existing preflight evidence",
    ):
        assert required in source

    for forbidden in (
        "Enable-WindowsOptionalFeature",
        "Disable-WindowsOptionalFeature",
        "New-VM",
        "Remove-VM",
        "Set-VMProcessor",
        "New-VHD",
        "Invoke-WebRequest",
        "Start-BitsTransfer",
    ):
        assert forbidden not in source


def test_n8n_guided_connection_evidence_proves_only_its_exact_boundary() -> None:
    schema = _load(N8N_GUIDED_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    evidence = _load(N8N_GUIDED_EVIDENCE_PATH)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(evidence)

    assert evidence["result"] == "PASS"
    assert evidence["real_n8n_execution_proven"] is True
    assert evidence["real_provider_observation_proven"] is False
    assert evidence["manual_flowproof_token_copying"] is False
    assert evidence["n8n_api_key_persisted_by_flowproof"] is False
    assert evidence["flowproof_connection"]["service_scopes"] == [
        "events:write",
        "recovery:execute",
        "recovery:verify",
    ]
    assert all(evidence["cleanup"].values())

    candidate_evidence = _load(N8N_GUIDED_CANDIDATE_EVIDENCE_PATH)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        candidate_evidence
    )
    assert candidate_evidence["runtime_scope"] == (
        "EXTRACTED_CANDIDATE_LOCAL_QUALIFICATION"
    )
    assert candidate_evidence["source_checkout_used_for_runtime"] is False
    assert candidate_evidence["artifact"]["sha256"] == CANDIDATE_2_SHA256

    candidate_3_evidence = _load(N8N_GUIDED_CANDIDATE_3_EVIDENCE_PATH)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        candidate_3_evidence
    )
    assert candidate_3_evidence["source_checkout_used_for_runtime"] is False
    assert candidate_3_evidence["artifact"]["sha256"] == CANDIDATE_3_SHA256


def test_windows_candidate_2_evidence_keeps_external_gates_explicit() -> None:
    evidence = _load(WINDOWS_CANDIDATE_2_EVIDENCE_PATH)
    assert evidence["candidate"]["sha256"] == CANDIDATE_2_SHA256
    assert evidence["candidate_source_inventory"]["recomputed_digest_match"] is True
    assert evidence["image_bundle"]["docker_load_result"] == "PASS"
    assert evidence["lifecycle"] == {
        "source_checkout_used_for_runtime": False,
        "duration_seconds": 149.56,
        "verdict": "PASS",
        "stage_count": 8,
        "passed_stage_count": 8,
        "confirmed_full_delete": True,
    }
    assert evidence["n8n_guided_connection"]["result"] == "PASS"
    assert evidence["n8n_guided_connection"]["manual_flowproof_token_copying"] is False
    assert evidence["truth_boundary"] == {
        "real_n8n_execution_proven": True,
        "fixture_evidence_classification": "LOCAL_REAL_N8N_TEST_FIXTURE_ONLY",
        "real_provider_proven": False,
        "fresh_machine_proven": False,
        "signed_asset_proven": False,
        "github_release_download_proven": False,
    }


def test_windows_candidate_3_evidence_covers_update_and_packaging_boundaries() -> None:
    evidence = _load(WINDOWS_CANDIDATE_3_EVIDENCE_PATH)
    assert evidence["candidate"]["sha256"] == CANDIDATE_3_SHA256
    assert evidence["candidate"]["bytes"] == 262_524_606
    assert evidence["candidate_source_inventory"] == {
        "filename": "candidate-source-inventory.json",
        "file_count": 14,
        "image_count": 4,
        "recomputed_digest_match": True,
    }
    assert evidence["image_bundle"]["docker_load_result"] == "PASS"
    assert evidence["image_bundle"]["candidate_tags_missing_before_lifecycle"] is (
        True
    )
    assert all(evidence["packaging"].values())
    assert evidence["lifecycle"] == {
        "source_checkout_used_for_runtime": False,
        "duration_seconds": 128.324,
        "verdict": "PASS",
        "stage_count": 8,
        "passed_stage_count": 8,
        "confirmed_full_delete": True,
    }
    assert evidence["update"]["result"] == "PASS"
    assert evidence["update"]["backup_first"] is True
    assert evidence["update"]["data_preserved"] is True
    assert evidence["update"]["injected_failure_rollback"] is True
    assert evidence["update"]["previous_configuration_restored_ready"] is True
    assert evidence["update"]["same_version_rejected_before_mutation"] is True
    assert evidence["n8n_guided_connection"]["result"] == "PASS"
    assert evidence["truth_boundary"] == {
        "real_n8n_execution_proven": True,
        "fixture_evidence_classification": "LOCAL_REAL_N8N_TEST_FIXTURE_ONLY",
        "real_provider_proven": False,
        "fresh_machine_proven": False,
        "signed_asset_proven": False,
        "github_release_download_proven": False,
    }


def test_candidate_2_to_3_update_evidence_is_backup_first_and_source_free() -> None:
    evidence = _load(WINDOWS_UPDATE_EVIDENCE_PATH)
    assert evidence["verdict"] == "PASS"
    assert evidence["source_checkout_used_for_runtime"] is False
    assert evidence["from_artifact"]["sha256"] == CANDIDATE_2_SHA256
    assert evidence["to_artifact"]["sha256"] == CANDIDATE_3_SHA256
    assert [stage["name"] for stage in evidence["stages"]] == [
        "source_candidate_install",
        "failure_rollback",
        "backup_first_update",
        "same_version_rejected",
        "confirmed_cleanup",
    ]
    assert all(stage["status"] == "PASS" for stage in evidence["stages"])
    rollback = evidence["stages"][1]["evidence"]
    assert rollback["previous_configuration_restored"] is True
    assert rollback["service_health"] == "READY"
    assert rollback["persisted_admin_count"] == 1
    update = evidence["stages"][2]["evidence"]
    assert update["from_version"] == "0.5.0-productization-candidate.2"
    assert update["to_version"] == "0.5.0-productization-candidate.3"
    assert update["backup_sidecars"] is True
    assert update["data_preserved"] is True
    assert update["persisted_admin_count_before"] == 1
    assert update["persisted_admin_count_after"] == 1
