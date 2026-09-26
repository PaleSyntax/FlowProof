from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WINDOWS_ROOT = ROOT / "productization" / "windows"
COMPOSE_PATH = WINDOWS_ROOT / "docker-compose.appliance.yml"
MANIFEST_PATH = WINDOWS_ROOT / "appliance-manifest.json"


def test_repository_docker_context_excludes_productization_assets_and_audit_dirs() -> None:
    patterns = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
    assert "dist" in patterns
    assert ".pytest-*" in patterns


def test_windows_appliance_compose_preserves_fixture_and_loopback_boundaries() -> None:
    compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = compose["services"]
    assert set(services) == {
        "postgres",
        "mock-accounting",
        "migrate",
        "api",
        "scheduler",
        "alert-worker",
        "ops-watcher",
        "web",
    }
    assert all("build" not in service for service in services.values())
    assert "n8n" not in services
    assert "ports" not in services["postgres"]
    assert "ports" not in services["mock-accounting"]
    assert services["api"]["ports"] == ["127.0.0.1:8000:8000"]
    assert services["web"]["ports"] == ["127.0.0.1:8080:8080"]
    environment = services["api"]["environment"]
    assert environment["FLOWPROOF_ENV"] == "local-appliance"
    assert environment["FLOWPROOF_CORS_ORIGIN"] == "http://127.0.0.1:8080"
    assert environment["FLOWPROOF_PROVIDER_CONTRACT_PATH"].endswith(
        "/mock-accounting/contract.json"
    )
    assert environment["FLOWPROOF_RECOVERY_WRITES_ENABLED"] == "true"
    assert environment["FLOWPROOF_SESSION_COOKIE_SECURE"] == "false"
    assert "FLOWPROOF_TOKEN_PEPPER" not in environment
    assert environment["FLOWPROOF_TOKEN_PEPPER_FILE"] == "/run/secrets/token_pepper"
    postgres_volume = services["postgres"]["volumes"][0]
    assert postgres_volume == {
        "type": "bind",
        "source": "${FLOWPROOF_POSTGRES_DATA_DIR:?FLOWPROOF_POSTGRES_DATA_DIR is required}",
        "target": "/var/lib/postgresql/data",
    }


def test_windows_appliance_manifest_is_explicitly_unbuilt() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["artifact_status"] == "DEVELOPMENT_UNBUILT"
    assert manifest["git_commit"] is None
    assert manifest["git_tree"] is None
    assert manifest["git_coordinate_scope"] == "DEVELOPMENT_WORKTREE"
    assert manifest["candidate_source_sha256"] is None
    assert manifest["built_at"] is None
    assert manifest["image_bundle"] is None
    assert manifest["update_contract"] == {
        "channel": "0.6.0",
        "target_version": None,
        "accepted_from": ["0.5.0-productization-candidate.4"],
        "database_schema": "0010_release_groundwork_fencing",
        "rollback_scope": "SAME_SCHEMA_CONFIGURATION_AND_SERVICES",
    }
    assert manifest["code_signing"] == "UNSIGNED_DEVELOPMENT"
    assert manifest["evidence_classification"] == "TEST_FIXTURE_ONLY"
    assert manifest["recovery_write_boundary"] == "MOCK_ACCOUNTING_FIXTURE_ONLY"
    assert "n8n" not in manifest["images"]
    assert "@sha256:" in manifest["images"]["postgres"]


def test_powershell_lifecycle_parses_and_generates_secret_free_environment(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    scripts = [
        WINDOWS_ROOT / "FlowProof.Runtime.psm1",
        WINDOWS_ROOT / "FlowProof.Artifacts.psm1",
        WINDOWS_ROOT / "FlowProof.N8n.psm1",
        WINDOWS_ROOT / "FlowProof-Controller.ps1",
        WINDOWS_ROOT / "Build-FlowProofWindowsAsset.ps1",
        ROOT / "quality" / "productization" / "run-current-host-lifecycle.ps1",
        ROOT / "quality" / "productization" / "run-fresh-local-profile.ps1",
        ROOT
        / "quality"
        / "productization"
        / "Invoke-FreshLocalProfileProof.ps1",
        ROOT
        / "quality"
        / "productization"
        / "Start-FreshLocalProfileProof.ps1",
        ROOT
        / "quality"
        / "productization"
        / "run-n8n-guided-connection.ps1",
        ROOT
        / "quality"
        / "productization"
        / "run-windows-update-lifecycle.ps1",
    ]
    for script in scripts:
        parse_command = (
            "$tokens=$null;$errors=$null;"
            f"[Management.Automation.Language.Parser]::ParseFile('{script}',"
            "[ref]$tokens,[ref]$errors)|Out-Null;"
            "if($errors.Count -gt 0){$errors|ForEach-Object{$_.Message};exit 1};"
            "exit 0"
        )
        subprocess.run(
            [powershell, "-NoProfile", "-Command", parse_command],
            check=True,
            capture_output=True,
            text=True,
        )

    data_root = tmp_path / "FlowProof Data"
    runtime = WINDOWS_ROOT / "FlowProof.Runtime.psm1"
    configuration_command = (
        f"Import-Module '{runtime}' -Force;"
        f"$layout=New-FlowProofApplianceConfiguration -DataRoot '{data_root}' -SkipAcl;"
        "$layout|ConvertTo-Json -Compress"
    )
    subprocess.run(
        [powershell, "-NoProfile", "-Command", configuration_command],
        check=True,
        capture_output=True,
        text=True,
    )
    environment_text = (data_root / "appliance.env").read_text(encoding="utf-8")
    token_pepper = (data_root / "secrets" / "token_pepper").read_text(
        encoding="utf-8"
    ).strip()
    postgres_password = (data_root / "secrets" / "postgres_password").read_text(
        encoding="utf-8"
    ).strip()
    assert len(token_pepper) >= 32
    assert len(postgres_password) >= 32
    assert token_pepper not in environment_text
    assert postgres_password not in environment_text
    assert "TOKEN_PEPPER=" not in environment_text
    assert "POSTGRES_PASSWORD=" not in environment_text
    assert str(data_root).replace("\\", "/") in environment_text


def test_artifacts_module_does_not_hide_runtime_commands() -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    runtime = WINDOWS_ROOT / "FlowProof.Runtime.psm1"
    artifacts = WINDOWS_ROOT / "FlowProof.Artifacts.psm1"
    command = (
        f"Import-Module '{runtime}' -Force;"
        f"Import-Module '{artifacts}' -Force;"
        "$runtimeCommand=Get-Command Initialize-FlowProofAppliance "
        "-ErrorAction SilentlyContinue;"
        "$artifactCommands=@(Get-Command New-FlowProofBackup,"
        "Update-FlowProofAppliance "
        "-ErrorAction SilentlyContinue);"
        "if($null -eq $runtimeCommand -or $artifactCommands.Count -ne 2){exit 1};"
        "exit 0"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_windows_migration_retries_only_transient_connection_startup_races() -> None:
    runtime_source = (WINDOWS_ROOT / "FlowProof.Runtime.psm1").read_text(
        encoding="utf-8"
    )
    artifacts_source = (WINDOWS_ROOT / "FlowProof.Artifacts.psm1").read_text(
        encoding="utf-8"
    )
    fresh_profile_source = (
        ROOT / "quality" / "productization" / "run-fresh-local-profile.ps1"
    ).read_text(encoding="utf-8")

    for required in (
        "function Invoke-FlowProofMigration",
        "[ValidateRange(1, 30)][int]$MaxAttempts = 12",
        "connection refused",
        "connection failed",
        "could not connect",
        "server closed the connection unexpectedly",
        "if (-not $transientConnectionFailure -or $attempt -eq $MaxAttempts)",
        "Start-Sleep -Seconds $RetryDelaySeconds",
        '"Invoke-FlowProofMigration"',
    ):
        assert required in runtime_source

    assert runtime_source.count('@("run", "--rm", "migrate")') == 1
    assert "Invoke-FlowProofMigration -DataRoot $layout.Root" in artifacts_source
    assert "Invoke-FlowProofMigration -DataRoot $layout.Root" in fresh_profile_source


def test_n8n_module_does_not_hide_runtime_or_artifact_commands() -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    runtime = WINDOWS_ROOT / "FlowProof.Runtime.psm1"
    artifacts = WINDOWS_ROOT / "FlowProof.Artifacts.psm1"
    n8n = WINDOWS_ROOT / "FlowProof.N8n.psm1"
    command = (
        f"Import-Module '{runtime}' -Force;"
        f"Import-Module '{artifacts}' -Force;"
        f"Import-Module '{n8n}' -Force;"
        "$commands=@(Get-Command Initialize-FlowProofAppliance,"
        "New-FlowProofBackup,Connect-FlowProofN8n -ErrorAction SilentlyContinue);"
        "if($commands.Count -ne 3){exit 1};exit 0"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_restart_excludes_one_shot_migration_service() -> None:
    runtime_text = (WINDOWS_ROOT / "FlowProof.Runtime.psm1").read_text(encoding="utf-8")
    restart_body = runtime_text.split("function Restart-FlowProofAppliance", maxsplit=1)[
        1
    ].split("function Open-FlowProofDashboard", maxsplit=1)[0]
    assert '"api", "scheduler", "alert-worker", "ops-watcher", "web"' in restart_body
    assert 'Invoke-FlowProofCompose $DataRoot @("restart")' not in restart_body
    assert '"migrate"' not in restart_body


def test_update_is_backup_first_compatible_and_rolls_back_configuration() -> None:
    artifacts = (WINDOWS_ROOT / "FlowProof.Artifacts.psm1").read_text(
        encoding="utf-8"
    )
    update_body = artifacts.split("function Update-FlowProofAppliance", maxsplit=1)[
        1
    ].split("function Uninstall-FlowProofAppliance", maxsplit=1)[0]
    assert "update_contract.accepted_from" in update_body
    assert "update_contract.database_schema" in update_body
    assert "New-FlowProofBackup" in update_body
    assert "Import-FlowProofBundledImages" in update_body
    assert update_body.index("New-FlowProofBackup") < update_body.index(
        "Import-FlowProofBundledImages"
    )
    assert "Write-FlowProofArtifactText $layout.Environment $previousEnvironment" in (
        update_body
    )
    assert "Write-FlowProofArtifactText $layout.State $previousState" in update_body
    assert "Wait-FlowProofReady" in update_body
    assert "previous application configuration is running again" in update_body

    controller = (WINDOWS_ROOT / "FlowProof-Controller.ps1").read_text(
        encoding="utf-8"
    )
    assert '"Update" { Update-FlowProofAppliance' in controller
    assert 'Name="UpdateButton"' in controller
    assert "Update first creates a database backup" in controller


def test_candidate_asset_bundles_exact_images_and_verifies_before_install() -> None:
    runtime_text = (WINDOWS_ROOT / "FlowProof.Runtime.psm1").read_text(
        encoding="utf-8"
    )
    initialize_body = runtime_text.split(
        "function Initialize-FlowProofAppliance", maxsplit=1
    )[1].split("function Get-FlowProofStatus", maxsplit=1)[0]
    assert "Import-FlowProofBundledImages" in initialize_body
    assert initialize_body.index("Import-FlowProofBundledImages") < initialize_body.index(
        "New-FlowProofApplianceConfiguration"
    )
    assert "Get-FileHash -Algorithm SHA256" in runtime_text
    assert 'Invoke-FlowProofDocker @("image", "load", "--input", $archive)' in runtime_text

    builder = (WINDOWS_ROOT / "Build-FlowProofWindowsAsset.ps1").read_text(
        encoding="utf-8"
    )
    assert "docker-image-save-tar" in builder
    assert "UNSIGNED_CANDIDATE" in builder
    assert "UNSIGNED_SMARTSCREEN_GATE" in builder
    assert "BASE_COMMIT_AND_TREE_WITH_WORKTREE_CANDIDATE_DIGEST" in builder
    assert "image save --output" in builder
    assert "Compress-Archive -LiteralPath $payload" in builder
    assert '"FlowProof.N8n.psm1"' in builder
    assert 'Join-Path $payload "n8n-workflows"' in builder
    assert "exactly four managed n8n workflows" in builder
    assert '"candidate-source-inventory.json"' in builder
    assert "$computedCandidateSourceSha256" in builder
    assert "The supplied candidate-source digest does not match" in builder
    assert "versioned candidate image reference" in builder
    assert "update_contract.target_version" in builder


def test_windows_start_here_contains_required_showable_packaging_sections() -> None:
    start_here = (WINDOWS_ROOT / "README-Windows.txt").read_text(encoding="utf-8")
    for heading in (
        "START HERE",
        "30-SECOND PITCH",
        "3-MINUTE SAFE DEMO",
        "SUPPORTED",
        "NOT SUPPORTED OR NOT YET PROVEN",
        "BACKUP, UPDATE AND UNINSTALL",
    ):
        assert heading in start_here
    assert "TEST_FIXTURE_ONLY" in start_here
    assert "DELETE FLOWPROOF DATA" in start_here
    assert "not store the n8n API key" in start_here


def test_update_proof_is_source_free_backup_first_and_cleans_up() -> None:
    proof = (
        ROOT / "quality" / "productization" / "run-windows-update-lifecycle.ps1"
    ).read_text(encoding="utf-8")
    assert 'source_checkout_used_for_runtime = $false' in proof
    assert "Assert-Artifact $FromArtifact $FromSha256" in proof
    assert "Assert-Artifact $ToArtifact $ToSha256" in proof
    assert 'Add-Stage "backup_first_update"' in proof
    assert 'Add-Stage "failure_rollback"' in proof
    assert "injected_missing_image_reference" in proof
    assert "previous_configuration_restored" in proof
    assert 'Add-Stage "same_version_rejected"' in proof
    assert 'DataDeletionConfirmation "DELETE FLOWPROOF DATA"' in proof
    assert "[IO.Directory]::Delete($WorkingRoot, $true)" in proof


def test_n8n_guided_connection_has_fixed_scope_and_cleanup_boundaries() -> None:
    source = (WINDOWS_ROOT / "FlowProof.N8n.psm1").read_text(encoding="utf-8")

    for scope in ("events:write", "recovery:execute", "recovery:verify"):
        assert f'"{scope}"' in source
    assert "recovery:approve" not in source
    assert 'Headers = @{ "X-N8N-API-KEY" = $plainApiKey }' in source
    assert 'value = "Bearer $serviceToken"' in source
    assert "api_key_persisted_by_flowproof = $false" in source
    assert "manual_flowproof_token_copying = $false" in source
    assert '"revoke-token", "--credential-id"' in source
    assert '"DELETE"' in source
    assert "$serviceToken = $null" in source
    assert "ZeroFreeBSTR" in source
    assert "MaximumRedirection = 0" in source


def test_n8n_guided_connection_rejects_insecure_remote_urls() -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    module = WINDOWS_ROOT / "FlowProof.N8n.psm1"
    command = (
        f"Import-Module '{module}' -Force;"
        "$module=Get-Module FlowProof.N8n;"
        "$local=& $module { Resolve-FlowProofConnectionUrl "
        "'http://127.0.0.1:5678' 'n8n' };"
        "$secure=& $module { Resolve-FlowProofConnectionUrl "
        "'https://n8n.example.test/base' 'n8n' };"
        "if($local -cne 'http://127.0.0.1:5678' -or "
        "$secure -cne 'https://n8n.example.test/base'){exit 2};"
        "foreach($invalid in @('http://n8n.example.test','https://user:pass@n8n.example.test')){"
        "try{& $module { param($value) Resolve-FlowProofConnectionUrl $value 'n8n' } "
        "$invalid;exit 3}catch{}};exit 0"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_n8n_workflow_rendering_replaces_only_connection_coordinates() -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    module = WINDOWS_ROOT / "FlowProof.N8n.psm1"
    template = ROOT / "workflows" / "invoice-intake.json"
    command = (
        f"Import-Module '{module}' -Force;"
        "$module=Get-Module FlowProof.N8n;"
        f"$body=& $module {{ ConvertTo-FlowProofN8nWorkflow '{template}' "
        "'https://flowproof.example.test' 'credential-123' };"
        "$body|ConvertTo-Json -Depth 30 -Compress"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )
    rendered = json.loads(result.stdout.strip().splitlines()[-1])
    serialized = json.dumps(rendered)
    assert "http://api:8000" not in serialized
    assert "https://flowproof.example.test" in serialized
    credential_ids = {
        node["credentials"]["httpHeaderAuth"]["id"]
        for node in rendered["nodes"]
        if "credentials" in node and "httpHeaderAuth" in node["credentials"]
    }
    assert credential_ids == {"credential-123"}
    assert set(rendered) <= {
        "name",
        "nodes",
        "connections",
        "settings",
        "staticData",
        "pinData",
    }


def test_frontend_default_api_origin_follows_the_appliance_hostname() -> None:
    api_source = (ROOT / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
    assert "new URL(window.location.href)" in api_source
    assert "pageOrigin.port = '8000'" in api_source
    assert "http://localhost:8000/api/v1" not in api_source


def test_full_data_deletion_fails_before_runtime_without_exact_confirmation(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    artifacts = WINDOWS_ROOT / "FlowProof.Artifacts.psm1"
    data_root = tmp_path / "protected-data"
    command = (
        f"Import-Module '{artifacts}' -Force;"
        "try {"
        f"Uninstall-FlowProofAppliance -DataRoot '{data_root}' -DeleteData "
        "-DataDeletionConfirmation 'wrong';exit 2"
        "} catch {if($_.Exception.Message -notmatch 'exact confirmation'){exit 3}};"
        "exit 0"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
