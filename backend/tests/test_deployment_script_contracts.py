import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def script(name: str) -> str:
    return (ROOT / "deploy" / "scripts" / name).read_text(encoding="utf-8")


def test_backup_rejects_filesystem_root_before_changing_permissions() -> None:
    contents = script("backup.sh")
    assert '[[ "$backup_dir" != "/" ]]' in contents
    assert contents.index('[[ "$backup_dir" != "/" ]]') < contents.index('chmod 700 "$backup_dir"')
    assert "dump.partial" in contents
    assert "cleanup_partial" in contents
    assert "application_version" in contents
    assert "source_image_revision" in contents


def test_isolated_restore_does_not_replay_source_owners_or_privileges() -> None:
    contents = script("restore-proof.sh")
    restore_command = next(line for line in contents.splitlines() if "pg_restore" in line)
    assert "--no-owner" in restore_command
    assert "--no-privileges" in restore_command
    assert "FLOWPROOF_RESTORE_SENTINELS_FILE" in contents
    assert "restore sentinel mismatch" in contents
    assert "docker exec -i" in contents
    assert "WHERE %s = :'sentinel_id';" in contents
    assert '-Atc "SELECT count(*) FROM $table_name' not in contents
    assert "ready_checks=0" in contents
    assert '[[ "$ready_checks" -ge 3 ]]' in contents
    assert "isolated restore database did not become stable" in contents
    assert "0010_release_groundwork_fencing" in contents
    assert "0008" not in contents


def test_deploy_dispatches_explicit_install_or_upgrade_lifecycle() -> None:
    contents = script("deploy.sh")
    assert 'install) exec bash "$root/deploy/scripts/install.sh"' in contents
    assert 'upgrade) exec bash "$root/deploy/scripts/upgrade.sh"' in contents


def test_static_preflight_has_no_database_or_n8n_token_prerequisite() -> None:
    contents = script("static-preflight.sh")
    assert "n8n_flowproof_token" not in contents
    assert "database-preflight" not in contents
    assert "FLOWPROOF_API_IMAGE" in contents
    assert "validate_image_reference" in contents
    assert "require_file_owner_uid" in contents


def test_shellcheck_can_follow_each_dynamic_common_helper_source() -> None:
    for name in (
        "backup.sh",
        "create-n8n-service-credential.sh",
        "finalize-n8n-service-credential-replacement.sh",
        "manage-n8n-service-credential.sh",
        "install.sh",
        "provision-n8n.sh",
        "rollback.sh",
        "static-preflight.sh",
        "upgrade.sh",
    ):
        assert "# shellcheck source=deploy/scripts/common.sh" in script(name)


def test_rollback_parses_state_instead_of_sourcing_shell_code() -> None:
    contents = script("rollback.sh")
    assert "validate_state_file()" in contents
    assert 'source "$FLOWPROOF_DEPLOY_STATE_FILE"' not in contents
    assert "unexpected key in deployment state" in contents
    assert "FLOWPROOF_API_REPOSITORY_DIGEST" in contents
    assert "SCHEMA_REVISION" in contents
    assert 'require_owner_file "$FLOWPROOF_DEPLOY_STATE_FILE"' in contents
    assert contents.index("current_schema=") < contents.index('"${COMPOSE[@]}" up -d')
    common = script("common.sh")
    assert "FLOWPROOF_CORE_HEALTH_ATTEMPTS:-30" in common
    assert "FLOWPROOF_CORE_HEALTH_DELAY_SECONDS:-2" in common
    assert "core health checks did not succeed" in common
    assert "wait_for_core_health" in contents


def test_n8n_provision_token_is_not_injected_into_a_container_environment() -> None:
    contents = script("provision-n8n.sh")
    assert "FLOWPROOF_PROVISION_TOKEN" not in contents
    assert "fs.readFileSync(0" in contents
    assert "printf '%s' \"$token\" |" in contents


def test_n8n_provision_retries_only_transient_sqlite_busy_failures() -> None:
    contents = script("provision-n8n.sh")
    assert "FLOWPROOF_N8N_CLI_BUSY_RETRIES:-5" in contents
    assert "FLOWPROOF_N8N_CLI_BUSY_DELAY_SECONDS:-2" in contents
    assert "SQLITE_BUSY: database is locked" in contents
    assert 'n8n_cli_with_busy_retry import:credentials' in contents
    assert 'n8n_cli_with_busy_retry import:workflow' in contents
    assert 'n8n_cli_with_busy_retry publish:workflow' in contents
    assert '! grep -Fq "SQLITE_BUSY: database is locked"' in contents


def test_local_n8n_smoke_avoids_startup_migration_race_and_cleans_volumes() -> None:
    contents = (ROOT / "scripts" / "run_n8n_webhook_smoke.ps1").read_text(
        encoding="utf-8"
    )
    n8n_start = contents.index("Invoke-Compose @('up', '--detach', 'n8n')")
    first_ready = contents.index("Wait-N8nReady", n8n_start)
    migration_barrier = contents.index("Wait-N8nMigrationsComplete", first_ready)
    credential_import = contents.index(
        "Install-N8nCredential $env:FLOWPROOF_N8N_SMOKE_TOKEN"
    )
    assert n8n_start < first_ready < migration_barrier < credential_import
    assert "Instance registered" in contents
    assert "down --volumes --remove-orphans" in contents


def test_n8n_credential_bootstraps_after_core_startup_without_approval_scope() -> None:
    contents = script("manage-n8n-service-credential.sh")
    assert "--name n8n-flowproof" in contents
    assert "--scope events:write --scope recovery:execute --scope recovery:verify" in contents
    assert "recovery:approve" not in contents
    assert "FLOWPROOF_N8N_CREDENTIAL_ROTATE" in contents
    assert "replacement_token_file" in contents and "superseded_token_file" in contents
    assert "credential_state_file" in contents
    assert "FLOWPROOF_N8N_FAILURE_INJECT" in contents
    assert "flock is required for n8n credential lifecycle operations" in contents
    assert "another n8n credential lifecycle process holds the operation lock" in contents
    for point in (
        "after_activation_state_transition",
        "after_active_token_file_switch",
        "after_superseded_credential_revoke",
    ):
        assert point in contents
    assert "planned" in contents and "verified_pending_activation" in contents
    finalizer_body = contents[contents.index("finalize_operation() {") :]
    transition_index = finalizer_body.index("transition_state verified_pending_revocation")
    reconciliation_index = finalizer_body.index("reconcile_replacement_activation")
    assert transition_index < reconciliation_index
    assert "replacement activation cannot be recovered" in contents
    assert "FLOWPROOF_N8N_SECRET_UID" in script("install.sh")
    finalizer = script("finalize-n8n-service-credential-replacement.sh")
    assert 'manage-n8n-service-credential.sh" finalize' in finalizer
    create = script("create-n8n-service-credential.sh")
    assert 'manage-n8n-service-credential.sh" start' in create


def test_production_smoke_orchestrates_committed_deployment_scripts() -> None:
    contents = (ROOT / "scripts" / "production_deployment_smoke.py").read_text(encoding="utf-8")
    core_start = contents.index("CORE_COMPOSE_FILES = (")
    core_files = contents[core_start : contents.index("\nCOMPOSE_FILES = (", core_start)]
    assert '"docker-compose.deployment-proof.yml"' in core_files
    for name in (
        "install.sh",
        "upgrade.sh",
        "backup.sh",
        "restore-proof.sh",
        "rollback.sh",
    ):
        assert f"deploy/scripts/{name}" in contents
    assert "def create_backup" not in contents
    assert "def restore_proof" not in contents
    assert "Linux-only" in contents
    assert "FLOWPROOF_ALLOW_LOCAL_IMAGE_IDS" in contents
    assert "negative deployment guard unexpectedly succeeded" in contents
    assert "schema-mismatch rollback changed candidate containers before refusal" in contents
    assert "n8n-credential-replacement.json" in contents
    assert "command exited non-zero" in contents
    assert "ERROR: deployment proof failed:" in contents
    assert "raise SystemExit(1) from None" in contents
    assert '"api": "true:true"' in contents
    assert '"scheduler": "false:false"' in contents
    assert "recovery gate mismatch" in contents
    assert '"FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS": "1800"' in contents
    assert '"FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS": "1790"' in contents
    assert '"service_credential_expiring"' in contents
    assert contents.index('"/api/v1/operations/alerts/test"') < contents.index(
        'command([sys.executable, "scripts/demo.py"]'
    )


def test_production_smokes_control_only_the_internal_mock_chaos_fixture() -> None:
    deployment = (ROOT / "scripts" / "production_deployment_smoke.py").read_text(
        encoding="utf-8"
    )
    for script_name in ("demo.py", "n8n_webhook_smoke.py"):
        contents = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
        assert 'f"{API}/chaos/mode"' not in contents
        assert contents.count('f"{MOCK}/chaos/mode"') == 2
    assert '"MOCK_ACCOUNTING_URL": "http://mock-accounting:8001"' in deployment


def test_required_deployment_entrypoints_are_executable_in_the_git_index() -> None:
    expected = {
        "deploy/scripts/deploy.sh",
        "deploy/scripts/install.sh",
        "deploy/scripts/upgrade.sh",
        "deploy/scripts/static-preflight.sh",
        "deploy/scripts/backup.sh",
        "deploy/scripts/restore-proof.sh",
        "deploy/scripts/rollback.sh",
        "deploy/scripts/create-n8n-service-credential.sh",
        "deploy/scripts/finalize-n8n-service-credential-replacement.sh",
        "deploy/scripts/manage-n8n-service-credential.sh",
        "deploy/scripts/provision-n8n.sh",
    }
    output = subprocess.run(
        ["git", "ls-files", "--stage", "deploy/scripts"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    modes = {line.split(maxsplit=3)[3]: line.split(maxsplit=1)[0] for line in output}
    assert {path: modes[path] for path in expected} == {path: "100755" for path in expected}
    assert modes["deploy/scripts/common.sh"] == "100644"


def test_deployment_workflow_propagates_smoke_failures_and_enforces_shellcheck() -> None:
    deployment = (ROOT / ".github" / "workflows" / "deployment-proof.yml").read_text(
        encoding="utf-8"
    )
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "set -Eeuo pipefail" in deployment
    assert (
        "python scripts/production_deployment_smoke.py 2>&1 | tee deployment-proof.log"
        in deployment
    )
    assert "validate_deployment_proof_result.py" in deployment
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in deployment
    assert (
        "find deploy/scripts security -type f -name '*.sh' -print0 | xargs -0 shellcheck -x" in ci
    )
    assert "bash -n deploy/scripts/*.sh" in ci
    assert "bash -n security/*.sh" in ci
    assert "Attest PR merge tree matches head tree" in ci
    assert "Gitleaks exact range and working tree scan" in ci
    assert "git merge-base --is-ancestor" in ci
    assert "--no-git" in ci
    assert "f44e526acc67786b7476db413edb993ce2d152660d32fb3eb48d9bca06fa83f8" in ci
    assert "test_gitleaks_exact_range.py" in ci
    assert "Scrub deployment proof artifact" in deployment
    assert "scrub_deployment_artifact.py" in deployment
    assert "credential-lifetime-evidence.json" in deployment
    assert "credential-crash-recovery-evidence.json" in deployment
    assert "gitleaks-range-evidence.json" in deployment
    owned = (ROOT / ".github" / "workflows" / "container-security.yml").read_text(encoding="utf-8")
    assert "Attest PR merge tree matches head tree" in owned


def test_deployment_result_validator_rejects_traceback_and_accepts_complete_contract(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "audit" / "proof"
    audit.mkdir(parents=True)
    head = "a" * 40
    tree = "b" * 40
    payload = {
        "status": "passed",
        "version": "0.6.0",
        "tested_head_sha": head,
        "tested_tree": tree,
        "fresh_install": "passed",
        "n8n_integration": "passed",
        "business_flow": "passed",
        "backup": "passed",
        "restore": "passed",
        "upgrade": "passed",
        "rollback": "passed",
        "log_redaction": "passed",
        "credential_lifetime_policy": "passed",
        "credential_expiry_alert": "passed",
        "credential_replacement_recovery": "passed",
        "credential_replacement_crash_recovery": "passed",
        "gitleaks_exact_range": "passed",
        "volumes_retained": True,
    }
    (audit / "result.json").write_text(json.dumps(payload), encoding="utf-8")
    crash_evidence_path = audit / "credential-crash-recovery-evidence.json"
    crash_evidence = {
        "result": "passed",
        "scenarios": [
            {
                "failure_injection_point": point,
                "recovered_after_restart": True,
                "final_operation_status": "finalized",
                "lifecycle": "finalized",
                "replacement_credential_id": f"replacement-{index}",
                "superseded_credential_id": f"superseded-{index}",
                "superseded_bearer_verification": "verified_401",
                "unexpired_unrevoked_count": 1,
                "expired_unrevoked_count": 0,
            }
            for index, point in enumerate(
                (
                    "after_activation_state_transition",
                    "after_active_token_file_switch",
                    "after_superseded_credential_revoke",
                ),
                start=1,
            )
        ],
    }
    crash_evidence_path.write_text(json.dumps(crash_evidence), encoding="utf-8")
    log = tmp_path / "deployment-proof.log"
    log.write_text('{"status":"passed"}\n', encoding="utf-8")
    command = [
        sys.executable,
        "scripts/validate_deployment_proof_result.py",
        "--audit-root",
        str(tmp_path / "audit"),
        "--log",
        str(log),
        "--expected-head",
        head,
        "--expected-tree",
        tree,
    ]
    assert subprocess.run(command, cwd=ROOT, check=False).returncode == 0
    crash_evidence_path.unlink()
    assert subprocess.run(command, cwd=ROOT, check=False).returncode != 0
    crash_evidence_path.write_text(json.dumps(crash_evidence), encoding="utf-8")
    log.write_text("Traceback (most recent call last):\n", encoding="utf-8")
    assert subprocess.run(command, cwd=ROOT, check=False).returncode != 0


def test_deployment_artifact_scrub_allows_only_sanitized_contract_files(tmp_path: Path) -> None:
    artifacts = {
        "deployment-proof.log": "deployment proof passed\n",
        "result.json": json.dumps({"status": "passed"}),
        "n8n-credential-replacement.json": json.dumps({"operation_id": "operation-1"}),
        "credential-crash-recovery-evidence.json": json.dumps({"result": "passed"}),
        "credential-lifetime-evidence.json": json.dumps({"result": "passed"}),
        "gitleaks-range-evidence.json": json.dumps({"result": "passed"}),
    }
    paths = []
    for name, contents in artifacts.items():
        path = tmp_path / name
        path.write_text(contents, encoding="utf-8")
        paths.append(path)
    command = [
        sys.executable,
        "scripts/scrub_deployment_artifact.py",
        *(str(path) for path in paths),
    ]
    assert subprocess.run(command, cwd=ROOT, check=False).returncode == 0
    paths[1].write_text(json.dumps({"token": "synthetic"}), encoding="utf-8")
    assert subprocess.run(command, cwd=ROOT, check=False).returncode != 0
