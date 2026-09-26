"""Linux deployment proof from an absent project; it never creates a repository .env file."""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]
CORE_COMPOSE_FILES = (
    "docker-compose.production.yml",
    "docker-compose.production-smoke.yml",
    "docker-compose.deployment-proof.yml",
)
COMPOSE_FILES = (
    "docker-compose.production.yml",
    "docker-compose.production-smoke.yml",
    "docker-compose.integration-n8n.yml",
    "docker-compose.deployment-proof.yml",
)
SENSITIVE_VALUES: set[str] = set()
LABELED_SECRET = re.compile(
    r"(?i)((?:authorization\s*[:=]\s*(?:bearer\s+)?|(?:token|password|secret|pepper)\s*[:=]\s*)\S+)"
)


def redact_failure_evidence(value: str) -> str:
    """Retain actionable command diagnostics without writing raw secret material."""

    redacted = value
    for secret_value in SENSITIVE_VALUES:
        if secret_value:
            redacted = redacted.replace(secret_value, "<redacted>")
    return LABELED_SECRET.sub("<redacted>", redacted)


def bash_executable() -> str:
    """Use Git Bash on Windows; the system bash.exe is only a WSL launcher."""

    configured = os.environ.get("FLOWPROOF_BASH_EXECUTABLE")
    if configured:
        return configured
    if os.name != "nt":
        return "bash"
    candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
    if candidate.is_file():
        return str(candidate)
    raise RuntimeError("Git Bash is required to run the production shell-script smoke")


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def command(
    args: list[str],
    *,
    env: dict[str, str],
    timeout: int = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            args,
            cwd=ROOT,
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"timed out after {timeout}s: {args[0]} {args[1]}") from exc
    if completed.returncode:
        diagnostic_path = env.get("FLOWPROOF_SMOKE_DIAGNOSTIC_PATH")
        if diagnostic_path:
            # Keep failed-script evidence local to the generated audit directory.
            # Commands receive only secret file paths; raw values are not recorded here.
            Path(diagnostic_path).write_text(
                json.dumps(
                    {
                        "argv": [args[0], args[1] if len(args) > 1 else ""],
                        "returncode": completed.returncode,
                        "stderr": redact_failure_evidence(
                            (completed.stderr or "")[-4000:]
                        ),
                        "stdout": redact_failure_evidence(
                            (completed.stdout or "")[-4000:]
                        ),
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        # Do not propagate command output: it may contain a service or secret-bearing URL.
        diagnostic = ""
        if args[-1].endswith("n8n_webhook_smoke.py"):
            for line in reversed((completed.stderr or "").splitlines()):
                if line and not line.startswith((" ", "Traceback", "File ")):
                    diagnostic = f" ({line[:240]})"
                    break
        raise RuntimeError(
            f"command exited non-zero ({completed.returncode}): {args[0]} {args[1]}{diagnostic}"
        )
    return completed


def must_fail(args: list[str], *, env: dict[str, str], timeout: int = 120) -> None:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode == 0:
        raise RuntimeError("negative deployment guard unexpectedly succeeded")


def compose_prefix(project: str) -> list[str]:
    result = ["docker", "compose", "--project-name", project, "--profile", "proof-edge"]
    for filename in COMPOSE_FILES:
        result.extend(["-f", filename])
    return result


def wait_for_http(url: str, *, expected: int, timeout: int = 90) -> httpx.Response:
    deadline = time.monotonic() + timeout
    with httpx.Client(verify=False, timeout=5.0) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get(url)
                if response.status_code == expected:
                    return response
            except httpx.HTTPError:
                pass
            time.sleep(1)
    raise RuntimeError(f"endpoint did not return {expected} before timeout")


def api_request(
    client: httpx.Client, method: str, path: str, **kwargs: object
) -> dict[str, Any] | None:
    response = client.request(method, path, **kwargs)
    if response.status_code == 204:
        return None
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise TypeError("API returned a non-object JSON payload")
    return body


def run_n8n_workflow_smoke(
    compose: list[str],
    env: dict[str, str],
    *,
    admin_name: str,
    admin_password: str,
    operator_name: str,
    operator_password: str,
    n8n_token: str,
) -> None:
    variables = {
        "FLOWPROOF_API_URL": "https://caddy/api/v1",
        "MOCK_ACCOUNTING_URL": "http://mock-accounting:8001",
        "N8N_WEBHOOK_URL": "http://n8n:5678/webhook",
        "FLOWPROOF_N8N_SMOKE_ADMIN_NAME": admin_name,
        "FLOWPROOF_N8N_SMOKE_ADMIN_PASSWORD": admin_password,
        "FLOWPROOF_N8N_SMOKE_OPERATOR_NAME": operator_name,
        "FLOWPROOF_N8N_SMOKE_OPERATOR_PASSWORD": operator_password,
        "FLOWPROOF_N8N_SMOKE_TOKEN": n8n_token,
    }
    invocation = compose + ["exec", "-T"]
    for name, value in variables.items():
        invocation.extend(["-e", f"{name}={value}"])
    invocation.extend(["api", "python", "/app/scripts/n8n_webhook_smoke.py"])
    command(invocation, env=env, timeout=150)


def expect_lifecycle_injected_crash(
    args: list[str], *, env: dict[str, str], failure_injection_point: str
) -> None:
    """Prove the lifecycle process stopped at the requested durable crash point."""

    completed = subprocess.run(
        args,
        cwd=ROOT,
        env=env | {"FLOWPROOF_N8N_FAILURE_INJECT": failure_injection_point},
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 75:
        raise RuntimeError(
            f"credential lifecycle did not stop at {failure_injection_point}"
        )


def exercise_activation_crash_recovery(
    compose: list[str],
    env: dict[str, str],
    *,
    secrets_dir: Path,
    audit_dir: Path,
    admin_name: str,
    admin_password: str,
    operator_password: str,
    active_token: str,
    failure_injection_point: str,
    scenario_number: int,
) -> tuple[str, dict[str, Any]]:
    """Run an actual credential rotation, crash, restart, and convergence check."""

    command(
        [bash_executable(), "deploy/scripts/create-n8n-service-credential.sh"],
        env=env | {"FLOWPROOF_N8N_CREDENTIAL_ROTATE": "true"},
        timeout=120,
    )
    active_file = secrets_dir / "n8n_flowproof_token"
    if active_file.read_text(encoding="utf-8").strip() != active_token:
        raise RuntimeError("replacement changed the active token before workflow verification")
    command(
        [bash_executable(), "deploy/scripts/manage-n8n-service-credential.sh", "resume"],
        env=env,
        timeout=180,
    )
    replacement_file = secrets_dir / ".n8n_flowproof_replacement_token"
    replacement_token = replacement_file.read_text(encoding="utf-8").strip()
    SENSITIVE_VALUES.add(replacement_token)
    if replacement_token == active_token:
        raise RuntimeError("staged n8n replacement did not issue a new credential")
    run_n8n_workflow_smoke(
        compose,
        env,
        admin_name=admin_name,
        admin_password=admin_password,
        operator_name=f"production-smoke-operator-recovery-{scenario_number}",
        operator_password=operator_password,
        n8n_token=replacement_token,
    )
    command(
        [bash_executable(), "deploy/scripts/manage-n8n-service-credential.sh", "resume"],
        env=env | {"FLOWPROOF_N8N_WORKFLOW_VERIFIED": "true"},
        timeout=120,
    )
    expect_lifecycle_injected_crash(
        [
            bash_executable(),
            "deploy/scripts/finalize-n8n-service-credential-replacement.sh",
        ],
        env=env,
        failure_injection_point=failure_injection_point,
    )
    command(
        [
            bash_executable(),
            "deploy/scripts/finalize-n8n-service-credential-replacement.sh",
        ],
        env=env
        | {
            "FLOWPROOF_N8N_RECOVERY_FAILURE_INJECTION_POINT": failure_injection_point,
            "FLOWPROOF_N8N_RECOVERED_AFTER_RESTART": "true",
        },
        timeout=120,
    )
    if active_file.read_text(encoding="utf-8").strip() != replacement_token:
        raise RuntimeError("crash-recovered replacement did not become active")
    evidence = json.loads(
        audit_dir.joinpath("n8n-credential-replacement.json").read_text(
            encoding="utf-8"
        )
    )
    required = {
        "failure_injection_point": failure_injection_point,
        "recovered_after_restart": True,
        "final_operation_status": "finalized",
        "lifecycle": "finalized",
        "superseded_bearer_verification": "verified_401",
        "unexpired_unrevoked_count": 1,
        "expired_unrevoked_count": 0,
    }
    if (
        any(evidence.get(key) != value for key, value in required.items())
        or evidence.get("replacement_credential_id")
        == evidence.get("superseded_credential_id")
    ):
        raise RuntimeError("crash-recovery credential evidence is incomplete")
    return replacement_token, evidence


def create_restore_sentinel_manifest(
    compose: list[str], env: dict[str, str], audit_dir: Path, admin_name: str
) -> Path:
    """Select one durable row of every production-critical type for script restore proof."""

    queries = {
        "principals": f"SELECT id FROM principals WHERE name = '{admin_name}'",
        "api_credentials": "SELECT id FROM api_credentials ORDER BY created_at DESC LIMIT 1",
        "auth_sessions": "SELECT id FROM auth_sessions ORDER BY created_at DESC LIMIT 1",
        "security_audit_events": "SELECT id FROM security_audit_events ORDER BY occurred_at DESC LIMIT 1",
        "business_events": "SELECT id FROM business_events ORDER BY ingested_at DESC LIMIT 1",
        "incidents": "SELECT id FROM incidents ORDER BY opened_at DESC LIMIT 1",
        "recovery_plans": "SELECT id FROM recovery_plans LIMIT 1",
        "deadline_jobs": "SELECT id FROM deadline_jobs ORDER BY created_at DESC LIMIT 1",
        "alert_outbox": "SELECT id FROM alert_outbox ORDER BY created_at DESC LIMIT 1",
        "service_heartbeats": "SELECT service FROM service_heartbeats WHERE service = 'scheduler'",
        "operational_alert_states": "SELECT id FROM operational_alert_states WHERE condition = 'proof_restore_sentinel'",
    }
    rows: list[str] = []
    for table, query in queries.items():
        result = command(
            compose
            + [
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "flowproof",
                "-d",
                "flowproof",
                "-Atc",
                query,
            ],
            env=env,
        ).stdout.strip()
        if not result or "\n" in result:
            raise RuntimeError(f"missing or ambiguous restore sentinel for {table}")
        rows.append(f"{table}\t{result}\t1")
    manifest = audit_dir / "restore-sentinels.tsv"
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    os.chmod(manifest, 0o600)
    return manifest


def main() -> int:
    if os.name == "nt":
        raise RuntimeError(
            "the deployment proof is Linux-only; NTFS cannot prove POSIX modes"
        )
    project = f"flowproof-production-smoke-{uuid4().hex[:10]}"
    smoke_root = Path(
        os.environ.get(
            "FLOWPROOF_SMOKE_AUDIT_ROOT", r"C:\tmp\flowproof-production-smoke"
        )
    )
    audit_dir = smoke_root / project
    secrets_dir = audit_dir / "secrets"
    n8n_secrets_dir = audit_dir / "n8n-secrets"
    secrets_dir.mkdir(parents=True, exist_ok=False)
    n8n_secrets_dir.mkdir(parents=True, exist_ok=False)
    audit_dir.joinpath("project.txt").write_text(project + "\n", encoding="utf-8")
    https_port = reserve_port()
    admin_name = "smoke-admin"
    admin_password = secrets.token_urlsafe(24)
    secret_values = {
        "token_pepper": secrets.token_urlsafe(48),
        "postgres_password": secrets.token_urlsafe(32),
        "alert_webhook_url": "http://mock-accounting:8001/alerts",
    }
    for name, value in secret_values.items():
        path = secrets_dir / name
        path.write_text(value + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    n8n_encryption_key = secrets.token_urlsafe(32)
    n8n_secrets_dir.joinpath("n8n_encryption_key").write_text(
        n8n_encryption_key + "\n", encoding="utf-8"
    )
    os.chmod(n8n_secrets_dir / "n8n_encryption_key", 0o600)
    initial_admin_password_file = secrets_dir / "initial_admin_password"
    initial_admin_password_file.write_text(admin_password + "\n", encoding="utf-8")
    os.chmod(initial_admin_password_file, 0o600)
    SENSITIVE_VALUES.update(
        {
            *secret_values.values(),
            n8n_encryption_key,
            admin_password,
            str(secrets_dir),
            str(n8n_secrets_dir),
        }
    )
    env = os.environ.copy()
    env.update(
        {
            "FLOWPROOF_API_IMAGE": "flowproof-api:production-smoke",
            "FLOWPROOF_WEB_IMAGE": "flowproof-web:production-smoke",
            "FLOWPROOF_MOCK_IMAGE": "flowproof-mock:production-smoke",
            "FLOWPROOF_SECRETS_DIR": str(secrets_dir),
            "FLOWPROOF_N8N_SECRETS_DIR": str(n8n_secrets_dir),
            "POSTGRES_DB": "flowproof",
            "POSTGRES_USER": "flowproof",
            "FLOWPROOF_ACCOUNTING_URL": "http://mock-accounting:8001",
            "FLOWPROOF_CORS_ORIGIN": "https://caddy",
            "FLOWPROOF_API_BIND": "127.0.0.1",
            "FLOWPROOF_WEB_BIND": "127.0.0.1",
            "FLOWPROOF_API_HEALTH_URL": "http://127.0.0.1:8000",
            "FLOWPROOF_PROOF_HTTPS_PORT": str(https_port),
            "FLOWPROOF_N8N_HOST": "n8n.example.test",
            "FLOWPROOF_N8N_PROTOCOL": "https",
            "FLOWPROOF_N8N_EDITOR_BASE_URL": "https://n8n.example.test/",
            "FLOWPROOF_N8N_WEBHOOK_URL": "https://n8n.example.test/",
            "FLOWPROOF_SCHEDULER_POLL_SECONDS": "1",
            "FLOWPROOF_OPS_WATCHER_POLL_SECONDS": "1",
            "FLOWPROOF_PYTHON_EXECUTABLE": sys.executable,
            "FLOWPROOF_COMPOSE_PROJECT_NAME": project,
            "FLOWPROOF_CORE_COMPOSE_FILES": ":".join(CORE_COMPOSE_FILES),
            "FLOWPROOF_DEPLOY_SMOKE": "true",
            "FLOWPROOF_DEPLOY_STATE_FILE": str(audit_dir / "previous-images.env"),
            "FLOWPROOF_BACKUP_DIR": str(audit_dir / "backups"),
            "FLOWPROOF_APPLICATION_VERSION": "0.6.0",
            "FLOWPROOF_SOURCE_IMAGE_REVISION": "local-production-smoke",
            "FLOWPROOF_SMOKE_DIAGNOSTIC_PATH": str(audit_dir / "failed-command.json"),
            "FLOWPROOF_INITIAL_ADMIN_NAME": admin_name,
            "FLOWPROOF_INITIAL_ADMIN_PASSWORD_FILE": str(initial_admin_password_file),
            "FLOWPROOF_N8N_CREDENTIAL_EVIDENCE_FILE": str(
                audit_dir / "n8n-credential-replacement.json"
            ),
            "FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS": "1800",
            "FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS": "1790",
        }
    )
    compose = compose_prefix(project)
    try:
        command(["docker", "version"], env=env, timeout=30)
        command(
            [
                "sudo",
                "chown",
                "10001:10001",
                *(str(secrets_dir / name) for name in secret_values),
            ],
            env=env,
        )
        command(
            ["sudo", "chown", "1000:1000", str(n8n_secrets_dir / "n8n_encryption_key")],
            env=env,
        )
        command(compose + ["config", "--quiet"], env=env, timeout=30)
        # A new project name must start with no Compose-owned runtime state.
        if command(compose + ["ps", "-aq"], env=env).stdout.strip():
            raise RuntimeError("deployment proof project was not absent before install")
        for resource in ("network", "volume"):
            existing = command(
                [
                    "docker",
                    resource,
                    "ls",
                    "--quiet",
                    "--filter",
                    f"label=com.docker.compose.project={project}",
                ],
                env=env,
            ).stdout.strip()
            if existing:
                raise RuntimeError(
                    f"deployment proof {resource} was not absent before install"
                )
        command(
            compose + ["build", "api", "web", "mock-accounting"], env=env, timeout=300
        )
        api_id = command(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "flowproof-api:production-smoke",
            ],
            env=env,
        ).stdout.strip()
        web_id = command(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "flowproof-web:production-smoke",
            ],
            env=env,
        ).stdout.strip()
        if not api_id.startswith("sha256:") or not web_id.startswith("sha256:"):
            raise RuntimeError("local proof did not resolve immutable local image IDs")
        env.update(
            {
                "FLOWPROOF_API_IMAGE": api_id,
                "FLOWPROOF_WEB_IMAGE": web_id,
                "FLOWPROOF_ALLOW_LOCAL_IMAGE_IDS": "true",
            }
        )
        command(
            [bash_executable(), "deploy/scripts/install.sh", "--with-n8n"],
            env=env,
            timeout=300,
        )
        expected_recovery_gates = {
            "api": "true:true",
            "scheduler": "false:false",
        }
        for service_name, expected_recovery_gate in expected_recovery_gates.items():
            proof_recovery_gate = command(
                compose
                + [
                    "exec",
                    "-T",
                    service_name,
                    "python",
                    "-c",
                    (
                        "import os; print("
                        "os.getenv('FLOWPROOF_RECOVERY_WRITES_ENABLED', '') + ':' + "
                        "os.getenv("
                        "'FLOWPROOF_DEPLOYMENT_PROOF_RECOVERY_WRITES_AUTHORIZED', "
                        "'false'"
                        "))"
                    ),
                ],
                env=env,
            ).stdout.strip()
            if proof_recovery_gate != expected_recovery_gate:
                raise RuntimeError(
                    f"installed {service_name} recovery gate mismatch: expected "
                    f"{expected_recovery_gate}, observed {proof_recovery_gate}"
                )
        must_fail(
            [bash_executable(), "deploy/scripts/install.sh"], env=env, timeout=120
        )
        command(
            compose + ["up", "--detach", "--wait", "mock-accounting", "caddy"],
            env=env,
            timeout=180,
        )
        base_url = f"https://localhost:{https_port}"
        wait_for_http(f"{base_url}/health/live", expected=200)
        wait_for_http(f"{base_url}/health/ready", expected=200)
        n8n_operator_password = secrets.token_urlsafe(24)
        n8n_token = (
            secrets_dir.joinpath(".n8n_flowproof_replacement_token")
            .read_text(encoding="utf-8")
            .strip()
        )
        SENSITIVE_VALUES.update({n8n_operator_password, n8n_token})
        run_n8n_workflow_smoke(
            compose,
            env,
            admin_name=admin_name,
            admin_password=admin_password,
            operator_name="production-smoke-operator-initial",
            operator_password=n8n_operator_password,
            n8n_token=n8n_token,
        )
        command(
            [
                bash_executable(),
                "deploy/scripts/manage-n8n-service-credential.sh",
                "resume",
            ],
            env=env | {"FLOWPROOF_N8N_WORKFLOW_VERIFIED": "true"},
            timeout=120,
        )
        command(
            [
                bash_executable(),
                "deploy/scripts/manage-n8n-service-credential.sh",
                "finalize",
            ],
            env=env,
            timeout=120,
        )
        if (
            secrets_dir.joinpath("n8n_flowproof_token")
            .read_text(encoding="utf-8")
            .strip()
            != n8n_token
        ):
            raise RuntimeError(
                "initial n8n credential was not activated after workflow verification"
            )
        crash_recovery_evidence: list[dict[str, Any]] = []
        active_n8n_token = n8n_token
        for scenario_number, failure_injection_point in enumerate(
            (
                "after_activation_state_transition",
                "after_active_token_file_switch",
                "after_superseded_credential_revoke",
            ),
            start=1,
        ):
            active_n8n_token, n8n_credential_replacement = (
                exercise_activation_crash_recovery(
                    compose,
                    env,
                    secrets_dir=secrets_dir,
                    audit_dir=audit_dir,
                    admin_name=admin_name,
                    admin_password=admin_password,
                    operator_password=n8n_operator_password,
                    active_token=active_n8n_token,
                    failure_injection_point=failure_injection_point,
                    scenario_number=scenario_number,
                )
            )
            crash_recovery_evidence.append(n8n_credential_replacement)
        audit_dir.joinpath("credential-crash-recovery-evidence.json").write_text(
            json.dumps(
                {"result": "passed", "scenarios": crash_recovery_evidence},
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        active_n8n_credentials = command(
            compose
            + [
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "flowproof",
                "-d",
                "flowproof",
                "-Atc",
                "SELECT count(*) FROM api_credentials c JOIN principals p ON p.id = c.principal_id WHERE p.name = 'n8n-flowproof' AND c.revoked_at IS NULL AND c.expires_at > now()",
            ],
            env=env,
        ).stdout.strip()
        if active_n8n_credentials != "1":
            raise RuntimeError(
                "n8n service principal has an uncontrolled unexpired credential count"
            )
        with httpx.Client(base_url=base_url, verify=False, timeout=20.0) as client:
            login = api_request(
                client,
                "POST",
                "/api/v1/auth/login",
                json={"name": admin_name, "password": admin_password},
            )
            if login is None or not isinstance(login.get("csrf_token"), str):
                raise RuntimeError("secure session login failed")
            csrf = str(login["csrf_token"])
            service = api_request(
                client,
                "POST",
                "/api/v1/identity/service-accounts",
                headers={"X-CSRF-Token": csrf},
                json={
                    "name": "production-smoke-events",
                    "scopes": ["events:write", "read:operations"],
                },
            )
            if service is None or not isinstance(service.get("id"), str):
                raise RuntimeError("service account creation failed")
            issued = api_request(
                client,
                "POST",
                f"/api/v1/identity/principals/{service['id']}/credentials",
                headers={"X-CSRF-Token": csrf},
                json={
                    "scopes": ["events:write", "read:operations"],
                    "expires_in_seconds": 900,
                },
            )
            if issued is None or not isinstance(issued.get("token"), str):
                raise RuntimeError("service credential issue failed")
            event_token = str(issued["token"])
            SENSITIVE_VALUES.add(event_token)
        demo_env = env | {
            "FLOWPROOF_API_URL": f"{base_url}/api/v1",
            "MOCK_ACCOUNTING_URL": f"{base_url}/smoke/mock",
            "FLOWPROOF_HTTP_VERIFY_TLS": "false",
            "FLOWPROOF_DEMO_EVENT_TOKEN": event_token,
            "FLOWPROOF_DEMO_ADMIN_NAME": admin_name,
            "FLOWPROOF_DEMO_ADMIN_PASSWORD": admin_password,
        }
        with httpx.Client(base_url=base_url, verify=False, timeout=20.0) as client:
            login = api_request(
                client,
                "POST",
                "/api/v1/auth/login",
                json={"name": admin_name, "password": admin_password},
            )
            if login is None or not isinstance(login.get("csrf_token"), str):
                raise RuntimeError("alert proof secure session login failed")
            api_request(
                client,
                "POST",
                "/api/v1/operations/alerts/test",
                headers={"X-CSRF-Token": str(login["csrf_token"])},
            )
        alert_items: list[object] = []
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            received_alerts = httpx.get(
                f"{base_url}/smoke/mock/alerts", verify=False, timeout=10.0
            )
            received_alerts.raise_for_status()
            candidate = received_alerts.json().get("items", [])
            if isinstance(candidate, list):
                alert_items = candidate
            received_conditions = {
                item.get("condition") for item in alert_items if isinstance(item, dict)
            }
            if {"test_alert", "service_credential_expiring"} <= received_conditions:
                break
            time.sleep(1)
        else:
            raise RuntimeError(
                "alert receiver did not receive durable test and credential-expiry events"
            )
        command([sys.executable, "scripts/demo.py"], env=demo_env, timeout=120)
        private_metrics = command(
            compose
            + [
                "exec",
                "-T",
                "-e",
                f"FLOWPROOF_SMOKE_METRICS_TOKEN={event_token}",
                "api",
                "python",
                "-c",
                "import os,httpx; r=httpx.get('http://localhost:8000/metrics', headers={'Authorization': 'Bearer '+os.environ['FLOWPROOF_SMOKE_METRICS_TOKEN']}); r.raise_for_status(); assert 'flowproof_http_requests_total' in r.text",
            ],
            env=env,
        )
        del private_metrics
        command(
            compose
            + [
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "flowproof",
                "-d",
                "flowproof",
                "-c",
                "INSERT INTO operational_alert_states (id, condition, subject, active, generation) VALUES ('00000000-0000-0000-0000-000000000007', 'proof_restore_sentinel', 'linux-deployment-proof', true, 1)",
            ],
            env=env,
        )
        sentinel_manifest = create_restore_sentinel_manifest(
            compose, env, audit_dir, admin_name
        )
        restore_env = env | {"FLOWPROOF_RESTORE_SENTINELS_FILE": str(sentinel_manifest)}
        command([bash_executable(), "deploy/scripts/backup.sh"], env=env, timeout=180)
        backups = sorted((audit_dir / "backups").glob("flowproof-*.dump"))
        if not backups:
            raise RuntimeError(
                "committed backup script did not produce a complete dump"
            )
        backup = max(backups, key=lambda path: path.stat().st_mtime_ns)
        restored = command(
            [
                bash_executable(),
                "deploy/scripts/restore-proof.sh",
                "--isolated",
                str(backup),
            ],
            env=restore_env,
            timeout=180,
        )
        restore_volume = restored.stdout.strip().rsplit(":", maxsplit=1)[-1].strip()
        if not restore_volume:
            raise RuntimeError(
                "isolated restore did not report its retained audit volume"
            )
        command(["docker", "volume", "inspect", restore_volume], env=env)
        # A failed dump must leave no partial or misleading completed backup artifact.
        time.sleep(1)
        command(compose + ["stop", "postgres"], env=env, timeout=60)
        must_fail([bash_executable(), "deploy/scripts/backup.sh"], env=env, timeout=120)
        if list((audit_dir / "backups").glob("*.partial")):
            raise RuntimeError("failed backup left a partial artifact")
        command(compose + ["up", "--detach", "--wait", "postgres"], env=env, timeout=90)
        wait_for_http(f"{base_url}/health/ready", expected=200)
        schema_before = command(
            compose
            + [
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "flowproof",
                "-d",
                "flowproof",
                "-Atc",
                "SELECT version_num FROM alembic_version",
            ],
            env=env,
        ).stdout.strip()
        command(
            [
                "docker",
                "build",
                "--build-arg",
                "VERSION=0.6.0",
                "--build-arg",
                "REVISION=linux-proof-candidate",
                "-f",
                "backend/Dockerfile",
                "-t",
                "flowproof-api:production-candidate",
                ".",
            ],
            env=env,
            timeout=300,
        )
        command(
            [
                "docker",
                "build",
                "--build-arg",
                "VERSION=0.6.0",
                "--build-arg",
                "REVISION=linux-proof-candidate",
                "-f",
                "frontend/Dockerfile",
                "-t",
                "flowproof-web:production-candidate",
                "frontend",
            ],
            env=env,
            timeout=300,
        )
        candidate_api = command(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "flowproof-api:production-candidate",
            ],
            env=env,
        ).stdout.strip()
        candidate_web = command(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "flowproof-web:production-candidate",
            ],
            env=env,
        ).stdout.strip()
        if candidate_api == api_id or candidate_web == web_id:
            raise RuntimeError(
                "previous and candidate images must be distinct local IDs"
            )
        env.update(
            {"FLOWPROOF_API_IMAGE": candidate_api, "FLOWPROOF_WEB_IMAGE": candidate_web}
        )
        command(
            [bash_executable(), "deploy/scripts/upgrade.sh", "--with-n8n"],
            env=env,
            timeout=300,
        )
        active_candidate_api = command(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Image}}",
                command(compose + ["ps", "-q", "api"], env=env).stdout.strip(),
            ],
            env=env,
        ).stdout.strip()
        active_candidate_web = command(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Image}}",
                command(compose + ["ps", "-q", "web"], env=env).stdout.strip(),
            ],
            env=env,
        ).stdout.strip()
        if (
            active_candidate_api != candidate_api
            or active_candidate_web != candidate_web
        ):
            raise RuntimeError("upgrade did not activate both candidate image IDs")
        state_file = audit_dir / "previous-images.env"
        state_text = state_file.read_text(encoding="utf-8")
        state_file.write_text("UNEXPECTED_KEY=1\n", encoding="utf-8")
        must_fail(
            [bash_executable(), "deploy/scripts/rollback.sh"],
            env=env | {"FLOWPROOF_SCHEMA_COMPATIBLE": "true"},
        )
        state_file.write_text(state_text, encoding="utf-8")
        candidate_api_container = command(
            compose + ["ps", "-q", "api"], env=env
        ).stdout.strip()
        candidate_web_container = command(
            compose + ["ps", "-q", "web"], env=env
        ).stdout.strip()
        incompatible_state = state_text.replace(
            f"SCHEMA_REVISION={schema_before}",
            "SCHEMA_REVISION=incompatible-proof-revision",
        )
        state_file.write_text(incompatible_state, encoding="utf-8")
        must_fail(
            [bash_executable(), "deploy/scripts/rollback.sh"],
            env=env | {"FLOWPROOF_SCHEMA_COMPATIBLE": "true"},
        )
        unchanged_api_container = command(
            compose + ["ps", "-q", "api"], env=env
        ).stdout.strip()
        unchanged_web_container = command(
            compose + ["ps", "-q", "web"], env=env
        ).stdout.strip()
        unchanged_api_image = command(
            ["docker", "inspect", "--format", "{{.Image}}", unchanged_api_container],
            env=env,
        ).stdout.strip()
        unchanged_web_image = command(
            ["docker", "inspect", "--format", "{{.Image}}", unchanged_web_container],
            env=env,
        ).stdout.strip()
        if (
            unchanged_api_container != candidate_api_container
            or unchanged_web_container != candidate_web_container
            or unchanged_api_image != candidate_api
            or unchanged_web_image != candidate_web
        ):
            raise RuntimeError(
                "schema-mismatch rollback changed candidate containers before refusal"
            )
        state_file.write_text(state_text, encoding="utf-8")
        command(
            [bash_executable(), "deploy/scripts/rollback.sh"],
            env=env | {"FLOWPROOF_SCHEMA_COMPATIBLE": "true"},
            timeout=180,
        )
        wait_for_http(f"{base_url}/health/live", expected=200)
        restored_api = command(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Image}}",
                command(compose + ["ps", "-q", "api"], env=env).stdout.strip(),
            ],
            env=env,
        ).stdout.strip()
        restored_web = command(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Image}}",
                command(compose + ["ps", "-q", "web"], env=env).stdout.strip(),
            ],
            env=env,
        ).stdout.strip()
        schema_after = command(
            compose
            + [
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "flowproof",
                "-d",
                "flowproof",
                "-Atc",
                "SELECT version_num FROM alembic_version",
            ],
            env=env,
        ).stdout.strip()
        if (
            restored_api != api_id
            or restored_web != web_id
            or schema_after != schema_before
        ):
            raise RuntimeError(
                "rollback did not restore prior images with an unchanged schema"
            )
        logs = command(compose + ["logs", "--no-color", "api", "n8n"], env=env).stdout
        inspect_payload = command(
            [
                "docker",
                "inspect",
                command(compose + ["ps", "-q", "api"], env=env).stdout.strip(),
                command(compose + ["ps", "-q", "n8n"], env=env).stdout.strip(),
            ],
            env=env,
        ).stdout
        protected_values = [
            *secret_values.values(),
            n8n_encryption_key,
            admin_password,
            n8n_operator_password,
            n8n_token,
            active_n8n_token,
            event_token,
        ]
        if '"service":"flowproof-api"' not in logs or any(
            value in logs or value in inspect_payload for value in protected_values
        ):
            raise RuntimeError("structured log proof failed")
        tested_head_sha = (
            os.environ.get("FLOWPROOF_TESTED_HEAD_SHA")
            or command(["git", "rev-parse", "HEAD"], env=env).stdout.strip()
        )
        tested_tree = (
            os.environ.get("FLOWPROOF_TESTED_TREE")
            or command(["git", "rev-parse", "HEAD^{tree}"], env=env).stdout.strip()
        )
        audit_dir.joinpath("credential-lifetime-evidence.json").write_text(
            json.dumps(
                {
                    "credential_ttl_seconds": int(
                        env["FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS"]
                    ),
                    "expiry_warning_seconds": int(
                        env["FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS"]
                    ),
                    "principal_id": n8n_credential_replacement["principal_id"],
                    "replacement_credential_id": n8n_credential_replacement[
                        "replacement_credential_id"
                    ],
                    "unexpired_unrevoked_count": n8n_credential_replacement[
                        "unexpired_unrevoked_count"
                    ],
                    "expired_unrevoked_count": n8n_credential_replacement[
                        "expired_unrevoked_count"
                    ],
                    "activation_crash_recovery": {
                        "result": "passed",
                        "failure_injection_points": [
                            evidence["failure_injection_point"]
                            for evidence in crash_recovery_evidence
                        ],
                    },
                    "result": "passed",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        audit_dir.joinpath("result.json").write_text(
            json.dumps(
                {
                    "status": "passed",
                    "version": "0.6.0",
                    "tested_head_sha": tested_head_sha,
                    "tested_tree": tested_tree,
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
                    "n8n_credential_replacement": n8n_credential_replacement,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"status": "passed", "version": "0.6.0"}, sort_keys=True))
        return 0
    finally:
        if os.environ.get("FLOWPROOF_SMOKE_KEEP_FAILED") != "true":
            subprocess.run(
                compose + ["down", "--remove-orphans"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                timeout=90,
                check=False,
            )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - no traceback may enter the proof artifact
        # The workflow persists the structured, redacted failed-command.json.
        # Keep the streamed log one safe diagnostic line so a failure cannot
        # become a false positive through a traceback-containing artifact.
        print(
            f"ERROR: deployment proof failed: {redact_failure_evidence(str(exc))}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
