from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote_plus, urlsplit

KNOWN_INSECURE_TOKEN_PEPPERS = frozenset(
    {
        "",
        "dev-flowproof-token",
        "replace-with-a-long-random-token",
        "replace-with-a-separate-local-operator-token",
        "replace-with-a-random-value-of-at-least-32-characters",
        "development-only-pepper-must-be-replaced-before-production",
    }
)


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    cors_origin: str
    mock_accounting_url: str
    policy_path: Path
    environment: str
    provider_base_url: str | None = None
    provider_contract_path: Path | None = None
    recovery_writes_enabled: bool = True
    fixture_demo_enabled: bool = False
    xero_pkce_enabled: bool = False
    xero_provider_contract_path: Path | None = None
    xero_redirect_uri: str = (
        "http://localhost:8000/api/v1/provider-connections/xero/callback"
    )
    deployment_proof_recovery_writes_authorized: bool = False
    token_pepper: str | None = None
    legacy_ingestion_token: str | None = None
    legacy_operator_token: str | None = None
    legacy_header_auth_enabled: bool = False
    session_cookie_secure: bool = False
    session_ttl_seconds: int = 28_800
    session_idle_seconds: int = 7_200
    session_absolute_seconds: int = 28_800
    api_token_default_ttl_seconds: int = 86_400
    api_token_max_ttl_seconds: int = 2_592_000
    n8n_credential_ttl_seconds: int = 2_592_000
    credential_expiry_alert_seconds: int = 604_800
    login_failure_limit: int = 5
    login_lock_seconds: int = 900
    max_body_bytes: int = 65_536
    max_payload_bytes: int = 16_384
    scheduler_poll_seconds: float = 1.0
    scheduler_lease_seconds: int = 30
    scheduler_max_attempts: int = 5
    scheduler_retry_base_seconds: int = 2
    alert_webhook_url: str | None = None
    alert_open_incident_seconds: int = 3_600
    alert_worker_poll_seconds: float = 2.0
    alert_lease_seconds: int = 30
    alert_max_attempts: int = 5
    alert_retry_base_seconds: int = 5
    ops_watcher_poll_seconds: float = 10.0
    ops_watcher_heartbeat_stale_seconds: int = 90
    ops_watcher_verifier_failure_threshold: int = 3
    ops_watcher_verifier_observation_seconds: int = 300

    @classmethod
    def from_environment(cls) -> Settings:
        package_root = Path(__file__).resolve().parents[3]
        policy_default = package_root / "specs" / "policies" / "invoice-processing.yaml"
        contract_default = (
            package_root / "specs" / "providers" / "mock-accounting" / "contract.json"
        )
        environment = os.getenv("FLOWPROOF_ENV", "development").strip().lower()
        return cls(
            database_url=_database_url_from_environment(),
            cors_origin=os.getenv("FLOWPROOF_CORS_ORIGIN", "http://localhost:5173"),
            mock_accounting_url=os.getenv("FLOWPROOF_MOCK_ACCOUNTING_URL", "http://localhost:8001"),
            policy_path=Path(os.getenv("FLOWPROOF_POLICY_PATH", str(policy_default))),
            environment=environment,
            provider_base_url=os.getenv("FLOWPROOF_PROVIDER_BASE_URL") or None,
            provider_contract_path=Path(
                os.getenv("FLOWPROOF_PROVIDER_CONTRACT_PATH", str(contract_default))
            ),
            recovery_writes_enabled=_bool(
                "FLOWPROOF_RECOVERY_WRITES_ENABLED", environment == "development"
            ),
            fixture_demo_enabled=_bool("FLOWPROOF_FIXTURE_DEMO_ENABLED", False),
            xero_pkce_enabled=_bool("FLOWPROOF_XERO_PKCE_ENABLED", False),
            xero_provider_contract_path=Path(
                os.getenv(
                    "FLOWPROOF_XERO_PROVIDER_CONTRACT_PATH",
                    str(package_root / "specs" / "providers" / "xero-demo" / "contract.json"),
                )
            ),
            xero_redirect_uri=os.getenv(
                "FLOWPROOF_XERO_REDIRECT_URI",
                "http://localhost:8000/api/v1/provider-connections/xero/callback",
            ),
            deployment_proof_recovery_writes_authorized=_bool(
                "FLOWPROOF_DEPLOYMENT_PROOF_RECOVERY_WRITES_AUTHORIZED", False
            ),
            token_pepper=_secret_value("FLOWPROOF_TOKEN_PEPPER"),
            legacy_ingestion_token=os.getenv("FLOWPROOF_TOKEN"),
            legacy_operator_token=os.getenv("FLOWPROOF_OPERATOR_TOKEN"),
            legacy_header_auth_enabled=_bool("FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH", False),
            session_cookie_secure=_bool(
                "FLOWPROOF_SESSION_COOKIE_SECURE", environment == "production"
            ),
            session_ttl_seconds=_positive_int("FLOWPROOF_SESSION_TTL_SECONDS", 28_800),
            session_idle_seconds=_positive_int("FLOWPROOF_SESSION_IDLE_SECONDS", 7_200),
            session_absolute_seconds=_positive_int("FLOWPROOF_SESSION_ABSOLUTE_SECONDS", 28_800),
            api_token_default_ttl_seconds=_positive_int(
                "FLOWPROOF_API_TOKEN_DEFAULT_TTL_SECONDS", 86_400
            ),
            api_token_max_ttl_seconds=_positive_int(
                "FLOWPROOF_API_TOKEN_MAX_TTL_SECONDS", 2_592_000
            ),
            n8n_credential_ttl_seconds=_positive_int(
                "FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS", 2_592_000
            ),
            credential_expiry_alert_seconds=_positive_int(
                "FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS", 604_800
            ),
            login_failure_limit=_positive_int("FLOWPROOF_LOGIN_FAILURE_LIMIT", 5),
            login_lock_seconds=_positive_int("FLOWPROOF_LOGIN_LOCK_SECONDS", 900),
            max_body_bytes=_positive_int("FLOWPROOF_MAX_BODY_BYTES", 65_536),
            max_payload_bytes=_positive_int("FLOWPROOF_MAX_PAYLOAD_BYTES", 16_384),
            scheduler_poll_seconds=_positive_float("FLOWPROOF_SCHEDULER_POLL_SECONDS", 1.0),
            scheduler_lease_seconds=_positive_int("FLOWPROOF_SCHEDULER_LEASE_SECONDS", 30),
            scheduler_max_attempts=_positive_int("FLOWPROOF_SCHEDULER_MAX_ATTEMPTS", 5),
            scheduler_retry_base_seconds=_positive_int("FLOWPROOF_SCHEDULER_RETRY_BASE_SECONDS", 2),
            alert_webhook_url=_secret_value("FLOWPROOF_ALERT_WEBHOOK_URL"),
            alert_open_incident_seconds=_positive_int(
                "FLOWPROOF_ALERT_OPEN_INCIDENT_SECONDS", 3_600
            ),
            alert_worker_poll_seconds=_positive_float("FLOWPROOF_ALERT_WORKER_POLL_SECONDS", 2.0),
            alert_lease_seconds=_positive_int("FLOWPROOF_ALERT_LEASE_SECONDS", 30),
            alert_max_attempts=_positive_int("FLOWPROOF_ALERT_MAX_ATTEMPTS", 5),
            alert_retry_base_seconds=_positive_int("FLOWPROOF_ALERT_RETRY_BASE_SECONDS", 5),
            ops_watcher_poll_seconds=_positive_float("FLOWPROOF_OPS_WATCHER_POLL_SECONDS", 10.0),
            ops_watcher_heartbeat_stale_seconds=_positive_int(
                "FLOWPROOF_OPS_WATCHER_HEARTBEAT_STALE_SECONDS", 90
            ),
            ops_watcher_verifier_failure_threshold=_positive_int(
                "FLOWPROOF_OPS_WATCHER_VERIFIER_FAILURE_THRESHOLD", 3
            ),
            ops_watcher_verifier_observation_seconds=_positive_int(
                "FLOWPROOF_OPS_WATCHER_VERIFIER_OBSERVATION_SECONDS", 300
            ),
        )

    def validate_production_security(self) -> None:
        if self.xero_pkce_enabled and self.environment not in {
            "development",
            "local-appliance",
        }:
            raise ValueError("Xero PKCE qualification is allowed only in local runtimes")
        if self.fixture_demo_enabled and self.environment not in {
            "development",
            "local-appliance",
        }:
            raise ValueError("fixture demo is allowed only in explicit local runtimes")
        if self.deployment_proof_recovery_writes_authorized:
            if self.environment != "production" or not self.recovery_writes_enabled:
                raise ValueError(
                    "deployment proof recovery-write authorization requires production writes"
                )
            if self.mock_accounting_url != "http://mock-accounting:8001":
                raise ValueError(
                    "deployment proof recovery-write authorization requires the isolated "
                    "mock-accounting fixture"
                )
        if self.environment not in {"production", "local-appliance"}:
            return
        if self.legacy_header_auth_enabled:
            raise ValueError("legacy header authentication is forbidden in hardened runtimes")
        if (
            self.environment == "production"
            and
            self.recovery_writes_enabled
            and not self.deployment_proof_recovery_writes_authorized
        ):
            raise ValueError(
                "production recovery writes remain disabled until a separately authorized gate"
            )
        if self.environment == "local-appliance" and self.recovery_writes_enabled:
            contract_path = self.provider_contract_path
            if (
                self.mock_accounting_url != "http://mock-accounting:8001"
                or contract_path is None
                or "mock-accounting" not in contract_path.parts
            ):
                raise ValueError(
                    "local-appliance recovery writes are allowed only for the "
                    "mock-accounting fixture"
                )
        pepper = self.token_pepper
        if pepper is None or len(pepper) < 32 or pepper in KNOWN_INSECURE_TOKEN_PEPPERS:
            raise ValueError(
                "FLOWPROOF_TOKEN_PEPPER must be a non-default value of at least 32 characters"
            )
        if not self.session_cookie_secure:
            if self.environment == "production":
                raise ValueError("production session cookies must be Secure")
            origin = urlsplit(self.cors_origin)
            if origin.scheme != "http" or origin.hostname not in {"127.0.0.1", "localhost"}:
                raise ValueError(
                    "local-appliance insecure cookies require an exact loopback HTTP origin"
                )
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ValueError("session idle lifetime must not exceed absolute lifetime")
        if self.api_token_default_ttl_seconds > self.api_token_max_ttl_seconds:
            raise ValueError("API token default lifetime must not exceed the maximum")
        if self.n8n_credential_ttl_seconds > self.api_token_max_ttl_seconds:
            raise ValueError("n8n credential lifetime must not exceed the API token maximum")
        if self.credential_expiry_alert_seconds >= self.n8n_credential_ttl_seconds:
            raise ValueError(
                "credential expiry alert threshold must be shorter than n8n credential lifetime"
            )
        if self.cors_origin == "*":
            raise ValueError("production CORS origin must be an exact origin")
        if self.environment == "production" and not self.alert_webhook_url:
            raise ValueError("production alert webhook destination is required")


def _database_url_from_environment() -> str:
    direct = os.getenv("FLOWPROOF_DATABASE_URL")
    if direct:
        return direct
    password = _secret_value("FLOWPROOF_DATABASE_PASSWORD") or _secret_value("POSTGRES_PASSWORD")
    if not password:
        return "sqlite:///./flowproof.db"
    host = os.getenv("FLOWPROOF_DATABASE_HOST", "postgres")
    port = _positive_int("FLOWPROOF_DATABASE_PORT", 5432)
    database = os.getenv("FLOWPROOF_DATABASE_NAME", "flowproof")
    user = os.getenv("FLOWPROOF_DATABASE_USER", "flowproof")
    if not host or not database or not user:
        raise ValueError("database host, name, and user must be non-empty")
    return (
        "postgresql+psycopg://"
        f"{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{quote_plus(database)}"
    )


def _secret_value(name: str) -> str | None:
    """Load a bounded secret from exactly one env or Docker-secret file source."""

    direct = os.getenv(name)
    file_name = os.getenv(f"{name}_FILE")
    if direct is not None and file_name is not None:
        raise ValueError(f"{name} and {name}_FILE cannot both be set")
    if file_name is None:
        return direct
    try:
        value = Path(file_name).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"{name}_FILE cannot be read") from exc
    value = value.rstrip("\r\n")
    if not value or "\x00" in value:
        raise ValueError(f"{name}_FILE must contain one non-empty text secret")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    if raw.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if raw.strip().lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value
