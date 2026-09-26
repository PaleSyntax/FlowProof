"""FlowProof API entry point with an explicit provider factory."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, status
from sqlalchemy.orm import Session, sessionmaker

from flowproof.accounting import AccountingClient, ProviderContract
from flowproof.config import Settings
from flowproof.provider_factory import create_provider_adapter
from flowproof.service import RecoveryGateError


def recovery_gate_http_exception(
    exc: RecoveryGateError,
) -> HTTPException:
    code = (
        status.HTTP_404_NOT_FOUND
        if str(exc) == "recovery plan was not found"
        else status.HTTP_409_CONFLICT
    )
    return HTTPException(status_code=code, detail=str(exc))


def create_app(
    settings: Settings | None = None,
    accounting: AccountingClient | None = None,
    session_factory: sessionmaker[Session] | None = None,
) -> FastAPI:
    """Validate startup input, select one registered adapter, then compose routes."""

    config = settings or Settings.from_environment()
    try:
        config.validate_production_security()
    except ValueError as exc:
        raise RuntimeError("invalid production identity configuration") from exc

    client = accounting
    if client is None:
        if config.provider_contract_path is None:
            raise RuntimeError("provider contract path is required")
        contract = ProviderContract.load(config.provider_contract_path)
        try:
            client = create_provider_adapter(
                config.provider_base_url or config.mock_accounting_url,
                contract,
                environment=config.environment,
            )
        except ValueError as exc:
            raise RuntimeError(
                "provider adapter configuration is invalid"
            ) from exc

    from flowproof.main_core import compose_app

    return compose_app(config, client, session_factory)


app = create_app()


__all__ = [
    "app",
    "create_app",
    "recovery_gate_http_exception",
]
