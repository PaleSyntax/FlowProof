"""Generate the committed OpenAPI contract from executable FastAPI routes."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml
from flowproof.config import Settings
from flowproof.main import create_app

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "specs" / "openapi.yaml")
    args = parser.parse_args()
    settings = Settings(
        database_url="sqlite://",
        cors_origin="http://localhost:5173",
        mock_accounting_url="http://mock-accounting:8001",
        policy_path=ROOT / "specs" / "policies" / "invoice-processing.yaml",
        environment="contract-generation",
        provider_contract_path=(
            ROOT / "specs" / "providers" / "mock-accounting" / "contract.json"
        ),
        token_pepper="contract-generation-pepper-value-32-bytes",
    )
    document = create_app(settings).openapi()
    args.output.write_text(
        yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
