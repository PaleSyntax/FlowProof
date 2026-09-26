"""OpenAPI route/auth/status contract composition."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


def install_openapi_contract(app: FastAPI) -> None:
    def secured_openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        document = get_openapi(title=app.title, version=app.version, routes=app.routes)
        security_schemes = document.setdefault("components", {}).setdefault(
            "securitySchemes", {}
        )
        security_schemes.update(
            {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "API credential issued to a human or service principal.",
                },
                "SessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "flowproof_session",
                    "description": (
                        "Human browser session; state-changing requests also require "
                        "X-CSRF-Token."
                    ),
                },
            }
        )
        for path, path_item in document.get("paths", {}).items():
            if path in {
                "/api/v1/auth/login",
                "/api/v1/provider-connections/xero/callback",
            } or not path.startswith("/api/v1/"):
                continue
            for method, operation in path_item.items():
                if method in {"get", "post", "put", "patch", "delete"}:
                    operation["security"] = [{"BearerAuth": []}, {"SessionCookie": []}]
        app.openapi_schema = document
        return document

    app.openapi = secured_openapi
