from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.api.errors import install_error_handlers
from app.api.routers import api_keys, authz, orgs, public, roles, teams, workflows


def _install_bearer_scheme(app: FastAPI) -> None:
    """Add an http-bearer security scheme to the OpenAPI document.

    Authentication happens in get_principal by reading the Authorization header
    directly, not through a FastAPI security utility, so nothing would otherwise put
    a scheme in the schema — leaving Swagger UI (/docs) with no "Authorize" button
    and no way to attach a Bearer token from the UI. This is a docs-only shim: it
    changes the generated schema, never request handling, so it neither enforces nor
    relaxes auth. Applied globally so the button is offered on every operation;
    public routes simply ignore the header.
    """

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema.setdefault("components", {})["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": (
                    "Paste a Supabase user access token — mint one with "
                    "POST /auth/v1/token?grant_type=password (see scripts/dev_seed.sh)."
                ),
            }
        }
        schema["security"] = [{"bearerAuth": []}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


def create_app() -> FastAPI:
    app = FastAPI(
        title="StackAI Authorization Service",
        version="0.1.0",
        description="Multi-tenant RBAC with Cedar-backed, fine-grained query-time enforcement.",
    )
    install_error_handlers(app)
    app.include_router(orgs.router)
    app.include_router(teams.router)
    app.include_router(workflows.router)
    app.include_router(api_keys.router)
    app.include_router(roles.router)
    app.include_router(public.router)
    app.include_router(authz.router)

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    _install_bearer_scheme(app)
    return app


app = create_app()
