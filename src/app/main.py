from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.api.errors import install_error_handlers
from app.api.routers import api_keys, authz, orgs, public, roles, teams, workflows

#: Tag groups in the order they appear in Swagger UI — arranged as a demo/recording
#: walkthrough (identity → hierarchy → resources → publishing → extensions). The
#: names carry a numeric prefix so the sequence is unmistakable in the docs.
TAGS_METADATA: list[dict[str, str]] = [
    {
        "name": "0 · Health",
        "description": "Liveness probe. Start here to confirm the service is up.",
    },
    {
        "name": "1 · Organizations",
        "description": (
            "Org membership: add/remove members and change org-level roles. Super-admin territory."
        ),
    },
    {
        "name": "2 · Teams",
        "description": (
            "Teams within an org: create teams, list your memberships, add/remove "
            "members, change team roles."
        ),
    },
    {
        "name": "3 · Workflows",
        "description": (
            "The resource being protected: create, list (per-row authorized), view, "
            "update, and run workflows."
        ),
    },
    {
        "name": "4 · Publishing & external access",
        "description": (
            "Publish a workflow and run it without logging in — with optional "
            "password and org-only restrictions."
        ),
    },
    {
        "name": "5 · API keys",
        "description": (
            "Machine identities with scoped, lower-than-login privilege (extra point 2)."
        ),
    },
    {
        "name": "6 · Roles (roles-as-data)",
        "description": (
            "Create custom roles by composing seeded capabilities — adding a role is "
            "data, not code."
        ),
    },
    {
        "name": "7 · Authorization (explain)",
        "description": (
            "Transparency endpoint: see ALLOW/DENY and the deciding Cedar policy for "
            "any (principal, action, resource)."
        ),
    },
]


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
            tags=TAGS_METADATA,
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

    @app.get("/health", tags=["0 · Health"], summary="Health check")
    async def health() -> dict[str, str]:
        """Liveness probe — returns `{"status": "ok"}`. Unauthenticated."""
        return {"status": "ok"}

    _install_bearer_scheme(app)
    return app


app = create_app()
