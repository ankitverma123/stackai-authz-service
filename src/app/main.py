from fastapi import FastAPI

from app.api.errors import install_error_handlers
from app.api.routers import api_keys, authz, orgs, public, roles, teams, workflows


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

    return app


app = create_app()
