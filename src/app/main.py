from fastapi import FastAPI

from app.api.errors import install_error_handlers
from app.api.routers import orgs, teams


def create_app() -> FastAPI:
    app = FastAPI(
        title="StackAI Authorization Service",
        version="0.1.0",
        description="Multi-tenant RBAC with Cedar-backed, fine-grained query-time enforcement.",
    )
    install_error_handlers(app)
    app.include_router(orgs.router)
    app.include_router(teams.router)

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
