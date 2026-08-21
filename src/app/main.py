from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="StackAI Authorization Service",
        version="0.1.0",
        description="Multi-tenant RBAC with Cedar-backed, fine-grained query-time enforcement.",
    )

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
