"""Task 18's security proof, mirrored from test_unknown_capability.py: an unknown
API-key scope must be a clean 422, not the uncaught FK-violation 500 that
`api_key_grants.scope` would otherwise raise — covered here without a live
database, the same idiom as UnknownCapability."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.errors import UnknownApiKeyScope, install_error_handlers
from app.api.routers.api_keys import _validate_scopes


def test_validate_scopes_raises_on_an_unknown_scope() -> None:
    with pytest.raises(UnknownApiKeyScope, match="workflow:write"):
        _validate_scopes(["workflow:read", "workflow:write"])


def test_validate_scopes_accepts_only_seeded_scopes() -> None:
    _validate_scopes(["workflow:read", "workflow:run"])  # no raise


def test_unknown_api_key_scope_maps_to_422_problem_json() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise UnknownApiKeyScope(["workflow:write"])

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert "workflow:write" in body["detail"]
    assert "correlation_id" in body
