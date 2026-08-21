"""Task 23's security proof: a role can never invent security surface because
`_validate_capabilities` rejects an unknown capability BEFORE any Supabase call
— covered here without a live database, the same idiom as test_role_not_found.py
for RoleNotFound.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.errors import UnknownCapability, install_error_handlers
from app.api.routers.roles import _validate_capabilities


def test_validate_capabilities_raises_on_an_unknown_capability() -> None:
    with pytest.raises(UnknownCapability, match="become_root"):
        _validate_capabilities(["view", "become_root"])


def test_validate_capabilities_accepts_only_seeded_capabilities() -> None:
    _validate_capabilities(["view", "run", "edit"])  # no raise


def test_unknown_capability_maps_to_422_problem_json() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise UnknownCapability(["become_root"])

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert "become_root" in body["detail"]
    assert "correlation_id" in body
