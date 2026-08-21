"""Task 16 fix round 1: an unknown role name used to fall through to
`rows[0]["id"]` on an empty list -> uncaught IndexError -> a bare 500 with no
RFC 9457 envelope, reachable by any authenticated caller sending a typo'd role.
Now it's `RoleNotFound` -> a clean 422.
"""

from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.errors import RoleNotFound, install_error_handlers
from app.api.routers.orgs import _resolve_org_role_id
from app.api.routers.teams import _resolve_team_role_id


class FakeTable:
    """Minimal stand-in for the supabase-py query builder (see test_entity_provider.py)."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def select(self, *_: str) -> "FakeTable":
        return self

    def eq(self, *_: object) -> "FakeTable":
        return self

    def or_(self, *_: object) -> "FakeTable":
        return self

    def execute(self) -> object:
        return type("Result", (), {"data": self._rows})()


class FakeClient:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def table(self, _name: str) -> FakeTable:
        return FakeTable(self._rows)


def test_resolve_org_role_id_raises_role_not_found_when_no_match() -> None:
    client = FakeClient([])
    org_id = UUID("11111111-1111-1111-1111-111111111111")
    with pytest.raises(RoleNotFound, match="not-a-real-role"):
        _resolve_org_role_id(client, org_id=org_id, name="not-a-real-role")  # type: ignore[arg-type]


def test_resolve_team_role_id_raises_role_not_found_when_no_match() -> None:
    client = FakeClient([])
    with pytest.raises(RoleNotFound, match="not-a-real-role"):
        _resolve_team_role_id(client, org_id="org-1", name="not-a-real-role")  # type: ignore[arg-type]


def test_role_not_found_maps_to_422_problem_json() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise RoleNotFound("not-a-real-role")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert "not-a-real-role" in body["detail"]
    assert "correlation_id" in body
