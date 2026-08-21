"""Router-level coverage for GET /v1/workflows — the over-fetch -> authorize_batch
-> take-limit pagination loop had zero coverage before fix round 1 caught a real
bug in it (see the docstring on the second test below).

Uses the FakeClient/FakeTable pattern from tests/test_entity_provider.py, but the
"workflows" table only: the entity provider and engine are swapped for stubs via
FastAPI's dependency_overrides (same technique as tests/conftest.py's StubEngine/
StubProvider), so this exercises the real router code end-to-end without a database.
"""

from typing import Any
from uuid import uuid4

from authz_core import (
    Allow,
    Capability,
    Decision,
    Deny,
    EntityRef,
    EntitySlice,
    PrincipalEntity,
)
from fastapi.testclient import TestClient

from app.api.deps import get_engine, get_entity_provider, get_principal
from app.api.routers.workflows import MAX_REFILL_ROUNDS, OVERFETCH_FACTOR
from app.auth.principal import AuthMethod, Principal
from app.infra.client import get_supabase
from app.infra.entity_provider import CapabilitySlice
from app.main import create_app

Row = dict[str, Any]

_PRINCIPAL = Principal(subject="u1", auth_method=AuthMethod.JWT)


def _row() -> Row:
    return {
        "id": str(uuid4()),
        "org_id": str(uuid4()),
        "team_id": str(uuid4()),
        "name": "wf",
        "created_at": "2026-01-01T00:00:00Z",
    }


class FakeWorkflowsTable:
    """Stands in for client.table("workflows")....execute() inside list_workflows.
    `pages` is keyed by the `.gt()` cursor value, so a test can script what each
    successive over-fetch round returns without a real database."""

    def __init__(self, pages: dict[str, list[Row]]) -> None:
        self._pages = pages
        self._cursor = ""
        self.gt_calls: list[str] = []

    def select(self, *_: str) -> "FakeWorkflowsTable":
        return self

    def or_(self, *_: str) -> "FakeWorkflowsTable":
        return self

    def gt(self, _column: str, value: str) -> "FakeWorkflowsTable":
        self.gt_calls.append(value)
        self._cursor = value
        return self

    def order(self, *_: str) -> "FakeWorkflowsTable":
        return self

    def limit(self, *_: int) -> "FakeWorkflowsTable":
        return self

    def execute(self) -> object:
        return type("Result", (), {"data": self._pages.get(self._cursor, [])})()


class FakeClient:
    def __init__(self, pages: dict[str, list[Row]]) -> None:
        self._table = FakeWorkflowsTable(pages)

    def table(self, name: str) -> FakeWorkflowsTable:
        assert name == "workflows", name
        return self._table


class StubProvider:
    """A non-empty capability slice so the pre-filter isn't trivially empty.
    slice_for's return value is never inspected by DecisionEngine below — it only
    needs to satisfy the router's `await provider.slice_for(...)` call."""

    async def capability_slice(self, user_id: str) -> CapabilitySlice:
        return CapabilitySlice(team_caps={"team-1": {Capability.VIEW}}, org_caps={})

    async def slice_for(
        self, principal: EntityRef, resources: tuple[EntityRef, ...]
    ) -> EntitySlice:
        return EntitySlice(principal=PrincipalEntity(ref=principal), resources=(), caps=())


class DecisionEngine:
    """authorize_batch decides per-resource via a caller-supplied set of allowed
    ids, so a test can control exactly which fetched rows survive."""

    def __init__(self, allowed_ids: set[str]) -> None:
        self._allowed_ids = allowed_ids

    def authorize_batch(
        self, *, resources: tuple[EntityRef, ...], **_: object
    ) -> tuple[Decision, ...]:
        return tuple(Allow(None) if r.id in self._allowed_ids else Deny(None) for r in resources)


def _client(pages: dict[str, list[Row]], allowed_ids: set[str]) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: _PRINCIPAL
    app.dependency_overrides[get_entity_provider] = lambda: StubProvider()
    app.dependency_overrides[get_engine] = lambda: DecisionEngine(allowed_ids)
    app.dependency_overrides[get_supabase] = lambda: FakeClient(pages)
    return TestClient(app)


def test_list_workflows_returns_authorized_survivors_with_a_live_cursor() -> None:
    """Normal page: one round over-fetches limit * OVERFETCH_FACTOR rows, only the
    first `limit` of them are allowed. The cursor must resume from the furthest row
    actually SCANNED (the last of the six fetched), not the furthest one RETURNED
    (the second) — resuming at the returned row would just re-scan the denied rows
    in between on the next page instead of moving past them."""
    limit = 2
    rows = [_row() for _ in range(limit * OVERFETCH_FACTOR)]
    allowed_ids = {rows[0]["id"], rows[1]["id"]}

    client = _client({"": rows}, allowed_ids)
    response = client.get("/v1/workflows", params={"limit": limit})

    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body["items"]] == [rows[0]["id"], rows[1]["id"]]
    assert body["next_cursor"] == rows[-1]["id"]


def test_list_workflows_end_of_results_returns_none_cursor() -> None:
    """Genuine end of results: fewer rows than a full fetch batch come back, so
    next_cursor must be null — the client's actual signal to stop paging."""
    limit = 5
    rows = [_row()]  # far fewer than limit * OVERFETCH_FACTOR

    client = _client({"": rows}, allowed_ids={rows[0]["id"]})
    response = client.get("/v1/workflows", params={"limit": limit})

    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body["items"]] == [rows[0]["id"]]
    assert body["next_cursor"] is None


def test_round_cap_hit_with_no_survivors_still_returns_a_live_cursor() -> None:
    """THE BUG (fix round 1): every row across every refill round is denied, so the
    round cap (MAX_REFILL_ROUNDS) is hit with zero survivors while the table is NOT
    exhausted (every round returns a full batch). The endpoint must return a
    non-None cursor here — returning None (the pre-fix behavior) is indistinguishable
    from genuine end-of-results and silently drops every row past the last one
    scanned."""
    limit = 1
    batch_size = limit * OVERFETCH_FACTOR
    pages: dict[str, list[Row]] = {}
    cursor_key = ""
    last_id = ""
    for _round in range(MAX_REFILL_ROUNDS):
        rows = [_row() for _ in range(batch_size)]
        pages[cursor_key] = rows
        cursor_key = rows[-1]["id"]
        last_id = cursor_key

    client = _client(pages, allowed_ids=set())  # every row denied, every round
    response = client.get("/v1/workflows", params={"limit": limit})

    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    assert body["next_cursor"] == last_id
    assert body["next_cursor"] is not None


def test_list_workflows_first_page_omits_the_gt_filter() -> None:
    """Regression: `.gt("id", fetch_cursor or "")` compared a uuid column against
    the empty string on the first page (no cursor), which Postgres rejects. The
    guard must skip the `.gt()` call entirely when there is no cursor yet."""
    limit = 2
    rows = [_row() for _ in range(limit)]
    fake_client = FakeClient({"": rows})

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: _PRINCIPAL
    app.dependency_overrides[get_entity_provider] = lambda: StubProvider()
    app.dependency_overrides[get_engine] = lambda: DecisionEngine({r["id"] for r in rows})
    app.dependency_overrides[get_supabase] = lambda: fake_client
    client = TestClient(app)

    response = client.get("/v1/workflows", params={"limit": limit})

    assert response.status_code == 200
    assert fake_client._table.gt_calls == []
