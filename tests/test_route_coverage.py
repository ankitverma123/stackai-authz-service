"""The service role bypasses RLS, so the FastAPI app is the only thing between a
request and the data (spec D2). The predictable failure is a developer adding an
endpoint and forgetting requires(...). This makes that a CI failure rather than a
silent hole, and adding a public endpoint a reviewable one-line diff.
"""

from collections.abc import Iterable, Iterator
from typing import Any

from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute

from app.api.deps import AUTHZ_DEPENDENCY_MARKER
from app.main import create_app

#: Deliberately unauthenticated. Every entry needs a reason.
PUBLIC_ROUTES: set[tuple[str, str]] = {
    ("GET", "/health"),                                        # liveness probe
    ("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json"),
    ("POST", "/v1/public/workflows/{workflow_id}/access"),      # password exchange, rate-limited
    ("POST", "/v1/public/workflows/{workflow_id}/executions"),  # guarded by Cedar forbids
}


def _is_authz_dependency(dependant: object) -> bool:
    call = getattr(dependant, "call", None)
    return bool(call is not None and getattr(call, AUTHZ_DEPENDENCY_MARKER, False))


def _iter_api_routes(routes: Iterable[Any]) -> Iterator[APIRoute]:
    """Recursively yields every APIRoute, descending into `include_router()` wrappers.

    fastapi>=0.141 wraps each `include_router()` call in a lazy `_IncludedRouter`
    placeholder instead of flattening its routes into `app.routes` eagerly (so
    `dependency_overrides` can rebuild a route's dependants per-app without
    mutating the shared sub-router). A plain `isinstance(route, APIRoute)` walk
    over `app.routes` therefore saw ONLY routes added directly on `app` — every
    route added via `include_router()`, i.e. every real /v1 route in this
    service, was invisible to this test, which passed VACUOUSLY (found during
    Task 18; see `test_walker_fails_closed_on_an_unguarded_included_route` below
    for the proof this recursion actually catches something).

    Handled via `original_router` (the fastapi 0.141 shape) with a fallback to a
    plain `.routes` attribute (Starlette `Mount`, or any future sub-app shape),
    so this keeps working if that internal changes again.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        sub_router = getattr(route, "original_router", None)
        sub_routes = getattr(sub_router, "routes", None)
        if sub_routes is None:
            sub_routes = getattr(route, "routes", None)
        if sub_routes:
            yield from _iter_api_routes(sub_routes)


def _find_unguarded(app: FastAPI, public_routes: set[tuple[str, str]]) -> list[str]:
    unguarded: list[str] = []
    for route in _iter_api_routes(app.routes):
        for method in route.methods - {"HEAD", "OPTIONS"}:
            if (method, route.path) in public_routes:
                continue
            if not any(_is_authz_dependency(d) for d in route.dependant.dependencies):
                unguarded.append(f"{method} {route.path}")
    return unguarded


def test_every_route_is_guarded_or_explicitly_public() -> None:
    unguarded = _find_unguarded(create_app(), PUBLIC_ROUTES)
    assert not unguarded, (
        "routes with no authorization dependency and no PUBLIC_ROUTES entry: "
        f"{sorted(unguarded)}"
    )


def test_allowlist_has_no_stale_entries() -> None:
    """A removed route must not leave a permanent hole in the allowlist."""
    actual = {
        (method, route.path)
        for route in _iter_api_routes(create_app().routes)
        for method in route.methods - {"HEAD", "OPTIONS"}
    }
    stale = {
        e
        for e in PUBLIC_ROUTES
        if e not in actual and not e[1].startswith(("/docs", "/redoc", "/openapi"))
    }
    assert not stale, f"PUBLIC_ROUTES entries for routes that no longer exist: {stale}"


def test_walker_fails_closed_on_an_unguarded_included_route() -> None:
    """Proves `_iter_api_routes` isn't vacuous: an unguarded route added via
    `include_router()` — the exact shape every real /v1 route uses — must be
    caught. Self-contained: builds a throwaway app, never touches create_app()."""
    leaky = APIRouter()

    @leaky.get("/definitely-not-guarded")
    async def _leak() -> dict[str, str]:
        return {"oops": "unguarded"}

    probe = FastAPI()
    probe.include_router(leaky)

    unguarded = _find_unguarded(probe, PUBLIC_ROUTES)
    assert "GET /definitely-not-guarded" in unguarded
