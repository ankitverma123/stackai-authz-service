"""The service role bypasses RLS, so the FastAPI app is the only thing between a
request and the data (spec D2). The predictable failure is a developer adding an
endpoint and forgetting requires(...). This makes that a CI failure rather than a
silent hole, and adding a public endpoint a reviewable one-line diff.
"""

from fastapi.routing import APIRoute

from app.api.deps import AUTHZ_DEPENDENCY_MARKER
from app.main import create_app

#: Deliberately unauthenticated. Every entry needs a reason.
PUBLIC_ROUTES: set[tuple[str, str]] = {
    ("GET", "/health"),                                        # liveness probe
    ("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json"),
    # Task 19 will add:
    # ("POST", "/v1/public/workflows/{workflow_id}/access"),     # password exchange
    # ("POST", "/v1/public/workflows/{workflow_id}/executions"), # guarded by Cedar forbids
}


def _is_authz_dependency(dependant: object) -> bool:
    call = getattr(dependant, "call", None)
    return bool(call is not None and getattr(call, AUTHZ_DEPENDENCY_MARKER, False))


def test_every_route_is_guarded_or_explicitly_public() -> None:
    unguarded: list[str] = []
    for route in create_app().routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            if (method, route.path) in PUBLIC_ROUTES:
                continue
            if not any(_is_authz_dependency(d) for d in route.dependant.dependencies):
                unguarded.append(f"{method} {route.path}")
    assert not unguarded, (
        "routes with no authorization dependency and no PUBLIC_ROUTES entry: "
        f"{sorted(unguarded)}"
    )


def test_allowlist_has_no_stale_entries() -> None:
    """A removed route must not leave a permanent hole in the allowlist."""
    actual = {
        (method, route.path)
        for route in create_app().routes
        if isinstance(route, APIRoute)
        for method in route.methods - {"HEAD", "OPTIONS"}
    }
    stale = {
        e
        for e in PUBLIC_ROUTES
        if e not in actual and not e[1].startswith(("/docs", "/redoc", "/openapi"))
    }
    assert not stale, f"PUBLIC_ROUTES entries for routes that no longer exist: {stale}"
