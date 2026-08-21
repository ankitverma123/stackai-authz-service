import os

import pytest
from authz_core import (
    Action,
    Allow,
    Capability,
    Decision,
    Deny,
    EngineError,
    EntityRef,
    EntitySlice,
    OrgEntity,
    PrincipalEntity,
    cap_ref,
)
from fastapi import Depends, FastAPI

from app.api.deps import (
    VISIBILITY_ACTION,
    Authorized,
    Resource,
    get_engine,
    get_entity_provider,
    requires,
)
from app.api.errors import install_error_handlers

# get_principal() (app/api/deps.py) calls get_authenticator() as a plain function,
# not through FastAPI's dependency-injection graph, so `dependency_overrides`
# cannot intercept it. That call constructs a JWTAuthenticator, which needs
# Settings to exist — even though these tests never send an Authorization header,
# so the JWT path is built but never exercised (AnonymousAuthenticator handles the
# request). setdefault so a real .env, if ever present, still wins.
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("WORKFLOW_ACCESS_TOKEN_SECRET", "test-workflow-token-secret")


class StubEngine:
    """Returns Allow for the visibility pre-check that `requires()` runs before the
    real decision, and the configured decision for the actual requested action.

    A dumb stub that returned one fixed decision for every call could never pass
    both checks: on a Deny fixture the visibility pre-check would itself Deny,
    turning every test into a 404 (ResourceNotVisible) before the code under test
    — the requested action's own Allow/Deny/EngineError handling — ever runs. This
    distinguishes the two calls by which action is being checked, the same way the
    real Cedar engine distinguishes them by policy content.
    """

    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    def authorize(self, *, action: Action, resource: EntityRef, **_: object) -> Decision:
        if action == VISIBILITY_ACTION.get(resource.type):
            return Allow(None)
        return self._decision

    def authorize_batch(
        self, *, resources: tuple[EntityRef, ...], **_: object
    ) -> tuple[Decision, ...]:
        return tuple(self._decision for _ in resources)


class StubProvider:
    """Reports every requested resource as existing (as an Organization), so the
    tier-1 membership check in `requires()` passes and control reaches the engine
    decision under test."""

    async def slice_for(
        self, principal: EntityRef, resources: tuple[EntityRef, ...]
    ) -> EntitySlice:
        entities = tuple(
            OrgEntity(ref=r, capabilities={c: cap_ref(c, "org", r.id) for c in Capability})
            for r in resources
        )
        return EntitySlice(principal=PrincipalEntity(ref=principal), resources=entities, caps=())


def _app(decision: Decision) -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/guarded/{org_id}")
    async def guarded(
        org_id: str,
        _: Authorized = Depends(requires(Action.WORKFLOW_VIEW, Resource.org())),
    ) -> dict[str, str]:
        return {"ok": "yes"}

    app.dependency_overrides[get_engine] = lambda: StubEngine(decision)
    app.dependency_overrides[get_entity_provider] = lambda: StubProvider()
    return app


@pytest.fixture
def app_with_denied_engine() -> FastAPI:
    return _app(Deny("api-key-no-governance"))


@pytest.fixture
def app_with_erroring_engine() -> FastAPI:
    return _app(EngineError("Workflow::\"wf-1\" does not have the attribute `exported`"))
