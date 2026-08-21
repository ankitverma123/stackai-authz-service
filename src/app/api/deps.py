"""The single choke point every authorization decision passes through.

No route handler contains role logic. Adding a guard is one dependency; the
route-coverage test in Task 14 makes forgetting one a CI failure.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, NewType

from authz_core import (
    Action,
    AuthzContext,
    AuthzDenied,
    AuthzEngineError,
    EngineError,
    EntityRef,
    PolicyEngine,
    ResourceNotVisible,
)
from fastapi import Depends, Request

from app.auth.base import AnonymousAuthenticator, AuthenticatorChain
from app.auth.jwt import JWTAuthenticator
from app.auth.principal import Principal
from app.infra.client import get_supabase
from app.infra.entity_provider import SupabaseEntityProvider
from app.settings import get_settings

Authorized = NewType("Authorized", bool)

#: The "can you see this at all?" action per resource type. Checked before the
#: real action so an invisible resource 404s instead of 403-ing (assumption #5).
VISIBILITY_ACTION: dict[str, Action] = {
    "Workflow": Action.WORKFLOW_VIEW,
    "Team": Action.TEAM_VIEW,
    "Organization": Action.ORG_VIEW,
}
# Each action reads an attribute its own resource type declares. An earlier draft
# borrowed WORKFLOW_LIST for Team and Organization; because cap-view evaluates
# `resource.can_view` and Organization has no such attribute, every org-scoped
# route (add/remove member, change role, create team) errored -> D6 -> 500.

#: Attribute stamped on generated dependencies so Task 14 can find them.
AUTHZ_DEPENDENCY_MARKER = "__is_authz_dependency__"


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    entity_type: str
    path_param: str | None = None
    literal_id: str | None = None

    def resolve(self, request: Request) -> EntityRef:
        if self.literal_id is not None:
            return EntityRef(self.entity_type, self.literal_id)
        assert self.path_param is not None
        return EntityRef(self.entity_type, str(request.path_params[self.path_param]))


class Resource:
    @staticmethod
    def workflow(path_param: str = "workflow_id") -> ResourceSpec:
        return ResourceSpec("Workflow", path_param=path_param)

    @staticmethod
    def team(path_param: str = "team_id") -> ResourceSpec:
        return ResourceSpec("Team", path_param=path_param)

    @staticmethod
    def org(path_param: str = "org_id") -> ResourceSpec:
        return ResourceSpec("Organization", path_param=path_param)


def requires_authenticated() -> Callable[..., Awaitable[Authorized]]:
    """Guard for collection endpoints that have no single resource to authorize against.

    `GET /v1/workflows` and `GET /v1/me/teams` are scoped by WHO is asking, not by a
    resource identifier — there is no one entity to pass to Cedar. Authorization for
    these is genuinely per-row: the SQL pre-filter narrows, then `authorize_batch`
    rules on every row that comes back (Task 17).

    So this dependency establishes an authenticated principal and nothing more. It
    carries the marker attribute, which means the route-coverage test in Task 14
    counts it as guarded — correct, because the real gate is the per-row batch check
    inside the handler, not an absent one.
    """

    async def dependency(
        request: Request,
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> Authorized:
        if principal.is_anonymous:
            raise AuthzDenied(None, "authenticated", "collection")
        return Authorized(True)

    setattr(dependency, AUTHZ_DEPENDENCY_MARKER, True)
    return dependency


@lru_cache
def get_engine() -> PolicyEngine:
    return PolicyEngine()


def get_entity_provider() -> SupabaseEntityProvider:
    """DELIBERATELY NOT @lru_cache'd, unlike get_engine and get_authenticator beside it.

    SupabaseEntityProvider._memo is unbounded and never cleared. It is safe only
    because a fresh provider is constructed per request and discarded with it —
    FastAPI caches the dependency result within a request, which is exactly the
    scope we want.

    Adding @lru_cache here to "fix the inconsistency" would promote that memo to a
    process-lifetime permission cache and silently destroy D8: a revoked permission
    would keep working until restart. The engine and authenticator ARE cached
    because they hold no per-principal state.
    """
    return SupabaseEntityProvider(get_supabase())


@lru_cache
def get_authenticator() -> AuthenticatorChain:
    settings = get_settings()
    return AuthenticatorChain([
        JWTAuthenticator(
            secret=settings.supabase_jwt_secret, audience=settings.jwt_audience
        ),
        AnonymousAuthenticator(),
    ])


async def get_principal(request: Request) -> Principal:
    principal = await get_authenticator().authenticate(dict(request.headers))
    request.state.principal = principal
    return principal


def build_context(request: Request, principal: Principal) -> AuthzContext:
    return AuthzContext(
        auth_method=principal.auth_method.value,
        password_verified=bool(getattr(request.state, "password_verified", False)),
        api_key_scopes=principal.api_key_scopes,
        # Without this, assumption #9's "scoped to one org" is unenforced: the key
        # inherits the owner's ENTIRE multi-org capability slice, so a key minted in
        # org A works on org B whenever the owner belongs to both.
        api_key_org_id=principal.api_key_org_id,
    )


def requires(
    action: Action, resource_spec: ResourceSpec
) -> Callable[..., Awaitable[Authorized]]:
    """Build the authorization dependency for one (action, resource) pair."""

    async def dependency(
        request: Request,
        principal: Annotated[Principal, Depends(get_principal)],
        engine: Annotated[PolicyEngine, Depends(get_engine)],
        provider: Annotated[SupabaseEntityProvider, Depends(get_entity_provider)],
    ) -> Authorized:
        resource = resource_spec.resolve(request)
        slice_ = await provider.slice_for(principal.ref, (resource,))

        # VISIBILITY FIRST, then the action. Without this pass, assumption #5 has no
        # implementation: a resource in another org returns 403, which confirms it
        # exists — the exact leak the design claims to prevent — and a nonexistent id
        # yields no entity in the slice, so Cedar errors and D6 turns it into a 500
        # instead of a 404.
        #
        # Costs one extra engine call and NO extra query: the slice is already built.
        if not any(e.ref == resource for e in slice_.resources):
            raise ResourceNotVisible(resource.literal())      # -> 404

        visibility = engine.authorize(
            principal=principal.ref,
            action=VISIBILITY_ACTION[resource.type],
            resource=resource,
            slice_=slice_,
            context=build_context(request, principal),
        )
        if isinstance(visibility, EngineError):
            raise AuthzEngineError(visibility.message)
        if not visibility.allowed:
            # Cannot see it at all -> deny its existence rather than its use.
            raise ResourceNotVisible(resource.literal())      # -> 404

        decision = engine.authorize(
            principal=principal.ref,
            action=action,
            resource=resource,
            slice_=slice_,
            context=build_context(request, principal),
        )

        # D6 — checked FIRST. An Allow carrying errors is the dangerous case.
        if isinstance(decision, EngineError):
            raise AuthzEngineError(decision.message)
        if not decision.allowed:
            raise AuthzDenied(decision.policy_id, action.value, resource.literal())

        request.state.authz_policy_id = decision.policy_id
        request.state.authz_action = action
        return Authorized(True)

    setattr(dependency, AUTHZ_DEPENDENCY_MARKER, True)
    return dependency
