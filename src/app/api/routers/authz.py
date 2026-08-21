"""`POST /v1/authz/explain` — the only endpoint that discloses a `policy_id` to a
client (see app/api/errors.py's module docstring). It exists for debugging "why was
I denied / allowed", so unlike `requires()` it does not raise on a Deny decision for
the requested action — it reports the decision instead.

Cross-tenant safety still applies: a resource the caller cannot SEE must 404 rather
than reveal its attributes, so this handler runs the same visibility check
`requires()` runs (app/api/deps.py) before evaluating the requested action.
"""

from authz_core import (
    Action,
    AuthzEngineError,
    EngineError,
    EntityRef,
    OrgEntity,
    PolicyEngine,
    ResourceNotVisible,
    TeamEntity,
    WorkflowEntity,
)
from fastapi import APIRouter, Depends, Request

from app.api.deps import (
    VISIBILITY_ACTION,
    Authorized,
    build_context,
    get_engine,
    get_entity_provider,
    get_principal,
    requires_authenticated,
)
from app.auth.principal import Principal
from app.domain.models import ExplainRequest, ExplainResponse
from app.infra.entity_provider import SupabaseEntityProvider

router = APIRouter(prefix="/v1", tags=["authz"])


@router.post("/authz/explain", response_model=ExplainResponse)
async def explain(
    request: Request,
    body: ExplainRequest,
    principal: Principal = Depends(get_principal),
    engine: PolicyEngine = Depends(get_engine),
    provider: SupabaseEntityProvider = Depends(get_entity_provider),
    _: Authorized = Depends(requires_authenticated()),
) -> ExplainResponse:
    resource = EntityRef(body.resource_type, str(body.resource_id))
    slice_ = await provider.slice_for(principal.ref, (resource,))

    # Same visibility gate as requires() (app/api/deps.py): a resource absent from
    # the slice — another org's, or nonexistent — 404s before its attributes are
    # ever built, let alone returned. This is what stops explain from becoming a
    # cross-tenant probe.
    entity: WorkflowEntity | TeamEntity | OrgEntity | None = next(
        (e for e in slice_.resources if e.ref == resource), None
    )
    if entity is None:
        raise ResourceNotVisible(resource.literal())

    context = build_context(request, principal)
    visibility = engine.authorize(
        principal=principal.ref,
        action=VISIBILITY_ACTION[resource.type],
        resource=resource,
        slice_=slice_,
        context=context,
    )
    if isinstance(visibility, EngineError):
        raise AuthzEngineError(visibility.message)
    if not visibility.allowed:
        raise ResourceNotVisible(resource.literal())

    # The actual question. Unlike requires(), a Deny here is the answer, not a
    # rejection — it is returned to the caller rather than raised as AuthzDenied.
    decision = engine.authorize(
        principal=principal.ref,
        action=Action(body.action),
        resource=resource,
        slice_=slice_,
        context=context,
    )
    if isinstance(decision, EngineError):  # D6: still never a bogus explain result
        raise AuthzEngineError(decision.message)

    return ExplainResponse(
        decision="Allow" if decision.allowed else "Deny",
        policy_id=decision.policy_id,
        principal_capabilities=sorted(c.literal() for c in slice_.principal.capabilities),
        resource_attributes=entity.to_cedar()["attrs"],
    )
