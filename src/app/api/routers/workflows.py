"""Workflow endpoints, including the query-time SQL pre-filter for the list route.

`list_workflows` is the only route guarded by `requires_authenticated()` rather than
`requires(...)`: a collection has no single resource, so the SQL pre-filter narrows
the candidate rows and `authorize_batch` rules on every row that comes back — see
that function's docstring and app/infra/prefilter.py's module docstring for why a
too-narrow filter would be a correctness bug, not just an inefficiency.

DEVIATION FROM THE BRIEF: workflow creation is `POST /v1/teams/{team_id}/workflows`,
not a flat `POST /v1/workflows`. `WORKFLOW_CREATE` is authorized against
`Resource.team()`, and `requires()`'s `ResourceSpec.resolve()` (app/api/deps.py)
only reads a resource id from a URL *path parameter* — there is no mechanism to
authorize against an id supplied in the request body. Nesting under the team
mirrors the existing convention for `POST /orgs/{org_id}/teams` and keeps the
shared guard machinery in deps.py untouched.
"""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from authz_core import Action, AuthzEngineError, EngineError, EntityRef, PolicyEngine
from fastapi import APIRouter, Depends, Query, Request, status

from app.api.deps import (
    Authorized,
    Resource,
    build_context,
    get_engine,
    get_entity_provider,
    get_principal,
    requires,
    requires_authenticated,
)
from app.auth.principal import Principal
from app.domain.models import (
    WorkflowCreate,
    WorkflowExecutionRead,
    WorkflowExportProtectionRead,
    WorkflowExportProtectionUpdate,
    WorkflowExportRead,
    WorkflowExportUpdate,
    WorkflowPage,
    WorkflowRead,
    WorkflowUpdate,
)
from app.infra.client import get_supabase
from app.infra.entity_provider import SupabaseEntityProvider
from app.infra.lookups import team_org_id as _team_org_id
from app.infra.prefilter import build_workflow_prefilter
from supabase import Client

router = APIRouter(prefix="/v1", tags=["workflows"])

Row = dict[str, Any]

#: Starting points (brief §17): trades a slightly larger fetch for far fewer
#: round-trips when a principal can see only a minority of the org's workflows.
OVERFETCH_FACTOR = 3
#: Caps the walk when almost everything is denied, so the endpoint returns a short
#: page with a live cursor rather than scanning the whole table one round at a time.
MAX_REFILL_ROUNDS = 5

#: Hashes and verifies passwords for protected exports. argon2-cffi's PasswordHasher
#: defaults to argon2id (CLAUDE.md: "the application does the cryptography, Cedar
#: makes the decision" — the hash never reaches the engine).
_hasher = PasswordHasher()


@router.post(
    "/teams/{team_id}/workflows",
    status_code=status.HTTP_201_CREATED,
    response_model=WorkflowRead,
)
async def create_workflow(
    team_id: UUID,
    body: WorkflowCreate,
    _: Authorized = Depends(requires(Action.WORKFLOW_CREATE, Resource.team())),
    principal: Principal = Depends(get_principal),
    client: Client = Depends(get_supabase),
) -> WorkflowRead:
    org_id = _team_org_id(client, team_id)
    row = cast(
        Row,
        client.table("workflows")
        .insert(
            {
                "org_id": org_id,
                "team_id": str(team_id),
                "name": body.name,
                "created_by": principal.subject,
            }
        )
        .execute()
        .data[0],
    )
    return WorkflowRead.model_validate(row)


@router.get("/workflows", response_model=WorkflowPage)
async def list_workflows(
    request: Request,
    principal: Principal = Depends(get_principal),
    provider: SupabaseEntityProvider = Depends(get_entity_provider),
    engine: PolicyEngine = Depends(get_engine),
    client: Client = Depends(get_supabase),
    limit: int = Query(50, le=200),
    cursor: str | None = Query(None, description="id of the last row from the previous page"),
    _: Authorized = Depends(requires_authenticated()),
) -> WorkflowPage:
    """Guarded by requires_authenticated() rather than requires(...): a collection
    has no single resource. The authoritative check is authorize_batch below, which
    rules on every row individually."""
    cap_slice = await provider.capability_slice(principal.subject)
    spec = build_workflow_prefilter(cap_slice)
    if spec.is_empty():
        return WorkflowPage(items=[], next_cursor=None)

    # Pagination happens AFTER authorization. The pre-filter is deliberately a
    # superset, so slicing the page in SQL would yield under-filled pages of
    # unpredictable size and a client could not tell "end of results" from "this
    # page was mostly denied". Over-fetch, authorize, then take `limit` survivors.
    survivors: list[Row] = []
    fetch_cursor = cursor
    last_fetched_id: str | None = None
    exhausted = False
    rounds = 0

    # Capped: a corpus where almost everything is denied would otherwise walk the
    # whole table one over-fetch at a time. On the cap we return a short page with
    # a live cursor rather than hanging.
    while len(survivors) < limit and not exhausted and rounds < MAX_REFILL_ROUNDS:
        rounds += 1
        query = (
            client.table("workflows").select("*, workflow_exports(*)").or_(spec.to_postgrest_or())
        )
        # Only applied once a cursor exists. `id` is a uuid column, and comparing
        # it against "" (the pre-fix sentinel for "no cursor yet") is rejected by
        # Postgres on the very first page — omit the filter entirely instead.
        if fetch_cursor:
            query = query.gt("id", fetch_cursor)
        rows = cast(
            list[Row],
            query.order("id").limit(limit * OVERFETCH_FACTOR).execute().data,
        )
        if not rows:
            exhausted = True
            break

        refs = tuple(EntityRef("Workflow", r["id"]) for r in rows)
        slice_ = await provider.slice_for(principal.ref, refs)
        decisions = engine.authorize_batch(  # authoritative — the filter is not
            principal=principal.ref,
            action=Action.WORKFLOW_VIEW,  # each ROW is a view; the endpoint
            resources=refs,  # itself is guarded by requires_authenticated()
            slice_=slice_,
            context=build_context(request, principal),
        )
        for decision in decisions:
            if isinstance(decision, EngineError):
                raise AuthzEngineError(decision.message)

        survivors.extend(row for row, d in zip(rows, decisions, strict=True) if d.allowed)
        last_fetched_id = rows[-1]["id"]
        fetch_cursor = last_fetched_id
        exhausted = len(rows) < limit * OVERFETCH_FACTOR

    page = survivors[:limit]
    if len(survivors) > limit:
        # More authorized rows were fetched than fit on this page: resume from the
        # last RETURNED row so the truncated extras (which sort after it) are
        # re-included on the next page.
        next_page_cursor = page[-1]["id"]
    elif exhausted:
        # Genuine end of results: rows ran out while scanning, not just while
        # collecting survivors.
        next_page_cursor = None
    else:
        # The round cap was hit (or the last round landed exactly on `limit`)
        # before the table was exhausted. Every fetched survivor was already
        # returned, so an empty-but-not-exhausted page must still carry a LIVE
        # cursor — resuming at the furthest id we SCANNED, not just the furthest
        # one we returned, or the client can't tell "denied so far" from "the end".
        next_page_cursor = last_fetched_id

    return WorkflowPage(
        items=[WorkflowRead.model_validate(r) for r in page],
        next_cursor=next_page_cursor,
    )


@router.get("/workflows/{workflow_id}", response_model=WorkflowRead)
async def get_workflow(
    workflow_id: UUID,
    _: Authorized = Depends(requires(Action.WORKFLOW_VIEW, Resource.workflow())),
    client: Client = Depends(get_supabase),
) -> WorkflowRead:
    row = cast(
        Row,
        client.table("workflows").select("*").eq("id", str(workflow_id)).single().execute().data,
    )
    return WorkflowRead.model_validate(row)


@router.put("/workflows/{workflow_id}", response_model=WorkflowRead)
async def update_workflow(
    workflow_id: UUID,
    body: WorkflowUpdate,
    _: Authorized = Depends(requires(Action.WORKFLOW_UPDATE, Resource.workflow())),
    client: Client = Depends(get_supabase),
) -> WorkflowRead:
    row = cast(
        Row,
        client.table("workflows")
        .update({"name": body.name})
        .eq("id", str(workflow_id))
        .execute()
        .data[0],
    )
    return WorkflowRead.model_validate(row)


@router.post(
    "/workflows/{workflow_id}/executions",
    status_code=status.HTTP_201_CREATED,
    response_model=WorkflowExecutionRead,
)
async def run_workflow(
    workflow_id: UUID,
    _: Authorized = Depends(requires(Action.WORKFLOW_RUN, Resource.workflow())),
) -> WorkflowExecutionRead:
    """Canned: no executions table exists (out of scope for this service). Proves
    the WORKFLOW_RUN guard without inventing storage this task doesn't own."""
    return WorkflowExecutionRead(
        id=uuid4(), workflow_id=workflow_id, status="queued", started_at=datetime.now(UTC)
    )


@router.put("/workflows/{workflow_id}/export", response_model=WorkflowExportRead)
async def set_workflow_export(
    workflow_id: UUID,
    body: WorkflowExportUpdate,
    _: Authorized = Depends(requires(Action.WORKFLOW_EXPORT, Resource.workflow())),
    client: Client = Depends(get_supabase),
) -> WorkflowExportRead:
    row = cast(
        Row,
        client.table("workflow_exports")
        .upsert(
            {
                "workflow_id": str(workflow_id),
                "is_exported": True,
                "visibility": body.visibility,
            }
        )
        .execute()
        .data[0],
    )
    return WorkflowExportRead(
        workflow_id=workflow_id,
        is_exported=row["is_exported"],
        visibility=row["visibility"],
        password_protected=row.get("password_hash") is not None,
    )


@router.delete("/workflows/{workflow_id}/export", status_code=status.HTTP_204_NO_CONTENT)
async def unset_workflow_export(
    workflow_id: UUID,
    _: Authorized = Depends(requires(Action.WORKFLOW_EXPORT, Resource.workflow())),
    client: Client = Depends(get_supabase),
) -> None:
    """A plain update, not a delete: password/visibility survive being unpublished,
    so re-publishing doesn't silently drop a protection password."""
    client.table("workflow_exports").update({"is_exported": False}).eq(
        "workflow_id", str(workflow_id)
    ).execute()


@router.put(
    "/workflows/{workflow_id}/export/protection", response_model=WorkflowExportProtectionRead
)
async def set_workflow_export_protection(
    workflow_id: UUID,
    body: WorkflowExportProtectionUpdate,
    _: Authorized = Depends(requires(Action.WORKFLOW_PROTECT_EXPORT, Resource.workflow())),
    client: Client = Depends(get_supabase),
) -> WorkflowExportProtectionRead:
    """Only `password_hash` is sent in the upsert payload, so on an existing row
    PostgREST's `ON CONFLICT DO UPDATE` leaves `is_exported`/`visibility` untouched;
    on a new row they take their table defaults. The hash itself never reaches
    Cedar — only `password_protected`, a derived boolean, does (entity_provider.py)."""
    password_hash = _hasher.hash(body.password) if body.password is not None else None
    row = cast(
        Row,
        client.table("workflow_exports")
        .upsert({"workflow_id": str(workflow_id), "password_hash": password_hash})
        .execute()
        .data[0],
    )
    return WorkflowExportProtectionRead(
        workflow_id=workflow_id, password_protected=row.get("password_hash") is not None
    )
