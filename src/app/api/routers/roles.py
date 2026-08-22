"""Runtime role creation (Task 23, Should tier) — the demonstration that "roles
are data, capabilities are code": a role composes EXISTING seeded capabilities
via table rows and can never invent security surface (D3).

DEVIATION FROM THE BRIEF, same shape as api_keys.py's create route: the brief's
Interfaces line reads `POST /v1/roles`, but `Resource.org()` (app/api/deps.py)
authorizes against an id read from a URL *path parameter* — there is no
mechanism to authorize against an id supplied in the body. So this is nested
under `/orgs/{org_id}/roles`, mirroring `POST /orgs/{org_id}/teams` and
`POST /orgs/{org_id}/api-keys`.
"""

from typing import Any, cast
from uuid import UUID

from authz_core import Action, Capability
from fastapi import APIRouter, Depends, status

from app.api.deps import Authorized, Resource, requires
from app.api.errors import UnknownCapability
from app.domain.models import RoleCreate, RoleRead
from app.infra.client import get_supabase
from supabase import Client

router = APIRouter(prefix="/v1", tags=["6 · Roles (roles-as-data)"])

Row = dict[str, Any]

_KNOWN_CAPABILITIES = frozenset(c.value for c in Capability)


def _validate_capabilities(names: list[str]) -> None:
    """Checked against the `Capability` enum — exactly the seeded set — BEFORE
    any Supabase call. This is what makes the 422 a validation failure rather
    than a database round-trip: a role can reference only capabilities that
    already exist as code, never invent one at request time."""
    unknown = [n for n in names if n not in _KNOWN_CAPABILITIES]
    if unknown:
        raise UnknownCapability(unknown)


@router.post(
    "/orgs/{org_id}/roles",
    status_code=status.HTTP_201_CREATED,
    response_model=RoleRead,
    summary="Create a custom role from existing capabilities",
    description=(
        "Demonstrates *adding a role is data, not code*: a new role is a row that "
        "composes already-seeded capabilities. **Requires** `ROLE_CREATE` (super-admin). "
        "Naming a capability that isn't seeded returns **422** — roles can never "
        "invent new security surface."
    ),
)
async def create_role(
    org_id: UUID,
    body: RoleCreate,
    _: Authorized = Depends(requires(Action.ROLE_CREATE, Resource.org())),
    client: Client = Depends(get_supabase),
) -> RoleRead:
    """Composes only existing capabilities: `role_capabilities` rows reference
    `capabilities.name`, a foreign key, so even a validation gap here would
    still be caught at the database — this check exists to turn that into a
    clean 422 instead of an unhandled FK-violation 500."""
    _validate_capabilities(body.capabilities)
    row = cast(
        Row,
        client.table("roles")
        .insert({"org_id": str(org_id), "name": body.name, "scope": body.scope})
        .execute()
        .data[0],
    )
    client.table("role_capabilities").insert(
        [{"role_id": row["id"], "capability": capability} for capability in body.capabilities]
    ).execute()
    return RoleRead(
        id=row["id"],
        org_id=row["org_id"],
        name=row["name"],
        scope=row["scope"],
        capabilities=body.capabilities,
    )
