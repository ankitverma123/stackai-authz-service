"""Organization membership endpoints. `remove_org_member` and `change_org_role`
are routed through their RPC so the last-super-admin count and the write run
atomically (spec D7a) — see app/invariants/sqlstate.py. `add_org_member` cannot
strand an org, so it is a direct insert.
"""

from typing import Any, cast
from uuid import UUID

from authz_core import Action
from fastapi import APIRouter, Depends, status
from postgrest.exceptions import APIError

from app.api.deps import Authorized, Resource, requires
from app.api.errors import RoleNotFound
from app.domain.models import MembershipCreate, MembershipRead
from app.infra.client import get_supabase
from app.invariants.sqlstate import raise_for_postgrest_error
from supabase import Client

router = APIRouter(prefix="/v1", tags=["orgs"])

Row = dict[str, Any]


def _resolve_org_role_id(client: Client, *, org_id: UUID, name: str) -> str:
    """Prefer a custom org role scoped to this org; fall back to the seeded
    built-in of the same name (roles.org_id is null for built-ins)."""
    rows = cast(
        list[Row],
        client.table("roles")
        .select("id, org_id")
        .eq("scope", "org")
        .eq("name", name)
        .or_(f"org_id.eq.{org_id},org_id.is.null")
        .execute()
        .data,
    )
    if not rows:
        raise RoleNotFound(name)
    for row in rows:
        if row["org_id"] == str(org_id):
            return str(row["id"])
    return str(rows[0]["id"])


@router.post(
    "/orgs/{org_id}/members",
    status_code=status.HTTP_201_CREATED,
    response_model=MembershipRead,
)
async def add_org_member(
    org_id: UUID,
    body: MembershipCreate,
    _: Authorized = Depends(requires(Action.ORG_ADD_USER, Resource.org())),
    client: Client = Depends(get_supabase),
) -> MembershipRead:
    """A direct insert, not an RPC: adding a member cannot strand the org, so
    there is no invariant to make atomic. The org_member_joins_default_team
    trigger enrolls the new member in the org's default team as a viewer."""
    role_id = _resolve_org_role_id(client, org_id=org_id, name=body.role)
    client.table("org_memberships").insert(
        {"org_id": str(org_id), "user_id": str(body.user_id), "role_id": role_id}
    ).execute()
    return MembershipRead(user_id=body.user_id, role=body.role)


@router.delete("/orgs/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_org_member(
    org_id: UUID,
    user_id: UUID,
    _: Authorized = Depends(requires(Action.ORG_REMOVE_USER, Resource.org())),
    client: Client = Depends(get_supabase),
) -> None:
    """Runs LastSuperAdmin inside remove_org_member; a ZA001 violation becomes 409."""
    try:
        client.rpc(
            "remove_org_member", {"p_org_id": str(org_id), "p_user_id": str(user_id)}
        ).execute()
    except APIError as exc:
        raise_for_postgrest_error(exc)


@router.patch("/orgs/{org_id}/members/{user_id}", response_model=MembershipRead)
async def change_org_role(
    org_id: UUID,
    user_id: UUID,
    body: MembershipCreate,
    _: Authorized = Depends(requires(Action.ORG_CHANGE_ROLE, Resource.org())),
    client: Client = Depends(get_supabase),
) -> MembershipRead:
    """Runs LastSuperAdmin inside change_org_role when the new role drops manage_org.
    The path `user_id` is authoritative; `body.user_id` is unused (the same
    MembershipCreate model also serves POST, where the body IS the target)."""
    role_id = _resolve_org_role_id(client, org_id=org_id, name=body.role)
    try:
        client.rpc(
            "change_org_role",
            {"p_org_id": str(org_id), "p_user_id": str(user_id), "p_role_id": role_id},
        ).execute()
    except APIError as exc:
        raise_for_postgrest_error(exc)
    return MembershipRead(user_id=user_id, role=body.role)
