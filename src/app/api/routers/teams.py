"""Team membership endpoints. `remove_team_member` and `change_team_role` are
routed through their RPC so the last-team-admin count and the default-team
protection run atomically with the write (spec D7a) — see
app/invariants/sqlstate.py. `add_team_member` cannot strand a team, so it is a
direct insert.
"""

from typing import Any, cast
from uuid import UUID

from authz_core import Action
from fastapi import APIRouter, Depends, status
from postgrest.exceptions import APIError

from app.api.deps import Authorized, Resource, get_principal, requires, requires_authenticated
from app.api.errors import RoleNotFound
from app.auth.principal import Principal
from app.domain.models import (
    MembershipCreate,
    MembershipRead,
    TeamCreate,
    TeamMembershipRead,
    TeamRead,
)
from app.infra.client import get_supabase
from app.invariants.sqlstate import raise_for_postgrest_error
from supabase import Client

router = APIRouter(prefix="/v1", tags=["teams"])

Row = dict[str, Any]


def _team_org_id(client: Client, team_id: UUID) -> str:
    """The guard has already confirmed team_id is visible, so exactly one row
    exists here — safe to use .single() rather than handling zero/many."""
    row = cast(
        Row, client.table("teams").select("org_id").eq("id", str(team_id)).single().execute().data
    )
    return str(row["org_id"])


def _resolve_team_role_id(client: Client, *, org_id: str, name: str) -> str:
    """Prefer a custom team role scoped to this org; fall back to the seeded
    built-in of the same name (roles.org_id is null for built-ins)."""
    rows = cast(
        list[Row],
        client.table("roles")
        .select("id, org_id")
        .eq("scope", "team")
        .eq("name", name)
        .or_(f"org_id.eq.{org_id},org_id.is.null")
        .execute()
        .data,
    )
    if not rows:
        raise RoleNotFound(name)
    for row in rows:
        if row["org_id"] == org_id:
            return str(row["id"])
    return str(rows[0]["id"])


def _is_org_super_admin(client: Client, *, org_id: str, user_id: str) -> bool:
    """remove_team_member/change_team_role waive the last-team-admin check for an
    org super-admin (they can always reach in and fix a stranded team)."""
    rows = cast(
        list[Row],
        client.table("org_memberships")
        .select("roles(role_capabilities(capability))")
        .eq("org_id", org_id)
        .eq("user_id", user_id)
        .execute()
        .data,
    )
    if not rows:
        return False
    caps = {rc["capability"] for rc in (rows[0].get("roles") or {}).get("role_capabilities", [])}
    return "manage_org" in caps


@router.post(
    "/orgs/{org_id}/teams",
    status_code=status.HTTP_201_CREATED,
    response_model=TeamRead,
)
async def create_team(
    org_id: UUID,
    body: TeamCreate,
    _: Authorized = Depends(requires(Action.TEAM_CREATE, Resource.org())),
    principal: Principal = Depends(get_principal),
    client: Client = Depends(get_supabase),
) -> TeamRead:
    """The creator is atomically made the team's admin — otherwise they would
    create a team they cannot administer (assumption #15)."""
    row = cast(
        Row,
        client.table("teams")
        .insert({"org_id": str(org_id), "name": body.name, "created_by": principal.subject})
        .execute()
        .data[0],
    )
    return TeamRead.model_validate(row)


@router.get("/me/teams", response_model=list[TeamMembershipRead])
async def list_my_teams(
    principal: Principal = Depends(get_principal),
    _: Authorized = Depends(requires_authenticated()),
    client: Client = Depends(get_supabase),
) -> list[TeamMembershipRead]:
    """Returns only the caller's OWN memberships, so the principal is the entire
    authorization scope — there is no resource to hand Cedar."""
    rows = cast(
        list[Row],
        client.table("team_memberships")
        .select("team_id, roles(name), teams(name, org_id, is_default)")
        .eq("user_id", principal.subject)
        .execute()
        .data,
    )
    return [
        TeamMembershipRead(
            team_id=row["team_id"],
            team_name=row["teams"]["name"],
            org_id=row["teams"]["org_id"],
            role=row["roles"]["name"],
            is_default=row["teams"]["is_default"],
        )
        for row in rows
    ]


@router.post(
    "/teams/{team_id}/members",
    status_code=status.HTTP_201_CREATED,
    response_model=MembershipRead,
)
async def add_team_member(
    team_id: UUID,
    body: MembershipCreate,
    _: Authorized = Depends(requires(Action.TEAM_ADD_MEMBER, Resource.team())),
    client: Client = Depends(get_supabase),
) -> MembershipRead:
    """A direct insert, not an RPC: adding a member cannot strand the team, so
    there is no invariant to make atomic."""
    org_id = _team_org_id(client, team_id)
    role_id = _resolve_team_role_id(client, org_id=org_id, name=body.role)
    client.table("team_memberships").insert(
        {"team_id": str(team_id), "user_id": str(body.user_id), "role_id": role_id}
    ).execute()
    return MembershipRead(user_id=body.user_id, role=body.role)


@router.delete("/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_team_member(
    team_id: UUID,
    user_id: UUID,
    _: Authorized = Depends(requires(Action.TEAM_REMOVE_MEMBER, Resource.team())),
    principal: Principal = Depends(get_principal),
    client: Client = Depends(get_supabase),
) -> None:
    """Runs LastTeamAdmin and DefaultTeamProtected after authorization; either
    raises InvariantViolation -> 409."""
    org_id = _team_org_id(client, team_id)
    actor_is_super_admin = _is_org_super_admin(client, org_id=org_id, user_id=principal.subject)
    try:
        client.rpc(
            "remove_team_member",
            {
                "p_team_id": str(team_id),
                "p_user_id": str(user_id),
                "p_actor_is_super_admin": actor_is_super_admin,
            },
        ).execute()
    except APIError as exc:
        raise_for_postgrest_error(exc)


@router.patch("/teams/{team_id}/members/{user_id}", response_model=MembershipRead)
async def change_team_role(
    team_id: UUID,
    user_id: UUID,
    body: MembershipCreate,
    _: Authorized = Depends(requires(Action.TEAM_CHANGE_ROLE, Resource.team())),
    principal: Principal = Depends(get_principal),
    client: Client = Depends(get_supabase),
) -> MembershipRead:
    """Runs LastTeamAdmin (demotion path) inside change_team_role when the new
    role drops manage_members. The path `user_id` is authoritative; `body.user_id`
    is unused (the same MembershipCreate model also serves POST, where the body
    IS the target)."""
    org_id = _team_org_id(client, team_id)
    role_id = _resolve_team_role_id(client, org_id=org_id, name=body.role)
    actor_is_super_admin = _is_org_super_admin(client, org_id=org_id, user_id=principal.subject)
    try:
        client.rpc(
            "change_team_role",
            {
                "p_team_id": str(team_id),
                "p_user_id": str(user_id),
                "p_role_id": role_id,
                "p_actor_is_super_admin": actor_is_super_admin,
            },
        ).execute()
    except APIError as exc:
        raise_for_postgrest_error(exc)
    return MembershipRead(user_id=user_id, role=body.role)
