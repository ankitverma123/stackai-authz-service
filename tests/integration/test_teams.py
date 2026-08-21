"""Endpoint x role behavior for the org and team membership routes.

Requires a live, seeded Supabase instance and a real JWT per principal — both
env-blocked here, the same ruling Task 15 recorded in
test_invariants_concurrent.py. This file documents the intended behavior; a
future conftest fixture must supply `client` and the seeded fixtures below.
Every test is deselected by default via the module-level `pytestmark`.
"""

from typing import Protocol

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

#: (org_id, super_admin_id, member_id, super_admin_jwt, member_jwt)
SeededOrgWithMember = tuple[str, str, str, str, str]
#: (org_id, super_admin_a, super_admin_b, jwt_a, jwt_b) — exactly two super-admins
SeededOrgTwoSuperAdmins = tuple[str, str, str, str, str]
#: (org_id, team_id, team_admin_id, team_admin_jwt, viewer_id, viewer_jwt)
SeededTeamWithAdmin = tuple[str, str, str, str, str, str]
#: (team_id, default_team_id, member_id, member_jwt) — member belongs to both
SeededDefaultTeamMember = tuple[str, str, str, str]
#: (team_id, admin_a, admin_b, jwt_a, jwt_b) — exactly two team admins
SeededTeamTwoAdmins = tuple[str, str, str, str, str]


class IntegrationClient(Protocol):
    def authed(self, jwt: str) -> TestClient: ...


@pytest.mark.integration
async def test_org_admin_can_add_member(
    seeded_org_with_member: SeededOrgWithMember, client: IntegrationClient
) -> None:
    """OrgAddUser, granted to the super_admin role. A direct insert, so the new
    row is visible immediately — no invariant applies to growing membership."""
    org_id, _, _, admin_jwt, _ = seeded_org_with_member
    response = client.authed(admin_jwt).post(
        f"/v1/orgs/{org_id}/members",
        json={"user_id": "11111111-1111-1111-1111-111111111111", "role": "member"},
    )
    assert response.status_code == 201
    assert response.json()["role"] == "member"


@pytest.mark.integration
async def test_plain_member_cannot_add_org_member(
    seeded_org_with_member: SeededOrgWithMember, client: IntegrationClient
) -> None:
    """OrgAddUser is not in the `member` role's capability set -> 403, not 404:
    the org itself IS visible to a member (assumption #5 only hides invisible
    resources, and a member can see the org they belong to)."""
    org_id, _, _, _, member_jwt = seeded_org_with_member
    response = client.authed(member_jwt).post(
        f"/v1/orgs/{org_id}/members",
        json={"user_id": "22222222-2222-2222-2222-222222222222", "role": "member"},
    )
    assert response.status_code == 403


@pytest.mark.integration
async def test_removing_last_super_admin_is_409(
    seeded_org_two_super_admins: SeededOrgTwoSuperAdmins, client: IntegrationClient
) -> None:
    """LastSuperAdmin, enforced by the remove_org_member RPC (ZA001 -> 409),
    exercised here through the HTTP layer rather than the raw RPC."""
    org_id, admin_a, admin_b, jwt_a, _ = seeded_org_two_super_admins
    # First removal succeeds, leaving exactly one super-admin.
    first = client.authed(jwt_a).delete(f"/v1/orgs/{org_id}/members/{admin_b}")
    assert first.status_code == 204

    second = client.authed(jwt_a).delete(f"/v1/orgs/{org_id}/members/{admin_a}")
    assert second.status_code == 409
    assert second.json()["invariant"] == "LastSuperAdmin"


@pytest.mark.integration
async def test_org_admin_can_change_role(
    seeded_org_with_member: SeededOrgWithMember, client: IntegrationClient
) -> None:
    """OrgChangeRole via change_org_role; the member keeps manage_org == false so
    no invariant fires."""
    org_id, _, member_id, admin_jwt, _ = seeded_org_with_member
    response = client.authed(admin_jwt).patch(
        f"/v1/orgs/{org_id}/members/{member_id}", json={"user_id": member_id, "role": "member"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "member"


@pytest.mark.integration
async def test_team_creator_becomes_admin(
    seeded_org_with_member: SeededOrgWithMember, client: IntegrationClient
) -> None:
    """TeamCreate, then the team_creator_is_admin trigger. Visible in /v1/me/teams
    with role=admin — the assertion this endpoint exists to make (assumption #15)."""
    org_id, _, _, _, member_jwt = seeded_org_with_member
    created = client.authed(member_jwt).post(f"/v1/orgs/{org_id}/teams", json={"name": "New Team"})
    assert created.status_code == 201
    team_id = created.json()["id"]

    mine = client.authed(member_jwt).get("/v1/me/teams")
    assert any(t["team_id"] == team_id and t["role"] == "admin" for t in mine.json())


@pytest.mark.integration
async def test_team_admin_can_add_member(
    seeded_team_with_admin: SeededTeamWithAdmin, client: IntegrationClient
) -> None:
    """TeamAddMember, a direct insert like add_org_member."""
    _, team_id, _, admin_jwt, viewer_id, _ = seeded_team_with_admin
    response = client.authed(admin_jwt).post(
        f"/v1/teams/{team_id}/members", json={"user_id": viewer_id, "role": "viewer"}
    )
    assert response.status_code == 201


@pytest.mark.integration
async def test_viewer_cannot_remove_team_member(
    seeded_team_with_admin: SeededTeamWithAdmin, client: IntegrationClient
) -> None:
    """TeamRemoveMember is not in the `viewer` role's capability set -> 403."""
    _, team_id, team_admin_id, _, _, viewer_jwt = seeded_team_with_admin
    response = client.authed(viewer_jwt).delete(f"/v1/teams/{team_id}/members/{team_admin_id}")
    assert response.status_code == 403


@pytest.mark.integration
async def test_removing_from_default_team_is_409(
    seeded_default_team_member: SeededDefaultTeamMember, client: IntegrationClient
) -> None:
    """DefaultTeamProtected (ZA003): a member cannot leave the org's default team
    while still belonging to the org — only remove_org_member's cascade may."""
    default_team_id, _, member_id, member_jwt = seeded_default_team_member
    response = client.authed(member_jwt).delete(f"/v1/teams/{default_team_id}/members/{member_id}")
    assert response.status_code == 409
    assert response.json()["invariant"] == "DefaultTeamProtected"


@pytest.mark.integration
async def test_demoting_last_team_admin_is_409(
    seeded_team_two_admins: SeededTeamTwoAdmins, client: IntegrationClient
) -> None:
    """LastTeamAdmin (ZA002) on the demotion path inside change_team_role, not
    just on removal."""
    team_id, admin_a, admin_b, jwt_a, _ = seeded_team_two_admins
    # Demote admin_b first — still one admin (admin_a) left, so this succeeds.
    first = client.authed(jwt_a).patch(
        f"/v1/teams/{team_id}/members/{admin_b}", json={"user_id": admin_b, "role": "viewer"}
    )
    assert first.status_code == 200

    second = client.authed(jwt_a).patch(
        f"/v1/teams/{team_id}/members/{admin_a}", json={"user_id": admin_a, "role": "viewer"}
    )
    assert second.status_code == 409
    assert second.json()["invariant"] == "LastTeamAdmin"


@pytest.mark.integration
async def test_org_super_admin_may_demote_last_team_admin(
    seeded_team_with_admin: SeededTeamWithAdmin, client: IntegrationClient
) -> None:
    """The one exception LastTeamAdmin carves out: an org super-admin can always
    reach into a team to fix it, per `p_actor_is_super_admin` in the RPC."""
    _, team_id, team_admin_id, _, _, _ = seeded_team_with_admin
    # `client` here is authenticated as the org's super-admin, not the team admin.
    response = client.authed("org-super-admin-jwt").delete(
        f"/v1/teams/{team_id}/members/{team_admin_id}"
    )
    assert response.status_code == 204
