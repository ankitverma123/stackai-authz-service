import asyncio
from typing import Protocol

import pytest

# The live-Supabase test client and fixtures these tests depend on don't exist yet
# (Supabase is env-blocked here per Task 15's ruling); this Protocol documents the
# interface a future conftest fixture must satisfy, and gives the parameters below
# a concrete type instead of `Any`.
SeededOrg = tuple[str, str, str]
SeededOrgWithTeam = tuple[str, str, str]
SeededOrgTwoTeamAdmins = tuple[str, str, str, str]


class IntegrationClient(Protocol):
    async def rpc_remove_org_member(self, org_id: str, user_id: str) -> None: ...
    async def rpc_remove_team_member(
        self, team_id: str, user_id: str, *, actor_is_super_admin: bool
    ) -> None: ...
    async def count_super_admins(self, org_id: str) -> int: ...
    async def count_team_admins(self, team_id: str) -> int: ...
    async def is_team_member(self, team_id: str, user_id: str) -> bool: ...
    async def is_org_member(self, org_id: str, user_id: str) -> bool: ...


@pytest.mark.integration
async def test_two_concurrent_demotions_cannot_both_succeed(
    seeded_org: SeededOrg, client: IntegrationClient
) -> None:
    """The race the invariant exists to prevent.

    With the check in Python this passes intermittently: both callers SELECT 2
    super-admins in separate PostgREST transactions, both proceed, and the org is
    locked out. With the check inside one Postgres function it cannot happen.
    """
    org_id, admin_a, admin_b = seeded_org  # exactly two super-admins

    results = await asyncio.gather(
        client.rpc_remove_org_member(org_id, admin_a),
        client.rpc_remove_org_member(org_id, admin_b),
        return_exceptions=True,
    )
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(failures) == 1, "exactly one demotion must be rejected"

    remaining = await client.count_super_admins(org_id)
    assert remaining >= 1, "the organization must never be left unmanageable"


@pytest.mark.integration
async def test_org_removal_cascades_out_of_that_orgs_teams(
    seeded_org_with_team: SeededOrgWithTeam, client: IntegrationClient
) -> None:
    """Assumption #2. This is NOT an FK cascade — it must be written explicitly in
    remove_org_member, and an earlier draft of the function omitted it entirely."""
    org_id, team_id, user_id = seeded_org_with_team

    await client.rpc_remove_org_member(org_id, user_id)

    assert not await client.is_team_member(team_id, user_id)
    assert not await client.is_org_member(org_id, user_id)


@pytest.mark.integration
async def test_cross_scope_race_cannot_strand_a_team(
    seeded_org_two_team_admins: SeededOrgTwoTeamAdmins, client: IntegrationClient
) -> None:
    """The bug that different advisory-lock namespaces allowed.

    T1 removes admin A from the ORG (cascading A out of team T, holding only the
    org key). T2 removes admin B from TEAM T (holding only the team key). Neither
    excludes the other, T2 counts A as still present, and the team ends with no
    admin. With org-then-team ordering T2 blocks until T1 commits, re-counts, and
    raises ZA002.
    """
    org_id, team_id, admin_a, admin_b = seeded_org_two_team_admins

    results = await asyncio.gather(
        client.rpc_remove_org_member(org_id, admin_a),
        client.rpc_remove_team_member(team_id, admin_b, actor_is_super_admin=False),
        return_exceptions=True,
    )

    remaining_admins = await client.count_team_admins(team_id)
    assert remaining_admins >= 1, f"team stranded with no admin; results={results}"
