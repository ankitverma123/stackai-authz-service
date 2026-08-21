"""`POST /v1/orgs/{org_id}/roles` (Task 23, Should tier) — runtime role creation.

Requires a live, seeded Supabase instance and a real JWT per principal — the
same env-blocked ruling test_teams.py and test_explain.py recorded. This file
documents the intended behavior; a future conftest fixture must supply `client`
and the seeded fixtures below. Every test is deselected by default via the
module-level `pytestmark`.

DEVIATION FROM THE BRIEF: the brief's guard test posts to `POST /v1/roles` and
reads back via `GET /v1/roles`. `Resource.org()` (app/api/deps.py) only
authorizes against an id read from a URL path parameter, so there is no flat
`/v1/roles` route — see app/api/routers/roles.py's module docstring. Both
tests below are adapted to `POST /v1/orgs/{org_id}/roles`; the second is
adapted to prove scoping via two creates (one per org) rather than a list
endpoint, since no `GET /v1/roles` exists (out of scope for this task).
"""

from typing import Protocol

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

#: (org_id, super_admin_id, super_admin_jwt)
SeededOrgWithSuperAdmin = tuple[str, str, str]
#: (org_id, super_admin_jwt) — a second, unrelated org
SeededOtherOrgWithSuperAdmin = tuple[str, str]


class IntegrationClient(Protocol):
    def authed(self, jwt: str) -> TestClient: ...


@pytest.mark.integration
async def test_cannot_create_a_role_referencing_an_unknown_capability(
    seeded_org_with_super_admin: SeededOrgWithSuperAdmin, client: IntegrationClient
) -> None:
    """Roles compose EXISTING capabilities only. A role can never invent security
    surface, which is what makes runtime role creation safe rather than a
    backdoor (D3)."""
    org_id, _, admin_jwt = seeded_org_with_super_admin
    response = client.authed(admin_jwt).post(
        f"/v1/orgs/{org_id}/roles",
        json={"name": "superuser", "scope": "team", "capabilities": ["become_root"]},
    )
    assert response.status_code == 422


@pytest.mark.integration
async def test_created_role_is_scoped_to_the_callers_org(
    seeded_org_with_super_admin: SeededOrgWithSuperAdmin,
    seeded_other_org_with_super_admin: SeededOtherOrgWithSuperAdmin,
    client: IntegrationClient,
) -> None:
    """The same role name in another tenant is a DIFFERENT role, not a
    collision — `roles.org_id` scopes it, and only the built-in unique index
    (`org_id is null`) would ever reject a duplicate name."""
    org_a_id, _, admin_a_jwt = seeded_org_with_super_admin
    org_b_id, admin_b_jwt = seeded_other_org_with_super_admin

    created_a = client.authed(admin_a_jwt).post(
        f"/v1/orgs/{org_a_id}/roles",
        json={"name": "auditor", "scope": "team", "capabilities": ["view"]},
    )
    created_b = client.authed(admin_b_jwt).post(
        f"/v1/orgs/{org_b_id}/roles",
        json={"name": "auditor", "scope": "team", "capabilities": ["view"]},
    )

    assert created_a.status_code == 201
    assert created_b.status_code == 201
    assert created_a.json()["id"] != created_b.json()["id"]
    assert created_a.json()["org_id"] == org_a_id
    assert created_b.json()["org_id"] == org_b_id
