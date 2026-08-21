"""Cross-tenant behavior for `POST /v1/authz/explain` (Task 22).

Requires a live, seeded Supabase instance and a real JWT per principal — the same
env-blocked ruling test_invariants_concurrent.py recorded. This file documents the
intended behavior; a future conftest fixture must supply `client` and the seeded
fixtures below. Every test is deselected by default via the module-level
`pytestmark`.
"""

from typing import Protocol

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

#: (org_a_id, workflow_in_org_a, member_a_jwt) — a workflow visible to member_a
SeededWorkflowInOrgA = tuple[str, str, str]
#: JWT for a user who belongs to org B only — no membership in org A whatsoever
SeededOrgBOutsiderJwt = str


class IntegrationClient(Protocol):
    def authed(self, jwt: str) -> TestClient: ...


@pytest.mark.integration
async def test_explain_on_own_org_workflow_returns_decision(
    seeded_workflow_in_org_a: SeededWorkflowInOrgA, client: IntegrationClient
) -> None:
    """The baseline: a principal explaining a decision about a resource they can
    see gets a decision, a policy_id, and resource attributes back — never a 404."""
    _, workflow_id, member_a_jwt = seeded_workflow_in_org_a
    response = client.authed(member_a_jwt).post(
        "/v1/authz/explain",
        json={"action": "WorkflowView", "resource_type": "Workflow", "resource_id": workflow_id},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] in {"Allow", "Deny"}
    assert "policy_id" in body
    assert body["resource_attributes"]


@pytest.mark.integration
async def test_explain_across_tenants_is_404_not_a_leak(
    seeded_workflow_in_org_a: SeededWorkflowInOrgA,
    seeded_org_b_outsider_jwt: SeededOrgBOutsiderJwt,
    client: IntegrationClient,
) -> None:
    """The property this file exists to prove: a caller with no membership in org A
    cannot use /explain to learn anything about org A's workflow — not its
    decision, not its policy_id, not its attributes. It 404s exactly like any other
    guarded route would (deps.requires()'s visibility check), never a 403 that
    would itself confirm the resource exists."""
    _, workflow_id, _ = seeded_workflow_in_org_a
    response = client.authed(seeded_org_b_outsider_jwt).post(
        "/v1/authz/explain",
        json={"action": "WorkflowView", "resource_type": "Workflow", "resource_id": workflow_id},
    )
    assert response.status_code == 404
    assert "policy_id" not in response.json()
    assert "resource_attributes" not in response.json()
