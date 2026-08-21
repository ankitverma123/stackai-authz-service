"""Endpoint behavior for the unauthenticated public workflow routes (Task 19).

Requires a live, seeded Supabase instance — env-blocked here, the same ruling
Task 15 recorded in test_invariants_concurrent.py. This file documents the
intended behavior; a future conftest fixture must supply `client` and the seeded
fixtures below. Every test is deselected by default via the module-level
`pytestmark`.
"""

from typing import Protocol

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

#: workflow_id of a workflow that has never been exported
SeededWorkflowNotExported = str
#: workflow_id of a workflow exported with visibility="public", no password
SeededWorkflowExportedPublic = str
#: (workflow_id, password) — exported, visibility="public", password-protected
SeededWorkflowExportedProtected = tuple[str, str]
#: (workflow_id, org_member_jwt) — exported, visibility="org_only"
SeededWorkflowExportedOrgOnly = tuple[str, str]


class IntegrationClient(Protocol):
    def authed(self, jwt: str) -> TestClient: ...
    def anonymous(self) -> TestClient: ...


@pytest.mark.integration
async def test_non_exported_workflow_is_forbidden(
    seeded_workflow_not_exported: SeededWorkflowNotExported, client: IntegrationClient
) -> None:
    """must-be-exported (extras.cedar): the baseline permit is carved back down to
    nothing until a workflow is explicitly published."""
    response = client.anonymous().post(
        f"/v1/public/workflows/{seeded_workflow_not_exported}/executions"
    )
    assert response.status_code == 403


@pytest.mark.integration
async def test_exported_public_workflow_runs_anonymously(
    seeded_workflow_exported_public: SeededWorkflowExportedPublic, client: IntegrationClient
) -> None:
    response = client.anonymous().post(
        f"/v1/public/workflows/{seeded_workflow_exported_public}/executions"
    )
    assert response.status_code == 201


@pytest.mark.integration
async def test_exported_protected_workflow_denies_without_token(
    seeded_workflow_exported_protected: SeededWorkflowExportedProtected,
    client: IntegrationClient,
) -> None:
    """exported-requires-password (extras.cedar) fires when no X-Workflow-Token
    header is present at all — password_verified defaults to False."""
    workflow_id, _ = seeded_workflow_exported_protected
    response = client.anonymous().post(f"/v1/public/workflows/{workflow_id}/executions")
    assert response.status_code == 403


@pytest.mark.integration
async def test_exported_protected_workflow_runs_with_a_valid_token(
    seeded_workflow_exported_protected: SeededWorkflowExportedProtected,
    client: IntegrationClient,
) -> None:
    """The full extra #3 flow: exchange the password once, then present the token."""
    workflow_id, password = seeded_workflow_exported_protected
    exchange = client.anonymous().post(
        f"/v1/public/workflows/{workflow_id}/access", json={"password": password}
    )
    assert exchange.status_code == 200
    token = exchange.json()["token"]

    response = client.anonymous().post(
        f"/v1/public/workflows/{workflow_id}/executions",
        headers={"X-Workflow-Token": token},
    )
    assert response.status_code == 201


@pytest.mark.integration
async def test_exported_org_only_workflow_denies_anonymous(
    seeded_workflow_exported_org_only: SeededWorkflowExportedOrgOnly,
    client: IntegrationClient,
) -> None:
    """exported-org-members-only (extras.cedar): anonymous is never `principal in
    resource.org`, so an org_only export always denies an unauthenticated caller
    regardless of visibility/password state."""
    workflow_id, _ = seeded_workflow_exported_org_only
    response = client.anonymous().post(f"/v1/public/workflows/{workflow_id}/executions")
    assert response.status_code == 403


@pytest.mark.integration
async def test_exported_org_only_workflow_runs_for_an_org_member(
    seeded_workflow_exported_org_only: SeededWorkflowExportedOrgOnly,
    client: IntegrationClient,
) -> None:
    """Same route, now authenticated: a Bearer token from a member of the
    workflow's own org satisfies `principal in resource.org`."""
    workflow_id, member_jwt = seeded_workflow_exported_org_only
    response = client.authed(member_jwt).post(f"/v1/public/workflows/{workflow_id}/executions")
    assert response.status_code == 201
