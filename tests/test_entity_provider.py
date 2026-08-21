from authz_core import Capability, EntityRef, TeamEntity, WorkflowEntity, cap_ref

from app.infra.entity_provider import CapabilitySlice, SupabaseEntityProvider


class FakeTable:
    """Minimal stand-in for the supabase-py query builder."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def select(self, *_: str) -> "FakeTable":
        return self

    def eq(self, *_: object) -> "FakeTable":
        return self

    def in_(self, *_: object) -> "FakeTable":
        return self

    def execute(self) -> object:
        return type("Result", (), {"data": self._rows})()


class FakeClient:
    def __init__(self, tables: dict[str, list[dict]]) -> None:
        self._tables = tables

    def table(self, name: str) -> FakeTable:
        return FakeTable(self._tables.get(name, []))


async def test_workflow_without_export_row_gets_defaults() -> None:
    """A workflow with no workflow_exports row must still emit exported/visibility/
    password_protected. Omitting them makes `must-be-exported` error and be SKIPPED,
    which fails OPEN on the public endpoint."""
    client = FakeClient({
        "workflows": [{"id": "wf-1", "org_id": "org-1", "team_id": "team-1"}],
        "workflow_exports": [],  # deliberately empty
    })
    provider = SupabaseEntityProvider(client)  # type: ignore[arg-type]
    entity = provider.build_workflow_entity(
        {"id": "wf-1", "org_id": "org-1", "team_id": "team-1"}, export_row=None
    )
    attrs = entity.to_cedar()["attrs"]
    assert attrs["exported"] is False
    assert attrs["visibility"] == "public"
    assert attrs["password_protected"] is False


async def test_password_protected_derived_from_hash_presence() -> None:
    provider = SupabaseEntityProvider(FakeClient({}))  # type: ignore[arg-type]
    entity = provider.build_workflow_entity(
        {"id": "wf-1", "org_id": "org-1", "team_id": "team-1"},
        export_row={"is_exported": True, "visibility": "org_only", "password_hash": "$argon2..."},
    )
    attrs = entity.to_cedar()["attrs"]
    assert attrs["exported"] is True
    assert attrs["visibility"] == "org_only"
    assert attrs["password_protected"] is True
    # The hash itself must NEVER reach Cedar.
    assert "password_hash" not in attrs


def test_capability_slice_groups_teams_by_capability() -> None:
    slice_ = CapabilitySlice(
        team_caps={"team-1": {Capability.VIEW, Capability.RUN}, "team-2": {Capability.VIEW}},
        org_caps={"org-1": {Capability.MANAGE_ORG}},
    )
    assert slice_.teams_with(Capability.VIEW) == {"team-1", "team-2"}
    assert slice_.teams_with(Capability.RUN) == {"team-1"}
    assert slice_.orgs_with(Capability.MANAGE_ORG) == {"org-1"}


async def test_capability_slice_parses_nested_membership_rows() -> None:
    """Exercises capability_slice against realistic supabase-py nested-embed shapes:
    team_memberships/org_memberships joined to roles joined to role_capabilities.
    A second team-1 row with roles=None proves the `(row.get("roles") or {}).get(...)`
    guard contributes no capabilities instead of crashing on `NoneType.get`."""
    client = FakeClient({
        "team_memberships": [
            {
                "team_id": "team-1",
                "roles": {"id": "r1", "role_capabilities": [
                    {"capability": "view"}, {"capability": "run"},
                ]},
            },
            {"team_id": "team-1", "roles": None},
        ],
        "org_memberships": [
            {
                "org_id": "org-1",
                "roles": {"id": "r2", "role_capabilities": [{"capability": "manage_org"}]},
            },
        ],
    })
    provider = SupabaseEntityProvider(client)  # type: ignore[arg-type]

    slice_ = await provider.capability_slice("u1")

    assert slice_.team_caps == {"team-1": {Capability.VIEW, Capability.RUN}}
    assert slice_.org_caps == {"org-1": {Capability.MANAGE_ORG}}


async def test_slice_for_batches_and_builds_entities() -> None:
    """Exercises the batched .in_() fetch + assembly: one workflow and one team
    resource, fetched in two queries (not per-resource), with the principal's
    capabilities and the org_admins Cap present on the resulting slice."""
    client = FakeClient({
        "team_memberships": [
            {
                "team_id": "team-1",
                "roles": {"id": "r1", "role_capabilities": [
                    {"capability": "view"}, {"capability": "run"},
                ]},
            },
        ],
        "org_memberships": [
            {
                "org_id": "org-1",
                "roles": {"id": "r2", "role_capabilities": [{"capability": "manage_org"}]},
            },
        ],
        "workflows": [
            {
                "id": "wf-1",
                "org_id": "org-1",
                "team_id": "team-1",
                "workflow_exports": [
                    {"is_exported": True, "visibility": "public", "password_hash": None},
                ],
            },
        ],
        "teams": [{"id": "team-1", "org_id": "org-1"}],
    })
    provider = SupabaseEntityProvider(client)  # type: ignore[arg-type]

    entity_slice = await provider.slice_for(
        EntityRef("User", "u1"), (EntityRef("Workflow", "wf-1"), EntityRef("Team", "team-1"))
    )

    workflows = [r for r in entity_slice.resources if isinstance(r, WorkflowEntity)]
    teams = [r for r in entity_slice.resources if isinstance(r, TeamEntity)]
    assert len(entity_slice.resources) == 2
    assert workflows[0].ref == EntityRef("Workflow", "wf-1")
    assert teams[0].ref == EntityRef("Team", "team-1")

    expected_principal_caps = {
        cap_ref(Capability.VIEW, "team", "team-1"),
        cap_ref(Capability.RUN, "team", "team-1"),
        cap_ref(Capability.MANAGE_ORG, "org", "org-1"),
    }
    assert expected_principal_caps <= entity_slice.principal.capabilities

    # org_admins Cap must exist as an entity even though it's built outside the
    # per-resource loop.
    assert cap_ref(Capability.MANAGE_ORG, "org", "org-1") in entity_slice.caps
