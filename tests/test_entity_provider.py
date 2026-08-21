from authz_core import Capability

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
