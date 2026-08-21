from collections.abc import Callable
from typing import Any

import pytest
from authz_core.capabilities import Capability
from authz_core.entities import EntityRef, OrgEntity, TeamEntity, WorkflowEntity
from authz_core.schema import CEDAR_SCHEMA


def _team() -> TeamEntity:
    org = EntityRef("Organization", "org-1")
    return TeamEntity(
        ref=EntityRef("Team", "team-1"),
        org=org,
        capabilities={c: EntityRef("Cap", f"{c.value}:team:team-1") for c in Capability},
    )


def _org() -> OrgEntity:
    return OrgEntity(
        ref=EntityRef("Organization", "org-1"),
        capabilities={c: EntityRef("Cap", f"{c.value}:org:org-1") for c in Capability},
    )


def _workflow() -> WorkflowEntity:
    org = EntityRef("Organization", "org-1")
    team = EntityRef("Team", "team-1")
    return WorkflowEntity(
        ref=EntityRef("Workflow", "wf-1"),
        org=org,
        team=team,
        capabilities={c: EntityRef("Cap", f"{c.value}:team:team-1") for c in Capability},
        exported=False,
        visibility="public",
        password_protected=False,
    )


ENTITY_FIXTURES: dict[str, Callable[[], Any]] = {
    "Workflow": _workflow,
    "Team": _team,
    "Organization": _org,
}


@pytest.mark.parametrize("entity_type", sorted(ENTITY_FIXTURES))
def test_entity_emits_every_schema_declared_attribute(entity_type: str) -> None:
    """Driven from CEDAR_SCHEMA itself, never from a hand-written expectation list.

    A hand-written list reproduces whatever omission it was written alongside — if
    the author forgot `org_admins` in the builder, they forget it in the expectations
    too, and the test is green while the entity is incomplete. Reading the schema
    makes the test independent of the author's memory.

    This is the exact analogue of test_every_action_has_at_least_one_permit: both
    assert that a declaration somewhere is actually honoured everywhere, and both
    catch a whole class rather than one instance.

    Why it is a security property and not tidiness: a missing attribute makes an
    applicable policy ERROR, Cedar SKIPS it, and if it was a `forbid` a `permit`
    wins. Observed in the spike as Allow with errors=1.
    """
    shape = CEDAR_SCHEMA[""]["entityTypes"][entity_type].get("shape")
    declared = set(shape["attributes"]) if shape else set()
    emitted = set(ENTITY_FIXTURES[entity_type]().to_cedar()["attrs"])
    missing = declared - emitted
    assert not missing, f"{entity_type} omits schema-declared attributes: {sorted(missing)}"


@pytest.mark.parametrize("entity_type", sorted(ENTITY_FIXTURES))
def test_entity_emits_no_undeclared_attribute(entity_type: str) -> None:
    """The other direction: an attribute Cedar's schema does not know about is a
    validation failure waiting to happen, and may mean a secret leaked into the
    entity payload."""
    shape = CEDAR_SCHEMA[""]["entityTypes"][entity_type].get("shape")
    declared = set(shape["attributes"]) if shape else set()
    extra = set(ENTITY_FIXTURES[entity_type]().to_cedar()["attrs"]) - declared
    assert not extra, f"{entity_type} emits undeclared attributes: {sorted(extra)}"


def test_entity_valued_attributes_are_wrapped() -> None:
    """Cedar requires {"__entity": {...}} for entity-valued attrs; a bare dict errors."""
    attrs = _workflow().to_cedar()["attrs"]
    assert attrs["org"] == {"__entity": {"type": "Organization", "id": "org-1"}}
    assert attrs["can_view"]["__entity"]["type"] == "Cap"


def test_defaults_are_applied_when_no_export_row_exists() -> None:
    """Most workflows have no workflow_exports row. The provider must LEFT JOIN
    and default, never omit."""
    attrs = _workflow().to_cedar()["attrs"]
    assert attrs["exported"] is False
    assert attrs["visibility"] == "public"
    assert attrs["password_protected"] is False
