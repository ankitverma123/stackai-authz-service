
import pytest
from authz_core import (
    Capability,
    EntityRef,
    EntitySlice,
    PolicyEngine,
    PrincipalEntity,
    TeamEntity,
    WorkflowEntity,
    cap_ref,
)

ORG = EntityRef("Organization", "org-1")
TEAM = EntityRef("Team", "team-1")
OTHER_TEAM = EntityRef("Team", "team-2")

ROLE_CAPS: dict[str, set[Capability]] = {
    "viewer": {Capability.VIEW, Capability.RUN},
    "editor": {Capability.VIEW, Capability.RUN, Capability.EDIT, Capability.EXPORT},
    "admin": {
        Capability.VIEW, Capability.RUN, Capability.EDIT, Capability.EXPORT,
        Capability.PROTECT_EXPORT, Capability.DELETE, Capability.MANAGE_MEMBERS,
    },
    "auditor": {Capability.VIEW},          # proves data-driven roles: view but NOT run
    "super_admin": set(),                   # power comes from the org_admins cap
    "outsider": set(),
    "anonymous": set(),
}

_ALL_TEAM_CAPS = {c: cap_ref(c, "team", TEAM.id) for c in Capability}


def build_slice(
    role: str,
    *,
    exported: bool = False,
    visibility: str = "public",
    password_protected: bool = False,
    in_org: bool = True,
    team: EntityRef = TEAM,
) -> tuple[EntityRef, EntitySlice]:
    caps: set[EntityRef] = {
        cap_ref(c, "team", team.id) for c in ROLE_CAPS.get(role, set())
    }
    if role == "super_admin":
        caps.add(cap_ref(Capability.MANAGE_ORG, "org", ORG.id))

    principal_ref = EntityRef("User", role)
    principal = PrincipalEntity(
        ref=principal_ref,
        capabilities=frozenset(caps),
        orgs=frozenset({ORG}) if in_org else frozenset(),
    )
    workflow = WorkflowEntity(
        ref=EntityRef("Workflow", "wf-1"),
        org=ORG,
        team=team,
        capabilities={c: cap_ref(c, "team", team.id) for c in Capability},
        exported=exported,
        visibility=visibility,
        password_protected=password_protected,
    )
    team_entity = TeamEntity(
        ref=team, org=ORG, capabilities={c: cap_ref(c, "team", team.id) for c in Capability}
    )
    all_caps = tuple(
        {*caps, *_ALL_TEAM_CAPS.values(), cap_ref(Capability.MANAGE_ORG, "org", ORG.id)}
    )
    return principal_ref, EntitySlice(
        principal=principal, resources=(workflow, team_entity), caps=all_caps
    )


@pytest.fixture(scope="session")
def engine() -> PolicyEngine:
    return PolicyEngine()
