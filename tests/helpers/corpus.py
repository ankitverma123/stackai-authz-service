"""In-memory fixtures for the pre-filter containment test (tests/test_prefilter.py).

Each scenario builds a principal's `CapabilitySlice` (what the pre-filter sees)
alongside a matching `EntitySlice` (what the real Cedar engine sees) and a list of
`WorkflowEntity` resources. The two must describe the SAME world — team caps here,
`WorkflowEntity.team`/`.org` there — or the containment test would be comparing two
unrelated things instead of checking that the filter is a superset of the engine.

`_build_slice` mirrors the tail of `SupabaseEntityProvider.slice_for` (principal
entity + the `all_caps` union, including every team's Cap entities and every
referenced org's `manage_org` Cap) so the engine never errors on a missing entity —
see that method's own comments for why each piece is there.
"""

from collections.abc import Iterable

from authz_core import Capability, EntityRef, EntitySlice, PrincipalEntity, WorkflowEntity, cap_ref

from app.infra.entity_provider import CapabilitySlice

Corpus = tuple[EntityRef, EntitySlice, CapabilitySlice, list[WorkflowEntity]]


def _workflow(wf_id: str, *, org_id: str, team_id: str) -> WorkflowEntity:
    return WorkflowEntity(
        ref=EntityRef("Workflow", wf_id),
        org=EntityRef("Organization", org_id),
        team=EntityRef("Team", team_id),
        capabilities={c: cap_ref(c, "team", team_id) for c in Capability},
        exported=False,
        visibility="public",
        password_protected=False,
    )


def _build_slice(
    principal: EntityRef, cap_slice: CapabilitySlice, workflows: Iterable[WorkflowEntity]
) -> EntitySlice:
    workflows = tuple(workflows)
    org_ids = set(cap_slice.org_caps) | {w.org.id for w in workflows}

    principal_entity = PrincipalEntity(
        ref=principal,
        capabilities=frozenset(cap_slice.cap_refs()),
        orgs=frozenset(EntityRef("Organization", o) for o in cap_slice.org_caps),
    )

    all_caps = cap_slice.cap_refs()
    for w in workflows:
        all_caps |= {cap_ref(c, "team", w.team.id) for c in Capability}
    all_caps |= {cap_ref(Capability.MANAGE_ORG, "org", o) for o in org_ids}

    return EntitySlice(principal=principal_entity, resources=workflows, caps=tuple(all_caps))


def corpus() -> list[Corpus]:
    """Scenarios spanning: a team-scoped viewer, an org super-admin, a principal
    with a capability that is NOT `view` (proving the filter doesn't over-trust any
    capability), a principal with no capabilities at all, and a principal who can
    see one team in an org but not a sibling team in that same org."""
    scenarios: list[Corpus] = []

    # 1. Team-scoped viewer: sees only their own team's workflow, not a sibling
    #    team's, even though both are in the same org.
    p1 = EntityRef("User", "u-viewer")
    cap1 = CapabilitySlice(
        team_caps={"team-1": {Capability.VIEW, Capability.RUN}},
        org_caps={},
    )
    wf1 = [
        _workflow("wf-1", org_id="org-1", team_id="team-1"),
        _workflow("wf-2", org_id="org-1", team_id="team-2"),
    ]
    scenarios.append((p1, _build_slice(p1, cap1, wf1), cap1, wf1))

    # 2. Org super-admin: manage_org grants visibility across every team in the
    #    org, not just teams they're a member of.
    p2 = EntityRef("User", "u-super-admin")
    cap2 = CapabilitySlice(team_caps={}, org_caps={"org-1": {Capability.MANAGE_ORG}})
    wf2 = [
        _workflow("wf-3", org_id="org-1", team_id="team-1"),
        _workflow("wf-4", org_id="org-1", team_id="team-3"),
        _workflow("wf-5", org_id="org-2", team_id="team-4"),  # different org
    ]
    scenarios.append((p2, _build_slice(p2, cap2, wf2), cap2, wf2))

    # 3. A capability that is NOT view: run-only membership must not leak into
    #    "can see". If the filter (or the engine) ever conflated the two, this
    #    scenario is where a too-narrow OR too-permissive filter would show up.
    p3 = EntityRef("User", "u-runner")
    cap3 = CapabilitySlice(team_caps={"team-5": {Capability.RUN}}, org_caps={})
    wf3 = [_workflow("wf-6", org_id="org-3", team_id="team-5")]
    scenarios.append((p3, _build_slice(p3, cap3, wf3), cap3, wf3))

    # 4. No capabilities at all.
    p4 = EntityRef("User", "u-nobody")
    cap4 = CapabilitySlice()
    wf4 = [_workflow("wf-7", org_id="org-4", team_id="team-6")]
    scenarios.append((p4, _build_slice(p4, cap4, wf4), cap4, wf4))

    # 5. Membership in several teams across two orgs, with view on some and
    #    nothing on others — the most "realistic" shape.
    p5 = EntityRef("User", "u-multi")
    cap5 = CapabilitySlice(
        team_caps={
            "team-7": {Capability.VIEW},
            "team-8": {Capability.EDIT},  # edit, but not view
        },
        org_caps={"org-6": {Capability.MANAGE_ORG}},
    )
    wf5 = [
        _workflow("wf-8", org_id="org-5", team_id="team-7"),
        _workflow("wf-9", org_id="org-5", team_id="team-8"),
        _workflow("wf-10", org_id="org-6", team_id="team-9"),  # covered by org-6 admin
        _workflow("wf-11", org_id="org-7", team_id="team-10"),  # unrelated org
    ]
    scenarios.append((p5, _build_slice(p5, cap5, wf5), cap5, wf5))

    return scenarios
