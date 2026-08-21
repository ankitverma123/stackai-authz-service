import re

import pytest
from authz_core import Action, AuthzContext, EngineError, EntityRef, PolicyEngine
from authz_core.actions import GOVERNANCE_ACTIONS, ORG_ADMINISTRABLE_ACTIONS
from authz_core.schema import load_policies

from .conftest import build_slice

WF = EntityRef("Workflow", "wf-1")
TEAM = EntityRef("Team", "team-1")

# (role, action, resource, expected_allow)
MATRIX = [
    ("viewer", Action.WORKFLOW_VIEW, WF, True),
    ("viewer", Action.WORKFLOW_RUN, WF, True),
    ("viewer", Action.WORKFLOW_UPDATE, WF, False),
    ("viewer", Action.WORKFLOW_EXPORT, WF, False),
    ("viewer", Action.WORKFLOW_DELETE, WF, False),
    ("viewer", Action.TEAM_ADD_MEMBER, TEAM, False),
    ("editor", Action.WORKFLOW_VIEW, WF, True),
    ("editor", Action.WORKFLOW_RUN, WF, True),
    ("editor", Action.WORKFLOW_UPDATE, WF, True),
    ("editor", Action.WORKFLOW_CREATE, TEAM, True),
    ("editor", Action.WORKFLOW_EXPORT, WF, True),
    ("editor", Action.WORKFLOW_PROTECT_EXPORT, WF, False),
    ("editor", Action.WORKFLOW_DELETE, WF, False),
    ("editor", Action.TEAM_ADD_MEMBER, TEAM, False),
    ("admin", Action.WORKFLOW_VIEW, WF, True),
    ("admin", Action.WORKFLOW_UPDATE, WF, True),
    ("admin", Action.WORKFLOW_EXPORT, WF, True),
    ("admin", Action.WORKFLOW_PROTECT_EXPORT, WF, True),
    ("admin", Action.WORKFLOW_DELETE, WF, True),
    ("admin", Action.TEAM_ADD_MEMBER, TEAM, True),
    ("admin", Action.TEAM_DELETE, TEAM, True),
    # Data-driven role invented with two INSERTs. View but NOT run — impossible
    # under the brief's linear admin>editor>viewer hierarchy.
    ("auditor", Action.WORKFLOW_VIEW, WF, True),
    ("auditor", Action.WORKFLOW_RUN, WF, False),
    ("auditor", Action.WORKFLOW_UPDATE, WF, False),
    # Super-admin bypasses team membership entirely within their own org.
    ("super_admin", Action.WORKFLOW_VIEW, WF, True),
    ("super_admin", Action.WORKFLOW_UPDATE, WF, True),
    ("super_admin", Action.WORKFLOW_DELETE, WF, True),
    ("super_admin", Action.TEAM_ADD_MEMBER, TEAM, True),
    ("super_admin", Action.TEAM_DELETE, TEAM, True),
    ("outsider", Action.WORKFLOW_VIEW, WF, False),
    ("outsider", Action.WORKFLOW_RUN, WF, False),
    ("outsider", Action.WORKFLOW_UPDATE, WF, False),
    ("anonymous", Action.WORKFLOW_VIEW, WF, False),
    ("anonymous", Action.WORKFLOW_RUN, WF, False),
]


def test_every_action_has_at_least_one_permit() -> None:
    """The general form of the dead-public-path bug.

    WorkflowRunExported once had three forbid policies and no permit. Cedar is
    default-deny, so every external execution was denied unconditionally — the
    brief's external-user requirement was dead, and extras #3/#4 were unobservable
    because nothing reached them. Worse, the fail-open test in test_fail_open.py
    passed VACUOUSLY: with no permit the raw verdict was Deny+errors, so it never
    reproduced the false Allow it claims to guard against.

    Five lines, and it fails loudly the next time an action is added without a grant.
    """
    policies = load_policies()
    permits = [
        block
        for block in re.split(r"@id\(", policies)
        if re.search(r"^\s*\"[^\"]+\"\)\s*permit", block)
    ]
    granted = {a for a in Action if any(a.value in p for p in permits)}
    # Action GROUPS confer membership, so expand them.
    if any('Action::"OrgAdministrable"' in p for p in permits):
        granted |= ORG_ADMINISTRABLE_ACTIONS
    ungranted = sorted(a.value for a in Action if a not in granted)
    assert not ungranted, (
        f"actions with no permit anywhere — Cedar default-deny makes these unreachable: {ungranted}"
    )


def test_every_action_is_classified() -> None:
    """Sibling of the permit-coverage guard: every Action belongs to exactly one of
    the two groups, so adding one forces an explicit decision about super-admins
    rather than inheriting a set-difference default."""
    unclassified = sorted(
        a.value
        for a in Action
        if a not in GOVERNANCE_ACTIONS and a not in ORG_ADMINISTRABLE_ACTIONS
    )
    assert unclassified == ["WorkflowRunExported"], (
        f"actions in neither group: {unclassified}. Add each to GOVERNANCE_ACTIONS "
        f"or ORG_ADMINISTRABLE_ACTIONS, or document the exclusion."
    )


@pytest.mark.parametrize(("role", "action", "resource", "expected"), MATRIX)
def test_matrix(
    engine: PolicyEngine, role: str, action: Action, resource: EntityRef, expected: bool
) -> None:
    principal, slice_ = build_slice(role)
    decision = engine.authorize(
        principal=principal,
        action=action,
        resource=resource,
        slice_=slice_,
        context=AuthzContext(auth_method="jwt"),
    )
    assert not isinstance(decision, EngineError), decision
    assert decision.allowed is expected, f"{role} {action.value} -> {decision!r}"


EXPORT_MATRIX = [
    # (exported, visibility, pw_protected, pw_verified, in_org, expected, why)
    (False, "public", False, False, False, False, "must-be-exported"),
    (True, "public", False, False, False, True, "public flow, anyone"),
    (True, "public", True, False, False, False, "password required"),
    (True, "public", True, True, False, True, "password supplied"),
    (True, "org_only", False, False, False, False, "not an org member"),
    (True, "org_only", False, False, True, True, "org member"),
    (True, "org_only", True, False, True, False, "org member, no password"),
    (True, "org_only", True, True, True, True, "org member with password"),
]


@pytest.mark.parametrize(
    ("exported", "visibility", "protected", "verified", "in_org", "expected", "why"),
    EXPORT_MATRIX,
)
def test_exported_workflow_access(
    engine: PolicyEngine,
    exported: bool,
    visibility: str,
    protected: bool,
    verified: bool,
    in_org: bool,
    expected: bool,
    why: str,
) -> None:
    """Extras #3 and #4 compose without ordering logic because both are forbids."""
    principal, slice_ = build_slice(
        "anonymous",
        exported=exported,
        visibility=visibility,
        password_protected=protected,
        in_org=in_org,
    )
    decision = engine.authorize(
        principal=principal,
        action=Action.WORKFLOW_RUN_EXPORTED,
        resource=WF,
        slice_=slice_,
        context=AuthzContext(auth_method="anonymous", password_verified=verified),
    )
    assert not isinstance(decision, EngineError), decision
    assert decision.allowed is expected, why


API_KEY_MATRIX = [
    (Action.WORKFLOW_RUN, frozenset({"workflow:run"}), True, "in scope"),
    (Action.WORKFLOW_VIEW, frozenset({"workflow:run"}), False, "scope missing"),
    (Action.WORKFLOW_VIEW, frozenset({"workflow:read"}), True, "in scope"),
    (Action.TEAM_DELETE, frozenset({"workflow:run"}), False, "governance forbidden"),
    (Action.TEAM_ADD_MEMBER, frozenset({"workflow:run"}), False, "governance forbidden"),
    (Action.ORG_REMOVE_USER, frozenset({"workflow:run"}), False, "governance forbidden"),
]


@pytest.mark.parametrize(("action", "scopes", "expected", "why"), API_KEY_MATRIX)
def test_api_key_is_weaker_than_the_session(
    engine: PolicyEngine, action: Action, scopes: frozenset[str], expected: bool, why: str
) -> None:
    """Extra #2: a super-admin's API key may run workflows but not delete a team."""
    resource = TEAM if action in {Action.TEAM_DELETE, Action.TEAM_ADD_MEMBER} else WF
    principal, slice_ = build_slice("super_admin")
    decision = engine.authorize(
        principal=principal,
        action=action,
        resource=resource,
        slice_=slice_,
        context=AuthzContext(auth_method="api_key", api_key_scopes=scopes, api_key_org_id="org-1"),
    )
    assert not isinstance(decision, EngineError), decision
    assert decision.allowed is expected, why


def test_same_super_admin_via_jwt_can_delete_team(engine: PolicyEngine) -> None:
    """The contrast that makes extra #2 legible: identical principal, different session."""
    principal, slice_ = build_slice("super_admin")
    decision = engine.authorize(
        principal=principal,
        action=Action.TEAM_DELETE,
        resource=TEAM,
        slice_=slice_,
        context=AuthzContext(auth_method="jwt"),
    )
    assert decision.allowed is True
