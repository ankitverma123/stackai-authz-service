"""The action vocabulary. Adding a member here is a deliberate security decision:
it must be classified into the two action groups below and given a scope mapping."""

from enum import StrEnum
from typing import Final


class Action(StrEnum):
    ORG_ADD_USER = "OrgAddUser"
    ORG_REMOVE_USER = "OrgRemoveUser"
    ORG_CHANGE_ROLE = "OrgChangeRole"

    TEAM_CREATE = "TeamCreate"
    TEAM_DELETE = "TeamDelete"
    TEAM_ADD_MEMBER = "TeamAddMember"
    TEAM_REMOVE_MEMBER = "TeamRemoveMember"
    TEAM_CHANGE_ROLE = "TeamChangeRole"

    ORG_VIEW = "OrgView"
    TEAM_VIEW = "TeamView"

    WORKFLOW_LIST = "WorkflowList"
    WORKFLOW_VIEW = "WorkflowView"
    WORKFLOW_CREATE = "WorkflowCreate"
    WORKFLOW_UPDATE = "WorkflowUpdate"
    WORKFLOW_DELETE = "WorkflowDelete"
    WORKFLOW_RUN = "WorkflowRun"
    WORKFLOW_EXPORT = "WorkflowExport"
    WORKFLOW_PROTECT_EXPORT = "WorkflowProtectExport"
    WORKFLOW_RUN_EXPORTED = "WorkflowRunExported"

    ROLE_CREATE = "RoleCreate"
    ROLE_DELETE = "RoleDelete"
    API_KEY_CREATE = "ApiKeyCreate"
    API_KEY_REVOKE = "ApiKeyRevoke"


#: Forbidden to API keys. Machine identities never perform governance.
GOVERNANCE_ACTIONS: Final[frozenset[Action]] = frozenset(
    {
        Action.ORG_ADD_USER,
        Action.ORG_REMOVE_USER,
        Action.ORG_CHANGE_ROLE,
        Action.TEAM_CREATE,
        Action.TEAM_DELETE,
        Action.TEAM_ADD_MEMBER,
        Action.TEAM_REMOVE_MEMBER,
        Action.TEAM_CHANGE_ROLE,
        Action.ROLE_CREATE,
        Action.ROLE_DELETE,
        Action.API_KEY_CREATE,
        Action.API_KEY_REVOKE,
    }
)

#: What an org super-admin may do inside their own org.
#:
#: ENUMERATED, never `set(Action) - {...}`. A set difference confers every action
#: added in future on the most privileged role in the system with no diff to review
#: — the same standing-grant hazard §6.2 removed from Cedar, just relocated into
#: Python. Adding an Action means deciding, here, whether super-admins get it.
#: test_every_action_is_classified enforces that the decision was made.
ORG_ADMINISTRABLE_ACTIONS: Final[frozenset[Action]] = frozenset(
    {
        Action.ORG_VIEW,
        Action.ORG_ADD_USER,
        Action.ORG_REMOVE_USER,
        Action.ORG_CHANGE_ROLE,
        Action.TEAM_VIEW,
        Action.TEAM_CREATE,
        Action.TEAM_DELETE,
        Action.TEAM_ADD_MEMBER,
        Action.TEAM_REMOVE_MEMBER,
        Action.TEAM_CHANGE_ROLE,
        Action.WORKFLOW_LIST,
        Action.WORKFLOW_VIEW,
        Action.WORKFLOW_CREATE,
        Action.WORKFLOW_UPDATE,
        Action.WORKFLOW_DELETE,
        Action.WORKFLOW_RUN,
        Action.WORKFLOW_EXPORT,
        Action.WORKFLOW_PROTECT_EXPORT,
        Action.ROLE_CREATE,
        Action.ROLE_DELETE,
        Action.API_KEY_CREATE,
        Action.API_KEY_REVOKE,
        # Deliberately EXCLUDED: WorkflowRunExported — the public endpoint applies to
        # everyone equally, super-admins included (assumption #13).
    }
)

#: Action -> API key scope. Absence causes api-key-scope-check to DENY (fail closed).
#:
#: `workflow:write` and `governance:denied` are SENTINELS: they are deliberately
#: never seeded into the api_key_scopes table, so no key can ever hold them and
#: those actions are unreachable by any machine identity. That is the mechanism
#: behind assumption #19 — API keys are read-and-run only. Granting write later is
#: one seed INSERT; no policy changes.
ACTION_SCOPES: Final[dict[Action, str]] = {
    Action.ORG_VIEW: "workflow:read",
    Action.TEAM_VIEW: "workflow:read",
    Action.WORKFLOW_LIST: "workflow:read",
    Action.WORKFLOW_VIEW: "workflow:read",
    Action.WORKFLOW_RUN: "workflow:run",
    Action.WORKFLOW_RUN_EXPORTED: "workflow:run",
    **{a: "governance:denied" for a in GOVERNANCE_ACTIONS},
    Action.WORKFLOW_CREATE: "workflow:write",
    Action.WORKFLOW_UPDATE: "workflow:write",
    Action.WORKFLOW_DELETE: "workflow:write",
    Action.WORKFLOW_EXPORT: "workflow:write",
    Action.WORKFLOW_PROTECT_EXPORT: "workflow:write",
}
