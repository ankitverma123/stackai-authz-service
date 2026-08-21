"""Cedar schema. Every action declares a context shape — without it, any policy
reading context.* fails validate_policies()."""

from pathlib import Path
from typing import Any, Final

from authz_core.actions import GOVERNANCE_ACTIONS, ORG_ADMINISTRABLE_ACTIONS, Action
from authz_core.capabilities import Capability

_CAP = {"type": "Entity", "name": "Cap"}
_ORG = {"type": "Entity", "name": "Organization"}
_TEAM = {"type": "Entity", "name": "Team"}

_CONTEXT: Final[dict[str, Any]] = {
    "type": "Record",
    "attributes": {
        "auth_method": {"type": "String"},
        "password_verified": {"type": "Boolean"},
        "required_scope": {"type": "String", "required": False},
        "api_key_scopes": {"type": "Set", "element": {"type": "String"}},
        "api_key_org": {"type": "Entity", "name": "Organization", "required": False},
    },
}


def _caps(*caps: Capability) -> dict[str, Any]:
    return {c.attribute: _CAP for c in caps}


_WORKFLOW_ATTRS: Final[dict[str, Any]] = {
    "org": _ORG,
    "team": _TEAM,
    "org_admins": _CAP,
    **_caps(
        Capability.VIEW,
        Capability.RUN,
        Capability.EDIT,
        Capability.EXPORT,
        Capability.PROTECT_EXPORT,
        Capability.DELETE,
    ),
    "exported": {"type": "Boolean"},
    "visibility": {"type": "String"},
    "password_protected": {"type": "Boolean"},
}

_TEAM_ATTRS: Final[dict[str, Any]] = {
    "org": _ORG,
    "org_admins": _CAP,
    **_caps(Capability.VIEW, Capability.EDIT, Capability.MANAGE_MEMBERS, Capability.DELETE),
}

_ORG_ATTRS: Final[dict[str, Any]] = {
    "org": _ORG,
    "org_admins": _CAP,
    **_caps(Capability.CREATE_TEAM, Capability.MANAGE_ROLES, Capability.MANAGE_API_KEYS),
}

_RESOURCE_TYPES: Final[dict[Action, list[str]]] = {
    Action.ORG_VIEW: ["Organization"],
    Action.TEAM_VIEW: ["Team"],
    Action.ORG_ADD_USER: ["Organization"],
    Action.ORG_REMOVE_USER: ["Organization"],
    Action.ORG_CHANGE_ROLE: ["Organization"],
    Action.TEAM_CREATE: ["Organization"],
    Action.ROLE_CREATE: ["Organization"],
    Action.ROLE_DELETE: ["Organization"],
    Action.API_KEY_CREATE: ["Organization"],
    Action.API_KEY_REVOKE: ["Organization"],
    Action.TEAM_DELETE: ["Team"],
    Action.TEAM_ADD_MEMBER: ["Team"],
    Action.TEAM_REMOVE_MEMBER: ["Team"],
    Action.TEAM_CHANGE_ROLE: ["Team"],
    Action.WORKFLOW_LIST: ["Team"],
    Action.WORKFLOW_CREATE: ["Team"],
}


def _build_actions() -> dict[str, Any]:
    actions: dict[str, Any] = {
        action.value: {
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": _RESOURCE_TYPES.get(action, ["Workflow"]),
                "context": _CONTEXT,
            }
        }
        for action in Action
    }
    # Groups are parentless container actions; members point at them.
    actions["Governance"] = {}
    actions["OrgAdministrable"] = {}
    for action in GOVERNANCE_ACTIONS:
        actions[action.value]["memberOf"] = [{"id": "Governance"}]
    for action in ORG_ADMINISTRABLE_ACTIONS:
        actions[action.value].setdefault("memberOf", []).append({"id": "OrgAdministrable"})
    return actions


CEDAR_SCHEMA: Final[dict[str, Any]] = {
    "": {
        "entityTypes": {
            "Cap": {},
            "Organization": {"shape": {"type": "Record", "attributes": _ORG_ATTRS}},
            "Team": {
                "memberOfTypes": ["Organization"],
                "shape": {"type": "Record", "attributes": _TEAM_ATTRS},
            },
            "User": {"memberOfTypes": ["Cap", "Organization"]},
            "Workflow": {"shape": {"type": "Record", "attributes": _WORKFLOW_ATTRS}},
        },
        "actions": _build_actions(),
    }
}

_POLICY_DIR = Path(__file__).parent / "policies"


def load_policies() -> str:
    """Concatenate every .cedar file into one policy set."""
    return "\n".join(sorted(p.read_text() for p in _POLICY_DIR.glob("*.cedar")))
