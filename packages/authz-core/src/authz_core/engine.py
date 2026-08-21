import json
from dataclasses import dataclass, field
from typing import Any

from cedarpy import is_authorized

from authz_core.actions import (
    ACTION_SCOPES,
    GOVERNANCE_ACTIONS,
    ORG_ADMINISTRABLE_ACTIONS,
    Action,
)
from authz_core.decision import Allow, Decision, Deny, EngineError
from authz_core.entities import EntityRef, EntitySlice
from authz_core.schema import CEDAR_SCHEMA, load_policies


@dataclass(frozen=True, slots=True)
class AuthzContext:
    auth_method: str
    password_verified: bool = False
    api_key_scopes: frozenset[str] = field(default_factory=frozenset)
    api_key_org_id: str | None = None

    def to_cedar(self, action: Action | None = None) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "auth_method": self.auth_method,
            "password_verified": self.password_verified,
            "api_key_scopes": sorted(self.api_key_scopes),
        }
        if action is not None and action in ACTION_SCOPES:
            ctx["required_scope"] = ACTION_SCOPES[action]
        if self.api_key_org_id is not None:
            # Entity-valued so it compares directly against resource.org, which all
            # three resource types declare. Absent => api-key-single-org denies.
            ctx["api_key_org"] = {
                "__entity": {"type": "Organization", "id": self.api_key_org_id}
            }
        return ctx


def _build_action_entities() -> list[dict[str, Any]]:
    """Build Cedar entities for action groups. Cedar evaluates group membership
    only through entity hierarchy — it cannot inspect the schema. These entities
    provide the group declarations that policies reference."""
    ents: list[dict[str, Any]] = [
        {"uid": {"type": "Action", "id": "Governance"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Action", "id": "OrgAdministrable"}, "attrs": {}, "parents": []},
    ]
    for a in Action:
        parents: list[dict[str, str]] = []
        if a in GOVERNANCE_ACTIONS:
            parents.append({"type": "Action", "id": "Governance"})
        if a in ORG_ADMINISTRABLE_ACTIONS:
            parents.append({"type": "Action", "id": "OrgAdministrable"})
        ents.append({"uid": {"type": "Action", "id": a.value}, "attrs": {}, "parents": parents})
    return ents


_ACTION_ENTITIES: list[dict[str, Any]] = _build_action_entities()


class PolicyEngine:
    """Wraps cedarpy. The wrapper exists so that D6 is enforced in exactly one place."""

    def __init__(self, policies: str | None = None) -> None:
        self._policies = policies if policies is not None else load_policies()
        self._schema = json.dumps(CEDAR_SCHEMA)

    def authorize_raw(
        self,
        *,
        principal: str,
        action: str,
        resource: str,
        entities: list[dict[str, Any]],
        context: AuthzContext,
        cedar_action: Action | None = None,
    ) -> Decision:
        result = is_authorized(
            {
                "principal": principal,
                "action": action,
                "resource": resource,
                "context": context.to_cedar(cedar_action),
            },
            self._policies,
            _ACTION_ENTITIES + entities,
        )

        # D6 — checked BEFORE the verdict. An Allow with errors is the dangerous case.
        if result.diagnostics.errors:
            return EngineError("; ".join(str(e) for e in result.diagnostics.errors))

        # cedarpy returns `reasons` from a Rust HashSet, whose iteration order is
        # randomized per process — when two or more policies produce the same
        # verdict (e.g. two forbids both matching), `reasons[0]` would report a
        # different "deciding" policy_id on every restart. Sorted for a stable
        # tie-break: the audit log and /v1/authz/explain must report the same
        # policy_id for the same decision, run to run.
        reasons = sorted(result.diagnostics.reasons)
        annotations = result.diagnostics.id_annotations_by_reason
        policy_id = annotations.get(reasons[0]) if reasons else None

        return Allow(policy_id) if result.allowed else Deny(policy_id)

    def authorize(
        self,
        *,
        principal: EntityRef,
        action: Action,
        resource: EntityRef,
        slice_: EntitySlice,
        context: AuthzContext,
    ) -> Decision:
        return self.authorize_raw(
            principal=principal.literal(),
            action=f'Action::"{action.value}"',
            resource=resource.literal(),
            entities=slice_.to_cedar(),
            context=context,
            cedar_action=action,
        )

    def authorize_batch(
        self,
        *,
        principal: EntityRef,
        action: Action,
        resources: tuple[EntityRef, ...],
        slice_: EntitySlice,
        context: AuthzContext,
    ) -> tuple[Decision, ...]:
        """One entity slice, N resources. The only place list endpoints call in."""
        entities = slice_.to_cedar()
        return tuple(
            self.authorize_raw(
                principal=principal.literal(),
                action=f'Action::"{action.value}"',
                resource=r.literal(),
                entities=entities,
                context=context,
                cedar_action=action,
            )
            for r in resources
        )
