"""Cedar entity marshalling. Two rules matter enormously here:

1. Entity-valued attributes MUST be wrapped {"__entity": {...}}.
2. Every declared attribute MUST be present. A missing attribute makes an
   applicable policy error; an errored forbid is SKIPPED and a permit can win.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from authz_core.capabilities import Capability

CedarEntity = dict[str, Any]


@dataclass(frozen=True, slots=True)
class EntityRef:
    type: str
    id: str

    def uid(self) -> dict[str, str]:
        return {"type": self.type, "id": self.id}

    def wrapped(self) -> dict[str, Any]:
        return {"__entity": self.uid()}

    def literal(self) -> str:
        return f'{self.type}::"{self.id}"'


PrincipalRef = EntityRef
ResourceRef = EntityRef


def cap_ref(capability: Capability, scope_type: str, scope_id: str) -> EntityRef:
    return EntityRef("Cap", f"{capability.value}:{scope_type}:{scope_id}")


@dataclass(frozen=True, slots=True)
class PrincipalEntity:
    ref: PrincipalRef
    capabilities: frozenset[EntityRef] = field(default_factory=frozenset)
    orgs: frozenset[EntityRef] = field(default_factory=frozenset)

    def to_cedar(self) -> CedarEntity:
        return {
            "uid": self.ref.uid(),
            "attrs": {},
            "parents": [c.uid() for c in self.capabilities] + [o.uid() for o in self.orgs],
        }


def _cap_attrs(caps: dict[Capability, EntityRef], wanted: set[Capability]) -> dict[str, Any]:
    return {c.attribute: caps[c].wrapped() for c in wanted}


@dataclass(frozen=True, slots=True)
class WorkflowEntity:
    ref: EntityRef
    org: EntityRef
    team: EntityRef
    capabilities: dict[Capability, EntityRef]
    exported: bool
    visibility: str
    password_protected: bool

    _ATTRS = frozenset(
        {
            Capability.VIEW,
            Capability.RUN,
            Capability.EDIT,
            Capability.EXPORT,
            Capability.PROTECT_EXPORT,
            Capability.DELETE,
        }
    )

    def to_cedar(self) -> CedarEntity:
        return {
            "uid": self.ref.uid(),
            "parents": [],
            "attrs": {
                "org": self.org.wrapped(),
                "team": self.team.wrapped(),
                "org_admins": cap_ref(Capability.MANAGE_ORG, "org", self.org.id).wrapped(),
                **_cap_attrs(self.capabilities, set(self._ATTRS)),
                "exported": self.exported,
                "visibility": self.visibility,
                "password_protected": self.password_protected,
            },
        }


@dataclass(frozen=True, slots=True)
class TeamEntity:
    ref: EntityRef
    org: EntityRef
    capabilities: dict[Capability, EntityRef]

    _ATTRS = frozenset(
        {
            Capability.VIEW,
            Capability.EDIT,
            Capability.MANAGE_MEMBERS,
            Capability.DELETE,
        }
    )

    def to_cedar(self) -> CedarEntity:
        return {
            "uid": self.ref.uid(),
            "parents": [self.org.uid()],
            "attrs": {
                "org": self.org.wrapped(),
                "org_admins": cap_ref(Capability.MANAGE_ORG, "org", self.org.id).wrapped(),
                **_cap_attrs(self.capabilities, set(self._ATTRS)),
            },
        }


@dataclass(frozen=True, slots=True)
class OrgEntity:
    ref: EntityRef
    capabilities: dict[Capability, EntityRef]

    _ATTRS = frozenset(
        {
            Capability.CREATE_TEAM,
            Capability.MANAGE_ROLES,
            Capability.MANAGE_API_KEYS,
        }
    )

    def to_cedar(self) -> CedarEntity:
        return {
            "uid": self.ref.uid(),
            "parents": [],
            "attrs": {
                "org": self.ref.wrapped(),
                "org_admins": cap_ref(Capability.MANAGE_ORG, "org", self.ref.id).wrapped(),
                **_cap_attrs(self.capabilities, set(self._ATTRS)),
            },
        }


@dataclass(frozen=True, slots=True)
class EntitySlice:
    """Everything one authorization decision needs. Deliberately small."""

    principal: PrincipalEntity
    resources: tuple[WorkflowEntity | TeamEntity | OrgEntity, ...]
    caps: tuple[EntityRef, ...]

    def to_cedar(self) -> list[CedarEntity]:
        entities: list[CedarEntity] = [
            {"uid": c.uid(), "attrs": {}, "parents": []} for c in self.caps
        ]
        entities.append(self.principal.to_cedar())
        entities.extend(r.to_cedar() for r in self.resources)
        # Organizations referenced as parents must exist as entities.
        seen = {(e["uid"]["type"], e["uid"]["id"]) for e in entities}
        for org in self.principal.orgs:
            if (org.type, org.id) not in seen:
                entities.append({"uid": org.uid(), "attrs": {}, "parents": []})
        return entities


@runtime_checkable
class EntityProvider(Protocol):
    """The seam between the engine and any datastore. Implement this to embed
    authz-core in a service with no knowledge of Supabase."""

    async def slice_for(
        self, principal: PrincipalRef, resources: tuple[ResourceRef, ...]
    ) -> EntitySlice: ...


class InMemoryEntityProvider:
    """Test double. The entire policy suite runs against this — no database."""

    def __init__(self, slices: dict[str, EntitySlice]) -> None:
        self._slices = slices

    async def slice_for(
        self, principal: PrincipalRef, resources: tuple[ResourceRef, ...]
    ) -> EntitySlice:
        return self._slices[principal.id]
