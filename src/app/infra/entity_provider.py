"""Builds Cedar entity slices from Supabase.

Two invariants this file exists to uphold:
  1. Every declared attribute is emitted (spec §6.1). A missing attribute makes an
     applicable policy error; an errored `forbid` is skipped and a permit can win.
  2. Secrets never reach Cedar. `password_protected` is a boolean derived from hash
     presence — the hash itself stays in the app.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any, cast

from authz_core import (
    Capability,
    EntityRef,
    EntitySlice,
    OrgEntity,
    PrincipalEntity,
    TeamEntity,
    WorkflowEntity,
    cap_ref,
)

from supabase import Client

Row = dict[str, Any]


@dataclass(frozen=True, slots=True)
class CapabilitySlice:
    """What a principal can do, and where. Used both to build Cedar entities and to
    derive the SQL pre-filter in Task 17."""

    team_caps: dict[str, set[Capability]] = field(default_factory=dict)
    org_caps: dict[str, set[Capability]] = field(default_factory=dict)

    def teams_with(self, capability: Capability) -> set[str]:
        return {t for t, caps in self.team_caps.items() if capability in caps}

    def orgs_with(self, capability: Capability) -> set[str]:
        return {o for o, caps in self.org_caps.items() if capability in caps}

    def cap_refs(self) -> set[EntityRef]:
        refs = {cap_ref(c, "team", t) for t, caps in self.team_caps.items() for c in caps}
        refs |= {cap_ref(c, "org", o) for o, caps in self.org_caps.items() for c in caps}
        return refs


class SupabaseEntityProvider:
    """Implements authz_core.EntityProvider against Supabase.

    Note there is no cache here. Authorization state never enters a token and is
    never cached, so a permission change takes effect on the very next request
    (spec D8). Spec §13 records the generation-counter design we would use if a
    cache were ever needed — deliberately not a TTL, which would reintroduce a
    staleness window.
    """

    def __init__(self, client: Client) -> None:
        self._client = client
        self._memo: dict[str, CapabilitySlice] = {}

    # NOTE: supabase-py's client is synchronous, so every .execute() below blocks the
    # event loop. Acceptable for a seeded demo; it must be resolved before §13 reports
    # p50/p99, since a blocked loop makes those numbers meaningless under any
    # concurrency. Two options, in preference order:
    #   1. `supabase.acreate_client()` / AsyncClient where available, or
    #   2. wrap each call in `anyio.to_thread.run_sync`.
    # Pick one during Task 11 and record the choice in the README's performance
    # section; do not leave it implicit.

    # ---- capability resolution -------------------------------------------------

    async def capability_slice(self, user_id: str) -> CapabilitySlice:
        """One query per membership kind, memoized for the request's lifetime so a
        visibility check and an action check share one fetch."""
        if user_id in self._memo:
            return self._memo[user_id]

        # An anonymous principal's subject is the sentinel string "anonymous", not a
        # uuid. Membership columns are uuid-typed, so querying them with it raises
        # Postgres 22P02 -> 500 on every anonymous request, including the public
        # workflow-run. A non-uuid subject has no memberships by construction, so the
        # slice is empty; short-circuit before touching the database.
        try:
            uuid.UUID(user_id)
        except ValueError:
            empty = CapabilitySlice()
            self._memo[user_id] = empty
            return empty

        team_rows = cast(
            list[Row],
            self._client.table("team_memberships")
            .select("team_id, roles(id, role_capabilities(capability))")
            .eq("user_id", user_id)
            .execute()
            .data,
        )
        org_rows = cast(
            list[Row],
            self._client.table("org_memberships")
            .select("org_id, roles(id, role_capabilities(capability))")
            .eq("user_id", user_id)
            .execute()
            .data,
        )

        team_caps: dict[str, set[Capability]] = {}
        for row in team_rows:
            caps = {
                Capability(rc["capability"])
                for rc in (row.get("roles") or {}).get("role_capabilities", [])
            }
            team_caps.setdefault(row["team_id"], set()).update(caps)

        org_caps: dict[str, set[Capability]] = {}
        for row in org_rows:
            caps = {
                Capability(rc["capability"])
                for rc in (row.get("roles") or {}).get("role_capabilities", [])
            }
            org_caps.setdefault(row["org_id"], set()).update(caps)

        result = CapabilitySlice(team_caps=team_caps, org_caps=org_caps)
        self._memo[user_id] = result
        return result

    # ---- entity construction ---------------------------------------------------

    def build_workflow_entity(self, row: Row, export_row: Row | None) -> WorkflowEntity:
        """export_row is None for the majority of workflows. Defaults are applied
        here rather than left absent — see the module docstring."""
        team_id = row["team_id"]
        export = export_row or {}
        return WorkflowEntity(
            ref=EntityRef("Workflow", row["id"]),
            org=EntityRef("Organization", row["org_id"]),
            team=EntityRef("Team", team_id),
            capabilities={c: cap_ref(c, "team", team_id) for c in Capability},
            exported=bool(export.get("is_exported", False)),
            visibility=str(export.get("visibility", "public")),
            password_protected=export.get("password_hash") is not None,
        )

    def build_team_entity(self, row: Row) -> TeamEntity:
        return TeamEntity(
            ref=EntityRef("Team", row["id"]),
            org=EntityRef("Organization", row["org_id"]),
            capabilities={c: cap_ref(c, "team", row["id"]) for c in Capability},
        )

    def build_org_entity(self, org_id: str) -> OrgEntity:
        return OrgEntity(
            ref=EntityRef("Organization", org_id),
            capabilities={c: cap_ref(c, "org", org_id) for c in Capability},
        )

    # ---- the protocol method ---------------------------------------------------

    async def slice_for(
        self, principal: EntityRef, resources: tuple[EntityRef, ...]
    ) -> EntitySlice:
        caps = await self.capability_slice(principal.id)
        org_ids = set(caps.org_caps)

        # BATCHED: two queries total, not 2N. An earlier draft called _fetch_one per
        # resource plus one per export row, which is exactly the fetch-side N+1 that
        # §13 claims authorize_batch eliminates — authorize_batch removes the N
        # DECISIONS, not the N fetches. The `.in_()` filter is why FakeTable in the
        # test double implements it.
        wanted: dict[str, list[str]] = {}
        for ref in resources:
            wanted.setdefault(ref.type, []).append(ref.id)

        entities: list[WorkflowEntity | TeamEntity | OrgEntity] = []

        if wanted.get("Workflow"):
            workflow_rows = cast(
                list[Row],
                self._client.table("workflows")
                .select("*, workflow_exports(*)")  # embedded: no second round-trip
                .in_("id", wanted["Workflow"])
                .execute()
                .data,
            )
            for row in workflow_rows:
                export = (row.get("workflow_exports") or [None])[0]
                entities.append(self.build_workflow_entity(row, export))
                org_ids.add(row["org_id"])

        if wanted.get("Team"):
            team_rows = cast(
                list[Row],
                self._client.table("teams").select("*").in_("id", wanted["Team"]).execute().data,
            )
            for row in team_rows:
                entities.append(self.build_team_entity(row))
                org_ids.add(row["org_id"])

        for org_id in wanted.get("Organization", []):
            entities.append(self.build_org_entity(org_id))
            org_ids.add(org_id)

        principal_entity = PrincipalEntity(
            ref=principal,
            capabilities=frozenset(caps.cap_refs()),
            orgs=frozenset(EntityRef("Organization", o) for o in caps.org_caps),
        )
        all_caps = caps.cap_refs() | {
            cap_ref(c, "team", e.ref.id)
            for e in entities
            if isinstance(e, TeamEntity)
            for c in Capability
        }
        for entity in entities:
            if isinstance(entity, WorkflowEntity):
                all_caps |= {cap_ref(c, "team", entity.team.id) for c in Capability}
        # Loop-INVARIANT: this belongs outside. Inside the loop it re-ran per entity
        # and, worse, never ran at all when `entities` was empty — leaving the
        # org_admins Cap entity undefined on exactly the paths that need it.
        all_caps |= {cap_ref(Capability.MANAGE_ORG, "org", o) for o in org_ids}

        return EntitySlice(
            principal=principal_entity,
            resources=tuple(entities),
            caps=tuple(all_caps),
        )
