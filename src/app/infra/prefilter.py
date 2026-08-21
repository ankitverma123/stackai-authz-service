"""Derives a SQL predicate from the principal's capability slice.

A pure post-fetch PDP must load every row in the organization to filter it —
O(rows in org) work for an O(rows visible) answer. authorize_batch fixes the
decision N+1 but not the fetch. This removes the term that grows with tenant size.
"""

from dataclasses import dataclass, field

from authz_core import Capability

from app.infra.entity_provider import CapabilitySlice


@dataclass(frozen=True, slots=True)
class PrefilterSpec:
    team_ids: set[str] = field(default_factory=set)
    org_ids: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not self.team_ids and not self.org_ids

    def matches(self, workflow: object) -> bool:
        """In-memory equivalent of the SQL predicate, used by the containment test."""
        team = getattr(workflow, "team", None)
        org = getattr(workflow, "org", None)
        return (team is not None and team.id in self.team_ids) or (
            org is not None and org.id in self.org_ids
        )

    def to_postgrest_or(self) -> str:
        """supabase-py .or_() syntax."""
        clauses: list[str] = []
        if self.team_ids:
            clauses.append(f"team_id.in.({','.join(sorted(self.team_ids))})")
        if self.org_ids:
            clauses.append(f"org_id.in.({','.join(sorted(self.org_ids))})")
        return ",".join(clauses)


def build_workflow_prefilter(slice_: CapabilitySlice) -> PrefilterSpec:
    return PrefilterSpec(
        team_ids=slice_.teams_with(Capability.VIEW),
        org_ids=slice_.orgs_with(Capability.MANAGE_ORG),
    )
