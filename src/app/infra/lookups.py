"""Small lookups shared by more than one router — kept out of any single router
module so neither one appears to "own" the other's helper."""

from typing import Any, cast
from uuid import UUID

from supabase import Client

Row = dict[str, Any]


def team_org_id(client: Client, team_id: UUID) -> str:
    """The guard has already confirmed team_id is visible, so exactly one row
    exists here — safe to use .single() rather than handling zero/many."""
    row = cast(
        Row, client.table("teams").select("org_id").eq("id", str(team_id)).single().execute().data
    )
    return str(row["org_id"])
