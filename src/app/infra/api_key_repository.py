"""Concrete `ApiKeyRepository` (app/auth/api_key.py) against Supabase.

One row read per authenticated request, by the indexed `prefix` column — never a
scan or a hash-against-every-key. `api_key_grants` is embedded so the scopes come
back in the same round-trip.
"""

from typing import Any, cast

from supabase import Client

Row = dict[str, Any]


class SupabaseApiKeyRepository:
    def __init__(self, client: Client) -> None:
        self._client = client

    async def by_prefix(self, prefix: str) -> Row | None:
        rows = cast(
            list[Row],
            self._client.table("api_keys")
            .select("*, api_key_grants(scope)")
            .eq("prefix", prefix)
            .execute()
            .data,
        )
        return rows[0] if rows else None
