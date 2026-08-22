"""API-key endpoints: machine identities with scoped authority (Task 18).

DEVIATION FROM THE BRIEF, same shape as workflows.py's create route: the brief's
Interfaces line reads `POST`/`GET /v1/api-keys`, but `Resource.org()` (app/api/deps.py)
authorizes against an id read from a URL *path parameter* — there is no mechanism to
authorize against an id supplied in the body. So these are nested under
`/orgs/{org_id}/api-keys`, mirroring `POST /orgs/{org_id}/teams`.

GET reuses `Action.API_KEY_CREATE` rather than adding a dedicated list action: both
are gated by the same `manage_api_keys` capability (cap-manage-api-keys in
core.cedar), and Action is deliberately not something to extend lightly (actions.py:
"Adding a member here is a deliberate security decision"). Listing key metadata is
exactly as sensitive as minting one, so sharing the guard is the correct call, not a
shortcut.
"""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from authz_core import Action, ResourceNotVisible
from fastapi import APIRouter, Depends, status

from app.api.deps import Authorized, Resource, get_principal, requires
from app.api.errors import UnknownApiKeyScope
from app.auth.api_key import mint_api_key
from app.auth.principal import Principal
from app.domain.models import ApiKeyCreate, ApiKeyCreated, ApiKeyRead
from app.infra.client import get_supabase
from supabase import Client

router = APIRouter(prefix="/v1", tags=["5 · API keys"])

Row = dict[str, Any]

#: The seeded rows of `api_key_scopes` (supabase/migrations/20260820000300_seed.sql).
#: No enum for this exists in authz_core the way `Capability` does — `workflow:write`
#: and `governance:denied` in ACTION_SCOPES (actions.py) are deliberate sentinels
#: never seeded, so they must NOT appear here.
_KNOWN_SCOPES = frozenset({"workflow:read", "workflow:run"})


def _validate_scopes(names: list[str]) -> None:
    """Checked against the seeded scope set BEFORE any Supabase call, the same
    idiom as roles.py's `_validate_capabilities`. `api_key_grants.scope` is an
    FK against `api_key_scopes`, so this turns what would otherwise be an
    unhandled FK-violation 500 into a clean 422."""
    unknown = [n for n in names if n not in _KNOWN_SCOPES]
    if unknown:
        raise UnknownApiKeyScope(unknown)


def _to_read(row: Row) -> ApiKeyRead:
    return ApiKeyRead(
        id=row["id"],
        name=row["name"],
        prefix=row["prefix"],
        scopes=[g["scope"] for g in row.get("api_key_grants", [])],
        created_at=row["created_at"],
        expires_at=row.get("expires_at"),
        revoked_at=row.get("revoked_at"),
        last_used_at=row.get("last_used_at"),
    )


@router.post(
    "/orgs/{org_id}/api-keys",
    status_code=status.HTTP_201_CREATED,
    response_model=ApiKeyCreated,
    summary="Mint an API key (scoped, lower privilege than login)",
    description=(
        "Creates a machine credential (extra point 2). An API key is deliberately "
        "*less* powerful than the owner's login: it is confined to `workflow:run` / "
        "`workflow:read` scopes, a single org, and can never perform governance "
        "(no team/role/key management). **Requires** `API_KEY_CREATE`. The full key "
        "is returned once here and never again."
    ),
)
async def create_api_key(
    org_id: UUID,
    body: ApiKeyCreate,
    _: Authorized = Depends(requires(Action.API_KEY_CREATE, Resource.org())),
    principal: Principal = Depends(get_principal),
    client: Client = Depends(get_supabase),
) -> ApiKeyCreated:
    """Only the prefix and hash are persisted — the full key is returned here and
    nowhere else."""
    _validate_scopes(body.scopes)
    full, prefix, hashed = mint_api_key()
    row = cast(
        Row,
        client.table("api_keys")
        .insert(
            {
                "user_id": principal.subject,
                "org_id": str(org_id),
                "name": body.name,
                "prefix": prefix,
                "key_hash": hashed,
                "expires_at": body.expires_at.isoformat() if body.expires_at else None,
            }
        )
        .execute()
        .data[0],
    )
    client.table("api_key_grants").insert(
        [{"api_key_id": row["id"], "scope": scope} for scope in body.scopes]
    ).execute()
    return ApiKeyCreated(
        id=row["id"],
        name=row["name"],
        prefix=prefix,
        api_key=full,
        scopes=body.scopes,
        expires_at=row.get("expires_at"),
    )


@router.get(
    "/orgs/{org_id}/api-keys",
    response_model=list[ApiKeyRead],
    summary="List an organization's API keys (metadata only)",
    description="Lists key metadata (never the secret). **Requires** `API_KEY_CREATE`.",
)
async def list_api_keys(
    org_id: UUID,
    _: Authorized = Depends(requires(Action.API_KEY_CREATE, Resource.org())),
    client: Client = Depends(get_supabase),
) -> list[ApiKeyRead]:
    """Metadata only — `key_hash` is never selected, so there is no accidental leak
    to guard against."""
    rows = cast(
        list[Row],
        client.table("api_keys")
        .select(
            "id, name, prefix, created_at, expires_at, revoked_at, last_used_at, "
            "api_key_grants(scope)"
        )
        .eq("org_id", str(org_id))
        .execute()
        .data,
    )
    return [_to_read(row) for row in rows]


@router.delete(
    "/orgs/{org_id}/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an API key",
    description=(
        "Revokes a key. **Requires** `API_KEY_REVOKE`. Scoped by org so a key id "
        "from another org can't be revoked here."
    ),
)
async def revoke_api_key(
    org_id: UUID,
    key_id: UUID,
    _: Authorized = Depends(requires(Action.API_KEY_REVOKE, Resource.org())),
    client: Client = Depends(get_supabase),
) -> None:
    """Scoped by org_id as well as key_id: the guard only proves the caller can
    manage THIS org's keys, so the update must not touch a key that happens to
    share its id with a row in a different org."""
    rows = cast(
        list[Row],
        client.table("api_keys")
        .update({"revoked_at": datetime.now(UTC).isoformat()})
        .eq("id", str(key_id))
        .eq("org_id", str(org_id))
        .execute()
        .data,
    )
    if not rows:
        # 404, not a silent no-op: distinguishes "already revoked" (rows would
        # still match) from "no such key in this org", without confirming the key
        # exists in some OTHER org (spec's not-visible -> 404 rule).
        raise ResourceNotVisible(f"ApiKey:{key_id}")
