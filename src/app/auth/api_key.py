"""API keys are service accounts: an identity that inherits its owner's roles but
is structurally barred from governance actions (api-key-no-governance) and narrowed
further per key (api-key-scope-check).

Format: ew_<prefix>_<secret>. The prefix is an indexed lookup handle so we do one
row read rather than hashing against every key. Only the secret half is hashed.
"""

import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from argon2 import PasswordHasher

from app.auth.principal import AuthMethod, Principal

_hasher = PasswordHasher()
_PREFIX_BYTES = 6
_SECRET_BYTES = 32


def mint_api_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, hash). The full key is shown to the user ONCE."""
    prefix = secrets.token_hex(_PREFIX_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    full = f"ew_{prefix}_{secret}"
    return full, prefix, _hasher.hash(secret)


def split_api_key(full: str) -> tuple[str, str] | None:
    parts = full.split("_", 2)
    if len(parts) != 3 or parts[0] != "ew":
        return None
    return parts[1], parts[2]


def verify_api_key(full: str, hashed: str) -> bool:
    parts = split_api_key(full)
    if parts is None:
        return False
    try:
        return _hasher.verify(hashed, parts[1])
    except Exception:  # argon2 raises several exception types on mismatch/corrupt hash
        return False


class ApiKeyRepository(Protocol):
    async def by_prefix(self, prefix: str) -> dict[str, Any] | None: ...


def _is_expired(value: str | None) -> bool:
    if value is None:
        return False
    return datetime.fromisoformat(value.replace("Z", "+00:00")) <= datetime.now(UTC)


class ApiKeyAuthenticator:
    def __init__(self, repository: ApiKeyRepository) -> None:
        self._repository = repository

    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None:
        raw = headers.get("x-api-key") or headers.get("X-API-Key")
        if not raw:
            return None
        parts = split_api_key(raw)
        if parts is None:
            return None

        row = await self._repository.by_prefix(parts[0])
        if row is None:
            return None
        if row.get("revoked_at") is not None:
            return None
        if _is_expired(row.get("expires_at")):
            return None
        if not verify_api_key(raw, row["key_hash"]):
            return None

        return Principal(
            subject=str(row["user_id"]),
            auth_method=AuthMethod.API_KEY,
            api_key_scopes=frozenset(g["scope"] for g in row.get("api_key_grants", [])),
            api_key_org_id=str(row["org_id"]),
        )
