from app.auth.api_key import ApiKeyAuthenticator, mint_api_key, verify_api_key
from app.auth.principal import AuthMethod


def test_minted_key_has_prefix_and_verifies() -> None:
    full, prefix, hashed = mint_api_key()
    assert full.startswith("ew_")
    assert prefix in full
    assert verify_api_key(full, hashed) is True


def test_wrong_key_does_not_verify() -> None:
    _full, _prefix, hashed = mint_api_key()
    other, _p2, _h2 = mint_api_key()
    assert verify_api_key(other, hashed) is False


def test_hash_is_not_the_key() -> None:
    """Raw keys are returned exactly once, at creation, and never stored."""
    full, _prefix, hashed = mint_api_key()
    assert full not in hashed
    assert hashed.startswith("$argon2")


class FakeRepo:
    def __init__(self, row: dict | None) -> None:
        self._row = row

    async def by_prefix(self, prefix: str) -> dict | None:
        return self._row


async def test_revoked_key_fails_closed() -> None:
    full, prefix, hashed = mint_api_key()
    repo = FakeRepo(
        {
            "id": "k1",
            "user_id": "u1",
            "org_id": "o1",
            "prefix": prefix,
            "key_hash": hashed,
            "revoked_at": "2026-01-01T00:00:00Z",
            "expires_at": None,
            "api_key_grants": [{"scope": "workflow:run"}],
        }
    )
    auth = ApiKeyAuthenticator(repo)
    assert await auth.authenticate({"x-api-key": full}) is None


async def test_expired_key_fails_closed() -> None:
    full, prefix, hashed = mint_api_key()
    repo = FakeRepo(
        {
            "id": "k1",
            "user_id": "u1",
            "org_id": "o1",
            "prefix": prefix,
            "key_hash": hashed,
            "revoked_at": None,
            "expires_at": "2020-01-01T00:00:00Z",
            "api_key_grants": [{"scope": "workflow:run"}],
        }
    )
    auth = ApiKeyAuthenticator(repo)
    assert await auth.authenticate({"x-api-key": full}) is None


async def test_valid_key_yields_principal_carrying_its_scopes() -> None:
    full, prefix, hashed = mint_api_key()
    repo = FakeRepo(
        {
            "id": "k1",
            "user_id": "u1",
            "org_id": "o1",
            "prefix": prefix,
            "key_hash": hashed,
            "revoked_at": None,
            "expires_at": None,
            "api_key_grants": [{"scope": "workflow:run"}],
        }
    )
    principal = await ApiKeyAuthenticator(repo).authenticate({"x-api-key": full})
    assert principal is not None
    assert principal.auth_method is AuthMethod.API_KEY
    assert principal.api_key_scopes == frozenset({"workflow:run"})
    assert principal.api_key_org_id == "o1"
