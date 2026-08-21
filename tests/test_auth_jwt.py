import time

import jwt
import pytest

from app.auth.base import AuthenticationFailed
from app.auth.jwt import JWTAuthenticator
from app.auth.principal import AuthMethod

SECRET = "test-secret"


def _token(**overrides: object) -> str:
    payload = {
        "sub": "11111111-1111-1111-1111-111111111111",
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
        "email": "alice@example.com",
    }
    payload.update(overrides)
    return jwt.encode(payload, SECRET, algorithm="HS256")


async def test_valid_token_yields_principal() -> None:
    auth = JWTAuthenticator(secret=SECRET, audience="authenticated")
    principal = await auth.authenticate({"authorization": f"Bearer {_token()}"})
    assert principal is not None
    assert principal.subject == "11111111-1111-1111-1111-111111111111"
    assert principal.auth_method is AuthMethod.JWT


async def test_expired_token_is_rejected() -> None:
    # P4b: credential present but invalid -> AuthenticationFailed (401), never a
    # silent fall-through to anonymous. See app/auth/base.py's docstring.
    auth = JWTAuthenticator(secret=SECRET, audience="authenticated")
    expired = _token(exp=int(time.time()) - 10)
    with pytest.raises(AuthenticationFailed):
        await auth.authenticate({"authorization": f"Bearer {expired}"})


async def test_wrong_audience_is_rejected() -> None:
    auth = JWTAuthenticator(secret=SECRET, audience="authenticated")
    bad = _token(aud="someone-else")
    with pytest.raises(AuthenticationFailed):
        await auth.authenticate({"authorization": f"Bearer {bad}"})


async def test_tampered_signature_is_rejected() -> None:
    auth = JWTAuthenticator(secret=SECRET, audience="authenticated")
    forged = jwt.encode({"sub": "x", "aud": "authenticated"}, "wrong-key", algorithm="HS256")
    with pytest.raises(AuthenticationFailed):
        await auth.authenticate({"authorization": f"Bearer {forged}"})


async def test_no_header_returns_none_not_error() -> None:
    auth = JWTAuthenticator(secret=SECRET, audience="authenticated")
    assert await auth.authenticate({}) is None
