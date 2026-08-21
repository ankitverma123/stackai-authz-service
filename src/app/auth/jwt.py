"""Supabase JWT verification, performed locally.

Two properties worth naming:
  * No network round-trip on the happy path — JWKS keys are cached by `kid`.
  * An unknown `kid` triggers at most ONE refetch per key per interval, so key
    rotation does not cause an outage and an attacker cannot use unknown kids to
    drive unbounded outbound requests (spec §7.3).
"""

import time
from collections.abc import Mapping
from typing import Protocol

import jwt
from jwt import PyJWKClient

from app.auth.base import AuthenticationFailed
from app.auth.principal import AuthMethod, Principal

_REFETCH_INTERVAL_SECONDS = 60


class ProfileRepository(Protocol):
    async def get(self, subject: str) -> dict[str, object] | None: ...


class JWTAuthenticator:
    def __init__(
        self,
        *,
        secret: str | None = None,
        jwks_url: str | None = None,
        audience: str = "authenticated",
        profiles: ProfileRepository | None = None,
    ) -> None:
        # `profiles` is optional: no ProfileRepository is wired in yet (Task 13 does
        # not construct one), so the disabled-user check below is dormant until one
        # is. Spec §7.3/§18's "access stops next request" claim does not hold until
        # that wiring lands — tracked as a documented gap, not implemented here.
        self._profiles = profiles
        if not secret and not jwks_url:
            raise ValueError("JWTAuthenticator needs either a secret or a jwks_url")
        self._secret = secret
        self._audience = audience
        self._jwks_client = PyJWKClient(jwks_url) if jwks_url else None
        self._last_refetch: dict[str, float] = {}

    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None:
        raw = headers.get("authorization") or headers.get("Authorization")
        if not raw or not raw.lower().startswith("bearer "):
            return None
        token = raw.split(" ", 1)[1].strip()

        # A Bearer header was supplied, so this is a credential presentation, not an
        # absence. Failing it must 401 — never fall through to anonymous.
        try:
            claims = self._decode(token)
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationFailed("Bearer", "token expired") from exc
        except jwt.PyJWTError as exc:
            raise AuthenticationFailed("Bearer", "invalid token") from exc

        subject = claims.get("sub")
        if not subject:
            raise AuthenticationFailed("Bearer", "token carries no subject")

        # FIX: §7.3 and §18's SCIM claim ("access stops on the very next request")
        # both depend on this lookup. Without it a disabled user's unexpired JWT
        # keeps working for its full TTL and that claim is simply false. Skipped
        # entirely when no ProfileRepository is wired in (see __init__).
        if self._profiles is not None:
            profile = await self._profiles.get(str(subject))
            if profile is None or profile.get("disabled_at") is not None:
                raise AuthenticationFailed("Bearer", "account disabled or unknown")

        email = claims.get("email")
        return Principal(
            subject=str(subject),
            auth_method=AuthMethod.JWT,
            email=str(email) if email is not None else None,
        )

    def _decode(self, token: str) -> dict[str, object]:
        if self._jwks_client is not None:
            kid = jwt.get_unverified_header(token).get("kid", "")
            self._maybe_refetch(str(kid))
            key = self._jwks_client.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token, key, algorithms=["RS256", "ES256"], audience=self._audience
            )
        assert self._secret is not None
        return jwt.decode(token, self._secret, algorithms=["HS256"], audience=self._audience)

    def _maybe_refetch(self, kid: str) -> None:
        """Rate-limited: one refetch per kid per interval."""
        now = time.monotonic()
        last = self._last_refetch.get(kid, 0.0)
        if now - last < _REFETCH_INTERVAL_SECONDS:
            return
        self._last_refetch[kid] = now
        if self._jwks_client is not None:
            self._jwks_client.fetch_data()
