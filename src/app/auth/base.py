from collections.abc import Mapping, Sequence
from typing import Protocol

from app.auth.principal import ANONYMOUS_PRINCIPAL, Principal


class Authenticator(Protocol):
    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None: ...


class AuthenticationFailed(Exception):
    """Credentials were PRESENT and invalid. Maps to 401.

    Distinct from returning None, which means "no credentials offered" and lets the
    chain fall through to anonymous — public endpoints depend on that. Collapsing
    the two is why an expired or tampered token previously became a valid anonymous
    principal and got a 403, or on a public route simply succeeded.
    """

    def __init__(self, scheme: str, reason: str) -> None:
        self.scheme = scheme
        self.reason = reason
        super().__init__(f"{scheme}: {reason}")


class AnonymousAuthenticator:
    """Terminal link. Yields a principal with no capabilities, which by construction
    satisfies no cap-* policy."""

    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None:
        return ANONYMOUS_PRINCIPAL


class AuthenticatorChain:
    def __init__(self, authenticators: Sequence[Authenticator]) -> None:
        self._authenticators = authenticators

    async def authenticate(self, headers: Mapping[str, str]) -> Principal:
        for authenticator in self._authenticators:
            principal = await authenticator.authenticate(headers)
            if principal is not None:
                return principal
        return ANONYMOUS_PRINCIPAL
