from dataclasses import dataclass, field
from enum import StrEnum

from authz_core import EntityRef


class AuthMethod(StrEnum):
    JWT = "jwt"
    API_KEY = "api_key"
    ANONYMOUS = "anonymous"


@dataclass(frozen=True, slots=True)
class Principal:
    """WHO. Produced by authentication, consumed by authorization.

    `auth_method` travels in the Cedar *context*, not on the entity, because it
    describes the session rather than the person: the same user is a different
    security subject depending on how they connected (spec §6.4).
    """

    subject: str
    auth_method: AuthMethod
    email: str | None = None
    api_key_scopes: frozenset[str] = field(default_factory=frozenset)
    api_key_org_id: str | None = None

    @property
    def ref(self) -> EntityRef:
        return EntityRef("User", self.subject)

    @property
    def is_anonymous(self) -> bool:
        return self.auth_method is AuthMethod.ANONYMOUS


ANONYMOUS_PRINCIPAL = Principal(subject="anonymous", auth_method=AuthMethod.ANONYMOUS)
