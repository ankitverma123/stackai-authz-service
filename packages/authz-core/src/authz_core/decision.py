from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class Allow:
    policy_id: str | None
    allowed: Literal[True] = True


@dataclass(frozen=True, slots=True)
class Deny:
    policy_id: str | None
    allowed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class EngineError:
    """Cedar produced evaluation errors. NEVER treat as a permission decision:
    an errored `forbid` is skipped, so the raw verdict may be a false Allow."""

    message: str
    allowed: Literal[False] = False


type Decision = Allow | Deny | EngineError
