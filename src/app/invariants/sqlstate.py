"""Translates the database's invariant violations into application exceptions.

The counting logic lives in Postgres (spec D7a) because only the database can make
a count and a mutation atomic on the PostgREST data path. What remains in Python is
the mapping from SQLSTATE to a friendly message — the division of labour being:
the database guarantees correctness, the application guarantees a good error.
"""

from typing import NoReturn

from app.invariants.base import InvariantViolation

#: Custom SQLSTATEs raised by supabase/migrations/20260820000400_invariants.sql
INVARIANT_BY_SQLSTATE: dict[str, str] = {
    "ZA001": "LastSuperAdmin",
    "ZA002": "LastTeamAdmin",
    "ZA003": "DefaultTeamProtected",
    "ZA004": "RoleInUse",
}

#: Canonical user-facing text per invariant name. Synthesized here rather than
#: forwarded from exc.message: the SQL RAISE text varies by call site (e.g.
#: "remove" vs "demote" the last super-admin) and is an implementation detail of
#: the migration, not a contract with the API response.
_MESSAGE_BY_NAME: dict[str, str] = {
    "LastSuperAdmin": (
        "Cannot remove the last super-admin: the organization would become "
        "permanently unmanageable."
    ),
    "LastTeamAdmin": (
        "Cannot remove the last team admin. An organization super-admin can "
        "perform this action."
    ),
    "DefaultTeamProtected": (
        "Members cannot leave the default team while they belong to the organization."
    ),
    "RoleInUse": "This role is still assigned to members and cannot be deleted.",
}


def raise_for_postgrest_error(exc: Exception) -> NoReturn:
    """Re-raise as InvariantViolation if this is one of ours; otherwise untouched.

    Unknown errors are deliberately passed through: a genuine database failure must
    surface as a 500, never be disguised as a tidy 409.
    """
    code = getattr(exc, "code", None)
    name = INVARIANT_BY_SQLSTATE.get(str(code)) if code else None
    if name is None:
        raise exc
    raise InvariantViolation(name, _MESSAGE_BY_NAME[name]) from exc
