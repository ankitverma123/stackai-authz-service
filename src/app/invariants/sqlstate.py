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

def raise_for_postgrest_error(exc: Exception) -> NoReturn:
    """Re-raise as InvariantViolation if this is one of ours; otherwise untouched.

    Unknown errors are deliberately passed through: a genuine database failure must
    surface as a 500, never be disguised as a tidy 409. The message is forwarded
    from the database rather than re-synthesized here: the SQL functions already
    craft careful, user-facing text, and duplicating it in Python would be a second
    source of truth that must be hand-synced with the SQL RAISE messages (which
    differ by call site, e.g. "remove" vs "demote" the last super-admin).
    """
    code = getattr(exc, "code", None)
    name = INVARIANT_BY_SQLSTATE.get(str(code)) if code else None
    if name is None:
        raise exc
    raise InvariantViolation(name, getattr(exc, "message", str(exc))) from exc
