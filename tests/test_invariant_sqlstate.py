import pytest

from app.invariants.base import InvariantViolation
from app.invariants.sqlstate import INVARIANT_BY_SQLSTATE, raise_for_postgrest_error


class FakeAPIError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def test_known_sqlstate_becomes_an_invariant_violation() -> None:
    with pytest.raises(InvariantViolation) as exc:
        raise_for_postgrest_error(
            FakeAPIError(
                "ZA001",
                "Cannot remove the last super-admin: the organization would become "
                "permanently unmanageable.",
            )
        )
    assert exc.value.name == "LastSuperAdmin"
    assert "last super-admin" in str(exc.value).lower()


def test_every_sqlstate_has_a_user_facing_message() -> None:
    for code, name in INVARIANT_BY_SQLSTATE.items():
        assert name, f"{code} has no invariant name"


def test_unknown_error_is_re_raised_untouched() -> None:
    """A genuine database failure must not be disguised as a 409."""
    original = FakeAPIError("23505", "duplicate key")
    with pytest.raises(FakeAPIError):
        raise_for_postgrest_error(original)
