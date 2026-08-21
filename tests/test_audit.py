from authz_core import Action, Allow, Deny, EngineError

from app.infra.audit import should_record


def test_denials_are_always_recorded() -> None:
    assert should_record(Action.WORKFLOW_VIEW, Deny("cap-view")) is True


def test_engine_errors_are_always_recorded() -> None:
    assert should_record(Action.WORKFLOW_VIEW, EngineError("boom")) is True


def test_allowed_reads_are_not_recorded() -> None:
    """Bounds write amplification: a list endpoint must not write N audit rows."""
    assert should_record(Action.WORKFLOW_VIEW, Allow("cap-view")) is False
    assert should_record(Action.WORKFLOW_LIST, Allow("cap-view")) is False


def test_allowed_mutations_are_recorded() -> None:
    assert should_record(Action.WORKFLOW_UPDATE, Allow("cap-edit")) is True
    assert should_record(Action.TEAM_DELETE, Allow("cap-delete")) is True
    assert should_record(Action.ORG_REMOVE_USER, Allow("org-super-admin-full")) is True
