"""The single most important test in the repository.

Cedar SKIPS a policy that raises an evaluation error. If that policy was a
`forbid`, a matching `permit` wins and the request is ALLOWED. Observed in the
spike: a Workflow with no `exported` attribute returned Allow on
WorkflowRunExported. D6 exists to make that impossible.
"""

from authz_core.decision import Allow, EngineError
from authz_core.engine import AuthzContext, PolicyEngine


def test_missing_attribute_yields_engine_error_not_allow() -> None:
    engine = PolicyEngine()
    entities = [
        {"uid": {"type": "User", "id": "anon"}, "attrs": {}, "parents": []},
        # `exported` deliberately absent — simulates a missing workflow_exports row
        {"uid": {"type": "Workflow", "id": "wf-1"}, "attrs": {}, "parents": []},
    ]
    decision = engine.authorize_raw(
        principal='User::"anon"',
        action='Action::"WorkflowRunExported"',
        resource='Workflow::"wf-1"',
        entities=entities,
        context=AuthzContext(auth_method="anonymous"),
    )
    assert isinstance(decision, EngineError), f"fail-open: got {decision!r}"
    assert not isinstance(decision, Allow)
    assert "exported" in decision.message


def test_clean_deny_is_not_an_engine_error() -> None:
    """A legitimate denial must stay a Deny — D6 must not turn every 403 into a 500."""
    engine = PolicyEngine()
    entities = [
        {"uid": {"type": "User", "id": "anon"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "Workflow", "id": "wf-1"},
            "attrs": {"exported": False, "visibility": "public", "password_protected": False},
            "parents": [],
        },
    ]
    decision = engine.authorize_raw(
        principal='User::"anon"',
        action='Action::"WorkflowRunExported"',
        resource='Workflow::"wf-1"',
        entities=entities,
        context=AuthzContext(auth_method="anonymous"),
    )
    assert not isinstance(decision, EngineError)
    assert decision.allowed is False
    assert decision.policy_id == "must-be-exported"
