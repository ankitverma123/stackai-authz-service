import json

from authz_core.actions import ACTION_SCOPES, Action
from authz_core.schema import CEDAR_SCHEMA, load_policies
from cedarpy import validate_policies


def test_schema_declares_context_on_every_action() -> None:
    """A policy reading context.* fails validation unless every action declares a context."""
    for name, spec in CEDAR_SCHEMA[""]["actions"].items():
        # Skip action groups, which are container actions without appliesTo
        if "appliesTo" not in spec:
            continue
        assert "context" in spec["appliesTo"], f"action {name} declares no context shape"


def test_every_action_has_a_scope_mapping() -> None:
    """api-key-scope-check denies when required_scope is absent, so every action needs one."""
    missing = [a for a in Action if a not in ACTION_SCOPES]
    assert not missing, f"actions with no scope mapping: {missing}"


def test_policies_validate_against_schema() -> None:
    result = validate_policies(load_policies(), json.dumps(CEDAR_SCHEMA))
    assert result.validation_passed, result.errors
