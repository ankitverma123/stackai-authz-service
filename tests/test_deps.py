import dataclasses

from authz_core import Action, AuthzContext, AuthzDenied, AuthzEngineError, ResourceNotVisible
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from app.api.deps import build_context
from app.auth.base import AuthenticationFailed
from app.auth.principal import AuthMethod, Principal
from app.invariants.base import InvariantViolation

#: §9's error table: exception class -> the status its handler in app/api/errors.py
#: registers. Exception classes carry no `.status` attribute of their own (unlike
#: HTTPException, which carries `.status_code` on instances, not the class), so
#: coverage is checked against this table instead.
STATUS_BY_EXCEPTION = {
    AuthenticationFailed: 401,
    AuthzDenied: 403,
    ResourceNotVisible: 404,
    InvariantViolation: 409,
    RequestValidationError: 422,
    AuthzEngineError: 500,
}


class _FakeRequest:
    """Minimal stand-in for the parts of Request that build_context touches."""

    class _State:
        pass

    def __init__(self) -> None:
        self.state = self._State()
        self.headers: dict[str, str] = {}
        self.path_params: dict[str, str] = {}


def test_denied_request_returns_403_without_policy_id(app_with_denied_engine: FastAPI) -> None:
    """policy_id is internal security structure — the client gets a correlation ID."""
    client = TestClient(app_with_denied_engine, raise_server_exceptions=False)
    response = client.get("/guarded/org-1")
    assert response.status_code == 403
    body = response.json()
    assert body["status"] == 403
    assert "correlation_id" in body
    assert "policy_id" not in body
    assert "api-key-no-governance" not in response.text


def test_denied_request_is_audited(app_with_denied_engine: FastAPI) -> None:
    """A Deny must leave an audit trail — "probing another org leaves a trace even
    though the client only ever sees a 404/403". `requires()` queues that write on
    BackgroundTasks and then raises; if the raise drops the queued task, denials
    (and engine-error 500s, and not-visible 404s) are never recorded and only the
    Allow path is audited."""
    from app.api.deps import get_audit_writer

    recorded: list[dict[str, object]] = []

    class RecordingWriter:
        def record(self, **kwargs: object) -> None:
            recorded.append(kwargs)

    app_with_denied_engine.dependency_overrides[get_audit_writer] = lambda: RecordingWriter()
    client = TestClient(app_with_denied_engine, raise_server_exceptions=False)

    response = client.get("/guarded/org-1")

    assert response.status_code == 403
    assert len(recorded) == 1
    assert recorded[0]["decision"].allowed is False  # type: ignore[attr-defined]


def test_engine_error_returns_500_not_403(app_with_erroring_engine: FastAPI) -> None:
    """D6. A schema bug must never masquerade as a legitimate permission denial,
    and an errored forbid must never surface as a quiet allow."""
    client = TestClient(app_with_erroring_engine, raise_server_exceptions=False)
    response = client.get("/guarded/org-1")
    assert response.status_code == 500
    assert response.json()["status"] == 500


def test_problem_json_content_type(app_with_denied_engine: FastAPI) -> None:
    client = TestClient(app_with_denied_engine, raise_server_exceptions=False)
    response = client.get("/guarded/org-1")
    assert response.headers["content-type"].startswith("application/problem+json")


def test_every_principal_field_is_consumed() -> None:
    """api_key_org_id was set by the authenticator, asserted in a test, and read by
    nothing — so a per-org key silently worked across every org its owner belonged
    to. A field that no consumer reads is a claim with no enforcement."""
    principal = Principal(
        subject="u1",
        auth_method=AuthMethod.API_KEY,
        email="a@b.c",
        api_key_scopes=frozenset({"workflow:run"}),
        api_key_org_id="org-1",
    )
    consumed = set(build_context(_FakeRequest(), principal).to_cedar(None))
    mapped = {"subject", "auth_method", "email", "api_key_scopes", "api_key_org_id"}
    declared = {f.name for f in dataclasses.fields(principal)}
    assert declared <= mapped, f"Principal fields with no known consumer: {declared - mapped}"
    assert "api_key_org" in consumed or principal.api_key_org_id is None


def test_every_documented_status_has_a_handler() -> None:
    """Spec §9's error table lists 401/403/404/409/422/500. 401 had a row, prose in
    two places, and no exception class or handler anywhere."""
    from app.main import create_app

    handled = {
        getattr(exc, "status", None) or STATUS_BY_EXCEPTION.get(exc)
        for exc in create_app().exception_handlers
    }
    for status in (401, 403, 404, 409, 422, 500):
        assert status in handled, f"§9 documents {status} but no handler registers it"


def test_context_always_carries_every_required_key() -> None:
    """exported-requires-password reads context.password_verified only when
    resource.password_protected is true, and Cedar short-circuits &&. So an
    unpopulated key merely happens not to be read. Rewriting that policy with the
    operands swapped would fail open on exactly the workflows it protects.

    Populating all three required keys unconditionally makes the fail-open path
    unreachable rather than merely unreached, with D6 as the net behind it."""
    for method in ("jwt", "api_key", "anonymous"):
        ctx = AuthzContext(auth_method=method).to_cedar(Action.WORKFLOW_VIEW)
        assert set(ctx) >= {"auth_method", "password_verified", "api_key_scopes"}
        assert ctx["password_verified"] is False
        assert ctx["api_key_scopes"] == []


def test_required_scope_absent_for_unmapped_action() -> None:
    """Absence is what makes api-key-scope-check DENY an unmapped action."""
    assert "required_scope" not in AuthzContext(auth_method="jwt").to_cedar(None)
