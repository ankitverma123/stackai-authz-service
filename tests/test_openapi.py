from app.main import TAGS_METADATA, create_app


def test_every_operation_has_a_summary_and_description() -> None:
    """Swagger must be self-documenting for the demo: every endpoint needs a
    human-readable summary (the collapsed-row title) and a description (what it does
    + who may do it). A new undocumented route should fail this."""
    schema = create_app().openapi()
    undocumented = [
        f"{method.upper()} {path}"
        for path, ops in schema["paths"].items()
        for method, op in ops.items()
        if not op.get("summary") or not op.get("description")
    ]
    assert not undocumented, f"operations missing summary/description: {undocumented}"


def test_tag_groups_render_in_demo_order() -> None:
    """The docs are ordered as a recording walkthrough; the OpenAPI `tags` array is
    what Swagger UI uses to order the groups. Keep it deliberate, not incidental."""
    schema = create_app().openapi()
    assert [t["name"] for t in schema["tags"]] == [t["name"] for t in TAGS_METADATA]

    # Every tag a route actually uses must be described in TAGS_METADATA (so nothing
    # falls to the bottom of the page ungrouped).
    declared = {t["name"] for t in TAGS_METADATA}
    used = {
        tag for ops in schema["paths"].values() for op in ops.values() for tag in op.get("tags", [])
    }
    assert used <= declared, f"tags used but not described/ordered: {used - declared}"


def test_openapi_declares_bearer_auth_so_swagger_shows_authorize() -> None:
    """The service authenticates by reading the Authorization header in
    get_principal, not via a FastAPI security utility, so nothing put a security
    scheme in the OpenAPI document — which means Swagger UI at /docs has no
    "Authorize" button and a user cannot attach a Bearer token from the UI. Declare
    an http-bearer scheme (docs-only; runtime auth is unchanged) so the button
    appears and Swagger sends the token."""
    schema = create_app().openapi()

    scheme = schema["components"]["securitySchemes"]["bearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    # Applied globally so the Authorize button is offered on every operation.
    assert {"bearerAuth": []} in schema["security"]
