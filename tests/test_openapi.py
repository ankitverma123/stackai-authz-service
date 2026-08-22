from app.main import create_app


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
