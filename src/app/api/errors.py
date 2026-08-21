"""RFC 9457 problem+json.

Policy identifiers are internal security structure. Disclosing which rule fired
tells a prober how the system is organised, so the client receives a correlation
ID and the policy_id goes to the log under that same ID. /v1/authz/explain does
return it — that endpoint is authenticated and exists for debugging, so the
disclosure is scoped and intentional (spec §9).
"""

import logging
import uuid
from typing import Any

from authz_core import AuthzDenied, AuthzEngineError, ResourceNotVisible
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.auth.base import AuthenticationFailed
from app.invariants.base import InvariantViolation

logger = logging.getLogger(__name__)

_BASE = "https://stackai.example/errors"


class RoleNotFound(Exception):
    """A request body named a role that matches no row in `roles` for the given
    scope + org. Malformed input, not a database failure — mapped to 422 so it
    doesn't propagate as an unhandled 500 (Task 16 fix round 1)."""

    def __init__(self, role: str) -> None:
        self.role = role
        super().__init__(f"Unknown role: {role!r}")


def problem_response(
    *, status: int, title: str, detail: str, correlation_id: str, **extra: Any  # noqa: ANN401
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"{_BASE}/{title.lower().replace(' ', '-')}",
        "title": title,
        "status": status,
        "detail": detail,
        "correlation_id": correlation_id,
        **extra,
    }
    return JSONResponse(
        status_code=status, content=body, media_type="application/problem+json"
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthzDenied)
    async def _denied(request: Request, exc: AuthzDenied) -> JSONResponse:
        cid = str(uuid.uuid4())
        logger.warning(
            "authz denied", extra={"correlation_id": cid, "policy_id": exc.policy_id,
                                   "action": exc.action, "resource": exc.resource},
        )
        return problem_response(
            status=403, title="Forbidden",
            detail="You do not have permission to perform this action.",
            correlation_id=cid,
        )

    @app.exception_handler(ResourceNotVisible)
    async def _not_visible(request: Request, exc: ResourceNotVisible) -> JSONResponse:
        # 404 rather than 403: a 403 would confirm the resource exists.
        return problem_response(
            status=404, title="Not Found", detail="Resource not found.",
            correlation_id=str(uuid.uuid4()),
        )

    @app.exception_handler(AuthzEngineError)
    async def _engine_error(request: Request, exc: AuthzEngineError) -> JSONResponse:
        cid = str(uuid.uuid4())
        logger.error("authz engine error", extra={"correlation_id": cid, "detail": str(exc)})
        return problem_response(
            status=500, title="Internal Server Error",
            detail="The authorization engine could not evaluate this request.",
            correlation_id=cid,
        )

    @app.exception_handler(InvariantViolation)
    async def _invariant(request: Request, exc: InvariantViolation) -> JSONResponse:
        # 409, not 403: the caller HAD permission; the operation would corrupt state.
        return problem_response(
            status=409, title="Conflict", detail=str(exc),
            correlation_id=str(uuid.uuid4()), invariant=exc.name,
        )

    @app.exception_handler(AuthenticationFailed)
    async def _unauthenticated(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        response = problem_response(
            status=401, title="Unauthorized",
            detail="Valid credentials are required.",
            correlation_id=str(uuid.uuid4()),
        )
        # RFC 9457 + RFC 7235: a 401 MUST carry WWW-Authenticate.
        response.headers["WWW-Authenticate"] = exc.scheme
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem_response(
            status=422, title="Unprocessable Entity", detail="Request validation failed.",
            correlation_id=str(uuid.uuid4()), errors=exc.errors(),
        )

    @app.exception_handler(RoleNotFound)
    async def _role_not_found(request: Request, exc: RoleNotFound) -> JSONResponse:
        # Also 422: a well-formed body referencing a role that doesn't exist.
        return problem_response(
            status=422, title="Unprocessable Entity", detail=str(exc),
            correlation_id=str(uuid.uuid4()),
        )
