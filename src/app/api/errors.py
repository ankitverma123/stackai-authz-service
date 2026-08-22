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


class RateLimited(Exception):
    """Too many password attempts for one (workflow, client) pair (app/api/routers/
    public.py's exchange endpoint). Maps to 429, not 403 — the caller isn't denied
    permission, they're denied a *turn*."""

    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"rate limited, retry after {retry_after_seconds:.1f}s")


class RoleNotFound(Exception):
    """A request body named a role that matches no row in `roles` for the given
    scope + org. Malformed input, not a database failure — mapped to 422 so it
    doesn't propagate as an unhandled 500 (Task 16 fix round 1)."""

    def __init__(self, role: str) -> None:
        self.role = role
        super().__init__(f"Unknown role: {role!r}")


class UnknownCapability(Exception):
    """`POST /v1/orgs/{org_id}/roles` named a capability that isn't seeded.

    This is the security proof for D3: roles compose EXISTING capabilities only,
    so a role can never invent security surface. Raised BEFORE any Supabase call
    — capabilities are validated against the `Capability` enum in authz-core,
    which is exactly the seeded set, so this never needs the database to reject
    a bad request."""

    def __init__(self, names: list[str]) -> None:
        self.names = names
        super().__init__(f"Unknown capability(ies): {names!r}")


class UnknownApiKeyScope(Exception):
    """`POST /v1/orgs/{org_id}/api-keys` named a scope that isn't seeded.

    `api_key_grants.scope` is FK-constrained against `api_key_scopes`, so this
    check exists for the same reason UnknownCapability does: turn what would
    otherwise be an unhandled PostgREST FK-violation into a clean 422, raised
    BEFORE any Supabase call."""

    def __init__(self, names: list[str]) -> None:
        self.names = names
        super().__init__(f"Unknown scope(s): {names!r}")


def problem_response(
    *,
    status: int,
    title: str,
    detail: str,
    correlation_id: str,
    **extra: Any,  # noqa: ANN401
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"{_BASE}/{title.lower().replace(' ', '-')}",
        "title": title,
        "status": status,
        "detail": detail,
        "correlation_id": correlation_id,
        **extra,
    }
    return JSONResponse(status_code=status, content=body, media_type="application/problem+json")


def _carry_audit_tasks(request: Request, response: JSONResponse) -> JSONResponse:
    """Reattach the audit BackgroundTasks that `requires()` queued before it raised.

    A response built by an exception handler carries no background tasks by default,
    so the Deny/EngineError/not-visible audit writes would be dropped — see the note
    in app/api/deps.py's requires()."""
    tasks = getattr(request.state, "audit_tasks", None)
    if tasks is not None:
        response.background = tasks
    return response


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthzDenied)
    async def _denied(request: Request, exc: AuthzDenied) -> JSONResponse:
        # Reuse the id requires() minted and wrote onto the audit row (if the
        # exception was raised there); a fresh one only for the rare exception
        # class that never went through requires().
        cid = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
        logger.warning(
            "authz denied",
            extra={
                "correlation_id": cid,
                "policy_id": exc.policy_id,
                "action": exc.action,
                "resource": exc.resource,
            },
        )
        return _carry_audit_tasks(
            request,
            problem_response(
                status=403,
                title="Forbidden",
                detail="You do not have permission to perform this action.",
                correlation_id=cid,
            ),
        )

    @app.exception_handler(ResourceNotVisible)
    async def _not_visible(request: Request, exc: ResourceNotVisible) -> JSONResponse:
        # 404 rather than 403: a 403 would confirm the resource exists.
        cid = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
        logger.warning("resource not visible", extra={"correlation_id": cid})
        return _carry_audit_tasks(
            request,
            problem_response(
                status=404,
                title="Not Found",
                detail="Resource not found.",
                correlation_id=cid,
            ),
        )

    @app.exception_handler(AuthzEngineError)
    async def _engine_error(request: Request, exc: AuthzEngineError) -> JSONResponse:
        cid = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
        logger.error("authz engine error", extra={"correlation_id": cid, "detail": str(exc)})
        return _carry_audit_tasks(
            request,
            problem_response(
                status=500,
                title="Internal Server Error",
                detail="The authorization engine could not evaluate this request.",
                correlation_id=cid,
            ),
        )

    @app.exception_handler(InvariantViolation)
    async def _invariant(request: Request, exc: InvariantViolation) -> JSONResponse:
        # 409, not 403: the caller HAD permission; the operation would corrupt state.
        return problem_response(
            status=409,
            title="Conflict",
            detail=str(exc),
            correlation_id=str(uuid.uuid4()),
            invariant=exc.name,
        )

    @app.exception_handler(AuthenticationFailed)
    async def _unauthenticated(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        response = problem_response(
            status=401,
            title="Unauthorized",
            detail="Valid credentials are required.",
            correlation_id=str(uuid.uuid4()),
        )
        # RFC 9457 + RFC 7235: a 401 MUST carry WWW-Authenticate.
        response.headers["WWW-Authenticate"] = exc.scheme
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem_response(
            status=422,
            title="Unprocessable Entity",
            detail="Request validation failed.",
            correlation_id=str(uuid.uuid4()),
            errors=exc.errors(),
        )

    @app.exception_handler(RateLimited)
    async def _rate_limited(request: Request, exc: RateLimited) -> JSONResponse:
        response = problem_response(
            status=429,
            title="Too Many Requests",
            detail="Too many password attempts for this workflow. Try again later.",
            correlation_id=str(uuid.uuid4()),
        )
        response.headers["Retry-After"] = str(max(1, round(exc.retry_after_seconds)))
        return response

    @app.exception_handler(RoleNotFound)
    async def _role_not_found(request: Request, exc: RoleNotFound) -> JSONResponse:
        # Also 422: a well-formed body referencing a role that doesn't exist.
        return problem_response(
            status=422,
            title="Unprocessable Entity",
            detail=str(exc),
            correlation_id=str(uuid.uuid4()),
        )

    @app.exception_handler(UnknownCapability)
    async def _unknown_capability(request: Request, exc: UnknownCapability) -> JSONResponse:
        # 422: a well-formed body naming a capability that isn't seeded. Never a
        # 500 — the whole point of D3 is that this is a validation failure, not
        # a database failure.
        return problem_response(
            status=422,
            title="Unprocessable Entity",
            detail=str(exc),
            correlation_id=str(uuid.uuid4()),
        )

    @app.exception_handler(UnknownApiKeyScope)
    async def _unknown_api_key_scope(request: Request, exc: UnknownApiKeyScope) -> JSONResponse:
        # 422, same reasoning as UnknownCapability: a well-formed body naming a
        # scope that isn't seeded is a validation failure, not a database one.
        return problem_response(
            status=422,
            title="Unprocessable Entity",
            detail=str(exc),
            correlation_id=str(uuid.uuid4()),
        )
