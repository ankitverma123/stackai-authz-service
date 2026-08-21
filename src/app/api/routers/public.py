"""Both routes are in PUBLIC_ROUTES deliberately. They are unauthenticated by
design and guarded by Cedar forbid policies rather than by a requires() dependency:
must-be-exported, exported-requires-password, exported-org-members-only
(packages/authz-core/src/authz_core/policies/extras.cedar).

Extra #3 is not a password replayed on every request. That is brute-forceable,
lands in proxy and access logs, and offers no natural place to rate-limit. Instead
the password is presented ONCE, to `/access`, which is rate-limited; `/executions`
then presents the short-lived token that endpoint issues, so guessing is bounded at
the exchange and execution itself carries no such penalty.
"""

import time
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from authz_core import (
    Action,
    AuthzDenied,
    AuthzEngineError,
    EngineError,
    EntityRef,
    PolicyEngine,
    ResourceNotVisible,
)
from fastapi import APIRouter, Depends, Request, status

from app.api.deps import build_context, get_engine, get_entity_provider, get_principal
from app.api.errors import RateLimited
from app.auth.principal import Principal
from app.auth.workflow_token import issue_workflow_token, verify_workflow_token
from app.domain.models import WorkflowAccessRequest, WorkflowAccessToken, WorkflowExecutionRead
from app.infra.client import get_supabase
from app.infra.entity_provider import SupabaseEntityProvider
from app.settings import Settings, get_settings
from supabase import Client

router = APIRouter(prefix="/v1/public", tags=["public"])

Row = dict[str, Any]

#: Hashes and verifies export passwords. Same algorithm choice as workflows.py's
#: protection endpoint — argon2-cffi defaults to argon2id.
_hasher = PasswordHasher()

#: Computed once at import. When a workflow has no real password_hash (unexported,
#: or exported without a password), _verify_password still runs against THIS hash
#: instead of short-circuiting — paying the same argon2 cost as a real mismatch, so
#: "no password to check" and "wrong password" are indistinguishable by timing.
_DUMMY_HASH = PasswordHasher().hash("dummy")


class _RateLimiter:
    """Exponential backoff per key, in-memory and per-process.

    Not distributed: behind more than one worker/replica each keeps its own state,
    so the effective limit is (limit x process count). Acceptable for this demo per
    CLAUDE.md's "keep it simple" — a real deployment would move this state to Redis
    or similar, keyed the same way.
    """

    def __init__(self, *, base_seconds: float = 1.0, max_seconds: float = 60.0) -> None:
        self._base = base_seconds
        self._max = max_seconds
        self._blocked_until: dict[tuple[str, str], float] = {}
        self._attempts: dict[tuple[str, str], int] = {}

    def check(self, key: tuple[str, str]) -> float | None:
        """Returns None if the request may proceed now, else seconds until it may."""
        remaining = self._blocked_until.get(key, 0.0) - time.monotonic()
        return remaining if remaining > 0 else None

    def record_failure(self, key: tuple[str, str]) -> None:
        attempts = self._attempts.get(key, 0) + 1
        self._attempts[key] = attempts
        backoff = min(self._base * (2 ** (attempts - 1)), self._max)
        self._blocked_until[key] = time.monotonic() + backoff

    def record_success(self, key: tuple[str, str]) -> None:
        self._attempts.pop(key, None)
        self._blocked_until.pop(key, None)


_rate_limiter = _RateLimiter()


def _client_ip(request: Request, settings: Settings) -> str:
    """Left-most X-Forwarded-For entry when the request comes from a configured
    trusted proxy, else the socket peer. Behind a load balancer the socket address
    is the proxy, so keying on it alone rate-limits every visitor as one attacker;
    trusting the header unconditionally lets an attacker rotate the key at will."""
    peer = request.client.host if request.client is not None else "unknown"
    trusted = {p.strip() for p in settings.trusted_proxies.split(",") if p.strip()}
    if peer in trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer


@router.post("/workflows/{workflow_id}/access", status_code=status.HTTP_200_OK)
async def exchange_password_for_token(
    workflow_id: UUID,
    body: WorkflowAccessRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    client: Client = Depends(get_supabase),
) -> WorkflowAccessToken:
    """Rate-limited per (workflow, client) with exponential backoff."""
    key = (str(workflow_id), _client_ip(request, settings))
    retry_after = _rate_limiter.check(key)
    if retry_after is not None:
        raise RateLimited(retry_after)

    rows = cast(
        list[Row],
        client.table("workflow_exports")
        .select("password_hash")
        .eq("workflow_id", str(workflow_id))
        .eq("is_exported", True)
        .execute()
        .data,
    )
    password_hash = rows[0].get("password_hash") if rows else None

    # A missing/absent hash fails the same way as a wrong password: neither the
    # response nor the timing should tell an anonymous caller whether the workflow
    # exists, is exported, or is merely unprotected. Verifying against _DUMMY_HASH
    # rather than short-circuiting on `password_hash is None` is what makes that
    # true of the TIMING too — both paths pay one argon2 verify before failing.
    if not _verify_password(body.password, password_hash or _DUMMY_HASH) or password_hash is None:
        _rate_limiter.record_failure(key)
        raise AuthzDenied(None, "WorkflowAccess", f"Workflow::{workflow_id}")

    _rate_limiter.record_success(key)
    token = issue_workflow_token(
        str(workflow_id),
        secret=settings.workflow_access_token_secret,
        ttl_seconds=settings.workflow_access_token_ttl_seconds,
    )
    return WorkflowAccessToken(token=token, expires_in=settings.workflow_access_token_ttl_seconds)


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except Exception:  # argon2 raises several exception types on mismatch/corrupt hash
        return False


@router.post(
    "/workflows/{workflow_id}/executions",
    status_code=status.HTTP_201_CREATED,
    response_model=WorkflowExecutionRead,
)
async def execute_exported_workflow(
    workflow_id: UUID,
    request: Request,
    principal: Principal = Depends(get_principal),
    engine: PolicyEngine = Depends(get_engine),
    provider: SupabaseEntityProvider = Depends(get_entity_provider),
    settings: Settings = Depends(get_settings),
) -> WorkflowExecutionRead:
    """Sets `request.state.password_verified` from the X-Workflow-Token header, then
    authorizes WORKFLOW_RUN_EXPORTED through the engine EXPLICITLY rather than via
    requires(): the principal may be anonymous, and it is the resource's own
    exported/visibility/password_protected state — not who is asking — that
    decides. There is no `VISIBILITY_ACTION` pre-check (that concept doesn't apply
    to an unauthenticated route), but a workflow id absent from the slice entirely
    still has to 404 rather than reach Cedar, or an undeclared `resource.exported`
    attribute would make the forbids error -> D6 -> 500 for the mundane case of a
    bad id."""
    token = request.headers.get("x-workflow-token")
    if token is not None:
        request.state.password_verified = verify_workflow_token(
            token, str(workflow_id), secret=settings.workflow_access_token_secret
        )

    resource = EntityRef("Workflow", str(workflow_id))
    slice_ = await provider.slice_for(principal.ref, (resource,))
    if not any(e.ref == resource for e in slice_.resources):
        raise ResourceNotVisible(resource.literal())

    decision = engine.authorize(
        principal=principal.ref,
        action=Action.WORKFLOW_RUN_EXPORTED,
        resource=resource,
        slice_=slice_,
        context=build_context(request, principal),
    )
    # D6 — checked FIRST. An Allow carrying errors is the dangerous case.
    if isinstance(decision, EngineError):
        raise AuthzEngineError(decision.message)
    if not decision.allowed:
        raise AuthzDenied(
            decision.policy_id, Action.WORKFLOW_RUN_EXPORTED.value, resource.literal()
        )

    return WorkflowExecutionRead(
        id=uuid4(), workflow_id=workflow_id, status="queued", started_at=datetime.now(UTC)
    )
