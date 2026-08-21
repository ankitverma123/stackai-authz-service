"""Decision log.

Written from a FastAPI BackgroundTask, never inline: an audit write must not add
latency to, or be able to fail, the request it describes.

Four limitations are load-bearing, not incidental — name them rather than let the
word "audit" imply coverage this table doesn't have:

1. **At-most-once, not exactly-once.** A row is lost if the container stops
   between the response and the write. Fine for an investigation log; **not** a
   compliance log of record. Exactly-once means writing inside the request
   transaction (paying the latency) or emitting to a durable queue — neither is
   built here.
2. **Authentication failures are absent.** A rejected credential never reaches
   `requires(...)`, so this table records *authorization* decisions only. 401s go
   to structured logs with a correlation ID instead; adding them here is a few
   lines in the authenticator chain (`action='Authenticate'`, `decision='deny'`)
   and is listed as should-have.
3. **Read `Allow`s are not recorded.** This bounds write amplification — a 50-row
   page would otherwise write 50 rows — but it means the system cannot answer
   "who viewed this workflow?", an ordinary compliance question. Denials and
   mutations are complete; successful reads are not. A per-org "verbose audit"
   flag is the natural fix.
4. **A resource entirely absent from the principal's slice yields no audit row.**
   `requires(...)`'s tier-1 check (is this resource in the slice at all?) raises
   `ResourceNotVisible` before any `engine.authorize()` call is made, so there is
   no `Decision` to hand `should_record` — auditing that path would mean
   synthesizing a decision Cedar never rendered. The 404 is real and correct; it
   just leaves no trace in this table. Every other Deny/EngineError produced by
   `requires(...)` — including the visibility check once a Decision exists — is
   recorded.
"""

import logging
from dataclasses import dataclass
from typing import Any

from authz_core import Action, Decision, EngineError

from supabase import Client

logger = logging.getLogger(__name__)

_READ_ACTIONS = frozenset({Action.WORKFLOW_VIEW, Action.WORKFLOW_LIST})


def should_record(action: Action, decision: Decision) -> bool:
    """Deny and EngineError always. Allow only for mutating actions, to bound
    write amplification on read paths."""
    if isinstance(decision, EngineError) or not decision.allowed:
        return True
    return action not in _READ_ACTIONS


@dataclass(slots=True)
class AuditWriter:
    client: Client

    def record(
        self,
        *,
        org_id: str | None,
        principal_id: str,
        auth_method: str,
        action: Action,
        resource_type: str,
        resource_id: str,
        decision: Decision,
        correlation_id: str,
    ) -> None:
        row: dict[str, Any] = {
            "org_id": org_id,
            "principal_id": principal_id,
            "auth_method": auth_method,
            "action": action.value,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "decision": "error"
            if isinstance(decision, EngineError)
            else ("allow" if decision.allowed else "deny"),
            "policy_id": getattr(decision, "policy_id", None),
            "correlation_id": correlation_id,
        }
        try:
            self.client.table("authz_audit_log").insert(row).execute()
        except Exception:
            logger.exception("failed to write audit row", extra={"correlation_id": correlation_id})
