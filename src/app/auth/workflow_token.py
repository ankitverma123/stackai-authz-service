"""Short-lived, workflow-scoped access token.

The password is presented ONCE to the exchange endpoint, which is rate-limited.
Execution calls then present this token, so guessing is bounded at the exchange and
execution is not penalised.

Cedar is untouched by any of this: the app validates the token and sets
`password_verified` in the context exactly as designed. The policy in the spec's
§6.3 does not change by one character — which is what a properly decoupled
credential mechanism looks like.
"""

import time

import jwt

_ALGORITHM = "HS256"
_AUDIENCE = "workflow-access"


def issue_workflow_token(workflow_id: str, *, secret: str, ttl_seconds: int) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": workflow_id, "aud": _AUDIENCE, "iat": now, "exp": now + ttl_seconds},
        secret,
        algorithm=_ALGORITHM,
    )


def verify_workflow_token(token: str, workflow_id: str, *, secret: str) -> bool:
    try:
        claims = jwt.decode(token, secret, algorithms=[_ALGORITHM], audience=_AUDIENCE)
    except jwt.PyJWTError:
        return False
    return claims.get("sub") == workflow_id
