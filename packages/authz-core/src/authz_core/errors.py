class AuthzError(Exception):
    """Base for everything this package raises."""


class AuthzDenied(AuthzError):
    def __init__(self, policy_id: str | None, action: str, resource: str) -> None:
        self.policy_id = policy_id
        self.action = action
        self.resource = resource
        super().__init__(f"denied: {action} on {resource}")


class AuthzEngineError(AuthzError):
    """Raised on EngineError. Callers MUST map this to 500, never 403."""


class ResourceNotVisible(AuthzError):
    """Principal cannot see the resource at all. Callers map this to 404."""
