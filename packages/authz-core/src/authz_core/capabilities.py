"""What policies bind to. Cedar never learns that roles exist — only capabilities."""

from enum import StrEnum


class Capability(StrEnum):
    VIEW = "view"
    RUN = "run"
    EDIT = "edit"
    EXPORT = "export"
    PROTECT_EXPORT = "protect_export"
    DELETE = "delete"
    MANAGE_MEMBERS = "manage_members"
    CREATE_TEAM = "create_team"
    MANAGE_ORG = "manage_org"
    MANAGE_ROLES = "manage_roles"
    MANAGE_API_KEYS = "manage_api_keys"

    @property
    def attribute(self) -> str:
        """The Cedar resource attribute holding this capability's group entity."""
        return f"can_{self.value}"
