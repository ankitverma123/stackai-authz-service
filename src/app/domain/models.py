from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class TeamRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    org_id: UUID
    name: str
    is_default: bool
    created_at: datetime


class TeamMembershipRead(BaseModel):
    """Satisfies the brief's 'list teams a user belongs to and his role within them'."""
    team_id: UUID
    team_name: str
    org_id: UUID
    role: str
    is_default: bool


class MembershipCreate(BaseModel):
    user_id: UUID
    role: str


class MembershipRead(BaseModel):
    user_id: UUID
    role: str


class WorkflowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    org_id: UUID
    team_id: UUID
    name: str
    created_at: datetime


class WorkflowPage(BaseModel):
    """Keyset page. Carries no total on purpose: a total would require authorizing
    every row in the organization, which is the cost the pre-filter exists to avoid.
    `next_cursor` is null only at true end-of-results (spec §12)."""

    items: list[WorkflowRead]
    next_cursor: str | None = None


class WorkflowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class WorkflowUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class WorkflowExecutionRead(BaseModel):
    """Canned — there is no executions table (spec §12 scopes real execution out
    of this service). Proves the WORKFLOW_RUN guard without inventing storage."""

    id: UUID
    workflow_id: UUID
    status: Literal["queued"]
    started_at: datetime


class WorkflowExportUpdate(BaseModel):
    visibility: Literal["public", "org_only"] = "public"


class WorkflowExportRead(BaseModel):
    workflow_id: UUID
    is_exported: bool
    visibility: Literal["public", "org_only"]
    password_protected: bool


class WorkflowExportProtectionUpdate(BaseModel):
    """A null/absent password clears protection rather than setting one."""

    password: str | None = None


class WorkflowExportProtectionRead(BaseModel):
    workflow_id: UUID
    password_protected: bool


class WorkflowAccessRequest(BaseModel):
    """Body of the password exchange. The password is presented ONCE here, never
    again — execution calls present the token this endpoint issues instead."""

    password: str = Field(min_length=1)


class WorkflowAccessToken(BaseModel):
    token: str
    expires_in: int


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1)
    expires_at: datetime | None = None


class ApiKeyCreated(BaseModel):
    """Returned exactly once, at creation. `key_hash` never appears in a response."""

    id: UUID
    name: str
    prefix: str
    api_key: str
    scopes: list[str]
    expires_at: datetime | None
    warning: str = "This key will not be shown again — store it securely."


class ApiKeyRead(BaseModel):
    """Metadata only. Never carries `key_hash`."""

    id: UUID
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
