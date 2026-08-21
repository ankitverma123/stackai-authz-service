from datetime import datetime
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
