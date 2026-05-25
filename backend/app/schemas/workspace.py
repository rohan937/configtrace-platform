"""Pydantic schemas for workspace, member, invite, and audit log resources — M50/M51."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# ── Role types ────────────────────────────────────────────────────────────────

WorkspaceRole = Literal["owner", "admin", "member"]
InviteRole = Literal["admin", "member"]  # owner is not directly inviteable


# ── Workspace ─────────────────────────────────────────────────────────────────


class WorkspaceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    created_by_user_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class WorkspaceUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class WorkspaceListResponse(BaseModel):
    workspaces: list[WorkspaceResponse]
    total: int


# ── Members ───────────────────────────────────────────────────────────────────


class WorkspaceMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    user_id: UUID
    role: WorkspaceRole
    # email and display_name joined from User (populated by service)
    email: Optional[str] = None
    display_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class MemberUpdateRequest(BaseModel):
    role: WorkspaceRole


class MemberListResponse(BaseModel):
    members: list[WorkspaceMemberResponse]
    total: int


# ── Invites ───────────────────────────────────────────────────────────────────


class WorkspaceInviteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    email: str
    role: InviteRole
    invited_by_user_id: Optional[UUID]
    expires_at: datetime
    accepted_at: Optional[datetime]
    revoked_at: Optional[datetime]
    created_at: datetime
    is_active: bool


class InviteCreateRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    role: InviteRole = "member"

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        """Lowercase and strip whitespace — normalise before storage."""
        return v.strip().lower()


class InviteCreateResponse(WorkspaceInviteResponse):
    """Extends the standard response with the one-time raw token."""

    # Raw token returned only once at creation; never stored or re-exposed.
    invite_token: str
    invite_url: str


class InviteListResponse(BaseModel):
    invites: list[WorkspaceInviteResponse]
    total: int


# ── Public invite preview (no auth required) ──────────────────────────────────


class InvitePreviewResponse(BaseModel):
    """Returned by GET /invites/{token} — safe to show to unauthenticated user."""

    workspace_name: str
    inviter_email: Optional[str]
    role: InviteRole
    email: str
    expires_at: datetime
    is_active: bool


# ── Audit log (M51) ───────────────────────────────────────────────────────────


class WorkspaceAuditLogResponse(BaseModel):
    """A single audit log entry — safe to display in the UI."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    actor_user_id: Optional[UUID]
    event_type: str
    target_type: Optional[str]
    target_id: Optional[str]
    target_display_name: Optional[str]
    metadata_json: Optional[Dict[str, Any]]
    created_at: datetime

    # Joined from User (populated by service layer).
    actor_email: Optional[str] = None
    actor_display_name: Optional[str] = None


class AuditLogListResponse(BaseModel):
    logs: list[WorkspaceAuditLogResponse]
    total: int
