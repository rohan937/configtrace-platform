"""Pydantic schemas for security finding notes + activity feed — M61.3."""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import UUID4, BaseModel, ConfigDict, field_validator

_NOTE_BODY_MAX_LEN = 2000


class SecurityFindingNoteCreate(BaseModel):
    """Request body for POST /security/findings/{id}/notes."""

    body: str

    @field_validator("body")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        v = (v or "").strip()
        if len(v) < 2:
            raise ValueError("Note body must be at least 2 characters.")
        if len(v) > _NOTE_BODY_MAX_LEN:
            raise ValueError(
                f"Note body must be {_NOTE_BODY_MAX_LEN} characters or fewer."
            )
        return v


class SecurityFindingNoteResponse(BaseModel):
    """A single review note returned from the API."""

    id: UUID4
    finding_id: UUID4
    workspace_id: Optional[UUID4]
    author_user_id: Optional[UUID4]
    body: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityFindingNoteListResponse(BaseModel):
    """List of review notes for a finding (oldest first)."""

    items: List[SecurityFindingNoteResponse]
    total: int


class SecurityFindingActivityItem(BaseModel):
    """One derived activity/audit entry for a finding."""

    type: str
    timestamp: Optional[datetime] = None
    actor_user_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    metadata: dict[str, Any] = {}


class SecurityFindingActivityResponse(BaseModel):
    """Combined activity feed for a finding (newest first)."""

    items: List[SecurityFindingActivityItem]
    total: int
