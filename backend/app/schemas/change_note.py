"""Pydantic schemas for change note endpoints — M58.8."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import UUID4, BaseModel, ConfigDict, field_validator

_NOTE_BODY_MAX_LEN = 2000


class ChangeNoteCreate(BaseModel):
    """Request body for POST /changes/{change_id}/notes."""

    body: str

    @field_validator("body")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Note body must not be empty.")
        if len(v) > _NOTE_BODY_MAX_LEN:
            raise ValueError(
                f"Note body must be {_NOTE_BODY_MAX_LEN} characters or fewer."
            )
        return v


class ChangeNoteResponse(BaseModel):
    """A single note returned from the API."""

    id: UUID4
    change_id: UUID4
    workspace_id: Optional[UUID4]
    author_user_id: Optional[UUID4]
    body: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ChangeNoteListResponse(BaseModel):
    """Paginated list of notes for a change."""

    items: List[ChangeNoteResponse]
    total: int
