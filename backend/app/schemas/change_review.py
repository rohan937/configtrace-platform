"""Pydantic schemas for change review endpoints — M57.2."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import UUID4, BaseModel, ConfigDict, field_validator


# ── Review status embedded in change responses ────────────────────────────────


class ChangeReviewInfo(BaseModel):
    """Embedded review state returned alongside a Change.

    Included in ChangeListItem and ChangeDetailResponse.  When no review
    row exists for a change the caller should treat it as ``needs_review``.
    """

    review_status: str
    reviewed_by_user_id: Optional[UUID4]
    reviewed_at: Optional[datetime]
    review_note: Optional[str]
    snoozed_until: Optional[datetime]
    snooze_reason: Optional[str]

    model_config = ConfigDict(from_attributes=True)


# ── Action request bodies ─────────────────────────────────────────────────────


class AcknowledgeRequest(BaseModel):
    """POST /changes/{id}/acknowledge"""

    note: Optional[str] = None

    @field_validator("note")
    @classmethod
    def _note_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 1000:
            raise ValueError("Review note must be 1000 characters or fewer.")
        return v or None  # treat empty string as None


class MarkExpectedRequest(BaseModel):
    """POST /changes/{id}/mark-expected"""

    note: Optional[str] = None

    @field_validator("note")
    @classmethod
    def _note_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 1000:
            raise ValueError("Review note must be 1000 characters or fewer.")
        return v or None


class SnoozeRequest(BaseModel):
    """POST /changes/{id}/snooze"""

    until: datetime
    reason: Optional[str] = None

    @field_validator("reason")
    @classmethod
    def _reason_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 1000:
            raise ValueError("Snooze reason must be 1000 characters or fewer.")
        return v or None


class ReopenRequest(BaseModel):
    """POST /changes/{id}/reopen"""

    note: Optional[str] = None

    @field_validator("note")
    @classmethod
    def _note_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 1000:
            raise ValueError("Review note must be 1000 characters or fewer.")
        return v or None


# ── Response ──────────────────────────────────────────────────────────────────


class ChangeReviewResponse(BaseModel):
    """Full review state returned from review action endpoints."""

    change_id: UUID4
    review_status: str
    reviewed_by_user_id: Optional[UUID4]
    reviewed_at: Optional[datetime]
    review_note: Optional[str]
    snoozed_until: Optional[datetime]
    snooze_reason: Optional[str]

    model_config = ConfigDict(from_attributes=True)
