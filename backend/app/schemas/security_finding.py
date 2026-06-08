"""Pydantic schemas for Security Exposure findings — M60.3.

Read-only response shapes for GET /security/findings and
GET /security/findings/{id}. JSONB fields (evidence, remediation) are typed as
``Optional[dict[str, Any]]`` and returned verbatim. Mutation schemas
(accept/snooze/review) are intentionally deferred to a later milestone.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import UUID4, BaseModel, ConfigDict, Field, field_validator


class SecurityFindingResponse(BaseModel):
    """A single security exposure finding (list + detail share this shape)."""

    id: UUID4
    workspace_id: UUID4
    integration_id: UUID4
    resource_id: Optional[UUID4]
    linked_change_id: Optional[UUID4]

    provider: str
    finding_key: str
    severity: str
    status: str

    title: str
    description: Optional[str]
    evidence: Optional[dict[str, Any]]
    remediation: Optional[dict[str, Any]]

    first_detected_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime]
    accepted_until: Optional[datetime]
    # M61.2 — when a snooze expires (NULL when not snoozed).
    snoozed_until: Optional[datetime] = None
    reviewed_by_user_id: Optional[UUID4]
    reviewed_at: Optional[datetime]
    # M61.1 — rationale captured when the finding was marked accepted_risk.
    acceptance_reason: Optional[str] = None

    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityFindingListResponse(BaseModel):
    """Paginated list of security findings — GET /security/findings."""

    items: list[SecurityFindingResponse]
    total: int
    page: int
    page_size: int


class AcceptRiskRequest(BaseModel):
    """Body for POST /security/findings/{id}/accept-risk (M61.1).

    Accepting risk records that the team is intentionally carrying a known
    exposure until ``accepted_until``. It does NOT mark the exposure fixed.
    """

    reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Why the team is intentionally carrying this risk.",
    )
    accepted_until: datetime = Field(
        ...,
        description="When the acceptance expires (must be in the future, UTC).",
    )

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("reason must not be blank.")
        return v.strip()

    @field_validator("accepted_until")
    @classmethod
    def _must_be_future(cls, v: datetime) -> datetime:
        aware = v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)
        if aware <= datetime.now(timezone.utc):
            raise ValueError("accepted_until must be in the future.")
        return aware


class SnoozeRequest(BaseModel):
    """Body for POST /security/findings/{id}/snooze (M61.2).

    Snoozing pauses active attention on an exposure until ``snoozed_until``. It
    does NOT accept the risk and does NOT mark the exposure fixed.
    """

    snoozed_until: datetime = Field(
        ...,
        description="When the snooze expires (must be in the future, UTC).",
    )

    @field_validator("snoozed_until")
    @classmethod
    def _must_be_future(cls, v: datetime) -> datetime:
        aware = v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)
        if aware <= datetime.now(timezone.utc):
            raise ValueError("snoozed_until must be in the future.")
        return aware
