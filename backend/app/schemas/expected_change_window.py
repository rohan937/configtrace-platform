"""Pydantic schemas for expected change window endpoints — M58.16."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import UUID4, BaseModel, ConfigDict, field_validator


# ── Response ──────────────────────────────────────────────────────────────────


class ExpectedChangeWindowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID4
    workspace_id: UUID4
    created_by_user_id: Optional[UUID4] = None
    approved_by_user_id: Optional[UUID4] = None
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    status: str
    alert_behavior: str
    filter_provider: Optional[str] = None
    filter_integration_id: Optional[UUID4] = None
    filter_risk_level: Optional[str] = None
    rejection_reason: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class ExpectedChangeWindowListResponse(BaseModel):
    windows: list[ExpectedChangeWindowResponse]
    total: int


# ── Create request ────────────────────────────────────────────────────────────

_VALID_ALERT_BEHAVIORS = frozenset({"annotate_only", "suppress"})
_VALID_RISK_LEVELS = frozenset({"critical", "high", "medium", "low"})
_TITLE_MAX_LEN = 200
_DESC_MAX_LEN = 2000


class ExpectedChangeWindowCreate(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    # Default to annotate_only — safe default
    alert_behavior: str = "annotate_only"
    # Optional filters; null means "match any"
    filter_provider: Optional[str] = None
    filter_integration_id: Optional[UUID4] = None
    filter_risk_level: Optional[str] = None

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title must not be empty")
        if len(v) > _TITLE_MAX_LEN:
            raise ValueError(f"title must be {_TITLE_MAX_LEN} characters or fewer")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            if len(v) > _DESC_MAX_LEN:
                raise ValueError(
                    f"description must be {_DESC_MAX_LEN} characters or fewer"
                )
        return v

    @field_validator("alert_behavior")
    @classmethod
    def validate_alert_behavior(cls, v: str) -> str:
        if v not in _VALID_ALERT_BEHAVIORS:
            raise ValueError(
                f"alert_behavior must be one of: {sorted(_VALID_ALERT_BEHAVIORS)}"
            )
        return v

    @field_validator("filter_risk_level")
    @classmethod
    def validate_filter_risk_level(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"filter_risk_level must be one of: {sorted(_VALID_RISK_LEVELS)}"
            )
        return v


# ── Action request bodies ─────────────────────────────────────────────────────


class ApproveWindowRequest(BaseModel):
    """No required fields — approval carries no additional payload."""
    pass


class RejectWindowRequest(BaseModel):
    reason: Optional[str] = None


class CancelWindowRequest(BaseModel):
    """No required fields — cancellation carries no additional payload."""
    pass


# ── Match response ────────────────────────────────────────────────────────────


class ExpectedChangeMatchResponse(BaseModel):
    """Result of checking whether a change falls within an approved window.

    matched:    True when a matching approved window was found.
    window:     The matched window (populated when matched=True).
    annotation: Human-readable explanation of the match.
    """

    matched: bool
    window: Optional[ExpectedChangeWindowResponse] = None
    annotation: Optional[str] = None
