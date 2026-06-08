"""Pydantic schemas for Security Exposure beta feedback (M63.6)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class SecurityBetaFeedbackCreate(BaseModel):
    """POST /security/beta-feedback request body."""

    feedback_type: str = "report_export"
    rating: str  # useful | somewhat | not_useful
    comment: Optional[str] = None
    # Allowlisted + truncated server-side; unknown keys are dropped.
    context: Optional[Dict[str, Any]] = Field(default=None)


class SecurityBetaFeedbackResponse(BaseModel):
    """POST /security/beta-feedback response."""

    id: str
    ok: bool = True
