"""Pydantic schemas for Security Exposure beta usage events (M63.1)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class SecurityBetaEventCreate(BaseModel):
    """POST /security/beta-events request body."""

    event_name: str
    page_path: Optional[str] = None
    # Allowlisted + truncated server-side; unknown keys are dropped.
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class SecurityBetaEventResponse(BaseModel):
    """POST /security/beta-events response."""

    id: str
    ok: bool = True
