"""Pydantic schemas for Security Exposure demo-data endpoints — M62.2."""

from __future__ import annotations

from pydantic import BaseModel


class SecurityDemoDataStatus(BaseModel):
    """Whether demo data exists in the current workspace + status counts."""

    exists: bool
    finding_count: int
    active_count: int
    resolved_count: int
    accepted_count: int
    snoozed_count: int


class SecurityDemoClearResponse(BaseModel):
    """Result of clearing demo data."""

    cleared: bool
    findings_deleted: int
    notes_deleted: int
