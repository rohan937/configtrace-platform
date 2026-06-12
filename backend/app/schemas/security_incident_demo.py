"""Schemas for the GitHub Incident Workflow demo (M66.10)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class IncidentDemoStatusResponse(BaseModel):
    seeded: bool
    case_id: Optional[str] = None
    link_count: int = 0


class IncidentDemoSeedResponse(BaseModel):
    seeded: bool
    created: bool
    case_id: Optional[str] = None
    link_count: int = 0


class IncidentDemoClearResponse(BaseModel):
    cleared: bool
