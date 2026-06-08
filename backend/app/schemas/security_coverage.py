"""Pydantic schemas for Security Exposure coverage quality — M62.3."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class SecurityCoverageRule(BaseModel):
    rule_key: str
    enabled: bool
    # True when observed records exist that this rule can evaluate.
    supported: bool


class SecurityCoverageProvider(BaseModel):
    provider: str
    connected: bool
    integration_id: Optional[str] = None
    integration_status: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    coverage_status: str  # good | limited | not_synced | needs_attention | not_connected
    monitored_surfaces: List[str]
    observed_record_types: List[str]
    expected_record_types: List[str]
    missing_record_types: List[str]
    active_rules: int
    disabled_rules: int
    supported_rules: int
    recommendation: str
    rules: List[SecurityCoverageRule]


class SecurityCoverageSummary(BaseModel):
    connected_providers: int
    good_coverage: int
    limited_coverage: int
    not_connected: int
    disabled_rules: int


class SecurityCoverageResponse(BaseModel):
    providers: List[SecurityCoverageProvider]
    summary: SecurityCoverageSummary
