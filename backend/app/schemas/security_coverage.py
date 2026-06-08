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
    # M62.8 — provider permission diagnostics (read-only; metadata-only).
    # ok | needs_sync | missing_metadata | permissions_likely_limited
    # | provider_not_connected | provider_attention_needed
    diagnostic_status: str = "ok"
    diagnostic_messages: List[str] = []
    recommended_actions: List[str] = []
    permission_hints: List[str] = []
    docs_hint: Optional[str] = None
    # Confidence in the DIAGNOSTIC itself (separate from finding confidence).
    diagnostic_confidence: str = "high"  # high | medium | low


class SecurityCoverageSummary(BaseModel):
    connected_providers: int
    good_coverage: int
    limited_coverage: int
    not_connected: int
    disabled_rules: int
    # M62.8 — diagnostic rollups
    diagnostics_ok: int = 0
    diagnostics_needs_sync: int = 0
    diagnostics_missing_metadata: int = 0
    diagnostics_permissions_likely_limited: int = 0


class SecurityCoverageResponse(BaseModel):
    providers: List[SecurityCoverageProvider]
    summary: SecurityCoverageSummary
