"""Case Evidence Report schema (M66.9).

A metadata-only investigation packet for a case. Typed sub-schemas act as a
privacy gate: only the declared safe fields can ever serialize — raw audit
payloads, raw IPs, secrets, tokens, evidence/remediation blobs, and customer data
have no field to land in.

CLAIM DISCIPLINE: this report presents evidence for review. It never asserts a
breach/attacker/compromise/unauthorized-access. ``case_status`` may be
"confirmed_by_user" (a human action) — never "confirmed breach".
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class CaseReportSignal(BaseModel):
    id: str
    title: str
    signal_type: str
    severity: str
    confidence: str
    status: str
    evidence_level: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class CaseReportRisk(BaseModel):
    id: str
    title: str
    rule: str
    severity: str
    status: str
    confidence: str
    first_detected_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class CaseReportActivity(BaseModel):
    id: str
    event_type: str
    provider: str
    source: str
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    # Pointer ids + salted hash only — never raw payloads/IPs.
    provider_event_id: Optional[str] = None
    raw_ref: Optional[str] = None
    source_ip_hash: Optional[str] = None
    occurred_at: Optional[datetime] = None
    ingested_at: Optional[datetime] = None
    metadata: Dict[str, Any] = {}


class CaseReportCorrelation(BaseModel):
    id: str
    title: str
    correlation_type: str
    severity: str
    confidence: str
    status: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class CaseReportTimelineItem(BaseModel):
    at: Optional[datetime] = None
    label: str


class CaseReportCase(BaseModel):
    id: str
    title: str
    summary: Optional[str] = None
    status: str
    severity: str
    confidence: str
    provider: Optional[str] = None
    opened_by_user_id: Optional[str] = None
    confirmed_by_user_id: Optional[str] = None
    confirmed_at: Optional[datetime] = None
    dismissed_by_user_id: Optional[str] = None
    dismissed_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class SecurityCaseReportResponse(BaseModel):
    """GET /security/cases/{id}/report — structured, metadata-only packet."""

    title: str = "ConfigTrace Case Evidence Report"
    generated_at: datetime
    executive_summary: str
    claim_note: str
    case: CaseReportCase
    signals: List[CaseReportSignal] = []
    risks: List[CaseReportRisk] = []
    activity_events: List[CaseReportActivity] = []
    correlations: List[CaseReportCorrelation] = []
    timeline: List[CaseReportTimelineItem] = []
    review_checklist: List[str] = []
    limitations: str
