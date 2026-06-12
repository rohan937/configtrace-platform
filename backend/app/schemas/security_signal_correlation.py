"""Pydantic schemas for risk × activity correlations (M66.6).

Response-only, safe fields. Correlations are evidence for review — never
breach/attacker/compromise claims.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class SecuritySignalCorrelationResponse(BaseModel):
    """A single correlation (safe fields only)."""

    id: str
    provider: str
    correlation_key: str
    correlation_type: str
    severity: str
    confidence: str
    status: str
    title: str
    summary: str
    linked_signal_id: Optional[str] = None
    linked_finding_id: Optional[str] = None
    linked_activity_event_id: Optional[str] = None
    linked_change_id: Optional[str] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime

    @classmethod
    def from_model(cls, c: Any) -> "SecuritySignalCorrelationResponse":
        def _s(v: Any) -> Optional[str]:
            return str(v) if v is not None else None

        return cls(
            id=str(c.id),
            provider=c.provider,
            correlation_key=c.correlation_key,
            correlation_type=c.correlation_type,
            severity=c.severity,
            confidence=c.confidence,
            status=c.status,
            title=c.title,
            summary=c.summary,
            linked_signal_id=_s(c.linked_signal_id),
            linked_finding_id=_s(c.linked_finding_id),
            linked_activity_event_id=_s(c.linked_activity_event_id),
            linked_change_id=_s(c.linked_change_id),
            window_start=c.window_start,
            window_end=c.window_end,
            first_seen_at=c.first_seen_at,
            last_seen_at=c.last_seen_at,
            metadata=c.correlation_metadata if isinstance(c.correlation_metadata, dict) else {},
            created_at=c.created_at,
        )


class SecuritySignalCorrelationListResponse(BaseModel):
    """GET /security/correlations response."""

    items: List[SecuritySignalCorrelationResponse]
    total: int
    page: int
    page_size: int


class SecurityCorrelationGenerateRequest(BaseModel):
    """POST /security/correlations/generate request body (all optional)."""

    provider: Optional[str] = None


class SecurityCorrelationGenerateResponse(BaseModel):
    """POST /security/correlations/generate response — generation summary."""

    provider: str
    findings_scanned: int = 0
    events_scanned: int = 0
    correlations_created: int = 0
    correlations_skipped: int = 0
