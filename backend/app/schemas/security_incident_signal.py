"""Pydantic schemas for control-plane Incident Signals (M66.3).

Response-only, safe fields. Signals are review signals derived from audit
activity — never breach/attacker/compromise claims.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class SecurityIncidentSignalResponse(BaseModel):
    """A single incident signal (safe fields only)."""

    id: str
    provider: str
    signal_key: str
    signal_type: str
    severity: str
    status: str
    title: str
    summary: str
    evidence_level: str
    confidence: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    linked_activity_event_id: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime

    @classmethod
    def from_model(cls, sig: Any) -> "SecurityIncidentSignalResponse":
        return cls(
            id=str(sig.id),
            provider=sig.provider,
            signal_key=sig.signal_key,
            signal_type=sig.signal_type,
            severity=sig.severity,
            status=sig.status,
            title=sig.title,
            summary=sig.summary,
            evidence_level=sig.evidence_level,
            confidence=sig.confidence,
            first_seen_at=sig.first_seen_at,
            last_seen_at=sig.last_seen_at,
            linked_activity_event_id=(
                str(sig.linked_activity_event_id)
                if sig.linked_activity_event_id is not None
                else None
            ),
            metadata=sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {},
            created_at=sig.created_at,
        )


class SecurityIncidentSignalListResponse(BaseModel):
    """GET /security/signals response."""

    items: List[SecurityIncidentSignalResponse]
    total: int
    page: int
    page_size: int


class SecuritySignalGenerateRequest(BaseModel):
    """POST /security/signals/generate request body (all optional)."""

    # Restrict generation to a provider; defaults to GitHub-only for now.
    provider: Optional[str] = None


class SecuritySignalGenerateResponse(BaseModel):
    """POST /security/signals/generate response — generation summary."""

    provider: str
    activity_events_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
