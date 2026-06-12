"""Pydantic schemas for the Investigations (Cases) workflow (M66.8).

Response-only safe fields. A case is a human-managed investigation container —
never an automated breach/attacker/compromise claim.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Cases ─────────────────────────────────────────────────────────────────────

class SecurityCaseCreate(BaseModel):
    """POST /security/cases request body."""

    title: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    provider: Optional[str] = None


class SecurityCaseUpdate(BaseModel):
    """PATCH /security/cases/{id} request body (all optional)."""

    title: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    # Lifecycle: open | investigating | confirmed_by_user | dismissed | resolved.
    # confirmed_by_user requires admin/owner (enforced in the router).
    status: Optional[str] = None


class SecurityCaseResponse(BaseModel):
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
    link_count: int = 0
    metadata: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, c: Any, link_count: int = 0) -> "SecurityCaseResponse":
        def _s(v: Any) -> Optional[str]:
            return str(v) if v is not None else None

        return cls(
            id=str(c.id),
            title=c.title,
            summary=c.summary,
            status=c.status,
            severity=c.severity,
            confidence=c.confidence,
            provider=c.provider,
            opened_by_user_id=_s(c.opened_by_user_id),
            confirmed_by_user_id=_s(c.confirmed_by_user_id),
            confirmed_at=c.confirmed_at,
            dismissed_by_user_id=_s(c.dismissed_by_user_id),
            dismissed_at=c.dismissed_at,
            resolved_at=c.resolved_at,
            link_count=link_count,
            metadata=c.case_metadata if isinstance(c.case_metadata, dict) else {},
            created_at=c.created_at,
            updated_at=c.updated_at,
        )


class SecurityCaseListResponse(BaseModel):
    items: List[SecurityCaseResponse]
    total: int
    page: int
    page_size: int


# ── Links ─────────────────────────────────────────────────────────────────────

class SecurityCaseLinkCreate(BaseModel):
    """POST /security/cases/{id}/links request body."""

    linked_object_type: str = Field(..., description="signal|correlation|finding|activity_event")
    linked_object_id: str


class SecurityCaseLinkResponse(BaseModel):
    id: str
    case_id: str
    linked_object_type: str
    linked_object_id: str
    created_by_user_id: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime

    @classmethod
    def from_model(cls, ln: Any) -> "SecurityCaseLinkResponse":
        return cls(
            id=str(ln.id),
            case_id=str(ln.case_id),
            linked_object_type=ln.linked_object_type,
            linked_object_id=str(ln.linked_object_id),
            created_by_user_id=str(ln.created_by_user_id) if ln.created_by_user_id else None,
            metadata=ln.link_metadata if isinstance(ln.link_metadata, dict) else {},
            created_at=ln.created_at,
        )


class SecurityCaseLinkListResponse(BaseModel):
    items: List[SecurityCaseLinkResponse]
    total: int


class SecurityCaseDetailResponse(BaseModel):
    """GET /security/cases/{id} — the case plus its links."""

    case: SecurityCaseResponse
    links: List[SecurityCaseLinkResponse]
