"""Pydantic schemas for normalized security activity events (M66.2).

Response-only, safe fields. These represent control-plane *activity* (the data
spine for future Incident Signals) — never breach/attacker/compromise claims.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class SecurityActivityEventResponse(BaseModel):
    """A single normalized activity event (safe fields only)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    provider: str
    source: str
    event_type: str
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    # Salted hash only — never a raw IP.
    source_ip_hash: Optional[str] = None
    occurred_at: Optional[datetime] = None
    ingested_at: datetime
    metadata: Dict[str, Any] = {}

    # Map the ORM ``event_metadata`` attribute onto the response ``metadata`` field.
    @classmethod
    def from_model(cls, ev: Any) -> "SecurityActivityEventResponse":
        return cls(
            id=str(ev.id),
            provider=ev.provider,
            source=ev.source,
            event_type=ev.event_type,
            actor_id=ev.actor_id,
            actor_type=ev.actor_type,
            resource_type=ev.resource_type,
            resource_id=ev.resource_id,
            source_ip_hash=ev.source_ip_hash,
            occurred_at=ev.occurred_at,
            ingested_at=ev.ingested_at,
            metadata=ev.event_metadata if isinstance(ev.event_metadata, dict) else {},
        )


class SecurityActivityEventListResponse(BaseModel):
    """GET /security/activity/events response."""

    items: List[SecurityActivityEventResponse]
    total: int
    page: int
    page_size: int


class SecurityActivitySyncRequest(BaseModel):
    """POST /security/activity/sync request body (all fields optional).

    ``integration_id`` targets a specific GitHub integration; when omitted, the
    first active GitHub integration in the workspace is used.
    """

    integration_id: Optional[str] = None


class SecurityActivitySyncResponse(BaseModel):
    """POST /security/activity/sync response — ingestion summary.

    Honest about partial/limited results: ``permission_limited`` is True when the
    provider denied audit-log access (common for non-org or non-Enterprise
    accounts). ``error_message`` is a short, safe string (never secrets).
    """

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    events_seen: int = 0
    events_inserted: int = 0
    events_updated_or_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None
