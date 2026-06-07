"""Pydantic schemas for Security Exposure findings — M60.3.

Read-only response shapes for GET /security/findings and
GET /security/findings/{id}. JSONB fields (evidence, remediation) are typed as
``Optional[dict[str, Any]]`` and returned verbatim. Mutation schemas
(accept/snooze/review) are intentionally deferred to a later milestone.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import UUID4, BaseModel, ConfigDict


class SecurityFindingResponse(BaseModel):
    """A single security exposure finding (list + detail share this shape)."""

    id: UUID4
    workspace_id: UUID4
    integration_id: UUID4
    resource_id: Optional[UUID4]
    linked_change_id: Optional[UUID4]

    provider: str
    finding_key: str
    severity: str
    status: str

    title: str
    description: Optional[str]
    evidence: Optional[dict[str, Any]]
    remediation: Optional[dict[str, Any]]

    first_detected_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime]
    accepted_until: Optional[datetime]
    reviewed_by_user_id: Optional[UUID4]
    reviewed_at: Optional[datetime]

    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityFindingListResponse(BaseModel):
    """Paginated list of security findings — GET /security/findings."""

    items: list[SecurityFindingResponse]
    total: int
    page: int
    page_size: int
