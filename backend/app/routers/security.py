"""Security Exposure router — M60.3 (read-only foundation).

Routes
------
GET /security/findings        — paginated, filtered list of security findings
GET /security/findings/{id}   — full detail for a single finding

Scope & security
----------------
Findings are workspace-scoped. Every result is restricted to workspaces the
authenticated user is a member of. The detail endpoint returns HTTP 404 (never
403) for findings the user cannot see, to avoid leaking existence — matching
the Changes endpoints.

Mutation actions (accept risk / snooze / review) are intentionally NOT included
in this milestone; they arrive alongside the evaluation engine work.

Naming: this is "security exposure findings" — security-relevant configuration
exposure. It is not breach or threat detection.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.security_finding import (
    VALID_FINDING_SEVERITIES,
    VALID_FINDING_STATUSES,
)
from app.models.user import User
from app.schemas.security_finding import (
    SecurityFindingListResponse,
    SecurityFindingResponse,
)
from app.services import security_finding_service

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/findings", response_model=SecurityFindingListResponse)
def list_security_findings(
    status: Optional[str] = Query(
        None, description="Filter by lifecycle status (active/resolved/accepted_risk/snoozed)."
    ),
    severity: Optional[str] = Query(
        None, description="Filter by severity (critical/high/medium/low/info)."
    ),
    provider: Optional[str] = Query(None, description="Filter by provider."),
    integration_id: Optional[UUID4] = Query(None),
    resource_id: Optional[UUID4] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingListResponse:
    """Return a paginated, filtered list of the user's security findings.

    Results are restricted to the authenticated user's workspaces and ordered
    by ``last_seen_at DESC``. All filters are optional and combined with AND.
    """
    if status is not None and status not in VALID_FINDING_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {status!r}")
    if severity is not None and severity not in VALID_FINDING_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"Invalid severity: {severity!r}")

    items, total = security_finding_service.list_findings(
        user_id=current_user.id,
        db=db,
        status=status,
        severity=severity,
        provider=provider,
        integration_id=integration_id,
        resource_id=resource_id,
        page=page,
        page_size=page_size,
    )

    return SecurityFindingListResponse(
        items=[SecurityFindingResponse.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/findings/{finding_id}", response_model=SecurityFindingResponse)
def get_security_finding(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Return full detail for a single security finding.

    Returns HTTP 404 whether the finding does not exist OR belongs to a
    workspace the user is not a member of.
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")
    return SecurityFindingResponse.model_validate(finding)
