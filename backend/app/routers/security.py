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
    AcceptRiskRequest,
    SecurityFindingListResponse,
    SecurityFindingResponse,
    SnoozeRequest,
)
from app.schemas.security_finding_note import (
    SecurityFindingActivityItem,
    SecurityFindingActivityResponse,
    SecurityFindingNoteCreate,
    SecurityFindingNoteListResponse,
    SecurityFindingNoteResponse,
)
from app.services import security_finding_service
from app.services import security_finding_note_service

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


@router.post(
    "/findings/{finding_id}/accept-risk",
    response_model=SecurityFindingResponse,
)
def accept_security_finding_risk(
    finding_id: UUID4,
    body: AcceptRiskRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Mark an active security finding as accepted risk (M61.1).

    Accepting risk records that the team is intentionally carrying a known
    exposure until ``accepted_until`` — for the stated reason. It does NOT mark
    the exposure resolved or fixed, and it sends no notifications.

    * 404 — finding does not exist, or belongs to a workspace the user is not a
      member of (never 403, to avoid leaking existence).
    * 400 — the finding cannot be accepted (e.g. it is already resolved).
    * 422 — the request body is invalid (missing reason, past expiry).

    Re-accepting an already ``accepted_risk`` finding updates its reason and
    expiry without re-subscribing it as a new exposure.
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")

    try:
        updated = security_finding_service.accept_finding_risk(
            db=db,
            finding=finding,
            actor_user_id=current_user.id,
            reason=body.reason,
            accepted_until=body.accepted_until,
        )
    except security_finding_service.FindingNotAcceptableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SecurityFindingResponse.model_validate(updated)


@router.post(
    "/findings/{finding_id}/acknowledge",
    response_model=SecurityFindingResponse,
)
def acknowledge_security_finding(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Acknowledge an active security finding (M61.2).

    Records that the team has reviewed the exposure and is tracking it. The
    finding stays ACTIVE — acknowledging does NOT mark it fixed or resolved, and
    it sends no notifications.

    * 404 — finding not found, or not in the user's workspace (never 403).
    * 400 — the finding cannot be acknowledged (resolved, accepted risk, or
      snoozed — those are already explicit review states).
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")

    try:
        updated = security_finding_service.acknowledge_finding(
            db=db,
            finding=finding,
            actor_user_id=current_user.id,
        )
    except security_finding_service.FindingNotAcceptableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SecurityFindingResponse.model_validate(updated)


@router.post(
    "/findings/{finding_id}/snooze",
    response_model=SecurityFindingResponse,
)
def snooze_security_finding(
    finding_id: UUID4,
    body: SnoozeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingResponse:
    """Snooze an active security finding until ``snoozed_until`` (M61.2).

    Snoozing pauses active attention on the exposure temporarily. It does NOT
    accept the risk and does NOT mark the exposure fixed or resolved, and it
    sends no notifications. While snoozed, the evaluator will not re-open an
    active duplicate; once the snooze expires and the risky state persists, a
    fresh active finding opens.

    * 404 — finding not found, or not in the user's workspace (never 403).
    * 400 — the finding cannot be snoozed (resolved, or accepted risk).
    * 422 — the request body is invalid (missing or past ``snoozed_until``).
    """
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id,
        user_id=current_user.id,
        db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")

    try:
        updated = security_finding_service.snooze_finding(
            db=db,
            finding=finding,
            actor_user_id=current_user.id,
            snoozed_until=body.snoozed_until,
        )
    except security_finding_service.FindingNotAcceptableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SecurityFindingResponse.model_validate(updated)


# ── Review notes + activity feed (M61.3) ──────────────────────────────────────


def _require_finding(finding_id, current_user, db):
    """Load a finding scoped to the user's workspace, or raise 404."""
    finding = security_finding_service.get_finding_for_user(
        finding_id=finding_id, user_id=current_user.id, db=db,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")
    return finding


@router.get(
    "/findings/{finding_id}/notes",
    response_model=SecurityFindingNoteListResponse,
)
def list_security_finding_notes(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingNoteListResponse:
    """Return all review notes for a finding, oldest first (M61.3).

    Only members of the finding's workspace may view notes; others get 404.
    """
    _require_finding(finding_id, current_user, db)
    notes = security_finding_note_service.list_notes(finding_id=finding_id, db=db)
    return SecurityFindingNoteListResponse(
        items=[SecurityFindingNoteResponse.model_validate(n) for n in notes],
        total=len(notes),
    )


@router.post(
    "/findings/{finding_id}/notes",
    response_model=SecurityFindingNoteResponse,
    status_code=201,
)
def create_security_finding_note(
    finding_id: UUID4,
    body: SecurityFindingNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingNoteResponse:
    """Add a review note to a finding (M61.3).

    Notes capture investigation context, owner handoff, or follow-up. A note
    NEVER changes the finding's status and sends no notifications.

    * 404 — finding not found, or not in the user's workspace.
    * 422 — note body is empty / too short / too long.
    """
    finding = _require_finding(finding_id, current_user, db)
    try:
        note = security_finding_note_service.create_note(
            finding_id=finding_id,
            workspace_id=finding.workspace_id,
            author_user_id=current_user.id,
            body=body.body,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityFindingNoteResponse.model_validate(note)


@router.get(
    "/findings/{finding_id}/activity",
    response_model=SecurityFindingActivityResponse,
)
def get_security_finding_activity(
    finding_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityFindingActivityResponse:
    """Return a combined, derived activity feed for a finding (M61.3).

    Combines lifecycle actions (exposure opened, acknowledged, snoozed, risk
    accepted, resolved) derived from the finding's own fields with note_added
    entries. Read-only and metadata-only; emits nothing.

    Only members of the finding's workspace may view activity; others get 404.
    """
    finding = _require_finding(finding_id, current_user, db)
    notes = security_finding_note_service.list_notes(finding_id=finding_id, db=db)
    items = security_finding_note_service.build_activity(finding=finding, notes=notes)
    return SecurityFindingActivityResponse(
        items=[SecurityFindingActivityItem(**it) for it in items],
        total=len(items),
    )
