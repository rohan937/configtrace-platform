"""Changes router — Milestone 11 / M57.2 / M57.3.

Routes
------
GET  /changes                       — paginated, filtered change timeline
GET  /changes/needs-review          — pre-DB-filtered "Needs Review" queue (M57.3)
GET  /changes/{change_id}           — single change with full snapshot context

M57.2 review actions (workspace-member RBAC):
POST /changes/{change_id}/acknowledge    — mark as acknowledged
POST /changes/{change_id}/mark-expected  — mark as expected drift
POST /changes/{change_id}/snooze         — snooze until a datetime
POST /changes/{change_id}/reopen         — reset to needs_review

Both GET routes now include an optional ``review`` field with the current
review state.  When no review row exists ``review`` is None (treat as
``needs_review``).

RBAC for review actions
-----------------------
The requester must be a member of the workspace that owns the change's
integration.  The workspace is derived via Change.integration_id →
Integration.workspace_id.  Both user_id owners AND workspace members can
review changes (operational access pattern).

Security
--------
GET endpoints are still scoped by user_id (existing behaviour preserved).
Review POST endpoints use workspace membership scoping.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.snapshot import Snapshot
from app.models.user import User
from app.schemas.change import ChangeDetailResponse, ChangeListItem, ChangeListResponse
from app.schemas.change_review import (
    AcknowledgeRequest,
    ChangeReviewInfo,
    ChangeReviewResponse,
    MarkExpectedRequest,
    ReopenRequest,
    SnoozeRequest,
)
from app.schemas.change_note import (
    ChangeNoteCreate,
    ChangeNoteListResponse,
    ChangeNoteResponse,
)
from app.schemas.change_correlation import CorrelationResponse
from app.services import changes_service
from app.services import change_review_service
from app.services import change_note_service
from app.services import change_correlation_service

router = APIRouter(prefix="/changes", tags=["changes"])


# ── Internal helpers ──────────────────────────────────────────────────────────


def _review_info(review) -> Optional[ChangeReviewInfo]:
    """Convert a ChangeReview row (or None) to ChangeReviewInfo."""
    if review is None:
        return None
    return ChangeReviewInfo.model_validate(review)


def _get_change_and_workspace(change_id, current_user, db):
    """Load a change and verify the requester is a workspace member.

    Returns (change, workspace_id) or raises HTTP 404 / 403.
    """
    import uuid as _uuid
    from app.models.change import Change
    from app.models.integration import Integration
    from app.models.workspace import WorkspaceMember

    change = db.get(Change, change_id)
    if change is None:
        raise HTTPException(status_code=404, detail="Change not found.")

    # Derive workspace from the integration
    integ = db.get(Integration, change.integration_id)
    if integ is None:
        raise HTTPException(status_code=404, detail="Change not found.")

    workspace_id = integ.workspace_id
    if workspace_id is None:
        # Integration not workspace-linked yet — fall back to user_id ownership check
        if change.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Change not found.")
        return change, None

    # Check workspace membership
    member = (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
        .first()
    )
    if member is None:
        # Return 404 to avoid leaking object existence
        raise HTTPException(status_code=404, detail="Change not found.")

    return change, workspace_id


# ── GET needs-review (M57.3) ──────────────────────────────────────────────────


@router.get("/needs-review", response_model=ChangeListResponse)
def list_needs_review_changes(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeListResponse:
    """Return a paginated list of changes that need review.

    A change needs review when:
    - It has no ChangeReview row (never reviewed), OR
    - Its review_status is 'needs_review', OR
    - Its review_status was 'snoozed' but the snooze has now expired.

    Unlike the M57.2 post-pagination review_status filter on GET /changes,
    this endpoint uses a pre-DB LEFT JOIN so the total count is accurate and
    pagination is correct across all pages.

    Results are ordered by ``created_at DESC`` (most-urgent first).
    """
    items, total = changes_service.get_needs_review_changes(
        user_id=current_user.id,
        db=db,
        page=page,
        page_size=page_size,
    )

    change_ids = [c.id for c in items]
    reviews = change_review_service.get_reviews_for_changes(change_ids, db)

    return ChangeListResponse(
        items=[
            ChangeListItem(
                id=c.id,
                integration_id=c.integration_id,
                resource_id=c.resource_id,
                change_type=c.change_type,
                record_identifier=c.record_identifier,
                field_path=c.field_path,
                prev_value=c.prev_value,
                new_value=c.new_value,
                risk_level=c.risk_level,
                risk_reason=c.risk_reason,
                provider_metadata=c.provider_metadata,
                created_at=c.created_at,
                review=_review_info(reviews.get(c.id)),
            )
            for c in items
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


# ── GET list ──────────────────────────────────────────────────────────────────


@router.get("", response_model=ChangeListResponse)
def list_changes(
    integration_id: Optional[UUID4] = Query(None),
    resource_id: Optional[UUID4] = Query(None),
    risk_level: Optional[str] = Query(None),
    change_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    review_status: Optional[str] = Query(
        None,
        description=(
            "Filter by review status: needs_review, acknowledged, expected, snoozed. "
            "Changes with no review row match 'needs_review'."
        ),
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeListResponse:
    """Return a paginated, filtered list of changes for the authenticated user.

    All filters are optional and combined with AND.  Results are ordered by
    ``created_at DESC`` (most-recent change first).

    M57.2 adds:
    - ``review_status`` filter  (applied post-fetch via review table lookup)
    - ``review`` field on each item
    """
    items, total = changes_service.get_changes(
        user_id=current_user.id,
        db=db,
        integration_id=integration_id,
        resource_id=resource_id,
        risk_level=risk_level,
        change_type=change_type,
        provider=provider,
        since=since,
        until=until,
        page=page,
        page_size=page_size,
    )

    # Bulk-load review state for this page (single IN query)
    change_ids = [c.id for c in items]
    reviews = change_review_service.get_reviews_for_changes(change_ids, db)

    # Apply review_status filter if requested (post-fetch, client-side for now)
    # For "needs_review", include changes with no review row OR review_status=="needs_review"
    if review_status is not None:
        filtered_items = []
        for c in items:
            r = reviews.get(c.id)
            actual_status = r.review_status if r else "needs_review"
            if actual_status == review_status:
                filtered_items.append(c)
        items = filtered_items
        # Note: total count is approximate when review_status filter is active
        # (we filtered post-pagination). Acceptable for M57.2 MVP.
        total = len(items)

    return ChangeListResponse(
        items=[
            ChangeListItem(
                id=c.id,
                integration_id=c.integration_id,
                resource_id=c.resource_id,
                change_type=c.change_type,
                record_identifier=c.record_identifier,
                field_path=c.field_path,
                prev_value=c.prev_value,
                new_value=c.new_value,
                risk_level=c.risk_level,
                risk_reason=c.risk_reason,
                provider_metadata=c.provider_metadata,
                created_at=c.created_at,
                review=_review_info(reviews.get(c.id)),
            )
            for c in items
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


# ── GET detail ────────────────────────────────────────────────────────────────


@router.get("/{change_id}", response_model=ChangeDetailResponse)
def get_change(
    change_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeDetailResponse:
    """Return full detail for a single change, including snapshot states.

    In addition to all list-view fields, the response includes:
    - ``prev_snapshot_id`` / ``new_snapshot_id``  — snapshot UUIDs
    - ``prev_snapshot_state`` / ``new_snapshot_state``  — full DNS record lists
    - ``prev_snapshot_created_at`` / ``new_snapshot_created_at``  — timestamps
    - ``review``  — current review state (M57.2)

    Returns HTTP 404 whether the change does not exist or belongs to a
    different user.
    """
    change = changes_service.get_change_by_id(
        change_id=change_id,
        user_id=current_user.id,
        db=db,
    )
    if change is None:
        raise HTTPException(status_code=404, detail="Change not found.")

    prev_snap: Optional[Snapshot] = db.get(Snapshot, change.prev_snapshot_id)
    new_snap: Optional[Snapshot] = db.get(Snapshot, change.new_snapshot_id)

    # Load review state
    review = change_review_service.get_review(change.id, db)

    return ChangeDetailResponse(
        id=change.id,
        integration_id=change.integration_id,
        resource_id=change.resource_id,
        change_type=change.change_type,
        record_identifier=change.record_identifier,
        field_path=change.field_path,
        prev_value=change.prev_value,
        new_value=change.new_value,
        risk_level=change.risk_level,
        risk_reason=change.risk_reason,
        provider_metadata=change.provider_metadata,
        created_at=change.created_at,
        review=_review_info(review),
        prev_snapshot_id=change.prev_snapshot_id,
        new_snapshot_id=change.new_snapshot_id,
        prev_snapshot_state=prev_snap.state if prev_snap else None,
        new_snapshot_state=new_snap.state if new_snap else None,
        prev_snapshot_created_at=prev_snap.created_at if prev_snap else None,
        new_snapshot_created_at=new_snap.created_at if new_snap else None,
    )


# ── Review action endpoints ───────────────────────────────────────────────────


@router.post("/{change_id}/acknowledge", response_model=ChangeReviewResponse)
def acknowledge_change(
    change_id: UUID4,
    body: AcknowledgeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeReviewResponse:
    """Mark a change as acknowledged.

    Records that your team has reviewed this drift.  Optionally attach a note.
    """
    change, _ws = _get_change_and_workspace(change_id, current_user, db)
    try:
        review = change_review_service.acknowledge_change(
            change=change,
            actor_user_id=current_user.id,
            db=db,
            note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ChangeReviewResponse.model_validate(review)


@router.post("/{change_id}/mark-expected", response_model=ChangeReviewResponse)
def mark_change_expected(
    change_id: UUID4,
    body: MarkExpectedRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeReviewResponse:
    """Mark a change as expected / planned drift.

    Use this when the drift was part of a planned deployment or migration.
    """
    change, _ws = _get_change_and_workspace(change_id, current_user, db)
    try:
        review = change_review_service.mark_change_expected(
            change=change,
            actor_user_id=current_user.id,
            db=db,
            note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ChangeReviewResponse.model_validate(review)


@router.post("/{change_id}/snooze", response_model=ChangeReviewResponse)
def snooze_change(
    change_id: UUID4,
    body: SnoozeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeReviewResponse:
    """Snooze a change until the given UTC datetime.

    Snoozed changes are hidden from "needs review" counts until the snooze
    expires (max 90 days from now).
    """
    change, _ws = _get_change_and_workspace(change_id, current_user, db)
    try:
        review = change_review_service.snooze_change(
            change=change,
            actor_user_id=current_user.id,
            db=db,
            until=body.until,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ChangeReviewResponse.model_validate(review)


@router.post("/{change_id}/reopen", response_model=ChangeReviewResponse)
def reopen_change(
    change_id: UUID4,
    body: ReopenRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeReviewResponse:
    """Reopen a change — reset its status back to 'needs_review'.

    Use this when a previously acknowledged or snoozed change needs another look.
    """
    change, _ws = _get_change_and_workspace(change_id, current_user, db)
    try:
        review = change_review_service.reopen_change(
            change=change,
            actor_user_id=current_user.id,
            db=db,
            note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ChangeReviewResponse.model_validate(review)


# ── Notes endpoints (M58.8) ───────────────────────────────────────────────────


@router.get("/{change_id}/notes", response_model=ChangeNoteListResponse)
def list_change_notes(
    change_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeNoteListResponse:
    """Return all investigation notes for a change, oldest first.

    Only workspace members may view notes (same RBAC as review actions).
    """
    _change, _ws = _get_change_and_workspace(change_id, current_user, db)
    notes = change_note_service.list_notes(change_id=change_id, db=db)
    return ChangeNoteListResponse(
        items=[ChangeNoteResponse.model_validate(n) for n in notes],
        total=len(notes),
    )


@router.post("/{change_id}/notes", response_model=ChangeNoteResponse, status_code=201)
def create_change_note(
    change_id: UUID4,
    body: ChangeNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChangeNoteResponse:
    """Add a team investigation note to a change.

    Only workspace members may add notes (same RBAC as review actions).
    The note body is plain text, max 2000 characters.
    """
    _change, workspace_id = _get_change_and_workspace(change_id, current_user, db)
    try:
        note = change_note_service.create_note(
            change_id=change_id,
            workspace_id=workspace_id,
            author_user_id=current_user.id,
            body=body.body,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ChangeNoteResponse.model_validate(note)


# ── Correlation endpoint (M58.10) ─────────────────────────────────────────────


@router.get("/{change_id}/correlation", response_model=CorrelationResponse)
def get_change_correlation(
    change_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CorrelationResponse:
    """Return correlation / risk-cluster analysis for a change.

    Deterministically computed from nearby changes in the same workspace.
    No external API calls, no LLM, no persisted cluster state.

    Returns ``{"available": false}`` when no meaningful cluster is found.
    The endpoint always returns 200; ``available`` communicates whether a
    cluster was detected.
    """
    # Authorise: requester must be a workspace member (same as review actions).
    _get_change_and_workspace(change_id, current_user, db)

    return change_correlation_service.correlate_change(
        change_id=change_id,
        user_id=current_user.id,
        db=db,
    )
