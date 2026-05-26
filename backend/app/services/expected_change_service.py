"""Expected Change Window service — M58.16.

Responsibilities
----------------
* CRUD for expected_change_windows rows (create, list, approve, reject, cancel).
* Matching: given a change_id, find the best approved window that covers it.

Design
------
* Windows are workspace-scoped.  Only windows with status="approved" are
  eligible for matching.  The time range check is:
    window.start_time <= change.created_at <= window.end_time

* Optional filter columns (filter_provider, filter_integration_id,
  filter_risk_level) are ANDed on top of the time range.  A NULL filter
  column means "match any value".

* alert_behavior="annotate_only" (default) — the match is returned in the
  API response but alert dispatch is NOT suppressed.  "suppress" would
  instruct the alert service to skip sending alerts for the change.

* The service layer owns validation (ValueError) and row retrieval
  (LookupError).  Routers translate these to HTTP 422 / 404 respectively.

* Database commits are NOT performed inside the service; the router
  calls db.commit() after a mutating operation succeeds.

Security
--------
* rejection_reason, title, and description are free-text; callers must
  not store credential values here.  The service does not inspect or
  log their contents.
* Window times are validated server-side (start < end, max 30 days).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.expected_change_window import ExpectedChangeWindow
from app.models.change import Change
from app.models.integration import Integration
from app.schemas.expected_change_window import (
    ExpectedChangeWindowCreate,
    ExpectedChangeWindowListResponse,
    ExpectedChangeWindowResponse,
    ExpectedChangeMatchResponse,
)

_MAX_PAGE_SIZE = 100
_MAX_WINDOW_DAYS = 30


# ── Public API ────────────────────────────────────────────────────────────────


def list_windows(
    workspace_id: uuid.UUID,
    db: Session,
    *,
    status_filter: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> ExpectedChangeWindowListResponse:
    """Return a paginated list of expected change windows for a workspace.

    Args:
        workspace_id:  Owning workspace.
        db:            Active SQLAlchemy session.
        status_filter: Restrict to windows with this status (e.g. "approved").
        page:          1-based page number.
        page_size:     Results per page (clamped to _MAX_PAGE_SIZE).

    Returns:
        ExpectedChangeWindowListResponse with windows and total count.
    """
    page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
    page = max(page, 1)

    q = db.query(ExpectedChangeWindow).filter(
        ExpectedChangeWindow.workspace_id == workspace_id
    )
    if status_filter is not None:
        q = q.filter(ExpectedChangeWindow.status == status_filter)

    q = q.order_by(ExpectedChangeWindow.start_time.desc())
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()

    return ExpectedChangeWindowListResponse(
        windows=[ExpectedChangeWindowResponse.model_validate(w) for w in items],
        total=total,
    )


def create_window(
    workspace_id: uuid.UUID,
    created_by_user_id: uuid.UUID,
    body: ExpectedChangeWindowCreate,
    db: Session,
) -> ExpectedChangeWindow:
    """Create a new expected change window in "pending" status.

    Raises:
        ValueError: when time bounds are invalid.

    The caller must call db.commit() after this returns.
    """
    _validate_times(body.start_time, body.end_time)

    window = ExpectedChangeWindow(
        workspace_id=workspace_id,
        created_by_user_id=created_by_user_id,
        title=body.title,
        description=body.description,
        start_time=body.start_time,
        end_time=body.end_time,
        status="pending",
        alert_behavior=body.alert_behavior,
        filter_provider=body.filter_provider,
        filter_integration_id=(
            body.filter_integration_id
            if body.filter_integration_id is None
            else uuid.UUID(str(body.filter_integration_id))
        ),
        filter_risk_level=body.filter_risk_level,
    )
    db.add(window)
    db.flush()
    return window


def approve_window(
    workspace_id: uuid.UUID,
    window_id: uuid.UUID,
    approver_user_id: uuid.UUID,
    db: Session,
) -> ExpectedChangeWindow:
    """Transition a pending window to approved.

    Raises:
        LookupError: window not found in this workspace.
        ValueError:  window is not in pending status.

    The caller must call db.commit() after this returns.
    """
    window = _get_window(workspace_id, window_id, db)
    if window.status != "pending":
        raise ValueError(
            f"Cannot approve a window with status '{window.status}'."
            " Only 'pending' windows can be approved."
        )
    window.status = "approved"
    window.approved_by_user_id = approver_user_id
    window.approved_at = datetime.now(timezone.utc)
    db.flush()
    return window


def reject_window(
    workspace_id: uuid.UUID,
    window_id: uuid.UUID,
    db: Session,
    *,
    reason: Optional[str] = None,
) -> ExpectedChangeWindow:
    """Transition a pending window to rejected.

    Raises:
        LookupError: window not found in this workspace.
        ValueError:  window is not in pending status.

    The caller must call db.commit() after this returns.
    """
    window = _get_window(workspace_id, window_id, db)
    if window.status != "pending":
        raise ValueError(
            f"Cannot reject a window with status '{window.status}'."
            " Only 'pending' windows can be rejected."
        )
    window.status = "rejected"
    window.rejection_reason = reason
    db.flush()
    return window


def cancel_window(
    workspace_id: uuid.UUID,
    window_id: uuid.UUID,
    db: Session,
) -> ExpectedChangeWindow:
    """Cancel a pending or approved window.

    Raises:
        LookupError: window not found in this workspace.
        ValueError:  window is already rejected or cancelled.

    The caller must call db.commit() after this returns.
    """
    window = _get_window(workspace_id, window_id, db)
    if window.status not in ("pending", "approved"):
        raise ValueError(
            f"Cannot cancel a window with status '{window.status}'."
            " Only 'pending' or 'approved' windows can be cancelled."
        )
    window.status = "cancelled"
    db.flush()
    return window


def match_change(
    change_id: uuid.UUID,
    db: Session,
) -> ExpectedChangeMatchResponse:
    """Check whether a change falls within an approved expected change window.

    Match criteria (all must be true):
      1. Window status == "approved".
      2. window.start_time <= change.created_at <= window.end_time.
      3. filter_provider matches the integration's provider (or is null).
      4. filter_integration_id matches change.integration_id (or is null).
      5. filter_risk_level matches change.risk_level (or is null).

    When multiple windows match, the one approved most recently is returned.

    Args:
        change_id: UUID of the Change row.
        db:        Active SQLAlchemy session.

    Returns:
        ExpectedChangeMatchResponse — always 200; matched=False when no window
        matches (including when the change itself is not found).
    """
    change = db.get(Change, change_id)
    if change is None:
        return ExpectedChangeMatchResponse(matched=False)

    integ = db.get(Integration, change.integration_id)
    if integ is None or integ.workspace_id is None:
        return ExpectedChangeMatchResponse(matched=False)

    workspace_id = integ.workspace_id
    provider = integ.provider
    change_time = change.created_at

    # Load approved windows whose time range covers the change's timestamp.
    # The DB-side filter handles the time range; Python handles optional filters.
    candidates = (
        db.query(ExpectedChangeWindow)
        .filter(
            ExpectedChangeWindow.workspace_id == workspace_id,
            ExpectedChangeWindow.status == "approved",
            ExpectedChangeWindow.start_time <= change_time,
            ExpectedChangeWindow.end_time >= change_time,
        )
        .order_by(ExpectedChangeWindow.approved_at.desc())
        .all()
    )

    for window in candidates:
        if _window_matches_change(window, change, provider):
            annotation = (
                f"Change falls within expected window: {window.title!r}"
                f" ({window.start_time.isoformat()} – {window.end_time.isoformat()})"
            )
            return ExpectedChangeMatchResponse(
                matched=True,
                window=ExpectedChangeWindowResponse.model_validate(window),
                annotation=annotation,
            )

    return ExpectedChangeMatchResponse(matched=False)


# ── Private helpers ───────────────────────────────────────────────────────────


def _get_window(
    workspace_id: uuid.UUID,
    window_id: uuid.UUID,
    db: Session,
) -> ExpectedChangeWindow:
    """Load a window by (workspace_id, id). Raise LookupError when absent."""
    window = (
        db.query(ExpectedChangeWindow)
        .filter(
            ExpectedChangeWindow.id == window_id,
            ExpectedChangeWindow.workspace_id == workspace_id,
        )
        .first()
    )
    if window is None:
        raise LookupError(f"Expected change window {window_id} not found.")
    return window


def _window_matches_change(
    window: ExpectedChangeWindow,
    change: Change,
    provider: str,
) -> bool:
    """Return True when all non-null filter columns match the change."""
    if window.filter_provider is not None:
        if window.filter_provider != provider:
            return False
    if window.filter_integration_id is not None:
        if window.filter_integration_id != change.integration_id:
            return False
    if window.filter_risk_level is not None:
        if window.filter_risk_level != change.risk_level:
            return False
    return True


def _validate_times(start_time: datetime, end_time: datetime) -> None:
    """Raise ValueError when the window time range is invalid."""
    # Coerce naive datetimes to UTC for comparison
    def _utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    s = _utc(start_time)
    e = _utc(end_time)

    if s >= e:
        raise ValueError("start_time must be before end_time.")

    duration_seconds = (e - s).total_seconds()
    max_seconds = _MAX_WINDOW_DAYS * 24 * 3600
    if duration_seconds > max_seconds:
        raise ValueError(
            f"Window duration must not exceed {_MAX_WINDOW_DAYS} days."
        )
