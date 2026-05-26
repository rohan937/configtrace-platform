"""Changes service — Milestone 11 / M57.3.

Responsibilities
----------------
* ``get_changes``             — paginated, filtered list of changes scoped by user
* ``get_change_by_id``        — single change scoped by user (returns None on miss/mismatch)
* ``get_needs_review_changes`` — pre-DB-filtered "Needs Review" queue (M57.3)

Design decisions
----------------
* Every query is scoped by ``user_id`` first, so a user cannot enumerate or
  access another user's changes even if they know the change UUID.  Missing
  records and unauthorised records both return ``None``; the caller (router)
  maps that to HTTP 404 so as not to leak object existence.

* ``page_size`` is clamped to ``_MAX_PAGE_SIZE`` server-side so that a caller
  cannot request an unbounded result set by passing a large value.

* ``since`` / ``until`` accept timezone-aware datetimes.  If a naive datetime
  is passed (no tzinfo), it is compared directly against the TIMESTAMPTZ
  column — SQLAlchemy / psycopg2 will coerce it, but callers should send
  UTC-aware values to avoid ambiguity.

* Most filters are single-table (``integration_id``, ``resource_id``, etc.).
  The ``provider`` filter (M29) requires a JOIN to the ``Integration`` table
  since ``provider`` is not denormalised onto the Change row.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import or_, outerjoin
from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.integration import Integration

_MAX_PAGE_SIZE = 100


def get_changes(
    user_id: uuid.UUID,
    db: Session,
    *,
    integration_id: Optional[uuid.UUID] = None,
    resource_id: Optional[uuid.UUID] = None,
    risk_level: Optional[str] = None,
    change_type: Optional[str] = None,
    provider: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Change], int]:
    """Return a page of changes scoped to *user_id* and a total row count.

    All filter parameters are optional.  Filters are combined with AND.
    Results are ordered by ``created_at DESC`` (most-recent first).

    Args:
        user_id:        Owning user — all results are scoped to this ID.
        db:             Active SQLAlchemy session.
        integration_id: Restrict to changes from this integration.
        resource_id:    Restrict to changes from this resource.
        risk_level:     Restrict to ``'low'``, ``'medium'``, ``'high'``, or
                        ``'critical'``.
        change_type:    Restrict to ``'added'``, ``'removed'``, or
                        ``'modified'``.
        provider:       Restrict to changes from integrations with this
                        provider (e.g. ``'cloudflare'``, ``'github'``).
                        Requires a JOIN to the Integration table.  Changes
                        from soft-deleted integrations are still included
                        because history must be preserved.
        since:          Return only changes with ``created_at >= since``.
        until:          Return only changes with ``created_at <= until``.
        page:           1-based page number (clamped to ≥ 1).
        page_size:      Results per page (clamped to ``_MAX_PAGE_SIZE``).

    Returns:
        ``(items, total)`` where *items* is the current page and *total* is
        the count before pagination.
    """
    page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
    page = max(page, 1)

    q = db.query(Change).filter(Change.user_id == user_id)

    if provider is not None:
        # JOIN to Integration to filter by provider.  Using a regular JOIN
        # (not outer join) is safe because every Change row has a valid
        # integration_id FK — the provider filter simply narrows to one
        # provider's rows.  Soft-deleted integrations are still joined so
        # their historical changes remain accessible.
        q = q.join(Integration, Change.integration_id == Integration.id)
        q = q.filter(Integration.provider == provider)

    if integration_id is not None:
        q = q.filter(Change.integration_id == integration_id)
    if resource_id is not None:
        q = q.filter(Change.resource_id == resource_id)
    if risk_level is not None:
        q = q.filter(Change.risk_level == risk_level)
    if change_type is not None:
        q = q.filter(Change.change_type == change_type)
    if since is not None:
        q = q.filter(Change.created_at >= since)
    if until is not None:
        q = q.filter(Change.created_at <= until)

    q = q.order_by(Change.created_at.desc())

    total: int = q.count()
    items: list[Change] = q.offset((page - 1) * page_size).limit(page_size).all()
    return items, total


def get_change_by_id(
    change_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Optional[Change]:
    """Return a single Change scoped to *user_id*, or ``None``.

    Returns ``None`` whether the change does not exist **or** belongs to a
    different user.  The caller should surface both cases as HTTP 404.

    Args:
        change_id: UUID of the target Change row.
        user_id:   Owning user — the row must match this ID.
        db:        Active SQLAlchemy session.
    """
    return (
        db.query(Change)
        .filter(Change.id == change_id, Change.user_id == user_id)
        .first()
    )


def get_needs_review_changes(
    user_id: uuid.UUID,
    db: Session,
    *,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Change], int]:
    """Return a page of changes that need review, with accurate pre-DB filtering.

    A change "needs review" when:
      - It has no ChangeReview row (never reviewed), OR
      - Its review_status is explicitly 'needs_review', OR
      - Its review_status is 'snoozed' and snoozed_until has passed (expired).

    Unlike the M57.2 post-pagination filter on GET /changes, this function
    applies the condition in SQL so that pagination counts are accurate.

    Args:
        user_id:   Owning user — all results scoped to this ID.
        db:        Active SQLAlchemy session.
        page:      1-based page number.
        page_size: Results per page (clamped to _MAX_PAGE_SIZE).

    Returns:
        ``(items, total)`` — current page and total matching count.
    """
    from app.models.change_review import ChangeReview

    page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
    page = max(page, 1)
    now = datetime.now(timezone.utc)

    # LEFT OUTER JOIN change_reviews so we can detect missing rows
    q = (
        db.query(Change)
        .outerjoin(ChangeReview, ChangeReview.change_id == Change.id)
        .filter(Change.user_id == user_id)
        .filter(
            or_(
                ChangeReview.id.is_(None),                         # no review row
                ChangeReview.review_status == "needs_review",      # explicitly set
                (
                    (ChangeReview.review_status == "snoozed")
                    & (ChangeReview.snoozed_until <= now)           # expired snooze
                ),
            )
        )
        .order_by(Change.created_at.desc())
    )

    total: int = q.count()
    items: list[Change] = q.offset((page - 1) * page_size).limit(page_size).all()
    return items, total


def count_needs_review(user_id: uuid.UUID, db: Session) -> int:
    """Return the total number of changes needing review for *user_id*.

    Used by dashboard stats.  Same logic as :func:`get_needs_review_changes`
    but returns only the scalar count.
    """
    from app.models.change_review import ChangeReview

    now = datetime.now(timezone.utc)
    return (
        db.query(Change)
        .outerjoin(ChangeReview, ChangeReview.change_id == Change.id)
        .filter(Change.user_id == user_id)
        .filter(
            or_(
                ChangeReview.id.is_(None),
                ChangeReview.review_status == "needs_review",
                (
                    (ChangeReview.review_status == "snoozed")
                    & (ChangeReview.snoozed_until <= now)
                ),
            )
        )
        .count()
    )


def count_needs_review_by_risk(
    user_id: uuid.UUID,
    risk_level: str,
    db: Session,
) -> int:
    """Return needs-review count filtered to a specific risk level.

    Used by dashboard stats to surface ``critical_needs_review_count``
    and ``high_needs_review_count``.
    """
    from app.models.change_review import ChangeReview

    now = datetime.now(timezone.utc)
    return (
        db.query(Change)
        .outerjoin(ChangeReview, ChangeReview.change_id == Change.id)
        .filter(Change.user_id == user_id, Change.risk_level == risk_level)
        .filter(
            or_(
                ChangeReview.id.is_(None),
                ChangeReview.review_status == "needs_review",
                (
                    (ChangeReview.review_status == "snoozed")
                    & (ChangeReview.snoozed_until <= now)
                ),
            )
        )
        .count()
    )
