"""Changes service — Milestone 11.

Responsibilities
----------------
* ``get_changes``       — paginated, filtered list of changes scoped by user
* ``get_change_by_id``  — single change scoped by user (returns None on miss/mismatch)

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

* No joins are performed here.  The ``integration_id`` and ``resource_id``
  are denormalised onto the Change row, so all filters are single-table.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.change import Change

_MAX_PAGE_SIZE = 100


def get_changes(
    user_id: uuid.UUID,
    db: Session,
    *,
    integration_id: Optional[uuid.UUID] = None,
    resource_id: Optional[uuid.UUID] = None,
    risk_level: Optional[str] = None,
    change_type: Optional[str] = None,
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
