"""Resources service — Milestone 11.

Responsibilities
----------------
* ``get_resources``         — paginated list of resources scoped by user
* ``get_resource_by_id``    — single resource scoped by user (None on miss)
* ``get_resource_snapshots`` — paginated snapshots for a verified resource
* ``get_resource_changes``  — paginated changes for a verified resource

Design decisions
----------------
* Ownership is always verified before returning sub-resources.  If a caller
  passes a resource_id that belongs to another user, ``get_resource_by_id``
  returns None and the sub-resource queries return empty results.  The router
  maps None to HTTP 404 without leaking object existence.

* ``get_resource_snapshots`` and ``get_resource_changes`` call
  ``get_resource_by_id`` as a gate.  This avoids a second WHERE clause on the
  snapshot/change query while keeping the ownership check explicit.

* ``page_size`` is clamped to ``_MAX_PAGE_SIZE`` server-side regardless of what
  the caller passes.

* Snapshots and changes are both ordered by ``created_at DESC`` (most-recent
  first) to match the timeline orientation of the frontend.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.resource import Resource
from app.models.snapshot import Snapshot

_MAX_PAGE_SIZE = 100


def get_resources(
    user_id: uuid.UUID,
    db: Session,
    *,
    integration_id: Optional[uuid.UUID] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Resource], int]:
    """Return a page of resources scoped to *user_id* and a total row count.

    Args:
        user_id:        Owning user — all results are scoped to this ID.
        db:             Active SQLAlchemy session.
        integration_id: Optional filter — restrict to one integration.
        page:           1-based page number (clamped to ≥ 1).
        page_size:      Results per page (clamped to ``_MAX_PAGE_SIZE``).

    Returns:
        ``(items, total)`` where *items* is the current page and *total* is
        the count before pagination.
    """
    page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
    page = max(page, 1)

    q = db.query(Resource).filter(Resource.user_id == user_id)
    if integration_id is not None:
        q = q.filter(Resource.integration_id == integration_id)
    q = q.order_by(Resource.created_at.desc())

    total: int = q.count()
    items: list[Resource] = q.offset((page - 1) * page_size).limit(page_size).all()
    return items, total


def get_resource_by_id(
    resource_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Optional[Resource]:
    """Return a single Resource scoped to *user_id*, or ``None``.

    Returns ``None`` whether the resource does not exist **or** belongs to a
    different user.  The caller should surface both as HTTP 404.
    """
    return (
        db.query(Resource)
        .filter(Resource.id == resource_id, Resource.user_id == user_id)
        .first()
    )


def get_resource_snapshots(
    resource_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
    *,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Snapshot], int]:
    """Return a page of snapshots for *resource_id*, verifying ownership first.

    Ownership is checked via :func:`get_resource_by_id`.  If the resource does
    not exist or belongs to another user, returns ``([], 0)``.

    Results are ordered ``created_at DESC`` (newest first).

    Args:
        resource_id: UUID of the target resource.
        user_id:     Owning user — resource must match this ID.
        db:          Active SQLAlchemy session.
        page:        1-based page number.
        page_size:   Results per page (clamped to ``_MAX_PAGE_SIZE``).

    Returns:
        ``(items, total)`` or ``([], 0)`` if the resource is not found/owned.
    """
    resource = get_resource_by_id(resource_id, user_id, db)
    if resource is None:
        return [], 0

    page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
    page = max(page, 1)

    q = (
        db.query(Snapshot)
        .filter(Snapshot.resource_id == resource_id)
        .order_by(Snapshot.created_at.desc())
    )
    total: int = q.count()
    items: list[Snapshot] = q.offset((page - 1) * page_size).limit(page_size).all()
    return items, total


def get_resource_changes(
    resource_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
    *,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Change], int]:
    """Return a page of changes for *resource_id*, verifying ownership first.

    Ownership is checked via :func:`get_resource_by_id`.  If the resource does
    not exist or belongs to another user, returns ``([], 0)``.

    Results are ordered ``created_at DESC`` (newest first).

    Args:
        resource_id: UUID of the target resource.
        user_id:     Owning user — resource must match this ID.
        db:          Active SQLAlchemy session.
        page:        1-based page number.
        page_size:   Results per page (clamped to ``_MAX_PAGE_SIZE``).

    Returns:
        ``(items, total)`` or ``([], 0)`` if the resource is not found/owned.
    """
    resource = get_resource_by_id(resource_id, user_id, db)
    if resource is None:
        return [], 0

    page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
    page = max(page, 1)

    q = (
        db.query(Change)
        .filter(Change.resource_id == resource_id)
        .order_by(Change.created_at.desc())
    )
    total: int = q.count()
    items: list[Change] = q.offset((page - 1) * page_size).limit(page_size).all()
    return items, total
