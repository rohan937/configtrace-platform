"""Resources service — Milestone 11.

Responsibilities
----------------
* ``get_resources``         — paginated list of resources scoped by workspace
* ``get_resource_by_id``    — single resource scoped by workspace (None on miss)
* ``get_resource_snapshots`` — paginated snapshots for a verified resource
* ``get_resource_changes``  — paginated changes for a verified resource

Design decisions
----------------
* Access is scoped by workspace membership (``_accessible_resource_filter``
  below), not just the row's ``user_id`` — fixed after an audit found these
  endpoints filtered strictly by ``Resource.user_id``, meaning an invited
  teammate could join a workspace and see zero resources for integrations
  someone else connected. Legacy resources whose integration predates
  workspace linking (``Integration.workspace_id IS NULL``) still fall back
  to strict ``user_id`` ownership, preserving their original behavior.
  If a caller passes a resource_id outside their access, ``get_resource_by_id``
  returns None and the sub-resource queries return empty results.  The router
  maps None to HTTP 404 without leaking object existence.

* ``get_resource_snapshots`` and ``get_resource_changes`` call
  ``get_resource_by_id`` as a gate.  This avoids a second WHERE clause on the
  snapshot/change query while keeping the access check explicit.

* ``page_size`` is clamped to ``_MAX_PAGE_SIZE`` server-side regardless of what
  the caller passes.

* Snapshots and changes are both ordered by ``created_at DESC`` (most-recent
  first) to match the timeline orientation of the frontend.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services.workspace_service import get_user_workspace_ids

_MAX_PAGE_SIZE = 100


def _accessible_resource_filter(user_id: uuid.UUID, db: Session):
    """SQLAlchemy filter expression: a Resource is visible to *user_id* if its
    integration belongs to a workspace the user is a member of, OR (legacy
    fallback) the resource's own ``user_id`` matches."""
    workspace_ids = get_user_workspace_ids(user_id, db)
    return or_(
        Integration.workspace_id.in_(workspace_ids),
        Resource.user_id == user_id,
    )


def get_resources(
    user_id: uuid.UUID,
    db: Session,
    *,
    integration_id: Optional[uuid.UUID] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Resource], int]:
    """Return a page of resources accessible to *user_id* and a total row count.

    Args:
        user_id:        Requesting user — results include every workspace
                         they're a member of.
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

    q = (
        db.query(Resource)
        .join(Integration, Resource.integration_id == Integration.id)
        .filter(_accessible_resource_filter(user_id, db))
    )
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
    """Return a single Resource accessible to *user_id*, or ``None``.

    Returns ``None`` whether the resource does not exist **or** the user has
    no access (not a member of its integration's workspace, and not the
    legacy creating user).  The caller should surface both as HTTP 404.
    """
    return (
        db.query(Resource)
        .join(Integration, Resource.integration_id == Integration.id)
        .filter(Resource.id == resource_id)
        .filter(_accessible_resource_filter(user_id, db))
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
