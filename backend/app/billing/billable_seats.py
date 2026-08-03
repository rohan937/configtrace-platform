"""Billable-member definition (Commercial Infrastructure message 1).

Audit of the repository's actual workspace-membership model
(``app/models/workspace.py``) as of this message:

  * ``WorkspaceMember`` has exactly three roles: owner / admin / member.
    Removing a member deletes its row (``cascade="all, delete-orphan"`` on
    ``Workspace.members``) — there is no soft-delete / deactivated /
    suspended state for a ``WorkspaceMember`` in this codebase today.
  * ``WorkspaceInvite`` is a SEPARATE table for pending invitations. An
    invite never becomes billable until it is accepted, at which point a
    real ``WorkspaceMember`` row is created (a distinct row, not the invite
    row itself).
  * There is no service-account / API-identity / suspended-user / guest
    concept anywhere in the workspace model — greped for
    ``deactivat``/``suspend``/``service_account``/``api_identity`` in
    ``app/models/workspace.py`` and ``app/services/workspace_service.py``
    with zero matches.

Given that real repository shape, the canonical billable-member definition
is deliberately simple and exactly matches what
``app.services.billing_service.get_workspace_usage`` already counts for
member-limit enforcement — no new concept is invented:

    Billable  = every real WorkspaceMember row (owner, admin, member alike)
    Not billable = pending WorkspaceInvite rows (never counted until accepted)

If a future message introduces deactivated members, service accounts, or
API identities to the workspace model, this function is the single place
to extend — no other module should re-derive a member count independently.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.workspace import Workspace, WorkspaceMember


class WorkspaceHasNoOwnerError(ValueError):
    """Raised when billable-seat calculation is asked to reason about a
    workspace with no owner — an invalid workspace domain state (message-1
    spec item 10: "a workspace with no owner should be invalid at the
    workspace domain level").
    """


def calculate_billable_member_count(workspace_id: uuid.UUID, db: Session) -> int:
    """Return the number of billable (real, active) members for a
    workspace: every ``WorkspaceMember`` row, full stop. Pending invites,
    which live in a separate table and are not yet real members, are never
    counted.

    Raises ``WorkspaceHasNoOwnerError`` if the workspace has no owner row —
    this is treated as an invalid domain state, never silently priced as
    zero billable members (see the zero-member decision documented in
    ``app.billing.pricing``).
    """
    has_owner = (
        db.query(WorkspaceMember)
        .filter(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role == "owner")
        .first()
        is not None
    )
    if not has_owner:
        raise WorkspaceHasNoOwnerError(
            f"workspace {workspace_id} has no owner — invalid workspace domain state, "
            "cannot calculate billable members"
        )

    count = (
        db.query(func.count(WorkspaceMember.id))
        .filter(WorkspaceMember.workspace_id == workspace_id)
        .scalar()
        or 0
    )
    return int(count)


def calculate_billable_member_count_in_memory(members: list[WorkspaceMember]) -> int:
    """Pure, DB-free variant for tests and in-memory ``Workspace`` objects:
    counts every member in the given list. Raises
    ``WorkspaceHasNoOwnerError`` if none has role == "owner"."""
    if not any(m.role == "owner" for m in members):
        raise WorkspaceHasNoOwnerError(
            "workspace member list has no owner — invalid workspace domain state"
        )
    return len(members)
