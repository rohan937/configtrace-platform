"""Workspace permission helpers for Security Exposure actions (M63.2).

Thin wrappers over the existing workspace role system
(`workspace_service.require_role`, ranks owner=3 > admin=2 > member=1). No new
RBAC framework, no new tables.

Two flavors:
  * ``require_workspace_member`` / ``require_workspace_admin`` raise HTTPException
    (404 if not a member, 403 if the role is insufficient) — for routers.
  * ``can_*`` predicates return a bool without raising — for tests / optional
    frontend affordances.

Policy (M63.2):
  * read Security pages / acknowledge / add note  → member or above
  * accept risk / snooze / toggle rules / demo data → admin or owner
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.workspace import WorkspaceMember
from app.services import workspace_service


def _require(
    workspace_id: uuid.UUID, user_id: uuid.UUID, min_role: str, db: Session
) -> WorkspaceMember:
    """Return the membership row, or raise 404 (not a member) / 403 (low role)."""
    try:
        return workspace_service.require_role(workspace_id, user_id, min_role, db)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def require_workspace_member(
    workspace_id: uuid.UUID, user_id: uuid.UUID, db: Session
) -> WorkspaceMember:
    return _require(workspace_id, user_id, "member", db)


def require_workspace_admin(
    workspace_id: uuid.UUID, user_id: uuid.UUID, db: Session
) -> WorkspaceMember:
    return _require(workspace_id, user_id, "admin", db)


def _has_role(
    workspace_id: uuid.UUID, user_id: uuid.UUID, min_role: str, db: Session
) -> bool:
    """Non-raising predicate: True iff the user has at least ``min_role``."""
    try:
        workspace_service.require_role(workspace_id, user_id, min_role, db)
        return True
    except (LookupError, PermissionError):
        return False


# ── Security Exposure action predicates ───────────────────────────────────────

def can_acknowledge_security_finding(workspace_id, user_id, db) -> bool:
    return _has_role(workspace_id, user_id, "member", db)


def can_add_security_note(workspace_id, user_id, db) -> bool:
    return _has_role(workspace_id, user_id, "member", db)


def can_accept_risk(workspace_id, user_id, db) -> bool:
    return _has_role(workspace_id, user_id, "admin", db)


def can_snooze(workspace_id, user_id, db) -> bool:
    return _has_role(workspace_id, user_id, "admin", db)


def can_manage_security_rules(workspace_id, user_id, db) -> bool:
    return _has_role(workspace_id, user_id, "admin", db)


def can_manage_demo_data(workspace_id, user_id, db) -> bool:
    return _has_role(workspace_id, user_id, "admin", db)
