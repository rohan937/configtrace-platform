"""M63.5 — GET /workspaces/{id}/membership/me (current user's role).

  1.  owner → role owner, is_admin true, is_owner true.
  2.  admin → role admin, is_admin true, is_owner false.
  3.  member → role member, is_admin false, is_owner false.
  4.  non-member → 404.
  5.  endpoint requires authentication (get_current_user dependency).
"""

from __future__ import annotations

import uuid

from app.core.auth import get_current_user
from app.main import app
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M63.5", db=db
    )


def _new_user(db, label="owner"):
    u = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name=label,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _add(db, ws_id, user_id, role):
    db.add(WorkspaceMember(workspace_id=ws_id, user_id=user_id, role=role))
    db.commit()


# ── 1. Owner ──────────────────────────────────────────────────────────────────


def test_owner_membership(client, test_user, db_session):
    ws = _ws(test_user, db_session)  # test_user is owner of their own workspace
    resp = client.get(f"/workspaces/{ws.id}/membership/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "owner"
    assert body["is_admin"] is True
    assert body["is_owner"] is True
    assert body["workspace_id"] == str(ws.id)


# ── 2 & 3. Admin + member (in another owner's workspace) ──────────────────────


def test_admin_membership(client, test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    _add(db_session, ws.id, test_user.id, "admin")
    try:
        resp = client.get(f"/workspaces/{ws.id}/membership/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == "admin"
        assert body["is_admin"] is True
        assert body["is_owner"] is False
    finally:
        db_session.delete(owner)
        db_session.commit()


def test_member_membership(client, test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    _add(db_session, ws.id, test_user.id, "member")
    try:
        resp = client.get(f"/workspaces/{ws.id}/membership/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == "member"
        assert body["is_admin"] is False
        assert body["is_owner"] is False
    finally:
        db_session.delete(owner)
        db_session.commit()


# ── 4. Non-member → 404 ───────────────────────────────────────────────────────


def test_non_member_404(client, test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)  # test_user is NOT a member
    try:
        resp = client.get(f"/workspaces/{ws.id}/membership/me")
        assert resp.status_code == 404
    finally:
        db_session.delete(owner)
        db_session.commit()


# ── 5. Requires auth ──────────────────────────────────────────────────────────


def test_endpoint_requires_auth():
    route = next(
        r
        for r in app.routes
        if getattr(r, "path", None) == "/workspaces/{workspace_id}/membership/me"
        and "GET" in getattr(r, "methods", set())
    )

    def _calls(dep):
        found = dep.call is get_current_user
        for sub in dep.dependencies:
            found = found or _calls(sub)
        return found

    assert _calls(route.dependant)
