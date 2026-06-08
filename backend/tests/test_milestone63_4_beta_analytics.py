"""M63.4 — Beta analytics summary over security_beta_events.

  1.  admin/owner can fetch the summary (HTTP 200).
  2.  member receives 403 (admin-only policy) — permission-helper level.
  3.  summary is workspace-scoped (other workspaces excluded).
  4.  days filter works (old events fall outside a short window).
  5.  counts by event name and route group.
  6.  unique user count.
  7.  recent events limited to 20 and ordered newest first.
  8.  metadata remains safe/allowlisted in recent events.
  9.  empty summary works (all zeros).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.security_beta_event import SecurityBetaEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_beta_event_service as svc
from app.services import workspace_permission_service as perms
from app.services import workspace_service


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M63.4", db=db
    )


def _new_user(db, label="member"):
    u = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name=label,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _ev(db, ws_id, name, *, user_id, created_at, metadata=None, page_path=None):
    e = SecurityBetaEvent(
        workspace_id=ws_id,
        user_id=user_id,
        event_name=name,
        event_category="security_beta",
        page_path=page_path,
        event_metadata=svc.sanitize_metadata(metadata),
        created_at=created_at,
    )
    db.add(e)
    db.commit()
    db.refresh(e)
    return e


def _cleanup(db, ws_id):
    db.query(SecurityBetaEvent).filter(
        SecurityBetaEvent.workspace_id == ws_id
    ).delete(synchronize_session=False)
    db.commit()


def _now():
    return datetime.now(timezone.utc)


# ── 1. Admin/owner can fetch (HTTP) ───────────────────────────────────────────


def test_admin_can_fetch_summary(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id,
        created_at=_now(), metadata={"route_group": "overview"})
    resp = client.get("/security/beta-events/summary?days=7")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_events"] == 1
    assert body["page_views"] == 1
    assert body["days"] == 7
    _cleanup(db_session, ws.id)


def test_invalid_days_rejected(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    assert client.get("/security/beta-events/summary?days=5").status_code == 422
    _cleanup(db_session, ws.id)


# ── 2. Member receives 403 (admin-only) ───────────────────────────────────────


def test_member_denied_admin_gate(db_session):
    owner = _new_user(db_session, "owner")
    member = _new_user(db_session, "member")
    ws = _ws(owner, db_session)
    db_session.add(WorkspaceMember(workspace_id=ws.id, user_id=member.id, role="member"))
    db_session.commit()
    try:
        with pytest.raises(Exception) as ei:
            perms.require_workspace_admin(ws.id, member.id, db_session)
        assert getattr(ei.value, "status_code", None) == 403
        assert perms.require_workspace_admin(ws.id, owner.id, db_session) is not None
    finally:
        db_session.delete(owner)
        db_session.delete(member)
        db_session.commit()


# ── 3. Workspace isolation ────────────────────────────────────────────────────


def test_summary_workspace_scoped(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    other = _new_user(db_session, "other")
    ows = _ws(other, db_session)
    _cleanup(db_session, ows.id)

    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now())
    _ev(db_session, ows.id, "security_page_viewed", user_id=other.id, created_at=_now())
    _ev(db_session, ows.id, "security_report_exported", user_id=other.id, created_at=_now())

    mine = svc.summarize(workspace_id=ws.id, days=7, db=db_session)
    assert mine["total_events"] == 1
    theirs = svc.summarize(workspace_id=ows.id, days=7, db=db_session)
    assert theirs["total_events"] == 2

    _cleanup(db_session, ws.id)
    _cleanup(db_session, ows.id)
    db_session.delete(other)
    db_session.commit()


# ── 4. Days filter ────────────────────────────────────────────────────────────


def test_days_filter(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now() - timedelta(days=2))
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now() - timedelta(days=40))
    assert svc.summarize(workspace_id=ws.id, days=7, db=db_session)["total_events"] == 1
    assert svc.summarize(workspace_id=ws.id, days=90, db=db_session)["total_events"] == 2
    _cleanup(db_session, ws.id)


# ── 5. Counts by name + route group ───────────────────────────────────────────


def test_counts_by_name_and_route_group(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now(), metadata={"route_group": "overview"})
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now(), metadata={"route_group": "overview"})
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now(), metadata={"route_group": "exposures"})
    _ev(db_session, ws.id, "security_report_exported", user_id=test_user.id, created_at=_now(), metadata={"action": "markdown_download"})

    s = svc.summarize(workspace_id=ws.id, days=7, db=db_session)
    assert s["events_by_name"]["security_page_viewed"] == 3
    assert s["events_by_name"]["security_report_exported"] == 1
    assert s["events_by_route_group"]["overview"] == 2
    assert s["events_by_route_group"]["exposures"] == 1
    assert s["report_exports"] == 1
    assert s["page_views"] == 3
    assert any(a["action"] == "markdown_download" for a in s["top_actions"])

    # route_group filter narrows the working set.
    only_overview = svc.summarize(workspace_id=ws.id, days=7, route_group="overview", db=db_session)
    assert only_overview["total_events"] == 2
    _cleanup(db_session, ws.id)


# ── 6. Unique users ───────────────────────────────────────────────────────────


def test_unique_users(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    other = _new_user(db_session, "other")
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now())
    _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id, created_at=_now())
    _ev(db_session, ws.id, "security_page_viewed", user_id=other.id, created_at=_now())
    _ev(db_session, ws.id, "security_page_viewed", user_id=None, created_at=_now())
    s = svc.summarize(workspace_id=ws.id, days=7, db=db_session)
    assert s["unique_users"] == 2  # null user_id not counted
    _cleanup(db_session, ws.id)
    db_session.delete(other)
    db_session.commit()


# ── 7. Recent events limited + newest first ───────────────────────────────────


def test_recent_events_limited_and_ordered(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    base = _now()
    for i in range(25):
        _ev(db_session, ws.id, "security_page_viewed", user_id=test_user.id,
            created_at=base - timedelta(minutes=i))
    s = svc.summarize(workspace_id=ws.id, days=7, db=db_session)
    assert len(s["recent_events"]) == 20
    times = [e["created_at"] for e in s["recent_events"]]
    assert times == sorted(times, reverse=True)  # newest first
    _cleanup(db_session, ws.id)


# ── 8. Metadata safe/allowlisted in recent events ─────────────────────────────


def test_recent_metadata_allowlisted(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    # Even if a forbidden key somehow lands in the row, summarize re-sanitizes.
    e = SecurityBetaEvent(
        workspace_id=ws.id, user_id=test_user.id, event_name="security_exposure_opened",
        event_category="security_beta", page_path="/security/exposures/[id]",
        event_metadata={"provider": "github", "evidence": "leak", "token": "x"},
        created_at=_now(),
    )
    db_session.add(e)
    db_session.commit()
    s = svc.summarize(workspace_id=ws.id, days=7, db=db_session)
    md = s["recent_events"][0]["metadata"]
    assert md == {"provider": "github"}
    assert "evidence" not in md and "token" not in md
    _cleanup(db_session, ws.id)


# ── 9. Empty summary ──────────────────────────────────────────────────────────


def test_empty_summary(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    s = svc.summarize(workspace_id=ws.id, days=7, db=db_session)
    assert s["total_events"] == 0
    assert s["unique_users"] == 0
    assert s["events_by_name"] == {}
    assert s["events_by_route_group"] == {}
    assert s["events_by_day"] == []
    assert s["recent_events"] == []
    assert s["report_exports"] == 0
    _cleanup(db_session, ws.id)
