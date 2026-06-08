"""M61.3 — Review notes + derived activity feed for security findings.

  1.  user can add a note to a finding in their workspace
  2.  note requires non-empty / min-length content (422)
  3.  note max length enforced (422)
  4.  notes list returns notes for the finding, oldest first
  5.  workspace isolation: cannot list/add notes for another workspace's finding
  6.  activity includes exposure_opened (from first_detected_at)
  7.  activity includes acknowledged when active + reviewed_at
  8.  activity includes snoozed when status=snoozed
  9.  activity includes accepted_risk when status=accepted_risk
  10. activity includes resolved when resolved_at present
  11. activity includes note_added for notes
  12. activity ordering is deterministic (newest first)
  13. (existing accept/ack/snooze suites still pass — run separately)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.security_finding_note import SecurityFindingNote
from app.models.user import User
from app.services import security_finding_service as svc
from app.services import security_finding_note_service as notesvc
from app.services import workspace_service


# ── builders ──────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M61.3", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="github", encrypted_credentials=ct, credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user, rid="acme/widgets"):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="github_repo", provider_resource_id=rid,
        display_name=rid, is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _make_finding(db, ws, integ, res, **over):
    kw = dict(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key="github_webhook_http:acme/widgets#webhook#1",
        severity="critical", title="GitHub webhook uses plain HTTP",
        resource_id=res.id,
    )
    kw.update(over)
    return svc.upsert_active_finding(**kw)


def _cleanup(db, ws_id):
    db.query(SecurityFindingNote).filter(SecurityFindingNote.workspace_id == ws_id).delete()
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


def _future(days=7):
    return datetime.now(timezone.utc) + timedelta(days=days)


def _types(items):
    return [it["type"] for it in items]


# ── 1 & 4. Add + list notes (service) ─────────────────────────────────────────


def test_add_and_list_notes(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    n1 = notesvc.create_note(
        finding_id=f.id, workspace_id=ws.id, author_user_id=test_user.id,
        body="Investigating with the platform team.", db=db_session,
    )
    n2 = notesvc.create_note(
        finding_id=f.id, workspace_id=ws.id, author_user_id=test_user.id,
        body="Owner handoff to security on-call.", db=db_session,
    )
    assert n1.author_user_id == test_user.id
    assert n1.workspace_id == ws.id

    listed = notesvc.list_notes(finding_id=f.id, db=db_session)
    assert [n.id for n in listed] == [n1.id, n2.id]  # oldest first
    _cleanup(db_session, ws.id)


# ── 6-11. Activity feed inclusion ─────────────────────────────────────────────


def test_activity_opened_and_note(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    notesvc.create_note(
        finding_id=f.id, workspace_id=ws.id, author_user_id=test_user.id,
        body="First triage note.", db=db_session,
    )
    notes = notesvc.list_notes(finding_id=f.id, db=db_session)
    items = notesvc.build_activity(finding=f, notes=notes)
    assert "exposure_opened" in _types(items)
    assert "note_added" in _types(items)
    _cleanup(db_session, ws.id)


def test_activity_acknowledged(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.acknowledge_finding(db=db_session, finding=f, actor_user_id=test_user.id)
    items = notesvc.build_activity(finding=f, notes=[])
    assert "acknowledged" in _types(items)
    ack = next(it for it in items if it["type"] == "acknowledged")
    assert ack["actor_user_id"] == str(test_user.id)
    _cleanup(db_session, ws.id)


def test_activity_snoozed(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.snooze_finding(db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future())
    items = notesvc.build_activity(finding=f, notes=[])
    types = _types(items)
    assert "snoozed" in types
    assert "acknowledged" not in types  # snoozed status, not active
    snz = next(it for it in items if it["type"] == "snoozed")
    assert snz["metadata"]["snoozed_until"] is not None
    _cleanup(db_session, ws.id)


def test_activity_accepted_risk(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="Carrying until Q3 migration.", accepted_until=_future(30),
    )
    items = notesvc.build_activity(finding=f, notes=[])
    assert "accepted_risk" in _types(items)
    ar = next(it for it in items if it["type"] == "accepted_risk")
    assert ar["metadata"]["accepted_until"] is not None
    assert ar["metadata"]["reason"] == "Carrying until Q3 migration."
    _cleanup(db_session, ws.id)


def test_activity_resolved(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f)
    items = notesvc.build_activity(finding=f, notes=[])
    assert "resolved" in _types(items)
    _cleanup(db_session, ws.id)


def test_activity_ordering_deterministic(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    notesvc.create_note(
        finding_id=f.id, workspace_id=ws.id, author_user_id=test_user.id,
        body="note A", db=db_session,
    )
    notes = notesvc.list_notes(finding_id=f.id, db=db_session)
    items1 = notesvc.build_activity(finding=f, notes=notes)
    items2 = notesvc.build_activity(finding=f, notes=notes)
    assert items1 == items2  # deterministic
    # Newest-first: timestamps are non-increasing.
    ts = [it["timestamp"] for it in items1 if it["timestamp"]]
    assert ts == sorted(ts, reverse=True)
    _cleanup(db_session, ws.id)


# ── API-level: notes CRUD, validation, workspace isolation ────────────────────


def test_api_add_and_list_notes(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    post = client.post(
        f"/security/findings/{f.id}/notes",
        json={"body": "Following up with the owner."},
    )
    assert post.status_code == 201
    assert post.json()["body"] == "Following up with the owner."
    assert post.json()["author_user_id"] == str(test_user.id)

    lst = client.get(f"/security/findings/{f.id}/notes")
    assert lst.status_code == 200
    assert lst.json()["total"] == 1
    _cleanup(db_session, ws.id)


def test_api_note_validation(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    assert client.post(f"/security/findings/{f.id}/notes", json={"body": "   "}).status_code == 422
    assert client.post(f"/security/findings/{f.id}/notes", json={"body": "a"}).status_code == 422
    assert client.post(
        f"/security/findings/{f.id}/notes", json={"body": "x" * 2001}
    ).status_code == 422
    _cleanup(db_session, ws.id)


def test_api_activity_feed(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.acknowledge_finding(db=db_session, finding=f, actor_user_id=test_user.id)
    client.post(f"/security/findings/{f.id}/notes", json={"body": "context note"})

    resp = client.get(f"/security/findings/{f.id}/activity")
    assert resp.status_code == 200
    types = [it["type"] for it in resp.json()["items"]]
    assert "exposure_opened" in types
    assert "acknowledged" in types
    assert "note_added" in types
    _cleanup(db_session, ws.id)


def test_api_workspace_isolation(client, test_user, db_session):
    other = User(
        clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
        email=f"other_{uuid.uuid4().hex[:8]}@configtrace.test",
        display_name="Other User",
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)

    ows = _ws(other, db_session)
    ointeg = _integ(db_session, other, ows.id)
    ores = _res(db_session, ointeg, other, rid="other/repo")
    of = _make_finding(
        db_session, ows, ointeg, ores,
        finding_key="github_webhook_http:other/repo#webhook#1",
    )

    assert client.get(f"/security/findings/{of.id}/notes").status_code == 404
    assert client.post(
        f"/security/findings/{of.id}/notes", json={"body": "should not work"}
    ).status_code == 404
    assert client.get(f"/security/findings/{of.id}/activity").status_code == 404

    # No note leaked into the other workspace.
    assert notesvc.list_notes(finding_id=of.id, db=db_session) == []

    _cleanup(db_session, ows.id)
    db_session.delete(other)
    db_session.commit()
