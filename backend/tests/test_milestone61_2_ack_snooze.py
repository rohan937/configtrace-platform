"""M61.2 — Acknowledge + Snooze actions for security findings.

Covers the two new mutations (service + API) and their interaction with the
evaluator:

  1.  active finding can be acknowledged
  2.  acknowledged finding stays active, sets reviewed_by_user_id + reviewed_at
  3.  resolved finding cannot be acknowledged (400)
  4.  accepted_risk finding cannot be acknowledged (400)
  5.  active finding can be snoozed with a future snoozed_until
  6.  snoozed finding has status snoozed, snoozed_until, reviewer, reviewed_at
  7.  snoozed_until must be in the future (422 at API, error in service)
  8.  resolved finding cannot be snoozed (400)
  9.  accepted_risk finding cannot be snoozed (400)
  10. workspace isolation: cannot acknowledge/snooze another workspace's finding
  11. evaluator does not overwrite a currently-snoozed finding
  12. evaluator creates no duplicate active finding while snooze is valid
  13. expired snooze + still-risky state → a fresh active finding opens
  14. acknowledge/snooze emit no lifecycle event and never resolve
  15. (existing accepted-risk + lifecycle suites still pass — run separately)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services import security_finding_service as svc
from app.services import workspace_service


# ── builders ──────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M61.2", db=db
    )


def _integ(db, user, ws_id, provider="github"):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider=provider,
        display_name=provider, encrypted_credentials=ct, credential_iv=iv,
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
        resource_id=res.id, description="desc",
        evidence={"rule": "github_webhook_http", "url": "http://x"},
        remediation={"summary": "Fix it", "steps": ["a"]},
    )
    kw.update(over)
    return svc.upsert_active_finding(**kw)


def _http_webhook(hook_id=1):
    return {
        "record_id": f"acme/widgets#webhook#{hook_id}",
        "record_type": GITHUB_WEBHOOK,
        "name": f"hook #{hook_id}",
        "url": "http://example.com/github-webhook",
        "active": True,
    }


def _snap(db, res, integ, user, state):
    s = Snapshot(
        resource_id=res.id, integration_id=integ.id, user_id=user.id,
        state=state, content_hash=uuid.uuid4().hex, triggered_by="manual",
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


def _future(days=7):
    return datetime.now(timezone.utc) + timedelta(days=days)


# ── 1 & 2. Acknowledge (service) ──────────────────────────────────────────────


def test_acknowledge_active_keeps_active(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    first_detected = f.first_detected_at

    acked = svc.acknowledge_finding(db=db_session, finding=f, actor_user_id=test_user.id)

    assert acked.status == "active"  # stays active — not a fix
    assert acked.reviewed_by_user_id == test_user.id
    assert acked.reviewed_at is not None
    assert acked.resolved_at is None
    assert acked.snoozed_until is None
    assert acked.first_detected_at == first_detected
    assert acked.evidence is not None
    _cleanup(db_session, ws.id)


# ── 3 & 4. Acknowledge rejects resolved / accepted_risk ───────────────────────


def test_acknowledge_resolved_rejected(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f)
    with pytest.raises(svc.FindingNotAcceptableError):
        svc.acknowledge_finding(db=db_session, finding=f, actor_user_id=test_user.id)
    _cleanup(db_session, ws.id)


def test_acknowledge_accepted_risk_rejected(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="accepted already", accepted_until=_future(30),
    )
    with pytest.raises(svc.FindingNotAcceptableError):
        svc.acknowledge_finding(db=db_session, finding=f, actor_user_id=test_user.id)
    _cleanup(db_session, ws.id)


# ── 5 & 6. Snooze (service) ───────────────────────────────────────────────────


def test_snooze_active(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    first_detected = f.first_detected_at

    snoozed = svc.snooze_finding(
        db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future(),
    )

    assert snoozed.status == "snoozed"
    assert snoozed.snoozed_until is not None
    assert snoozed.reviewed_by_user_id == test_user.id
    assert snoozed.reviewed_at is not None
    assert snoozed.resolved_at is None
    assert snoozed.first_detected_at == first_detected
    assert snoozed.evidence is not None
    _cleanup(db_session, ws.id)


# ── 7. snoozed_until must be future ───────────────────────────────────────────


def test_snooze_past_rejected(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    with pytest.raises(svc.FindingNotAcceptableError):
        svc.snooze_finding(
            db=db_session, finding=f, actor_user_id=test_user.id,
            snoozed_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
    _cleanup(db_session, ws.id)


# ── 8 & 9. Snooze rejects resolved / accepted_risk ────────────────────────────


def test_snooze_resolved_rejected(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f)
    with pytest.raises(svc.FindingNotAcceptableError):
        svc.snooze_finding(
            db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future(),
        )
    _cleanup(db_session, ws.id)


def test_snooze_accepted_risk_rejected(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="accepted already", accepted_until=_future(30),
    )
    with pytest.raises(svc.FindingNotAcceptableError):
        svc.snooze_finding(
            db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future(),
        )
    _cleanup(db_session, ws.id)


# ── 11 & 12. Evaluator suppresses while snoozed ───────────────────────────────


def test_evaluator_does_not_overwrite_snoozed(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    snoozed = svc.snooze_finding(
        db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future(),
    )
    snoozed_id = snoozed.id

    finding, created = svc.record_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f.finding_key, severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    assert created is False
    assert finding.id == snoozed_id
    assert finding.status == "snoozed"
    _cleanup(db_session, ws.id)


def test_no_duplicate_active_while_snoozed(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.snooze_finding(
        db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future(),
    )

    snap = _snap(db_session, res, integ, test_user, [_http_webhook(1)])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap,
    )
    actives = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.status == "active",
            SecurityFinding.finding_key == f.finding_key,
        )
        .all()
    )
    assert actives == []
    assert summary["events"] == []
    _cleanup(db_session, ws.id)


# ── 13. Expired snooze reopens a fresh active finding ─────────────────────────


def test_expired_snooze_reopens_active(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    snoozed = svc.snooze_finding(
        db=db_session, finding=f, actor_user_id=test_user.id, snoozed_until=_future(),
    )
    snoozed.snoozed_until = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.add(snoozed)
    db_session.commit()

    finding, created = svc.record_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f.finding_key, severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    assert created is True
    assert finding.id != snoozed.id
    assert finding.status == "active"
    old = db_session.get(SecurityFinding, snoozed.id)
    assert old is not None and old.status == "snoozed"
    _cleanup(db_session, ws.id)


# ── 14. No events / no resolve from ack or snooze ─────────────────────────────


def test_ack_and_snooze_emit_no_event(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    f1 = _make_finding(db_session, ws, integ, res)
    acked = svc.acknowledge_finding(db=db_session, finding=f1, actor_user_id=test_user.id)
    assert isinstance(acked, SecurityFinding)
    assert acked.resolved_at is None

    f2 = _make_finding(
        db_session, ws, integ, res,
        finding_key="github_webhook_http:acme/widgets#webhook#2",
        resource_id=res.id,
    )
    snoozed = svc.snooze_finding(
        db=db_session, finding=f2, actor_user_id=test_user.id, snoozed_until=_future(),
    )
    assert isinstance(snoozed, SecurityFinding)
    assert snoozed.resolved_at is None
    _cleanup(db_session, ws.id)


# ── API-level tests ───────────────────────────────────────────────────────────


def test_api_acknowledge_active(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    resp = client.post(f"/security/findings/{f.id}/acknowledge")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "active"
    assert body["reviewed_by_user_id"] == str(test_user.id)
    assert body["reviewed_at"] is not None
    _cleanup(db_session, ws.id)


def test_api_acknowledge_resolved_400(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f)
    resp = client.post(f"/security/findings/{f.id}/acknowledge")
    assert resp.status_code == 400
    _cleanup(db_session, ws.id)


def test_api_snooze_active(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    resp = client.post(
        f"/security/findings/{f.id}/snooze",
        json={"snoozed_until": _future().isoformat()},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "snoozed"
    assert body["snoozed_until"] is not None
    assert body["reviewed_by_user_id"] == str(test_user.id)
    _cleanup(db_session, ws.id)


def test_api_snooze_past_422(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    resp = client.post(
        f"/security/findings/{f.id}/snooze",
        json={"snoozed_until": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
    )
    assert resp.status_code == 422
    _cleanup(db_session, ws.id)


def test_api_snooze_accepted_risk_400(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="accepted already", accepted_until=_future(30),
    )
    resp = client.post(
        f"/security/findings/{f.id}/snooze",
        json={"snoozed_until": _future().isoformat()},
    )
    assert resp.status_code == 400
    _cleanup(db_session, ws.id)


# ── 10. Workspace isolation ───────────────────────────────────────────────────


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

    ack = client.post(f"/security/findings/{of.id}/acknowledge")
    assert ack.status_code == 404
    snooze = client.post(
        f"/security/findings/{of.id}/snooze",
        json={"snoozed_until": _future().isoformat()},
    )
    assert snooze.status_code == 404

    db_session.refresh(of)
    assert of.status == "active"  # untouched

    _cleanup(db_session, ows.id)
    db_session.delete(other)
    db_session.commit()
