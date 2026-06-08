"""M61.1 — Accepted Risk workflow for security findings.

Covers the new accept-risk mutation (service + API) and its interaction with
the evaluator:

  1.  active finding can be accepted with reason + future accepted_until
  2.  accepted finding carries status/accepted_until/reviewer/reviewed_at/reason
  3.  a resolved finding cannot be accepted (400)
  4.  accepted_until must be in the future (422)
  5.  reason is required / too-short (422)
  6.  workspace isolation: cannot accept another workspace's finding (404)
  7.  evaluator does not overwrite an accepted_risk finding
  8.  evaluator does not create a duplicate active finding while acceptance valid
  9.  expired acceptance + still-risky state → a fresh active finding opens
  10. accepting risk does not emit a lifecycle event / does not resolve
  11. re-accepting an accepted_risk finding updates reason + expiry
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
        user_id=user.id, user_display_name=user.display_name or "M61.1", db=db
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
        db=db,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http:acme/widgets#webhook#1",
        severity="critical",
        title="GitHub webhook uses plain HTTP",
        resource_id=res.id,
        description="desc",
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


def _future(days=30):
    return datetime.now(timezone.utc) + timedelta(days=days)


# ── 1 & 2. Accept an active finding (service) ─────────────────────────────────


def test_accept_active_finding(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    first_detected = f.first_detected_at
    until = _future()

    accepted = svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="Carrying this until the Q3 migration ships.", accepted_until=until,
    )

    assert accepted.status == "accepted_risk"
    assert accepted.accepted_until is not None
    assert accepted.reviewed_by_user_id == test_user.id
    assert accepted.reviewed_at is not None
    assert accepted.acceptance_reason == "Carrying this until the Q3 migration ships."
    # Does not resolve and preserves history.
    assert accepted.resolved_at is None
    assert accepted.first_detected_at == first_detected
    assert accepted.evidence is not None
    _cleanup(db_session, ws.id)


# ── 3. Resolved finding cannot be accepted ────────────────────────────────────


def test_resolved_cannot_be_accepted(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f)

    with pytest.raises(svc.FindingNotAcceptableError):
        svc.accept_finding_risk(
            db=db_session, finding=f, actor_user_id=test_user.id,
            reason="too late", accepted_until=_future(),
        )
    _cleanup(db_session, ws.id)


# ── 4 & 5. Validation (service-level defence in depth) ────────────────────────


def test_accepted_until_must_be_future(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    with pytest.raises(svc.FindingNotAcceptableError):
        svc.accept_finding_risk(
            db=db_session, finding=f, actor_user_id=test_user.id,
            reason="valid reason here",
            accepted_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
    _cleanup(db_session, ws.id)


def test_reason_required(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    with pytest.raises(svc.FindingNotAcceptableError):
        svc.accept_finding_risk(
            db=db_session, finding=f, actor_user_id=test_user.id,
            reason="  ", accepted_until=_future(),
        )
    _cleanup(db_session, ws.id)


# ── 7. Evaluator does not overwrite an accepted_risk finding ──────────────────


def test_evaluator_does_not_overwrite_accepted(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    accepted = svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="known and accepted", accepted_until=_future(),
    )
    accepted_id = accepted.id

    # Re-record the same logical key (risky state still present).
    finding, created = svc.record_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id,
        provider="github", finding_key=f.finding_key, severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    assert created is False
    assert finding.id == accepted_id
    assert finding.status == "accepted_risk"  # untouched
    _cleanup(db_session, ws.id)


# ── 8. No duplicate active finding while acceptance is valid ──────────────────


def test_no_duplicate_active_while_accepted(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="accepted for now", accepted_until=_future(),
    )

    # A full evaluator pass over a snapshot that still shows the risky state.
    snap = _snap(db_session, res, integ, test_user, [_http_webhook(1)])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res,
        snapshot=snap,
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
    assert actives == []  # suppressed — no active duplicate
    assert summary["events"] == []  # and no opened/reopened event emitted
    _cleanup(db_session, ws.id)


# ── 9. Expired acceptance + still-risky → a fresh active finding opens ────────


def test_expired_acceptance_reopens_active(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    accepted = svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="accepted briefly", accepted_until=_future(),
    )
    # Force the acceptance to be in the past.
    accepted.accepted_until = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.add(accepted)
    db_session.commit()

    finding, created = svc.record_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=integ.id,
        provider="github", finding_key=f.finding_key, severity="critical",
        title="GitHub webhook uses plain HTTP", resource_id=res.id,
    )
    assert created is True  # acceptance expired → new active finding
    assert finding.id != accepted.id
    assert finding.status == "active"
    # The expired accepted_risk row remains as history.
    old = db_session.get(SecurityFinding, accepted.id)
    assert old is not None and old.status == "accepted_risk"
    _cleanup(db_session, ws.id)


# ── 10. Accepting risk emits no lifecycle event and does not resolve ──────────


def test_accept_emits_no_event(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    accepted = svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="no alert please", accepted_until=_future(),
    )
    # accept_finding_risk returns the finding, not an event — and never resolves.
    assert isinstance(accepted, SecurityFinding)
    assert accepted.resolved_at is None
    assert accepted.status == "accepted_risk"
    _cleanup(db_session, ws.id)


# ── 11. Re-accepting updates reason + expiry, same row ────────────────────────


def test_reaccept_updates_reason_and_expiry(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    first = svc.accept_finding_risk(
        db=db_session, finding=f, actor_user_id=test_user.id,
        reason="first reason", accepted_until=_future(10),
    )
    fid = first.id
    # Capture the original expiry as a value BEFORE re-accepting mutates the row.
    original_until = first.accepted_until
    original_until = original_until if original_until.tzinfo else original_until.replace(tzinfo=timezone.utc)

    second = svc.accept_finding_risk(
        db=db_session, finding=first, actor_user_id=test_user.id,
        reason="updated reason", accepted_until=_future(60),
    )
    new_until = second.accepted_until if second.accepted_until.tzinfo else second.accepted_until.replace(tzinfo=timezone.utc)
    assert second.id == fid  # same row, not a new exposure
    assert second.acceptance_reason == "updated reason"
    assert new_until > original_until
    _cleanup(db_session, ws.id)


# ── API-level tests (auth + status codes via the router) ──────────────────────


def test_api_accept_active(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    resp = client.post(
        f"/security/findings/{f.id}/accept-risk",
        json={
            "reason": "Tracked in JIRA-123; carrying until next sprint.",
            "accepted_until": _future().isoformat(),
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "accepted_risk"
    assert body["acceptance_reason"].startswith("Tracked in JIRA-123")
    assert body["accepted_until"] is not None
    assert body["reviewed_by_user_id"] == str(test_user.id)
    _cleanup(db_session, ws.id)


def test_api_resolved_returns_400(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f)

    resp = client.post(
        f"/security/findings/{f.id}/accept-risk",
        json={"reason": "too late now", "accepted_until": _future().isoformat()},
    )
    assert resp.status_code == 400
    _cleanup(db_session, ws.id)


def test_api_past_until_returns_422(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    resp = client.post(
        f"/security/findings/{f.id}/accept-risk",
        json={
            "reason": "valid reason text",
            "accepted_until": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 422
    _cleanup(db_session, ws.id)


def test_api_missing_reason_returns_422(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    resp = client.post(
        f"/security/findings/{f.id}/accept-risk",
        json={"accepted_until": _future().isoformat()},
    )
    assert resp.status_code == 422
    # Short reason also rejected.
    resp2 = client.post(
        f"/security/findings/{f.id}/accept-risk",
        json={"reason": "no", "accepted_until": _future().isoformat()},
    )
    assert resp2.status_code == 422
    _cleanup(db_session, ws.id)


def test_api_workspace_isolation_returns_404(client, test_user, db_session):
    # A finding in a DIFFERENT user's workspace must be invisible (404).
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

    resp = client.post(
        f"/security/findings/{of.id}/accept-risk",
        json={"reason": "should not work", "accepted_until": _future().isoformat()},
    )
    assert resp.status_code == 404

    # And the other workspace's finding is untouched.
    db_session.refresh(of)
    assert of.status == "active"

    _cleanup(db_session, ows.id)
    db_session.delete(other)
    db_session.commit()
