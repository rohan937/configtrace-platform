"""M60.7 — Security finding lifecycle correctness.

Hardens and pins the open → refresh → resolve → re-open lifecycle:

  1.  active refresh preserves first_detected_at
  2.  active refresh updates last_seen_at
  3.  active refresh updates evidence/remediation/title/severity
  4.  resolve sets status=resolved + resolved_at
  5.  resolve is idempotent (resolved_at preserved)
  6.  resolved finding does not block a new active finding (same logical key)
  7.  new active after resolved has a new id + new first_detected_at
  8.  evaluator resolves only the missing active findings for THAT resource
  9.  evaluator never overwrites/resolves accepted_risk or snoozed findings
  10. linked_change_id attaches when available, stays null otherwise, and is
      not cleared by a later refresh that lacks one
  11. evaluator is resilient: a raising rule does not abort the pass
  12. duplicate active finding is prevented (partial unique index) and upsert
      dedupes instead
"""

from __future__ import annotations

import time
import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.core.encryption import encrypt_credentials
from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services import security_finding_service as svc


# ── fixtures / builders ──────────────────────────────────────────────────────


def _ws(user, db):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.7", db=db
    )


def _integ(db, user, ws_id, provider="github"):
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    i = Integration(
        user_id=user.id,
        workspace_id=ws_id,
        provider=provider,
        display_name=provider,
        encrypted_credentials=ct,
        credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user, rid="acme/widgets"):
    r = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id=rid,
        display_name=rid,
        is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _snap(db, res, integ, user, state):
    s = Snapshot(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=user.id,
        state=state,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _http_webhook(hook_id=1):
    return {
        "record_id": f"acme/widgets#webhook#{hook_id}",
        "record_type": GITHUB_WEBHOOK,
        "name": f"hook #{hook_id}",
        "url": "http://example.com/github-webhook",
        "active": True,
    }


def _https_webhook(hook_id=1):
    r = _http_webhook(hook_id)
    r["url"] = "https://api.example.com/github-webhook"
    return r


def _active(db, ws_id, res_id):
    return (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws_id,
            SecurityFinding.resource_id == res_id,
            SecurityFinding.status == "active",
        )
        .all()
    )


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


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
        description="desc v1",
        evidence={"rule": "github_webhook_http", "url": "http://x"},
        remediation={"summary": "Fix it", "steps": ["a"]},
    )
    kw.update(over)
    return svc.upsert_active_finding(**kw)


# ── 1–3. Active refresh ──────────────────────────────────────────────────────


def test_refresh_preserves_first_detected_updates_last_seen(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    f1 = _make_finding(db_session, ws, integ, res)
    first_detected = f1.first_detected_at
    last_seen_1 = f1.last_seen_at
    fid = f1.id

    time.sleep(0.01)
    f2 = _make_finding(db_session, ws, integ, res)  # same logical key → refresh

    assert f2.id == fid
    assert f2.first_detected_at == first_detected  # (1) preserved
    assert f2.last_seen_at >= last_seen_1  # (2) bumped
    _cleanup(db_session, ws.id)


def test_refresh_updates_mutable_fields(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    _make_finding(db_session, ws, integ, res, severity="critical", title="old")
    f2 = _make_finding(
        db_session,
        ws,
        integ,
        res,
        severity="high",
        title="new title",
        description="desc v2",
        evidence={"rule": "github_webhook_http", "url": "http://y"},
        remediation={"summary": "Fix v2", "steps": ["b", "c"]},
    )
    assert f2.severity == "high"
    assert f2.title == "new title"
    assert f2.description == "desc v2"
    assert f2.evidence["url"] == "http://y"
    assert f2.remediation["summary"] == "Fix v2"
    _cleanup(db_session, ws.id)


def test_refresh_does_not_clobber_review_fields(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    f1 = _make_finding(db_session, ws, integ, res)
    # Simulate a future review workflow stamping attribution.
    f1.reviewed_by_user_id = test_user.id
    f1.reviewed_at = svc._utcnow()
    db_session.add(f1)
    db_session.commit()

    f2 = _make_finding(db_session, ws, integ, res)  # refresh
    assert f2.reviewed_by_user_id == test_user.id  # not clobbered
    assert f2.reviewed_at is not None
    _cleanup(db_session, ws.id)


# ── 4–5. Resolve ─────────────────────────────────────────────────────────────


def test_resolve_sets_status_and_timestamp(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    r = svc.resolve_finding(db=db_session, finding=f)
    assert r.status == "resolved"
    assert r.resolved_at is not None
    _cleanup(db_session, ws.id)


def test_resolve_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    f = _make_finding(db_session, ws, integ, res)

    r1 = svc.resolve_finding(db=db_session, finding=f)
    first_resolved_at = r1.resolved_at
    first_detected = r1.first_detected_at
    r2 = svc.resolve_finding(db=db_session, finding=r1)
    assert r2.id == r1.id
    assert r2.resolved_at == first_resolved_at  # not changed
    assert r2.first_detected_at == first_detected  # preserved
    assert r2.evidence is not None  # not cleared
    _cleanup(db_session, ws.id)


# ── 6–7. Re-open ─────────────────────────────────────────────────────────────


def test_resolved_does_not_block_new_active(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    f1 = _make_finding(db_session, ws, integ, res)
    svc.resolve_finding(db=db_session, finding=f1)

    # Same logical key reappears → a brand-new active row.
    f2 = _make_finding(db_session, ws, integ, res)
    assert f2.id != f1.id  # (7) new id
    assert f2.status == "active"
    assert f2.first_detected_at >= f1.first_detected_at  # (7) fresh detection

    rows = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.finding_key == f1.finding_key,
        )
        .all()
    )
    assert sorted(r.status for r in rows) == ["active", "resolved"]  # (6) history kept
    _cleanup(db_session, ws.id)


# ── 8. Evaluator resolve scoping ─────────────────────────────────────────────


def test_evaluator_resolves_only_that_resource(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res_a = _res(db_session, integ, test_user, "acme/a")
    res_b = _res(db_session, integ, test_user, "acme/b")

    # Both resources have an active HTTP-webhook finding.
    for res in (res_a, res_b):
        snap = _snap(db_session, res, integ, test_user, [_http_webhook()])
        evaluator.evaluate_security_findings_for_resource(
            db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
        )
    assert len(_active(db_session, ws.id, res_a.id)) == 1
    assert len(_active(db_session, ws.id, res_b.id)) == 1

    # Resource A fixed → only A's finding resolves; B untouched.
    snap_a = _snap(db_session, res_a, integ, test_user, [_https_webhook()])
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res_a, snapshot=snap_a
    )
    assert summary["resolved"] == 1
    assert _active(db_session, ws.id, res_a.id) == []
    assert len(_active(db_session, ws.id, res_b.id)) == 1  # B unaffected
    _cleanup(db_session, ws.id)


# ── 9. accepted_risk / snoozed safety ────────────────────────────────────────


@pytest.mark.parametrize("protected_status", ["accepted_risk", "snoozed"])
def test_evaluator_never_touches_protected_status(test_user, db_session, protected_status):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    # An existing finding the user moved to accepted_risk / snoozed.
    f = _make_finding(db_session, ws, integ, res)
    f.status = protected_status
    f.last_seen_at = svc._utcnow()
    db_session.add(f)
    db_session.commit()
    protected_last_seen = f.last_seen_at
    protected_id = f.id

    # (a) risky state still present → protected row untouched; a NEW active row
    # opens (upsert only matches active rows).
    snap = _snap(db_session, res, integ, test_user, [_http_webhook()])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    db_session.refresh(f)
    assert f.status == protected_status  # not overwritten
    assert f.last_seen_at == protected_last_seen  # not refreshed
    actives = _active(db_session, ws.id, res.id)
    assert len(actives) == 1 and actives[0].id != protected_id

    # (b) risky state gone → protected row still NOT resolved.
    snap2 = _snap(db_session, res, integ, test_user, [_https_webhook()])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap2
    )
    db_session.refresh(f)
    assert f.status == protected_status  # still not resolved
    _cleanup(db_session, ws.id)


# ── 10. linked_change_id ─────────────────────────────────────────────────────


def test_linked_change_attached_and_preserved(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    rec = _http_webhook(hook_id=3)
    snap = _snap(db_session, res, integ, test_user, [rec])

    change = Change(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=test_user.id,
        prev_snapshot_id=snap.id,
        new_snapshot_id=snap.id,
        change_type="modified",
        record_identifier=rec["record_id"],
        field_path="url",
        risk_level="critical",
        provider_metadata={"record_id": rec["record_id"]},
    )
    db_session.add(change)
    db_session.commit()
    db_session.refresh(change)

    # First pass with a matching change → link attached.
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res,
        snapshot=snap, linked_changes=[change],
    )
    f = _active(db_session, ws.id, res.id)[0]
    assert f.linked_change_id == change.id

    # Second pass with NO change → existing link must be preserved, not cleared.
    snap2 = _snap(db_session, res, integ, test_user, [rec])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res,
        snapshot=snap2, linked_changes=[],
    )
    f2 = _active(db_session, ws.id, res.id)[0]
    assert f2.id == f.id
    assert f2.linked_change_id == change.id  # preserved

    db_session.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws.id
    ).delete()
    db_session.commit()
    db_session.delete(change)
    db_session.commit()


def test_linked_change_null_when_unavailable(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    snap = _snap(db_session, res, integ, test_user, [_http_webhook()])
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res,
        snapshot=snap, linked_changes=[],
    )
    f = _active(db_session, ws.id, res.id)[0]
    assert f.linked_change_id is None
    _cleanup(db_session, ws.id)


# ── 11. evaluator resilience (non-fatal) ─────────────────────────────────────


def test_evaluate_record_resilient_to_raising_rule(monkeypatch):
    def _boom(_record):
        raise RuntimeError("rule blew up")

    # Inject a raising rule into the dispatch table; evaluate_record must
    # swallow the error and return [], never propagating it up to sync.
    monkeypatch.setitem(evaluator._PROVIDER_RULES, "github", [_boom])
    out = evaluator.evaluate_record(_http_webhook(), "github")
    assert out == []


# ── 12. duplicate-active prevention ──────────────────────────────────────────


def test_duplicate_active_prevented_and_upsert_dedupes(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    common = dict(
        db=db_session,
        workspace_id=ws.id,
        integration_id=integ.id,
        provider="github",
        finding_key="github_webhook_http:dup",
        severity="critical",
        title="dup",
        resource_id=res.id,
    )
    svc.create_finding(**common)
    # Second raw insert of the same active logical key → DB constraint.
    with pytest.raises(IntegrityError):
        svc.create_finding(**common)
    db_session.rollback()

    # upsert dedupes instead of erroring.
    again = svc.upsert_active_finding(**common)
    count = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.finding_key == "github_webhook_http:dup",
            SecurityFinding.status == "active",
        )
        .count()
    )
    assert count == 1
    assert again is not None
    _cleanup(db_session, ws.id)
