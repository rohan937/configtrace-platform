"""M60.10 — security exposure lifecycle alert events.

Pins the event layer emitted by the evaluator on lifecycle transitions:

  1. a new active finding emits exactly one "opened" event
  2. repeated evaluation of the same active finding emits no opened event
  3. resolving an active finding emits exactly one "resolved" event
  4. re-evaluating with the state still gone emits no duplicate resolved event
  5. a fresh active finding after a prior resolved one emits "reopened"
  6. severity policy: critical/high are alertable; medium/low/info are not
  7. event payload is metadata-only and includes the required fields
  8. event-creation failure is non-fatal (finding still persists, sync safe)
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_exposure_events as events
from app.services import security_finding_evaluator as evaluator
from app.services import security_finding_service as svc


# ── builders ─────────────────────────────────────────────────────────────────


def _ws(user, db):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.10", db=db
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


def _res(db, integ, user):
    r = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id="acme/widgets",
        display_name="acme/widgets",
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


def _http_webhook():
    return {
        "record_id": "acme/widgets#webhook#1",
        "record_type": GITHUB_WEBHOOK,
        "name": "hook #1",
        "url": "http://example.com/github-webhook",
        "active": True,
    }


def _https_webhook():
    r = _http_webhook()
    r["url"] = "https://api.example.com/github-webhook"
    return r


def _evaluate(db, ws, integ, res, state):
    snap = _snap(db, res, integ, user=_user_of(integ, db), state=state)
    return evaluator.evaluate_security_findings_for_resource(
        db=db, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )


def _user_of(integ, db):
    return db.get(User, integ.user_id)


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


# ── 1–2. opened + dedupe ─────────────────────────────────────────────────────


def test_new_finding_emits_one_opened_event(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    summary = _evaluate(db_session, ws, integ, res, [_http_webhook()])
    evs = summary["events"]
    assert len(evs) == 1
    assert evs[0].event_type == events.EVENT_OPENED
    assert evs[0].severity == "critical"
    assert evs[0].finding_id
    assert evs[0].status == "active"
    _cleanup(db_session, ws.id)


def test_repeated_eval_emits_no_opened_event(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    _evaluate(db_session, ws, integ, res, [_http_webhook()])
    summary2 = _evaluate(db_session, ws, integ, res, [_http_webhook()])
    assert summary2["upserted"] == 1  # refreshed
    assert summary2["events"] == []  # no duplicate opened
    _cleanup(db_session, ws.id)


# ── 3–4. resolved + dedupe ───────────────────────────────────────────────────


def test_resolve_emits_one_resolved_event(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    _evaluate(db_session, ws, integ, res, [_http_webhook()])
    summary = _evaluate(db_session, ws, integ, res, [_https_webhook()])  # safe now
    evs = summary["events"]
    assert summary["resolved"] == 1
    assert len(evs) == 1
    assert evs[0].event_type == events.EVENT_RESOLVED
    assert evs[0].status == "resolved"
    assert evs[0].resolved_at is not None
    _cleanup(db_session, ws.id)


def test_already_resolved_emits_no_duplicate(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    _evaluate(db_session, ws, integ, res, [_http_webhook()])
    _evaluate(db_session, ws, integ, res, [_https_webhook()])  # resolves
    summary3 = _evaluate(db_session, ws, integ, res, [_https_webhook()])  # nothing active
    assert summary3["resolved"] == 0
    assert summary3["events"] == []
    _cleanup(db_session, ws.id)


# ── 5. reopened ──────────────────────────────────────────────────────────────


def test_reopened_event_after_prior_resolution(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    _evaluate(db_session, ws, integ, res, [_http_webhook()])  # opened
    _evaluate(db_session, ws, integ, res, [_https_webhook()])  # resolved
    summary = _evaluate(db_session, ws, integ, res, [_http_webhook()])  # risky again

    evs = summary["events"]
    assert len(evs) == 1
    assert evs[0].event_type == events.EVENT_REOPENED
    assert evs[0].status == "active"
    _cleanup(db_session, ws.id)


# ── 6. severity policy ───────────────────────────────────────────────────────


def test_severity_alertable_policy(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    def _ev(sev: str):
        f = svc.create_finding(
            db=db_session,
            workspace_id=ws.id,
            integration_id=integ.id,
            provider="github",
            finding_key=f"k_{sev}",
            severity=sev,
            title=f"{sev} finding",
            resource_id=res.id,
        )
        return events.event_from_finding(events.EVENT_OPENED, f)

    assert _ev("critical").is_alertable is True
    assert _ev("high").is_alertable is True
    assert _ev("medium").is_alertable is False
    assert _ev("low").is_alertable is False
    assert _ev("info").is_alertable is False
    _cleanup(db_session, ws.id)


# ── 7. payload privacy + required fields ─────────────────────────────────────


def test_payload_is_metadata_only_with_required_fields(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    summary = _evaluate(db_session, ws, integ, res, [_http_webhook()])
    ev = summary["events"][0]
    payload = ev.to_payload()

    required = {
        "event_type", "finding_id", "workspace_id", "integration_id",
        "resource_id", "provider", "severity", "title", "status",
        "finding_key", "first_detected_at", "last_seen_at", "resolved_at",
        "linked_change_id", "detail_path", "alertable",
    }
    assert required.issubset(payload.keys())
    assert payload["detail_path"] == f"/security/exposures/{ev.finding_id}"

    # Must NOT leak evidence/remediation or any secret-looking content.
    assert "evidence" not in payload
    assert "remediation" not in payload
    import re

    secret_re = re.compile(r"secret|token|password|api_?key|private_?key", re.I)
    for k in payload.keys():
        assert not secret_re.search(k)
    _cleanup(db_session, ws.id)


# ── 8. event failure is non-fatal ────────────────────────────────────────────


def test_event_failure_is_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    def _boom(*_a, **_k):
        raise RuntimeError("event build failed")

    monkeypatch.setattr(events, "event_from_finding", _boom)

    # Evaluation must still complete and persist the finding.
    summary = _evaluate(db_session, ws, integ, res, [_http_webhook()])
    assert summary["upserted"] == 1
    assert summary["events"] == []  # event failed → swallowed
    active = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.status == "active",
        )
        .count()
    )
    assert active == 1  # finding persisted despite event failure
    _cleanup(db_session, ws.id)
