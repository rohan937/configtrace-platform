"""M69.4B — GitHub secret-scanning alert Incident Signals.

Normalized GitHub secret-scanning activity (``security_activity_events``,
provider=github, source=secret_scanning_alert — ingested in M69.4A) is grouped by
repository / alert number / secret type and surfaced as review-worthy Incident
Signals (``security_incident_signals``, signal_type="github_secret_scanning_alert",
evidence_level="activity", confidence="medium").

These tests assert: open alert → signal; publicly-leaked → high; active validity →
high; resolved/revoked → lower severity; false-positive/used-in-tests → low context
signal; idempotency; workspace scoping; endpoint admin gating; member cannot
generate; privacy (no raw secret/token/URL/locations in stored metadata); and claim
discipline (no leakage/compromise/breach/attack/unauthorized-access claims).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import github_secret_scanning_signal_service as sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "secret leakage confirmed", "compromise confirmed", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
RAW_SECRET = "ghp_SUPERSECRETTOKENVALUE1234567890"
RAW_URL = "https://github.com/acme/app/security/secret-scanning/1?token=" + RAW_SECRET
REPO = "acme/app"

_OPEN = "github.secret_scanning.alert.open"
_RESOLVED = "github.secret_scanning.alert.resolved"
_REVOKED = "github.secret_scanning.alert.revoked"
_FALSE_POSITIVE = "github.secret_scanning.alert.false_positive"
_USED_IN_TESTS = "github.secret_scanning.alert.used_in_tests"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.4B", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _event(
    db, ws_id, *, number, event_type, state, resolution=None,
    secret_type="github_personal_access_token", publicly_leaked=False,
    validity="active", repo=REPO, when=None,
):
    """Insert a normalized secret-scanning activity event (already sanitized)."""
    when = when or _now()
    ev = SecurityActivityEvent(
        workspace_id=ws_id,
        integration_id=None,
        provider="github",
        source="secret_scanning_alert",
        provider_event_id=f"ghss:{uuid.uuid4().hex[:40]}",
        event_type=event_type,
        actor_id="octocat" if state == "resolved" else None,
        actor_type="user",
        resource_type="secret_scanning_alert",
        resource_id=repo,
        source_ip_hash=None,
        occurred_at=when,
        event_metadata={
            "repository": repo,
            "repository_full_name": repo,
            "alert_number": number,
            "state": state,
            "resolution": resolution,
            "secret_type": secret_type,
            "secret_type_display_name": "GitHub Personal Access Token",
            "validity": validity,
            "publicly_leaked": publicly_leaked,
            "location_count": 2,
            "alert_url_hash": "deadbeef" * 4,
        },
        raw_ref=f"alert#{number}",
    )
    db.add(ev); db.commit(); db.refresh(ev)
    return ev


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "github",
        SecurityIncidentSignal.signal_type == "github_secret_scanning_alert",
    ).all()


def _by_pattern(signals):
    return {s.signal_metadata.get("pattern"): s for s in signals}


def _gen(ws_id, db, **kw):
    return sig.generate_github_secret_scanning_signals(workspace_id=ws_id, db=db, **kw)


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. open alert creates a signal ────────────────────────────────────────────

def test_open_alert_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=1, event_type=_OPEN, state="open",
           publicly_leaked=False, validity="inactive")
    try:
        summary = _gen(ws.id, db_session)
        assert summary["provider"] == "github"
        assert summary["source"] == "secret_scanning_alert"
        assert summary["signals_created"] == 1
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "open_alert" in sigs
        s = sigs["open_alert"]
        assert s.signal_type == "github_secret_scanning_alert"
        assert s.evidence_level == "activity"
        assert s.confidence == "medium"
        assert s.severity == "medium"  # not public, not active
        assert s.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. publicly-leaked → high-severity signal ─────────────────────────────────

def test_publicly_leaked_high_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=2, event_type=_OPEN, state="open",
           publicly_leaked=True, validity="inactive")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "publicly_leaked" in sigs
        assert sigs["publicly_leaked"].severity == "high"
        # open_alert also high because publicly leaked.
        assert sigs["open_alert"].severity == "high"
        assert sigs["publicly_leaked"].signal_metadata.get("publicly_leaked") is True
    finally:
        _cleanup(db_session, ws.id)


# ── 3. active validity → high-severity signal ─────────────────────────────────

def test_active_validity_high_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=3, event_type=_OPEN, state="open",
           publicly_leaked=False, validity="active")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "active_validity" in sigs
        assert sigs["active_validity"].severity == "high"
        assert sigs["open_alert"].severity == "high"  # active ⇒ high
        assert sigs["active_validity"].signal_metadata.get("validity") == "active"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. resolved/revoked → lower-severity signal ───────────────────────────────

def test_resolved_or_revoked_lower_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=4, event_type=_RESOLVED, state="resolved",
           resolution="resolved")
    _event(db_session, ws.id, number=5, event_type=_REVOKED, state="resolved",
           resolution="revoked")
    try:
        _gen(ws.id, db_session)
        sigs = _signals(db_session, ws.id)
        rr = [s for s in sigs if s.signal_metadata.get("pattern") == "resolved_or_revoked"]
        assert len(rr) == 2
        sevs = {s.signal_metadata.get("resolution"): s.severity for s in rr}
        assert sevs.get("resolved") == "low"
        assert sevs.get("revoked") == "medium"
        # No open_alert signal — these alerts are resolved.
        assert all(s.signal_metadata.get("pattern") != "open_alert" for s in sigs)
    finally:
        _cleanup(db_session, ws.id)


# ── 5. false-positive / used-in-tests → low context signal ────────────────────

def test_non_actionable_low_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=6, event_type=_FALSE_POSITIVE, state="resolved",
           resolution="false_positive")
    _event(db_session, ws.id, number=7, event_type=_USED_IN_TESTS, state="resolved",
           resolution="used_in_tests")
    try:
        _gen(ws.id, db_session)
        sigs = _signals(db_session, ws.id)
        na = [s for s in sigs if s.signal_metadata.get("pattern") == "non_actionable"]
        assert len(na) == 2
        assert all(s.severity == "low" for s in na)
    finally:
        _cleanup(db_session, ws.id)


# ── 6. idempotency ────────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=8, event_type=_OPEN, state="open",
           publicly_leaked=True, validity="active")
    try:
        s1 = _gen(ws.id, db_session)
        s2 = _gen(ws.id, db_session)
        # open_alert + publicly_leaked + active_validity = 3 signals.
        assert s1["signals_created"] == 3
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 3
        assert len(_signals(db_session, ws.id)) == 3
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    _event(db_session, ws_a.id, number=9, event_type=_OPEN, state="open")
    try:
        _gen(ws_a.id, db_session)
        assert len(_signals(db_session, ws_a.id)) >= 1
        assert len(_signals(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 8. endpoint requires admin/owner; member cannot generate ──────────────────

def test_member_cannot_generate(test_user, db_session):
    owner = _new_user(db_session, "owner")
    ws = _ws(owner, db_session)
    m = WorkspaceMember(workspace_id=ws.id, user_id=test_user.id, role="member")
    db_session.add(m); db_session.commit()
    try:
        with pytest.raises(HTTPException) as exc:
            workspace_permission_service.require_workspace_admin(ws.id, test_user.id, db_session)
        assert exc.value.status_code == 403
    finally:
        try:
            db_session.delete(owner); db_session.commit()
        except Exception:
            db_session.rollback()


def test_owner_can_generate_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=10, event_type=_OPEN, state="open",
           publicly_leaked=True, validity="active")
    try:
        resp = client.post("/security/github-secret-scanning/generate-signals")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "github"
        assert body["source"] == "secret_scanning_alert"
        assert body["signals_created"] == 3
    finally:
        _cleanup(db_session, ws.id)


# ── 9. privacy: no raw secret / token / URL / locations in metadata ───────────

def test_no_raw_secret_in_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=11, event_type=_OPEN, state="open",
           publicly_leaked=True, validity="active")
    try:
        _gen(ws.id, db_session)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({
                "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
            }, default=str)
            assert RAW_SECRET not in blob
            assert "ghp_" not in blob
            assert "token=" not in blob
            assert "html_url" not in s.signal_metadata
            assert "locations_url" not in s.signal_metadata
            assert "secret" not in s.signal_metadata  # no raw "secret" key
            # safe aggregate is allowed.
            assert s.signal_metadata.get("location_count") == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=12, event_type=_OPEN, state="open",
           publicly_leaked=True, validity="active")
    _event(db_session, ws.id, number=13, event_type=_REVOKED, state="resolved",
           resolution="revoked")
    _event(db_session, ws.id, number=14, event_type=_FALSE_POSITIVE, state="resolved",
           resolution="false_positive")
    try:
        _gen(ws.id, db_session)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({
                "t": s.title, "s": s.summary, "m": s.signal_metadata,
            }, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            # Positive calibration: summary disclaims confirmation.
            assert "does not confirm" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 11. lookback window filters older events ──────────────────────────────────

def test_lookback_filters_old_events(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=15, event_type=_OPEN, state="open",
           when=_now() - timedelta(hours=200))
    try:
        summary = _gen(ws.id, db_session, lookback_hours=24)
        assert summary["events_scanned"] == 0
        assert summary["signals_created"] == 0
        assert _signals(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)
