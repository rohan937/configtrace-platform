"""M69.4E — GitHub code-scanning alert Incident Signals.

Normalized GitHub code-scanning activity (``security_activity_events``,
provider=github, source=code_scanning_alert — ingested in M69.4D) is grouped by
repository / alert number / rule / tool and surfaced as review-worthy Incident
Signals (``security_incident_signals``, signal_type="github_code_scanning_alert",
evidence_level="activity", confidence="medium").

These tests assert: open alert → signal; high/critical → high; reopened → signal;
fixed → low; dismissed → context signal; idempotency; workspace scoping; endpoint
admin gating; member cannot generate; privacy (no raw code/SARIF/locations/path/
URL in metadata); and claim discipline (no exploitation/compromise/breach/attack/
unauthorized-access claims).
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
from app.services import github_code_scanning_signal_service as sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "vulnerability exploitation confirmed", "compromise confirmed", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
REPO = "acme/app"

_OPEN = "github.code_scanning.alert.open"
_FIXED = "github.code_scanning.alert.fixed"
_DISMISSED = "github.code_scanning.alert.dismissed"
_REOPENED = "github.code_scanning.alert.reopened"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.4E", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _event(
    db, ws_id, *, number, event_type, state, rule_id="js/sql-injection",
    tool_name="CodeQL", security_severity_level="high", dismissed_reason=None,
    repo=REPO, when=None,
):
    """Insert a normalized code-scanning activity event (already sanitized)."""
    when = when or _now()
    ev = SecurityActivityEvent(
        workspace_id=ws_id,
        integration_id=None,
        provider="github",
        source="code_scanning_alert",
        provider_event_id=f"ghcs:{uuid.uuid4().hex[:40]}",
        event_type=event_type,
        actor_id="octocat" if state == "dismissed" else None,
        actor_type="user",
        resource_type="repository",
        resource_id=repo,
        source_ip_hash=None,
        occurred_at=when,
        event_metadata={
            "repository": repo,
            "repository_full_name": repo,
            "alert_number": number,
            "state": state,
            "rule_id": rule_id,
            "rule_name": "Database query built from user-controlled sources",
            "rule_description": "Database query built from user-controlled sources",
            "tool_name": tool_name,
            "severity": "error",
            "security_severity_level": security_severity_level,
            "dismissed_reason": dismissed_reason,
            "instances_count": 2,
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
        SecurityIncidentSignal.signal_type == "github_code_scanning_alert",
    ).all()


def _by_pattern(signals):
    return {s.signal_metadata.get("pattern"): s for s in signals}


def _gen(ws_id, db, **kw):
    return sig.generate_github_code_scanning_signals(workspace_id=ws_id, db=db, **kw)


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
           security_severity_level="medium")
    try:
        summary = _gen(ws.id, db_session)
        assert summary["provider"] == "github"
        assert summary["source"] == "code_scanning_alert"
        assert summary["signals_created"] == 1
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "open_alert" in sigs
        s = sigs["open_alert"]
        assert s.signal_type == "github_code_scanning_alert"
        assert s.evidence_level == "activity"
        assert s.confidence == "medium"
        assert s.severity == "medium"  # medium security severity
        assert s.signal_metadata.get("tool_name") == "CodeQL"
        assert s.signal_metadata.get("rule_id") == "js/sql-injection"
        assert s.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. high/critical severity → high-severity signal ──────────────────────────

def test_high_severity_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=2, event_type=_OPEN, state="open",
           security_severity_level="critical")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "high_severity" in sigs
        assert sigs["high_severity"].severity == "high"
        # open_alert is also high because the alert is critical.
        assert sigs["open_alert"].severity == "high"
        assert sigs["high_severity"].signal_metadata.get("security_severity_level") == "critical"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. reopened alert → signal ────────────────────────────────────────────────

def test_reopened_alert_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=3, event_type=_REOPENED, state="open",
           security_severity_level="high")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "reopened" in sigs
        assert sigs["reopened"].severity == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. fixed alert → low-severity context signal ──────────────────────────────

def test_fixed_alert_low_severity(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=4, event_type=_FIXED, state="fixed",
           security_severity_level="high")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "fixed" in sigs
        assert sigs["fixed"].severity == "low"
        # No open_alert signal — this alert is fixed.
        assert "open_alert" not in sigs
    finally:
        _cleanup(db_session, ws.id)


# ── 5. dismissed alert → context signal ───────────────────────────────────────

def test_dismissed_alert_context_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=5, event_type=_DISMISSED, state="dismissed",
           dismissed_reason="false positive", security_severity_level="medium")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "dismissed" in sigs
        assert sigs["dismissed"].severity == "low"
        assert sigs["dismissed"].signal_metadata.get("dismissed_reason") == "false positive"
    finally:
        _cleanup(db_session, ws.id)


def test_dismissed_wont_fix_high_severity_is_medium(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=6, event_type=_DISMISSED, state="dismissed",
           dismissed_reason="won't fix", security_severity_level="critical")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert sigs["dismissed"].severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. idempotency ────────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=7, event_type=_OPEN, state="open",
           security_severity_level="critical")
    try:
        s1 = _gen(ws.id, db_session)
        s2 = _gen(ws.id, db_session)
        # open_alert + high_severity = 2 signals.
        assert s1["signals_created"] == 2
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 2
        assert len(_signals(db_session, ws.id)) == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    _event(db_session, ws_a.id, number=8, event_type=_OPEN, state="open")
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
    _event(db_session, ws.id, number=9, event_type=_OPEN, state="open",
           security_severity_level="high")
    try:
        resp = client.post("/security/github-code-scanning/generate-signals")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "github"
        assert body["source"] == "code_scanning_alert"
        assert body["signals_created"] == 2  # open_alert + high_severity
    finally:
        _cleanup(db_session, ws.id)


# ── 9. privacy: no raw code / SARIF / locations / path / URL in metadata ──────

def test_no_raw_code_in_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=10, event_type=_OPEN, state="open",
           security_severity_level="high")
    try:
        _gen(ws.id, db_session)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({
                "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
            }, default=str)
            assert "ghp_" not in blob
            assert "token=" not in blob
            assert "SELECT" not in blob
            for bad in ("snippet", "code", "sarif", "locations", "location", "path",
                        "html_url", "url", "patch", "message", "full_description"):
                assert bad not in s.signal_metadata
            # safe aggregate is allowed.
            assert s.signal_metadata.get("instances_count") == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=11, event_type=_OPEN, state="open",
           security_severity_level="critical")
    _event(db_session, ws.id, number=12, event_type=_DISMISSED, state="dismissed",
           dismissed_reason="false positive")
    _event(db_session, ws.id, number=13, event_type=_FIXED, state="fixed")
    try:
        _gen(ws.id, db_session)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({
                "t": s.title, "s": s.summary, "m": s.signal_metadata,
            }, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 11. lookback window filters older events ──────────────────────────────────

def test_lookback_filters_old_events(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=14, event_type=_OPEN, state="open",
           when=_now() - timedelta(hours=200))
    try:
        summary = _gen(ws.id, db_session, lookback_hours=24)
        assert summary["events_scanned"] == 0
        assert summary["signals_created"] == 0
        assert _signals(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)
