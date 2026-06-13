"""M69.4H — GitHub Dependabot alert Incident Signals.

Normalized GitHub Dependabot activity (``security_activity_events``,
provider=github, source=dependabot_alert — ingested in M69.4G) is grouped by
repository / alert number / package / advisory and surfaced as review-worthy
Incident Signals (``security_incident_signals``,
signal_type="github_dependabot_alert", evidence_level="activity",
confidence="medium").

These tests assert: open alert → signal; high/critical → high; reopened → signal;
fixed → low; dismissed/auto-dismissed → context signal; idempotency; workspace
scoping; endpoint admin gating; member cannot generate; privacy (no raw manifest
path / file paths / advisory body / API response in metadata); and claim
discipline (no exploitation/compromise/breach/attack/unauthorized-access claims).
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
from app.services import github_dependabot_signal_service as sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "exploitation confirmed", "vulnerable dependency was exploited",
    "compromise confirmed", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
REPO = "acme/app"

_OPEN = "github.dependabot.alert.open"
_FIXED = "github.dependabot.alert.fixed"
_DISMISSED = "github.dependabot.alert.dismissed"
_AUTO_DISMISSED = "github.dependabot.alert.auto_dismissed"
_REOPENED = "github.dependabot.alert.reopened"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.4H", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _event(
    db, ws_id, *, number, event_type, state, package_name="lodash",
    ecosystem="npm", advisory_severity="high", dismissed_reason=None,
    cvss_score=7.2, repo=REPO, when=None,
):
    """Insert a normalized Dependabot activity event (already sanitized)."""
    when = when or _now()
    ev = SecurityActivityEvent(
        workspace_id=ws_id,
        integration_id=None,
        provider="github",
        source="dependabot_alert",
        provider_event_id=f"ghdep:{uuid.uuid4().hex[:40]}",
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
            "dependency_package_name": package_name,
            "dependency_ecosystem": ecosystem,
            "vulnerable_version_range": "< 4.17.21",
            "patched_versions": "4.17.21",
            "advisory_ghsa_id": "GHSA-jf85-cpcp-j695",
            "advisory_cve_id": "CVE-2021-23337",
            "advisory_severity": advisory_severity,
            "advisory_summary": "Command Injection in lodash",
            "cvss_score": cvss_score,
            "epss_percentage": 0.0042,
            "scope": "runtime",
            "dismissed_reason": dismissed_reason,
        },
        raw_ref=f"alert#{number}",
    )
    db.add(ev); db.commit(); db.refresh(ev)
    return ev


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "github",
        SecurityIncidentSignal.signal_type == "github_dependabot_alert",
    ).all()


def _by_pattern(signals):
    return {s.signal_metadata.get("pattern"): s for s in signals}


def _gen(ws_id, db, **kw):
    return sig.generate_github_dependabot_signals(workspace_id=ws_id, db=db, **kw)


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
           advisory_severity="medium", cvss_score=5.0)
    try:
        summary = _gen(ws.id, db_session)
        assert summary["provider"] == "github"
        assert summary["source"] == "dependabot_alert"
        assert summary["signals_created"] == 1
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "open_alert" in sigs
        s = sigs["open_alert"]
        assert s.signal_type == "github_dependabot_alert"
        assert s.evidence_level == "activity"
        assert s.confidence == "medium"
        assert s.severity == "medium"  # medium advisory + cvss 5.0
        assert s.signal_metadata.get("dependency_package_name") == "lodash"
        assert s.signal_metadata.get("advisory_ghsa_id") == "GHSA-jf85-cpcp-j695"
        assert s.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. high/critical advisory → high-severity signal ──────────────────────────

def test_high_severity_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=2, event_type=_OPEN, state="open",
           advisory_severity="critical", cvss_score=9.8)
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "high_severity" in sigs
        assert sigs["high_severity"].severity == "high"
        assert sigs["open_alert"].severity == "high"
        assert sigs["high_severity"].signal_metadata.get("advisory_severity") == "critical"
    finally:
        _cleanup(db_session, ws.id)


def test_high_severity_via_cvss_escalation(test_user, db_session):
    # Even when advisory_severity is medium, a CVSS >= 7.0 escalates to high.
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=20, event_type=_OPEN, state="open",
           advisory_severity="medium", cvss_score=7.5)
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "high_severity" in sigs
        assert sigs["open_alert"].severity == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. reopened alert → signal ────────────────────────────────────────────────

def test_reopened_alert_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=3, event_type=_REOPENED, state="open",
           advisory_severity="high")
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
           advisory_severity="high")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "fixed" in sigs
        assert sigs["fixed"].severity == "low"
        assert "open_alert" not in sigs
    finally:
        _cleanup(db_session, ws.id)


# ── 5. dismissed / auto-dismissed alert → context signal ──────────────────────

def test_dismissed_alert_context_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=5, event_type=_DISMISSED, state="dismissed",
           dismissed_reason="no_bandwidth", advisory_severity="medium")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "dismissed" in sigs
        assert sigs["dismissed"].severity == "low"
        assert sigs["dismissed"].signal_metadata.get("dismissed_reason") == "no_bandwidth"
    finally:
        _cleanup(db_session, ws.id)


def test_auto_dismissed_alert_context_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=6, event_type=_AUTO_DISMISSED, state="auto_dismissed",
           advisory_severity="low")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert "dismissed" in sigs
        assert sigs["dismissed"].severity == "low"
    finally:
        _cleanup(db_session, ws.id)


def test_dismissed_tolerable_risk_high_severity_is_medium(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=7, event_type=_DISMISSED, state="dismissed",
           dismissed_reason="tolerable_risk", advisory_severity="critical")
    try:
        _gen(ws.id, db_session)
        sigs = _by_pattern(_signals(db_session, ws.id))
        assert sigs["dismissed"].severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. idempotency ────────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=8, event_type=_OPEN, state="open",
           advisory_severity="critical")
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
           advisory_severity="high")
    try:
        resp = client.post("/security/github-dependabot/generate-signals")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "github"
        assert body["source"] == "dependabot_alert"
        assert body["signals_created"] == 2  # open_alert + high_severity
    finally:
        _cleanup(db_session, ws.id)


# ── 9. privacy: no raw manifest path / file paths / body / API response ───────

def test_no_raw_path_or_body_in_metadata(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=11, event_type=_OPEN, state="open",
           advisory_severity="high")
    try:
        _gen(ws.id, db_session)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({
                "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
            }, default=str)
            assert "ghp_" not in blob
            assert "token=" not in blob
            for bad in ("manifest_path", "path", "location", "description", "body",
                        "details", "html_url", "url", "patch", "dependency",
                        "security_advisory", "security_vulnerability"):
                assert bad not in s.signal_metadata
            # safe aggregate fields are allowed.
            assert s.signal_metadata.get("cvss_score") == 7.2
            assert s.signal_metadata.get("dependency_ecosystem") == "npm"
    finally:
        _cleanup(db_session, ws.id)


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session)
    _event(db_session, ws.id, number=12, event_type=_OPEN, state="open",
           advisory_severity="critical")
    _event(db_session, ws.id, number=13, event_type=_DISMISSED, state="dismissed",
           dismissed_reason="no_bandwidth")
    _event(db_session, ws.id, number=14, event_type=_FIXED, state="fixed")
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
    _event(db_session, ws.id, number=15, event_type=_OPEN, state="open",
           when=_now() - timedelta(hours=200))
    try:
        summary = _gen(ws.id, db_session, lookback_hours=24)
        assert summary["events_scanned"] == 0
        assert summary["signals_created"] == 0
        assert _signals(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)
