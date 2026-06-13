"""M69.4G — GitHub Dependabot alert ingestion.

GitHub repository DEPENDABOT (vulnerable-dependency) ALERTS (the
``GET /repos/{owner}/{repo}/dependabot/alerts`` API) are normalized into the
shared ``security_activity_events`` spine (provider=github, source=
dependabot_alert) as GitHub's THIRD security-alert evidence plane (after
secret-scanning in M69.4A and code-scanning in M69.4D). These tests assert
state→event-type mapping, privacy (raw advisory body / manifest path / file path /
URL is NEVER stored), malformed-alert safety, fail-soft permission/feature
handling, idempotency, workspace scoping, endpoint admin gating, and claim
discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.github import GitHubConnector
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import github_dependabot_ingestion_service as dep
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "exploitation confirmed", "vulnerable dependency was exploited",
    "compromise confirmed", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
RAW_DESC = "lodash prior to 4.17.21 — SECRET ghp_RAWTOKENABC123 in advisory body"
MANIFEST = "services/internal/package-lock.json"
REPO = "acme/app"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert(number, state, *, dismissed_reason=None, ecosystem="npm",
           package_name="lodash", severity="high", with_epss=True):
    return {
        "number": number,
        "state": state,
        "dismissed_reason": dismissed_reason,
        "dismissed_at": _now_iso() if state == "dismissed" else None,
        "auto_dismissed_at": _now_iso() if state == "auto_dismissed" else None,
        "fixed_at": _now_iso() if state == "fixed" else None,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "url": f"https://api.github.com/repos/acme/app/dependabot/alerts/{number}",
        "html_url": f"https://github.com/acme/app/security/dependabot/{number}?token=ghp_RAWTOKENABC123",
        "dependency": {
            "package": {"ecosystem": ecosystem, "name": package_name},
            "manifest_path": MANIFEST,
            "scope": "runtime",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-jf85-cpcp-j695",
            "cve_id": "CVE-2021-23337",
            "summary": "Command Injection in lodash",
            "description": RAW_DESC,  # long body — MUST be dropped
            "severity": severity,
            "cvss": {"score": 7.2, "vector_string": "CVSS:3.1/AV:N/..."},
            "epss": {"percentage": 0.0042, "percentile": 0.5} if with_epss else None,
        },
        "security_vulnerability": {
            "package": {"ecosystem": ecosystem, "name": package_name},
            "severity": severity,
            "vulnerable_version_range": "< 4.17.21",
            "first_patched_version": {"identifier": "4.17.21"},
        },
        "dismissed_by": {"login": "octocat"} if state == "dismissed" else None,
    }


# ── connector mock ──────────────────────────────────────────────────────────

def _patch(monkeypatch, alerts=None, *, raise_exc=None):
    def _fake(self, credentials, *, per_page=100, max_alerts=1000, max_pages=10):
        if raise_exc is not None:
            raise raise_exc
        return alerts or []
    monkeypatch.setattr(GitHubConnector, "list_dependabot_alerts", _fake)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.4G", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _gh_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"github_token": "ghp_x", "repo_owner": "acme",
                                  "repo_name": "app"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="github",
        display_name="github", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "github",
        SecurityActivityEvent.source == "dependabot_alert",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return dep.ingest_github_dependabot_alerts(
        integration=integ, workspace_id=ws_id, db=db)


# ── 1. open alert normalizes ──────────────────────────────────────────────────

def test_open_alert_normalizes(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_alert(1, "open")])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "dependabot_alert"
        assert summary["events_inserted"] == 1
        row = _rows(db_session, ws.id)[0]
        assert row.event_type == "github.dependabot.alert.open"
        md = row.event_metadata
        assert md.get("dependency_package_name") == "lodash"
        assert md.get("dependency_ecosystem") == "npm"
        assert md.get("vulnerable_version_range") == "< 4.17.21"
        assert md.get("patched_versions") == "4.17.21"
        assert md.get("advisory_ghsa_id") == "GHSA-jf85-cpcp-j695"
        assert md.get("advisory_cve_id") == "CVE-2021-23337"
        assert md.get("advisory_severity") == "high"
        assert md.get("cvss_score") == 7.2
        assert md.get("epss_percentage") == 0.0042
        assert md.get("scope") == "runtime"
        assert md.get("repository") == REPO
    finally:
        _cleanup(db_session, ws.id)


# ── 2. state mapping (fixed / dismissed / reopened / auto_dismissed) ──────────

def test_state_mapping(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _alert(10, "fixed"),
        _alert(11, "dismissed", dismissed_reason="tolerable_risk"),
        _alert(12, "reopened"),
        _alert(13, "auto_dismissed"),
        _alert(14, "open"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "github.dependabot.alert.fixed",
            "github.dependabot.alert.dismissed",
            "github.dependabot.alert.reopened",
            "github.dependabot.alert.auto_dismissed",
            "github.dependabot.alert.open",
        } <= types
        dm = [r for r in _rows(db_session, ws.id)
              if r.event_type == "github.dependabot.alert.dismissed"][0]
        assert dm.event_metadata.get("dismissed_reason") == "tolerable_risk"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. privacy: raw advisory body / manifest path / URL never stored ──────────

def test_no_raw_body_or_path_or_url(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_alert(2, "open")])
    try:
        _ingest(integ, ws.id, db_session)
        row = _rows(db_session, ws.id)[0]
        blob = json.dumps({
            "event_type": row.event_type, "resource_id": row.resource_id,
            "metadata": row.event_metadata, "raw_ref": row.raw_ref,
        }, default=str)
        assert RAW_DESC not in blob
        assert "ghp_" not in blob          # no token text anywhere
        assert "token=" not in blob        # raw URL with token never stored
        assert MANIFEST not in blob        # no raw manifest path
        assert "package-lock.json" not in blob
        assert "advisory body" not in blob  # no raw description text
        # Safe fields ARE present.
        assert row.event_metadata.get("advisory_summary") == "Command Injection in lodash"
        # Forbidden raw keys never present.
        for bad in ("description", "manifest_path", "path", "location", "body",
                    "details", "html_url", "url", "cvss", "patch", "dependency",
                    "security_advisory", "security_vulnerability"):
            assert bad not in row.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 4. malformed alert skipped ────────────────────────────────────────────────

def test_malformed_alert_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, ["not-a-dict", None, {"state": "open"}, _alert(3, "open"), 42])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["succeeded"] is True
        assert summary["alerts_seen"] == 5
        assert summary["events_inserted"] == 1  # only the valid alert (#3)
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 5. permission/feature unavailable → fail soft ─────────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=AuthenticationError("denied", status_code=403))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert summary["events_inserted"] == 0


def test_feature_unavailable_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, raise_exc=ConnectorError("disabled", status_code=404))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []


# ── 6. idempotency ────────────────────────────────────────────────────────────

def test_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    fixed = _alert(4, "open")
    _patch(monkeypatch, [fixed])
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _gh_integ(db_session, test_user, ws_a.id)
    _patch(monkeypatch, [_alert(5, "open")])
    try:
        _ingest(integ_a, ws_a.id, db_session)
        assert len(_rows(db_session, ws_a.id)) == 1
        assert len(_rows(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 8. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_alert(6, "open")])
    try:
        _ingest(integ, ws.id, db_session)
        for r in _rows(db_session, ws.id):
            blob = json.dumps({"t": r.event_type, "m": r.event_metadata}, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 9. endpoint admin gating ──────────────────────────────────────────────────

def test_member_cannot_sync(test_user, db_session):
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


def test_owner_can_sync_via_endpoint(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_alert(7, "open")])
    try:
        resp = client.post("/security/github-dependabot/sync")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "github" and body["source"] == "dependabot_alert"
        assert body["events_inserted"] == 1
    finally:
        _cleanup(db_session, ws.id)
