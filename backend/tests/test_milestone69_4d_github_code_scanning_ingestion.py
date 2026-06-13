"""M69.4D — GitHub code-scanning alert ingestion.

GitHub repository code-scanning (SAST) ALERTS (the
``GET /repos/{owner}/{repo}/code-scanning/alerts`` API) are normalized into the
shared ``security_activity_events`` spine (provider=github, source=
code_scanning_alert) as GitHub's SECOND security-alert evidence plane (after
secret-scanning in M69.4A). These tests assert state→event-type mapping, privacy
(raw SARIF / code snippet / file content / locations / URL is NEVER stored),
malformed-alert safety, fail-soft permission/feature handling, idempotency,
workspace scoping, endpoint admin gating, and claim discipline.
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
from app.services import github_code_scanning_ingestion_service as cs
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "vulnerability exploitation confirmed", "compromise confirmed", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
RAW_SNIPPET = "SELECT * FROM users WHERE id = req.params.id  # ghp_RAWTOKENABC123"
REPO = "acme/app"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert(number, state, *, dismissed_reason=None, rule_id="js/sql-injection",
           security_severity_level="high", with_instances=True):
    return {
        "number": number,
        "state": state,
        "dismissed_reason": dismissed_reason,
        "dismissed_at": _now_iso() if state == "dismissed" else None,
        "fixed_at": _now_iso() if state == "fixed" else None,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "html_url": f"https://github.com/acme/app/security/code-scanning/{number}?token=ghp_RAWTOKENABC123",
        "url": f"https://api.github.com/repos/acme/app/code-scanning/alerts/{number}",
        "rule": {
            "id": rule_id,
            "name": "Database query built from user-controlled sources",
            "severity": "error",
            "security_severity_level": security_severity_level,
            "description": "Database query built from user-controlled sources",
            "full_description": "A very long description that should not be stored verbatim... " * 5,
            "tags": ["security", "external/cwe/cwe-089"],
        },
        "tool": {"name": "CodeQL", "version": "2.15.0", "guid": None},
        # most_recent_instance carries raw code/location — MUST be dropped wholesale.
        "most_recent_instance": {
            "ref": "refs/heads/main",
            "state": state,
            "location": {"path": "src/db/query.js", "start_line": 42, "end_line": 42},
            "message": {"text": RAW_SNIPPET},
        },
        "instances": ([{"ref": "refs/heads/main"}, {"ref": "refs/heads/dev"}]
                      if with_instances else None),
        "dismissed_by": {"login": "octocat"} if state == "dismissed" else None,
    }


# ── connector mock ──────────────────────────────────────────────────────────

def _patch(monkeypatch, alerts=None, *, raise_exc=None):
    def _fake(self, credentials, *, per_page=100, max_alerts=1000, max_pages=10):
        if raise_exc is not None:
            raise raise_exc
        return alerts or []
    monkeypatch.setattr(GitHubConnector, "list_code_scanning_alerts", _fake)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.4D", db=db)


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
        SecurityActivityEvent.source == "code_scanning_alert",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return cs.ingest_github_code_scanning_alerts(
        integration=integ, workspace_id=ws_id, db=db)


# ── 1. open alert normalizes ──────────────────────────────────────────────────

def test_open_alert_normalizes(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [_alert(1, "open")])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "code_scanning_alert"
        assert summary["events_inserted"] == 1
        row = _rows(db_session, ws.id)[0]
        assert row.event_type == "github.code_scanning.alert.open"
        assert row.event_metadata.get("rule_id") == "js/sql-injection"
        assert row.event_metadata.get("tool_name") == "CodeQL"
        assert row.event_metadata.get("security_severity_level") == "high"
        assert row.event_metadata.get("repository") == REPO
        assert row.event_metadata.get("instances_count") == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 2. state mapping (fixed / dismissed / reopened) ───────────────────────────

def test_state_mapping(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _gh_integ(db_session, test_user, ws.id)
    _patch(monkeypatch, [
        _alert(10, "fixed"),
        _alert(11, "dismissed", dismissed_reason="false positive"),
        _alert(12, "reopened"),
        _alert(13, "open"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "github.code_scanning.alert.fixed",
            "github.code_scanning.alert.dismissed",
            "github.code_scanning.alert.reopened",
            "github.code_scanning.alert.open",
        } <= types
        # dismissed_reason is stored as a safe label.
        dm = [r for r in _rows(db_session, ws.id)
              if r.event_type == "github.code_scanning.alert.dismissed"][0]
        assert dm.event_metadata.get("dismissed_reason") == "false positive"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. privacy: raw SARIF / snippet / location / URL never stored ─────────────

def test_no_raw_code_or_url(test_user, db_session, monkeypatch):
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
        assert RAW_SNIPPET not in blob
        assert "ghp_" not in blob          # no token text anywhere
        assert "token=" not in blob        # raw URL with token never stored
        assert "SELECT" not in blob        # no raw code snippet
        assert "query.js" not in blob      # no raw file path / location
        assert "src/db" not in blob
        # Safe fields ARE present.
        assert row.event_metadata.get("alert_url_hash") is not None
        assert row.event_metadata.get("rule_id") == "js/sql-injection"
        # Forbidden raw keys never present.
        for bad in ("most_recent_instance", "locations", "location", "message",
                    "full_description", "html_url", "url", "instances",
                    "snippet", "path", "patch", "sarif", "code"):
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
        resp = client.post("/security/github-code-scanning/sync")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "github" and body["source"] == "code_scanning_alert"
        assert body["events_inserted"] == 1
    finally:
        _cleanup(db_session, ws.id)
