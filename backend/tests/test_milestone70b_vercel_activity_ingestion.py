"""M70B — Vercel activity/audit ingestion foundation.

Vercel team audit-log activity is normalized into the shared
``security_activity_events`` spine (provider=vercel, source=audit_log) as
evidence for review. Activity ingestion ONLY — no signals/correlations/demo.
These tests assert normalization + event-type mapping, idempotency, non-fatal
permission/unavailable handling, malformed-event skipping, privacy (no env var
values, deploy hook URLs, tokens, headers, raw JSON, actor emails), endpoint
admin gating, workspace scoping, and claim discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.vercel import VercelConnector
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import vercel_activity_ingestion_service as ve_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
ENV_VALUE = "super_secret_env_value_should_never_store"
HOOK_URL = "https://api.vercel.com/v1/integrations/deploy/prj_x/SECRETTOKEN"
ACTOR_EMAIL = "admin@example.com"


def _entry(event_id, action, *, with_secrets=True, **ctx):
    """Build a raw Vercel audit-log entry in the shape the normalizer expects."""
    context = {
        "projectId": "prj_x",
        "projectName": "demo-project",
        "teamId": "team_x",
    }
    context.update(ctx)
    e = {
        "id": event_id,
        "action": action,
        "createdAt": 1_770_000_000_000,  # epoch ms
        "actor": {"type": "user", "id": "u-1", "email": ACTOR_EMAIL},
        "context": context,
    }
    if with_secrets:
        # These must never be traversed/stored by the allowlist gate.
        e["payload"] = {"value": ENV_VALUE, "url": HOOK_URL, "token": ENV_VALUE}
        e["headers"] = {"Authorization": f"Bearer {ENV_VALUE}"}
    return e


def _patch_audit(monkeypatch, entries=None, *, raise_exc=None):
    def _fake(self, credentials, *, max_events=100, lookback_hours=24):
        if raise_exc is not None:
            raise raise_exc
        return entries or []
    monkeypatch.setattr(VercelConnector, "list_audit_events", _fake)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M70B", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ve_integ(db, user, ws_id):
    ct, iv = encrypt_credentials(
        {"vercel_token": "x", "vercel_project_id": "prj_x", "vercel_team_id": "team_x"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="vercel",
                    display_name="vercel", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "vercel",
        SecurityActivityEvent.source == "audit_log",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return ve_ingest.ingest_vercel_activity(integration=integ, workspace_id=ws_id, db=db)


# ── 1. normalize + event-type mapping ─────────────────────────────────────────

def test_normalizes_and_maps_event_types(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    entries = [
        _entry("e1", "project.update"),
        _entry("e2", "domain.create", domain="app.example.com"),
        _entry("e3", "domain.remove", domain="old.example.com"),
        _entry("e4", "env.create", envKey="DATABASE_URL"),
        _entry("e5", "env.update", envKey="API_KEY"),
        _entry("e6", "env.delete", envKey="OLD_FLAG"),
        _entry("e7", "deployHook.create", deployHookName="nightly", branch="main"),
        _entry("e8", "deployHook.remove", deployHookName="stale"),
        _entry("e9", "deployment.create", deploymentId="dpl_1", target="production"),
        _entry("e10", "deployment.promote", deploymentId="dpl_2"),
        _entry("e11", "mystery.poke"),  # → fallback event
    ]
    _patch_audit(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "audit_log"
        assert summary["events_inserted"] == 11
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "vercel.project.updated", "vercel.domain.added", "vercel.domain.removed",
            "vercel.env_var.created", "vercel.env_var.updated", "vercel.env_var.deleted",
            "vercel.deploy_hook.created", "vercel.deploy_hook.deleted",
            "vercel.deployment.created", "vercel.deployment.promoted",
            "vercel.project.event",
        } <= types
        env = next(r for r in _rows(db_session, ws.id)
                   if r.event_type == "vercel.env_var.created")
        assert env.event_metadata.get("env_var_key") == "DATABASE_URL"
        assert env.event_metadata.get("project_name") == "demo-project"
        # Actor email is never stored as actor_id.
        assert env.actor_id is None
        assert env.actor_type == "user"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. malformed events are skipped safely ────────────────────────────────────

def test_malformed_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    entries = [
        _entry("ok1", "project.update"),
        "not-a-dict",                       # not a dict → skip
        {"id": "no-action"},                # no action → skip
        {"action": ""},                     # empty action → skip
        None,                               # None → skip
    ]
    _patch_audit(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_seen"] == 5
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 3. permission / unavailable failures are non-fatal ────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, raise_exc=AuthenticationError("denied"))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_unavailable_endpoint_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, raise_exc=ConnectorError("no team", status_code=404))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []
    assert summary["error_message"] and "limited" in summary["error_message"].lower()


def test_no_team_id_fails_soft_via_real_connector(test_user, db_session):
    """No team id → the real connector raises a 404 → permission_limited."""
    ws = _ws(test_user, db_session)
    ct, iv = encrypt_credentials({"vercel_token": "x", "vercel_project_id": "prj_x"})
    integ = Integration(user_id=test_user.id, workspace_id=ws.id, provider="vercel",
                        display_name="vercel", encrypted_credentials=ct,
                        credential_iv=iv, status="active")
    db_session.add(integ); db_session.commit(); db_session.refresh(integ)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] is True
        assert summary["permission_limited"] is True
        assert summary["events_inserted"] == 0
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


# ── 4. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_ingestion(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("dupe", "env.update", envKey="X")])
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_idempotent_without_event_id_via_fingerprint(test_user, db_session, monkeypatch):
    """Entries with no id still dedupe via the deterministic fingerprint."""
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    e = _entry(None, "project.update")
    e.pop("id", None)
    _patch_audit(monkeypatch, [dict(e), dict(e)])
    try:
        summary = _ingest(integ, ws.id, db_session)
        # Two identical id-less entries collapse to one via fingerprint.
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
        row = _rows(db_session, ws.id)[0]
        assert row.provider_event_id.startswith("fp:")
    finally:
        _cleanup(db_session, ws.id)


# ── 5. privacy: no values / URLs / tokens / headers / emails / raw JSON ───────

def test_no_secrets_urls_emails_or_raw_json(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [
        _entry("p1", "env.create", envKey="STRIPE_SECRET_KEY"),
        _entry("p2", "deployHook.create", deployHookName="nightly", branch="main"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        rows = _rows(db_session, ws.id)
        blob = json.dumps([{
            "event_type": r.event_type, "actor_id": r.actor_id,
            "actor_type": r.actor_type, "resource_id": r.resource_id,
            "metadata": r.event_metadata, "raw_ref": r.raw_ref,
        } for r in rows], default=str)
        assert ENV_VALUE not in blob
        assert HOOK_URL not in blob
        assert ACTOR_EMAIL not in blob
        for bad in ("value", "url", "token", "authorization", "bearer ",
                    "headers", "@example.com"):
            assert bad not in blob.lower()
        # No event ever stores a value/url key in metadata.
        for r in rows:
            assert "value" not in r.event_metadata
            assert "url" not in r.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 6. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _ve_integ(db_session, test_user, ws_a.id)
    _patch_audit(monkeypatch, [_entry("sc1", "project.update")])
    try:
        _ingest(integ_a, ws_a.id, db_session)
        assert len(_rows(db_session, ws_a.id)) == 1
        assert len(_rows(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 7. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _ve_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [
        _entry("c1", "env.create", envKey="API_KEY"),
        _entry("c2", "deployment.promote", deploymentId="dpl_9"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        blob = json.dumps(
            [{"t": r.event_type, "m": r.event_metadata} for r in _rows(db_session, ws.id)],
            default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 8. endpoint admin gating ──────────────────────────────────────────────────

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
    integ = _ve_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("ep1", "env.create", envKey="X")])
    try:
        r = client.post("/security/vercel-activity/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "vercel" and body["source"] == "audit_log"
        assert body["events_inserted"] == 1
        # Member-readable list endpoint surfaces the vercel events.
        lst = client.get("/security/activity/events?provider=vercel")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_no_active_integration_returns_clean_summary(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    # No vercel integration in this workspace.
    r = client.post("/security/vercel-activity/sync")
    assert r.status_code == 200
    body = r.json()
    assert body["attempted"] is False and body["provider"] == "vercel"
    assert body["error_message"]
