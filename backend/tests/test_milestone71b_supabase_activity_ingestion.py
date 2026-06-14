"""M71B — Supabase activity/audit ingestion foundation.

Supabase organization audit-log activity is normalized into the shared
``security_activity_events`` spine (provider=supabase, source=audit_log) as
evidence for review. Activity ingestion ONLY — no signals/correlations/demo.
These tests assert normalization + event-type mapping, idempotency, non-fatal
permission/unavailable handling, malformed-event skipping, privacy (no row data,
SQL rows, auth users, emails, JWT/service-role/anon keys, db passwords, tokens,
headers, raw payloads, policy expressions, Edge Function env var values),
endpoint admin gating, workspace scoping, and claim discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.supabase import SupabaseConnector
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import supabase_activity_ingestion_service as sb_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
SERVICE_ROLE_KEY = "service_role_key_should_never_store"
JWT_SECRET = "super-jwt-secret-never-store"
ACTOR_EMAIL = "admin@example.com"
ROW_DATA = "row_value_should_never_store"
POLICY_EXPR = "(auth.uid() = user_id) -- raw SQL expression"


def _entry(event_id, action, *, with_secrets=True, **target_meta):
    """Build a raw Supabase audit-log entry in the shape the normalizer expects."""
    meta = {"project_ref": "demoref0000000000000", "project_name": "demo-project"}
    meta.update(target_meta)
    e = {
        "id": event_id,
        "action": {"name": action},
        "occurred_at": "2026-06-14T10:00:00Z",
        "actor": {"id": "u-1", "type": "user", "metadata": [{"email": ACTOR_EMAIL}]},
        "target": {"description": "demo target", "metadata": meta},
    }
    if with_secrets:
        # None of these must ever be traversed/stored by the allowlist gate.
        e["payload"] = {
            "service_role_key": SERVICE_ROLE_KEY, "jwt_secret": JWT_SECRET,
            "anon_key": "anon123", "db_password": "pw", "row": ROW_DATA,
            "using_expression": POLICY_EXPR, "env_var_value": "env_secret",
        }
        e["headers"] = {"Authorization": f"Bearer {SERVICE_ROLE_KEY}"}
    return e


def _patch_audit(monkeypatch, entries=None, *, raise_exc=None):
    def _fake(self, credentials, *, organization_id=None, max_events=100, lookback_hours=24):
        if raise_exc is not None:
            raise raise_exc
        return entries or []
    monkeypatch.setattr(SupabaseConnector, "list_activity_events", _fake)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M71B", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _sb_integ(db, user, ws_id, *, org=False):
    creds = {"access_token": "sbp_x", "project_ref": "demoref0000000000000"}
    if org:
        creds["organization_id"] = "demo-org"
    ct, iv = encrypt_credentials(creds)
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="supabase",
                    display_name="supabase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "supabase",
        SecurityActivityEvent.source == "audit_log",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db):
    return sb_ingest.ingest_supabase_activity(integration=integ, workspace_id=ws_id, db=db)


# ── 1. normalize + event-type mapping ─────────────────────────────────────────

def test_normalizes_and_maps_event_types(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id)
    entries = [
        _entry("e1", "project.update"),
        _entry("e2", "table.update", table_name="customers", schema_name="public"),
        _entry("e3", "rls.update", table_name="orders", schema_name="public"),
        _entry("e4", "policy.create", policy_name="p_read", policy_command="SELECT"),
        _entry("e5", "policy.update", policy_name="p_write", policy_command="UPDATE"),
        _entry("e6", "policy.delete", policy_name="p_old"),
        _entry("e7", "storage.bucket.create", storage_bucket_name="public-assets"),
        _entry("e8", "storage.bucket.update", storage_bucket_name="assets"),
        _entry("e9", "storage.bucket.delete", storage_bucket_name="stale"),
        _entry("e10", "function.create", edge_function_name="webhook"),
        _entry("e11", "function.update", edge_function_name="task"),
        _entry("e12", "function.delete", edge_function_name="old-fn"),
        _entry("e13", "auth.config.update", auth_setting_name="mfa"),
        _entry("e14", "mystery.poke"),  # → fallback event
    ]
    _patch_audit(monkeypatch, entries)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "audit_log"
        assert summary["events_inserted"] == 14
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert {
            "supabase.project.updated", "supabase.table.updated", "supabase.rls.updated",
            "supabase.policy.created", "supabase.policy.updated", "supabase.policy.deleted",
            "supabase.storage_bucket.created", "supabase.storage_bucket.updated",
            "supabase.storage_bucket.deleted", "supabase.edge_function.created",
            "supabase.edge_function.updated", "supabase.edge_function.deleted",
            "supabase.auth_config.updated", "supabase.project.event",
        } <= types
        policy = next(r for r in _rows(db_session, ws.id)
                      if r.event_type == "supabase.policy.created")
        assert policy.event_metadata.get("policy_name") == "p_read"
        assert policy.event_metadata.get("policy_command") == "SELECT"
        assert policy.event_metadata.get("project_name") == "demo-project"
        # Actor email is never stored as actor_id.
        assert policy.actor_id is None
        assert policy.actor_type == "user"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. malformed events are skipped safely ────────────────────────────────────

def test_malformed_events_skipped(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id)
    entries = [
        _entry("ok1", "project.update"),
        "not-a-dict",                       # not a dict → skip
        {"id": "no-action"},                # no action → skip
        {"action": {"name": ""}},           # empty action → skip
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
    integ = _sb_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, raise_exc=AuthenticationError("denied"))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0


def test_unavailable_endpoint_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, raise_exc=ConnectorError("no org", status_code=404))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["succeeded"] is True
    assert summary["permission_limited"] is True
    assert _rows(db_session, ws.id) == []
    assert summary["error_message"] and "limited" in summary["error_message"].lower()


def test_no_org_slug_fails_soft_via_real_connector(test_user, db_session):
    """No organization slug → the real connector raises a 404 → permission_limited."""
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id, org=False)
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] is True
        assert summary["permission_limited"] is True
        assert summary["events_inserted"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 4. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_ingestion(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("dupe", "policy.update", policy_name="X")])
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
    integ = _sb_integ(db_session, test_user, ws.id)
    e = _entry(None, "project.update")
    e.pop("id", None)
    _patch_audit(monkeypatch, [dict(e), dict(e)])
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
        row = _rows(db_session, ws.id)[0]
        assert row.provider_event_id.startswith("fp:")
    finally:
        _cleanup(db_session, ws.id)


# ── 5. privacy: no secrets / row data / expressions / emails / headers ────────

def test_no_secrets_rows_emails_or_raw_json(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [
        _entry("p1", "policy.create", policy_name="p_users", policy_command="SELECT",
               table_name="users", schema_name="public"),
        _entry("p2", "function.update", edge_function_name="webhook"),
    ])
    try:
        _ingest(integ, ws.id, db_session)
        rows = _rows(db_session, ws.id)
        blob = json.dumps([{
            "event_type": r.event_type, "actor_id": r.actor_id,
            "actor_type": r.actor_type, "resource_id": r.resource_id,
            "metadata": r.event_metadata, "raw_ref": r.raw_ref,
        } for r in rows], default=str)
        assert SERVICE_ROLE_KEY not in blob
        assert JWT_SECRET not in blob
        assert ACTOR_EMAIL not in blob
        assert ROW_DATA not in blob
        assert POLICY_EXPR not in blob
        for bad in ("service_role", "jwt_secret", "anon_key", "db_password",
                    "authorization", "bearer ", "headers", "using_expression",
                    "env_var_value", "@example.com"):
            assert bad not in blob.lower()
        # No event ever stores a secret/raw/expression key in metadata.
        for r in rows:
            for forbidden_key in ("service_role_key", "jwt_secret", "anon_key",
                                  "db_password", "row", "using_expression",
                                  "env_var_value", "payload", "headers"):
                assert forbidden_key not in r.event_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 6. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _sb_integ(db_session, test_user, ws_a.id)
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
    integ = _sb_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [
        _entry("c1", "policy.create", policy_name="p_read"),
        _entry("c2", "rls.update", table_name="accounts"),
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


# ── 8. endpoint admin gating + member read ────────────────────────────────────

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


def test_owner_can_sync_and_member_can_read_via_endpoint(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _sb_integ(db_session, test_user, ws.id)
    _patch_audit(monkeypatch, [_entry("ep1", "policy.create", policy_name="X")])
    try:
        r = client.post("/security/supabase-activity/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "supabase" and body["source"] == "audit_log"
        assert body["events_inserted"] == 1
        # Member-readable list endpoint surfaces the supabase events.
        lst = client.get("/security/activity/events?provider=supabase")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_no_active_integration_returns_clean_summary(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    # No supabase integration in this workspace.
    r = client.post("/security/supabase-activity/sync")
    assert r.status_code == 200
    body = r.json()
    assert body["attempted"] is False and body["provider"] == "supabase"
    assert body["error_message"]
