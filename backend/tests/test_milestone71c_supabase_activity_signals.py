"""M71C — Supabase activity Incident Signals.

Supabase organization audit-log activity (provider=supabase, source=audit_log,
ingested in M71B) is promoted into review-worthy Incident Signals
(signal_type="supabase_activity_signal", evidence_level="activity",
confidence="medium"). These tests assert per-pattern signal creation, sensitive
table/bucket/function severity bumps, write-command policy bump, idempotency,
workspace scoping, endpoint admin gating, metadata privacy, and claim discipline.

Signals only — no correlations / demo.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

# Recent ISO timestamp so events fall inside the generator's lookback window.
_NOW_ISO = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import supabase_activity_ingestion_service as sb_ingest
from app.services import supabase_activity_signal_service as sb_sig
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


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M71C", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _sb_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"access_token": "sbp_x", "project_ref": "demoref0000000000000"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="supabase",
                    display_name="supabase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _entry(event_id, action, *, with_secrets=True, **target_meta):
    meta = {"project_ref": "demoref0000000000000", "project_name": "demo-project"}
    meta.update(target_meta)
    e = {
        "id": event_id,
        "action": {"name": action},
        "occurred_at": _NOW_ISO,
        "actor": {"id": "u-1", "type": "user", "metadata": [{"email": ACTOR_EMAIL}]},
        "target": {"description": "demo target", "metadata": meta},
    }
    if with_secrets:
        e["payload"] = {
            "service_role_key": SERVICE_ROLE_KEY, "jwt_secret": JWT_SECRET,
            "anon_key": "anon123", "db_password": "pw", "row": ROW_DATA,
            "using_expression": POLICY_EXPR, "env_var_value": "env_secret",
        }
        e["headers"] = {"Authorization": f"Bearer {SERVICE_ROLE_KEY}"}
    return e


def _ingest(db, ws_id, integ, entries):
    """Normalize + upsert raw Supabase audit entries into activity events."""
    for entry in entries:
        norm = sb_ingest.normalize_supabase_activity_event(entry)
        assert norm is not None, f"entry did not normalize: {entry}"
        activity_svc.upsert_activity_event(
            workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "supabase",
    ).all()


def _gen(db, ws_id):
    return sb_sig.generate_supabase_activity_signals(workspace_id=ws_id, db=db)


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. RLS / table posture change → signal (+ sensitive severity bump) ────────

def test_table_posture_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("r1", "rls.update", table_name="customers", schema_name="public"),
            _entry("t1", "table.update", table_name="widgets", schema_name="public"),
        ])
        summary = _gen(db_session, ws.id)
        assert summary["provider"] == "supabase" and summary["source"] == "audit_log"
        assert summary["signals_created"] == 2
        sev = {}
        for s in _signals(db_session, ws.id):
            assert s.signal_type == "supabase_activity_signal"
            assert s.evidence_level == "activity" and s.confidence == "medium"
            assert "table access posture changed" in s.title.lower()
            sev[s.signal_metadata.get("table_name")] = s.severity
            assert s.linked_activity_event_id is not None
        assert sev["customers"] == "high"   # public + sensitive name
        assert sev["widgets"] == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. policy created/updated/deleted → signal (+ write-command bump) ─────────

def test_policy_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("p1", "policy.create", policy_name="p_read", policy_command="SELECT", table_name="widgets"),
            _entry("p2", "policy.update", policy_name="p_write", policy_command="UPDATE", table_name="widgets"),
            _entry("p3", "policy.delete", policy_name="p_old", table_name="customers"),
        ])
        _gen(db_session, ws.id)
        sev = {}
        for s in _signals(db_session, ws.id):
            assert "access policy changed" in s.title.lower()
            sev[s.signal_metadata.get("policy_name")] = s.severity
            # No SQL expression ever stored.
            assert POLICY_EXPR not in json.dumps(s.signal_metadata, default=str)
        assert sev["p_read"] == "medium"   # read on a non-sensitive table
        assert sev["p_write"] == "high"    # write command
        assert sev["p_old"] == "high"      # sensitive table name
    finally:
        _cleanup(db_session, ws.id)


# ── 3. storage bucket change → signal (+ sensitive bucket bump) ──────────────

def test_storage_bucket_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("b1", "storage.bucket.create", storage_bucket_name="user-uploads"),
            _entry("b2", "storage.bucket.update", storage_bucket_name="public-assets"),
        ])
        _gen(db_session, ws.id)
        sev = {}
        for s in _signals(db_session, ws.id):
            assert "storage bucket configuration changed" in s.title.lower()
            sev[s.signal_metadata.get("storage_bucket_name")] = s.severity
        assert sev["user-uploads"] == "high"
        assert sev["public-assets"] == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. Edge Function change → signal (+ sensitive function bump) ─────────────

def test_edge_function_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("f1", "function.update", edge_function_name="admin-webhook"),
            _entry("f2", "function.create", edge_function_name="render-page"),
        ])
        _gen(db_session, ws.id)
        sev = {}
        for s in _signals(db_session, ws.id):
            assert "edge function configuration changed" in s.title.lower()
            sev[s.signal_metadata.get("edge_function_name")] = s.severity
        assert sev["admin-webhook"] == "high"
        assert sev["render-page"] == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. auth config change → signal ────────────────────────────────────────────

def test_auth_config_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("a1", "auth.config.update", auth_setting_name="mfa"),
        ])
        _gen(db_session, ws.id)
        s = _signals(db_session, ws.id)[0]
        assert "authentication configuration changed" in s.title.lower()
        assert s.severity == "medium"
        assert s.signal_metadata.get("auth_setting_name") == "mfa"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. project updated / fallback → signal ────────────────────────────────────

def test_project_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("pr1", "project.update", target_type="settings", target_id="cfg"),
            _entry("pr2", "mystery.poke"),  # → supabase.project.event fallback
        ])
        summary = _gen(db_session, ws.id)
        assert summary["signals_created"] == 2
        sev_by_type = {}
        for s in _signals(db_session, ws.id):
            assert "project configuration changed" in s.title.lower()
            sev_by_type[s.signal_metadata.get("event_type")] = s.severity
        assert sev_by_type["supabase.project.updated"] == "medium"
        # A bare fallback event with no target is the lowest-signal case.
        assert sev_by_type["supabase.project.event"] == "low"
    finally:
        _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("i1", "policy.create", policy_name="p_read", policy_command="SELECT"),
        ])
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["signals_created"] == 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 1
        assert len(_signals(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 8. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _sb_integ(db_session, test_user, ws_a.id)
    try:
        _ingest(db_session, ws_a.id, integ_a, [_entry("w1", "rls.update", table_name="orders")])
        _gen(db_session, ws_a.id)
        assert len(_signals(db_session, ws_a.id)) == 1
        assert len(_signals(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 9. metadata privacy ───────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("m1", "policy.create", policy_name="p_users", policy_command="SELECT",
                   table_name="user_secrets", schema_name="public"),
            _entry("m2", "function.update", edge_function_name="admin-delete"),
        ])
        _gen(db_session, ws.id)
        blob = json.dumps([{
            "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
        } for s in _signals(db_session, ws.id)], default=str)
        assert SERVICE_ROLE_KEY not in blob
        assert JWT_SECRET not in blob
        assert ACTOR_EMAIL not in blob
        assert ROW_DATA not in blob
        assert POLICY_EXPR not in blob
        for bad in ("service_role", "jwt_secret", "anon_key", "db_password",
                    "authorization", "bearer ", "using_expression", "env_var_value",
                    "@example.com"):
            assert bad not in blob.lower()
        for s in _signals(db_session, ws.id):
            for forbidden_key in ("service_role_key", "jwt_secret", "anon_key",
                                  "db_password", "row", "using_expression",
                                  "env_var_value", "payload", "headers", "actor_email"):
                assert forbidden_key not in s.signal_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("c1", "policy.create", policy_name="p_read", policy_command="ALL", table_name="accounts"),
            _entry("c2", "storage.bucket.create", storage_bucket_name="backups"),
        ])
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "evidence for review" in s.summary.lower()
            assert "does not confirm" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 11. endpoint admin gating + member read ──────────────────────────────────

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


def test_owner_can_generate_and_member_can_read_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session); integ = _sb_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [_entry("ep1", "policy.create", policy_name="X", policy_command="SELECT")])
        r = client.post("/security/supabase-activity/generate-signals")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "supabase" and body["source"] == "audit_log"
        assert body["signals_created"] == 1
        # Member-readable list endpoint surfaces the supabase signals.
        lst = client.get("/security/signals?provider=supabase")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
