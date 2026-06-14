"""M70C — Vercel activity Incident Signals.

Vercel team audit-log activity (provider=vercel, source=audit_log, ingested in
M70B) is promoted into review-worthy Incident Signals
(signal_type="vercel_activity_signal", evidence_level="activity",
confidence="medium"). These tests assert per-pattern signal creation, sensitive
env-var severity bump, production-branch deploy-hook bump, idempotency, workspace
scoping, endpoint admin gating, metadata privacy, and claim discipline.

Signals only — no correlations / demo.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

# Recent epoch-ms so events fall inside the signal generator's lookback window.
_NOW_MS = int(datetime.now(timezone.utc).timestamp() * 1000)

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import vercel_activity_ingestion_service as ve_ingest
from app.services import vercel_activity_signal_service as ve_sig
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
ENV_VALUE = "super_secret_env_value_should_never_store"
HOOK_URL = "https://api.vercel.com/v1/integrations/deploy/prj_x/SECRETTOKEN"
ACTOR_EMAIL = "admin@example.com"


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M70C", db=db)


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


def _entry(event_id, action, *, with_secrets=True, **ctx):
    context = {"projectId": "prj_x", "projectName": "demo-project", "teamId": "team_x"}
    context.update(ctx)
    e = {
        "id": event_id, "action": action, "createdAt": _NOW_MS,
        "actor": {"type": "user", "id": "u-1", "email": ACTOR_EMAIL},
        "context": context,
    }
    if with_secrets:
        e["payload"] = {"value": ENV_VALUE, "url": HOOK_URL, "token": ENV_VALUE}
        e["headers"] = {"Authorization": f"Bearer {ENV_VALUE}"}
    return e


def _ingest(db, ws_id, integ, entries):
    """Normalize + upsert raw Vercel audit entries into activity events."""
    for entry in entries:
        norm = ve_ingest.normalize_vercel_audit_event(entry)
        assert norm is not None, f"entry did not normalize: {entry.get('action')}"
        activity_svc.upsert_activity_event(
            workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "vercel",
    ).all()


def _gen(db, ws_id):
    return ve_sig.generate_vercel_activity_signals(workspace_id=ws_id, db=db)


def _cleanup(db, ws_id):
    from app.models.security_activity_event import SecurityActivityEvent
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. project updated → signal ───────────────────────────────────────────────

def test_project_updated_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [_entry("e1", "project.update")])
        summary = _gen(db_session, ws.id)
        assert summary["provider"] == "vercel" and summary["source"] == "audit_log"
        assert summary["signals_created"] == 1
        s = _signals(db_session, ws.id)[0]
        assert s.signal_type == "vercel_activity_signal"
        assert s.evidence_level == "activity" and s.confidence == "medium"
        assert s.severity == "medium"
        assert "settings changed" in s.title.lower()
        assert s.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── 2. domain added/removed → signal ──────────────────────────────────────────

def test_domain_change_creates_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("d1", "domain.create", domain="app.example.com"),
            _entry("d2", "domain.remove", domain="old.example.com"),
        ])
        summary = _gen(db_session, ws.id)
        assert summary["signals_created"] == 2
        for s in _signals(db_session, ws.id):
            assert "domain configuration changed" in s.title.lower()
            assert s.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. env var event → signal, high severity for sensitive key ───────────────

def test_env_var_signal_severity(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("s1", "env.create", envKey="STRIPE_SECRET_KEY"),
            _entry("s2", "env.update", envKey="FEATURE_FLAG_X"),
        ])
        _gen(db_session, ws.id)
        sev = {}
        for s in _signals(db_session, ws.id):
            key = s.signal_metadata.get("env_var_key")
            sev[key] = s.severity
            assert "environment variable metadata changed" in s.title.lower()
        assert sev["STRIPE_SECRET_KEY"] == "high"
        assert sev["FEATURE_FLAG_X"] == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. deploy hook event → signal without raw URL; prod branch bumps severity ─

def test_deploy_hook_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("h1", "deployHook.create", deployHookName="prod-hook", branch="main"),
            _entry("h2", "deployHook.create", deployHookName="dev-hook", branch="dev"),
        ])
        _gen(db_session, ws.id)
        sev = {}
        blob = json.dumps([s.signal_metadata for s in _signals(db_session, ws.id)], default=str)
        for s in _signals(db_session, ws.id):
            sev[s.signal_metadata.get("deploy_hook_name")] = s.severity
            assert "deploy hook configuration changed" in s.title.lower()
        assert sev["prod-hook"] == "high"   # branch=main → production
        assert sev["dev-hook"] == "medium"
        assert HOOK_URL not in blob and "url" not in blob.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 5. deployment created/promoted → signal (production vs not) ──────────────

def test_deployment_signal(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("p1", "deployment.promote", deploymentId="dpl_1", target="production"),
            _entry("p2", "deployment.create", deploymentId="dpl_2", target="preview"),
        ])
        _gen(db_session, ws.id)
        sev = {}
        for s in _signals(db_session, ws.id):
            sev[s.signal_metadata.get("deployment_id")] = s.severity
            assert "deployment activity observed" in s.title.lower()
        assert sev["dpl_1"] == "medium"   # production
        assert sev["dpl_2"] == "low"      # preview
    finally:
        _cleanup(db_session, ws.id)


# ── 6. fallback event is not promoted ─────────────────────────────────────────

def test_fallback_event_not_promoted(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [_entry("f1", "mystery.poke")])
        summary = _gen(db_session, ws.id)
        assert summary["events_scanned"] == 1
        assert summary["signals_created"] == 0
        assert _signals(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_idempotent_generation(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [_entry("i1", "env.create", envKey="API_KEY")])
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
    integ_a = _ve_integ(db_session, test_user, ws_a.id)
    try:
        _ingest(db_session, ws_a.id, integ_a, [_entry("w1", "project.update")])
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
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("m1", "env.create", envKey="DB_PASSWORD"),
            _entry("m2", "deployHook.create", deployHookName="nightly", branch="main"),
        ])
        _gen(db_session, ws.id)
        blob = json.dumps([{
            "title": s.title, "summary": s.summary, "metadata": s.signal_metadata,
        } for s in _signals(db_session, ws.id)], default=str)
        # No raw secret material / artifacts in the rendered signal.
        assert ENV_VALUE not in blob
        assert HOOK_URL not in blob
        assert ACTOR_EMAIL not in blob
        for bad in ("bearer ", "authorization", "@example.com"):
            assert bad not in blob.lower()
        # No env var VALUE field, deploy hook URL, or token keys in any metadata.
        for s in _signals(db_session, ws.id):
            for forbidden_key in ("value", "url", "token", "headers", "secret", "actor_email"):
                assert forbidden_key not in s.signal_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 10. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [
            _entry("c1", "env.create", envKey="API_KEY"),
            _entry("c2", "deployment.promote", deploymentId="dpl_9", target="production"),
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


# ── 11. endpoint admin gating ─────────────────────────────────────────────────

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
    ws = _ws(test_user, db_session); integ = _ve_integ(db_session, test_user, ws.id)
    try:
        _ingest(db_session, ws.id, integ, [_entry("ep1", "env.create", envKey="X")])
        r = client.post("/security/vercel-activity/generate-signals")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "vercel" and body["source"] == "audit_log"
        assert body["signals_created"] == 1
        # Member-readable list endpoint surfaces the vercel signals.
        lst = client.get("/security/signals?provider=vercel")
        assert lst.status_code == 200
        assert lst.json()["total"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
