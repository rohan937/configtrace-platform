"""M71D — Supabase configuration-risk × activity correlations.

Correlates an ACTIVE Supabase configuration-risk finding with Supabase audit
activity (source="audit_log") that shares the narrowest available identity (same
schema+table / same Edge Function / same project for auth config), when an
aligned event falls inside the finding's review window (first_detected_at - 24h
.. last_seen_at + 24h) AND — when both sides carry a project_ref — the SAME
project. Correlations only — no demo.

These tests assert per-rule correlation creation, narrow-identity matching
(different table / different function / provider-only / out-of-window all skip),
storage-bucket deferral, idempotency, linked correlation Incident Signal
creation, list/generate endpoints, metadata privacy, and claim discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import supabase_activity_ingestion_service as sb_ingest
from app.services import workspace_permission_service
from app.services import workspace_service
from app.services.security_rule_registry import KNOWN_RULE_KEYS

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
PROJECT_REF = "demoref0000000000000"
_NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M71D", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"access_token": "sbp_x", "project_ref": PROJECT_REF})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="supabase",
                    display_name="supabase", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user, project=PROJECT_REF):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="supabase_project", provider_resource_id=project,
                 display_name="demo-project", is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, rule, *, severity="high", evidence=None):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="supabase",
        finding_key=f"{rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"{rule} risk", resource_id=res.id, description="d",
        evidence=evidence or {"rule": rule}, remediation={"summary": "fix"})


def _event(db, ws_id, integ, action, *, project=PROJECT_REF, with_project=True,
           occurred=None, **meta):
    md = {"project_name": "demo-project"}
    if with_project:
        md["project_ref"] = project
    md.update(meta)
    when = occurred if occurred is not None else _NOW
    entry = {
        "id": f"ev-{uuid.uuid4().hex[:10]}",
        "action": {"name": action},
        "occurred_at": when.isoformat(),
        "actor": {"id": "u-1", "type": "user", "metadata": [{"email": ACTOR_EMAIL}]},
        "target": {"description": "demo target", "metadata": md},
        "payload": {
            "service_role_key": SERVICE_ROLE_KEY, "jwt_secret": JWT_SECRET,
            "anon_key": "anon123", "db_password": "pw", "row": ROW_DATA,
            "using_expression": POLICY_EXPR, "env_var_value": "env_secret",
        },
        "headers": {"Authorization": f"Bearer {SERVICE_ROLE_KEY}"},
    }
    norm = sb_ingest.normalize_supabase_activity_event(entry)
    assert norm is not None
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_supabase_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    return db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id,
        SecuritySignalCorrelation.provider == "supabase",
    ).all()


def _cleanup(db, ws_id):
    from app.models.security_activity_event import SecurityActivityEvent
    from app.models.security_finding import SecurityFinding
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _setup(db, user):
    ws = _ws(user, db); integ = _integ(db, user, ws.id); res = _res(db, integ, user)
    return ws, integ, res


# ── 1. RLS disabled risk × table/RLS activity ────────────────────────────────

def test_rls_risk_table_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public", table_name="customers")
        s = _gen(db_session, ws.id)
        assert s["provider"] == "supabase"
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "supabase_rls_risk_activity"
        assert c.severity == "high" and c.confidence == "medium"
        assert c.linked_finding_id and c.linked_activity_event_id
    finally:
        _cleanup(db_session, ws.id)


# ── 2. public SELECT risk × policy activity ──────────────────────────────────

def test_public_select_risk_policy_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_public_select_sensitive_table",
                 evidence={"rule": "supabase_public_select_sensitive_table", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "policy.create", schema_name="public",
               table_name="customers", policy_name="p_read", policy_command="SELECT")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        assert _corrs(db_session, ws.id)[0].correlation_type == "supabase_public_select_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. public write risk × policy activity ───────────────────────────────────

def test_public_write_risk_policy_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_public_write_policy",
                 evidence={"rule": "supabase_public_write_policy", "schema": "public", "table": "orders"})
        _event(db_session, ws.id, integ, "policy.update", schema_name="public",
               table_name="orders", policy_name="p_write", policy_command="UPDATE")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        assert _corrs(db_session, ws.id)[0].correlation_type == "supabase_public_write_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. Edge Function JWT risk × function activity ────────────────────────────

def test_edge_function_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_edge_function_jwt_disabled",
                 evidence={"rule": "supabase_edge_function_jwt_disabled", "function_name": "admin-webhook", "verify_jwt": False})
        _event(db_session, ws.id, integ, "function.update", edge_function_name="admin-webhook")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        assert _corrs(db_session, ws.id)[0].correlation_type == "supabase_edge_function_risk_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. auth protection risk × auth config activity ───────────────────────────

def test_auth_protection_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_auth_protection_missing", severity="medium",
                 evidence={"rule": "supabase_auth_protection_missing", "leaked_password_protection_enabled": False})
        _event(db_session, ws.id, integ, "auth.config.update", auth_setting_name="mfa")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "supabase_auth_protection_risk_activity"
        assert c.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. storage-bucket correlation is deferred (rule does not exist) ──────────

def test_storage_bucket_correlation_deferred():
    # The storage-bucket config-risk rule is deferred in M71A, so there is no
    # finding side to match — the correlation type is intentionally absent.
    assert "supabase_public_storage_bucket" not in KNOWN_RULE_KEYS
    types = {r["correlation_type"] for r in corr_svc.SUPABASE_CORRELATION_RULES.values()}
    assert "supabase_storage_bucket_risk_activity" not in types
    assert "supabase_public_storage_bucket" not in corr_svc.SUPABASE_CORRELATION_RULES


# ── 7. different table does not correlate ────────────────────────────────────

def test_different_table_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public", table_name="orders")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 8. different function does not correlate ─────────────────────────────────

def test_different_function_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_edge_function_jwt_disabled",
                 evidence={"rule": "supabase_edge_function_jwt_disabled", "function_name": "admin-webhook", "verify_jwt": False})
        _event(db_session, ws.id, integ, "function.update", edge_function_name="render-page")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 9. provider-only match (no table identity on event) does not correlate ───

def test_provider_only_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        # Same project + aligned event_type, but no table_name on the event.
        _event(db_session, ws.id, integ, "rls.update")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 10. different project does not correlate ─────────────────────────────────

def test_different_project_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        # Table identity matches but the event belongs to a different project.
        _event(db_session, ws.id, integ, "rls.update", project="other-project-ref",
               schema_name="public", table_name="customers")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 11. event outside review window does not correlate ───────────────────────

def test_out_of_window_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public",
               table_name="customers", occurred=_NOW - timedelta(days=3))
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 12. idempotency ───────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public", table_name="customers")
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 13. linked correlation Incident Signal created ───────────────────────────

def test_linked_correlation_signal(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public", table_name="customers")
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.signal_type == "supabase_rls_risk_activity"
        assert sig.linked_finding_id == c.linked_finding_id
        assert sig.linked_activity_event_id == c.linked_activity_event_id
    finally:
        _cleanup(db_session, ws.id)


# ── 14. metadata privacy ──────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_public_write_policy",
                 evidence={"rule": "supabase_public_write_policy", "schema": "public", "table": "user_secrets"})
        _event(db_session, ws.id, integ, "policy.update", schema_name="public",
               table_name="user_secrets", policy_name="p_write", policy_command="UPDATE")
        _gen(db_session, ws.id)
        cs = _corrs(db_session, ws.id)
        assert cs
        blob = json.dumps([{"t": c.title, "s": c.summary, "m": c.correlation_metadata}
                           for c in cs], default=str)
        assert SERVICE_ROLE_KEY not in blob
        assert JWT_SECRET not in blob
        assert ACTOR_EMAIL not in blob
        assert ROW_DATA not in blob
        assert POLICY_EXPR not in blob
        for bad in ("service_role", "jwt_secret", "anon_key", "db_password",
                    "authorization", "bearer ", "using_expression", "env_var_value",
                    "@example.com"):
            assert bad not in blob.lower()
        for c in cs:
            for forbidden_key in ("service_role_key", "jwt_secret", "anon_key",
                                  "db_password", "row", "using_expression",
                                  "env_var_value", "payload", "headers", "actor_email"):
                assert forbidden_key not in c.correlation_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 15. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "accounts"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public", table_name="accounts")
        _gen(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = f"{c.title}\n{c.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.summary.lower()
            assert "review" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 16. list + generate endpoints ────────────────────────────────────────────

def test_list_and_generate_endpoints(client, test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "supabase_rls_disabled",
                 evidence={"rule": "supabase_rls_disabled", "schema": "public", "table": "customers"})
        _event(db_session, ws.id, integ, "rls.update", schema_name="public", table_name="customers")
        r = client.post("/security/correlations/generate", json={"provider": "supabase"})
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "supabase" and body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=supabase&correlation_type=supabase_rls_risk_activity")
        assert lst.status_code == 200
        data = lst.json()
        assert data["total"] >= 1
        assert all(it["correlation_type"] == "supabase_rls_risk_activity" for it in data["items"])
        none = client.get("/security/correlations?provider=supabase&correlation_type=supabase_edge_function_risk_activity")
        assert none.json()["total"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 17. generate endpoint admin gating ───────────────────────────────────────

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
