"""M70D — Vercel configuration-risk × activity correlations.

Correlates an ACTIVE Vercel configuration-risk finding with Vercel audit activity
(source="audit_log") for the SAME project, when an aligned event falls inside the
finding's review window (first_detected_at - 24h .. last_seen_at + 24h). Project
identity is the finding's Resource.provider_resource_id matched against the
event's metadata project_id / project_name. Correlations only — no demo.

These tests assert per-rule correlation creation, sensitive-env-var high severity,
project-scoped matching (different project / provider-only / out-of-window all
skip), idempotency, linked correlation Incident Signal creation, list/generate
endpoints, metadata privacy, and claim discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

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
PROJECT_ID = "prj_x"
_NOW_MS = int(datetime.now(timezone.utc).timestamp() * 1000)
_DAY_MS = 86_400_000


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M70D", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials(
        {"vercel_token": "x", "vercel_project_id": PROJECT_ID, "vercel_team_id": "team_x"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="vercel",
                    display_name="vercel", encrypted_credentials=ct,
                    credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _res(db, integ, user, project=PROJECT_ID):
    r = Resource(integration_id=integ.id, user_id=user.id,
                 provider_resource_type="vercel_project", provider_resource_id=project,
                 display_name=project, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, rule, *, evidence=None):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="vercel",
        finding_key=f"{rule}:{uuid.uuid4().hex[:8]}", severity="medium",
        title=f"{rule} risk", resource_id=res.id, description="d",
        evidence=evidence or {"rule": rule}, remediation={"summary": "fix"})


def _event(db, ws_id, integ, action, *, project=PROJECT_ID, with_project=True,
           created_ms=None, **ctx):
    context = {"projectId": project, "projectName": project, "teamId": "team_x"}
    if not with_project:
        context.pop("projectId", None)
        context.pop("projectName", None)
    context.update(ctx)
    entry = {
        "id": f"ev-{uuid.uuid4().hex[:10]}", "action": action,
        "createdAt": created_ms if created_ms is not None else _NOW_MS,
        "actor": {"type": "user", "id": "u-1", "email": ACTOR_EMAIL},
        "context": context,
        "payload": {"value": ENV_VALUE, "url": HOOK_URL, "token": ENV_VALUE},
    }
    norm = ve_ingest.normalize_vercel_audit_event(entry)
    assert norm is not None
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ.id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return corr_svc.generate_vercel_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id):
    return db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id,
        SecuritySignalCorrelation.provider == "vercel",
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


# ── 1. production branch risk × project.updated ──────────────────────────────

def test_branch_risk_project_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_production_branch_missing")
        _event(db_session, ws.id, integ, "project.update")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "vercel_project_branch_activity"
        assert c.severity == "medium" and c.confidence == "medium"
        assert c.linked_finding_id and c.linked_activity_event_id
    finally:
        _cleanup(db_session, ws.id)


# ── 2. domain risk × domain activity ─────────────────────────────────────────

def test_domain_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_domain_unverified")
        _event(db_session, ws.id, integ, "domain.create", domain="app.example.com")
        _event(db_session, ws.id, integ, "domain.remove", domain="old.example.com")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 2
        assert all(c.correlation_type == "vercel_domain_risk_activity"
                   for c in _corrs(db_session, ws.id))
    finally:
        _cleanup(db_session, ws.id)


# ── 3 + 4. env var risk × env activity; sensitive → high ─────────────────────

def test_env_var_risk_activity_and_sensitive_high(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_env_var_broad_target")
        _finding(db_session, ws, integ, res, "vercel_sensitive_env_var_broad_scope")
        _event(db_session, ws.id, integ, "env.create", envKey="API_KEY")
        s = _gen(db_session, ws.id)
        # Both findings correlate to the one env event.
        assert s["correlations_created"] == 2
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert types == {"vercel_env_var_risk_activity"}
        sev_by_rule = {
            c.correlation_metadata.get("finding_rule"): c.severity
            for c in _corrs(db_session, ws.id)
        }
        assert sev_by_rule["vercel_env_var_broad_target"] == "medium"
        assert sev_by_rule["vercel_sensitive_env_var_broad_scope"] == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. deploy hook risk × deploy hook activity (no raw URL) ──────────────────

def test_deploy_hook_risk_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_deploy_hook_production_branch")
        _event(db_session, ws.id, integ, "deployHook.create", deployHookName="nightly", branch="main")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id)[0]
        assert c.correlation_type == "vercel_deploy_hook_risk_activity"
        blob = json.dumps(c.correlation_metadata, default=str)
        assert HOOK_URL not in blob and "url" not in blob.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 6. preview protection risk × deployment activity ─────────────────────────

def test_deployment_protection_activity(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_preview_unprotected")
        _event(db_session, ws.id, integ, "deployment.promote", deploymentId="dpl_1", target="production")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 1
        assert _corrs(db_session, ws.id)[0].correlation_type == "vercel_deployment_protection_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── 7. different project does not correlate ──────────────────────────────────

def test_different_project_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_production_branch_missing")
        _event(db_session, ws.id, integ, "project.update", project="prj_other")
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 8. provider-only match (no project identity on event) does not correlate ─

def test_provider_only_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_production_branch_missing")
        _event(db_session, ws.id, integ, "project.update", with_project=False)
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 9. event outside review window does not correlate ────────────────────────

def test_out_of_window_no_correlation(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_production_branch_missing")
        # 3 days ago — outside [now-24h, now+24h].
        _event(db_session, ws.id, integ, "project.update", created_ms=_NOW_MS - 3 * _DAY_MS)
        s = _gen(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 10. idempotency ───────────────────────────────────────────────────────────

def test_idempotent(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_domain_unverified")
        _event(db_session, ws.id, integ, "domain.create", domain="app.example.com")
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 11. linked correlation Incident Signal created ───────────────────────────

def test_linked_correlation_signal(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_production_branch_missing")
        _event(db_session, ws.id, integ, "project.update")
        _gen(db_session, ws.id)
        c = _corrs(db_session, ws.id)[0]
        assert c.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == c.linked_signal_id).first()
        assert sig is not None
        assert sig.evidence_level == "correlation"
        assert sig.signal_type == "vercel_project_branch_activity"
        assert sig.linked_finding_id == c.linked_finding_id
        assert sig.linked_activity_event_id == c.linked_activity_event_id
    finally:
        _cleanup(db_session, ws.id)


# ── 12. metadata privacy ──────────────────────────────────────────────────────

def test_metadata_privacy(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_env_var_broad_target")
        _finding(db_session, ws, integ, res, "vercel_deploy_hook_production_branch")
        _event(db_session, ws.id, integ, "env.create", envKey="DB_PASSWORD")
        _event(db_session, ws.id, integ, "deployHook.create", deployHookName="nightly", branch="main")
        _gen(db_session, ws.id)
        cs = _corrs(db_session, ws.id)
        blob = json.dumps([{"t": c.title, "s": c.summary, "m": c.correlation_metadata}
                           for c in cs], default=str)
        assert ENV_VALUE not in blob
        assert HOOK_URL not in blob
        assert ACTOR_EMAIL not in blob
        for bad in ("bearer ", "authorization", "@example.com"):
            assert bad not in blob.lower()
        for c in cs:
            for forbidden_key in ("value", "url", "token", "headers", "secret", "actor_email"):
                assert forbidden_key not in c.correlation_metadata
    finally:
        _cleanup(db_session, ws.id)


# ── 13. claim discipline ──────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_production_branch_missing")
        _event(db_session, ws.id, integ, "project.update")
        _gen(db_session, ws.id)
        for c in _corrs(db_session, ws.id):
            blob = f"{c.title}\n{c.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "does not confirm" in c.summary.lower()
            assert "review" in c.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 14. list endpoint filters provider + correlation_type ────────────────────

def test_list_endpoint_filters(client, test_user, db_session):
    ws, integ, res = _setup(db_session, test_user)
    try:
        _finding(db_session, ws, integ, res, "vercel_domain_unverified")
        _event(db_session, ws.id, integ, "domain.create", domain="app.example.com")
        r = client.post("/security/correlations/generate", json={"provider": "vercel"})
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "vercel" and body["correlations_created"] == 1

        lst = client.get("/security/correlations?provider=vercel&correlation_type=vercel_domain_risk_activity")
        assert lst.status_code == 200
        data = lst.json()
        assert data["total"] >= 1
        assert all(it["correlation_type"] == "vercel_domain_risk_activity" for it in data["items"])
        # A non-matching type filter returns none.
        none = client.get("/security/correlations?provider=vercel&correlation_type=vercel_env_var_risk_activity")
        assert none.json()["total"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 15. generate endpoint admin gating ───────────────────────────────────────

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
