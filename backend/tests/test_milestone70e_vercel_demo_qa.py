"""M70E — Vercel security demo + QA hardening.

The Vercel incident demo seeds a coherent end-to-end story on a hidden demo
integration: configuration-risk findings (production branch / sensitive env var /
deploy hook) + Vercel audit activity + activity Incident Signals + risk×activity
correlations + a human-reviewed case. ``clear_vercel`` removes every seeded
artifact and nothing else. The case report / timeline / graph render the Vercel
provider label, the diverse evidence, and review-only language.
"""

from __future__ import annotations

import json
import uuid

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_incident_demo_service as demo
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
ENV_KEY = demo.VERCEL_DEMO_ENV_KEY
HOOK_NAME = demo.VERCEL_DEMO_HOOK_NAME


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M70E", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _demo_case(db, ws_id):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == demo.VERCEL_DEMO_CASE_SOURCE,
    ).first()


# ── 1. seed creates the full Vercel evidence story ──────────────────────────

def test_seed_creates_full_story(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert res["seeded"] and res["created"]
        case = _demo_case(db_session, ws.id)
        assert case is not None and case.provider == "vercel"

        integ = demo.get_vercel_demo_integration(ws.id, db_session)
        assert integ is not None and integ.status == "deleted"

        # Findings: branch / env var / deploy hook risks.
        f_rules = {f.finding_key.split(":", 1)[0]
                   for f in db_session.query(SecurityFinding).filter(
                       SecurityFinding.integration_id == integ.id).all()}
        assert "vercel_production_branch_unusual" in f_rules
        assert "vercel_sensitive_env_var_broad_scope" in f_rules
        assert "vercel_deploy_hook_production_branch" in f_rules

        # Activity events: project / env var / deploy hook changes.
        types = {e.event_type for e in db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()}
        assert {"vercel.project.updated", "vercel.env_var.updated",
                "vercel.deploy_hook.created"} <= types

        # Signals + correlations exist.
        sig_n = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id).count()
        corr_n = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id).count()
        assert sig_n >= 3 and corr_n >= 3

        # Case links everything.
        assert case_svc.count_links(case.id, db_session) >= 9
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)


# ── 2. seeded correlations carry the expected types + linked signals ─────────

def test_seeded_correlation_types_and_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id).all()
        types = {c.correlation_type for c in corrs}
        assert "vercel_project_branch_activity" in types
        assert "vercel_env_var_risk_activity" in types
        assert "vercel_deploy_hook_risk_activity" in types
        # Every correlation links an evidence signal.
        assert all(c.linked_signal_id is not None for c in corrs)
        # Sensitive env var correlation is high severity.
        env_c = next(c for c in corrs if c.correlation_type == "vercel_env_var_risk_activity")
        assert env_c.severity == "high"
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)


# ── 3. idempotent seed ───────────────────────────────────────────────────────

def test_seed_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        r1 = demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        r2 = demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert r1["created"] is True and r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert len(db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo.VERCEL_DEMO_CASE_SOURCE).all()) == 1
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)


# ── 4. status reflects seeded / unseeded ─────────────────────────────────────

def test_status_reflects_state(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        assert demo.get_vercel_status(ws.id, db_session)["seeded"] is False
        demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        st = demo.get_vercel_status(ws.id, db_session)
        assert st["seeded"] is True and st["link_count"] >= 9
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)
    assert demo.get_vercel_status(ws.id, db_session)["seeded"] is False


# ── 5. case report: Vercel label + diverse evidence + review language ────────

def test_case_report_label_evidence_and_claims(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id)
        rep = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(rep, default=str)

        # Provider label "Vercel".
        assert "Vercel" in rep["executive_summary"]

        # Diverse evidence present.
        assert "vercel.project.updated" in blob
        assert "vercel.env_var.updated" in blob
        assert "vercel.deploy_hook.created" in blob
        assert "vercel_production_branch_unusual" in blob
        assert "vercel_deploy_hook_risk_activity" in blob

        # Review language; never breach/secret-leak language.
        low = blob.lower()
        for phrase in _FORBIDDEN:
            assert phrase not in low
        assert "does not" in low and "confirm" in low

        # Privacy: env var value never appears (only the KEY name does).
        assert "url" not in {k.lower() for ae in rep["activity_events"]
                             for k in (ae.get("metadata") or {})}
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)


# ── 6. timeline + graph build for the Vercel demo case ───────────────────────

def test_timeline_and_graph_build(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id)

        tl = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert tl["provider"] == "Vercel" and tl["total"] >= 1
        for kind in ("finding", "activity_event", "incident_signal", "correlation"):
            assert tl["counts_by_type"].get(kind, 0) >= 1

        g = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert g["counts_by_node_type"].get("case", 0) == 1
        assert g["counts_by_edge_type"].get("case_contains", 0) >= 1
        assert g["counts_by_provider"].get("vercel", 0) >= 1

        # No forbidden claims in timeline/graph.
        for payload in (tl, g):
            low = json.dumps(payload, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)


# ── 7. clear removes all demo artifacts but not non-demo data ────────────────

def test_clear_removes_demo_only(test_user, db_session):
    ws = _ws(test_user, db_session)
    # A real (non-demo) Vercel integration + finding that must survive clear.
    ct, iv = encrypt_credentials({"vercel_token": "x", "vercel_project_id": "real"})
    real_integ = Integration(user_id=test_user.id, workspace_id=ws.id, provider="vercel",
                             display_name="real vercel", encrypted_credentials=ct,
                             credential_iv=iv, status="active")
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real_res = Resource(integration_id=real_integ.id, user_id=test_user.id,
                        provider_resource_type="vercel_project", provider_resource_id="real",
                        display_name="real", is_active=True)
    db_session.add(real_res); db_session.commit(); db_session.refresh(real_res)
    real_finding = finding_svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=real_integ.id, provider="vercel",
        finding_key="vercel_domain_unverified:real#1", severity="medium",
        title="Real domain risk", resource_id=real_res.id, description="d",
        evidence={"rule": "vercel_domain_unverified"}, remediation={"summary": "fix"})
    real_fid = real_finding.id
    try:
        demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        demo.clear_vercel(workspace_id=ws.id, db=db_session)

        # All demo artifacts gone.
        assert demo.get_vercel_demo_integration(ws.id, db_session) is None
        assert _demo_case(db_session, ws.id) is None
        # Demo activity/signals/correlations gone (only the real finding remains).
        remaining = {f.id for f in db_session.query(SecurityFinding).filter(
            SecurityFinding.workspace_id == ws.id).all()}
        assert remaining == {real_fid}
        assert db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).count() == 0
        assert db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id).count() == 0
    finally:
        demo.clear_vercel(workspace_id=ws.id, db=db_session)
        db_session.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.query(Resource).filter(Resource.integration_id == real_integ.id).delete(synchronize_session=False)
        db_session.query(Integration).filter(Integration.id == real_integ.id).delete(synchronize_session=False)
        db_session.commit()


# ── 8. clear is idempotent ────────────────────────────────────────────────────

def test_clear_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo.seed_vercel(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    assert demo.clear_vercel(workspace_id=ws.id, db=db_session)["cleared"] is True
    assert demo.clear_vercel(workspace_id=ws.id, db=db_session)["cleared"] is True
