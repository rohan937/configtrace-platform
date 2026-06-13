"""M69.6 — GitHub security demo + QA hardening.

The GitHub incident demo seeds a coherent end-to-end story on a hidden demo
integration: repository / ruleset / automation-permission configuration risks +
audit activity + secret-scanning / code-scanning / Dependabot alert evidence +
incident signals + correlations + a human-reviewed case. ``clear`` removes every
seeded artifact and nothing else. The case report renders the GitHub provider
label, the diverse evidence, and review-only language.
"""

from __future__ import annotations

import json
import uuid

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.security_case import SecurityCase
from app.models.user import User
from app.services import security_incident_demo_service as demo
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "token leaked", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.6", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _demo_findings(db, ws_id):
    return db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws_id,
        SecurityFinding.finding_key.like(f"%{demo.DEMO_REPO}#demo"),
    ).all()


def _demo_case(db, ws_id):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == demo.DEMO_CASE_SOURCE,
    ).first()


# ── 1. seed creates the full GitHub evidence story ───────────────────────────

def test_seed_creates_full_story(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert res["seeded"] and res["created"]
        case = _demo_case(db_session, ws.id)
        assert case is not None and case.provider == "github"

        integ = demo.get_demo_integration(ws.id, db_session)
        assert integ is not None

        # Findings: repo / ruleset / automation.
        f_rules = {f.finding_key.split(":", 1)[0]
                   for f in db_session.query(SecurityFinding).filter(
                       SecurityFinding.integration_id == integ.id).all()}
        assert "github_webhook_http" in f_rules
        assert "github_ruleset_not_enforced" in f_rules
        assert "github_automation_admin_permission" in f_rules

        # Activity/alert events: audit + secret + code + dependabot sources.
        sources = {e.source for e in db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()}
        assert {"audit_log", "secret_scanning_alert", "code_scanning_alert",
                "dependabot_alert"} <= sources

        # Signals + correlations exist.
        sig_n = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id).count()
        corr_n = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id).count()
        assert sig_n >= 3 and corr_n >= 4

        # Case links everything.
        assert case_svc.count_links(case.id, db_session) >= 10
    finally:
        demo.clear(workspace_id=ws.id, db=db_session)


# ── 2. seeded correlations carry the expected types + linked signals ─────────

def test_seeded_correlation_types_and_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id).all()
        types = {c.correlation_type for c in corrs}
        # M69.4 + M69.5C families represented.
        assert "github_automation_secret_alert" in types
        assert "github_automation_code_alert" in types
        assert "github_automation_dependabot_alert" in types
        assert "github_ruleset_risk_activity" in types
        assert "github_automation_permission_security_alert" in types
        # Every correlation links an evidence signal.
        assert all(c.linked_signal_id is not None for c in corrs)
    finally:
        demo.clear(workspace_id=ws.id, db=db_session)


# ── 3. idempotent seed ───────────────────────────────────────────────────────

def test_seed_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        r1 = demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        r2 = demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert len(db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo.DEMO_CASE_SOURCE).all()) == 1
    finally:
        demo.clear(workspace_id=ws.id, db=db_session)


# ── 4. status endpoint reflects seeded / unseeded ────────────────────────────

def test_status_reflects_state(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        assert demo.get_status(ws.id, db_session)["seeded"] is False
        demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        st = demo.get_status(ws.id, db_session)
        assert st["seeded"] is True and st["link_count"] >= 10
    finally:
        demo.clear(workspace_id=ws.id, db=db_session)
    assert demo.get_status(ws.id, db_session)["seeded"] is False


# ── 5. clear removes all demo artifacts but not non-demo data ────────────────

def test_clear_removes_demo_only(test_user, db_session):
    ws = _ws(test_user, db_session)
    # A real (non-demo) GitHub integration + finding that must survive clear.
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "real", "repo_name": "repo"})
    real_integ = Integration(user_id=test_user.id, workspace_id=ws.id, provider="github",
                             display_name="real github", encrypted_credentials=ct,
                             credential_iv=iv, status="active")
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real_res = Resource(integration_id=real_integ.id, user_id=test_user.id,
                        provider_resource_type="github_repo", provider_resource_id="real/repo",
                        display_name="real/repo", is_active=True)
    db_session.add(real_res); db_session.commit(); db_session.refresh(real_res)
    real_finding = finding_svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=real_integ.id, provider="github",
        finding_key="github_webhook_http:real/repo#1", severity="high",
        title="Real webhook risk", resource_id=real_res.id, description="d",
        evidence={"rule": "github_webhook_http"}, remediation={"summary": "fix"})
    real_fid = real_finding.id
    try:
        demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        demo.clear(workspace_id=ws.id, db=db_session)

        # All demo artifacts gone.
        assert demo.get_demo_integration(ws.id, db_session) is None
        assert _demo_case(db_session, ws.id) is None
        assert _demo_findings(db_session, ws.id) == []
        # Demo activity/signals/correlations gone (only the real finding remains).
        remaining_findings = {f.id for f in db_session.query(SecurityFinding).filter(
            SecurityFinding.workspace_id == ws.id).all()}
        assert remaining_findings == {real_fid}
        assert db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).count() == 0
        assert db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id).count() == 0

        # Non-demo finding survived.
        assert db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_fid).first() is not None
    finally:
        demo.clear(workspace_id=ws.id, db=db_session)
        db_session.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).delete()
        for r in db_session.query(Resource).filter(Resource.integration_id == real_integ.id).all():
            db_session.delete(r)
        db_session.query(Integration).filter(Integration.id == real_integ.id).delete()
        db_session.commit()


# ── 6. clear is idempotent ───────────────────────────────────────────────────

def test_clear_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    assert demo.clear(workspace_id=ws.id, db=db_session)["cleared"] is True
    assert demo.clear(workspace_id=ws.id, db=db_session)["cleared"] is True


# ── 7. case report: GitHub label + diverse evidence + review language ────────

def test_case_report_label_evidence_and_claims(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = _demo_case(db_session, ws.id)
        rep = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(rep, default=str)

        # Provider label "GitHub".
        assert "GitHub" in rep["executive_summary"]

        # Diverse evidence sources / rules present in the report payload.
        assert "secret_scanning_alert" in blob
        assert "code_scanning_alert" in blob
        assert "dependabot_alert" in blob
        assert "github_ruleset_not_enforced" in blob
        assert "github_automation_admin_permission" in blob

        # Review language; never breach language.
        low = blob.lower()
        for phrase in _FORBIDDEN:
            assert phrase not in low
        assert "does not" in low and "confirm" in low
    finally:
        demo.clear(workspace_id=ws.id, db=db_session)
