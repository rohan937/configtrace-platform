"""M68.7 — Cloudflare final demo + QA hardening.

The Cloudflare incident demo seeds one coherent, clearly-marked, demo-only
evidence chain (no real Cloudflare sync, no notifications):

  Configuration Risk (WAF rule disabled) → Cloudflare audit activity
  (cloudflare.waf_rule.changed) → Cloudflare WAF/security activity
  (cloudflare.waf_event.block) → Cloudflare audit-activity Incident Signal +
  Cloudflare WAF/security Incident Signal → Cloudflare risk × audit-activity
  correlation + Cloudflare risk × WAF/security-activity correlation → human-
  reviewed Case → Report.

These tests assert the full chain, idempotency, clear-isolation (Cloudflare vs
GitHub vs AWS), the report export (Cloudflare executive summary + audit_log and
waf_security_event sources + activity/correlation evidence levels), privacy (no
raw IPs / URLs / paths / query strings / raw GraphQL JSON / oldValue-newValue /
tokens / secrets / headers / cookies / sessions), admin gating, and claim
discipline.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_case_report_service as report_svc
from app.services import security_case_service as case_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "exploit confirmed",
]
# Raw Cloudflare fields/markers that must NEVER appear in seeded objects/report.
_FORBIDDEN_RAW = [
    "clientip", "clientrequestpath", "clientrequestquery", "clientrequesturi",
    "firewalleventsadaptive", "api_token", "apitoken", "authorization",
    "set-cookie", "oldvalue", "newvalue", "sessiontoken", "x-auth",
]
CF_SOURCE = "demo_cloudflare_incident"


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M68.7", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _cf_cases(db, ws_id):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == CF_SOURCE,
    ).count()


# ── 1. full chain ─────────────────────────────────────────────────────────────

def test_cloudflare_demo_seeds_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed_cloudflare(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert out["seeded"] and out["created"]
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(out["case_id"])).first()
        assert case is not None and case.provider == "cloudflare"

        links = case_svc.list_case_links(case_id=case.id, db=db_session)
        types = {ln.linked_object_type for ln in links}
        assert {"finding", "activity_event", "correlation", "signal"} <= types

        # Activity spans Cloudflare audit + WAF/security sources.
        sources = {
            r.source for r in db_session.query(SecurityActivityEvent).filter(
                SecurityActivityEvent.workspace_id == ws.id,
                SecurityActivityEvent.provider == "cloudflare",
            ).all()
        }
        assert {"audit_log", "waf_security_event"} <= sources

        # Both audit and WAF Incident Signals are present.
        sig_types = {
            s.signal_type for s in db_session.query(SecurityIncidentSignal).filter(
                SecurityIncidentSignal.workspace_id == ws.id,
                SecurityIncidentSignal.provider == "cloudflare",
            ).all()
        }
        assert "cloudflare_audit_activity" in sig_types
        assert "cloudflare_waf_activity_signal" in sig_types

        # Both audit and WAF/security correlations are present.
        corr_types = {
            c.correlation_type for c in db_session.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == ws.id,
                SecuritySignalCorrelation.provider == "cloudflare",
            ).all()
        }
        assert "cloudflare_waf_change" in corr_types          # audit correlation
        assert "cloudflare_waf_risk_activity" in corr_types   # WAF/security correlation
    finally:
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)


# ── 2. idempotency ────────────────────────────────────────────────────────────

def test_cloudflare_demo_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        s1 = demo_svc.seed_cloudflare(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        s2 = demo_svc.seed_cloudflare(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert s1["created"] is True
        assert s2["created"] is False
        assert s1["case_id"] == s2["case_id"]
        assert _cf_cases(db_session, ws.id) == 1
    finally:
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)


# ── 3. clear removes only Cloudflare demo evidence ────────────────────────────

def test_clear_removes_all_cloudflare_demo_evidence(test_user, db_session):
    ws = _ws(test_user, db_session)
    demo_svc.seed_cloudflare(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)

    assert demo_svc.get_cloudflare_status(ws.id, db_session)["seeded"] is False
    assert _cf_cases(db_session, ws.id) == 0
    assert demo_svc.get_cloudflare_demo_integration(ws.id, db_session) is None
    assert db_session.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws.id).count() == 0
    assert db_session.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws.id).count() == 0
    assert db_session.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws.id).count() == 0


# ── 4. isolation: GitHub + AWS demos remain intact ────────────────────────────

def test_cloudflare_demo_isolated_from_github_and_aws(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        gh = demo_svc.seed(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        aws = demo_svc.seed_aws(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        cf = demo_svc.seed_cloudflare(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert len({gh["case_id"], aws["case_id"], cf["case_id"]}) == 3
        # Clearing Cloudflare leaves GitHub + AWS demos intact.
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)
        assert demo_svc.get_cloudflare_status(ws.id, db_session)["seeded"] is False
        assert demo_svc.get_status(ws.id, db_session)["seeded"] is True
        assert demo_svc.get_aws_status(ws.id, db_session)["seeded"] is True
        assert demo_svc.get_demo_integration(ws.id, db_session) is not None
        assert demo_svc.get_aws_demo_integration(ws.id, db_session) is not None
    finally:
        demo_svc.clear(workspace_id=ws.id, db=db_session)
        demo_svc.clear_aws(workspace_id=ws.id, db=db_session)
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)


# ── 5. report export ──────────────────────────────────────────────────────────

def test_report_exports_cloudflare_summaries_safely(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        out = demo_svc.seed_cloudflare(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(out["case_id"])).first()
        report = report_svc.build_case_report(case=case, db=db_session)

        assert "Cloudflare" in report["executive_summary"]
        assert len(report["risks"]) >= 1
        assert len(report["signals"]) >= 4  # audit + waf + 2 correlation-evidence
        # Activity spans the Cloudflare sources.
        report_sources = {e["source"] for e in report["activity_events"]}
        assert {"audit_log", "waf_security_event"} <= report_sources
        # Evidence levels render (activity + correlation).
        levels = {s["evidence_level"] for s in report["signals"]}
        assert "activity" in levels and "correlation" in levels
        # Correlation types render cleanly.
        ctypes = {c["correlation_type"] for c in report["correlations"]}
        assert {"cloudflare_waf_change", "cloudflare_waf_risk_activity"} <= ctypes

        blob = json.dumps(report, default=str).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob, f"forbidden claim {phrase!r}"
        for raw in _FORBIDDEN_RAW:
            assert raw not in blob, f"raw marker {raw!r} leaked"
        # Activity events expose only a hashed IP, never a raw IP field.
        for ev in report["activity_events"]:
            assert "source_ip" not in ev  # only source_ip_hash allowed
            md = ev.get("metadata") or {}
            # No raw path / url / query keys leak via metadata.
            for bad in ("path", "url", "uri", "query", "client_ip"):
                assert bad not in md
    finally:
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)


# ── 6. claim discipline in seeded objects ─────────────────────────────────────

def test_no_forbidden_wording_in_seeded_objects(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        demo_svc.seed_cloudflare(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        blobs = []
        for c in db_session.query(SecurityCase).filter(
                SecurityCase.workspace_id == ws.id).all():
            blobs.append(f"{c.title}\n{c.summary}")
        for s in db_session.query(SecurityIncidentSignal).filter(
                SecurityIncidentSignal.workspace_id == ws.id).all():
            blobs.append(f"{s.title}\n{s.summary}")
        for cr in db_session.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == ws.id).all():
            blobs.append(f"{cr.title}\n{cr.summary}")
        text = "\n".join(blobs).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in text, f"forbidden phrase {phrase!r}"
    finally:
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)


# ── 7. member permission ──────────────────────────────────────────────────────

def test_member_cannot_seed_or_clear(test_user, db_session):
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


# ── 8. endpoint authorization (admin) ─────────────────────────────────────────

def test_admin_can_seed_clear_via_endpoints(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        r = client.post("/security/incident-demo/seed?provider=cloudflare")
        assert r.status_code == 200 and r.json()["seeded"] is True
        st = client.get("/security/incident-demo/status?provider=cloudflare")
        assert st.json()["seeded"] is True
        c = client.post("/security/incident-demo/clear?provider=cloudflare")
        assert c.status_code == 200 and c.json()["cleared"] is True
    finally:
        demo_svc.clear_cloudflare(workspace_id=ws.id, db=db_session)
