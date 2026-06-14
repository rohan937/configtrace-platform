"""M71E — Supabase security demo + QA hardening.

The Supabase incident demo seeds one coherent, clearly-marked synthetic story on
a hidden demo integration: Supabase configuration risks (RLS disabled + public
SELECT on a sensitive table + public write policy + Edge Function JWT disabled +
auth protection missing) -> Supabase audit activity (rls / policy / edge-function
/ auth-config changes) -> activity signals -> risk×activity correlations -> a
case. These tests assert the seeded chain, the case report / timeline / graph
render with the "Supabase" provider label, claim discipline, demo-only isolation
of clear_supabase, and seed/clear idempotency + status.
"""

from __future__ import annotations

import json
import uuid

from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "secret leaked", "data leaked", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected",
]
_EXPECTED_CORRELATION_TYPES = {
    "supabase_rls_risk_activity",
    "supabase_public_select_risk_activity",
    "supabase_public_write_risk_activity",
    "supabase_edge_function_risk_activity",
    "supabase_auth_protection_risk_activity",
}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M71E", db=db)


def _seed(db, ws, user):
    return demo_svc.seed_supabase(workspace_id=ws.id, actor_user_id=user.id, db=db)


def _cleanup(db, ws_id):
    demo_svc.clear_supabase(workspace_id=ws_id, db=db)


# ── 1. seed creates the full Supabase demo chain ─────────────────────────────

def test_seed_creates_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        assert res["seeded"] and res["created"]
        assert res["case_id"] and res["link_count"] > 0

        integ = demo_svc.get_supabase_demo_integration(ws.id, db_session)
        assert integ is not None and integ.provider == demo_svc.DEMO_PROVIDER_TAG

        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert {
            "supabase_rls_disabled", "supabase_public_select_sensitive_table",
            "supabase_public_write_policy", "supabase_edge_function_jwt_disabled",
            "supabase_auth_protection_missing",
        } <= rules

        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()
        etypes = {e.event_type for e in events}
        assert "supabase.rls.updated" in etypes
        assert any(t.startswith("supabase.policy.") for t in etypes)
        assert "supabase.edge_function.updated" in etypes
        assert "supabase.auth_config.updated" in etypes

        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "supabase").all()
        assert any(s.signal_type == "supabase_activity_signal" for s in sigs)

        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "supabase").all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes
    finally:
        _cleanup(db_session, ws.id)


# ── 2. seeded findings carry table/RLS/policy/function evidence ──────────────

def test_seeded_evidence_shapes(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_supabase_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert by_rule["supabase_rls_disabled"].evidence.get("table") == "customers"
        assert by_rule["supabase_rls_disabled"].evidence.get("schema") == "public"
        assert by_rule["supabase_public_write_policy"].evidence.get("table") == "orders"
        assert by_rule["supabase_edge_function_jwt_disabled"].evidence.get("function_name") == "admin-webhook"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. seeded correlations carry linked correlation signals ──────────────────

def test_correlations_have_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "supabase").all()
        assert corrs
        for c in corrs:
            assert c.linked_finding_id is not None
            assert c.linked_activity_event_id is not None
            assert c.linked_signal_id is not None
            sig = db_session.query(SecurityIncidentSignal).filter(
                SecurityIncidentSignal.id == c.linked_signal_id).first()
            assert sig is not None and sig.evidence_level == "correlation"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. case report uses the "Supabase" provider label + Supabase evidence ────

def test_case_report_provider_label(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        assert "Supabase" in blob
        # The report links the Supabase risk/activity/signal/correlation evidence.
        lower = blob.lower()
        assert "supabase_rls_risk_activity" in lower or "supabase.rls.updated" in lower
        assert "supabase_rls_disabled" in lower
        for phrase in _FORBIDDEN:
            assert phrase not in lower
    finally:
        _cleanup(db_session, ws.id)


# ── 5. timeline + graph build for the demo case (claim-safe) ─────────────────

def test_timeline_and_graph_build(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        timeline = report_svc.build_case_evidence_timeline(case_id=case_id, workspace_id=ws.id, db=db_session)
        graph = report_svc.build_case_evidence_graph(case_id=case_id, workspace_id=ws.id, db=db_session)
        assert timeline["timeline_items"]
        assert graph["nodes"]
        # The dominant provider label for the demo case renders as "Supabase".
        assert timeline["provider"] == "Supabase"
        blob = (json.dumps(timeline, default=str) + json.dumps(graph, default=str)).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 6. report/timeline/graph carry no raw secret material ────────────────────

def test_no_secret_material_in_report(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        timeline = report_svc.build_case_evidence_timeline(case_id=case_id, workspace_id=ws.id, db=db_session)
        graph = report_svc.build_case_evidence_graph(case_id=case_id, workspace_id=ws.id, db=db_session)
        blob = (json.dumps(report, default=str) + json.dumps(timeline, default=str)
                + json.dumps(graph, default=str)).lower()
        for bad in ("service_role", "jwt_secret", "anon_key", "db_password",
                    "authorization", "bearer ", "using_expression", "env_var_value"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 7. clear removes Supabase demo artifacts only ────────────────────────────

def test_clear_removes_only_demo(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # A REAL (non-demo) Supabase integration + finding that must survive clear.
    ct, iv = encrypt_credentials({"access_token": "sbp_x", "project_ref": "realref0000000000000"})
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="supabase",
        display_name="real-supabase", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="supabase",
        finding_key="supabase_rls_disabled:real#keep",
        severity="high", title="Real Supabase risk (keep)", status="active",
        evidence={"rule": "supabase_rls_disabled"}, remediation={"summary": "x"},
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    real_id = real.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_supabase(workspace_id=ws.id, db=db_session)

        # All Supabase demo artifacts gone.
        assert demo_svc.get_supabase_demo_integration(ws.id, db_session) is None
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.SUPABASE_DEMO_CASE_SOURCE,
        ).count() == 0
        # The real non-demo finding is preserved.
        assert db_session.query(SecurityFinding).filter(SecurityFinding.id == real_id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(SecurityFinding.id == real_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(Integration.id == real_integ.id).delete(synchronize_session=False)
        db_session.commit()
        _cleanup(db_session, ws.id)


# ── 8. seed + clear are idempotent; status reflects state ────────────────────

def test_seed_clear_idempotent_and_status(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        assert demo_svc.get_supabase_status(ws.id, db_session)["seeded"] is False
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert demo_svc.get_supabase_status(ws.id, db_session)["seeded"] is True

        demo_svc.clear_supabase(workspace_id=ws.id, db=db_session)
        demo_svc.clear_supabase(workspace_id=ws.id, db=db_session)  # idempotent
        assert demo_svc.get_supabase_status(ws.id, db_session)["seeded"] is False
    finally:
        _cleanup(db_session, ws.id)
