"""M72E — Firebase security demo + QA hardening.

The Firebase incident demo seeds one coherent, clearly-marked synthetic story on
a hidden demo integration: Firebase configuration risks (Firestore rules public +
Realtime Database rules public write + Storage rules public + anonymous auth
enabled + auth protection missing) -> Firebase audit activity (Firestore /
Realtime Database / Storage rules + auth-config changes) -> activity signals ->
risk×activity correlations -> a case. These tests assert the seeded chain, the
case report / timeline / graph render with the "Firebase" provider label, claim
discipline, demo-only isolation of clear_firebase, and seed/clear idempotency +
status.
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
    "firebase_firestore_rules_risk_activity",
    "firebase_database_rules_risk_activity",
    "firebase_storage_rules_risk_activity",
    "firebase_anonymous_auth_risk_activity",
    "firebase_auth_protection_risk_activity",
}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M72E", db=db)


def _seed(db, ws, user):
    return demo_svc.seed_firebase(workspace_id=ws.id, actor_user_id=user.id, db=db)


def _cleanup(db, ws_id):
    demo_svc.clear_firebase(workspace_id=ws_id, db=db)


# ── 1. seed creates the full Firebase demo chain ─────────────────────────────

def test_seed_creates_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        assert res["seeded"] and res["created"]
        assert res["case_id"] and res["link_count"] > 0

        integ = demo_svc.get_firebase_demo_integration(ws.id, db_session)
        assert integ is not None and integ.provider == demo_svc.DEMO_PROVIDER_TAG

        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert {
            "firebase_rules_public", "firebase_database_public_write",
            "firebase_storage_rules_public", "firebase_anonymous_auth_enabled",
            "firebase_auth_protection_missing",
        } <= rules

        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()
        etypes = {e.event_type for e in events}
        assert "firebase.firestore_rules.updated" in etypes
        assert "firebase.database_rules.updated" in etypes
        assert "firebase.storage_rules.updated" in etypes
        assert "firebase.auth_config.updated" in etypes

        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "firebase").all()
        assert any(s.signal_type == "firebase_activity_signal" for s in sigs)

        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "firebase").all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes
    finally:
        _cleanup(db_session, ws.id)


# ── 2. seeded findings carry project/rules/auth evidence ─────────────────────

def test_seeded_evidence_shapes(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_firebase_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert by_rule["firebase_rules_public"].evidence.get("public_read_detected") is True
        assert by_rule["firebase_database_public_write"].evidence.get("public_write_detected") is True
        assert by_rule["firebase_database_public_write"].evidence.get("database_instance")
        assert by_rule["firebase_anonymous_auth_enabled"].evidence.get("anonymous_enabled") is True
        assert by_rule["firebase_auth_protection_missing"].evidence.get("mfa_enabled") is False
    finally:
        _cleanup(db_session, ws.id)


# ── 3. seeded correlations carry linked correlation signals ──────────────────

def test_correlations_have_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "firebase").all()
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


# ── 4. case report uses the "Firebase" provider label + Firebase evidence ────

def test_case_report_provider_label(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        assert "Firebase" in blob
        lower = blob.lower()
        assert "firebase_firestore_rules_risk_activity" in lower or "firebase.firestore_rules.updated" in lower
        assert "firebase_rules_public" in lower
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
        assert timeline["provider"] == "Firebase"
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
        for bad in ("private_key", "client_email", "private_key_id", "service_account",
                    "authorization", "bearer ", "id_token", "refresh_token"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 7. clear removes Firebase demo artifacts only ────────────────────────────

def test_clear_removes_only_demo(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # A REAL (non-demo) Firebase integration + finding that must survive clear.
    ct, iv = encrypt_credentials({"project_id": "real-fb", "client_email": "x@y.iam"})
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="firebase",
        display_name="real-firebase", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="firebase",
        finding_key="firebase_rules_public:real#keep",
        severity="high", title="Real Firebase risk (keep)", status="active",
        evidence={"rule": "firebase_rules_public"}, remediation={"summary": "x"},
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    real_id = real.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_firebase(workspace_id=ws.id, db=db_session)

        # All Firebase demo artifacts gone.
        assert demo_svc.get_firebase_demo_integration(ws.id, db_session) is None
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.FIREBASE_DEMO_CASE_SOURCE,
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
        assert demo_svc.get_firebase_status(ws.id, db_session)["seeded"] is False
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert demo_svc.get_firebase_status(ws.id, db_session)["seeded"] is True

        demo_svc.clear_firebase(workspace_id=ws.id, db=db_session)
        demo_svc.clear_firebase(workspace_id=ws.id, db=db_session)  # idempotent
        assert demo_svc.get_firebase_status(ws.id, db_session)["seeded"] is False
    finally:
        _cleanup(db_session, ws.id)
