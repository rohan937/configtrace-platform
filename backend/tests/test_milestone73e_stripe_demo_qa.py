"""M73E — Stripe security demo + QA hardening.

The Stripe incident demo seeds one coherent, clearly-marked synthetic story on
a hidden demo integration: Stripe configuration risks (insecure webhook, broad
webhook event set, payment link with automatic tax off and promotion codes
allowed, customer portal with hosted login page on, and account not fully
enabled for payments) -> Stripe configuration activity (webhook endpoint,
payment link, portal configuration, account, and capability changes) for the
same objects -> activity signals -> risk×activity correlations -> a case. These
tests assert the seeded chain, the case report / timeline / graph render with
the "Stripe" provider label, claim discipline, demo-only isolation of
``clear_stripe``, and seed/clear idempotency + status.
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
    "compromise confirmed", "secret leaked", "data leaked", "customer data leaked",
    "payment fraud detected", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
_EXPECTED_CORRELATION_TYPES = {
    "stripe_webhook_insecure_risk_activity",
    "stripe_webhook_broad_events_risk_activity",
    "stripe_payment_link_tax_risk_activity",
    "stripe_payment_link_promo_risk_activity",
    "stripe_portal_login_risk_activity",
    "stripe_account_capability_risk_activity",
}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M73E", db=db)


def _seed(db, ws, user):
    return demo_svc.seed_stripe(workspace_id=ws.id, actor_user_id=user.id, db=db)


def _cleanup(db, ws_id):
    demo_svc.clear_stripe(workspace_id=ws_id, db=db)


# ── 1. seed creates the full Stripe demo chain ───────────────────────────────

def test_seed_creates_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        assert res["seeded"] and res["created"]
        assert res["case_id"] and res["link_count"] > 0

        integ = demo_svc.get_stripe_demo_integration(ws.id, db_session)
        assert integ is not None and integ.provider == demo_svc.DEMO_PROVIDER_TAG

        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert {
            "stripe_webhook_http",
            "stripe_webhook_broad_events",
            "stripe_payment_link_tax_disabled",
            "stripe_payment_link_promo_codes_enabled",
            "stripe_portal_login_enabled",
            "stripe_account_capability_incomplete",
        } <= rules

        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()
        etypes = {e.event_type for e in events}
        assert {
            "stripe.webhook_endpoint.updated",
            "stripe.payment_link.updated",
            "stripe.portal_config.updated",
            "stripe.account.updated",
            "stripe.capability.updated",
        } <= etypes

        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "stripe").all()
        assert any(s.signal_type == "stripe_activity_signal" for s in sigs)

        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "stripe").all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes
    finally:
        _cleanup(db_session, ws.id)


# ── 2. seeded findings carry account/webhook/payment-link/portal evidence ────

def test_seeded_evidence_shapes(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_stripe_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert by_rule["stripe_webhook_http"].evidence.get("url", "").startswith("http://")
        assert by_rule["stripe_webhook_broad_events"].evidence.get("subscribes_to_all_events") is True
        assert by_rule["stripe_payment_link_tax_disabled"].evidence.get("automatic_tax_enabled") is False
        assert by_rule["stripe_payment_link_promo_codes_enabled"].evidence.get("allow_promotion_codes") is True
        assert by_rule["stripe_portal_login_enabled"].evidence.get("login_page_enabled") is True
        assert by_rule["stripe_account_capability_incomplete"].evidence.get("charges_enabled") is False
    finally:
        _cleanup(db_session, ws.id)


# ── 3. seeded correlations carry linked correlation signals ──────────────────

def test_correlations_have_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "stripe").all()
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


# ── 4. case report uses the "Stripe" provider label + Stripe evidence ────────

def test_case_report_provider_label(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        assert "Stripe" in blob
        lower = blob.lower()
        assert (
            "stripe_webhook_insecure_risk_activity" in lower
            or "stripe.webhook_endpoint.updated" in lower
        )
        assert "stripe_webhook_http" in lower
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
        assert timeline["provider"] == "Stripe"
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
        for bad in ("sk_live", "sk_test", "rk_live", "whsec_", "bearer ",
                    "authorization", "customer_email", "card number",
                    "?session_id", "?secret=", "?token=",
                    "id_token", "refresh_token"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 7. clear removes Stripe demo artifacts only ──────────────────────────────

def test_clear_removes_only_demo(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # A REAL (non-demo) Stripe integration + finding that must survive clear.
    ct, iv = encrypt_credentials({"stripe_api_key": "rk_live_real"})
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="stripe",
        display_name="real-stripe", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="stripe",
        finding_key="stripe_webhook_http:real#keep",
        severity="critical", title="Real Stripe risk (keep)", status="active",
        evidence={"rule": "stripe_webhook_http"}, remediation={"summary": "x"},
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    real_id = real.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_stripe(workspace_id=ws.id, db=db_session)

        # All Stripe demo artifacts gone.
        assert demo_svc.get_stripe_demo_integration(ws.id, db_session) is None
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.STRIPE_DEMO_CASE_SOURCE,
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
        assert demo_svc.get_stripe_status(ws.id, db_session)["seeded"] is False
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert demo_svc.get_stripe_status(ws.id, db_session)["seeded"] is True

        demo_svc.clear_stripe(workspace_id=ws.id, db=db_session)
        demo_svc.clear_stripe(workspace_id=ws.id, db=db_session)  # idempotent
        assert demo_svc.get_stripe_status(ws.id, db_session)["seeded"] is False
    finally:
        _cleanup(db_session, ws.id)
