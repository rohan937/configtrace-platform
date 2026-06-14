"""M74E — Shopify security demo + QA hardening.

The Shopify incident demo seeds one coherent, clearly-marked synthetic story
on a hidden demo integration: Shopify configuration risks (insecure webhook
over HTTP, high-risk webhook topic, primary domain without SSL, primary
domain unverified, broad app write scopes, and a missing standard policy) ->
Shopify configuration activity (shopify.webhook.updated for both webhooks,
shopify.domain.updated, shopify.shop.updated) -> activity signals ->
risk x activity correlations (webhook insecure, webhook high-risk topic,
domain SSL, domain verification — app-scope and policy correlations stay
uncorrelated because M74B does not emit those event types yet) -> a case.
These tests assert the seeded chain, the case report / timeline / graph
render with the "Shopify" provider label, claim discipline, demo-only
isolation of ``clear_shopify``, and seed/clear idempotency + status.
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
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]
_EXPECTED_CORRELATION_TYPES = {
    "shopify_webhook_insecure_risk_activity",
    "shopify_webhook_topic_risk_activity",
    "shopify_domain_ssl_risk_activity",
    "shopify_domain_verification_risk_activity",
}
_DEFERRED_FINDING_RULES = {
    # M74B does not emit shopify.app_scopes.updated or shopify.policy.*,
    # so these risk findings exist in the case as evidence but produce no
    # correlation row.
    "shopify_app_broad_write_scopes",
    "shopify_policy_missing",
}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M74E", db=db)


def _seed(db, ws, user):
    return demo_svc.seed_shopify(workspace_id=ws.id, actor_user_id=user.id, db=db)


def _cleanup(db, ws_id):
    demo_svc.clear_shopify(workspace_id=ws_id, db=db)


# ── 1. seed creates the full Shopify demo chain ──────────────────────────────

def test_seed_creates_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        assert res["seeded"] and res["created"]
        assert res["case_id"] and res["link_count"] > 0

        integ = demo_svc.get_shopify_demo_integration(ws.id, db_session)
        assert integ is not None and integ.provider == demo_svc.DEMO_PROVIDER_TAG

        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        # Correlatable risks AND deferred risks both appear.
        assert {
            "shopify_webhook_http",
            "shopify_webhook_high_risk_topic",
            "shopify_domain_ssl_missing",
            "shopify_domain_unverified",
        } <= rules
        assert _DEFERRED_FINDING_RULES <= rules

        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()
        etypes = {e.event_type for e in events}
        # Webhook + domain + shop activity present (no app_scopes/policy).
        assert {
            "shopify.webhook.updated",
            "shopify.domain.updated",
            "shopify.shop.updated",
        } <= etypes
        assert "shopify.app_scopes.updated" not in etypes
        assert all(not t.startswith("shopify.policy.") for t in etypes)

        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "shopify").all()
        assert any(s.signal_type == "shopify_activity_signal" for s in sigs)

        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "shopify").all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes
    finally:
        _cleanup(db_session, ws.id)


# ── 2. seeded findings carry webhook/domain/app-scope/policy evidence ───────

def test_seeded_evidence_shapes(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_shopify_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}
        assert by_rule["shopify_webhook_http"].evidence.get("endpoint_scheme") == "http"
        assert by_rule["shopify_webhook_high_risk_topic"].evidence.get("topic") == "orders/create"
        assert by_rule["shopify_domain_ssl_missing"].evidence.get("ssl_enabled") is False
        assert by_rule["shopify_domain_unverified"].evidence.get("verified") is False
        assert by_rule["shopify_app_broad_write_scopes"].evidence.get(
            "high_risk_write_scope_count") == 3
        assert by_rule["shopify_policy_missing"].evidence.get("policy_type") == "refund_policy"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. seeded correlations carry linked correlation signals ─────────────────

def test_correlations_have_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "shopify").all()
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


# ── 4. case report uses the "Shopify" provider label + Shopify evidence ─────

def test_case_report_provider_label(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        assert "Shopify" in blob
        lower = blob.lower()
        assert (
            "shopify_webhook_insecure_risk_activity" in lower
            or "shopify.webhook.updated" in lower
        )
        assert "shopify_webhook_http" in lower
        for phrase in _FORBIDDEN:
            assert phrase not in lower
    finally:
        _cleanup(db_session, ws.id)


# ── 5. timeline + graph build for the demo case (claim-safe) ────────────────

def test_timeline_and_graph_build(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session)
        graph = report_svc.build_case_evidence_graph(
            case_id=case_id, workspace_id=ws.id, db=db_session)
        assert timeline["timeline_items"]
        assert graph["nodes"]
        assert timeline["provider"] == "Shopify"
        blob = (
            json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        ).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 6. report/timeline/graph carry no raw secret / PII / order material ─────

def test_no_secret_material_in_report(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session)
        graph = report_svc.build_case_evidence_graph(
            case_id=case_id, workspace_id=ws.id, db=db_session)
        blob = (
            json.dumps(report, default=str)
            + json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        ).lower()
        for bad in (
            # Shopify access-token shapes + signing secrets.
            "shpat_", "shpss_", "shpca_", "shpapp_", "whsec_",
            # Generic OAuth / auth headers.
            "bearer ", "authorization", "id_token", "refresh_token",
            # Customer PII / orders / cards / carts / checkouts.
            "customer_email", "customer@example.com",
            "card number", "?session_id", "?secret=", "?token=",
            "?cart_token=",
        ):
            assert bad not in blob
        # No raw event payload keys leaked into the report.
        for k in ("arguments", "message", "path", "author", "body",
                  "signing_secret", "access_token"):
            # These keys must not appear as JSON metadata keys; checking
            # quoted form catches the leakage pattern.
            assert f'"{k}":' not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 7. clear removes Shopify demo artifacts only ────────────────────────────

def test_clear_removes_only_demo(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # A REAL (non-demo) Shopify integration + finding that must survive clear.
    ct, iv = encrypt_credentials({
        "shop_domain": "real-store.myshopify.com",
        "access_token": "shpat_real",
    })
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="shopify",
        display_name="real-shopify", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="shopify",
        finding_key="shopify_webhook_http:real#keep",
        severity="critical", title="Real Shopify risk (keep)", status="active",
        evidence={"rule": "shopify_webhook_http"}, remediation={"summary": "x"},
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    real_id = real.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_shopify(workspace_id=ws.id, db=db_session)

        # All Shopify demo artifacts gone.
        assert demo_svc.get_shopify_demo_integration(ws.id, db_session) is None
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.SHOPIFY_DEMO_CASE_SOURCE,
        ).count() == 0
        # The real non-demo finding is preserved.
        assert db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real_integ.id).delete(synchronize_session=False)
        db_session.commit()
        _cleanup(db_session, ws.id)


# ── 8. seed + clear are idempotent; status reflects state ───────────────────

def test_seed_clear_idempotent_and_status(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        assert demo_svc.get_shopify_status(ws.id, db_session)["seeded"] is False
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert demo_svc.get_shopify_status(ws.id, db_session)["seeded"] is True

        demo_svc.clear_shopify(workspace_id=ws.id, db=db_session)
        demo_svc.clear_shopify(workspace_id=ws.id, db=db_session)  # idempotent
        assert demo_svc.get_shopify_status(ws.id, db_session)["seeded"] is False
    finally:
        _cleanup(db_session, ws.id)
