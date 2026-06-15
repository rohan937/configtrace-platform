"""M77G — Azure security demo + QA hardening.

The Azure incident demo seeds one coherent, clearly-marked synthetic story
on a hidden demo integration:

    Azure configuration risks (NSG public admin ingress, Storage public blob
    access, Key Vault public network access, broad Owner role assignment at
    subscription scope) -> Azure Activity Log activity (azure.nsg_rule.updated,
    azure.storage_account.updated, azure.key_vault.updated,
    azure.role_assignment.created) -> Azure activity signals -> Azure risk x
    activity correlations -> a case.

These tests assert the seeded chain, the case report / timeline / graph
render with the "Azure" provider label, claim discipline, demo-only isolation
of ``clear_azure``, and seed/clear idempotency + status.
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

# Azure correlation types we expect on the seeded story.
_EXPECTED_CORRELATION_TYPES = {
    "azure_nsg_exposure_activity_correlation",
    "azure_storage_risk_activity_correlation",
    "azure_key_vault_risk_activity_correlation",
    "azure_role_assignment_risk_activity_correlation",
}

# Activity event types we expect on the seeded story.
_EXPECTED_EVENT_TYPES = {
    "azure.nsg_rule.updated",
    "azure.storage_account.updated",
    "azure.key_vault.updated",
    "azure.role_assignment.created",
}

# Finding rule keys we expect on the seeded story.
_EXPECTED_FINDING_RULES = {
    "azure_nsg_public_admin_ingress",
    "azure_storage_public_blob_access",
    "azure_key_vault_public_network_access",
    "azure_role_assignment_broad_privilege",
}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M77G", db=db,
    )


def _seed(db, ws, user):
    return demo_svc.seed_azure(workspace_id=ws.id, actor_user_id=user.id, db=db)


def _cleanup(db, ws_id):
    demo_svc.clear_azure(workspace_id=ws_id, db=db)


# ── 1. seed creates the full Azure demo chain ────────────────────────────────


def test_seed_creates_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        assert res["seeded"] and res["created"]
        assert res["case_id"] and res["link_count"] > 0

        integ = demo_svc.get_azure_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG

        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert _EXPECTED_FINDING_RULES <= rules

        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()
        etypes = {e.event_type for e in events}
        assert _EXPECTED_EVENT_TYPES <= etypes

        # Every event uses provider=azure source=azure_activity_log.
        for e in events:
            assert e.provider == "azure"
            assert e.source == "azure_activity_log"

        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "azure").all()
        sig_types = {s.signal_type for s in sigs}
        # M77E signal types should appear for each anchor event.
        assert "azure_network_exposure_changed" in sig_types
        assert "azure_storage_config_changed" in sig_types
        assert "azure_key_vault_config_changed" in sig_types
        assert "azure_role_assignment_changed" in sig_types

        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "azure").all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes
    finally:
        _cleanup(db_session, ws.id)


# ── 2. seeded findings carry safe NSG/Storage/KV/role-assignment evidence ───


def test_seeded_evidence_shapes(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_azure_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}

        nsg_ev = by_rule["azure_nsg_public_admin_ingress"].evidence
        assert nsg_ev.get("nsg_name") == demo_svc.AZURE_DEMO_NSG_NAME
        assert nsg_ev.get("resource_group") == demo_svc.AZURE_DEMO_RESOURCE_GROUP
        assert nsg_ev.get("admin_port") == 3389

        storage_ev = by_rule["azure_storage_public_blob_access"].evidence
        assert storage_ev.get("account_name") == demo_svc.AZURE_DEMO_STORAGE_NAME
        assert storage_ev.get("allow_blob_public_access") is True

        kv_ev = by_rule["azure_key_vault_public_network_access"].evidence
        assert kv_ev.get("vault_name") == demo_svc.AZURE_DEMO_VAULT_NAME
        assert kv_ev.get("public_network_access") == "Enabled"

        role_ev = by_rule["azure_role_assignment_broad_privilege"].evidence
        assert role_ev.get("role_definition_name") == "Owner"
        assert role_ev.get("scope_type") == "subscription"
        # No PII in evidence — never store principal_id / email / display_name.
        for forbidden in ("principal_id", "principal_email", "display_name",
                          "caller", "upn"):
            assert forbidden not in role_ev
    finally:
        _cleanup(db_session, ws.id)


# ── 3. seeded correlations have linked correlation signals ──────────────────


def test_correlations_have_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "azure").all()
        assert corrs
        for c in corrs:
            assert c.linked_finding_id is not None
            assert c.linked_activity_event_id is not None
            assert c.linked_signal_id is not None
            sig = db_session.query(SecurityIncidentSignal).filter(
                SecurityIncidentSignal.id == c.linked_signal_id).first()
            assert sig is not None
            assert sig.evidence_level == "correlation"
    finally:
        _cleanup(db_session, ws.id)


# ── 4. case report uses the "Azure" provider label + Azure evidence ─────────


def test_case_report_provider_label(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        assert "Azure" in blob
        lower = blob.lower()
        assert (
            "azure_nsg_exposure_activity_correlation" in lower
            or "azure.nsg_rule.updated" in lower
        )
        assert "azure_nsg_public_admin_ingress" in lower
        for phrase in _FORBIDDEN:
            assert phrase not in lower
    finally:
        _cleanup(db_session, ws.id)


# ── 5. timeline + graph build for the Azure demo case (claim-safe) ──────────


def test_timeline_and_graph_build(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        graph = report_svc.build_case_evidence_graph(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        assert timeline["timeline_items"]
        assert graph["nodes"]
        assert timeline["provider"] == "Azure"
        blob = (
            json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        ).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 6. report/timeline/graph carry no raw PII / secrets / payloads ──────────


def test_no_secret_material_in_report(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        graph = report_svc.build_case_evidence_graph(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        blob = (
            json.dumps(report, default=str)
            + json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        ).lower()
        for bad in (
            # Azure access-token shapes + key prefixes
            "bearer ", "id_token", "refresh_token",
            "accountkey=", "?sv=", "endpointsuffix=", "connectionstring",
            # PII / customer / principal identifiers
            "customer@example.com", "user@example.com",
            "?session_id=", "?token=", "?secret=",
        ):
            assert bad not in blob, f"forbidden substring {bad!r} present"
        # No raw event-payload-shaped keys leaked into the report.
        for k in (
            "caller", "claims", "authorization", "properties", "httprequest",
            "tenantid", "principal_id", "object_id", "ip_address",
            "client_secret", "access_token",
        ):
            assert f'"{k}":' not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 7. clear removes Azure demo artifacts only ──────────────────────────────


def test_clear_removes_only_demo(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # A REAL (non-demo) Azure integration + finding that must survive clear.
    ct, iv = encrypt_credentials({
        "tenant_id": "real-tenant", "client_id": "real-client",
        "client_secret": "real-secret",
        "subscription_id": "real-subscription",
    })
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="azure",
        display_name="real-azure", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="azure",
        finding_key="azure_nsg_public_admin_ingress:real#keep",
        severity="critical", title="Real Azure risk (keep)", status="active",
        evidence={"rule": "azure_nsg_public_admin_ingress"},
        remediation={"summary": "x"},
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    real_id = real.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_azure(workspace_id=ws.id, db=db_session)

        # All Azure demo artifacts gone.
        assert demo_svc.get_azure_demo_integration(ws.id, db_session) is None
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.AZURE_DEMO_CASE_SOURCE,
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
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is False
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is True

        demo_svc.clear_azure(workspace_id=ws.id, db=db_session)
        demo_svc.clear_azure(workspace_id=ws.id, db=db_session)  # idempotent
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is False
    finally:
        _cleanup(db_session, ws.id)


# ── 9. clear does not remove a different provider's demo (Shopify) ──────────


def test_clear_azure_leaves_other_provider_demo(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        # Seed both demos
        demo_svc.seed_shopify(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        demo_svc.seed_azure(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert demo_svc.get_shopify_status(ws.id, db_session)["seeded"] is True
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is True

        # Clear Azure only
        demo_svc.clear_azure(workspace_id=ws.id, db=db_session)

        # Azure gone, Shopify still present
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is False
        assert demo_svc.get_shopify_status(ws.id, db_session)["seeded"] is True
    finally:
        demo_svc.clear_shopify(workspace_id=ws.id, db=db_session)
        _cleanup(db_session, ws.id)


# ── 10. capability matrix + expansion framework reflect M77G ────────────────


def test_capability_matrix_marks_azure_demo_ready():
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("azure")
    assert cap is not None
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True
    # Maturity remains partial — Azure is not in the canonical 8.
    assert cap.maturity == "partial"


def test_expansion_framework_next_stage_is_m77h():
    """Rolled forward in M78B: GCP core security foundation landed → M78C."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M78C" in stage


# ── 11. demo case copy is review-safe (no overclaim) ────────────────────────


def test_demo_case_copy_review_safe(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])).first()
        text = (case.title + " " + (case.summary or "")).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in text
        # Must use review-safe wording.
        assert "evidence for review" in text or "may require review" in text
        assert "does not confirm" in text
    finally:
        _cleanup(db_session, ws.id)


# ── 12. M77A/B/C/D/E/F regression smoke ─────────────────────────────────────


def test_m77_arc_capabilities_intact():
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("azure")
    assert cap is not None
    # All Azure security capabilities through M77G should be True now.
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True


def test_m77b_rules_still_registered():
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert "azure_nsg_public_admin_ingress" in KNOWN_RULE_KEYS
    assert "azure_role_assignment_broad_privilege" in KNOWN_RULE_KEYS


def test_m77f_correlation_rules_still_registered():
    from app.services.security_signal_correlation_service import (
        AZURE_CORRELATION_RULES,
    )
    assert len(AZURE_CORRELATION_RULES) == 20
