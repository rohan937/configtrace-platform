"""M78G — Google Cloud security demo + QA hardening.

The Google Cloud incident demo seeds one coherent, clearly-marked synthetic
story on a hidden demo integration:

    Google Cloud configuration risks (IAM public member, firewall public admin
    ingress, Cloud Storage public-access-prevention disabled, Cloud SQL public
    network access, Cloud Run public invoker, GKE public control plane,
    long-lived user-managed service-account keys, Secret Manager auto-
    replication without CMEK) -> Google Cloud Audit Log activity
    (google_cloud.iam_policy.updated, google_cloud.firewall_rule.updated,
    google_cloud.storage_bucket.updated, google_cloud.sql_instance.updated,
    google_cloud.run_service.updated, google_cloud.gke_cluster.updated,
    google_cloud.service_account_key.created, google_cloud.secret.updated)
    -> Google Cloud activity signals -> Google Cloud risk × activity
    correlations -> a case.

These tests assert the seeded chain, the case report / timeline / graph
render with the "Google Cloud" provider label, claim discipline, demo-only
isolation of ``clear_google_cloud``, seed/clear idempotency + status,
capability matrix flip, and the rolled-forward expansion-framework pointer.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_service

_FORBIDDEN_CLAIMS = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]

# Google Cloud correlation types expected on the seeded story (M78F).
_EXPECTED_CORRELATION_TYPES = {
    "google_cloud_iam_risk_activity_correlation",
    "google_cloud_firewall_risk_activity_correlation",
    "google_cloud_storage_risk_activity_correlation",
    "google_cloud_sql_risk_activity_correlation",
    "google_cloud_run_risk_activity_correlation",
    "google_cloud_gke_risk_activity_correlation",
    "google_cloud_service_account_key_risk_activity_correlation",
    "google_cloud_secret_manager_risk_activity_correlation",
}

# Activity event types expected on the seeded story (M78D).
_EXPECTED_EVENT_TYPES = {
    "google_cloud.iam_policy.updated",
    "google_cloud.firewall_rule.updated",
    "google_cloud.storage_bucket.updated",
    "google_cloud.sql_instance.updated",
    "google_cloud.run_service.updated",
    "google_cloud.gke_cluster.updated",
    "google_cloud.service_account_key.created",
    "google_cloud.secret.updated",
}

# Finding rule keys expected on the seeded story (M78B/M78C).
_EXPECTED_FINDING_RULES = {
    "google_cloud_iam_public_member",
    "google_cloud_firewall_public_admin_ingress",
    "google_cloud_storage_public_access_prevention_disabled",
    "google_cloud_sql_public_network_access",
    "google_cloud_run_public_invoker",
    "google_cloud_gke_public_control_plane",
    "google_cloud_service_account_old_keys",
    "google_cloud_secret_manager_auto_replication_without_cmek",
}

# Signal types expected on the seeded story (M78E).
_EXPECTED_SIGNAL_TYPES = {
    "google_cloud_iam_policy_changed",
    "google_cloud_firewall_config_changed",
    "google_cloud_storage_bucket_changed",
    "google_cloud_sql_instance_changed",
    "google_cloud_run_service_changed",
    "google_cloud_gke_cluster_changed",
    "google_cloud_service_account_key_changed",
    "google_cloud_secret_config_changed",
}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M78G", db=db,
    )


def _seed(db, ws, user):
    return demo_svc.seed_google_cloud(
        workspace_id=ws.id, actor_user_id=user.id, db=db,
    )


def _cleanup(db, ws_id):
    demo_svc.clear_google_cloud(workspace_id=ws_id, db=db)


# ── 1. seed creates the full Google Cloud demo chain ─────────────────────────


def test_seed_creates_full_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        assert res["seeded"] and res["created"]
        assert res["case_id"] and res["link_count"] > 0

        integ = demo_svc.get_google_cloud_demo_integration(ws.id, db_session)
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

        # Every event uses provider=google_cloud source=google_cloud_audit_log.
        for e in events:
            assert e.provider == "google_cloud"
            assert e.source == "google_cloud_audit_log"

        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "google_cloud").all()
        sig_types = {s.signal_type for s in sigs}
        assert _EXPECTED_SIGNAL_TYPES <= sig_types

        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "google_cloud").all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes
    finally:
        _cleanup(db_session, ws.id)


# ── 2. seeded findings carry safe IAM / firewall / storage / SQL / Run / GKE /
#       service-account-key / Secret Manager evidence (no PII) ───────────────


def test_seeded_evidence_shapes(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_google_cloud_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        by_rule = {f.finding_key.split(":", 1)[0]: f for f in findings}

        iam_ev = by_rule["google_cloud_iam_public_member"].evidence
        assert iam_ev.get("project_id") == demo_svc.GOOGLE_CLOUD_DEMO_PROJECT_ID
        assert iam_ev.get("allusers_binding_present") is True
        assert "binding_count" in iam_ev

        fw_ev = by_rule["google_cloud_firewall_public_admin_ingress"].evidence
        assert fw_ev.get("firewall_rule_name") == demo_svc.GOOGLE_CLOUD_DEMO_FIREWALL_NAME
        assert fw_ev.get("admin_port") == 3389

        bucket_ev = by_rule[
            "google_cloud_storage_public_access_prevention_disabled"
        ].evidence
        assert bucket_ev.get("bucket_name") == demo_svc.GOOGLE_CLOUD_DEMO_BUCKET_NAME
        assert bucket_ev.get("public_access_prevention") == "inherited"

        sql_ev = by_rule["google_cloud_sql_public_network_access"].evidence
        assert sql_ev.get("sql_instance_name") == demo_svc.GOOGLE_CLOUD_DEMO_SQL_INSTANCE_NAME
        assert sql_ev.get("ipv4_enabled") is True
        assert sql_ev.get("require_ssl") is False

        run_ev = by_rule["google_cloud_run_public_invoker"].evidence
        assert run_ev.get("run_service_name") == demo_svc.GOOGLE_CLOUD_DEMO_RUN_SERVICE_NAME
        assert run_ev.get("allusers_invoker_present") is True

        gke_ev = by_rule["google_cloud_gke_public_control_plane"].evidence
        assert gke_ev.get("gke_cluster_name") == demo_svc.GOOGLE_CLOUD_DEMO_GKE_CLUSTER_NAME
        assert gke_ev.get("private_cluster") is False

        sa_ev = by_rule["google_cloud_service_account_old_keys"].evidence
        assert "user_managed_key_count" in sa_ev
        assert "user_managed_key_old_count" in sa_ev

        sec_ev = by_rule[
            "google_cloud_secret_manager_auto_replication_without_cmek"
        ].evidence
        assert sec_ev.get("auto_replicated_without_cmek_count", 0) >= 1

        # No PII in evidence — never store principal emails / SA emails /
        # display names / caller / UPN / raw IPs / secret values /
        # database names / private keys / kubeconfig / pod specs.
        for f in findings:
            for forbidden in (
                "principal_email", "service_account_email", "user_email",
                "display_name", "caller", "upn", "raw_ip",
                "secret_value", "secret_name", "database_name",
                "database_user", "database_password", "connection_string",
                "env_var_value", "kubeconfig", "private_key",
                "private_key_id", "access_token", "refresh_token",
            ):
                assert forbidden not in f.evidence, (
                    f"forbidden key {forbidden!r} in {f.finding_key} evidence"
                )
    finally:
        _cleanup(db_session, ws.id)


# ── 3. seeded correlations have linked correlation signals ──────────────────


def test_correlations_have_linked_signals(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "google_cloud").all()
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


# ── 4. case report uses the "Google Cloud" provider label + GCP evidence ────


def test_case_report_provider_label(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        assert "Google Cloud" in blob
        lower = blob.lower()
        assert (
            "google_cloud_iam_risk_activity_correlation" in lower
            or "google_cloud.iam_policy.updated" in lower
        )
        assert "google_cloud_iam_public_member" in lower
        for phrase in _FORBIDDEN_CLAIMS:
            assert phrase not in lower
    finally:
        _cleanup(db_session, ws.id)


# ── 5. timeline + graph build for the Google Cloud demo case (claim-safe) ───


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
        assert timeline["provider"] == "Google Cloud"
        blob = (
            json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        ).lower()
        for phrase in _FORBIDDEN_CLAIMS:
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
        # Google-specific secret / token / payload shapes that must NEVER
        # appear in demo evidence.
        for bad in (
            "bearer ", "id_token", "refresh_token", "access_token",
            "ya29.",  # OAuth access token prefix
            "-----begin private key-----",
            "-----begin rsa private",
            "-----begin certificate-----",
            "private_key_id",
            "?key=", "&key=",
            "customer@example.com", "user@example.com",
            ".iam.gserviceaccount.com",  # SA email suffix — never embed real SAs
        ):
            assert bad not in blob, f"forbidden substring {bad!r} present"
        # No raw event-payload-shaped keys leaked into the report.
        for k in (
            "principal_email", "service_account_email", "user_email",
            "caller_ip", "client_ip", "raw_ip", "user_agent",
            "authenticationinfo", "authorizationinfo", "protopayload",
            "requestbody", "responsebody",
            "secret_value", "private_key", "kubeconfig",
            "database_password", "connection_string",
            "env_var_value", "env_var_name",
        ):
            assert f'"{k}":' not in blob, f"forbidden quoted key {k!r} present"
    finally:
        _cleanup(db_session, ws.id)


# ── 7. clear removes Google Cloud demo artifacts only ───────────────────────


def test_clear_removes_only_demo(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # A REAL (non-demo) Google Cloud integration + finding that must survive clear.
    ct, iv = encrypt_credentials({
        "type": "service_account", "project_id": "real-project",
        "private_key_id": "real-key-id",
        "private_key": "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n",
        "client_email": "real@real-project.iam.gserviceaccount.com",
        "client_id": "1234567890",
    })
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="google_cloud",
        display_name="real-google-cloud", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="google_cloud",
        finding_key="google_cloud_iam_public_member:real#keep",
        severity="high", title="Real Google Cloud risk (keep)", status="active",
        evidence={"rule": "google_cloud_iam_public_member"},
        remediation={"summary": "x"},
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    real_id = real.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_google_cloud(workspace_id=ws.id, db=db_session)

        # All Google Cloud demo artifacts gone.
        assert demo_svc.get_google_cloud_demo_integration(
            ws.id, db_session
        ) is None
        assert db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext
            == demo_svc.GOOGLE_CLOUD_DEMO_CASE_SOURCE,
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
        assert demo_svc.get_google_cloud_status(
            ws.id, db_session
        )["seeded"] is False
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
        assert demo_svc.get_google_cloud_status(
            ws.id, db_session
        )["seeded"] is True

        demo_svc.clear_google_cloud(workspace_id=ws.id, db=db_session)
        # Idempotent — second clear is a no-op.
        demo_svc.clear_google_cloud(workspace_id=ws.id, db=db_session)
        assert demo_svc.get_google_cloud_status(
            ws.id, db_session
        )["seeded"] is False
    finally:
        _cleanup(db_session, ws.id)


# ── 9. clear does not remove a different provider's demo (Azure) ────────────


def test_clear_google_cloud_leaves_other_provider_demo(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        # Seed both demos
        demo_svc.seed_azure(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session,
        )
        demo_svc.seed_google_cloud(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session,
        )
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is True
        assert demo_svc.get_google_cloud_status(
            ws.id, db_session
        )["seeded"] is True

        # Clear Google Cloud only
        demo_svc.clear_google_cloud(workspace_id=ws.id, db=db_session)

        # GCP gone, Azure still present
        assert demo_svc.get_google_cloud_status(
            ws.id, db_session
        )["seeded"] is False
        assert demo_svc.get_azure_status(ws.id, db_session)["seeded"] is True
    finally:
        demo_svc.clear_azure(workspace_id=ws.id, db=db_session)
        _cleanup(db_session, ws.id)


# ── 10. capability matrix + expansion framework reflect M78G ────────────────


def test_capability_matrix_marks_google_cloud_demo_ready():
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("google_cloud")
    assert cap is not None
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True
    # Maturity remains partial — GCP is not in the canonical 8.
    assert cap.maturity == "partial"
    # Notes mention demo-ready.
    assert "demo-ready" in cap.notes.lower() or "demo-ready" in cap.notes


def test_expansion_framework_next_stage_is_m78h():
    """Rolled forward in M79B: Twilio Core Security Foundation complete → M79C."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M79C" in stage
    assert "Twilio" in stage
    # Google Cloud arc is closed; no M78x in planned_next_stage.
    assert "M78G" not in stage
    assert "M78I" not in stage


# ── 11. demo case copy is review-safe (no overclaim) ────────────────────────


def test_demo_case_copy_review_safe(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])).first()
        text = (case.title + " " + (case.summary or "")).lower()
        for phrase in _FORBIDDEN_CLAIMS:
            assert phrase not in text
        # Must use review-safe wording.
        assert "evidence for review" in text or "may require review" in text
        assert "does not confirm" in text
    finally:
        _cleanup(db_session, ws.id)


# ── 12. demo finding evidence carries no raw IAM bindings / secret values ──


def test_demo_finding_evidence_has_no_raw_payloads(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_google_cloud_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id).all()
        blob = json.dumps([f.evidence for f in findings]).lower()
        # No service account private keys.
        for bad in (
            "-----begin private key-----",
            "-----begin rsa private",
            "private_key_id",
            "ya29.",
            ".iam.gserviceaccount.com",
        ):
            assert bad not in blob
        # No raw IAM bindings (just counts + booleans).
        assert '"bindings":' not in blob
        assert '"members":' not in blob
        # No raw secret material.
        assert "secret_value" not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 13. activity events use only allowlisted metadata keys ─────────────────


def test_activity_events_only_use_allowlisted_metadata(test_user, db_session):
    from app.services.security_activity_event_service import (
        ALLOWED_METADATA_KEYS,
    )
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_google_cloud_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id).all()
        assert events
        for e in events:
            md = e.event_metadata or {}
            assert isinstance(md, dict)
            for k in md.keys():
                assert k in ALLOWED_METADATA_KEYS, (
                    f"event {e.event_type!r} carries forbidden key {k!r}"
                )
    finally:
        _cleanup(db_session, ws.id)


# ── 14. frontend cases page demo card includes Google Cloud ────────────────


def test_fe_cases_page_has_google_cloud_demo_card():
    fe_path = Path(__file__).resolve().parents[2] / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
    if not fe_path.exists():
        # Frontend may not be mounted in the docker test runner; skip safely.
        import pytest
        pytest.skip("frontend not mounted")
    text = fe_path.read_text()
    assert 'provider: "google_cloud"' in text
    assert "Load Google Cloud security demo" in text
    assert "Clear Google Cloud demo" in text


# ── 15. frontend demo script mentions Google Cloud ─────────────────────────


def test_fe_demo_script_mentions_google_cloud():
    fe_path = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "securityDemoScript.ts"
    if not fe_path.exists():
        import pytest
        pytest.skip("frontend not mounted")
    text = fe_path.read_text()
    assert "Google Cloud" in text


# ── 16. M78A/B/C/D/E/F regression smoke ────────────────────────────────────


def test_m78f_correlation_helpers_still_present():
    """Sanity: M78F builder/map both still exist (we depend on them in seed)."""
    from app.services import security_signal_correlation_service as corr_svc
    assert hasattr(corr_svc, "GOOGLE_CLOUD_CORRELATION_RULES")
    assert hasattr(corr_svc, "build_google_cloud_correlation")
    # Every rule that we wire up in the seed must be in the M78F map.
    for rule in _EXPECTED_FINDING_RULES:
        assert rule in corr_svc.GOOGLE_CLOUD_CORRELATION_RULES, (
            f"M78F correlation map missing rule {rule!r}"
        )


def test_m78e_signal_builder_still_present():
    """Sanity: M78E _build_signal is what we use; one signal per event type."""
    from app.services import google_cloud_activity_signal_service as gcp_sig
    assert hasattr(gcp_sig, "_build_signal")
    # Every expected event type must map to a known M78E pattern.
    for ev in _EXPECTED_EVENT_TYPES:
        assert ev in gcp_sig._EVENT_PATTERNS, (
            f"M78E pattern map missing event type {ev!r}"
        )


# ── 17. router admin/owner guard wiring (smoke) ────────────────────────────


def test_router_dispatches_google_cloud_provider():
    """The /security/incident-demo/* endpoints must dispatch provider=google_cloud."""
    from app.routers import security as router_module
    src = router_module.__file__
    text = Path(src).read_text()
    assert 'prov == "google_cloud"' in text
    assert "security_incident_demo_service.seed_google_cloud" in text
    assert "security_incident_demo_service.clear_google_cloud" in text
    assert "security_incident_demo_service.get_google_cloud_status" in text
