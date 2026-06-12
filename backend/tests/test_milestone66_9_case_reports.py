"""M66.9 — Case Evidence Report export.

A metadata-only investigation packet. These tests assert it summarizes linked
evidence, leaks no raw payloads/IPs/secrets, uses calibrated wording, and is
strictly workspace-scoped.

  1. Report is workspace-scoped (own case → 200, cross-workspace → 404).
  2. Report includes linked signal/correlation/activity/risk summaries.
  3. Report leaks no forbidden raw fields (raw IP, actor_ip, evidence/remediation,
     tokens/secrets); source IP appears only as a hash.
  4. Report claim wording contains no forbidden breach/attacker/compromise claims.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.services import security_activity_event_service as activity_svc
from app.services import security_case_service as case_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_signal_service as signal_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
REPO = "acme/repo"
RAW_IP = "203.0.113.9"


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M66.9", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"github_token": "x", "repo_owner": "acme", "repo_name": "repo"})
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="github", display_name="github",
                    encrypted_credentials=ct, credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _repo(db, integ, user):
    r = Resource(integration_id=integ.id, user_id=user.id, provider_resource_type="github_repo",
                 provider_resource_id=REPO, display_name=REPO, is_active=True)
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="github",
        finding_key=f"github_webhook_http:{uuid.uuid4().hex[:8]}", severity="high",
        title="webhook risk", resource_id=res.id, description="d",
        evidence={"rule": "github_webhook_http", "secret_value": "shhh"},
        remediation={"summary": "fix"})


def _activity(db, ws_id, integ_id):
    norm = activity_svc.normalize_activity_event(
        provider="github", source="audit_log", event_type="github.webhook.updated",
        occurred_at=datetime.now(timezone.utc), provider_event_id="doc-xyz",
        actor_id="mallory", resource_type="repository", resource_id=REPO,
        source_ip=RAW_IP,  # stored only as a salted hash
        metadata={"action": "hook.config_changed", "repository": REPO})
    _, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _case_with_evidence(db, user):
    """Build evidence + a case linking signal/correlation/finding/activity."""
    ws = _ws(user, db)
    integ = _integ(db, user, ws.id)
    res = _repo(db, integ, user)
    _finding(db, ws, integ, res)
    _activity(db, ws.id, integ.id)
    corr_svc.generate_github_correlations(workspace_id=ws.id, db=db)
    items, _ = corr_svc.list_correlations(workspace_id=ws.id, db=db)
    correlation = items[0]
    signal_svc.generate_github_incident_signals(workspace_id=ws.id, db=db)
    case = case_svc.create_case_from_correlation(
        workspace_id=ws.id, user_id=user.id, correlation=correlation, db=db)
    return ws, case


def _cleanup(db, ws_id):
    db.query(SecurityCaseLink).filter(SecurityCaseLink.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityCase).filter(SecurityCase.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecuritySignalCorrelation).filter(SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── 1. scoping ────────────────────────────────────────────────────────────────

def test_report_workspace_scoped(client, test_user, db_session):
    ws, case = _case_with_evidence(db_session, test_user)
    try:
        resp = client.get(f"/security/cases/{case.id}/report")
        assert resp.status_code == 200
        assert resp.json()["title"] == "ConfigTrace Case Evidence Report"
    finally:
        _cleanup(db_session, ws.id)


def test_report_404_cross_workspace(client, test_user, db_session):
    other = _new_user(db_session, "other")
    ws_b, case_b = _case_with_evidence(db_session, other)
    try:
        resp = client.get(f"/security/cases/{case_b.id}/report")
        assert resp.status_code == 404
    finally:
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 2. content ────────────────────────────────────────────────────────────────

def test_report_includes_evidence_summaries(client, test_user, db_session):
    ws, case = _case_with_evidence(db_session, test_user)
    try:
        body = client.get(f"/security/cases/{case.id}/report").json()
        assert len(body["risks"]) >= 1
        assert len(body["activity_events"]) >= 1
        assert len(body["correlations"]) >= 1
        assert len(body["signals"]) >= 1  # correlation creates a correlation signal
        assert len(body["timeline"]) >= 2
        assert body["review_checklist"]
        assert body["risks"][0]["rule"] == "github_webhook_http"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. privacy ────────────────────────────────────────────────────────────────

def test_report_leaks_no_raw_fields(client, test_user, db_session):
    ws, case = _case_with_evidence(db_session, test_user)
    try:
        body = client.get(f"/security/cases/{case.id}/report").json()
        blob = json.dumps(body)
        # No raw IP / raw IP field / secrets / evidence-remediation blobs.
        assert RAW_IP not in blob
        assert "actor_ip" not in blob
        assert "secret_value" not in blob and "shhh" not in blob
        assert "remediation" not in blob
        assert "\"evidence\"" not in blob
        # Source IP is present ONLY as a hash on the activity event.
        act = body["activity_events"][0]
        assert act["source_ip_hash"]
        assert act["source_ip_hash"] != RAW_IP
        assert act["provider_event_id"] == "doc-xyz"  # pointer id only
    finally:
        _cleanup(db_session, ws.id)


# ── 4. claim discipline ───────────────────────────────────────────────────────

def test_report_has_no_forbidden_claims(client, test_user, db_session):
    ws, case = _case_with_evidence(db_session, test_user)
    try:
        body = client.get(f"/security/cases/{case.id}/report").json()
        blob = json.dumps(body).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in blob, f"forbidden phrase {phrase!r} in report"
        assert "evidence for review" in body["claim_note"].lower()
        assert "does not automatically confirm" in body["claim_note"].lower()
    finally:
        _cleanup(db_session, ws.id)
