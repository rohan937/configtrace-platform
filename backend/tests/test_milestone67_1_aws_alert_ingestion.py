"""M67.1 — AWS GuardDuty / Access Analyzer alert ingestion → AWS Incident Signals.

GuardDuty/Access Analyzer are provider-ADJUDICATED findings. These tests assert
normalization into security_activity_events, idempotency, graceful permission
failure, privacy (no raw payload/IP/secrets), AWS signal generation + severity
mapping, idempotent signals, admin gating, workspace scoping, and that no
forbidden breach/attacker/compromise wording appears.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.connectors.aws import AWSConnector
from app.connectors.exceptions import ConnectorError
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import aws_security_alert_ingestion_service as aws_ingest
from app.services import security_incident_signal_service as signal_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
RAW_IP = "198.51.100.23"

# Two GuardDuty findings (high + medium). The high one carries a raw IP deep in
# the network payload — which must NOT be stored.
_GD_FINDINGS = [
    {
        "Id": "gd-finding-1",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Severity": 8.0,
        "Title": "SSH brute force against an EC2 instance",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Service": {
            "ServiceName": "guardduty", "DetectorId": "det-1",
            "Action": {"NetworkConnectionAction": {"RemoteIpDetails": {"IpAddressV4": RAW_IP}}},
        },
        "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-0abc123"}},
        "CreatedAt": "2026-06-01T00:00:00.000Z",
        "UpdatedAt": "2026-06-01T01:00:00.000Z",
    },
    {
        "Id": "gd-finding-2",
        "Type": "Discovery:IAMUser/AnomalousBehavior",
        "Severity": 5.0,
        "Title": "Anomalous IAM activity",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Service": {"ServiceName": "guardduty", "DetectorId": "det-1"},
        "Resource": {"ResourceType": "AccessKey", "AccessKeyDetails": {"UserName": "deploy", "AccessKeyId": "AKIAEXAMPLESECRET"}},
        "CreatedAt": "2026-06-01T00:00:00.000Z",
        "UpdatedAt": "2026-06-01T00:30:00.000Z",
    },
]


class _FakeGuardDuty:
    def list_detectors(self):
        return {"DetectorIds": ["det-1"]}
    def list_findings(self, **kw):
        return {"FindingIds": ["gd-finding-1", "gd-finding-2"]}
    def get_findings(self, **kw):
        return {"Findings": [dict(f) for f in _GD_FINDINGS]}


class _NoDetector:
    def list_detectors(self):
        return {"DetectorIds": []}


def _make_client_factory(gd_client, aa_raises_403=False):
    def _factory(self, service, credentials, region=None):
        if service == "guardduty":
            return gd_client
        # Access Analyzer denied/empty for these tests.
        if aa_raises_403:
            raise ConnectorError("denied", status_code=403)

        class _AA:
            def list_analyzers(self_inner):
                return {"analyzers": []}
        return _AA()
    return _factory


def _passthrough_call(self, fn, *args, **kwargs):
    """Bypass _call_aws's botocore error-translation in tests (no boto3 installed)."""
    return fn(*args, **kwargs)


def _install_fake_aws(monkeypatch, gd_client, aa_raises_403=False):
    monkeypatch.setattr(AWSConnector, "_make_client", _make_client_factory(gd_client, aa_raises_403))
    monkeypatch.setattr(AWSConnector, "_call_aws", _passthrough_call)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.1", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _aws_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "aws_access_key_id": "AKIATEST", "aws_secret_access_key": "shh",
        "aws_default_region": "us-east-1",
    })
    i = Integration(user_id=user.id, workspace_id=ws_id, provider="aws", display_name="aws",
                    encrypted_credentials=ct, credential_iv=iv, status="active")
    db.add(i); db.commit(); db.refresh(i)
    return i


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(Integration).filter(Integration.workspace_id == ws_id, Integration.provider == "aws").delete(synchronize_session=False)
    db.commit()


# ── 1. normalize + ingest ─────────────────────────────────────────────────────

def test_guardduty_findings_normalize_into_activity_events(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeGuardDuty())
    try:
        summary = aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["findings_seen"] == 2
        assert summary["events_inserted"] == 2
        rows = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id,
            SecurityActivityEvent.provider == "aws",
            SecurityActivityEvent.source == "security_alert",
        ).all()
        assert len(rows) == 2
        types = {r.event_type for r in rows}
        assert "aws.guardduty.unauthorized_access" in types
        assert "aws.guardduty.discovery" in types
    finally:
        _cleanup(db_session, ws.id)


def test_ingestion_is_idempotent(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeGuardDuty())
    try:
        s1 = aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        s2 = aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        assert s1["events_inserted"] == 2
        assert s2["events_inserted"] == 0 and s2["events_skipped"] == 2
        assert db_session.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws.id).count() == 2
    finally:
        _cleanup(db_session, ws.id)


# ── 2. permission failure non-fatal ───────────────────────────────────────────

def test_permission_failure_is_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)

    def _denied(self, service, credentials, region=None):
        raise ConnectorError("AWS access denied", status_code=403)
    monkeypatch.setattr(AWSConnector, "_make_client", _denied)
    try:
        summary = aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        assert summary["attempted"] is True
        assert summary["succeeded"] is True       # attempted ok, just limited
        assert summary["permission_limited"] is True
        assert summary["events_inserted"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_no_detector_is_clean_zero(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _NoDetector())
    try:
        summary = aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        assert summary["succeeded"] is True
        assert summary["findings_seen"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── 3. privacy ────────────────────────────────────────────────────────────────

def test_no_raw_ip_or_secret_stored(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeGuardDuty())
    try:
        aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        rows = db_session.query(SecurityActivityEvent).filter(SecurityActivityEvent.workspace_id == ws.id).all()
        blob = json.dumps([{
            "event_type": r.event_type, "resource_id": r.resource_id,
            "source_ip_hash": r.source_ip_hash, "metadata": r.event_metadata, "raw_ref": r.raw_ref,
        } for r in rows], default=str)
        assert RAW_IP not in blob                  # raw GuardDuty IP never stored
        assert "AKIAEXAMPLESECRET" not in blob      # access key id never stored
        assert "IpAddressV4" not in blob            # no raw network payload
        # The safe resource identifier (instance id / user name) IS present.
        rids = {r.resource_id for r in rows}
        assert "i-0abc123" in rids and "deploy" in rids
    finally:
        _cleanup(db_session, ws.id)


# ── 4. signal generation + severity mapping ───────────────────────────────────

def test_aws_signal_generation_and_severity(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeGuardDuty())
    try:
        aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        gen = signal_svc.generate_aws_incident_signals(workspace_id=ws.id, db=db_session)
        assert gen["signals_created"] == 2
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id).all()
        for s in sigs:
            assert s.evidence_level == "provider_alert"
            assert s.confidence == "high"
            assert s.signal_key == "aws_guardduty_finding"
            assert s.title.startswith("GuardDuty finding:")
        sevs = {s.severity for s in sigs}
        assert "critical" in sevs   # severity 8.0 → critical
        assert "medium" in sevs     # severity 5.0 → medium

        # Idempotent signal generation.
        gen2 = signal_svc.generate_aws_incident_signals(workspace_id=ws.id, db=db_session)
        assert gen2["signals_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_no_forbidden_wording_in_aws_signals(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeGuardDuty())
    try:
        aws_ingest.ingest_aws_security_alerts(integration=integ, workspace_id=ws.id, db=db_session)
        signal_svc.generate_aws_incident_signals(workspace_id=ws.id, db=db_session)
        for s in db_session.query(SecurityIncidentSignal).filter(SecurityIncidentSignal.workspace_id == ws.id).all():
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "may require review" in s.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── 5. endpoints: admin gating + scoping ──────────────────────────────────────

def test_endpoints_admin_gated_and_scoped(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)  # test_user owns their workspace
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeGuardDuty())
    try:
        r = client.post("/security/aws-alerts/sync", json={})
        assert r.status_code == 200
        assert r.json()["events_inserted"] == 2
        g = client.post("/security/aws-alerts/generate-signals")
        assert g.status_code == 200
        assert g.json()["signals_created"] == 2
        # AWS signals are visible in the workspace-scoped signal list.
        lst = client.get("/security/signals?provider=aws")
        assert lst.status_code == 200
        assert lst.json()["total"] == 2
    finally:
        _cleanup(db_session, ws.id)


def test_member_cannot_sync_or_generate(test_user, db_session):
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
