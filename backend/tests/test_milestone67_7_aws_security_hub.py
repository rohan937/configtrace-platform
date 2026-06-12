"""M67.7 — AWS Security Hub findings ingestion + signal generation.

Security Hub (ASFF) findings are provider-reported evidence normalized into the
shared ``security_activity_events`` spine (provider=aws, source=security_hub),
and optionally promoted to AWS Incident Signals (evidence_level="provider_alert",
confidence="high"). These tests assert normalization, finding-Id idempotency,
severity mapping, IAM/S3/EC2/KMS/vendor type mapping, safe fallback, privacy (no
raw JSON / secrets / tokens / raw IPs), non-fatal permission failure, signal
generation + idempotency, workspace scoping, admin gating, and claim discipline.
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
from app.services import aws_security_hub_ingestion_service as sh_ingest
from app.services import security_incident_signal_service as signal_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
RAW_IP = "198.51.100.23"
SECRET_VALUE = "AKIAEXAMPLESECRETVALUE9999"
_ALLOWED_SIGNAL_META = {
    "event_type", "finding_type", "finding_title", "severity_label",
    "product_name", "account_id", "region", "workflow_status", "compliance_status",
}


# ── fake AWS plumbing ─────────────────────────────────────────────────────────

class _FakeSecurityHub:
    def __init__(self, findings, raise_403=False):
        self._findings = findings
        self._raise_403 = raise_403

    def get_findings(self, **kwargs):
        if self._raise_403:
            raise ConnectorError("AccessDenied", status_code=403)
        return {"Findings": self._findings, "NextToken": None}


def _make_client_factory(sh_client):
    def _factory(self, service, credentials, region=None):
        if service == "securityhub":
            return sh_client
        class _Other:  # pragma: no cover
            pass
        return _Other()
    return _factory


def _passthrough_call(self, fn, *args, **kwargs):
    return fn(*args, **kwargs)


def _install_fake_aws(monkeypatch, sh_client):
    monkeypatch.setattr(AWSConnector, "_make_client", _make_client_factory(sh_client))
    monkeypatch.setattr(AWSConnector, "_call_aws", _passthrough_call)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.7", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _aws_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="aws",
        display_name="aws", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _finding(fid, *, product="Security Hub", resource_type="AwsS3Bucket",
             severity_label="HIGH", types=None, with_secrets=True):
    f = {
        "Id": fid,
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": product,
        "CompanyName": "AWS",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
        "AwsAccountId": "123456789012",
        "Region": "us-east-1",
        "Types": types or ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": "2026-06-12T09:00:00.000Z",
        "UpdatedAt": "2026-06-12T10:00:00.000Z",
        "Severity": {"Label": severity_label, "Normalized": 70},
        "Title": "S3 Block Public Access setting should be enabled",
        "Description": "This control checks the bucket public access configuration.",
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "Compliance": {"Status": "FAILED"},
        "Resources": [{"Type": resource_type, "Id": f"arn:aws:s3:::demo-bucket-{fid}"}],
    }
    if with_secrets:
        # These must never be traversed/stored by the normalizer.
        f["ProductFields"] = {"aws/securityhub/SecretMaterial": SECRET_VALUE}
        f["Network"] = {"SourceIpV4": RAW_IP}
        f["Sample"] = {"malwareName": "Trojan.Example"}
    return f


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "aws",
        SecurityActivityEvent.source == "security_hub",
    ).all()


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "aws",
        SecurityIncidentSignal.signal_type == "aws_security_hub_finding",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. normalize into the activity spine ──────────────────────────────────────

def test_findings_normalize_into_spine(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("sh-1")]))
    try:
        summary = sh_ingest.ingest_aws_security_hub_findings(
            integration=integ, workspace_id=ws.id, db=db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "security_hub"
        assert summary["findings_seen"] == 1
        assert summary["events_inserted"] == 1
        row = _rows(db_session, ws.id)[0]
        assert row.event_type == "aws.security_hub.s3_finding"
        assert row.event_metadata.get("finding_title", "").startswith("S3 Block")
        assert row.event_metadata.get("severity_label") == "high"
        assert row.event_metadata.get("compliance_status") == "FAILED"
        assert row.resource_type == "AwsS3Bucket"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. idempotency via finding Id ─────────────────────────────────────────────

def test_idempotency_by_finding_id(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("sh-dupe")]))
    try:
        s1 = sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        s2 = sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 3. severity mapping ───────────────────────────────────────────────────────

def test_severity_mapping(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    findings = [
        _finding("sev-crit", severity_label="CRITICAL"),
        _finding("sev-info", severity_label="INFORMATIONAL"),
    ]
    _install_fake_aws(monkeypatch, _FakeSecurityHub(findings))
    try:
        sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        labels = {r.event_metadata.get("severity_label") for r in _rows(db_session, ws.id)}
        assert "critical" in labels
        assert "info" in labels
    finally:
        _cleanup(db_session, ws.id)


# ── 4. IAM/S3/EC2/KMS/vendor type mapping + fallback ──────────────────────────

def test_type_mapping_and_fallback(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    findings = [
        _finding("t-iam", resource_type="AwsIamRole"),
        _finding("t-s3", resource_type="AwsS3Bucket"),
        _finding("t-ec2", resource_type="AwsEc2Instance"),
        _finding("t-kms", resource_type="AwsKmsKey"),
        _finding("t-gd", product="GuardDuty", resource_type="AwsEc2Instance"),
        _finding("t-insp", product="Inspector", resource_type="AwsEc2Instance"),
        _finding("t-macie", product="Macie", resource_type="AwsS3Bucket"),
        _finding("t-unknown", product="SomeVendor", resource_type="AwsThingUnknown"),
    ]
    _install_fake_aws(monkeypatch, _FakeSecurityHub(findings))
    try:
        sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert "aws.security_hub.iam_finding" in types
        assert "aws.security_hub.s3_finding" in types
        assert "aws.security_hub.ec2_finding" in types
        assert "aws.security_hub.kms_finding" in types
        assert "aws.security_hub.guardduty_finding" in types
        assert "aws.security_hub.inspector_finding" in types
        assert "aws.security_hub.macie_finding" in types
        assert "aws.security_hub.finding" in types  # fallback
    finally:
        _cleanup(db_session, ws.id)


# ── 5. privacy: no raw secrets / IPs / payloads / JSON ────────────────────────

def test_no_raw_secrets_or_payloads(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("priv-1")]))
    try:
        sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        row = _rows(db_session, ws.id)[0]
        blob = json.dumps({
            "event_type": row.event_type, "resource_id": row.resource_id,
            "resource_type": row.resource_type, "metadata": row.event_metadata,
            "source_ip_hash": row.source_ip_hash,
        }, default=str)
        assert RAW_IP not in blob
        assert SECRET_VALUE not in blob
        for bad in ("ProductFields", "SecretMaterial", "Network", "SourceIpV4",
                    "Sample", "malwareName"):
            assert bad not in blob
        # Security Hub findings never traverse network payloads → no source IP.
        assert row.source_ip_hash is None
    finally:
        _cleanup(db_session, ws.id)


# ── 6. permission failure is non-fatal ────────────────────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([], raise_403=True))
    summary = sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0
    assert _rows(db_session, ws.id) == []


# ── 7. Security Hub Incident Signal generated + idempotent ────────────────────

def test_signal_generation_and_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("sig-1", severity_label="CRITICAL")]))
    try:
        sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        g1 = signal_svc.generate_aws_security_hub_signals(workspace_id=ws.id, db=db_session)
        g2 = signal_svc.generate_aws_security_hub_signals(workspace_id=ws.id, db=db_session)
        assert g1["signals_created"] == 1
        assert g2["signals_created"] == 0
        assert g2["signals_skipped"] == 1
        sig = _signals(db_session, ws.id)[0]
        assert sig.signal_key == "aws_security_hub_finding"
        assert sig.evidence_level == "provider_alert"
        assert sig.confidence == "high"
        assert sig.severity == "critical"
        assert sig.title.startswith("Security Hub finding:")
    finally:
        _cleanup(db_session, ws.id)


# ── 8. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _aws_integ(db_session, test_user, ws_a.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("scoped")]))
    try:
        sh_ingest.ingest_aws_security_hub_findings(integration=integ_a, workspace_id=ws_a.id, db=db_session)
        assert len(_rows(db_session, ws_a.id)) == 1
        assert len(_rows(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 9. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("claim-1")]))
    try:
        sh_ingest.ingest_aws_security_hub_findings(integration=integ, workspace_id=ws.id, db=db_session)
        signal_svc.generate_aws_security_hub_signals(workspace_id=ws.id, db=db_session)
        for s in _signals(db_session, ws.id):
            blob = f"{s.title}\n{s.summary}".lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
            assert "may require review" in s.summary.lower()
            assert "provider-reported" in s.summary.lower()
            assert set(s.signal_metadata.keys()) <= _ALLOWED_SIGNAL_META
    finally:
        _cleanup(db_session, ws.id)


# ── 10. endpoints admin-gated + member blocked ────────────────────────────────

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


def test_owner_can_sync_and_generate_via_endpoints(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeSecurityHub([_finding("ep-1")]))
    try:
        r = client.post("/security/aws-security-hub/sync")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "aws" and body["source"] == "security_hub"
        assert body["events_inserted"] == 1

        g = client.post("/security/aws-security-hub/generate-signals")
        assert g.status_code == 200
        assert g.json()["signals_created"] == 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
