"""M67.5 — AWS CloudTrail management-event ingestion.

CloudTrail control-plane events are normalized into the shared
``security_activity_events`` spine (provider=aws, source=cloudtrail) as evidence
for review. These tests assert normalization, EventId idempotency, management
event mapping (IAM/S3/EC2/KMS/console), safe fallback for unknown events,
privacy (no raw source IP / requestParameters / responseElements / secrets /
tokens), non-fatal permission failure, workspace scoping, admin gating, and that
no forbidden breach/attacker/compromise wording appears.
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
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import aws_cloudtrail_ingestion_service as ct_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]

RAW_IP = "203.0.113.77"
SECRET_VALUE = "wJalrXUtnFEMIbProbablySecretValue"


# ── fake AWS plumbing (no boto3 in the container) ─────────────────────────────

class _FakeCloudTrail:
    def __init__(self, events, raise_403=False):
        self._events = events
        self._raise_403 = raise_403

    def lookup_events(self, **kwargs):
        if self._raise_403:
            raise ConnectorError("AccessDenied", status_code=403)
        return {"Events": self._events, "NextToken": None}


def _make_client_factory(ct_client):
    def _factory(self, service, credentials, region=None):
        if service == "cloudtrail":
            return ct_client
        class _Other:  # pragma: no cover - not used here
            pass
        return _Other()
    return _factory


def _passthrough_call(self, fn, *args, **kwargs):
    return fn(*args, **kwargs)


def _install_fake_aws(monkeypatch, ct_client):
    monkeypatch.setattr(AWSConnector, "_make_client", _make_client_factory(ct_client))
    monkeypatch.setattr(AWSConnector, "_call_aws", _passthrough_call)


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.5", db=db)


def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _aws_integ(db, user, ws_id):
    ct, iv = encrypt_credentials({
        "aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "x",
        "aws_default_region": "us-east-1",
    })
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="aws",
        display_name="aws", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _ct_event(event_id, event_name, *, event_source="iam.amazonaws.com",
              resources=None, with_ip=True, with_secrets=True, user_name="alice"):
    """Build a realistic CloudTrail LookupEvents item with an embedded JSON blob."""
    detail = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEPRINCIPAL",
            "arn": f"arn:aws:iam::123456789012:user/{user_name}",
            "accountId": "123456789012",
            "userName": user_name,
            "accessKeyId": "AKIAEXAMPLEKEYID",
        },
        "eventTime": "2026-06-12T10:00:00Z",
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "userAgent": "aws-cli/2.13.0 Python/3.11",
        "eventID": event_id,
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123456789012",
        "eventCategory": "Management",
    }
    if with_ip:
        detail["sourceIPAddress"] = RAW_IP
    if with_secrets:
        # These blobs must NEVER be traversed/stored by the normalizer.
        detail["requestParameters"] = {"userName": user_name, "policyDocument": "{...}"}
        detail["responseElements"] = {
            "accessKey": {
                "accessKeyId": "AKIANEWKEYID",
                "secretAccessKey": SECRET_VALUE,
                "sessionToken": "FwoSESSIONTOKEN" + SECRET_VALUE,
                "status": "Active",
            }
        }
    return {
        "EventId": event_id,
        "EventName": event_name,
        "EventTime": datetime(2026, 6, 12, 10, 0, tzinfo=timezone.utc),
        "EventSource": event_source,
        "Username": user_name,
        "Resources": resources or [],
        "CloudTrailEvent": json.dumps(detail),
    }


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "aws",
        SecurityActivityEvent.source == "cloudtrail",
    ).all()


# ── 1. normalize into the activity spine ──────────────────────────────────────

def test_cloudtrail_events_normalize_into_activity_spine(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    events = [_ct_event("evt-iam-1", "CreateAccessKey")]
    _install_fake_aws(monkeypatch, _FakeCloudTrail(events))
    try:
        summary = ct_ingest.ingest_aws_cloudtrail_events(
            integration=integ, workspace_id=ws.id, db=db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "cloudtrail"
        assert summary["events_seen"] == 1
        assert summary["events_inserted"] == 1
        rows = _rows(db_session, ws.id)
        assert len(rows) == 1
        assert rows[0].event_type == "aws.iam.create_access_key"
        assert rows[0].actor_id == "alice"
        assert rows[0].event_metadata.get("event_name") == "CreateAccessKey"
        assert rows[0].event_metadata.get("aws_region") == "us-east-1"
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.commit()


# ── 2. EventId idempotency ─────────────────────────────────────────────────────

def test_eventid_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    events = [_ct_event("evt-dupe", "CreateUser")]
    _install_fake_aws(monkeypatch, _FakeCloudTrail(events))
    try:
        s1 = ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
        s2 = ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.commit()


# ── 3. management event mapping (IAM/S3/EC2/KMS/console) ───────────────────────

def test_management_event_mapping(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    events = [
        _ct_event("e1", "ConsoleLogin", event_source="signin.amazonaws.com"),
        _ct_event("e2", "AttachUserPolicy"),
        _ct_event("e3", "PutBucketPolicy", event_source="s3.amazonaws.com"),
        _ct_event("e4", "AuthorizeSecurityGroupIngress", event_source="ec2.amazonaws.com"),
        _ct_event("e5", "ScheduleKeyDeletion", event_source="kms.amazonaws.com"),
        _ct_event("e6", "UpdateAssumeRolePolicy"),
    ]
    _install_fake_aws(monkeypatch, _FakeCloudTrail(events))
    try:
        ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert "aws.cloudtrail.console_login" in types
        assert "aws.iam.attach_user_policy" in types
        assert "aws.s3.put_bucket_policy" in types
        assert "aws.ec2.authorize_security_group_ingress" in types
        assert "aws.kms.schedule_key_deletion" in types
        assert "aws.iam.update_assume_role_policy" in types
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.commit()


# ── 4. unknown events fall back safely ─────────────────────────────────────────

def test_unknown_event_falls_back(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    events = [_ct_event("evt-x", "DescribeSomethingObscure", event_source="x.amazonaws.com")]
    _install_fake_aws(monkeypatch, _FakeCloudTrail(events))
    try:
        ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
        rows = _rows(db_session, ws.id)
        assert len(rows) == 1
        assert rows[0].event_type == "aws.cloudtrail.event"
        # the original event name is still retained as safe metadata
        assert rows[0].event_metadata.get("event_name") == "DescribeSomethingObscure"
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.commit()


# ── 5. privacy: no raw IP, no requestParameters/responseElements/secrets ──────

def test_no_raw_ip_or_secrets_stored(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    events = [_ct_event("evt-secret", "CreateAccessKey",
                        resources=[{"ResourceType": "AWS::IAM::AccessKey", "ResourceName": "AKIAEXAMPLEKEYID"}])]
    _install_fake_aws(monkeypatch, _FakeCloudTrail(events))
    try:
        ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
        row = _rows(db_session, ws.id)[0]
        # Source IP is present only as a salted hash — never raw.
        assert row.source_ip_hash is not None
        blob = json.dumps({
            "event_type": row.event_type,
            "actor_id": row.actor_id,
            "resource_id": row.resource_id,
            "resource_type": row.resource_type,
            "metadata": row.event_metadata,
            "source_ip_hash": row.source_ip_hash,
        }, default=str)
        assert RAW_IP not in blob
        assert SECRET_VALUE not in blob
        for forbidden in ("requestParameters", "responseElements", "secretAccessKey",
                          "sessionToken", "policyDocument", "userAgent"):
            assert forbidden not in blob
        # principalId is hashed, never raw.
        assert "AIDAEXAMPLEPRINCIPAL" not in blob
        assert row.event_metadata.get("principal_id_hash")
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.commit()


# ── 6. permission failure is non-fatal ────────────────────────────────────────

def test_permission_failure_is_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeCloudTrail([], raise_403=True))
    summary = ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True       # non-fatal — does not raise
    assert summary["events_inserted"] == 0
    assert _rows(db_session, ws.id) == []


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _aws_integ(db_session, test_user, ws_a.id)
    _install_fake_aws(monkeypatch, _FakeCloudTrail([_ct_event("evt-scoped", "CreateRole")]))
    try:
        ct_ingest.ingest_aws_cloudtrail_events(integration=integ_a, workspace_id=ws_a.id, db=db_session)
        assert len(_rows(db_session, ws_a.id)) == 1
        assert len(_rows(db_session, ws_b.id)) == 0
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws_a.id).delete(synchronize_session=False)
        db_session.commit()
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 8. endpoint admin gating ──────────────────────────────────────────────────

def test_endpoint_requires_admin_and_member_blocked(test_user, db_session, monkeypatch):
    # Member cannot sync — permission helper raises 403.
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


def test_owner_can_sync_via_endpoint(client, test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeCloudTrail([_ct_event("evt-ep", "CreateUser")]))
    try:
        resp = client.post("/security/aws-cloudtrail/sync")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws" and body["source"] == "cloudtrail"
        assert body["events_inserted"] == 1
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


# ── 9. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording_in_events(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install_fake_aws(monkeypatch, _FakeCloudTrail([_ct_event("evt-claim", "PutUserPolicy")]))
    try:
        ct_ingest.ingest_aws_cloudtrail_events(integration=integ, workspace_id=ws.id, db=db_session)
        for r in _rows(db_session, ws.id):
            blob = json.dumps({"t": r.event_type, "m": r.event_metadata}, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
    finally:
        db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.workspace_id == ws.id).delete(synchronize_session=False)
        db_session.commit()
