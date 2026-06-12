"""M67.8 — AWS S3 object-level data-event ingestion.

CloudTrail S3 DATA events are read from a caller-supplied trail bucket (gzipped
CloudTrail JSON), filtered to S3 data events only, and normalized into the shared
``security_activity_events`` spine (provider=aws, source=s3_data_event) as
object-level activity evidence. These tests assert gzip parsing, data-event-only
filtering, event mapping, eventID idempotency, privacy (object key + source IP
hashed only; no requestParameters/responseElements/raw JSON), malformed-object
safety, non-fatal permission failure, workspace scoping, admin gating, and claim
discipline.
"""

from __future__ import annotations

import gzip
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
from app.services import aws_s3_data_event_ingestion_service as s3_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "data exfiltration confirmed",
]
RAW_IP = "203.0.113.55"
SECRET_KEY_PART = "customers/ssn-7788-secret-object.csv"


# ── fake AWS S3 plumbing ──────────────────────────────────────────────────────

class _FakeS3:
    """Mimics the bits of an S3 client our connector uses."""

    def __init__(self, objects, *, list_403=False, get_403=False):
        # objects: {key: bytes}
        self._objects = objects
        self._list_403 = list_403
        self._get_403 = get_403

    def list_objects_v2(self, **kwargs):
        if self._list_403:
            raise ConnectorError("AccessDenied", status_code=403)
        contents = [{"Key": k} for k in self._objects]
        return {"Contents": contents, "IsTruncated": False}

    def get_object(self, **kwargs):
        if self._get_403:
            raise ConnectorError("AccessDenied", status_code=403)
        key = kwargs.get("Key")
        data = self._objects.get(key, b"")

        class _Body:
            def __init__(self, b):
                self._b = b
            def read(self, amt=None):
                return self._b
        return {"Body": _Body(data)}


def _factory(s3_client):
    def _make(self, service, credentials, region=None):
        if service == "s3":
            return s3_client
        class _Other:  # pragma: no cover
            pass
        return _Other()
    return _make


def _passthrough(self, fn, *args, **kwargs):
    return fn(*args, **kwargs)


def _install(monkeypatch, s3_client):
    monkeypatch.setattr(AWSConnector, "_make_client", _factory(s3_client))
    monkeypatch.setattr(AWSConnector, "_call_aws", _passthrough)


# ── record + object builders ──────────────────────────────────────────────────

def _record(event_id, event_name, *, bucket="data-bucket", key=SECRET_KEY_PART,
            with_ip=True, with_blobs=True, category="Data", source="s3.amazonaws.com"):
    rec = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser", "principalId": "AIDAEXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012", "userName": "alice",
        },
        "eventTime": "2026-06-12T10:00:00Z",
        "eventSource": source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "eventID": event_id,
        "readOnly": event_name in ("GetObject", "HeadObject", "ListBucket"),
        "eventType": "AwsApiCall",
        "eventCategory": category,
        "recipientAccountId": "123456789012",
        "requestParameters": {"bucketName": bucket, "key": key},
        "additionalEventData": {"bytesTransferredIn": 0, "bytesTransferredOut": 2048},
        "resources": [{"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}"}],
    }
    if with_ip:
        rec["sourceIPAddress"] = RAW_IP
    if with_blobs:
        rec["userAgent"] = "aws-cli/2.0 secretAgentString"
        rec["responseElements"] = {"x-amz-secret": "SECRETRESPONSE"}
    return rec


def _gz(records):
    return gzip.compress(json.dumps({"Records": records}).encode("utf-8"))


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.8", db=db)


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


def _rows(db, ws_id):
    return db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id,
        SecurityActivityEvent.provider == "aws",
        SecurityActivityEvent.source == "s3_data_event",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db, **kw):
    return s3_ingest.ingest_aws_s3_data_events(
        integration=integ, workspace_id=ws_id, db=db, trail_bucket="trail-logs", **kw)


# ── 1. parse gzipped records + only data events ingested ──────────────────────

def test_parses_gzip_and_only_data_events(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    records = [
        _record("e1", "GetObject"),
        # management S3 event — must be EXCLUDED
        _record("e2", "PutBucketPolicy", category="Management"),
        # non-S3 event — must be EXCLUDED
        _record("e3", "AssumeRole", category="Management", source="sts.amazonaws.com"),
    ]
    objects = {"AWSLogs/123/CloudTrail/x.json.gz": _gz(records)}
    _install(monkeypatch, _FakeS3(objects))
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "s3_data_event"
        assert summary["files_seen"] == 1 and summary["files_read"] == 1
        rows = _rows(db_session, ws.id)
        assert len(rows) == 1
        assert rows[0].event_type == "aws.s3.data.get_object"
        assert rows[0].resource_id == "data-bucket"
        assert rows[0].event_metadata.get("bucket_name") == "data-bucket"
        assert rows[0].event_metadata.get("bytes_transferred") == 2048
    finally:
        _cleanup(db_session, ws.id)


# ── 2. event-name mappings ────────────────────────────────────────────────────

def test_event_name_mappings(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    records = [
        _record("m1", "GetObject"), _record("m2", "PutObject"),
        _record("m3", "DeleteObject"), _record("m4", "ListBucket"),
        _record("m5", "CopyObject"), _record("m6", "HeadObject"),
        _record("m7", "PutObjectAcl"), _record("m8", "RestoreObject"),
    ]
    _install(monkeypatch, _FakeS3({"a.json.gz": _gz(records)}))
    try:
        _ingest(integ, ws.id, db_session)
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert "aws.s3.data.get_object" in types
        assert "aws.s3.data.put_object" in types
        assert "aws.s3.data.delete_object" in types
        assert "aws.s3.data.list_bucket" in types
        assert "aws.s3.data.copy_object" in types
        assert "aws.s3.data.head_object" in types
        assert "aws.s3.data.put_object_acl" in types
        assert "aws.s3.data.event" in types  # RestoreObject → fallback
    finally:
        _cleanup(db_session, ws.id)


# ── 3. eventID idempotency ────────────────────────────────────────────────────

def test_eventid_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({"a.json.gz": _gz([_record("dupe", "PutObject")])}))
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 4. privacy: object key + IP hashed only, no blobs ─────────────────────────

def test_no_raw_key_ip_or_blobs(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({"a.json.gz": _gz([_record("p1", "GetObject")])}))
    try:
        _ingest(integ, ws.id, db_session)
        row = _rows(db_session, ws.id)[0]
        blob = json.dumps({
            "event_type": row.event_type, "actor_id": row.actor_id,
            "resource_id": row.resource_id, "metadata": row.event_metadata,
            "source_ip_hash": row.source_ip_hash,
        }, default=str)
        # Raw object key never stored — only a hash.
        assert SECRET_KEY_PART not in blob
        assert "ssn-7788" not in blob
        assert row.event_metadata.get("object_key_hash")
        # The sanitized prefix is only the safe top-level segment ("customers").
        assert row.event_metadata.get("object_key_prefix") == "customers"
        # Source IP hashed only.
        assert RAW_IP not in blob
        assert row.source_ip_hash is not None
        # No payloads / agent / response blobs.
        for bad in ("requestParameters", "responseElements", "userAgent",
                    "secretAgentString", "SECRETRESPONSE", "x-amz-secret"):
            assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 5. malformed log object handled safely ────────────────────────────────────

def test_malformed_object_is_safe(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    objects = {
        "bad.json.gz": b"this-is-not-gzip-or-json",
        "good.json.gz": _gz([_record("g1", "GetObject")]),
    }
    _install(monkeypatch, _FakeS3(objects))
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["succeeded"] is True
        assert summary["files_read"] == 2  # both read; one yields no records
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 6. permission failure is non-fatal ────────────────────────────────────────

def test_permission_failure_non_fatal(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({}, list_403=True))
    summary = _ingest(integ, ws.id, db_session)
    assert summary["attempted"] is True
    assert summary["permission_limited"] is True
    assert summary["succeeded"] is True
    assert summary["events_inserted"] == 0
    assert _rows(db_session, ws.id) == []


# ── 7. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session, monkeypatch):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _aws_integ(db_session, test_user, ws_a.id)
    _install(monkeypatch, _FakeS3({"a.json.gz": _gz([_record("s1", "PutObject")])}))
    try:
        _ingest(integ_a, ws_a.id, db_session)
        assert len(_rows(db_session, ws_a.id)) == 1
        assert len(_rows(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 8. claim discipline ───────────────────────────────────────────────────────

def test_no_forbidden_wording(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({"a.json.gz": _gz([_record("c1", "GetObject")])}))
    try:
        _ingest(integ, ws.id, db_session)
        for r in _rows(db_session, ws.id):
            blob = json.dumps({"t": r.event_type, "m": r.event_metadata}, default=str).lower()
            for phrase in _FORBIDDEN:
                assert phrase not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 9. endpoint admin gating ──────────────────────────────────────────────────

def test_member_cannot_sync(test_user, db_session):
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
    _install(monkeypatch, _FakeS3({"a.json.gz": _gz([_record("ep1", "GetObject")])}))
    try:
        resp = client.post(
            "/security/aws-s3-data-events/sync",
            json={"trail_bucket": "trail-logs", "max_files": 5},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws" and body["source"] == "s3_data_event"
        assert body["events_inserted"] == 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_endpoint_requires_trail_bucket(client, test_user, db_session):
    # Missing required trail_bucket → 422 from request validation.
    resp = client.post("/security/aws-s3-data-events/sync", json={})
    assert resp.status_code == 422
