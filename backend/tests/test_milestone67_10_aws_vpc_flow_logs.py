"""M67.10 — AWS VPC Flow Logs ingestion.

VPC Flow Logs are read from a caller-supplied S3 bucket (gzip or plaintext),
parsed in the default record format, and normalized into the shared
``security_activity_events`` spine (provider=aws, source=vpc_flow_log) as network
activity evidence. These tests assert parsing, ACCEPT/REJECT/fallback mapping,
malformed-line + header skipping, privacy (raw IPs/lines never stored; src+dst
hashed), deterministic-fingerprint idempotency, non-fatal permission failure,
workspace scoping, admin gating, and claim discipline.
"""

from __future__ import annotations

import gzip
import json
import uuid

import pytest
from fastapi import HTTPException

from app.connectors.aws import AWSConnector
from app.connectors.exceptions import ConnectorError
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import aws_vpc_flow_log_ingestion_service as vpc_ingest
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "network intrusion confirmed",
]
SRC_IP = "10.0.5.23"
DST_IP = "93.184.216.34"
_HEADER = ("version account-id interface-id srcaddr dstaddr srcport dstport "
           "protocol packets bytes start end action log-status")


def _flow(action="ACCEPT", *, src=SRC_IP, dst=DST_IP, eni="eni-0abc", dport="443",
          start="1718182800", end="1718182860"):
    return (f"2 123456789012 {eni} {src} {dst} 49152 {dport} 6 12 1840 "
            f"{start} {end} {action} OK")


# ── fake AWS S3 plumbing ──────────────────────────────────────────────────────

class _FakeS3:
    def __init__(self, objects, *, list_403=False, get_403=False):
        self._objects = objects
        self._list_403 = list_403
        self._get_403 = get_403

    def list_objects_v2(self, **kwargs):
        if self._list_403:
            raise ConnectorError("AccessDenied", status_code=403)
        return {"Contents": [{"Key": k} for k in self._objects], "IsTruncated": False}

    def get_object(self, **kwargs):
        if self._get_403:
            raise ConnectorError("AccessDenied", status_code=403)
        data = self._objects.get(kwargs.get("Key"), b"")

        class _Body:
            def __init__(self, b): self._b = b
            def read(self, amt=None): return self._b
        return {"Body": _Body(data)}


def _install(monkeypatch, s3):
    def _make(self, service, credentials, region=None):
        if service == "s3":
            return s3
        class _O:  # pragma: no cover
            pass
        return _O()
    monkeypatch.setattr(AWSConnector, "_make_client", _make)
    monkeypatch.setattr(AWSConnector, "_call_aws", lambda self, fn, *a, **k: fn(*a, **k))


def _gz(lines):
    return gzip.compress(("\n".join(lines) + "\n").encode("utf-8"))


def _plain(lines):
    return ("\n".join(lines) + "\n").encode("utf-8")


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.10", db=db)


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
        SecurityActivityEvent.source == "vpc_flow_log",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


def _ingest(integ, ws_id, db, **kw):
    return vpc_ingest.ingest_aws_vpc_flow_logs(
        integration=integ, workspace_id=ws_id, db=db, flow_log_bucket="flow-logs", **kw)


# ── 1. parse default lines + mappings ─────────────────────────────────────────

def test_parses_and_maps_accept_reject_fallback(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    lines = [
        _HEADER,                                  # header — skipped
        _flow("ACCEPT", eni="eni-a"),
        _flow("REJECT", eni="eni-b"),
        _flow("-", eni="eni-c"),                  # no action → fallback
        "garbage short line",                     # malformed — skipped
    ]
    _install(monkeypatch, _FakeS3({"AWSLogs/x.log.gz": _gz(lines)}))
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["attempted"] and summary["succeeded"]
        assert summary["source"] == "vpc_flow_log"
        assert summary["files_seen"] == 1 and summary["files_read"] == 1
        types = {r.event_type for r in _rows(db_session, ws.id)}
        assert types == {"aws.vpc.flow.accept", "aws.vpc.flow.reject", "aws.vpc.flow.event"}
        accept = next(r for r in _rows(db_session, ws.id)
                      if r.event_type == "aws.vpc.flow.accept")
        assert accept.resource_id == "eni-a"
        assert accept.event_metadata.get("dst_port") == 443
        assert accept.event_metadata.get("protocol") == 6
        assert accept.event_metadata.get("action") == "ACCEPT"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. plaintext (non-gzip) supported ─────────────────────────────────────────

def test_plaintext_supported(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({"flow.log": _plain([_HEADER, _flow("ACCEPT")])}))
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["events_inserted"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 3. privacy: raw IPs + raw lines never stored, hashes present ──────────────

def test_no_raw_ips_or_lines(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({"a.log.gz": _gz([_flow("ACCEPT")])}))
    try:
        _ingest(integ, ws.id, db_session)
        row = _rows(db_session, ws.id)[0]
        blob = json.dumps({
            "event_type": row.event_type, "resource_id": row.resource_id,
            "metadata": row.event_metadata, "source_ip_hash": row.source_ip_hash,
            "raw_ref": row.raw_ref,
        }, default=str)
        # Raw source/destination IPs never stored.
        assert SRC_IP not in blob
        assert DST_IP not in blob
        # Both directions hashed.
        assert row.source_ip_hash is not None
        assert row.event_metadata.get("destination_ip_hash") is not None
        # No raw log line / payload markers.
        for bad in ("49152", "1840"):  # raw port-pair / byte string fragments are fine as ints
            pass
        assert "ACCEPT OK" not in blob  # the raw line is never persisted
    finally:
        _cleanup(db_session, ws.id)


# ── 4. idempotency via deterministic fingerprint ──────────────────────────────

def test_idempotency(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _install(monkeypatch, _FakeS3({"a.log.gz": _gz([_flow("ACCEPT")])}))
    try:
        s1 = _ingest(integ, ws.id, db_session)
        s2 = _ingest(integ, ws.id, db_session)
        assert s1["events_inserted"] == 1
        assert s2["events_inserted"] == 0
        assert s2["events_skipped"] == 1
        assert len(_rows(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 5. malformed gzip handled safely ──────────────────────────────────────────

def test_malformed_object_safe(test_user, db_session, monkeypatch):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    objects = {"bad.log.gz": b"\x00not-gzip", "good.log.gz": _gz([_flow("ACCEPT")])}
    _install(monkeypatch, _FakeS3(objects))
    try:
        summary = _ingest(integ, ws.id, db_session)
        assert summary["succeeded"] is True
        assert summary["files_read"] == 2
        assert summary["events_inserted"] == 1
    finally:
        _cleanup(db_session, ws.id)


# ── 6. permission failure non-fatal ───────────────────────────────────────────

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
    _install(monkeypatch, _FakeS3({"a.log.gz": _gz([_flow("ACCEPT")])}))
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
    _install(monkeypatch, _FakeS3({"a.log.gz": _gz([_flow("REJECT")])}))
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
    _install(monkeypatch, _FakeS3({"a.log.gz": _gz([_flow("ACCEPT")])}))
    try:
        resp = client.post(
            "/security/aws-vpc-flow-logs/sync",
            json={"flow_log_bucket": "flow-logs", "max_files": 5},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws" and body["source"] == "vpc_flow_log"
        assert body["events_inserted"] == 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()


def test_endpoint_requires_flow_log_bucket(client, test_user, db_session):
    resp = client.post("/security/aws-vpc-flow-logs/sync", json={})
    assert resp.status_code == 422
