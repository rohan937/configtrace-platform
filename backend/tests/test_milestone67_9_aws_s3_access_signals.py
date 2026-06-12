"""M67.9 — AWS S3 object-access spike signals from S3 data events.

Groups normalized S3 object-level activity (provider=aws, source=s3_data_event)
by principal + bucket and surfaces review-worthy access SPIKES as Incident
Signals (signal_type="s3_object_access_spike"). These tests assert each spike
pattern, below-threshold quiet, idempotency, workspace scoping, admin gating,
metadata privacy (safe aggregate counts only — no raw keys/IPs/payloads), and
claim discipline (no forbidden wording, never "data exfiltration confirmed").
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import aws_s3_access_signal_service as spike_svc
from app.services import security_activity_event_service as activity_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "data exfiltration confirmed",
]
_ALLOWED_SIGNAL_META = {
    "source", "pattern", "bucket_name", "actor_id", "event_count",
    "unique_object_count", "window_start", "window_end", "object_key_prefix",
    "event_types",
}
THRESHOLD = 5
RAW_IP = "203.0.113.41"


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.9", db=db)


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


def _s3_evt(db, ws_id, integ_id, event_type, actor, bucket, *,
            object_key_hash="objhash-default", object_key_prefix="logs",
            occurred=None, source_ip=RAW_IP):
    norm = activity_svc.normalize_activity_event(
        provider="aws", source="s3_data_event", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"s3-{uuid.uuid4().hex[:14]}",
        actor_id=actor, actor_type="IAMUser",
        resource_type="aws_s3_bucket", resource_id=bucket,
        source_ip=source_ip,
        metadata={
            "bucket_name": bucket,
            "object_key_hash": object_key_hash,
            "object_key_prefix": object_key_prefix,
            "event_name": event_type.split(".")[-1],
        },
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen(db, ws_id, **kw):
    return spike_svc.generate_aws_s3_access_signals(
        workspace_id=ws_id, db=db, read_threshold=THRESHOLD, **kw)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "aws",
        SecurityIncidentSignal.signal_type == "s3_object_access_spike",
    ).all()


def _keys(db, ws_id):
    return {s.signal_key for s in _signals(db, ws_id)}


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. high GetObject volume ──────────────────────────────────────────────────

def test_high_read_volume(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    # 5 reads of the SAME object → high volume, but unique=1 (isolates pattern A).
    for _ in range(THRESHOLD):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "alice", "vault",
                object_key_hash="same-hash")
    try:
        _gen(db_session, ws.id)
        assert "aws.s3_access.high_read_volume" in _keys(db_session, ws.id)
        assert "aws.s3_access.unique_objects_read" not in _keys(db_session, ws.id)
        sig = next(s for s in _signals(db_session, ws.id)
                   if s.signal_key == "aws.s3_access.high_read_volume")
        assert sig.confidence == "medium"
        assert sig.evidence_level == "activity"
        assert sig.signal_metadata.get("event_count") == THRESHOLD
        assert sig.signal_metadata.get("bucket_name") == "vault"
    finally:
        _cleanup(db_session, ws.id)


# ── 2. many unique objects read ───────────────────────────────────────────────

def test_unique_objects_read(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for i in range(THRESHOLD):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "bob", "vault",
                object_key_hash=f"hash-{i}")
    try:
        _gen(db_session, ws.id)
        assert "aws.s3_access.unique_objects_read" in _keys(db_session, ws.id)
        sig = next(s for s in _signals(db_session, ws.id)
                   if s.signal_key == "aws.s3_access.unique_objects_read")
        assert sig.severity == "high"
        assert sig.signal_metadata.get("unique_object_count") == THRESHOLD
    finally:
        _cleanup(db_session, ws.id)


# ── 3. ListBucket followed by GetObject burst ─────────────────────────────────

def test_list_then_read_burst(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    base = datetime.now(timezone.utc) - timedelta(minutes=30)
    _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.list_bucket", "carol", "vault",
            occurred=base)
    for i in range(THRESHOLD):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "carol", "vault",
                object_key_hash=f"h{i}", occurred=base + timedelta(minutes=i + 1))
    try:
        _gen(db_session, ws.id)
        assert "aws.s3_access.list_then_read_burst" in _keys(db_session, ws.id)
    finally:
        _cleanup(db_session, ws.id)


# ── 4. PutObjectAcl near object activity ──────────────────────────────────────

def test_acl_changed_near_activity(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.put_object_acl", "dave", "vault")
    _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "dave", "vault")
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.s3_access.acl_changed_near_activity"), None)
        assert sig is not None
        assert sig.severity == "medium"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. DeleteObject burst ─────────────────────────────────────────────────────

def test_delete_burst(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for i in range(THRESHOLD):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.delete_object", "erin", "vault",
                object_key_hash=f"d{i}")
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.s3_access.delete_burst"), None)
        assert sig is not None
        assert sig.severity == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 6. below threshold → no signal ────────────────────────────────────────────

def test_below_threshold_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for i in range(THRESHOLD - 1):  # 4 < 5
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "frank", "vault",
                object_key_hash=f"u{i}")
    try:
        summary = _gen(db_session, ws.id)
        assert summary["signals_created"] == 0
        assert _signals(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


# ── 7. idempotency ────────────────────────────────────────────────────────────

def test_generation_is_idempotent(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for i in range(THRESHOLD):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.delete_object", "grace", "vault",
                object_key_hash=f"x{i}")
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["signals_created"] >= 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] >= 1
    finally:
        _cleanup(db_session, ws.id)


# ── 8. workspace scoping ──────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ_a = _aws_integ(db_session, test_user, ws_a.id)
    for i in range(THRESHOLD):
        _s3_evt(db_session, ws_a.id, integ_a.id, "aws.s3.data.get_object", "heidi", "vault",
                object_key_hash=f"h{i}")
    try:
        _gen(db_session, ws_a.id)
        assert len(_signals(db_session, ws_a.id)) >= 1
        assert len(_signals(db_session, ws_b.id)) == 0
    finally:
        _cleanup(db_session, ws_a.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── 9. metadata privacy + claim discipline ────────────────────────────────────

def test_metadata_privacy_and_claims(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for i in range(THRESHOLD):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "ivan", "vault",
                object_key_hash=f"h{i}")
    try:
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({"t": s.title, "s": s.summary, "m": s.signal_metadata}, default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden phrase {phrase!r}"
            assert "may require review" in s.summary.lower()
            assert "does not confirm data exfiltration" in s.summary.lower()
            # Only safe aggregate metadata (object_key_hash/prefix are safe; the
            # allowlist-subset check guarantees no raw object-key field leaks).
            assert set(s.signal_metadata.keys()) <= _ALLOWED_SIGNAL_META
            assert "object_key_hash" not in s.signal_metadata  # not even the hash
            assert RAW_IP not in blob
            for bad in ("requestParameters", "responseElements", "sourceIPAddress",
                        "source_ip_hash", "secret", "token"):
                assert bad not in blob
    finally:
        _cleanup(db_session, ws.id)


# ── 10. endpoint admin gating ─────────────────────────────────────────────────

def test_member_cannot_generate(test_user, db_session):
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


def test_owner_can_generate_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for i in range(6):
        _s3_evt(db_session, ws.id, integ.id, "aws.s3.data.get_object", "ivan", "vault",
                object_key_hash=f"h{i}")
    try:
        # default threshold is 50, so a 6-event group must NOT create signals…
        resp = client.post("/security/aws-s3-data-events/generate-signals", json={})
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws"
        assert body["events_scanned"] >= 6
        assert body["signals_created"] == 0
        # …but a low read_threshold surfaces the spike.
        resp2 = client.post(
            "/security/aws-s3-data-events/generate-signals",
            json={"read_threshold": 5},
        )
        assert resp2.status_code == 200
        assert resp2.json()["signals_created"] >= 1
    finally:
        _cleanup(db_session, ws.id)
