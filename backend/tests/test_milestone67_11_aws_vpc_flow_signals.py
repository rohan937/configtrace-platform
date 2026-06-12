"""M67.11 — AWS VPC Flow Log network-activity signals.

Groups normalized VPC Flow Log activity (provider=aws, source=vpc_flow_log) by
network interface + destination port and surfaces review-worthy NETWORK patterns
as Incident Signals (signal_type="vpc_flow_activity_signal"). These tests assert
each pattern, below-threshold quiet, idempotency, workspace scoping, admin
gating, metadata privacy (safe aggregate counts only — no raw IPs/lines), and
claim discipline (no forbidden wording, never "network intrusion confirmed").
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import aws_vpc_flow_signal_service as flow_svc
from app.services import security_activity_event_service as activity_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
    "network intrusion confirmed",
]
_ALLOWED_SIGNAL_META = {
    "source", "pattern", "interface_id", "dst_port", "protocol", "flow_action",
    "event_count", "bytes_total", "packets_total", "window_start", "window_end",
    "event_types",
}
THRESHOLD = 4
RAW_IP = "198.51.100.7"


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.11", db=db)


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


def _flow_evt(db, ws_id, integ_id, action, *, interface="eni-1", dst_port=22,
              protocol=6, nbytes=1000, packets=5):
    event_type = {"ACCEPT": "aws.vpc.flow.accept", "REJECT": "aws.vpc.flow.reject"}.get(
        action, "aws.vpc.flow.event")
    norm = activity_svc.normalize_activity_event(
        provider="aws", source="vpc_flow_log", event_type=event_type,
        occurred_at=datetime.now(timezone.utc),
        provider_event_id=f"vpcfl-{uuid.uuid4().hex[:14]}",
        actor_id=None, actor_type="network_flow",
        resource_type="aws_network_interface", resource_id=interface,
        source_ip=RAW_IP,
        metadata={
            "interface_id": interface, "dst_port": dst_port, "protocol": protocol,
            "bytes": nbytes, "packets": packets, "action": action,
            "destination_ip_hash": "dsthash" * 4,
        },
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen(db, ws_id, **kw):
    return flow_svc.generate_aws_vpc_flow_signals(
        workspace_id=ws_id, db=db,
        rejected_threshold=THRESHOLD, sensitive_port_threshold=1,
        bytes_threshold=5000, port_activity_threshold=THRESHOLD, **kw)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "aws",
        SecurityIncidentSignal.signal_type == "vpc_flow_activity_signal",
    ).all()


def _keys(db, ws_id):
    return {s.signal_key for s in _signals(db, ws_id)}


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. accepted sensitive-port flow ───────────────────────────────────────────

def test_sensitive_port_accept(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    # single accepted SSH flow on a quiet interface (threshold 1)
    _flow_evt(db_session, ws.id, integ.id, "ACCEPT", interface="eni-a", dst_port=22)
    try:
        _gen(db_session, ws.id)
        assert "aws.vpc_flow.sensitive_port_accept" in _keys(db_session, ws.id)
        sig = next(s for s in _signals(db_session, ws.id)
                   if s.signal_key == "aws.vpc_flow.sensitive_port_accept")
        assert sig.severity == "high"  # 22 is an admin port
        assert sig.confidence == "medium"
        assert sig.evidence_level == "activity"
        assert sig.signal_metadata.get("dst_port") == 22
    finally:
        _cleanup(db_session, ws.id)


# ── 2. high rejected-flow volume ──────────────────────────────────────────────

def test_high_rejected_volume(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for _ in range(THRESHOLD):
        _flow_evt(db_session, ws.id, integ.id, "REJECT", interface="eni-b", dst_port=8080)
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.vpc_flow.rejected_volume"), None)
        assert sig is not None
        assert sig.severity == "medium"
        assert sig.signal_metadata.get("event_count") == THRESHOLD
    finally:
        _cleanup(db_session, ws.id)


# ── 3. high outbound byte volume ──────────────────────────────────────────────

def test_high_byte_volume(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    # one accept on a non-sensitive port carrying a large byte count
    _flow_evt(db_session, ws.id, integ.id, "ACCEPT", interface="eni-c", dst_port=443,
              nbytes=10000)
    try:
        _gen(db_session, ws.id)  # bytes_threshold=5000
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.vpc_flow.high_byte_volume"), None)
        assert sig is not None
        assert sig.signal_metadata.get("bytes_total") == 10000
        assert "does not identify the external destination" in sig.summary
    finally:
        _cleanup(db_session, ws.id)


# ── 4. repeated admin-port activity ───────────────────────────────────────────

def test_admin_port_activity(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for _ in range(THRESHOLD):
        _flow_evt(db_session, ws.id, integ.id, "REJECT", interface="eni-d", dst_port=3389)
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.vpc_flow.admin_port_activity"), None)
        assert sig is not None
        assert sig.severity == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. database-port activity burst ───────────────────────────────────────────

def test_db_port_activity_burst(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    for _ in range(THRESHOLD):
        _flow_evt(db_session, ws.id, integ.id, "ACCEPT", interface="eni-e", dst_port=5432)
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.vpc_flow.db_port_activity"), None)
        assert sig is not None
        assert sig.severity in ("medium", "high")
    finally:
        _cleanup(db_session, ws.id)


# ── 6. below threshold → no signal ────────────────────────────────────────────

def test_below_threshold_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    # 2 rejects on a non-sensitive port, small bytes → nothing fires.
    for _ in range(2):
        _flow_evt(db_session, ws.id, integ.id, "REJECT", interface="eni-f", dst_port=8080,
                  nbytes=10)
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
    for _ in range(THRESHOLD):
        _flow_evt(db_session, ws.id, integ.id, "REJECT", interface="eni-g", dst_port=3389)
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
    _flow_evt(db_session, ws_a.id, integ_a.id, "ACCEPT", interface="eni-x", dst_port=22)
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
    for _ in range(THRESHOLD):
        _flow_evt(db_session, ws.id, integ.id, "REJECT", interface="eni-y", dst_port=3389)
    try:
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({"t": s.title, "s": s.summary, "m": s.signal_metadata}, default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden phrase {phrase!r}"
            assert "may require review" in s.summary.lower()
            assert "does not confirm intrusion" in s.summary.lower()
            assert set(s.signal_metadata.keys()) <= _ALLOWED_SIGNAL_META
            assert RAW_IP not in blob
            for bad in ("srcaddr", "dstaddr", "source_ip", "destination_ip_hash",
                        "raw", "secret", "token"):
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
    for _ in range(3):
        _flow_evt(db_session, ws.id, integ.id, "REJECT", interface="eni-z", dst_port=3389)
    try:
        # default thresholds (rejected=20, port_activity=5) → 3 events fire nothing
        resp = client.post("/security/aws-vpc-flow-logs/generate-signals", json={})
        assert resp.status_code == 200
        assert resp.json()["signals_created"] == 0
        # a low rejected_threshold surfaces the rejected-volume signal
        resp2 = client.post(
            "/security/aws-vpc-flow-logs/generate-signals",
            json={"rejected_threshold": 2},
        )
        assert resp2.status_code == 200
        body = resp2.json()
        assert body["provider"] == "aws"
        assert body["interfaces_scanned"] >= 1
        assert body["signals_created"] >= 1
    finally:
        _cleanup(db_session, ws.id)
