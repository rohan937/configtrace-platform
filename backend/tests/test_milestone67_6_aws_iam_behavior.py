"""M67.6 — AWS IAM behavior timelines from CloudTrail management events.

Groups normalized CloudTrail activity (provider=aws, source=cloudtrail) by IAM
principal and surfaces review-worthy behavior chains as Incident Signals
(signal_type="iam_behavior_timeline"). These tests assert pattern detection
(access-key+policy chain, admin-like policy, role trust policy, KMS protection,
S3 access control), that unrelated events produce nothing, idempotency,
workspace scoping, admin gating, claim discipline, and that no raw request
parameters / secrets / tokens / IPs land in the signal metadata.
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
from app.services import aws_iam_behavior_service as behavior_svc
from app.services import security_activity_event_service as activity_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "breach detected", "attacker found", "compromise confirmed",
    "someone has access", "unauthorized access confirmed", "attack detected",
]
RAW_IP = "203.0.113.99"
_ALLOWED_SIGNAL_META = {
    "event_types", "actor_id", "resource_id", "event_count", "window_start",
    "window_end", "principal_hash", "policy_name", "resource_name", "event_type",
}


# ── builders ──────────────────────────────────────────────────────────────────

def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M67.6", db=db)


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


def _ct_evt(db, ws_id, integ_id, event_type, actor, *, resource_id=None,
            resource_name=None, source_ip=None):
    norm = activity_svc.normalize_activity_event(
        provider="aws", source="cloudtrail", event_type=event_type,
        occurred_at=datetime.now(timezone.utc),
        provider_event_id=f"ct-{uuid.uuid4().hex[:12]}",
        actor_id=actor, actor_type="IAMUser",
        resource_type="aws_iam", resource_id=resource_id or actor,
        source_ip=source_ip,
        metadata={
            "event_name": event_type.split(".")[-1],
            "user_name": actor,
            "resource_name": resource_name,
            "principal_id_hash": "deadbeef" * 4,
        },
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen(db, ws_id):
    return behavior_svc.generate_aws_iam_behavior_signals(workspace_id=ws_id, db=db)


def _signals(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.provider == "aws",
        SecurityIncidentSignal.signal_type == "iam_behavior_timeline",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    db.commit()


# ── 1. access key + policy change → high signal ───────────────────────────────

def test_access_key_plus_policy_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.create_access_key", "alice", resource_name="alice")
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.attach_user_policy", "alice", resource_name="alice")
    try:
        summary = _gen(db_session, ws.id)
        assert summary["provider"] == "aws"
        keys = {s.signal_key for s in _signals(db_session, ws.id)}
        assert "aws.iam_behavior.access_key_policy_chain" in keys
        sig = next(s for s in _signals(db_session, ws.id)
                   if s.signal_key == "aws.iam_behavior.access_key_policy_chain")
        assert sig.severity == "high"
        assert sig.confidence == "medium"
        assert sig.evidence_level == "activity"
        assert sig.linked_activity_event_id is not None
        assert "create_access_key" in sig.signal_metadata.get("event_types", "")
    finally:
        _cleanup(db_session, ws.id)


# ── 2. admin-like policy attach → high signal ─────────────────────────────────

def test_admin_like_policy_change(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.attach_user_policy", "bob",
            resource_name="AdministratorAccess")
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.iam_behavior.admin_policy_change"), None)
        assert sig is not None
        assert sig.severity == "high"
        assert sig.signal_metadata.get("policy_name") == "AdministratorAccess"
    finally:
        _cleanup(db_session, ws.id)


# ── 3. role trust policy change → signal ──────────────────────────────────────

def test_role_trust_policy_change(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.update_assume_role_policy", "deploy-role")
    try:
        _gen(db_session, ws.id)
        keys = {s.signal_key for s in _signals(db_session, ws.id)}
        assert "aws.iam_behavior.role_trust_policy_change" in keys
    finally:
        _cleanup(db_session, ws.id)


# ── 4. KMS disable / schedule deletion → signal ───────────────────────────────

def test_kms_key_protection_change(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.kms.schedule_key_deletion", "carol", resource_id="key-9")
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.kms_behavior.key_protection_changed"), None)
        assert sig is not None
        assert sig.severity == "high"
    finally:
        _cleanup(db_session, ws.id)


# ── 5. S3 access control change → signal ──────────────────────────────────────

def test_s3_access_control_change(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.s3.put_bucket_policy", "dave", resource_id="bkt-1")
    try:
        _gen(db_session, ws.id)
        sig = next((s for s in _signals(db_session, ws.id)
                    if s.signal_key == "aws.s3_behavior.access_control_changed"), None)
        assert sig is not None
        assert sig.severity == "medium"
        # Must never infer data access.
        assert "data was accessed" in sig.summary  # phrased as a negation
        assert "does not infer" in sig.summary
    finally:
        _cleanup(db_session, ws.id)


# ── 6. unrelated event produces no signal ─────────────────────────────────────

def test_unrelated_event_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.cloudtrail.console_login", "erin")
    _ct_evt(db_session, ws.id, integ.id, "aws.cloudtrail.event", "erin")
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
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.create_access_key", "frank")
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.put_user_policy", "frank")
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
    _ct_evt(db_session, ws_a.id, integ_a.id, "aws.iam.create_access_key", "grace")
    _ct_evt(db_session, ws_a.id, integ_a.id, "aws.iam.attach_user_policy", "grace")
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


# ── 9. claim discipline + privacy of metadata ─────────────────────────────────

def test_no_forbidden_claims_and_no_raw_data(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _aws_integ(db_session, test_user, ws.id)
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.create_access_key", "heidi", source_ip=RAW_IP)
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.attach_role_policy", "heidi",
            resource_name="AdministratorAccess", source_ip=RAW_IP)
    try:
        _gen(db_session, ws.id)
        for s in _signals(db_session, ws.id):
            blob = json.dumps({"t": s.title, "s": s.summary, "m": s.signal_metadata}, default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden phrase {phrase!r}"
            assert "may require review" in s.summary.lower()
            # Privacy: only allowlisted metadata keys, no raw IP / secrets / blobs.
            assert set(s.signal_metadata.keys()) <= _ALLOWED_SIGNAL_META
            assert RAW_IP not in blob
            for bad in ("requestParameters", "responseElements", "secretAccessKey",
                        "sessionToken", "source_ip"):
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
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.create_access_key", "ivan")
    _ct_evt(db_session, ws.id, integ.id, "aws.iam.attach_user_policy", "ivan")
    try:
        resp = client.post("/security/aws-cloudtrail/generate-behavior-signals")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws"
        assert body["signals_created"] >= 1
        assert body["principals_scanned"] >= 1
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(Integration.id == integ.id).delete(synchronize_session=False)
        db_session.commit()
