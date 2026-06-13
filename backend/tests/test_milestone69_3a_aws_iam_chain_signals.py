"""M69.3A — AWS IAM privilege-escalation chain detection.

Groups normalized CloudTrail management activity by TARGET IAM ENTITY (the
user/role being created/modified via ``resource_id``) and detects ORDERED
privilege-escalation SEQUENCES within a configurable chain window, surfacing
them as Incident Signals (``signal_type="aws_iam_privilege_chain"``,
``evidence_level="activity"``, ``confidence="medium"``).

Patterns implemented (all require same workspace + provider + source + ordered
sequence + within chain_window):
  A. CreateUser → AttachUserPolicy / PutUserPolicy   → aws.iam_chain.user_create_privilege_grant
  B. CreateRole → AttachRolePolicy / PutRolePolicy   → aws.iam_chain.role_create_privilege_grant
  C. AttachUserPolicy / PutUserPolicy → CreateAccessKey → aws.iam_chain.privilege_grant_access_key

Patterns deferred:
  D. UpdateAssumeRolePolicy → AssumeRole: AssumeRole not ingested.
  E. AddUserToGroup → CreateAccessKey: AddUserToGroup not ingested.

These tests assert each pattern, sequential-order enforcement, chain-window
gating, different-entity isolation, idempotency, workspace scoping, endpoint
admin gating, privacy (no raw CloudTrail JSON, requestParameters,
responseElements, access keys, secrets, tokens, IPs), and claim discipline.
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
from app.services import aws_iam_chain_signal_service as chain_svc
from app.services import security_activity_event_service as activity_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
_FORBIDDEN_RAW = [
    "requestparameters", "responseelements", "secretaccesskey",
    "aws_secret_access_key", "sessiontoken", "sourceipaddress",
    "accesskeyid",
]
SOURCE = "cloudtrail"
TARGET_USER = "deploy-bot"
TARGET_ROLE = "demo-role"


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.3A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="aws", display_name="aws",
        encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _ct_event(db, ws_id, integ_id, event_type, *,
              resource_id, actor_id="admin-user", occurred=None):
    """Create a CloudTrail management-event activity row directly."""
    norm = activity_svc.normalize_activity_event(
        provider="aws", source=SOURCE, event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"ct-{uuid.uuid4().hex[:12]}",
        actor_id=actor_id, actor_type="IAMUser",
        resource_type="aws_iam",
        resource_id=resource_id,
        metadata={
            "event_name": event_type.split(".")[-1],
            "event_source": "iam.amazonaws.com",
            "user_name": actor_id,
            "resource_name": resource_id,
            "aws_region": "us-east-1",
            "account_id": "123456789012",
        },
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen(db, ws_id, *, chain_window_minutes=60, lookback_hours=24):
    return chain_svc.generate_aws_iam_chain_signals(
        workspace_id=ws_id, db=db,
        chain_window_minutes=chain_window_minutes,
        lookback_hours=lookback_hours,
    )


def _sigs(db, ws_id):
    return db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id,
        SecurityIncidentSignal.signal_type == "aws_iam_privilege_chain",
    ).all()


def _cleanup(db, ws_id):
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── A. CreateUser → AttachUserPolicy ─────────────────────────────────────────

def test_pattern_a_create_user_attach_policy(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    t1 = t0 + timedelta(minutes=10)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s = _gen(db_session, ws.id)
        assert s["signals_created"] == 1
        sig = _sigs(db_session, ws.id)[0]
        assert sig.signal_type == "aws_iam_privilege_chain"
        assert sig.evidence_level == "activity"
        assert sig.confidence == "medium"
        assert sig.linked_activity_event_id is not None
        assert sig.signal_metadata.get("chain_pattern") == "user_create_privilege_grant"
        assert sig.signal_metadata.get("chain_steps") == 2
    finally:
        _cleanup(db_session, ws.id)


def test_pattern_a_create_user_put_policy(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)
    t1 = t0 + timedelta(minutes=5)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.put_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s = _gen(db_session, ws.id)
        assert s["signals_created"] == 1
        assert _sigs(db_session, ws.id)[0].signal_metadata.get("chain_pattern") == "user_create_privilege_grant"
    finally:
        _cleanup(db_session, ws.id)


# ── B. CreateRole → AttachRolePolicy ─────────────────────────────────────────

def test_pattern_b_create_role_attach_policy(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=25)
    t1 = t0 + timedelta(minutes=8)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_role",
              resource_id=TARGET_ROLE, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_role_policy",
              resource_id=TARGET_ROLE, occurred=t1)
    try:
        s = _gen(db_session, ws.id)
        assert s["signals_created"] == 1
        sig = _sigs(db_session, ws.id)[0]
        assert sig.signal_metadata.get("chain_pattern") == "role_create_privilege_grant"
    finally:
        _cleanup(db_session, ws.id)


# ── C. AttachUserPolicy → CreateAccessKey ────────────────────────────────────

def test_pattern_c_privilege_grant_then_access_key(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=40)
    t1 = t0 + timedelta(minutes=15)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_access_key",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s = _gen(db_session, ws.id)
        assert s["signals_created"] == 1
        sig = _sigs(db_session, ws.id)[0]
        assert sig.signal_metadata.get("chain_pattern") == "privilege_grant_access_key"
        # Anchor should be the access key event (highest rank).
        assert sig.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── negatives ─────────────────────────────────────────────────────────────────

def test_reversed_order_no_signal(test_user, db_session):
    """AttachPolicy AFTER CreateAccessKey — wrong order, no Pattern C signal."""
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=40)
    t1 = t0 + timedelta(minutes=15)
    # Access key FIRST, policy LATER — Pattern C requires policy → key order.
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_access_key",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s = _gen(db_session, ws.id)
        # Pattern A (no CreateUser), Pattern B (no CreateRole), Pattern C (wrong order).
        chain_sigs = [sig for sig in _sigs(db_session, ws.id)
                      if sig.signal_metadata.get("chain_pattern") == "privilege_grant_access_key"]
        assert chain_sigs == []
    finally:
        _cleanup(db_session, ws.id)


def test_outside_chain_window_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    t1 = t0 + timedelta(minutes=90)  # 90 min gap > chain_window=60
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s = _gen(db_session, ws.id, chain_window_minutes=60)
        assert s["signals_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_different_target_entity_no_cross_chain(test_user, db_session):
    """CreateUser for userA, AttachPolicy for userB — different entities, no chain."""
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)
    t1 = t0 + timedelta(minutes=5)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id="user-a", occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id="user-b", occurred=t1)
    try:
        s = _gen(db_session, ws.id)
        # user-a has CreateUser but no grant; user-b has grant but no CreateUser.
        chain_sigs = [sig for sig in _sigs(db_session, ws.id)
                      if sig.signal_metadata.get("chain_pattern") == "user_create_privilege_grant"]
        assert chain_sigs == []
    finally:
        _cleanup(db_session, ws.id)


def test_events_outside_lookback_no_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    # Events 48h ago; lookback=24h.
    t0 = datetime.now(timezone.utc) - timedelta(hours=48)
    t1 = t0 + timedelta(minutes=5)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s = _gen(db_session, ws.id, lookback_hours=24)
        assert s["signals_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_no_resource_id_events_excluded(test_user, db_session):
    """Events without resource_id cannot be chain-grouped."""
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)
    t1 = t0 + timedelta(minutes=5)
    ev1 = _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
                    resource_id=TARGET_USER, occurred=t0)
    ev2 = _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
                    resource_id=TARGET_USER, occurred=t1)
    # Clear resource_id on both events.
    ev1.resource_id = None; ev2.resource_id = None
    db_session.commit()
    try:
        s = _gen(db_session, ws.id)
        assert s["signals_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── idempotency ────────────────────────────────────────────────────────────────

def test_idempotent_regeneration(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    t1 = t0 + timedelta(minutes=10)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        s1 = _gen(db_session, ws.id)
        s2 = _gen(db_session, ws.id)
        assert s1["signals_created"] == 1
        assert s2["signals_created"] == 0
        assert s2["signals_skipped"] == 1
        assert len(_sigs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


# ── workspace scoping ─────────────────────────────────────────────────────────

def test_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)
    _ct_event(db_session, ws_a.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws_a.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t0 + timedelta(minutes=5))
    try:
        _gen(db_session, ws_a.id)
        assert len(_sigs(db_session, ws_a.id)) == 1
        assert _sigs(db_session, ws_b.id) == []
    finally:
        _cleanup(db_session, ws_a.id)
        _cleanup(db_session, ws_b.id)
        try:
            db_session.delete(other); db_session.commit()
        except Exception:
            db_session.rollback()


# ── privacy + claim discipline ────────────────────────────────────────────────

def test_metadata_privacy_and_claims(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    t1 = t0 + timedelta(minutes=10)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t1)
    try:
        _gen(db_session, ws.id)
        allowed = {
            "source", "chain_pattern", "event_types", "actor_id", "resource_name",
            "target_user", "target_role", "policy_arn", "chain_steps",
            "event_count", "chain_window_minutes", "window_start", "window_end",
        }
        for sig in _sigs(db_session, ws.id):
            blob = json.dumps({"t": sig.title, "s": sig.summary, "m": sig.signal_metadata},
                              default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden claim {phrase!r}"
            for raw in _FORBIDDEN_RAW:
                assert raw not in low, f"raw field {raw!r} leaked"
            assert set(sig.signal_metadata.keys()) <= allowed
            assert "may require review" in sig.summary.lower()
            assert "does not confirm compromise" in sig.summary.lower()
    finally:
        _cleanup(db_session, ws.id)


# ── endpoint admin gating ─────────────────────────────────────────────────────

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
    integ = _integ(db_session, test_user, ws.id)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.create_user",
              resource_id=TARGET_USER, occurred=t0)
    _ct_event(db_session, ws.id, integ.id, "aws.iam.attach_user_policy",
              resource_id=TARGET_USER, occurred=t0 + timedelta(minutes=5))
    try:
        resp = client.post("/security/aws-iam-chains/generate-signals",
                           json={"chain_window_minutes": 60})
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "aws"
        assert body["source"] == "cloudtrail"
        assert body["signals_created"] == 1
        assert "chains_scanned" in body and "events_scanned" in body
    finally:
        _cleanup(db_session, ws.id)
