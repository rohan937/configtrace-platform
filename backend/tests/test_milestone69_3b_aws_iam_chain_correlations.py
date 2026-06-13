"""M69.3B — AWS IAM Configuration Risk × IAM privilege-chain correlations.

Correlates AWS IAM Configuration Risk findings (``aws_iam_admin_policy_attached``
/ ``aws_access_key_unused`` from ``security_rules/aws.py``) with M69.3A IAM
privilege-chain Incident Signals (``signal_type="aws_iam_privilege_chain"``)
when BOTH reference the SAME IAM target entity (user/role) within the finding's
review window AND share the same integration (same AWS account/region):

  A. admin-policy risk  × any IAM privilege chain        → aws_iam_admin_risk_privilege_chain
  B. stale access-key risk × access-key-creation chain   → aws_iam_access_key_risk_privilege_chain

Rule C (dedicated role trust/policy risk) and Rule D (generic fallback) are
DEFERRED — no dedicated role-trust finding rule exists (the admin rule already
covers admin policies attached to roles via principal_name), and provider/
account-only matching is intentionally never done.

These tests assert each rule, entity matching, the review window, the
linked-anchor requirement, idempotency, the linked correlation-evidence signal,
the combined provider=aws endpoint, list filtering, workspace scoping,
permissions, privacy, and claim discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services import security_activity_event_service as activity_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_signal_service as signal_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "compromise confirmed", "attacker found", "someone has access",
    "unauthorized access confirmed", "breach detected", "attack detected",
]
_FORBIDDEN_RAW = [
    "requestparameters", "responseelements", "secretaccesskey",
    "aws_secret_access_key", "sessiontoken", "sourceipaddress", "accesskeyid",
]
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
        user_id=user.id, user_display_name=user.display_name or "M69.3B", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="aws", display_name="aws",
        encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _resource(db, integ, user, rid="iam-resource"):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="aws_iam", provider_resource_id=rid,
        display_name=rid, is_active=True,
    )
    db.add(r); db.commit(); db.refresh(r)
    return r


def _iam_finding(db, ws, integ, res, base_rule="aws_iam_admin_policy_attached", *,
                 principal_name=TARGET_USER, username=TARGET_USER, severity="high"):
    if base_rule == "aws_iam_admin_policy_attached":
        evidence = {"rule": base_rule, "principal_type": "user",
                    "principal_name": principal_name, "policy_name": "AdministratorAccess"}
        title = "AWS AdministratorAccess attached to an IAM principal"
    else:  # aws_access_key_unused
        evidence = {"rule": base_rule, "username": username,
                    "status": "Active", "last_used_age_days": 120}
        title = "AWS access key is active but unused"
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="aws",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=title, resource_id=res.id, description="desc",
        evidence=evidence, remediation={"summary": "fix"},
    )


def _anchor_event(db, ws_id, integ_id, *, event_type="aws.iam.attach_user_policy",
                  target=TARGET_USER, occurred=None):
    """Create a CloudTrail anchor activity event (what a chain signal links to)."""
    norm = activity_svc.normalize_activity_event(
        provider="aws", source="cloudtrail", event_type=event_type,
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"ct-{uuid.uuid4().hex[:12]}",
        actor_id="admin-user", actor_type="IAMUser",
        resource_type="aws_iam", resource_id=target,
        metadata={"event_name": event_type.split(".")[-1], "user_name": "admin-user",
                  "resource_name": target, "account_id": "123456789012"},
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _chain_signal(db, ws_id, integ_id, *, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant", occurred=None,
                  with_anchor=True, target_is_role=False):
    """Build an M69.3A-shaped aws_iam_privilege_chain signal directly."""
    when = occurred or (datetime.now(timezone.utc) - timedelta(minutes=20))
    anchor_id = None
    if with_anchor:
        anchor = _anchor_event(db, ws_id, integ_id, target=target, occurred=when)
        anchor_id = anchor.id
    md = {
        "source": "cloudtrail",
        "chain_pattern": chain_pattern,
        "event_types": "aws.iam.create_user,aws.iam.attach_user_policy",
        "actor_id": "admin-user",
        "resource_name": target,
        "target_user": None if target_is_role else target,
        "target_role": target if target_is_role else None,
        "chain_steps": 2,
        "event_count": 2,
        "chain_window_minutes": 60,
    }
    signal = {
        "provider": "aws",
        "integration_id": integ_id,
        "signal_key": f"aws.iam_chain.{chain_pattern}",
        "signal_type": "aws_iam_privilege_chain",
        "severity": "high",
        "status": "open",
        "title": f"AWS IAM privilege-chain activity ({target})",
        "summary": "IAM privilege-chain activity. This may require review.",
        "evidence_level": "activity",
        "confidence": "medium",
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": anchor_id,
        "metadata": signal_svc.sanitize_signal_metadata(md),
    }
    _o, row = signal_svc.upsert_incident_signal(workspace_id=ws_id, signal=signal, db=db)
    return row


def _gen_iam(db, ws_id):
    return corr_svc.generate_aws_iam_chain_correlations(workspace_id=ws_id, db=db)


def _gen_all(db, ws_id):
    return corr_svc.generate_aws_correlations(workspace_id=ws_id, db=db)


def _corrs(db, ws_id, ctype=None):
    items, _ = corr_svc.list_correlations(
        workspace_id=ws_id, db=db, provider="aws", correlation_type=ctype)
    return items


def _cleanup(db, ws_id):
    db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == ws_id).delete(synchronize_session=False)
    db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == ws_id).delete(synchronize_session=False)
    integ_ids = [i.id for i in db.query(Integration).filter(Integration.workspace_id == ws_id).all()]
    if integ_ids:
        db.query(Resource).filter(Resource.integration_id.in_(integ_ids)).delete(synchronize_session=False)
        db.query(Integration).filter(Integration.id.in_(integ_ids)).delete(synchronize_session=False)
    db.commit()


# ── A. admin-policy risk × IAM privilege chain ───────────────────────────────

def test_admin_risk_privilege_chain_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id, ctype="aws_iam_admin_risk_privilege_chain")[0]
        assert c.provider == "aws"
        assert c.confidence == "high"
        assert c.correlation_metadata.get("source_signal_type") == "aws_iam_privilege_chain"
        assert c.correlation_metadata.get("target_user") == TARGET_USER
        assert c.correlation_metadata.get("chain_pattern") == "user_create_privilege_grant"
        assert c.linked_finding_id is not None and c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


def test_admin_risk_matches_role_target(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    # AdministratorAccess attached to a ROLE; chain targets the same role.
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_ROLE)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_ROLE,
                  chain_pattern="role_create_privilege_grant", target_is_role=True)
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id, ctype="aws_iam_admin_risk_privilege_chain")[0]
        assert c.correlation_metadata.get("target_role") == TARGET_ROLE
    finally:
        _cleanup(db_session, ws.id)


# ── B. access-key risk × access-key-creation chain ───────────────────────────

def test_access_key_risk_with_access_key_chain_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_access_key_unused", username=TARGET_USER,
                 severity="medium")
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="privilege_grant_access_key")
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id, ctype="aws_iam_access_key_risk_privilege_chain")[0]
        assert c.correlation_type == "aws_iam_access_key_risk_privilege_chain"
    finally:
        _cleanup(db_session, ws.id)


def test_access_key_risk_wrong_chain_pattern_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    # Access-key risk but chain is a user-create pattern (not access-key creation).
    _iam_finding(db_session, ws, integ, res, "aws_access_key_unused", username=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── negatives ─────────────────────────────────────────────────────────────────

def test_different_target_entity_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name="user-a")
    _chain_signal(db_session, ws.id, integ.id, target="user-b",
                  chain_pattern="user_create_privilege_grant")
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_different_integration_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ_a = _integ(db_session, test_user, ws.id)
    integ_b = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ_a, test_user)
    _iam_finding(db_session, ws, integ_a, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    # Chain signal under a DIFFERENT integration (different AWS account).
    _chain_signal(db_session, ws.id, integ_b.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_chain_signal_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    # Chain signal active 48h ago — outside the finding's ±24h window.
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant", occurred=old)
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_chain_signal_without_anchor_skipped(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant", with_anchor=False)
    try:
        s = _gen_iam(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── idempotency + linked signal ───────────────────────────────────────────────

def test_idempotent_regeneration(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        s1 = _gen_iam(db_session, ws.id)
        s2 = _gen_iam(db_session, ws.id)
        assert s1["correlations_created"] == 1
        assert s2["correlations_created"] == 0
        assert s2["correlations_skipped"] == 1
        assert len(_corrs(db_session, ws.id)) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_correlation_creates_linked_signal(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    finding = _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                           principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        _gen_iam(db_session, ws.id)
        corr = _corrs(db_session, ws.id)[0]
        assert corr.linked_signal_id is not None
        sig = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.id == corr.linked_signal_id).first()
        assert sig is not None
        assert sig.provider == "aws"
        assert sig.evidence_level == "correlation"
        assert sig.linked_finding_id == finding.id
    finally:
        _cleanup(db_session, ws.id)


# ── combined endpoint generates IAM chain correlations ────────────────────────

def test_combined_provider_aws_generates_iam_chain(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        s = _gen_all(db_session, ws.id)
        assert s["correlations_created"] == 1
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert "aws_iam_admin_risk_privilege_chain" in types
    finally:
        _cleanup(db_session, ws.id)


# ── list filter + workspace scoping ───────────────────────────────────────────

def test_list_filter_and_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws_a, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws_a.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        _gen_iam(db_session, ws_a.id)
        assert len(_corrs(db_session, ws_a.id, ctype="aws_iam_admin_risk_privilege_chain")) == 1
        assert _corrs(db_session, ws_b.id) == []
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
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        _gen_iam(db_session, ws.id)
        allowed = {
            "source", "source_signal_type", "chain_pattern", "finding_rule",
            "finding_severity", "event_type", "target_user", "target_role",
            "resource_id", "event_count", "window_hours",
        }
        for c in _corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden claim {phrase!r}"
            for raw in _FORBIDDEN_RAW:
                assert raw not in low, f"raw field {raw!r} leaked"
            assert set(c.correlation_metadata.keys()) <= allowed
            assert "may require review" in c.summary.lower()
            assert "does not confirm compromise" in c.summary.lower()
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


def test_owner_can_generate_and_list_via_endpoint(client, test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _iam_finding(db_session, ws, integ, res, "aws_iam_admin_policy_attached",
                 principal_name=TARGET_USER)
    _chain_signal(db_session, ws.id, integ.id, target=TARGET_USER,
                  chain_pattern="user_create_privilege_grant")
    try:
        gen = client.post("/security/correlations/generate", json={"provider": "aws"})
        assert gen.status_code == 200
        body = gen.json()
        assert body["provider"] == "aws"
        assert body["correlations_created"] == 1

        lst = client.get(
            "/security/correlations?provider=aws"
            "&correlation_type=aws_iam_admin_risk_privilege_chain")
        assert lst.status_code == 200
        lb = lst.json()
        assert lb["total"] == 1
        assert lb["items"][0]["correlation_type"] == "aws_iam_admin_risk_privilege_chain"
    finally:
        _cleanup(db_session, ws.id)
