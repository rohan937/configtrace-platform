"""M69.2A — AWS S3 exposure × S3 object-activity correlations.

Links an AWS S3 public-EXPOSURE Configuration Risk finding (``aws_s3_public_policy``
/ ``aws_s3_public_acl``) to S3 OBJECT-LEVEL activity (``security_activity_events``
provider=aws, source="s3_data_event" — ingested in M67.8) for the SAME bucket
within the finding's review window:

  * exposure risk + GetObject activity  → aws_s3_public_getobject_activity
  * exposure risk + ListBucket activity → aws_s3_public_listbucket_activity
  * exposure risk + object-access spike → aws_s3_public_access_spike_activity (M67.9)

These tests assert each rule, the bucket join key (no different-bucket / account-
only matching), the time window, the no-bucket guard, idempotency, the linked
correlation-evidence signal, the combined provider=aws endpoint (alerts + S3
activity), list filtering, workspace scoping, permissions, privacy (no raw object
keys / IPs / requestParameters / responseElements / tokens / secrets / keys), and
claim discipline (never asserts data exfiltration or unauthorized access).
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
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_permission_service
from app.services import workspace_service

_FORBIDDEN = [
    "data exfiltration confirmed", "breach detected", "attacker found",
    "compromise confirmed", "someone has access", "unauthorized access confirmed",
    "attack detected",
]
_FORBIDDEN_RAW = [
    "requestparameters", "responseelements", "secretaccesskey",
    "aws_secret_access_key", "sessiontoken", "sourceipaddress",
]
BUCKET = "acme-prod-bucket"
RAW_KEY = "exports/customers/ssn-2026.csv"


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.2A", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="aws", display_name="aws",
        encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _resource(db, integ, user, rid=BUCKET):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="aws_s3_bucket", provider_resource_id=rid,
        display_name=rid, is_active=True,
    )
    db.add(r); db.commit(); db.refresh(r)
    return r


def _finding(db, ws, integ, res, base_rule="aws_s3_public_policy", *, bucket=BUCKET, severity="critical"):
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="aws",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title="S3 bucket policy allows public access", resource_id=res.id,
        description="desc", evidence={"rule": base_rule, "bucket": bucket},
        remediation={"summary": "fix"},
    )


def _s3_event(db, ws_id, integ_id, event_name, *, bucket=BUCKET, occurred=None,
              object_key=RAW_KEY):
    """Create an S3 data-event activity row via the M67.8 normalizer path.

    Uses normalize_s3_data_event so the privacy gate (object-key hash + safe prefix,
    no raw key) is exercised exactly as in production.
    """
    from app.services import aws_s3_data_event_ingestion_service as s3_ing
    when = occurred or datetime.now(timezone.utc)
    record = {
        "eventSource": "s3.amazonaws.com",
        "eventCategory": "Data",
        "eventName": event_name,
        "eventID": uuid.uuid4().hex,
        "eventTime": when.isoformat(),
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "readOnly": event_name in ("GetObject", "ListBucket", "HeadObject"),
        "userIdentity": {"type": "IAMUser", "userName": "deploy-bot",
                         "accountId": "123456789012"},
        "requestParameters": {"bucketName": bucket, "key": object_key},
        "sourceIPAddress": "203.0.113.40",
    }
    norm = s3_ing.normalize_s3_data_event(record)
    assert norm is not None
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen_s3(db, ws_id):
    return corr_svc.generate_aws_s3_exposure_activity_correlations(workspace_id=ws_id, db=db)


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


# ── A. GetObject ──────────────────────────────────────────────────────────────

def test_exposure_plus_getobject_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res)
    _s3_event(db_session, ws.id, integ.id, "GetObject")
    try:
        s = _gen_s3(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id, ctype="aws_s3_public_getobject_activity")[0]
        assert c.provider == "aws"
        assert c.correlation_metadata.get("bucket_name") == BUCKET
        assert c.correlation_metadata.get("event_count") == 1
        assert c.linked_finding_id is not None and c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


# ── B. ListBucket ─────────────────────────────────────────────────────────────

def test_exposure_plus_listbucket_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, "aws_s3_public_acl")
    _s3_event(db_session, ws.id, integ.id, "ListBucket", object_key=None)
    try:
        _gen_s3(db_session, ws.id)
        c = _corrs(db_session, ws.id, ctype="aws_s3_public_listbucket_activity")[0]
        assert c.correlation_type == "aws_s3_public_listbucket_activity"
    finally:
        _cleanup(db_session, ws.id)


# ── C. object-access spike ────────────────────────────────────────────────────

def test_exposure_plus_access_spike_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res)
    # Enough GetObject events to trigger an M67.9 spike signal, then generate it.
    for _ in range(6):
        _s3_event(db_session, ws.id, integ.id, "GetObject")
    from app.services import aws_s3_access_signal_service as spike_svc
    spike_svc.generate_aws_s3_access_signals(workspace_id=ws.id, db=db_session, read_threshold=5)
    try:
        _gen_s3(db_session, ws.id)
        keys = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert "aws_s3_public_access_spike_activity" in keys
    finally:
        _cleanup(db_session, ws.id)


# ── negatives ─────────────────────────────────────────────────────────────────

def test_different_bucket_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res, bucket=BUCKET)
    _s3_event(db_session, ws.id, integ.id, "GetObject", bucket="some-other-bucket")
    try:
        s = _gen_s3(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res)
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _s3_event(db_session, ws.id, integ.id, "GetObject", occurred=old)
    try:
        s = _gen_s3(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_event_without_bucket_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res)
    # Build a normalized S3 event then strip its bucket (resource_id + metadata).
    ev = _s3_event(db_session, ws.id, integ.id, "GetObject")
    ev.resource_id = None
    md = dict(ev.event_metadata or {})
    md["bucket_name"] = None
    ev.event_metadata = md
    db_session.commit()
    try:
        s = _gen_s3(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── idempotency + linked signal ───────────────────────────────────────────────

def test_idempotent_regeneration(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws, integ, res)
    _s3_event(db_session, ws.id, integ.id, "GetObject")
    try:
        s1 = _gen_s3(db_session, ws.id)
        s2 = _gen_s3(db_session, ws.id)
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
    finding = _finding(db_session, ws, integ, res)
    _s3_event(db_session, ws.id, integ.id, "GetObject")
    try:
        _gen_s3(db_session, ws.id)
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


# ── combined endpoint generates both alert + S3-activity correlations ─────────

def test_combined_provider_aws_generates_s3_activity(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    # Alert side (M67.3): S3 finding + provider alert for same bucket.
    _finding(db_session, ws, integ, res)
    alert_norm = activity_svc.normalize_activity_event(
        provider="aws", source="security_alert", event_type="aws.guardduty.s3_finding",
        occurred_at=datetime.now(timezone.utc), provider_event_id=uuid.uuid4().hex,
        actor_id=None, resource_type="aws_resource", resource_id=BUCKET,
        metadata={"severity_label": "high", "region": "us-east-1", "account_id": "123456789012"},
    )
    activity_svc.upsert_activity_event(
        workspace_id=ws.id, integration_id=integ.id, normalized=alert_norm, db=db_session)
    # Activity side (M69.2A): S3 GetObject for same bucket.
    _s3_event(db_session, ws.id, integ.id, "GetObject")
    try:
        s = _gen_all(db_session, ws.id)
        # 1 alert correlation + 1 getobject correlation.
        assert s["correlations_created"] == 2
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert "aws_s3_public_access_alert" in types
        assert "aws_s3_public_getobject_activity" in types
    finally:
        _cleanup(db_session, ws.id)


# ── list filter + workspace scoping ───────────────────────────────────────────

def test_list_filter_and_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    res = _resource(db_session, integ, test_user)
    _finding(db_session, ws_a, integ, res)
    _s3_event(db_session, ws_a.id, integ.id, "GetObject")
    try:
        _gen_s3(db_session, ws_a.id)
        assert len(_corrs(db_session, ws_a.id, ctype="aws_s3_public_getobject_activity")) == 1
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
    _finding(db_session, ws, integ, res)
    _s3_event(db_session, ws.id, integ.id, "GetObject", object_key=RAW_KEY)
    try:
        _gen_s3(db_session, ws.id)
        allowed = {"source", "finding_rule", "finding_severity", "event_type",
                   "bucket_name", "object_key_prefix", "event_count", "window_hours"}
        for c in _corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden claim {phrase!r}"
            for raw in _FORBIDDEN_RAW:
                assert raw not in low, f"raw marker {raw!r} leaked"
            # Raw object key / IP never present.
            assert "ssn-2026" not in blob and "203.0.113.40" not in blob
            assert "customers/ssn" not in blob
            assert set(c.correlation_metadata.keys()) <= allowed
            assert "may require review" in c.summary.lower()
            assert "does not confirm data exfiltration" in c.summary.lower()
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
    _finding(db_session, ws, integ, res)
    _s3_event(db_session, ws.id, integ.id, "GetObject")
    try:
        gen = client.post("/security/correlations/generate", json={"provider": "aws"})
        assert gen.status_code == 200
        body = gen.json()
        assert body["provider"] == "aws"
        assert body["correlations_created"] == 1

        lst = client.get(
            "/security/correlations?provider=aws"
            "&correlation_type=aws_s3_public_getobject_activity")
        assert lst.status_code == 200
        lb = lst.json()
        assert lb["total"] == 1
        assert lb["items"][0]["correlation_type"] == "aws_s3_public_getobject_activity"
    finally:
        _cleanup(db_session, ws.id)
