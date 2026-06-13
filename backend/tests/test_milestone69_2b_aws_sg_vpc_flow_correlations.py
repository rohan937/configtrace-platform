"""M69.2B — AWS Security Group exposure × VPC Flow Log correlations.

Links an AWS Security Group public-EXPOSURE Configuration Risk finding
(``aws_public_admin_port`` / ``aws_public_database_port`` /
``aws_public_all_ports``) to VPC Flow Log network activity
(``security_activity_events`` provider=aws, source="vpc_flow_log" — ingested
in M67.10) for the SAME integration (same AWS account/region) when the VPC
flow's destination port falls within the SG rule's exposed port range, within
the finding's review window:

  * SG admin-port exposure + ACCEPT flow to admin port   → aws_sg_public_admin_port_flow
  * SG database-port exposure + ACCEPT flow to DB port   → aws_sg_public_database_port_flow
  * SG all-ports exposure + ACCEPT flow to admin/DB port → admin/DB correlation
  * SG exposure + ≥2 REJECT flows to exposed port       → aws_sg_public_rejected_flow_activity

JOIN: same ``integration_id`` (same AWS account/region) + dst_port in SG's
exposed range + risk-area match + review window. No SG→ENI mapping is
attempted (no such data exists; deferred per spec).

These tests assert each rule, port-range matching, protocol matching, the
no-dst-port guard, the reject threshold, idempotency, the linked
correlation-evidence signal, the combined provider=aws endpoint, list
filtering, workspace scoping, permissions, privacy (no raw IPs, raw flow lines,
payloads, headers, tokens, secrets, access keys), and claim discipline (never
asserts network intrusion or unauthorized access).
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
    "network intrusion confirmed", "breach detected", "attacker found",
    "compromise confirmed", "someone has access", "unauthorized access confirmed",
    "attack detected",
]
_FORBIDDEN_RAW = [
    "sourceipaddress", "destinationipaddress", "srcaddr", "dstaddr",
    "requestparameters", "responseelements", "secretaccesskey", "sessiontoken",
]
ENI = "eni-0abc1234demo"
SG_ID = "sg-0demo12345"
RAW_SRC_IP = "203.0.113.77"
RAW_DST_IP = "10.0.0.8"


# ── builders ──────────────────────────────────────────────────────────────────

def _new_user(db, label="owner"):
    u = User(clerk_id=f"test_clerk_{uuid.uuid4().hex[:12]}",
             email=f"{label}_{uuid.uuid4().hex[:8]}@configtrace.test", display_name=label)
    db.add(u); db.commit(); db.refresh(u)
    return u


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M69.2B", db=db)


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"})
    i = Integration(
        user_id=user.id, workspace_id=ws_id, provider="aws", display_name="aws",
        encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db.add(i); db.commit(); db.refresh(i)
    return i


def _resource(db, integ, user, rid=SG_ID):
    r = Resource(
        integration_id=integ.id, user_id=user.id,
        provider_resource_type="aws_security_group", provider_resource_id=rid,
        display_name=rid, is_active=True,
    )
    db.add(r); db.commit(); db.refresh(r)
    return r


def _sg_finding(db, ws, integ, res, base_rule="aws_public_admin_port", *,
                severity="high", from_port=22, to_port=22, port_category="admin"):
    evidence = {
        "rule": base_rule,
        "group_id": SG_ID,
        "direction": "ingress",
        "port_category": port_category,
        "cidr": "0.0.0.0/0",
        "protocol": "tcp",
    }
    if from_port is not None:
        evidence["from_port"] = from_port
    if to_port is not None:
        evidence["to_port"] = to_port
    return finding_svc.upsert_active_finding(
        db=db, workspace_id=ws.id, integration_id=integ.id, provider="aws",
        finding_key=f"{base_rule}:{uuid.uuid4().hex[:8]}", severity=severity,
        title=f"AWS security group exposes {port_category} port(s) to the internet",
        resource_id=res.id, description="desc",
        evidence=evidence, remediation={"summary": "fix"},
    )


def _flow_event(db, ws_id, integ_id, *, dst_port=22, action="ACCEPT",
                protocol=6, interface_id=ENI, occurred=None):
    norm = activity_svc.normalize_activity_event(
        provider="aws", source="vpc_flow_log",
        event_type="aws.vpc.flow.accept" if action == "ACCEPT" else "aws.vpc.flow.reject",
        occurred_at=occurred or datetime.now(timezone.utc),
        provider_event_id=f"vpcfl-{uuid.uuid4().hex[:16]}",
        actor_id=None, actor_type="network_flow",
        resource_type="aws_network_interface",
        resource_id=interface_id,
        source_ip=RAW_SRC_IP,
        metadata={
            "interface_id": interface_id,
            "src_port": 52000,
            "dst_port": dst_port,
            "protocol": protocol,
            "packets": 8,
            "bytes": 640,
            "action": action,
            "log_status": "OK",
            "destination_ip_hash": activity_svc.hash_source_ip(RAW_DST_IP),
        },
    )
    _o, row = activity_svc.upsert_activity_event(
        workspace_id=ws_id, integration_id=integ_id, normalized=norm, db=db)
    return row


def _gen_sg(db, ws_id):
    return corr_svc.generate_aws_sg_vpc_flow_correlations(workspace_id=ws_id, db=db)


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


# ── A. admin-port ACCEPT ──────────────────────────────────────────────────────

def test_admin_port_accept_flow_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 1
        c = _corrs(db_session, ws.id, ctype="aws_sg_public_admin_port_flow")[0]
        assert c.provider == "aws"
        assert c.correlation_metadata.get("dst_port") == 22
        assert c.correlation_metadata.get("security_group_id") == SG_ID
        assert c.correlation_metadata.get("event_count") == 1
        assert c.linked_finding_id is not None and c.linked_activity_event_id is not None
    finally:
        _cleanup(db_session, ws.id)


def test_rdp_admin_port_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    # SG exposes port 22-3389 range, VPC flow to RDP port 3389.
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=3389, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=3389, action="ACCEPT")
    try:
        _gen_sg(db_session, ws.id)
        c = _corrs(db_session, ws.id, ctype="aws_sg_public_admin_port_flow")[0]
        assert c.correlation_metadata.get("dst_port") == 3389
    finally:
        _cleanup(db_session, ws.id)


# ── B. database-port ACCEPT ───────────────────────────────────────────────────

def test_database_port_accept_flow_correlates(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_database_port",
                severity="critical", from_port=3306, to_port=3306, port_category="database")
    _flow_event(db_session, ws.id, integ.id, dst_port=3306, action="ACCEPT")
    try:
        _gen_sg(db_session, ws.id)
        c = _corrs(db_session, ws.id, ctype="aws_sg_public_database_port_flow")[0]
        assert c.correlation_type == "aws_sg_public_database_port_flow"
        assert c.correlation_metadata.get("dst_port") == 3306
    finally:
        _cleanup(db_session, ws.id)


# ── C. all-ports finding → both admin + DB correlations ───────────────────────

def test_all_ports_finding_matches_admin_and_db(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    # from_port/to_port absent → all ports exposed.
    _sg_finding(db_session, ws, integ, res, "aws_public_all_ports",
                severity="critical", from_port=None, to_port=None, port_category="all")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    _flow_event(db_session, ws.id, integ.id, dst_port=5432, action="ACCEPT")
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 2  # admin + DB
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert "aws_sg_public_admin_port_flow" in types
        assert "aws_sg_public_database_port_flow" in types
    finally:
        _cleanup(db_session, ws.id)


# ── D. rejected-flow threshold ────────────────────────────────────────────────

def test_reject_threshold_creates_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    for _ in range(3):  # threshold is 2
        _flow_event(db_session, ws.id, integ.id, dst_port=22, action="REJECT")
    try:
        _gen_sg(db_session, ws.id)
        c = _corrs(db_session, ws.id, ctype="aws_sg_public_rejected_flow_activity")[0]
        assert c.confidence == "low"  # rejected flow is weaker evidence
        assert c.correlation_metadata.get("event_count") == 3
    finally:
        _cleanup(db_session, ws.id)


def test_single_reject_below_threshold_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="REJECT")  # only 1
    try:
        s = _gen_sg(db_session, ws.id)
        reject_corrs = _corrs(db_session, ws.id, ctype="aws_sg_public_rejected_flow_activity")
        assert reject_corrs == []
    finally:
        _cleanup(db_session, ws.id)


# ── negatives ─────────────────────────────────────────────────────────────────

def test_different_port_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=80, action="ACCEPT")  # not an admin port
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 0
        assert _corrs(db_session, ws.id) == []
    finally:
        _cleanup(db_session, ws.id)


def test_port_outside_sg_range_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    # SG only exposes port 22, but flow targets 3389 (admin but not in range 22..22).
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=3389, action="ACCEPT")
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_outside_window_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT", occurred=old)
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_event_without_dst_port_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    ev = _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    # Strip dst_port from the event's metadata.
    md = dict(ev.event_metadata or {})
    md["dst_port"] = None
    ev.event_metadata = md
    db_session.commit()
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


def test_different_integration_no_correlation(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ_a = _integ(db_session, test_user, ws.id)
    integ_b = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ_a, test_user)
    _sg_finding(db_session, ws, integ_a, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    # Flow is on a DIFFERENT integration → different AWS account.
    _flow_event(db_session, ws.id, integ_b.id, dst_port=22, action="ACCEPT")
    try:
        s = _gen_sg(db_session, ws.id)
        assert s["correlations_created"] == 0
    finally:
        _cleanup(db_session, ws.id)


# ── idempotency + linked signal ───────────────────────────────────────────────

def test_idempotent_regeneration(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    try:
        s1 = _gen_sg(db_session, ws.id)
        s2 = _gen_sg(db_session, ws.id)
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
    finding = _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                          from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    try:
        _gen_sg(db_session, ws.id)
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


# ── combined endpoint generates alerts + S3 + SG correlations ─────────────────

def test_combined_provider_aws_generates_sg_vpc(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    try:
        s = _gen_all(db_session, ws.id)
        assert s["correlations_created"] == 1
        types = {c.correlation_type for c in _corrs(db_session, ws.id)}
        assert "aws_sg_public_admin_port_flow" in types
    finally:
        _cleanup(db_session, ws.id)


# ── list filter + workspace scoping ───────────────────────────────────────────

def test_list_filter_and_workspace_scoping(test_user, db_session):
    other = _new_user(db_session, "other")
    ws_a = _ws(test_user, db_session)
    ws_b = _ws(other, db_session)
    integ = _integ(db_session, test_user, ws_a.id)
    res = _resource(db_session, integ, test_user)
    _sg_finding(db_session, ws_a, integ, res, "aws_public_database_port",
                from_port=5432, to_port=5432, port_category="database")
    _flow_event(db_session, ws_a.id, integ.id, dst_port=5432, action="ACCEPT")
    try:
        _gen_sg(db_session, ws_a.id)
        assert len(_corrs(db_session, ws_a.id, ctype="aws_sg_public_database_port_flow")) == 1
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
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    try:
        _gen_sg(db_session, ws.id)
        allowed = {
            "source", "finding_rule", "finding_severity", "event_type",
            "security_group_id", "dst_port", "port_category", "interface_id",
            "protocol", "flow_action", "event_count", "window_hours",
        }
        for c in _corrs(db_session, ws.id):
            blob = json.dumps({"t": c.title, "s": c.summary, "m": c.correlation_metadata},
                              default=str)
            low = blob.lower()
            for phrase in _FORBIDDEN:
                assert phrase not in low, f"forbidden claim {phrase!r}"
            for raw in _FORBIDDEN_RAW:
                assert raw not in low, f"raw marker {raw!r} leaked"
            # Raw IPs never present.
            assert RAW_SRC_IP not in blob and RAW_DST_IP not in blob
            assert "203.0.113" not in blob and "10.0.0.8" not in blob
            assert set(c.correlation_metadata.keys()) <= allowed
            assert "may require review" in c.summary.lower()
            assert "does not confirm network intrusion" in c.summary.lower()
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
    _sg_finding(db_session, ws, integ, res, "aws_public_admin_port",
                from_port=22, to_port=22, port_category="admin")
    _flow_event(db_session, ws.id, integ.id, dst_port=22, action="ACCEPT")
    try:
        gen = client.post("/security/correlations/generate", json={"provider": "aws"})
        assert gen.status_code == 200
        body = gen.json()
        assert body["provider"] == "aws"
        assert body["correlations_created"] == 1

        lst = client.get(
            "/security/correlations?provider=aws"
            "&correlation_type=aws_sg_public_admin_port_flow")
        assert lst.status_code == 200
        lb = lst.json()
        assert lb["total"] == 1
        assert lb["items"][0]["correlation_type"] == "aws_sg_public_admin_port_flow"
    finally:
        _cleanup(db_session, ws.id)
