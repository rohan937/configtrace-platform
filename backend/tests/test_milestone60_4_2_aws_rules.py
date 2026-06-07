"""M60.4.2 — expanded AWS security exposure rules.

Unit tests per rule (risky fires / safe does not / web-not-critical / malformed
ignored / evidence metadata-only) plus DB-backed evaluator tests for lifecycle
(dedupe + resolve) and multi-record separate findings.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.orm import Session

from app.connectors.aws_schema import (
    AWS_IAM_ACCESS_KEY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_S3_BUCKET,
    AWS_SECURITY_GROUP_RULE,
)
from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_finding import SecurityFinding
from app.models.snapshot import Snapshot
from app.models.user import User
from app.services import security_finding_evaluator as evaluator
from app.services.security_rules import aws as aws_rules

_SECRET_RE = re.compile(
    r"secret|token|password|api_?key|access_?key|private_?key|client_secret", re.I
)


# ── record builders ──────────────────────────────────────────────────────────


def _sg_rule(**over) -> dict:
    rec = {
        "record_type": AWS_SECURITY_GROUP_RULE,
        "record_id": "us-east-1/sg-123/abc",
        "name": "ingress tcp 22 0.0.0.0/0",
        "group_id": "sg-123",
        "region": "us-east-1",
        "direction": "ingress",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_ipv4": "0.0.0.0/0",
        "cidr_ipv6": None,
        "is_public": True,
        "port_category": "admin",
    }
    rec.update(over)
    return rec


def _s3(**over) -> dict:
    rec = {
        "record_type": AWS_S3_BUCKET,
        "record_id": "my-bucket",
        "name": "my-bucket",
        "bucket_name": "my-bucket",
        "policy_status_is_public": False,
        "public_principals_detected": False,
        "public_access_block_configured": True,
        "acl_all_users_read": False,
        "acl_all_users_write": False,
        "acl_authenticated_users_read": False,
        "acl_authenticated_users_write": False,
    }
    rec.update(over)
    return rec


def _iam_attach(**over) -> dict:
    rec = {
        "record_type": AWS_IAM_POLICY_ATTACHMENT,
        "record_id": "attach-abc",
        "name": "AdministratorAccess → deploy-bot",
        "principal_type": "user",
        "principal_id": "AID123",
        "principal_name": "deploy-bot",
        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "policy_name": "AdministratorAccess",
    }
    rec.update(over)
    return rec


def _access_key(**over) -> dict:
    rec = {
        "record_type": AWS_IAM_ACCESS_KEY,
        "record_id": "AKIAEXAMPLE1234",
        "name": "AKIAEXAMPLE1234",
        "access_key_id": "AKIAEXAMPLE1234",
        "username": "ci-user",
        "status": "Active",
        "last_used_age_days": 200,
    }
    rec.update(over)
    return rec


def _assert_evidence_safe(cands):
    for c in cands:
        for k in c.evidence.keys():
            assert not _SECRET_RE.search(k), f"sensitive evidence key: {k}"
        # The full access key id must never appear verbatim in evidence values.
        for v in c.evidence.values():
            assert v != "AKIAEXAMPLE1234", "full access key id leaked in evidence"


# ── Security group rules ─────────────────────────────────────────────────────


def test_public_ssh_admin_fires_high():
    out = aws_rules.evaluate(_sg_rule(from_port=22, to_port=22, port_category="admin"))
    assert len(out) == 1
    assert out[0].rule_key == "aws_public_admin_port"
    assert out[0].severity == "high"
    assert "SSH" in out[0].title
    _assert_evidence_safe(out)


def test_public_rdp_admin_labelled():
    out = aws_rules.evaluate(_sg_rule(from_port=3389, to_port=3389, port_category="admin"))
    assert "RDP" in out[0].title


def test_public_database_fires_critical():
    out = aws_rules.evaluate(
        _sg_rule(from_port=5432, to_port=5432, port_category="database")
    )
    assert out[0].rule_key == "aws_public_database_port"
    assert out[0].severity == "critical"


def test_public_all_ports_fires_critical():
    out = aws_rules.evaluate(
        _sg_rule(protocol="-1", from_port=None, to_port=None, port_category="all")
    )
    assert out[0].rule_key == "aws_public_all_ports"
    assert out[0].severity == "critical"


def test_public_web_ports_not_flagged():
    # Public 443 (web) must NOT create a finding — avoids normal web-traffic noise.
    out = aws_rules.evaluate(
        _sg_rule(from_port=443, to_port=443, port_category="web")
    )
    assert out == []


def test_private_cidr_not_flagged():
    out = aws_rules.evaluate(_sg_rule(is_public=False))
    assert out == []


def test_egress_not_flagged():
    out = aws_rules.evaluate(_sg_rule(direction="egress"))
    assert out == []


def test_sg_rule_malformed_ignored():
    # Missing port_category / is_public → ignored safely.
    assert aws_rules.evaluate({"record_type": AWS_SECURITY_GROUP_RULE, "direction": "ingress"}) == []


# ── S3 ───────────────────────────────────────────────────────────────────────


def test_s3_public_policy_fires_critical():
    out = aws_rules.evaluate(_s3(policy_status_is_public=True))
    assert any(c.rule_key == "aws_s3_public_policy" for c in out)
    assert next(c for c in out if c.rule_key == "aws_s3_public_policy").severity == "critical"
    _assert_evidence_safe(out)


def test_s3_public_acl_read_high_write_critical():
    out_read = aws_rules.evaluate(_s3(acl_all_users_read=True))
    acl = next(c for c in out_read if c.rule_key == "aws_s3_public_acl")
    assert acl.severity == "high"

    out_write = aws_rules.evaluate(_s3(acl_all_users_write=True))
    acl_w = next(c for c in out_write if c.rule_key == "aws_s3_public_acl")
    assert acl_w.severity == "critical"


def test_s3_private_no_finding():
    assert aws_rules.evaluate(_s3()) == []


def test_s3_unknown_none_not_flagged():
    # None (could-not-determine) must never be treated as public.
    out = aws_rules.evaluate(
        _s3(policy_status_is_public=None, public_principals_detected=None,
            acl_all_users_read=None, acl_all_users_write=None,
            acl_authenticated_users_read=None, acl_authenticated_users_write=None)
    )
    assert out == []


# ── IAM admin attachment ─────────────────────────────────────────────────────


def test_iam_admin_attachment_fires():
    out = aws_rules.evaluate(_iam_attach())
    assert len(out) == 1
    assert out[0].rule_key == "aws_iam_admin_policy_attached"
    assert out[0].severity == "high"
    assert out[0].evidence["principal_name"] == "deploy-bot"
    _assert_evidence_safe(out)


def test_iam_non_admin_attachment_ignored():
    out = aws_rules.evaluate(
        _iam_attach(policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess")
    )
    assert out == []


# ── Access key staleness ─────────────────────────────────────────────────────


def test_stale_active_key_fires_medium():
    out = aws_rules.evaluate(_access_key(last_used_age_days=200))
    assert len(out) == 1
    assert out[0].rule_key == "aws_access_key_unused"
    assert out[0].severity == "medium"
    # Key id shown as last 4 only.
    assert out[0].evidence["key_id_last4"] == "1234"
    _assert_evidence_safe(out)


def test_recently_used_key_not_flagged():
    assert aws_rules.evaluate(_access_key(last_used_age_days=3)) == []


def test_inactive_key_not_flagged():
    assert aws_rules.evaluate(_access_key(status="Inactive", last_used_age_days=400)) == []


def test_key_unknown_age_not_flagged():
    # None age is ambiguous (never used vs. fetch failed) → not flagged.
    assert aws_rules.evaluate(_access_key(last_used_age_days=None)) == []


# ── Unknown record ───────────────────────────────────────────────────────────


def test_unknown_aws_record_ignored():
    assert aws_rules.evaluate({"record_type": "aws_vpc", "name": "vpc-1"}) == []
    assert aws_rules.evaluate({"weird": "shape"}) == []


# ════════════════════════════════════════════════════════════════════════════
# DB-backed evaluator integration: lifecycle + multi-record
# ════════════════════════════════════════════════════════════════════════════


def _ws(user, db):
    from app.services import workspace_service

    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M60.4.2", db=db
    )


def _integ(db, user, ws_id):
    ct, iv = encrypt_credentials({"credential_type": "aws"})
    i = Integration(
        user_id=user.id,
        workspace_id=ws_id,
        provider="aws",
        display_name="aws",
        encrypted_credentials=ct,
        credential_iv=iv,
        status="active",
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _res(db, integ, user):
    r = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type="aws_account",
        provider_resource_id="123456789012",
        display_name="aws account",
        is_active=True,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _snap(db, res, integ, user, state):
    s = Snapshot(
        resource_id=res.id,
        integration_id=integ.id,
        user_id=user.id,
        state=state,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _active(db, ws_id, res_id):
    return (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws_id,
            SecurityFinding.resource_id == res_id,
            SecurityFinding.status == "active",
        )
        .all()
    )


def _cleanup(db, ws_id):
    db.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws_id).delete()
    db.commit()


def test_multiple_aws_records_separate_findings(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)
    state = [
        _sg_rule(record_id="us-east-1/sg-1/ssh", from_port=22, to_port=22, port_category="admin"),
        _sg_rule(record_id="us-east-1/sg-2/db", from_port=5432, to_port=5432, port_category="database"),
        _s3(record_id="bucket-a", bucket_name="bucket-a", policy_status_is_public=True),
        _iam_attach(record_id="attach-1"),
        _access_key(record_id="AKIA1111", access_key_id="AKIA1111", last_used_age_days=120),
        # safe rows that must NOT produce findings:
        _sg_rule(record_id="us-east-1/sg-3/web", from_port=443, to_port=443, port_category="web"),
        _s3(record_id="bucket-safe", bucket_name="bucket-safe"),
    ]
    snap = _snap(db_session, res, integ, test_user, state)

    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=snap
    )
    findings = _active(db_session, ws.id, res.id)
    keys = {f.finding_key for f in findings}
    assert len(findings) == 5
    assert any(k.startswith("aws_public_admin_port") for k in keys)
    assert any(k.startswith("aws_public_database_port") for k in keys)
    assert any(k.startswith("aws_s3_public_policy") for k in keys)
    assert any(k.startswith("aws_iam_admin_policy_attached") for k in keys)
    assert any(k.startswith("aws_access_key_unused") for k in keys)

    _cleanup(db_session, ws.id)


def test_aws_lifecycle_dedupe_and_resolve(test_user, db_session):
    ws = _ws(test_user, db_session)
    integ = _integ(db_session, test_user, ws.id)
    res = _res(db_session, integ, test_user)

    risky = [_sg_rule(record_id="us-east-1/sg-1/ssh", from_port=22, to_port=22, port_category="admin")]
    s1 = _snap(db_session, res, integ, test_user, risky)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s1
    )
    f1 = _active(db_session, ws.id, res.id)
    assert len(f1) == 1
    first_seen = f1[0].last_seen_at

    s2 = _snap(db_session, res, integ, test_user, risky)
    evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s2
    )
    f2 = _active(db_session, ws.id, res.id)
    assert len(f2) == 1 and f2[0].id == f1[0].id
    assert f2[0].last_seen_at >= first_seen

    # Rule made private → finding resolves.
    s3 = _snap(
        db_session, res, integ, test_user,
        [_sg_rule(record_id="us-east-1/sg-1/ssh", is_public=False, port_category="admin")],
    )
    summary = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=s3
    )
    assert summary["resolved"] == 1
    assert _active(db_session, ws.id, res.id) == []

    _cleanup(db_session, ws.id)
