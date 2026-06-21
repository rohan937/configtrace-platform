"""AWS provider depth QA guardrails.

Deep-audits the AWS security-rule stack: registry/confidence/pack/coverage and
frontend-catalog alignment, evidence privacy safety, security-group port-category
ordering (the M60.4.x QA fix), S3 dynamic severity, IAM principal variants, the
new broad-policy / root-MFA rules, and capability-matrix / expansion-framework
state (Kubernetes is the *next* provider and is intentionally NOT implemented).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.connectors.aws import _port_category
from app.connectors.aws_schema import (
    AWS_IAM_ACCOUNT_SUMMARY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_S3_BUCKET,
    AWS_SECURITY_GROUP_RULE,
)
from app.services.security_rules import aws as aws_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# ── Complete AWS rule key set (7 original + 3 new) ────────────────────────────

ALL_AWS_RULE_KEYS = [
    "aws_public_admin_port",
    "aws_public_database_port",
    "aws_public_all_ports",
    "aws_s3_public_policy",
    "aws_s3_public_acl",
    "aws_iam_admin_policy_attached",
    "aws_access_key_unused",
    # New QA rules
    "aws_iam_broad_policy_attached",
    "aws_root_mfa_disabled",
]

# Evidence keys that must never appear in any AWS finding evidence dict.
FORBIDDEN_EVIDENCE_KEYS = {
    "access_key", "secret_key", "session_token", "api_key", "authorization",
    "payload", "request", "response", "raw", "secret_value", "policy_json",
    "cloudtrail_event", "ip_address", "account_id", "kms_key_material",
}

# Forbidden over-claiming wording in rule titles/descriptions.
FORBIDDEN_WORDING = [
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked",
    "unauthorized access confirmed", "data exposure confirmed",
    "publicly exposed data",
]


# ── record builders ───────────────────────────────────────────────────────────


def _sg_rule(**over) -> dict:
    rec = {
        "record_type": AWS_SECURITY_GROUP_RULE,
        "record_id": "us-east-1/sg-123/abc",
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


def _sg_rule_classified(**over) -> dict:
    """Build an SG rule whose port_category is computed by the connector."""
    rec = _sg_rule(**over)
    rec["port_category"] = _port_category(
        rec.get("from_port"), rec.get("to_port"), rec.get("protocol")
    )
    return rec


def _s3(**over) -> dict:
    rec = {
        "record_type": AWS_S3_BUCKET,
        "record_id": "my-bucket",
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
        "principal_type": "user",
        "principal_id": "AID123",
        "principal_name": "deploy-bot",
        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "policy_name": "AdministratorAccess",
    }
    rec.update(over)
    return rec


def _account_summary(**over) -> dict:
    rec = {
        "record_type": AWS_IAM_ACCOUNT_SUMMARY,
        "record_id": "123456789012/iam_account_summary",
        "mfa_enabled_for_root": True,
        "user_count": 5,
    }
    rec.update(over)
    return rec


# ════════════════════════════════════════════════════════════════════════════
# Registry / catalog completeness
# ════════════════════════════════════════════════════════════════════════════


def test_all_aws_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for rk in ALL_AWS_RULE_KEYS:
        assert rk in KNOWN_RULE_KEYS, f"{rk} missing from KNOWN_RULE_KEYS"


def test_all_aws_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for rk in ALL_AWS_RULE_KEYS:
        assert rk in RULE_CONFIDENCE, f"{rk} missing from RULE_CONFIDENCE"


def test_all_aws_rule_keys_in_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for rk in ALL_AWS_RULE_KEYS:
        assert rk in _RULE_META, f"{rk} missing from _RULE_META"


def test_all_aws_rule_keys_in_coverage() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for rk in ALL_AWS_RULE_KEYS:
        assert rk in RULE_RECORD_TYPES, f"{rk} missing from RULE_RECORD_TYPES"


def test_all_aws_rule_keys_in_fe_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for rk in ALL_AWS_RULE_KEYS:
        assert rk in text, f"{rk} missing from securityRuleCatalog.ts"


def test_backend_frontend_severity_match() -> None:
    """Each AWS rule's pack severity matches its frontend catalog severity."""
    from app.services.security_rule_pack import _RULE_META
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for rk in ALL_AWS_RULE_KEYS:
        backend_sev = _RULE_META[rk][1]
        # Find the catalog entry block for this key and read its severity field.
        m = re.search(
            rf'key:\s*"{re.escape(rk)}",.*?severity:\s*"([a-z]+)"',
            text,
            re.DOTALL,
        )
        assert m is not None, f"no severity found for {rk} in catalog"
        assert m.group(1) == backend_sev, (
            f"severity mismatch for {rk}: backend={backend_sev} fe={m.group(1)}"
        )


def test_no_forbidden_wording_in_rule_strings() -> None:
    src = (
        REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "aws.py"
    ).read_text(encoding="utf-8").lower()
    for phrase in FORBIDDEN_WORDING:
        assert phrase.lower() not in src, f"forbidden wording {phrase!r} in aws.py"


# ════════════════════════════════════════════════════════════════════════════
# Evidence safety
# ════════════════════════════════════════════════════════════════════════════


def _all_candidates() -> list:
    cands: list = []
    cands += aws_rules.evaluate(_sg_rule(port_category="admin"))
    cands += aws_rules.evaluate(_sg_rule(from_port=5432, to_port=5432, port_category="database"))
    cands += aws_rules.evaluate(_sg_rule(protocol="-1", from_port=None, to_port=None, port_category="all"))
    cands += aws_rules.evaluate(_s3(policy_status_is_public=True))
    cands += aws_rules.evaluate(_s3(acl_all_users_write=True))
    cands += aws_rules.evaluate(_iam_attach())
    cands += aws_rules.evaluate(_iam_attach(policy_arn="arn:aws:iam::aws:policy/PowerUserAccess", policy_name="PowerUserAccess"))
    cands += aws_rules.evaluate(_account_summary(mfa_enabled_for_root=False))
    cands += aws_rules.evaluate({
        "record_type": "aws_iam_access_key", "record_id": "AKIA1",
        "access_key_id": "AKIAEXAMPLE1234", "username": "ci", "status": "Active",
        "last_used_age_days": 200,
    })
    return cands


def test_evidence_has_no_forbidden_keys() -> None:
    for c in _all_candidates():
        for k in c.evidence.keys():
            assert k not in FORBIDDEN_EVIDENCE_KEYS, f"forbidden evidence key {k!r}"


# ════════════════════════════════════════════════════════════════════════════
# Port-category ordering regression (the QA fix)
# ════════════════════════════════════════════════════════════════════════════


def test_public_tcp_1_65535_fires_all_ports_critical() -> None:
    rec = _sg_rule_classified(protocol="tcp", from_port=1, to_port=65535)
    assert rec["port_category"] == "all"
    out = aws_rules.evaluate(rec)
    assert out[0].rule_key == "aws_public_all_ports"
    assert out[0].severity == "critical"


def test_public_tcp_0_65535_fires_all_ports_critical() -> None:
    rec = _sg_rule_classified(protocol="tcp", from_port=0, to_port=65535)
    assert rec["port_category"] == "all"
    out = aws_rules.evaluate(rec)
    assert out[0].rule_key == "aws_public_all_ports"
    assert out[0].severity == "critical"


def test_protocol_minus1_public_fires_all_ports_critical() -> None:
    rec = _sg_rule_classified(protocol="-1", from_port=None, to_port=None)
    assert rec["port_category"] == "all"
    out = aws_rules.evaluate(rec)
    assert out[0].rule_key == "aws_public_all_ports"
    assert out[0].severity == "critical"


def test_public_tcp_22_only_fires_admin_high() -> None:
    rec = _sg_rule_classified(protocol="tcp", from_port=22, to_port=22)
    assert rec["port_category"] == "admin"
    out = aws_rules.evaluate(rec)
    assert out[0].rule_key == "aws_public_admin_port"
    assert out[0].severity == "high"


def test_private_cidr_wide_range_does_not_fire() -> None:
    rec = _sg_rule_classified(
        protocol="tcp", from_port=1, to_port=65535,
        cidr_ipv4="10.0.0.0/8", is_public=False,
    )
    assert aws_rules.evaluate(rec) == []


# ════════════════════════════════════════════════════════════════════════════
# S3 dynamic severity
# ════════════════════════════════════════════════════════════════════════════


def test_s3_acl_read_only_is_high() -> None:
    out = aws_rules.evaluate(_s3(acl_all_users_read=True, acl_all_users_write=False))
    acl = next(c for c in out if c.rule_key == "aws_s3_public_acl")
    assert acl.severity == "high"


def test_s3_acl_write_is_critical() -> None:
    out = aws_rules.evaluate(_s3(acl_all_users_write=True))
    acl = next(c for c in out if c.rule_key == "aws_s3_public_acl")
    assert acl.severity == "critical"


def test_s3_public_principals_alone_fires_policy_rule() -> None:
    # public_principals_detected=True alone is a trigger for aws_s3_public_policy.
    out = aws_rules.evaluate(
        _s3(public_principals_detected=True, policy_status_is_public=False)
    )
    assert any(c.rule_key == "aws_s3_public_policy" for c in out)


# ════════════════════════════════════════════════════════════════════════════
# IAM admin principal variants
# ════════════════════════════════════════════════════════════════════════════


def test_iam_admin_fires_for_role() -> None:
    out = aws_rules.evaluate(_iam_attach(principal_type="Role", principal_name="ci-role"))
    assert out[0].rule_key == "aws_iam_admin_policy_attached"


def test_iam_admin_fires_for_group() -> None:
    out = aws_rules.evaluate(_iam_attach(principal_type="Group", principal_name="admins"))
    assert out[0].rule_key == "aws_iam_admin_policy_attached"


def test_iam_admin_fires_for_user() -> None:
    out = aws_rules.evaluate(_iam_attach(principal_type="User", principal_name="root-ops"))
    assert out[0].rule_key == "aws_iam_admin_policy_attached"


# ════════════════════════════════════════════════════════════════════════════
# New rule: broad managed policy
# ════════════════════════════════════════════════════════════════════════════


def test_broad_poweruser_fires_high() -> None:
    out = aws_rules.evaluate(
        _iam_attach(policy_arn="arn:aws:iam::aws:policy/PowerUserAccess", policy_name="PowerUserAccess")
    )
    assert len(out) == 1
    assert out[0].rule_key == "aws_iam_broad_policy_attached"
    assert out[0].severity == "high"
    assert out[0].evidence["policy_name"] == "PowerUserAccess"
    assert out[0].evidence["broad_policy_category"] == "aws_managed_broad"


def test_broad_iamfullaccess_fires_high() -> None:
    out = aws_rules.evaluate(
        _iam_attach(policy_arn="arn:aws:iam::aws:policy/IAMFullAccess", policy_name="IAMFullAccess")
    )
    assert out[0].rule_key == "aws_iam_broad_policy_attached"
    assert out[0].evidence["policy_name"] == "IAMFullAccess"


def test_broad_policy_not_fired_for_readonly() -> None:
    out = aws_rules.evaluate(
        _iam_attach(policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess", policy_name="ReadOnlyAccess")
    )
    assert out == []


# ════════════════════════════════════════════════════════════════════════════
# New rule: root MFA disabled
# ════════════════════════════════════════════════════════════════════════════


def test_root_mfa_disabled_fires_high() -> None:
    out = aws_rules.evaluate(_account_summary(mfa_enabled_for_root=False))
    assert len(out) == 1
    assert out[0].rule_key == "aws_root_mfa_disabled"
    assert out[0].severity == "high"
    assert out[0].evidence["root_mfa_enabled"] is False
    # No account id / username in evidence.
    assert "account_id" not in out[0].evidence


def test_root_mfa_enabled_does_not_fire() -> None:
    assert aws_rules.evaluate(_account_summary(mfa_enabled_for_root=True)) == []


def test_root_mfa_unknown_does_not_fire() -> None:
    # None (could not determine) must never be treated as disabled.
    assert aws_rules.evaluate(_account_summary(mfa_enabled_for_root=None)) == []


# ── Deferred rule: per-user IAM MFA ───────────────────────────────────────────


def test_per_user_mfa_rule_is_deferred() -> None:
    """The aws_iam_user record lacks console/password-enabled state, so a per-user
    MFA-disabled rule is intentionally NOT implemented (would be noisy for service
    users). Documented as deferred; root MFA is covered instead."""
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert "aws_iam_user_mfa_disabled" not in KNOWN_RULE_KEYS


# ════════════════════════════════════════════════════════════════════════════
# Capability matrix / expansion framework / Kubernetes-not-implemented
# ════════════════════════════════════════════════════════════════════════════


def test_aws_in_capability_matrix() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    assert get_provider_capability("aws") is not None


def test_expansion_framework_points_to_kubernetes() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    labels = [p.get("label", "") for p in fw.get("recommended_next_providers", [])]
    assert "M89" in planned or "Kubernetes" in planned or any(
        "Kubernetes" in label for label in labels
    )


def test_no_kubernetes_connector_file() -> None:
    assert not os.path.exists(
        str(REPO_ROOT / "backend" / "app" / "connectors" / "kubernetes.py")
    )


def test_no_kubernetes_security_rules_file() -> None:
    assert not os.path.exists(
        str(REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "kubernetes.py")
    )
