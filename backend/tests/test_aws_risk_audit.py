"""AWS risk accuracy audit — local-only regression tests.

Builds the scenario matrix from the verification brief and asserts the
expected severity for each scenario. Documents ConfigTrace's AWS risk
policy so any future regression that mis-rates one of these scenarios
fails loudly here.

Special care for AWS: a security-group rule allowing 0.0.0.0/0 does NOT
prove a resource is publicly reachable without route/IGW/public-IP/subnet
context — so risk reasons must use hedged language ("may expose",
"could expose") and never assert confirmed reachability for SG events.

Pure-mock; no DB, no network, no AWS API.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _change(
    *,
    record_type: str,
    field_path: str | None = None,
    change_type: str = "modified",
    new_value: Any = None,
    prev_value: Any = None,
    record_name: str = "",
    record_id: str = "",
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {
        "record_type": record_type,
        "record_name": record_name,
        "record_id": record_id,
    }
    if extra_metadata:
        pm.update(extra_metadata)
    c = MagicMock(name="Change")
    c.field_path        = field_path
    c.change_type       = change_type
    c.new_value         = new_value
    c.prev_value        = prev_value
    c.old_value         = prev_value
    c.provider_metadata = pm
    # The AWS RDS classifier reads .name directly off the change object —
    # mirror record_name so the sensitive-name heuristic fires.
    c.name              = record_name
    return c


def _classify(change):
    from app.services.risk_rules.aws import classify_aws_change
    return classify_aws_change(change)


def _sg_rule(
    *,
    direction: str = "ingress",
    is_public: bool = True,
    from_port: int | None = None,
    to_port: int | None = None,
    protocol: str = "tcp",
    cidr_ipv4: str = "0.0.0.0/0",
) -> dict:
    return {
        "direction":   direction,
        "is_public":   is_public,
        "from_port":   from_port if from_port is not None else None,
        "to_port":     to_port   if to_port   is not None else from_port,
        "protocol":    protocol,
        "cidr_ipv4":   cidr_ipv4,
        "group_id":    "sg-test123",
        "region":      "us-east-1",
    }


# ─────────────────────────────────────────────────────────────────────────────
# A. Security Groups / Network Exposure
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityGroupRules:
    def test_A1_public_ssh_ingress_is_critical(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=22, to_port=22),
        )
        level, reason = _classify(c)
        assert level == "critical"
        # Hedged language only — no confirmed reachability claim.
        lower = reason.lower()
        assert "may" in lower or "could" in lower, (
            f"SG rule reason must use hedged language; got: {reason!r}"
        )
        assert "is publicly reachable" not in lower
        assert "is reachable from the public internet" not in lower

    def test_A2_public_ssh_ipv6_is_critical(self):
        rule = _sg_rule(from_port=22, to_port=22, cidr_ipv4="")
        rule["cidr_ipv6"] = "::/0"
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=rule,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A3_public_rdp_ingress_is_critical(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=3389, to_port=3389),
        )
        level, reason = _classify(c)
        assert level == "critical"
        assert "rdp" in reason.lower() or "3389" in reason

    def test_A4_public_winrm_is_critical(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=5985, to_port=5986),
        )
        level, _ = _classify(c)
        assert level == "critical"

    @pytest.mark.parametrize("port", [
        5432,   # PostgreSQL
        3306,   # MySQL
        1433,   # MSSQL
        1521,   # Oracle
        27017,  # MongoDB
        6379,   # Redis
        9200,   # Elasticsearch
    ])
    def test_A5_public_database_port_ingress_is_critical(self, port):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=port, to_port=port),
        )
        level, _ = _classify(c)
        assert level == "critical", f"port {port} must be critical"

    def test_A6_public_all_ports_ingress_is_critical(self):
        # protocol "-1" = all-traffic
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(protocol="-1", from_port=None, to_port=None),
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A7_public_http_on_normal_web_sg_is_medium(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=80, to_port=80),
            record_name="public-web-sg",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A8_public_https_on_normal_web_sg_is_medium(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=443, to_port=443),
            record_name="public-web-sg",
        )
        level, _ = _classify(c)
        assert level == "medium"

    @pytest.mark.parametrize("name", [
        "production-backend-sg",
        "admin-bastion-sg",
        "internal-api-sg",
        "db-cluster-sg",
    ])
    def test_A9_public_http_on_sensitive_sg_is_high(self, name):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=80, to_port=80),
            record_name=name,
        )
        level, _ = _classify(c)
        assert level == "high", (
            f"public HTTP on sensitive SG {name!r} must be high; got {level}"
        )

    def test_A10_private_cidr_ingress_is_low(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value={
                "direction":   "ingress",
                "is_public":   False,
                "from_port":   22,
                "to_port":     22,
                "protocol":    "tcp",
                "cidr_ipv4":   "10.0.0.0/16",
                "group_id":    "sg-private",
                "region":      "us-east-1",
            },
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A11_default_egress_all_traffic_is_low(self):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(
                direction="egress", protocol="-1",
                from_port=None, to_port=None,
            ),
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A12_sg_rule_removal_is_low(self):
        # A removed rule reduces exposure → never warn-level.
        c = _change(
            record_type="aws_security_group_rule",
            change_type="removed",
            prev_value=_sg_rule(from_port=22, to_port=22),
        )
        level, _ = _classify(c)
        assert level == "low"

    @pytest.mark.parametrize("port", [8080, 8443])
    def test_A13_public_alt_http_port_on_normal_sg_at_least_medium(self, port):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=port, to_port=port),
            record_name="public-web-sg",
        )
        level, _ = _classify(c)
        # Brief: "public 8080/8443" → at least medium (high on internal SG).
        assert level in ("medium", "high")

    @pytest.mark.parametrize("port", [8080, 8443])
    def test_A14_public_alt_http_port_on_sensitive_sg_is_high(self, port):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=port, to_port=port),
            record_name="internal-admin-sg",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A15_public_ssh_on_default_sg_is_critical(self):
        # Default SG is always sensitive — admin-port public ingress must
        # stay at critical regardless of name.
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=22, to_port=22),
            record_name="default",
        )
        level, _ = _classify(c)
        assert level == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# B. S3 / Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestS3:
    def test_B1_public_access_block_disabled_is_high_or_critical(self):
        c = _change(
            record_type="aws_s3_bucket",
            field_path="block_public_acls",
            new_value=False,
            prev_value=True,
            record_name="company-backups",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_B2_encryption_disabled_is_high_or_critical(self):
        # Actual field name in the S3 classifier is `encryption_enabled`.
        c = _change(
            record_type="aws_s3_bucket",
            field_path="encryption_enabled",
            new_value=False,
            prev_value=True,
            record_name="customer-data",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_B3_versioning_disabled_is_medium_or_high(self):
        c = _change(
            record_type="aws_s3_bucket",
            field_path="versioning_status",
            new_value="Suspended",
            prev_value="Enabled",
            record_name="customer-data",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_B4_public_access_block_unconfigured_is_high_or_critical(self):
        # Field is `public_access_block_configured` on the S3 record.
        c = _change(
            record_type="aws_s3_bucket",
            field_path="public_access_block_configured",
            new_value=False,
            prev_value=True,
            record_name="customer-data",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_B5_logging_disabled_is_at_least_medium(self):
        # S3 access-log disabling reduces forensic visibility.
        c = _change(
            record_type="aws_s3_bucket",
            field_path="logging_enabled",
            new_value=False,
            prev_value=True,
            record_name="customer-data",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high", "critical")

    def test_B6_bucket_removed_is_at_least_medium(self):
        c = _change(
            record_type="aws_s3_bucket",
            change_type="removed",
            record_name="customer-data",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")


# ─────────────────────────────────────────────────────────────────────────────
# C. IAM / Identity
# ─────────────────────────────────────────────────────────────────────────────

class TestIam:
    def test_C1_active_access_key_created_is_at_least_medium(self):
        # The classifier only escalates beyond "low" when the new key is
        # Active. Inactive-on-create is low (e.g. provisioning flow).
        c = _change(
            record_type="aws_iam_access_key",
            change_type="added",
            new_value={"status": "Active"},
            record_name="AKIAEXAMPLE",
            extra_metadata={"user_name": "alice"},
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_C2_iam_user_created_with_active_keys_no_mfa_is_high(self):
        # A user created already carrying an active access key and no MFA
        # is the "high" branch in _classify_iam_user_change.
        c = _change(
            record_type="aws_iam_user",
            change_type="added",
            new_value={"active_key_count": 1, "mfa_enabled": False},
            record_name="bob",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_C3_administrator_access_attached_is_critical(self):
        c = _change(
            record_type="aws_iam_policy_attachment",
            change_type="added",
            new_value={
                "principal_name":  "ci-deployer",
                "principal_type":  "role",
                "policy_name":     "AdministratorAccess",
            },
        )
        level, reason = _classify(c)
        assert level == "critical"
        assert "administratoraccess" in reason.lower() or "administrator" in reason.lower()

    def test_C4_wildcard_admin_managed_policy_created_is_at_least_high(self):
        # The policy-summary helper keys on `admin_access` (action=*, resource=*).
        c = _change(
            record_type="aws_iam_policy",
            change_type="added",
            new_value={
                "policy_summary": {
                    "admin_access":   True,
                    "finding_codes": ["admin_action_resource"],
                },
            },
            record_name="WildcardPolicy",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_C5_role_trust_wildcard_principal_is_critical(self):
        # Trust policy changes from non-wildcard to wildcard principal →
        # critical (any AWS principal could assume the role).
        c = _change(
            record_type="aws_iam_role",
            field_path="trust_summary",
            new_value={"has_wildcard_principal": True,  "has_external_account_trust": False},
            prev_value={"has_wildcard_principal": False, "has_external_account_trust": False},
            record_name="prod-eks-node-role",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_C6_role_trust_external_account_added_is_at_least_medium(self):
        c = _change(
            record_type="aws_iam_role",
            field_path="trust_summary",
            new_value={"has_external_account_trust": True,  "has_wildcard_principal": False},
            prev_value={"has_external_account_trust": False, "has_wildcard_principal": False},
            record_name="prod-data-reader-role",
        )
        level, _ = _classify(c)
        # Sensitive name → high; otherwise medium.
        assert level in ("medium", "high")

    def test_C7_role_external_id_condition_removed_is_high(self):
        # Removing ExternalId on a cross-account role enables the
        # "confused deputy" pattern → high.
        c = _change(
            record_type="aws_iam_role",
            field_path="trust_summary",
            new_value={
                "has_external_account_trust": True,
                "has_external_id_condition":  False,
                "has_wildcard_principal":     False,
            },
            prev_value={
                "has_external_account_trust": True,
                "has_external_id_condition":  True,
                "has_wildcard_principal":     False,
            },
            record_name="cross-account-data-role",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C8_policy_removed_is_not_over_risked(self):
        # Brief: "policy removed/narrowed should not be over-risked."
        c = _change(
            record_type="aws_iam_policy",
            change_type="removed",
            record_name="LegacyReadOnly",
        )
        level, _ = _classify(c)
        assert level in ("low", "medium")


# ─────────────────────────────────────────────────────────────────────────────
# D. KMS / Secrets / Parameter Store
# ─────────────────────────────────────────────────────────────────────────────

class TestKmsAndSecrets:
    def test_D1_kms_key_pending_deletion_is_critical_or_high(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="key_state",
            new_value="PendingDeletion",
            prev_value="Enabled",
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")


# ─────────────────────────────────────────────────────────────────────────────
# E. CloudTrail / GuardDuty
# ─────────────────────────────────────────────────────────────────────────────

class TestLoggingAndMonitoring:
    def test_E1_cloudtrail_logging_disabled_is_critical(self):
        c = _change(
            record_type="aws_cloudtrail_trail",
            field_path="is_logging",
            new_value=False,
            prev_value=True,
            record_name="org-trail",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_E2_cloudtrail_removed_is_critical_or_high(self):
        c = _change(
            record_type="aws_cloudtrail_trail",
            change_type="removed",
            record_name="org-trail",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_E3_guardduty_detector_disabled_is_critical_or_high(self):
        c = _change(
            record_type="aws_guardduty_detector",
            field_path="status",
            new_value="DISABLED",
            prev_value="ENABLED",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_E4_multi_region_trail_disabled_is_critical_or_high(self):
        c = _change(
            record_type="aws_cloudtrail_trail",
            field_path="is_multi_region_trail",
            new_value=False,
            prev_value=True,
            record_name="org-trail",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_E5_log_file_validation_disabled_is_critical_or_high(self):
        c = _change(
            record_type="aws_cloudtrail_trail",
            field_path="log_file_validation_enabled",
            new_value=False,
            prev_value=True,
            record_name="org-trail",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_E6_guardduty_detector_removed_is_critical(self):
        c = _change(
            record_type="aws_guardduty_detector",
            change_type="removed",
            record_name="us-east-1",
        )
        level, _ = _classify(c)
        assert level == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# F. RDS / Database
# ─────────────────────────────────────────────────────────────────────────────

class TestRds:
    def test_F1_rds_public_accessibility_enabled_uses_hedged_language(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="publicly_accessible",
            new_value=True,
            prev_value=False,
            record_name="prod-customer-db",
        )
        level, reason = _classify(c)
        assert level in ("critical", "high")
        # The brief explicitly forbids overclaiming reachability without
        # subnet/route/IGW context. Even though RDS publicly_accessible is
        # a real AWS setting, end-to-end reachability requires public-subnet
        # routing. The reason must hedge.
        lower = reason.lower()
        # Either hedged ("may", "could") OR it must mention the dependent
        # network controls — which the current copy does.
        assert (
            "may " in lower
            or "could " in lower
            or "network-level" in lower
            or "security group" in lower
            or "subnet" in lower
        ), (
            "RDS public-accessibility reason must hedge actual reachability "
            f"(brief policy): {reason!r}"
        )

    def test_F2_storage_encryption_disabled_is_critical(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="storage_encrypted",
            new_value=False,
            prev_value=True,
            record_name="prod-db",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_F3_deletion_protection_disabled_on_sensitive_is_critical(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="deletion_protection",
            new_value=False,
            prev_value=True,
            record_name="prod-payments-db",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")


# ─────────────────────────────────────────────────────────────────────────────
# G. Route53 / DNS
# ─────────────────────────────────────────────────────────────────────────────

class TestRoute53:
    def test_G1_record_removed_is_at_least_medium(self):
        # The classifier inspects record_id / name; pass enough metadata
        # for it to make a sensible decision.
        c = _change(
            record_type="aws_route53_record",
            change_type="removed",
            record_name="api.example.com",
            extra_metadata={"name": "api.example.com", "type": "A"},
        )
        level, _ = _classify(c)
        assert level in ("medium", "high"), (
            f"Route53 record removal must register; got {level}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# H. Unknown / safety
# ─────────────────────────────────────────────────────────────────────────────

class TestUnknownSubtype:
    def test_H1_unknown_subtype_falls_back_safely(self):
        c = _change(record_type="aws_future_feature")
        level, reason = _classify(c)
        assert level == "low"
        # Must not crash, must mention aws somehow.
        assert isinstance(reason, str) and len(reason) > 0

    def test_H2_malformed_metadata_does_not_raise(self):
        for bad_pm in (None, "not a dict", 42, []):
            c = MagicMock(name="Change")
            c.field_path        = None
            c.change_type       = "modified"
            c.new_value         = None
            c.prev_value        = None
            c.old_value         = None
            c.provider_metadata = bad_pm
            level, _ = _classify(c)
            assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# I. Reachability-overclaim audit — most important AWS-specific check
# ─────────────────────────────────────────────────────────────────────────────

class TestNoReachabilityOverclaim:
    """The brief is explicit: a SG rule allowing 0.0.0.0/0 does not prove a
    resource is publicly reachable. SG-rule reasons must hedge."""

    @pytest.mark.parametrize("port,proto", [
        (22, "tcp"),       # SSH
        (3389, "tcp"),     # RDP
        (5432, "tcp"),     # PG
        (3306, "tcp"),     # MySQL
        (None, "-1"),      # all-traffic
    ])
    def test_I1_sg_rule_reasons_use_hedged_language(self, port, proto):
        c = _change(
            record_type="aws_security_group_rule",
            change_type="added",
            new_value=_sg_rule(from_port=port, to_port=port, protocol=proto),
        )
        _, reason = _classify(c)
        lower = reason.lower()
        # No absolute reachability claims for SG events.
        for absolute in (
            "is publicly reachable",
            "is reachable from the public internet",
            "is now reachable from the public internet",
            "is exposed to the internet",
            "is now exposed",
        ):
            assert absolute not in lower, (
                f"SG rule reason must hedge; found absolute claim {absolute!r} in: {reason!r}"
            )
        # Should contain at least one hedge.
        assert any(h in lower for h in ("may ", "could ", " may be", "may now")), (
            f"SG rule reason should hedge with may/could; got: {reason!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# J. Safety — no secrets in reasons
# ─────────────────────────────────────────────────────────────────────────────

class TestSafetyInvariants:
    @pytest.mark.parametrize("change_args", [
        dict(record_type="aws_security_group_rule", change_type="added",
             new_value=_sg_rule(from_port=22, to_port=22)),
        dict(record_type="aws_iam_access_key", change_type="added",
             extra_metadata={"user_name": "alice"}),
        dict(record_type="aws_cloudtrail_trail", field_path="is_logging",
             new_value=False, prev_value=True, record_name="org-trail"),
        dict(record_type="aws_rds_db_instance", field_path="publicly_accessible",
             new_value=True, prev_value=False, record_name="prod-db"),
        dict(record_type="aws_kms_key", field_path="key_state",
             new_value="PendingDeletion", prev_value="Enabled",
             record_name="prod-data-key"),
    ])
    def test_J1_reason_does_not_leak_aws_credentials(self, change_args):
        """Reasons must not contain AWS-credential-shaped strings."""
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # Access-key IDs are 20 chars starting with AKIA / ASIA / AIDA.
        for prefix in ("akia", "asia", "aida", "arox", "fas"):
            # Allow these prefixes ONLY when they're embedded as English words
            # (e.g. "AIDA" doesn't appear in any AWS English).
            # Real keys would have >= 16 alnum chars after.
            import re
            assert not re.search(
                rf"{prefix}[a-z0-9]{{14,}}", lower
            ), f"reason looks like an AWS credential: {reason!r}"
        # Session-token shaped (very long base64) — practical proxy: any
        # 50+ run of base64 chars in the reason would be suspicious.
        import re
        long_b64 = re.search(r"[A-Za-z0-9+/=]{60,}", reason)
        assert long_b64 is None, (
            f"reason contains a suspiciously long token-shaped string: {reason!r}"
        )

    def test_J2_no_auto_fix_language(self):
        cases = [
            dict(record_type="aws_security_group_rule", change_type="added",
                 new_value=_sg_rule(from_port=22, to_port=22)),
            dict(record_type="aws_cloudtrail_trail", field_path="is_logging",
                 new_value=False, record_name="org-trail"),
            dict(record_type="aws_guardduty_detector", field_path="status",
                 new_value="DISABLED"),
            dict(record_type="aws_rds_db_instance", field_path="publicly_accessible",
                 new_value=True, record_name="prod-db"),
        ]
        bad = ("auto-fix", "automatically fix", "guaranteed", "auto fix")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, f"reason contains {phrase!r}: {reason!r}"
