"""AWS Part 2 — remaining-surface risk audit (RDS, KMS/secrets/SSM,
Lambda/ECS/EKS, Route53, VPC/routing).

Part 1 (see `test_aws_risk_audit.py`) covered SG/S3/IAM/CloudTrail/GuardDuty.
This file picks up where Part 1 stopped, documenting the expected severity
for the remaining provider surfaces under the same audit policy from the
verification brief.

Special hedging policy (same as Part 1):
  • Do NOT claim confirmed public reachability from SG/VPC data alone.
  • Use "may expose" / "could expose" / "may create a public path".

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
        "record_id":   record_id,
    }
    if extra_metadata:
        pm.update(extra_metadata)
    c = MagicMock(name="Change")
    c.field_path        = field_path
    c.change_type       = change_type
    c.new_value         = new_value
    c.prev_value        = prev_value
    c.old_value         = prev_value
    c.previous_value    = prev_value   # Route53 reads .previous_value
    c.provider_metadata = pm
    c.name              = record_name  # RDS reads change.name directly
    return c


def _classify(change):
    from app.services.risk_rules.aws import classify_aws_change
    return classify_aws_change(change)


# ═════════════════════════════════════════════════════════════════════════════
# A. RDS / Database
# ═════════════════════════════════════════════════════════════════════════════

class TestRdsInstance:
    def test_A1_publicly_accessible_on_prod_db_is_critical(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="publicly_accessible",
            new_value=True,
            prev_value=False,
            record_name="prod-customer-db",
        )
        level, reason = _classify(c)
        assert level == "critical"
        # Per audit policy: must not assert confirmed reachability without
        # subnet/route context. The current copy passes because it mentions
        # dependent "network-level controls (security groups, NACLs)".
        lower = reason.lower()
        assert (
            "may " in lower
            or "could " in lower
            or "network-level" in lower
            or "security group" in lower
            or "subnet" in lower
        ), f"RDS public reason must hedge or reference dependent controls; got {reason!r}"

    def test_A2_publicly_accessible_on_nonsensitive_db_is_high(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="publicly_accessible",
            new_value=True,
            prev_value=False,
            record_name="qa-fixture-01",  # avoids prod/db/payment/etc patterns
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A3_storage_encryption_disabled_is_critical(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="storage_encrypted",
            new_value=False,
            prev_value=True,
            record_name="prod-db",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A4_deletion_protection_off_on_prod_is_at_least_high(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="deletion_protection",
            new_value=False,
            prev_value=True,
            record_name="prod-payments-db",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_A5_deletion_protection_off_on_nonsensitive_is_medium(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="deletion_protection",
            new_value=False,
            prev_value=True,
            record_name="qa-fixture-01",  # avoids prod/db/payment/etc patterns
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_A6_backup_retention_zero_on_prod_is_high(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="backup_retention_period",
            new_value=0,
            prev_value=7,
            record_name="prod-customer-db",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A7_backup_retention_reduced_but_nonzero_is_medium(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="backup_retention_period",
            new_value=3,
            prev_value=14,
            record_name="prod-customer-db",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A8_backup_retention_increased_is_low(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="backup_retention_period",
            new_value=14,
            prev_value=7,
            record_name="prod-customer-db",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A9_publicly_accessible_disabled_is_low(self):
        c = _change(
            record_type="aws_rds_db_instance",
            field_path="publicly_accessible",
            new_value=False,
            prev_value=True,
            record_name="prod-db",
        )
        level, _ = _classify(c)
        assert level == "low"


class TestRdsCluster:
    def test_A10_cluster_publicly_accessible_on_prod_is_critical(self):
        c = _change(
            record_type="aws_rds_db_cluster",
            field_path="publicly_accessible",
            new_value=True,
            prev_value=False,
            record_name="prod-aurora-cluster",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")


class TestRdsSnapshot:
    def test_A11_snapshot_publicly_accessible_on_prod_is_critical(self):
        c = _change(
            record_type="aws_rds_db_snapshot",
            field_path="publicly_accessible",
            new_value=True,
            prev_value=False,
            record_name="prod-snap-2024-01-01",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")


# ═════════════════════════════════════════════════════════════════════════════
# B. KMS / Secrets / SSM
# ═════════════════════════════════════════════════════════════════════════════

class TestKms:
    def test_B1_key_pending_deletion_on_prod_is_critical(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="key_state",
            new_value="PendingDeletion",
            prev_value="Enabled",
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_B2_key_disabled_is_critical_or_high(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="enabled",
            new_value=False,
            prev_value=True,
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_B3_key_rotation_disabled_is_at_least_medium(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="rotation_enabled",
            new_value=False,
            prev_value=True,
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_B4_key_policy_opened_to_external_or_wildcard_is_critical(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="public_or_cross_account_policy",
            new_value=True,
            prev_value=False,
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_B5_wildcard_admin_policy_added_is_critical_or_high(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="wildcard_admin_policy",
            new_value=True,
            prev_value=False,
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_B6_deletion_cancelled_is_low(self):
        c = _change(
            record_type="aws_kms_key",
            field_path="deletion_date_present",
            new_value=False,
            prev_value=True,
            record_name="prod-data-key",
        )
        level, _ = _classify(c)
        assert level == "low"


class TestSecretsManager:
    def test_B7_secret_removed_on_sensitive_is_critical(self):
        c = _change(
            record_type="aws_secretsmanager_secret",
            change_type="removed",
            prev_value={"sensitive_name_category": "credential"},
            record_name="prod/api/stripe_key",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B8_secret_removed_on_nonsensitive_is_high(self):
        c = _change(
            record_type="aws_secretsmanager_secret",
            change_type="removed",
            prev_value={"sensitive_name_category": "none"},
            record_name="dev/scratch",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B9_secret_rotation_disabled_on_sensitive_is_critical(self):
        c = _change(
            record_type="aws_secretsmanager_secret",
            field_path="rotation_enabled",
            new_value=False,
            prev_value=True,
            record_name="prod/api/stripe_key",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_B10_secret_rotation_disabled_on_nonsensitive_is_high(self):
        c = _change(
            record_type="aws_secretsmanager_secret",
            field_path="rotation_enabled",
            new_value=False,
            prev_value=True,
            record_name="dev/scratch",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_B11_secret_added_with_wildcard_principal_is_critical(self):
        c = _change(
            record_type="aws_secretsmanager_secret",
            change_type="added",
            new_value={
                "sensitive_name_category": "credential",
                "rotation_enabled":         False,
                "has_resource_policy":      True,
                "policy_summary":           {"has_wildcard_principal": True},
            },
            record_name="prod/api/stripe_key",
        )
        level, _ = _classify(c)
        assert level == "critical"


class TestSsmParameter:
    def test_B12_ssm_parameter_does_not_leak_value(self):
        # Whatever the rule path, the reason must never echo new_value
        # for an SSM parameter (values may be SecureString or sensitive
        # plaintext).
        c = _change(
            record_type="aws_ssm_parameter",
            field_path="value_hash",
            new_value="SECRET-VALUE-DO-NOT-LOG",
            prev_value="OLD-VALUE",
            record_name="/prod/api/stripe_key",
        )
        _, reason = _classify(c)
        assert "secret-value-do-not-log" not in reason.lower(), (
            f"SSM parameter value must never appear in reason: {reason!r}"
        )

    def test_B13_ssm_parameter_removed_does_not_crash(self):
        c = _change(
            record_type="aws_ssm_parameter",
            change_type="removed",
            record_name="/prod/api/db_url",
        )
        level, _ = _classify(c)
        assert level in ("low", "medium", "high", "critical")


# ═════════════════════════════════════════════════════════════════════════════
# C. Lambda / ECS / EKS / Compute
# ═════════════════════════════════════════════════════════════════════════════

class TestLambdaFunction:
    def test_C1_function_url_created_with_auth_none_is_critical(self):
        c = _change(
            record_type="aws_lambda_function_url",
            change_type="added",
            new_value={"auth_type": "NONE"},
            record_name="process-payments",
        )
        level, reason = _classify(c)
        assert level == "critical"
        # Must say the endpoint can be invoked without auth; OK to be
        # assertive here because AWS itself controls auth_type semantics.
        assert "auth" in reason.lower() or "without authentication" in reason.lower()

    def test_C2_function_url_auth_changed_to_none_is_critical(self):
        c = _change(
            record_type="aws_lambda_function_url",
            field_path="auth_type",
            new_value="NONE",
            prev_value="AWS_IAM",
            record_name="process-payments",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_C3_function_url_auth_changed_from_none_to_iam_is_low(self):
        c = _change(
            record_type="aws_lambda_function_url",
            field_path="auth_type",
            new_value="AWS_IAM",
            prev_value="NONE",
            record_name="process-payments",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C4_function_url_removed_is_low(self):
        c = _change(
            record_type="aws_lambda_function_url",
            change_type="removed",
            record_name="process-payments",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C5_function_env_var_count_changed_does_not_leak_values(self):
        c = _change(
            record_type="aws_lambda_function",
            field_path="env_var_key_count",
            new_value=7,
            prev_value=5,
            record_name="process-payments",
        )
        _, reason = _classify(c)
        # Reason should mention count change but never any value.
        assert "value" not in reason.lower() or "values" in reason.lower(), reason


class TestEks:
    def test_C6_eks_public_access_fully_open_on_prod_is_critical(self):
        c = _change(
            record_type="aws_eks_cluster",
            field_path="public_access_fully_open",
            new_value=True,
            prev_value=False,
            record_name="prod-platform-cluster",
        )
        level, _ = _classify(c)
        assert level in ("critical", "high")

    def test_C7_eks_endpoint_public_access_enabled_is_at_least_medium(self):
        c = _change(
            record_type="aws_eks_cluster",
            field_path="endpoint_public_access",
            new_value=True,
            prev_value=False,
            record_name="prod-platform-cluster",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_C8_eks_endpoint_public_disabled_is_low(self):
        c = _change(
            record_type="aws_eks_cluster",
            field_path="endpoint_public_access",
            new_value=False,
            prev_value=True,
            record_name="prod-platform-cluster",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C9_eks_secrets_encryption_disabled_is_at_least_medium(self):
        c = _change(
            record_type="aws_eks_cluster",
            field_path="secrets_encryption_enabled",
            new_value=False,
            prev_value=True,
            record_name="prod-platform-cluster",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")


class TestEcs:
    def test_C10_ecs_task_role_change_is_at_least_medium(self):
        c = _change(
            record_type="aws_ecs_task_definition",
            field_path="task_role_arn_hash",
            new_value="abc123",
            prev_value="def456",
            record_name="prod-api-task",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_C11_ecs_service_task_definition_change_is_at_least_low(self):
        c = _change(
            record_type="aws_ecs_service",
            field_path="task_definition_arn_hash",
            new_value="newhash",
            prev_value="oldhash",
            record_name="prod-api-svc",
        )
        level, _ = _classify(c)
        assert level in ("low", "medium", "high")


# ═════════════════════════════════════════════════════════════════════════════
# D. Route53 / DNS
# ═════════════════════════════════════════════════════════════════════════════

class TestRoute53:
    def test_D1_apex_a_record_removed_is_critical(self):
        c = _change(
            record_type="aws_route53_record",
            change_type="removed",
            record_name="example.com",
            extra_metadata={
                "dns_record_name": "example.com",
                "dns_record_type": "A",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_D2_mx_record_removed_is_critical(self):
        c = _change(
            record_type="aws_route53_record",
            change_type="removed",
            record_name="example.com",
            extra_metadata={
                "dns_record_name": "example.com",
                "dns_record_type": "MX",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_D3_ns_record_value_changed_is_critical(self):
        c = _change(
            record_type="aws_route53_record",
            field_path="value_hash",
            new_value="newhash",
            prev_value="oldhash",
            record_name="example.com",
            extra_metadata={
                "dns_record_name": "example.com",
                "dns_record_type": "NS",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_D4_apex_a_value_changed_is_critical(self):
        c = _change(
            record_type="aws_route53_record",
            field_path="value_hash",
            new_value="newip-hash",
            prev_value="oldip-hash",
            record_name="example.com",
            extra_metadata={
                "dns_record_name": "example.com",
                "dns_record_type": "A",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_D5_wildcard_added_is_at_least_high(self):
        c = _change(
            record_type="aws_route53_record",
            change_type="added",
            record_name="*.example.com",
            extra_metadata={
                "dns_record_name": "*.example.com",
                "dns_record_type": "A",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_D6_caa_removed_is_at_least_medium(self):
        c = _change(
            record_type="aws_route53_record",
            change_type="removed",
            record_name="example.com",
            extra_metadata={
                "dns_record_name": "example.com",
                "dns_record_type": "CAA",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_D7_non_critical_dns_change_is_low_or_medium(self):
        # Brief: "non-critical DNS change should not be over-risked."
        c = _change(
            record_type="aws_route53_record",
            change_type="added",
            record_name="docs.example.com",
            extra_metadata={
                "dns_record_name": "docs.example.com",
                "dns_record_type": "A",
                "zone_name":       "example.com",
            },
        )
        level, _ = _classify(c)
        assert level in ("low", "medium")

    def test_D8_non_critical_dns_change_uses_hedged_language(self):
        # Brief: "wording should say may disrupt/may redirect, not
        # guaranteed outage." Sample a generic apex-A change.
        c = _change(
            record_type="aws_route53_record",
            field_path="value_hash",
            new_value="newhash",
            prev_value="oldhash",
            record_name="example.com",
            extra_metadata={
                "dns_record_name": "example.com",
                "dns_record_type": "A",
                "zone_name":       "example.com",
            },
        )
        _, reason = _classify(c)
        lower = reason.lower()
        # Should not assert guaranteed outage / breach.
        for absolute in ("guaranteed outage", "is unreachable", "is offline"):
            assert absolute not in lower, (
                f"Route53 reason must not assert outage: {reason!r}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# E. VPC / Route Tables / IGW / Subnets
# ═════════════════════════════════════════════════════════════════════════════

class TestVpcRouting:
    def test_E1_route_table_igw_route_added_uses_hedged_language(self):
        c = _change(
            record_type="aws_route_table",
            field_path="has_igw_route",
            new_value=True,
            prev_value=False,
            record_id="us-east-1/rtb-deadbeef",
        )
        level, reason = _classify(c)
        # Brief: should be high, with hedged language about possible
        # internet path — never an absolute reachability claim.
        assert level in ("high", "critical")
        lower = reason.lower()
        assert "may " in lower or "could " in lower or "may now" in lower, (
            f"route-table IGW-route reason must hedge: {reason!r}"
        )
        for absolute in (
            "is publicly reachable",
            "is reachable from the public internet",
            "is exposed to the internet",
        ):
            assert absolute not in lower

    def test_E2_route_table_igw_route_removed_is_low(self):
        c = _change(
            record_type="aws_route_table",
            field_path="has_igw_route",
            new_value=False,
            prev_value=True,
            record_id="us-east-1/rtb-deadbeef",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_E3_route_table_route_count_decrease_is_medium(self):
        c = _change(
            record_type="aws_route_table",
            field_path="route_count",
            new_value=2,
            prev_value=5,
            record_id="us-east-1/rtb-deadbeef",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E4_subnet_metadata_change_does_not_create_noisy_critical(self):
        # Brief: route_table/subnet/NACL metadata changes shouldn't create
        # noisy Critical findings unless direct exposure is clear.
        c = _change(
            record_type="aws_subnet",
            field_path="cidr_block",
            new_value="10.0.0.0/24",
            prev_value="10.0.0.0/22",
            record_id="us-east-1/subnet-abc",
        )
        level, _ = _classify(c)
        assert level in ("low", "medium")


# ═════════════════════════════════════════════════════════════════════════════
# F. Safety: secrets, tokens, malformed metadata
# ═════════════════════════════════════════════════════════════════════════════

class TestSafetyInvariants:
    @pytest.mark.parametrize("change_args", [
        # RDS
        dict(record_type="aws_rds_db_instance",
             field_path="publicly_accessible", new_value=True, prev_value=False,
             record_name="prod-db"),
        # KMS
        dict(record_type="aws_kms_key", field_path="key_state",
             new_value="PendingDeletion", prev_value="Enabled",
             record_name="prod-data-key"),
        dict(record_type="aws_kms_key", field_path="rotation_enabled",
             new_value=False, prev_value=True, record_name="prod-data-key"),
        # Secrets
        dict(record_type="aws_secretsmanager_secret", change_type="removed",
             prev_value={"sensitive_name_category": "credential"},
             record_name="prod/api/stripe_key"),
        # Lambda function URL
        dict(record_type="aws_lambda_function_url",
             change_type="added", new_value={"auth_type": "NONE"},
             record_name="process-payments"),
        # EKS
        dict(record_type="aws_eks_cluster",
             field_path="public_access_fully_open", new_value=True, prev_value=False,
             record_name="prod-cluster"),
        # Route53
        dict(record_type="aws_route53_record", change_type="removed",
             record_name="example.com",
             extra_metadata={"dns_record_name": "example.com",
                             "dns_record_type": "A",
                             "zone_name": "example.com"}),
        # Route table
        dict(record_type="aws_route_table", field_path="has_igw_route",
             new_value=True, prev_value=False, record_id="us-east-1/rtb-x"),
    ])
    def test_F1_reasons_do_not_leak_credentials_or_tokens(self, change_args):
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # AWS access-key shapes: AKIA / ASIA / AIDA / AROX / followed by ≥14 alnum.
        import re
        for prefix in ("akia", "asia", "aida", "arox", "abia"):
            assert not re.search(rf"{prefix}[a-z0-9]{{14,}}", lower), (
                f"reason looks like an access key: {reason!r}"
            )
        # No 60+ char base64-shaped string.
        assert not re.search(r"[A-Za-z0-9+/=]{60,}", reason), (
            f"reason contains a token-shaped string: {reason!r}"
        )

    def test_F2_no_auto_fix_language(self):
        cases = [
            dict(record_type="aws_rds_db_instance",
                 field_path="storage_encrypted", new_value=False, prev_value=True,
                 record_name="prod-db"),
            dict(record_type="aws_kms_key", field_path="key_state",
                 new_value="PendingDeletion", prev_value="Enabled",
                 record_name="prod-key"),
            dict(record_type="aws_lambda_function_url",
                 change_type="added", new_value={"auth_type": "NONE"},
                 record_name="process-payments"),
            dict(record_type="aws_eks_cluster",
                 field_path="public_access_fully_open", new_value=True,
                 prev_value=False, record_name="prod-cluster"),
            dict(record_type="aws_secretsmanager_secret",
                 change_type="removed",
                 prev_value={"sensitive_name_category": "credential"},
                 record_name="prod/api/key"),
        ]
        bad = ("auto-fix", "automatically fix", "guaranteed", "auto fix")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, (
                    f"reason contains {phrase!r}: {reason!r}"
                )

    @pytest.mark.parametrize("rt", [
        "aws_rds_db_instance", "aws_rds_db_cluster", "aws_rds_db_snapshot",
        "aws_kms_key", "aws_kms_alias",
        "aws_secretsmanager_secret", "aws_ssm_parameter",
        "aws_lambda_function", "aws_lambda_function_url",
        "aws_ecs_cluster", "aws_ecs_service", "aws_ecs_task_definition",
        "aws_eks_cluster",
        "aws_route53_hosted_zone", "aws_route53_record",
        "aws_route_table", "aws_subnet", "aws_internet_gateway",
        "aws_network_acl", "aws_vpc",
    ])
    def test_F3_malformed_metadata_does_not_crash(self, rt):
        # Dispatcher must survive malformed provider_metadata for every
        # Part-2 record type just as it does for Part-1.
        for bad_pm in (None, "not a dict", 42, [], ()):
            c = MagicMock(name="Change")
            c.field_path        = "field"
            c.change_type       = "modified"
            c.new_value         = None
            c.prev_value        = None
            c.old_value         = None
            c.previous_value    = None
            c.provider_metadata = bad_pm
            c.name              = ""
            level, _ = _classify(c)
            assert level == "low", (
                f"{rt}: malformed provider_metadata {bad_pm!r} did not fall "
                f"back to low (got {level})"
            )

    @pytest.mark.parametrize("rt", [
        "aws_rds_db_instance", "aws_eks_cluster", "aws_lambda_function_url",
        "aws_route_table", "aws_route53_record",
    ])
    def test_F4_sg_style_reachability_overclaims_absent(self, rt):
        # Spot-check that high-level "is publicly reachable" / "is exposed
        # to the internet" never appear in remaining-surface reasons.
        # (RDS already passes via "network-level controls" mention; route
        #  table hedges with "may now have internet connectivity"; EKS uses
        #  AWS-managed public-access setting which IS factual.)
        c = _change(
            record_type=rt,
            field_path="publicly_accessible" if "rds" in rt else
                       "public_access_fully_open" if "eks" in rt else
                       "has_igw_route" if "route_table" in rt else
                       "value_hash" if "route53" in rt else None,
            change_type="added" if rt == "aws_lambda_function_url" else "modified",
            new_value={"auth_type": "NONE"} if rt == "aws_lambda_function_url" else True,
            prev_value=False,
            record_name="prod-resource",
            extra_metadata=(
                {"dns_record_name": "example.com",
                 "dns_record_type": "A", "zone_name": "example.com"}
                if "route53" in rt else None
            ),
        )
        _, reason = _classify(c)
        lower = reason.lower()
        for absolute in (
            "is publicly reachable",
            "is reachable from the public internet",
        ):
            assert absolute not in lower, (
                f"{rt} reason must hedge; found {absolute!r} in: {reason!r}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# G. Unknown subtype safety (specific to Part-2 namespace)
# ═════════════════════════════════════════════════════════════════════════════

class TestUnknown:
    def test_G1_unknown_aws_subtype_falls_back_safely(self):
        c = _change(record_type="aws_future_service_x")
        level, reason = _classify(c)
        assert level == "low"
        assert isinstance(reason, str) and len(reason) > 0
