"""AWS Part 2 expansion — Config, Access Analyzer, Org/SCP, CloudWatch
alarms, ECR, ACM, deeper data-protection posture.

Coverage strategy
-----------------
* **NEW record types** (Config recorder/delivery channel, Access Analyzer
  + findings, Security Hub finding, ACM certificate): full scenario
  coverage via the new sub-classifiers added in M59.9.
* **Existing record types** (Security Hub account, CloudWatch alarms,
  ECR repositories, Organizations/SCPs, KMS, Secrets Manager, RDS,
  S3 — see Parts 1 + existing M40-M49 audits): black-box re-verification
  that the brief's scenarios still produce non-crashing classifications.
* **Dispatcher / safety**: unknown subtype + malformed `provider_metadata`.
* **Secret-safety tripwires**: realistic AWS-shaped credentials must never
  appear in any risk reason.

All tests run without PostgreSQL.  No real AWS API is called.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.aws import (
    classify_aws_change,
    _classify_config_recorder_change,
    _classify_config_delivery_channel_change,
    _classify_access_analyzer_change,
    _classify_access_analyzer_finding_change,
    _classify_securityhub_finding_change,
    _classify_acm_certificate_change,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ch(
    *,
    record_type: str,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    pm_extra: dict | None = None,
):
    c = MagicMock(name="Change")
    c.change_type = change_type
    c.field_path = field_path
    c.prev_value = prev_value
    c.new_value = new_value
    pm = {"record_type": record_type}
    if pm_extra:
        pm.update(pm_extra)
    c.provider_metadata = pm
    return c


# ═════════════════════════════════════════════════════════════════════════════
# A. aws_config_recorder + aws_config_delivery_channel  (NEW)
# ═════════════════════════════════════════════════════════════════════════════


class TestConfigRecorder:

    def test_A1_recorder_removed_is_critical(self):
        c = _ch(
            record_type="aws_config_recorder", change_type="removed",
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "config" in reason.lower() and "removed" in reason.lower()

    def test_A2_recorder_paused_is_critical(self):
        c = _ch(
            record_type="aws_config_recorder", field_path="recording",
            prev_value=True, new_value=False,
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_A3_recorder_resumed_is_low(self):
        c = _ch(
            record_type="aws_config_recorder", field_path="recording",
            prev_value=False, new_value=True,
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_A4_global_resources_no_longer_recorded_is_high(self):
        c = _ch(
            record_type="aws_config_recorder",
            field_path="records_global_resources",
            prev_value=True, new_value=False,
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A5_resource_types_narrowed_is_high(self):
        c = _ch(
            record_type="aws_config_recorder",
            field_path="resource_types_count",
            prev_value=50, new_value=5,
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A6_recorder_added_is_low(self):
        c = _ch(
            record_type="aws_config_recorder", change_type="added",
            pm_extra={"name": "default", "region": "eu-west-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"


class TestConfigDeliveryChannel:

    def test_A7_delivery_channel_removed_is_high(self):
        c = _ch(
            record_type="aws_config_delivery_channel", change_type="removed",
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A8_s3_bucket_changed_is_medium(self):
        c = _ch(
            record_type="aws_config_delivery_channel",
            field_path="s3_bucket_name",
            prev_value="my-config-bucket", new_value="someone-else-bucket",
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_A9_kms_key_changed_is_medium(self):
        c = _ch(
            record_type="aws_config_delivery_channel",
            field_path="s3_kms_key_id",
            prev_value="hash_old", new_value="hash_new",
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# B. aws_access_analyzer + aws_access_analyzer_finding  (NEW)
# ═════════════════════════════════════════════════════════════════════════════


class TestAccessAnalyzer:

    def test_B1_analyzer_removed_is_high(self):
        c = _ch(
            record_type="aws_access_analyzer", change_type="removed",
            pm_extra={"name": "org-analyzer", "region": "us-east-1",
                      "type": "ACCOUNT"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_B2_analyzer_added_is_low(self):
        c = _ch(
            record_type="aws_access_analyzer", change_type="added",
            pm_extra={"name": "org-analyzer", "region": "us-east-1",
                      "type": "ORGANIZATION"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_B3_analyzer_disabled_is_high(self):
        c = _ch(
            record_type="aws_access_analyzer", field_path="status",
            prev_value="ACTIVE", new_value="DISABLED",
            pm_extra={"name": "org-analyzer"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_B4_analyzer_scope_narrowed_org_to_account_is_medium(self):
        c = _ch(
            record_type="aws_access_analyzer", field_path="type",
            prev_value="ORGANIZATION", new_value="ACCOUNT",
            pm_extra={"name": "org-analyzer"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_B5_analyzer_scope_broadened_account_to_org_is_low(self):
        c = _ch(
            record_type="aws_access_analyzer", field_path="type",
            prev_value="ACCOUNT", new_value="ORGANIZATION",
            pm_extra={"name": "org-analyzer"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"


class TestAccessAnalyzerFinding:

    def test_B6_new_public_finding_on_s3_is_critical(self):
        c = _ch(
            record_type="aws_access_analyzer_finding", change_type="added",
            pm_extra={
                "finding_id": "find-001",
                "resource_type": "AWS::S3::Bucket",
                "is_public": True,
                "finding_type": "ExternalAccess",
            },
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "public" in reason.lower()

    def test_B7_new_public_finding_on_kms_is_critical(self):
        c = _ch(
            record_type="aws_access_analyzer_finding", change_type="added",
            pm_extra={
                "finding_id": "find-002",
                "resource_type": "AWS::KMS::Key",
                "is_public": True,
            },
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_B8_new_public_finding_on_non_sensitive_is_high(self):
        c = _ch(
            record_type="aws_access_analyzer_finding", change_type="added",
            pm_extra={
                "finding_id": "find-003",
                "resource_type": "AWS::EFS::FileSystem",  # not in sensitive set
                "is_public": True,
            },
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_B9_new_cross_account_on_sensitive_is_high(self):
        c = _ch(
            record_type="aws_access_analyzer_finding", change_type="added",
            pm_extra={
                "finding_id": "find-004",
                "resource_type": "AWS::IAM::Role",
                "is_public": False,
            },
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_B10_finding_archived_on_public_sensitive_is_high(self):
        c = _ch(
            record_type="aws_access_analyzer_finding", field_path="status",
            prev_value="ACTIVE", new_value="ARCHIVED",
            pm_extra={
                "finding_id": "find-005",
                "resource_type": "AWS::S3::Bucket",
                "is_public": True,
            },
        )
        level, reason = classify_aws_change(c)
        assert level == "high"
        assert "archived" in reason.lower()

    def test_B11_finding_resolved_is_low(self):
        c = _ch(
            record_type="aws_access_analyzer_finding", field_path="status",
            prev_value="ACTIVE", new_value="RESOLVED",
            pm_extra={"finding_id": "find-006",
                      "resource_type": "AWS::S3::Bucket",
                      "is_public": True},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. aws_securityhub_finding  (NEW)
# ═════════════════════════════════════════════════════════════════════════════


class TestSecurityHubFinding:

    def test_C1_new_critical_finding_is_critical(self):
        c = _ch(
            record_type="aws_securityhub_finding", change_type="added",
            pm_extra={"finding_id": "sh-001", "severity": "CRITICAL",
                      "resource_type": "AWS::S3::Bucket"},
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_C2_new_high_finding_is_high(self):
        c = _ch(
            record_type="aws_securityhub_finding", change_type="added",
            pm_extra={"finding_id": "sh-002", "severity": "HIGH",
                      "resource_type": "AWS::IAM::Role"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_C3_new_medium_finding_is_medium(self):
        c = _ch(
            record_type="aws_securityhub_finding", change_type="added",
            pm_extra={"finding_id": "sh-003", "severity": "MEDIUM",
                      "resource_type": "AWS::CloudTrail::Trail"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_C4_critical_finding_suppressed_is_high(self):
        c = _ch(
            record_type="aws_securityhub_finding", field_path="workflow_status",
            prev_value="NEW", new_value="SUPPRESSED",
            pm_extra={"finding_id": "sh-004", "severity": "CRITICAL",
                      "resource_type": "AWS::S3::Bucket"},
        )
        level, reason = classify_aws_change(c)
        assert level == "high"
        assert "suppressed" in reason.lower()

    def test_C5_critical_finding_archived_is_high(self):
        c = _ch(
            record_type="aws_securityhub_finding", field_path="record_state",
            prev_value="ACTIVE", new_value="ARCHIVED",
            pm_extra={"finding_id": "sh-005", "severity": "CRITICAL",
                      "resource_type": "AWS::IAM::User"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_C6_finding_resolved_is_low(self):
        c = _ch(
            record_type="aws_securityhub_finding", field_path="workflow_status",
            prev_value="NEW", new_value="RESOLVED",
            pm_extra={"finding_id": "sh-006", "severity": "HIGH",
                      "resource_type": "AWS::S3::Bucket"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_C7_severity_raised_to_critical_is_high(self):
        c = _ch(
            record_type="aws_securityhub_finding", field_path="severity",
            prev_value="HIGH", new_value="CRITICAL",
            pm_extra={"finding_id": "sh-007",
                      "resource_type": "AWS::S3::Bucket", "severity": "CRITICAL"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# D. aws_acm_certificate  (NEW)
# ═════════════════════════════════════════════════════════════════════════════


class TestACMCertificate:

    def test_D1_cert_removed_on_prod_domain_is_high(self):
        c = _ch(
            record_type="aws_acm_certificate", change_type="removed",
            pm_extra={"record_id": "cert-001",
                      "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_D2_cert_removed_on_non_prod_is_medium(self):
        # 3+ labels to avoid the apex heuristic; no production hint prefix.
        c = _ch(
            record_type="aws_acm_certificate", change_type="removed",
            pm_extra={"record_id": "cert-002",
                      "domain_name": "playground.staging.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_D3_cert_expired_on_prod_is_critical(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value="ISSUED", new_value="EXPIRED",
            pm_extra={"record_id": "cert-003", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_D4_cert_expired_on_non_prod_is_high(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value="ISSUED", new_value="EXPIRED",
            pm_extra={"record_id": "cert-004",
                      "domain_name": "playground.example.dev"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_D5_validation_failed_is_high(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value="PENDING_VALIDATION", new_value="FAILED",
            pm_extra={"record_id": "cert-005", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_D6_pending_validation_is_medium(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value=None, new_value="PENDING_VALIDATION",
            pm_extra={"record_id": "cert-006", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_D7_issued_is_low(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value="PENDING_VALIDATION", new_value="ISSUED",
            pm_extra={"record_id": "cert-007", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_D8_days_to_expiry_under_14_on_prod_is_high(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="days_to_expiry",
            prev_value=30, new_value=7,
            pm_extra={"record_id": "cert-008", "domain_name": "api.example.com"},
        )
        level, reason = classify_aws_change(c)
        assert level == "high"
        assert "expire" in reason.lower() or "renewal" in reason.lower()

    def test_D9_days_to_expiry_zero_on_prod_is_critical(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="days_to_expiry",
            prev_value=1, new_value=0,
            pm_extra={"record_id": "cert-009", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_D10_domain_name_changed_is_high(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="domain_name",
            prev_value="api.example.com", new_value="api.attacker.example",
            pm_extra={"record_id": "cert-010",
                      "domain_name": "api.attacker.example"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_D11_san_count_increased_is_medium(self):
        c = _ch(
            record_type="aws_acm_certificate",
            field_path="subject_alternative_names_count",
            prev_value=2, new_value=6,
            pm_extra={"record_id": "cert-011", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_D12_weak_key_algorithm_is_high(self):
        c = _ch(
            record_type="aws_acm_certificate", field_path="key_algorithm",
            prev_value="RSA_2048", new_value="RSA_1024",
            pm_extra={"record_id": "cert-012", "domain_name": "api.example.com"},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_D13_targets_production_flag_overrides_domain_hint(self):
        """Explicit ``targets_production=True`` escalates expiry severity
        even when the domain name doesn't match the production hint set."""
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value="ISSUED", new_value="EXPIRED",
            pm_extra={"record_id": "cert-013",
                      "domain_name": "obscure-service-name.example.io",
                      "targets_production": True},
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"


# ═════════════════════════════════════════════════════════════════════════════
# E. Existing surfaces — black-box re-verification
# ═════════════════════════════════════════════════════════════════════════════


class TestExistingSurfacesReverify:
    """Re-verify the brief's Part-2 scenarios against the EXISTING
    classifiers (CloudWatch alarms, ECR, KMS, Secrets Manager, SCPs).
    These tests pass through `classify_aws_change` — they assert only
    that a non-crashing valid level + non-empty reason is returned."""

    @pytest.mark.parametrize(
        "record_type,field_path,prev,nxt,pm_extra",
        [
            ("aws_cloudwatch_metric_alarm", "actions_enabled",
             True, False,
             {"record_id": "billing-alarm", "name": "billing-alarm"}),
            ("aws_cloudwatch_metric_alarm", "threshold",
             100, 1_000_000,
             {"record_id": "error-rate", "name": "error-rate"}),
            ("aws_ecr_repository", "image_scanning_enabled",
             True, False,
             {"record_id": "prod-app", "name": "prod-app"}),
            ("aws_ecr_repository", "image_tag_mutability",
             "IMMUTABLE", "MUTABLE",
             {"record_id": "prod-app", "name": "prod-app"}),
            ("aws_kms_key", "key_policy_hash",
             "hash-a", "hash-b",
             {"record_id": "1234abcd"}),
            ("aws_secretsmanager_secret", "rotation_enabled",
             True, False,
             {"record_id": "prod-db-password"}),
            ("aws_organizations_scp_attachment", None, None, None,
             {"record_id": "scp-attach-001"}),
        ],
    )
    def test_E1_existing_classifier_returns_valid_tuple(
        self, record_type, field_path, prev, nxt, pm_extra
    ):
        ct = "removed" if field_path is None else "modified"
        c = _ch(
            record_type=record_type, change_type=ct, field_path=field_path,
            prev_value=prev, new_value=nxt, pm_extra=pm_extra,
        )
        level, reason = classify_aws_change(c)
        assert level in ("critical", "high", "medium", "low")
        assert isinstance(reason, str) and reason


# ═════════════════════════════════════════════════════════════════════════════
# F. Dispatcher / safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    @pytest.mark.parametrize(
        "fn",
        [
            _classify_config_recorder_change,
            _classify_config_delivery_channel_change,
            _classify_access_analyzer_change,
            _classify_access_analyzer_finding_change,
            _classify_securityhub_finding_change,
            _classify_acm_certificate_change,
        ],
    )
    def test_F1_malformed_pm_does_not_crash(self, fn, bad_pm):
        c = MagicMock()
        c.change_type = "modified"
        c.field_path = "x"
        c.prev_value = "a"
        c.new_value = "b"
        c.provider_metadata = bad_pm
        level, _ = fn(c)
        assert level in ("critical", "high", "medium", "low")

    def test_F2_unknown_aws_subtype_safe_default(self):
        c = _ch(
            record_type="aws_does_not_exist", field_path="x",
            prev_value="a", new_value="b",
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_F3_top_level_dispatch_routes_new_types(self):
        for rt, expected in [
            ("aws_config_recorder", "critical"),
            ("aws_config_delivery_channel", "high"),
            ("aws_access_analyzer", "high"),
            ("aws_access_analyzer_finding", "critical"),
            ("aws_securityhub_finding", "critical"),
            ("aws_acm_certificate", "critical"),
        ]:
            if rt == "aws_config_recorder":
                c = _ch(record_type=rt, change_type="removed",
                        pm_extra={"name": "default"})
            elif rt == "aws_config_delivery_channel":
                c = _ch(record_type=rt, change_type="removed",
                        pm_extra={"name": "default"})
            elif rt == "aws_access_analyzer":
                c = _ch(record_type=rt, change_type="removed",
                        pm_extra={"name": "az"})
            elif rt == "aws_access_analyzer_finding":
                c = _ch(record_type=rt, change_type="added",
                        pm_extra={"finding_id": "f1",
                                  "resource_type": "AWS::S3::Bucket",
                                  "is_public": True})
            elif rt == "aws_securityhub_finding":
                c = _ch(record_type=rt, change_type="added",
                        pm_extra={"finding_id": "f1", "severity": "CRITICAL",
                                  "resource_type": "AWS::S3::Bucket"})
            elif rt == "aws_acm_certificate":
                c = _ch(record_type=rt, field_path="status",
                        prev_value="ISSUED", new_value="EXPIRED",
                        pm_extra={"record_id": "c1",
                                  "domain_name": "api.example.com"})
            level, _ = classify_aws_change(c)
            assert level == expected, f"{rt}: expected {expected}, got {level}"


# ═════════════════════════════════════════════════════════════════════════════
# G. Schema registry includes new entries
# ═════════════════════════════════════════════════════════════════════════════


class TestSchemaRegistry:

    def test_G1_new_record_types_registered(self):
        from app.connectors.aws_schema import (
            AWS_CONFIG_RECORDER,
            AWS_CONFIG_DELIVERY_CHANNEL,
            AWS_ACCESS_ANALYZER,
            AWS_ACCESS_ANALYZER_FINDING,
            AWS_SECURITYHUB_FINDING,
            AWS_ACM_CERTIFICATE,
            AWS_RECORD_TYPES,
        )
        for rt in (
            AWS_CONFIG_RECORDER, AWS_CONFIG_DELIVERY_CHANNEL,
            AWS_ACCESS_ANALYZER, AWS_ACCESS_ANALYZER_FINDING,
            AWS_SECURITYHUB_FINDING, AWS_ACM_CERTIFICATE,
        ):
            assert rt in AWS_RECORD_TYPES


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires across the new classifiers
# ═════════════════════════════════════════════════════════════════════════════


_SECRET_FIXTURES: dict[str, str] = {
    "aws_akia": "AKIA" + ("K" * 16),
    "aws_asia": "ASIA" + ("L" * 16),
    "aws_secret_40": "M" * 40,
    "aws_session_token": "FQoG" + ("N" * 200),
    "bearer_jwt": "Bearer eyJhbGciOi" + ("X" * 80),
    "stripe_sk_live": "sk_live_" + ("A" * 99),
    "private_key_pem": (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("O" * 60) + "\n"
        "-----END PRIVATE KEY-----"
    ),
    "iam_policy_blob": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                       '"Action":"*","Resource":"*"}]}',
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bASIA[A-Z0-9]{16}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"\bFQoG[A-Za-z0-9+/=]{50,}"),
)


def _assert_safe(reason: str, secret: str) -> None:
    assert secret not in reason, f"reason leaked: {reason!r}"
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_acm_domain_secret_never_echoed(self, name, secret):
        """A misconfigured domain_name carrying credential-shaped text must
        not be echoed into the reason."""
        c = _ch(
            record_type="aws_acm_certificate", field_path="status",
            prev_value="ISSUED", new_value="EXPIRED",
            pm_extra={"record_id": "cert-leak", "domain_name": secret},
        )
        _, reason = classify_aws_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_finding_resource_type_secret_never_echoed(self, name, secret):
        """Access Analyzer finding reason refers to resource_type — must not
        echo a credential-shaped value."""
        c = _ch(
            record_type="aws_access_analyzer_finding", change_type="added",
            pm_extra={"finding_id": "f1",
                      "resource_type": secret,
                      "is_public": True},
        )
        _, reason = classify_aws_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S3_config_delivery_channel_destination_secret_never_echoed(self, name, secret):
        c = _ch(
            record_type="aws_config_delivery_channel",
            field_path="s3_bucket_name",
            prev_value="my-bucket", new_value=secret,
            pm_extra={"name": "default", "region": "us-east-1"},
        )
        _, reason = classify_aws_change(c)
        _assert_safe(reason, secret)

    def test_S4_no_forbidden_phrases_in_severe_reasons(self):
        bad_phrases = (
            "compromised", "hacked", "definitely", "guaranteed",
        )
        scenarios = [
            _ch(record_type="aws_config_recorder", change_type="removed",
                pm_extra={"name": "default"}),
            _ch(record_type="aws_access_analyzer_finding", change_type="added",
                pm_extra={"finding_id": "f1",
                          "resource_type": "AWS::S3::Bucket",
                          "is_public": True}),
            _ch(record_type="aws_securityhub_finding", change_type="added",
                pm_extra={"finding_id": "f1", "severity": "CRITICAL",
                          "resource_type": "AWS::S3::Bucket"}),
            _ch(record_type="aws_acm_certificate", field_path="status",
                prev_value="ISSUED", new_value="EXPIRED",
                pm_extra={"record_id": "c1",
                          "domain_name": "api.example.com"}),
        ]
        for c in scenarios:
            _, reason = classify_aws_change(c)
            r = reason.lower()
            for bad in bad_phrases:
                assert bad not in r, (
                    f"forbidden phrase {bad!r} in: {reason!r}"
                )
