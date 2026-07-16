"""AWS change-classification QA regression coverage (message-2 pass).

This file covers bugs found while auditing classification correctness for
the 87 AWS record types currently emitted by `AWSConnector.fetch()`
(detection/routing/tracking correctness was covered in message 1, committed
as `667396c`). This pass focuses on exact transition severity, restoration
direction, unknown handling, and Security Finding severity parity.

Bugs fixed and covered here:

  1. Five Security-Finding-vs-Change severity mismatches, where a fresh
     transition into a bad state was rated LOWER than the equivalent static
     Finding for the identical fact pattern:
     - `_classify_s3_change` (`public_principals_detected`): downgraded to
       "high" for a non-"sensitive"-named bucket; the `aws_s3_public_policy`
       Finding fires "critical" unconditionally for this signal.
     - `_classify_s3_change` (`acl_authenticated_users_write`): rated "high";
       the `aws_s3_public_acl` Finding treats authenticated-users-write the
       same as all-users-write ("critical").
     - `_classify_s3_change` (`acl_authenticated_users_read`): rated
       "medium"; the Finding treats authenticated-users-read the same as
       all-users-read ("high").
     - `_classify_iam_policy_attachment_change` (PowerUserAccess/
       IAMFullAccess attached to a non-"sensitive"-named principal): rated
       "medium"; the `aws_iam_broad_policy_attached` Finding fires "high"
       unconditionally.
     - `_classify_iam_access_key_change` (`last_used_age_days`): rated "low"
       with a `> 90` threshold; the `aws_access_key_unused` Finding fires
       "medium" at `>= 90` (also fixes the off-by-one at exactly 90 days).
  2. A widespread Boolean-unknown-handling bug repeated ~30 times across
     CloudTrail trail/event-data-store, Security Hub account, GuardDuty
     detector/publishing-destination, ECS cluster/service/task-definition,
     EKS cluster, ECR repository, SQS queue, SNS topic/subscription, KMS key,
     EventBridge rule/target, Backup vault/recovery-point, WAF Web ACL,
     ELBv2 load balancer, and Organizations SCP classifiers: each had the
     shape `if nv is False: <escalate>` followed immediately by an
     *unconditional* `return (..., "<feature> was enabled/added/restored")`
     with no `nv is None` branch — meaning a genuinely unknown/unavailable
     value (e.g. a permission hiccup on re-fetch) silently fell into the
     positive "was enabled"/"was restored" claim. Fixed by adding an
     explicit `nv is None` branch with "could not be determined" copy to
     every confirmed site.

These tests exercise the REAL compute_diff() -> classify_aws_change()
pipeline (not hand-built Change objects with fabricated field names),
except for the source-scan regression guard in TestNoStaleChangeFields.
"""

from __future__ import annotations

from pathlib import Path

from app.services.diff_service import compute_diff
from app.services.risk_rules.aws import classify_aws_change

_AWS_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[1] / "app" / "services" / "risk_rules" / "aws.py"
)


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _classify_field(prev: list[dict], new: list[dict], field_path: str):
    changes = _real_changes(prev, new)
    matching = [c for c in changes if c["field_path"] == field_path]
    assert len(matching) == 1, f"expected exactly one Change for {field_path!r}, got {len(matching)}"
    return classify_aws_change(matching[0])


# ── A. Real Change-shape regression guard ────────────────────────────────────

class TestNoStaleChangeFields:
    """Fails if any AWS production classifier reads a stale previous-value
    field name. Real compute_diff() Changes only ever carry `prev_value`."""

    def test_risk_rules_aws_never_reads_stale_previous_value_fields(self):
        src = _AWS_RISK_RULES_PATH.read_text()
        # Strip comment lines so this test doesn't flag the regression-note
        # comments that intentionally document the bug that was fixed.
        code_lines = [
            line for line in src.splitlines()
            if not line.strip().startswith("#")
        ]
        code_only = "\n".join(code_lines)
        for stale_field in ("old_value", "previous_value", "prior_value"):
            assert f'"{stale_field}"' not in code_only, (
                f"risk_rules/aws.py reads a stale Change field {stale_field!r} "
                "in live code — real compute_diff() Changes only carry prev_value."
            )

    def test_route53_hosted_zone_uses_prev_value(self):
        prev = [{
            "record_type": "aws_route53_hosted_zone", "record_id": "Z1/zone",
            "name": "example.com", "zone_type": "private", "private_zone": True,
            "resource_record_set_count": 5, "linked_vpc_count": 1, "comment": "",
            "name_servers": [], "tag_keys": [],
        }]
        new = [{**prev[0], "zone_type": "public", "private_zone": False}]
        level, reason = _classify_field(prev, new, "zone_type")
        assert level == "high"
        assert "private to public" in reason.lower()

    def test_cloudfront_distribution_uses_prev_value(self):
        prev = [{
            "record_type": "aws_cloudfront_distribution", "record_id": "E1",
            "name": "d1.cloudfront.net", "enabled": True, "status": "Deployed",
            "aliases": [], "alias_count": 0, "default_root_object": "",
            "price_class": "PriceClass_All", "http_version": "http2",
            "ipv6_enabled": True, "web_acl_id": None,
            "viewer_certificate_summary": "default", "origin_count": 1,
            "origins_summary": "s3", "default_cache_behavior_summary": "default",
            "ordered_cache_behavior_count": 0, "ordered_cache_behaviors_summary": "",
            "logging_enabled": False, "logging_bucket_domain": None,
            "custom_error_response_count": 0, "restrictions_summary": "none",
            "tag_keys": [],
        }]
        new = [{**prev[0], "enabled": False}]
        level, reason = _classify_field(prev, new, "enabled")
        assert level in ("critical", "high")
        assert "removed" not in reason.lower()


# ── Q. Security Finding severity parity ──────────────────────────────────────

class TestS3FindingParity:
    _BASE = {
        "record_type": "aws_s3_bucket", "record_id": "b1/bucket",
        "name": "my-app-data", "bucket_region": "us-east-1",
        "public_access_block_configured": True, "policy_present": False,
        "policy_status_is_public": False, "policy_hash": None,
        "public_principals_detected": False, "acl_all_users_read": False,
        "acl_all_users_write": False, "acl_authenticated_users_read": False,
        "acl_authenticated_users_write": False, "encryption_enabled": True,
        "encryption_algorithm": "AES256", "bucket_key_enabled": False,
        "versioning_status": "Enabled", "mfa_delete_status": "Disabled",
        "logging_enabled": True, "logging_target_bucket": "logs",
        "lifecycle_rule_count": 0, "tag_keys": [],
    }

    def test_public_principal_non_sensitive_bucket_is_critical(self):
        """Matches aws_s3_public_policy Finding, which fires critical
        unconditionally — must not be downgraded for a non-"sensitive" name."""
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_principals_detected": True}]
        level, _ = _classify_field(prev, new, "public_principals_detected")
        assert level == "critical"

    def test_acl_authenticated_users_write_is_critical(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "acl_authenticated_users_write": True}]
        level, _ = _classify_field(prev, new, "acl_authenticated_users_write")
        assert level == "critical"

    def test_acl_authenticated_users_read_is_high(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "acl_authenticated_users_read": True}]
        level, _ = _classify_field(prev, new, "acl_authenticated_users_read")
        assert level == "high"


class TestIamFindingParity:
    def test_broad_policy_non_sensitive_principal_is_high(self):
        new = [{
            "record_type": "aws_iam_policy_attachment", "record_id": "attach-1",
            "principal_name": "svc-deploy", "policy_name": "PowerUserAccess",
            "principal_type": "role",
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, _ = classify_aws_change(added[0])
        assert level == "high"

    def test_access_key_unused_at_90_days_is_medium(self):
        """Matches aws_access_key_unused Finding's `>= 90` threshold —
        exactly 90 days must not fall below the Finding's severity."""
        prev = [{
            "record_type": "aws_iam_access_key", "record_id": "AKIA1",
            "status": "Active", "last_used_age_days": 10,
        }]
        new = [{**prev[0], "last_used_age_days": 90}]
        level, _ = _classify_field(prev, new, "last_used_age_days")
        assert level == "medium"


# ── M. Boolean unknown handling (sample across services) ────────────────────

class TestCloudTrailUnknownHandling:
    _BASE = {
        "record_type": "aws_cloudtrail_trail", "record_id": "arn:trail1",
        "name": "org-trail", "home_region": "us-east-1",
        "is_multi_region_trail": True, "include_global_service_events": True,
        "is_organization_trail": True, "log_file_validation_enabled": True,
        "kms_key_id_present": True, "s3_bucket_name_hash": "h1",
        "sns_topic_name_present": False, "cloud_watch_logs_enabled": True,
        "has_custom_event_selectors": False, "is_logging": True,
        "latest_delivery_error_present": False,
        "latest_notification_error_present": False,
        "management_events_enabled": True, "read_write_type": "All",
        "include_management_events": True, "data_resource_type_counts": {},
        "exclude_management_event_sources_count": 0,
        "insight_selector_count": 0, "insight_selector_types": [],
        "tag_keys": [],
    }

    def test_is_logging_becoming_unknown_is_not_reported_as_resumed(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "is_logging": None}]
        level, reason = _classify_field(prev, new, "is_logging")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "resumed" not in reason.lower()

    def test_log_file_validation_becoming_unknown_is_not_reported_as_enabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "log_file_validation_enabled": None}]
        level, reason = _classify_field(prev, new, "log_file_validation_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_is_logging_false_still_critical(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "is_logging": False}]
        level, reason = _classify_field(prev, new, "is_logging")
        assert level == "critical"
        assert "stopped logging" in reason.lower()


class TestKmsKeyUnknownHandling:
    _BASE = {
        "record_type": "aws_kms_key", "record_id": "key1",
        "name": "app-key", "key_state": "Enabled", "enabled": True,
        "key_usage": "ENCRYPT_DECRYPT", "key_spec": "SYMMETRIC_DEFAULT",
        "key_manager": "CUSTOMER", "origin": "AWS_KMS", "multi_region": False,
        "deletion_date_present": False, "valid_to_present": False,
        "rotation_enabled": True, "policy_present": True,
        "public_or_cross_account_policy": False, "wildcard_admin_policy": False,
        "tag_keys": [],
    }

    def test_enabled_becoming_unknown_is_not_reported_as_reenabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "enabled": None}]
        level, reason = _classify_field(prev, new, "enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "re-enabled" not in reason.lower()


class TestSecurityHubUnknownHandling:
    _BASE = {
        "record_type": "aws_securityhub_account", "record_id": "acct1/hub",
        "name": "us-east-1", "hub_enabled": True, "auto_enable_controls": True,
        "control_finding_generator": "SECURITY_CONTROL",
        "enabled_standards_count": 3, "enabled_products_count": 2,
        "finding_aggregator_present": True, "tag_keys": [],
    }

    def test_hub_enabled_becoming_unknown_is_not_reported_as_enabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "hub_enabled": None}]
        level, reason = _classify_field(prev, new, "hub_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()


class TestEksClusterUnknownHandling:
    _BASE = {
        "record_type": "aws_eks_cluster", "record_id": "cluster1",
        "name": "prod-cluster", "status": "ACTIVE", "kubernetes_version": "1.29",
        "platform_version": "eks.5", "role_arn_hash": "h1",
        "endpoint_public_access": False, "endpoint_private_access": True,
        "public_access_fully_open": False, "public_access_cidrs_count": 0,
        "subnet_count": 3, "security_group_count": 1, "ip_family": "ipv4",
        "enabled_log_types": ["audit"], "has_audit_logging": True,
        "secrets_encryption_enabled": True, "kms_key_hash": "h2",
        "tag_keys": [],
    }

    def test_secrets_encryption_becoming_unknown_is_not_reported_as_enabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "secrets_encryption_enabled": None}]
        level, reason = _classify_field(prev, new, "secrets_encryption_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()


class TestMessagingUnknownHandling:
    def test_sqs_public_policy_becoming_unknown_is_not_reported_as_private(self):
        prev = [{
            "record_type": "aws_sqs_queue", "record_id": "q1",
            "name": "orders", "public_or_cross_account_policy": True,
        }]
        new = [{**prev[0], "public_or_cross_account_policy": None}]
        level, reason = _classify_field(prev, new, "public_or_cross_account_policy")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_ecr_policy_is_public_becoming_unknown_is_not_reported_as_private(self):
        prev = [{
            "record_type": "aws_ecr_repository", "record_id": "repo1",
            "name": "internal-app", "policy_is_public": True,
        }]
        new = [{**prev[0], "policy_is_public": None}]
        level, reason = _classify_field(prev, new, "policy_is_public")
        assert level == "medium"
        assert "could not be determined" in reason.lower()


class TestBackupVaultUnknownHandling:
    def test_locked_becoming_unknown_is_not_reported_as_enabled(self):
        prev = [{
            "record_type": "aws_backup_vault", "record_id": "vault1",
            "name": "prod-vault", "locked": True,
        }]
        new = [{**prev[0], "locked": None}]
        level, reason = _classify_field(prev, new, "locked")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
