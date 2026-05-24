"""Tests for Milestone 45: AWS CloudTrail + GuardDuty + Security Hub Posture.

Covers:
- Security hard rules: no LookupEvents, no GetFindings, no log reads
- Schema registration: all 7 M45 types in AWS_RECORD_TYPES
- Diff service tracked field registration for all 7 M45 types
- Helper functions: _summarize_cloudtrail_event_selectors,
  _summarize_cloudtrail_advanced_event_selectors,
  _summarize_cloudtrail_insight_selectors,
  _summarize_guardduty_features, _securityhub_standard_name_from_arn
- Risk classification: aws_cloudtrail_trail (full matrix)
- Risk classification: aws_cloudtrail_event_data_store
- Risk classification: aws_guardduty_detector (full matrix)
- Risk classification: aws_guardduty_publishing_destination
- Risk classification: aws_securityhub_account (full matrix)
- Risk classification: aws_securityhub_standard_subscription
- Risk classification: aws_securityhub_finding_aggregator
- Failure classification: classify_aws_cloudtrail_failure
- Failure classification: classify_aws_guardduty_failure
- Failure classification: classify_aws_securityhub_failure
- Connector normalization: _fetch_cloudtrail_trail_detail,
  _fetch_cloudtrail_event_data_stores_in_region,
  _fetch_guardduty_in_region, _fetch_securityhub_in_region
- Service inventory: cloudtrail, guardduty, security_hub in enabled_surfaces
- Fail-soft: per-region errors do not abort full fetch
- M44 regression guard
"""

import inspect
import pytest
from unittest.mock import MagicMock, patch

from app.connectors.aws import (
    AWSConnector,
    _hash_kms_key_id,
    _extract_tag_keys,
)
from app.connectors.aws_schema import (
    AWS_CLOUDTRAIL_TRAIL,
    AWS_CLOUDTRAIL_EVENT_DATA_STORE,
    AWS_GUARDDUTY_DETECTOR,
    AWS_GUARDDUTY_PUBLISHING_DESTINATION,
    AWS_SECURITYHUB_ACCOUNT,
    AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
    AWS_SECURITYHUB_FINDING_AGGREGATOR,
    AWS_SERVICE_INVENTORY,
    AWS_WAFV2_WEB_ACL,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_cloudtrail_failure,
    classify_aws_guardduty_failure,
    classify_aws_securityhub_failure,
)
from app.connectors.exceptions import (
    ConnectorError,
    AuthenticationError,
    RateLimitError,
    NetworkError,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_connector():
    """Create an AWSConnector without calling __init__ (no DB needed)."""
    conn = AWSConnector.__new__(AWSConnector)
    return conn


def _creds(regions=None):
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_default_region": "us-east-1",
        "aws_selected_regions": regions or ["us-east-1"],
    }


def _ct_change(
    record_type=AWS_CLOUDTRAIL_TRAIL,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-trail",
    is_organization_trail=False,
    is_multi_region_trail=False,
):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
            "is_organization_trail": is_organization_trail,
            "is_multi_region_trail": is_multi_region_trail,
        },
    }


def _gd_change(
    record_type=AWS_GUARDDUTY_DETECTOR,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="guardduty-us-east-1-abcd1234",
):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


def _sh_change(
    record_type=AWS_SECURITYHUB_ACCOUNT,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="securityhub-us-east-1",
):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Security hard rules
# ─────────────────────────────────────────────────────────────────────────────

class TestM45SecurityHardRules:
    """Verify that forbidden API calls never appear in the codebase."""

    def _source_of(self, method_name: str) -> str:
        conn = _make_connector()
        method = getattr(conn, method_name, None)
        if method is None:
            return ""
        return inspect.getsource(method)

    def test_cloudtrail_lookup_events_never_called(self):
        src = self._source_of("_fetch_cloudtrail_resources")
        src += self._source_of("_fetch_cloudtrail_trail_detail")
        # Check that lookup_events is not called as a boto3 method
        # (comments mentioning it as forbidden are fine)
        assert "client.lookup_events" not in src.lower()
        assert ".lookup_events(" not in src.lower()

    def test_cloudtrail_s3_log_objects_never_read(self):
        src = self._source_of("_fetch_cloudtrail_trail_detail")
        assert ".get_object(" not in src.lower()
        assert "client.get_object" not in src.lower()

    def test_guardduty_get_findings_never_called(self):
        src = self._source_of("_fetch_guardduty_in_region")
        src += self._source_of("_fetch_guardduty_resources")
        # Check no actual API call to get_findings
        assert ".get_findings(" not in src.lower()
        assert "client.get_findings" not in src.lower()

    def test_securityhub_get_findings_never_called(self):
        src = self._source_of("_fetch_securityhub_in_region")
        src += self._source_of("_fetch_securityhub_resources")
        # Check no actual API call to get_findings
        assert ".get_findings(" not in src.lower()
        assert "client.get_findings" not in src.lower()

    def test_cloudtrail_failure_classifier_mentions_no_log_access(self):
        """Failure classifier recommended_action must explicitly state events not accessed."""
        fc = classify_aws_cloudtrail_failure(
            "DescribeTrails",
            ConnectorError("AccessDenied", status_code=403),
        )
        action_lower = fc.recommended_action.lower()
        assert "never" in action_lower or "not" in action_lower

    def test_guardduty_failure_classifier_mentions_no_findings(self):
        fc = classify_aws_guardduty_failure(
            "ListDetectors",
            ConnectorError("AccessDenied", status_code=403),
        )
        action_lower = fc.recommended_action.lower()
        assert "finding" in action_lower
        assert "never" in action_lower or "not" in action_lower

    def test_securityhub_failure_classifier_mentions_no_findings(self):
        fc = classify_aws_securityhub_failure(
            "DescribeHub",
            ConnectorError("AccessDenied", status_code=403),
        )
        action_lower = fc.recommended_action.lower()
        assert "finding" in action_lower
        assert "never" in action_lower or "not" in action_lower


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

class TestM45Schema:
    def test_all_m45_types_in_record_types(self):
        for rt in (
            AWS_CLOUDTRAIL_TRAIL,
            AWS_CLOUDTRAIL_EVENT_DATA_STORE,
            AWS_GUARDDUTY_DETECTOR,
            AWS_GUARDDUTY_PUBLISHING_DESTINATION,
            AWS_SECURITYHUB_ACCOUNT,
            AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
            AWS_SECURITYHUB_FINDING_AGGREGATOR,
        ):
            assert rt in AWS_RECORD_TYPES, f"{rt} missing from AWS_RECORD_TYPES"

    def test_constants_have_correct_values(self):
        assert AWS_CLOUDTRAIL_TRAIL == "aws_cloudtrail_trail"
        assert AWS_CLOUDTRAIL_EVENT_DATA_STORE == "aws_cloudtrail_event_data_store"
        assert AWS_GUARDDUTY_DETECTOR == "aws_guardduty_detector"
        assert AWS_GUARDDUTY_PUBLISHING_DESTINATION == "aws_guardduty_publishing_destination"
        assert AWS_SECURITYHUB_ACCOUNT == "aws_securityhub_account"
        assert AWS_SECURITYHUB_STANDARD_SUBSCRIPTION == "aws_securityhub_standard_subscription"
        assert AWS_SECURITYHUB_FINDING_AGGREGATOR == "aws_securityhub_finding_aggregator"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

def _fields_for(record_type: str) -> tuple:
    """Helper to call _tracked_fields_for with a record dict."""
    return _tracked_fields_for({"record_type": record_type})


class TestM45DiffService:
    def test_cloudtrail_trail_tracked_fields(self):
        fields = _fields_for(AWS_CLOUDTRAIL_TRAIL)
        assert fields is not None
        for f in (
            # "trail_name" intentionally absent — identity via hashed ARN record_id
            "home_region", "is_multi_region_trail",
            "include_global_service_events", "is_organization_trail",
            "log_file_validation_enabled", "kms_key_id_present", "kms_key_id_hash",
            "s3_bucket_name_hash", "sns_topic_name_present",
            "cloud_watch_logs_enabled", "has_custom_event_selectors",
            "is_logging", "latest_delivery_error_present",
            "latest_notification_error_present",
            "management_events_enabled", "read_write_type",
            "include_management_events", "data_resource_type_counts",
            "exclude_management_event_sources_count",
            "insight_selector_count", "insight_selector_types",
            "tag_keys", "config_fetch_warnings",
            # "sensitive_name_category" removed — connector does not output this field
        ):
            assert f in fields, f"cloudtrail_trail missing field: {f}"
        # Confirm dead fields were cleaned up
        assert "trail_name" not in fields
        assert "sensitive_name_category" not in fields

    def test_cloudtrail_event_data_store_tracked_fields(self):
        fields = _fields_for(AWS_CLOUDTRAIL_EVENT_DATA_STORE)
        assert fields is not None
        for f in (
            "name", "status", "termination_protection_enabled",
            "multi_region_enabled", "organization_enabled", "retention_period",
            "advanced_event_selector_count", "kms_key_id_present",
            "billing_mode", "tag_keys", "config_fetch_warnings",
        ):
            assert f in fields, f"cloudtrail_event_data_store missing field: {f}"

    def test_guardduty_detector_tracked_fields(self):
        fields = _fields_for(AWS_GUARDDUTY_DETECTOR)
        assert fields is not None
        for f in (
            "status", "finding_publishing_frequency",
            "s3_logs_enabled", "eks_audit_logs_enabled",
            "malware_protection_enabled", "rds_login_events_enabled",
            "lambda_network_logs_enabled", "runtime_monitoring_enabled",
            "ebs_malware_protection_enabled", "feature_count",
            "member_count", "active_member_count",
            "admin_account_present", "tag_keys", "config_fetch_warnings",
        ):
            assert f in fields, f"guardduty_detector missing field: {f}"

    def test_guardduty_publishing_destination_tracked_fields(self):
        fields = _fields_for(AWS_GUARDDUTY_PUBLISHING_DESTINATION)
        assert fields is not None
        for f in (
            "destination_type", "status",
            "kms_key_arn_present", "destination_arn_present",
            "config_fetch_warnings",
        ):
            assert f in fields, f"guardduty_publishing_destination missing field: {f}"

    def test_securityhub_account_tracked_fields(self):
        fields = _fields_for(AWS_SECURITYHUB_ACCOUNT)
        assert fields is not None
        for f in (
            "hub_enabled", "auto_enable_controls",
            "control_finding_generator", "enabled_standards_count",
            "enabled_products_count", "finding_aggregator_present",
            "tag_keys", "config_fetch_warnings",
        ):
            assert f in fields, f"securityhub_account missing field: {f}"

    def test_securityhub_standard_subscription_tracked_fields(self):
        fields = _fields_for(AWS_SECURITYHUB_STANDARD_SUBSCRIPTION)
        assert fields is not None
        for f in (
            "standards_status", "standards_status_reason",
            "standards_name_summary", "config_fetch_warnings",
        ):
            assert f in fields, f"securityhub_standard_subscription missing field: {f}"

    def test_securityhub_finding_aggregator_tracked_fields(self):
        fields = _fields_for(AWS_SECURITYHUB_FINDING_AGGREGATOR)
        assert fields is not None
        for f in (
            "linking_mode", "specified_regions_count",
            "specified_regions", "config_fetch_warnings",
        ):
            assert f in fields, f"securityhub_finding_aggregator missing field: {f}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Helper functions
# ─────────────────────────────────────────────────────────────────────────────

class TestM45Helpers:
    def test_summarize_event_selectors_basic(self):
        selectors = [
            {
                "ReadWriteType": "WriteOnly",
                "IncludeManagementEvents": True,
                "DataResources": [
                    {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]},
                ],
                "ExcludeManagementEventSources": [],
            }
        ]
        result = AWSConnector._summarize_cloudtrail_event_selectors(selectors)
        assert result["read_write_type"] == "WriteOnly"
        assert result["include_management_events"] is True
        assert result["data_resource_type_counts"] == {"AWS::S3::Object": 1}
        assert result["exclude_management_event_sources_count"] == 0

    def test_summarize_event_selectors_excludes_counted(self):
        selectors = [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": False,
                "DataResources": [],
                "ExcludeManagementEventSources": ["kms.amazonaws.com", "rdsdata.amazonaws.com"],
            }
        ]
        result = AWSConnector._summarize_cloudtrail_event_selectors(selectors)
        assert result["include_management_events"] is False
        assert result["exclude_management_event_sources_count"] == 2
        # SECURITY: source names NOT stored in data_resource_type_counts

    def test_summarize_event_selectors_empty(self):
        result = AWSConnector._summarize_cloudtrail_event_selectors([])
        assert result["read_write_type"] == "All"
        assert result["include_management_events"] is True
        assert result["data_resource_type_counts"] is None

    def test_summarize_advanced_event_selectors(self):
        adv = [
            {
                "Name": "Management events selector",
                "FieldSelectors": [
                    {"Field": "readWriteType", "Equals": ["ReadOnly"]},
                    {"Field": "eventCategory", "Equals": ["Management"]},
                ],
            }
        ]
        result = AWSConnector._summarize_cloudtrail_advanced_event_selectors(adv)
        assert result["read_write_type"] == "ReadOnly"
        assert result["include_management_events"] is True

    def test_summarize_insight_selectors(self):
        selectors = [
            {"InsightType": "ApiCallRateInsight"},
            {"InsightType": "ApiErrorRateInsight"},
        ]
        result = AWSConnector._summarize_cloudtrail_insight_selectors(selectors)
        assert result["insight_selector_count"] == 2
        assert set(result["insight_selector_types"]) == {
            "ApiCallRateInsight", "ApiErrorRateInsight"
        }

    def test_summarize_insight_selectors_empty(self):
        result = AWSConnector._summarize_cloudtrail_insight_selectors([])
        assert result["insight_selector_count"] == 0
        assert result["insight_selector_types"] is None

    def test_summarize_guardduty_features_all_known(self):
        features = [
            {"Name": "S3_LOGS", "Status": "ENABLED"},
            {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"},
            {"Name": "MALWARE_PROTECTION", "Status": "ENABLED"},
            {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"},
            {"Name": "LAMBDA_NETWORK_LOGS", "Status": "DISABLED"},
            {"Name": "RUNTIME_MONITORING", "Status": "ENABLED"},
            {"Name": "EBS_MALWARE_PROTECTION", "Status": "DISABLED"},
        ]
        result = AWSConnector._summarize_guardduty_features(features)
        assert result["s3_logs_enabled"] is True
        assert result["eks_audit_logs_enabled"] is False
        assert result["malware_protection_enabled"] is True
        assert result["rds_login_events_enabled"] is True
        assert result["lambda_network_logs_enabled"] is False
        assert result["runtime_monitoring_enabled"] is True
        assert result["ebs_malware_protection_enabled"] is False

    def test_summarize_guardduty_features_lowercase(self):
        features = [{"Name": "s3_logs", "Status": "enabled"}]
        result = AWSConnector._summarize_guardduty_features(features)
        assert result.get("s3_logs_enabled") is True

    def test_securityhub_standard_name_cis(self):
        arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
        assert AWSConnector._securityhub_standard_name_from_arn(arn) == "CIS"

    def test_securityhub_standard_name_fsbp(self):
        arn = (
            "arn:aws:securityhub:us-east-1::standards/"
            "aws-foundational-security-best-practices/v/1.0.0"
        )
        assert AWSConnector._securityhub_standard_name_from_arn(arn) == "FSBP"

    def test_securityhub_standard_name_nist(self):
        arn = "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"
        assert AWSConnector._securityhub_standard_name_from_arn(arn) == "NIST-800-53"

    def test_securityhub_standard_name_pci(self):
        arn = "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"
        assert AWSConnector._securityhub_standard_name_from_arn(arn) == "PCI-DSS"

    def test_securityhub_standard_name_unknown_fallback(self):
        arn = "arn:aws:securityhub:us-east-1::standards/custom-standard-xyz/v/1.0.0"
        name = AWSConnector._securityhub_standard_name_from_arn(arn)
        assert "custom-standard-xyz" in name or len(name) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification — aws_cloudtrail_trail
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudtrailTrailRiskClassification:
    """Full risk matrix for aws_cloudtrail_trail."""

    def test_is_logging_false_org_trail_critical(self):
        # is_organization_trail flag in provider_metadata triggers critical
        sev, _ = classify_aws_change(
            _ct_change(field_path="is_logging", new_value=False,
                       record_name="my-central-trail",
                       is_organization_trail=True)
        )
        assert sev == "critical"

    def test_is_logging_false_multi_region_trail_critical(self):
        # is_multi_region_trail flag in provider_metadata triggers critical
        sev, _ = classify_aws_change(
            _ct_change(field_path="is_logging", new_value=False,
                       record_name="my-central-trail",
                       is_multi_region_trail=True)
        )
        assert sev == "critical"

    def test_is_logging_false_regular_trail_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="is_logging", new_value=False,
                       record_name="my-trail")
        )
        assert sev == "high"

    def test_is_multi_region_false_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="is_multi_region_trail", new_value=False)
        )
        assert sev in ("high", "critical")

    def test_include_global_service_events_false_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="include_global_service_events", new_value=False)
        )
        assert sev in ("high", "critical")

    def test_log_file_validation_disabled_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="log_file_validation_enabled", new_value=False)
        )
        assert sev in ("high", "critical")

    def test_kms_key_removed_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="kms_key_id_present", new_value=False, prev_value=True)
        )
        assert sev in ("high", "critical")

    def test_kms_key_hash_changed_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="kms_key_id_hash", new_value="abc123",
                       prev_value="def456")
        )
        assert sev == "high"

    def test_s3_bucket_changed_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="s3_bucket_name_hash", new_value="abc123",
                       prev_value="def456")
        )
        assert sev == "high"

    def test_management_events_disabled_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="management_events_enabled", new_value=False)
        )
        assert sev in ("high", "critical")

    def test_read_write_type_downgrade_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="read_write_type", new_value="ReadOnly",
                       prev_value="All")
        )
        assert sev in ("high", "critical")

    def test_trail_removed_high(self):
        sev, _ = classify_aws_change(
            _ct_change(change_type="removed")
        )
        assert sev in ("high", "critical")

    def test_latest_delivery_error_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="latest_delivery_error_present", new_value=True)
        )
        assert sev in ("high", "medium")

    def test_insight_selectors_removed_high(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="insight_selector_count",
                       new_value=0, prev_value=2)
        )
        assert sev in ("high", "medium")

    def test_tag_keys_change_low(self):
        sev, _ = classify_aws_change(
            _ct_change(field_path="tag_keys", new_value=["env"], prev_value=["env", "app"])
        )
        assert sev == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk classification — aws_cloudtrail_event_data_store
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudtrailEventDataStoreRisk:
    def test_removed_high(self):
        sev, _ = classify_aws_change(
            _ct_change(record_type=AWS_CLOUDTRAIL_EVENT_DATA_STORE, change_type="removed")
        )
        assert sev == "high"

    def test_termination_protection_disabled_high(self):
        sev, _ = classify_aws_change(
            _ct_change(record_type=AWS_CLOUDTRAIL_EVENT_DATA_STORE,
                       field_path="termination_protection_enabled",
                       new_value=False, prev_value=True)
        )
        assert sev == "high"

    def test_retention_reduced_high(self):
        sev, _ = classify_aws_change(
            _ct_change(record_type=AWS_CLOUDTRAIL_EVENT_DATA_STORE,
                       field_path="retention_period",
                       new_value=30, prev_value=90)
        )
        assert sev == "high"

    def test_status_stopped_high(self):
        sev, _ = classify_aws_change(
            _ct_change(record_type=AWS_CLOUDTRAIL_EVENT_DATA_STORE,
                       field_path="status", new_value="STOPPED")
        )
        assert sev == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk classification — aws_guardduty_detector
# ─────────────────────────────────────────────────────────────────────────────

class TestGuarddutyDetectorRisk:
    def test_status_disabled_critical(self):
        sev, _ = classify_aws_change(
            _gd_change(field_path="status", new_value="DISABLED")
        )
        assert sev == "critical"

    def test_removed_critical(self):
        sev, _ = classify_aws_change(
            _gd_change(change_type="removed")
        )
        assert sev == "critical"

    def test_s3_logs_disabled_high(self):
        sev, _ = classify_aws_change(
            _gd_change(field_path="s3_logs_enabled", new_value=False, prev_value=True)
        )
        assert sev in ("high", "medium")

    def test_malware_protection_disabled_high(self):
        sev, _ = classify_aws_change(
            _gd_change(field_path="malware_protection_enabled",
                       new_value=False, prev_value=True)
        )
        assert sev in ("high", "medium")

    def test_publishing_frequency_slowed_high(self):
        sev, _ = classify_aws_change(
            _gd_change(field_path="finding_publishing_frequency",
                       new_value="SIX_HOURS", prev_value="FIFTEEN_MINUTES")
        )
        assert sev in ("high", "medium")

    def test_member_count_decreased_medium(self):
        sev, _ = classify_aws_change(
            _gd_change(field_path="member_count", new_value=0, prev_value=3)
        )
        assert sev in ("medium", "high")

    def test_eks_audit_logs_disabled_high(self):
        sev, _ = classify_aws_change(
            _gd_change(field_path="eks_audit_logs_enabled",
                       new_value=False, prev_value=True)
        )
        assert sev in ("high", "medium")


# ─────────────────────────────────────────────────────────────────────────────
# 8. Risk classification — aws_guardduty_publishing_destination
# ─────────────────────────────────────────────────────────────────────────────

class TestGuarddutyPublishingDestinationRisk:
    def test_removed_high(self):
        sev, _ = classify_aws_change(
            _gd_change(record_type=AWS_GUARDDUTY_PUBLISHING_DESTINATION,
                       change_type="removed")
        )
        assert sev == "high"

    def test_status_unable_to_export_high(self):
        sev, _ = classify_aws_change(
            _gd_change(record_type=AWS_GUARDDUTY_PUBLISHING_DESTINATION,
                       field_path="status", new_value="UNABLE_TO_EXPORT_FINDINGS")
        )
        assert sev == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Risk classification — aws_securityhub_account
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHubAccountRisk:
    def test_hub_disabled_high(self):
        sev, _ = classify_aws_change(
            _sh_change(field_path="hub_enabled", new_value=False)
        )
        assert sev in ("critical", "high")

    def test_hub_removed_high(self):
        sev, _ = classify_aws_change(
            _sh_change(change_type="removed")
        )
        assert sev in ("critical", "high")

    def test_enabled_standards_count_zero_high(self):
        sev, _ = classify_aws_change(
            _sh_change(field_path="enabled_standards_count", new_value=0, prev_value=3)
        )
        assert sev in ("critical", "high")

    def test_auto_enable_controls_disabled_high(self):
        sev, _ = classify_aws_change(
            _sh_change(field_path="auto_enable_controls", new_value=False)
        )
        assert sev in ("high", "medium")

    def test_finding_aggregator_removed_high(self):
        sev, _ = classify_aws_change(
            _sh_change(field_path="finding_aggregator_present",
                       new_value=False, prev_value=True)
        )
        assert sev in ("high", "medium")


# ─────────────────────────────────────────────────────────────────────────────
# 10. Risk classification — aws_securityhub_standard_subscription
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHubStandardSubscriptionRisk:
    def test_critical_standard_removed_critical(self):
        for critical_std in ("CIS", "FSBP", "NIST-800-53", "PCI-DSS"):
            sev, msg = classify_aws_change(
                _sh_change(
                    record_type=AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
                    change_type="removed",
                    record_name=f"securityhub-std-{critical_std}",
                )
            )
            assert sev in ("critical", "high"), f"{critical_std} removal gave {sev}"

    def test_generic_standard_removed_high(self):
        sev, _ = classify_aws_change(
            _sh_change(record_type=AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
                       change_type="removed",
                       record_name="securityhub-std-custom-standard")
        )
        assert sev in ("high", "critical")


# ─────────────────────────────────────────────────────────────────────────────
# 11. Risk classification — aws_securityhub_finding_aggregator
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHubFindingAggregatorRisk:
    def test_removed_high(self):
        sev, _ = classify_aws_change(
            _sh_change(record_type=AWS_SECURITYHUB_FINDING_AGGREGATOR,
                       change_type="removed")
        )
        assert sev == "high"

    def test_linking_mode_narrowed_high(self):
        sev, _ = classify_aws_change(
            _sh_change(record_type=AWS_SECURITYHUB_FINDING_AGGREGATOR,
                       field_path="linking_mode",
                       new_value="SPECIFIED_REGIONS", prev_value="ALL_REGIONS")
        )
        assert sev == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 12. Failure classification — classify_aws_cloudtrail_failure
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudtrailFailureClassification:
    def test_access_denied_403(self):
        fc = classify_aws_cloudtrail_failure(
            "DescribeTrails",
            ConnectorError("AccessDeniedException", status_code=403),
        )
        assert fc.error_code == "aws_cloudtrail_access_denied"
        assert fc.category == "authentication"

    def test_auth_error(self):
        fc = classify_aws_cloudtrail_failure(
            "DescribeTrails",
            AuthenticationError("InvalidToken"),
        )
        assert fc.error_code == "aws_cloudtrail_access_denied"

    def test_rate_limited(self):
        fc = classify_aws_cloudtrail_failure(
            "DescribeTrails",
            RateLimitError("Throttling"),
        )
        assert fc.error_code == "aws_cloudtrail_rate_limited"

    def test_network_error(self):
        fc = classify_aws_cloudtrail_failure(
            "DescribeTrails",
            NetworkError("Connection refused"),
        )
        assert fc.category == "network"

    def test_describe_trails_unavailable(self):
        fc = classify_aws_cloudtrail_failure(
            "DescribeTrails",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "cloudtrail" in fc.error_code

    def test_get_trail_status_unavailable(self):
        fc = classify_aws_cloudtrail_failure(
            "GetTrailStatus",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "cloudtrail" in fc.error_code

    def test_list_event_data_stores(self):
        fc = classify_aws_cloudtrail_failure(
            "ListEventDataStores",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "cloudtrail" in fc.error_code

    def test_no_log_events_in_recommended_action(self):
        """Log event access must be explicitly excluded from recommended actions."""
        for api in ("DescribeTrails", "GetTrailStatus", "GetEventSelectors"):
            fc = classify_aws_cloudtrail_failure(
                api,
                ConnectorError("AccessDeniedException", status_code=403),
            )
            action_lower = fc.recommended_action.lower()
            # Must mention what's NOT accessed
            assert "never" in action_lower or "not" in action_lower


# ─────────────────────────────────────────────────────────────────────────────
# 13. Failure classification — classify_aws_guardduty_failure
# ─────────────────────────────────────────────────────────────────────────────

class TestGuarddutyFailureClassification:
    def test_access_denied_403(self):
        fc = classify_aws_guardduty_failure(
            "ListDetectors",
            ConnectorError("AccessDeniedException", status_code=403),
        )
        assert fc.error_code == "aws_guardduty_access_denied"
        assert fc.category == "authentication"

    def test_rate_limited(self):
        fc = classify_aws_guardduty_failure(
            "GetDetector",
            RateLimitError("Throttling"),
        )
        assert fc.error_code == "aws_guardduty_rate_limited"

    def test_list_detectors_unavailable(self):
        fc = classify_aws_guardduty_failure(
            "ListDetectors",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "guardduty" in fc.error_code

    def test_get_detector_unavailable(self):
        fc = classify_aws_guardduty_failure(
            "GetDetector",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "guardduty" in fc.error_code

    def test_list_publishing_destinations(self):
        fc = classify_aws_guardduty_failure(
            "ListPublishingDestinations",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "guardduty" in fc.error_code

    def test_no_findings_in_recommended_action(self):
        fc = classify_aws_guardduty_failure(
            "ListDetectors",
            ConnectorError("AccessDeniedException", status_code=403),
        )
        action_lower = fc.recommended_action.lower()
        assert "finding" in action_lower
        assert "never" in action_lower or "not" in action_lower


# ─────────────────────────────────────────────────────────────────────────────
# 14. Failure classification — classify_aws_securityhub_failure
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHubFailureClassification:
    def test_access_denied_403(self):
        fc = classify_aws_securityhub_failure(
            "DescribeHub",
            ConnectorError("AccessDeniedException", status_code=403),
        )
        assert fc.error_code == "aws_securityhub_access_denied"
        assert fc.category == "authentication"

    def test_rate_limited(self):
        fc = classify_aws_securityhub_failure(
            "DescribeHub",
            RateLimitError("Throttling"),
        )
        assert fc.error_code == "aws_securityhub_rate_limited"

    def test_describe_hub_not_enabled(self):
        """400 from DescribeHub → hub_unavailable (not enabled in region)."""
        fc = classify_aws_securityhub_failure(
            "DescribeHub",
            ConnectorError("InvalidAccessException", status_code=400),
        )
        assert fc.error_code == "aws_securityhub_hub_unavailable"

    def test_get_enabled_standards(self):
        fc = classify_aws_securityhub_failure(
            "GetEnabledStandards",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "securityhub" in fc.error_code

    def test_list_finding_aggregators(self):
        fc = classify_aws_securityhub_failure(
            "ListFindingAggregators",
            ConnectorError("ServiceUnavailable", status_code=503),
        )
        assert "securityhub" in fc.error_code

    def test_no_findings_in_recommended_action(self):
        fc = classify_aws_securityhub_failure(
            "DescribeHub",
            ConnectorError("AccessDeniedException", status_code=403),
        )
        action_lower = fc.recommended_action.lower()
        assert "finding" in action_lower
        assert "never" in action_lower or "not" in action_lower


# ─────────────────────────────────────────────────────────────────────────────
# 15. Connector normalization — _fetch_cloudtrail_trail_detail
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudtrailTrailNormalization:
    """Verify _fetch_cloudtrail_trail_detail produces correct schema."""

    ACCOUNT_ID = "123456789012"
    TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail"

    def _make_trail_data(self, **overrides):
        base = {
            "TrailARN": self.TRAIL_ARN,
            "Name": "my-trail",
            "IsMultiRegionTrail": True,
            "IsOrganizationTrail": False,
            "IncludeGlobalServiceEvents": True,
            "LogFileValidationEnabled": True,
            "S3BucketName": "my-log-bucket",
            "SNSTopicARN": "",
            "KMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:...",
            "HomeRegion": "us-east-1",
        }
        base.update(overrides)
        return base

    def _make_call_aws(self, home_client):
        """Build a _call_aws function using identity comparison (M44 pattern)."""
        def _call_aws(fn, **kwargs):
            if fn is home_client.get_trail_status:
                return {
                    "IsLogging": True,
                    "LatestDeliveryError": None,
                    "LatestNotificationError": None,
                }
            if fn is home_client.get_event_selectors:
                return {
                    "EventSelectors": [
                        {
                            "ReadWriteType": "All",
                            "IncludeManagementEvents": True,
                            "DataResources": [],
                            "ExcludeManagementEventSources": [],
                        }
                    ]
                }
            if fn is home_client.get_insight_selectors:
                return {"InsightSelectors": []}
            if fn is home_client.list_tags:
                return {"ResourceTagList": [{"TagsList": []}]}
            return {}
        return _call_aws

    def test_basic_trail_record_shape(self):
        conn = _make_connector()
        home_client = MagicMock()

        conn._call_aws = self._make_call_aws(home_client)
        conn._make_client = MagicMock(return_value=home_client)

        record = conn._fetch_cloudtrail_trail_detail(
            _creds(), self._make_trail_data(), self.ACCOUNT_ID, "us-east-1"
        )

        assert record["record_type"] == AWS_CLOUDTRAIL_TRAIL
        assert record["name"] == "my-trail"
        assert record["is_multi_region_trail"] is True
        assert record["is_organization_trail"] is False
        assert record["log_file_validation_enabled"] is True
        assert record["kms_key_id_present"] is True
        assert record["kms_key_id_hash"] is not None
        assert len(record["kms_key_id_hash"]) == 12
        assert record["s3_bucket_name_hash"] is not None
        assert record["cloud_watch_logs_enabled"] is True
        assert record["is_logging"] is True
        assert record["latest_delivery_error_present"] is False

    def test_kms_key_not_stored_raw(self):
        """Raw KMS key ARN must never appear in the record."""
        import json
        conn = _make_connector()
        raw_arn = "arn:aws:kms:us-east-1:123456789012:key/my-secret-key-id"
        trail_data = self._make_trail_data(KMSKeyId=raw_arn, S3BucketName="bucket")

        conn._call_aws = MagicMock(side_effect=Exception("fail"))
        conn._make_client = MagicMock(return_value=MagicMock())

        record = conn._fetch_cloudtrail_trail_detail(
            _creds(), trail_data, self.ACCOUNT_ID, "us-east-1"
        )
        serialized = json.dumps(record)
        assert raw_arn not in serialized
        assert "my-secret-key-id" not in serialized

    def test_trail_arn_not_stored_raw(self):
        """Raw trail ARN must never appear verbatim in the record."""
        import json
        conn = _make_connector()
        trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/sensitive-trail"
        trail_data = self._make_trail_data(TrailARN=trail_arn, Name="sensitive-trail",
                                           KMSKeyId="", S3BucketName="")
        conn._call_aws = MagicMock(side_effect=Exception("fail"))
        conn._make_client = MagicMock(return_value=MagicMock())

        record = conn._fetch_cloudtrail_trail_detail(
            _creds(), trail_data, self.ACCOUNT_ID, "us-east-1"
        )
        serialized = json.dumps(record)
        assert trail_arn not in serialized

    def test_fail_soft_on_all_optional_calls(self):
        """All per-trail optional API calls should fail-soft."""
        conn = _make_connector()
        trail_data = self._make_trail_data(KMSKeyId="", S3BucketName="")
        conn._call_aws = MagicMock(
            side_effect=ConnectorError("ServiceUnavailable", status_code=503)
        )
        conn._make_client = MagicMock(return_value=MagicMock())

        record = conn._fetch_cloudtrail_trail_detail(
            _creds(), trail_data, self.ACCOUNT_ID, "us-east-1"
        )
        assert record["record_type"] == AWS_CLOUDTRAIL_TRAIL
        assert record["config_fetch_warnings"] is not None
        assert len(record["config_fetch_warnings"]) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 16. Connector normalization — _fetch_cloudtrail_event_data_stores_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudtrailEventDataStoreNormalization:
    def test_basic_eds_record_shape(self):
        conn = _make_connector()
        mc = MagicMock()
        eds_arn = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/abc123"

        def _call_aws(fn, **kwargs):
            if fn is mc.list_event_data_stores:
                return {
                    "EventDataStores": [
                        {
                            "EventDataStoreArn": eds_arn,
                            "Name": "my-eds",
                            "Status": "ENABLED",
                            "TerminationProtectionEnabled": True,
                            "MultiRegionEnabled": False,
                            "OrganizationEnabled": False,
                            "RetentionPeriod": 90,
                            "BillingMode": "EXTENDABLE_RETENTION_PRICING",
                            "KmsKeyId": "",
                            "AdvancedEventSelectors": [],
                        }
                    ],
                }
            if fn is mc.get_event_data_store:
                return {"Tags": []}
            return {}

        conn._call_aws = _call_aws

        records = conn._fetch_cloudtrail_event_data_stores_in_region(
            mc, "123456789012", "us-east-1"
        )
        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == AWS_CLOUDTRAIL_EVENT_DATA_STORE
        assert r["name"] == "my-eds"
        assert r["status"] == "ENABLED"
        assert r["termination_protection_enabled"] is True
        assert r["retention_period"] == 90
        assert r["kms_key_id_present"] is False

    def test_list_event_data_stores_fail_soft(self):
        conn = _make_connector()
        conn._call_aws = MagicMock(
            side_effect=ConnectorError("AccessDenied", status_code=403)
        )
        mc = MagicMock()
        records = conn._fetch_cloudtrail_event_data_stores_in_region(
            mc, "123456789012", "us-east-1"
        )
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 17. Connector normalization — _fetch_guardduty_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestGuarddutyInRegionNormalization:
    def test_basic_detector_record_shape(self):
        conn = _make_connector()
        mc = MagicMock()
        detector_id = "abc123def456abc123def456abc123de"

        def _call_aws(fn, **kwargs):
            if fn is mc.list_detectors:
                return {"DetectorIds": [detector_id]}
            if fn is mc.get_detector:
                return {
                    "Status": "ENABLED",
                    "FindingPublishingFrequency": "FIFTEEN_MINUTES",
                    "Features": [
                        {"Name": "S3_LOGS", "Status": "ENABLED"},
                        {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"},
                    ],
                }
            if fn is mc.list_members:
                return {
                    "Members": [
                        {"RelationshipStatus": "Enabled"},
                        {"RelationshipStatus": "Resigned"},
                    ]
                }
            if fn is mc.get_administrator_account:
                return {"Administrator": {"AccountId": "111111111111"}}
            if fn is mc.list_publishing_destinations:
                return {"Destinations": []}
            if fn is mc.list_tags_for_resource:
                return {"Tags": {"env": "prod"}}
            return {}

        conn._call_aws = _call_aws

        records = conn._fetch_guardduty_in_region(mc, "123456789012", "us-east-1")

        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == AWS_GUARDDUTY_DETECTOR
        assert r["status"] == "ENABLED"
        assert r["finding_publishing_frequency"] == "FIFTEEN_MINUTES"
        assert r["s3_logs_enabled"] is True
        assert r["eks_audit_logs_enabled"] is False
        assert r["feature_count"] == 2
        assert r["member_count"] == 2
        assert r["active_member_count"] == 1
        assert r["admin_account_present"] is True
        assert r["tag_keys"] == ["env"]

    def test_get_findings_never_called(self):
        """Verify GetFindings is never called during guardduty fetch."""
        conn = _make_connector()
        mc = MagicMock()
        called_fns: list = []

        def _call_aws(fn, **kwargs):
            called_fns.append(fn)
            if fn is mc.list_detectors:
                return {"DetectorIds": ["det123"]}
            return {}

        conn._call_aws = _call_aws
        conn._fetch_guardduty_in_region(mc, "123456789012", "us-east-1")

        # Verify mc.get_findings was never called
        assert mc.get_findings not in called_fns

    def test_list_detectors_fail_soft(self):
        conn = _make_connector()
        conn._call_aws = MagicMock(
            side_effect=ConnectorError("AccessDenied", status_code=403)
        )
        mc = MagicMock()
        records = conn._fetch_guardduty_in_region(mc, "123456789012", "us-east-1")
        assert records == []

    def test_publishing_destinations_included(self):
        conn = _make_connector()
        mc = MagicMock()
        detector_id = "det456"
        dest_id = "dest789"

        def _call_aws(fn, **kwargs):
            if fn is mc.list_detectors:
                return {"DetectorIds": [detector_id]}
            if fn is mc.get_detector:
                return {"Status": "ENABLED", "FindingPublishingFrequency": "SIX_HOURS"}
            if fn is mc.list_publishing_destinations:
                return {
                    "Destinations": [
                        {
                            "DestinationId": dest_id,
                            "DestinationType": "S3",
                            "Status": "PUBLISHING",
                        }
                    ]
                }
            if fn is mc.describe_publishing_destination:
                return {
                    "DestinationProperties": {
                        "KmsKeyArn": "arn:aws:kms:...",
                        "DestinationArn": "arn:aws:s3:::...",
                    }
                }
            if fn is mc.list_members:
                return {"Members": []}
            if fn is mc.get_administrator_account:
                return {"Administrator": {}}
            if fn is mc.list_tags_for_resource:
                return {"Tags": {}}
            return {}

        conn._call_aws = _call_aws
        records = conn._fetch_guardduty_in_region(mc, "123456789012", "us-east-1")

        dest_records = [r for r in records if r["record_type"] == AWS_GUARDDUTY_PUBLISHING_DESTINATION]
        assert len(dest_records) == 1
        d = dest_records[0]
        assert d["destination_type"] == "S3"
        assert d["status"] == "PUBLISHING"
        assert d["kms_key_arn_present"] is True
        assert d["destination_arn_present"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 18. Connector normalization — _fetch_securityhub_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHubInRegionNormalization:
    def test_hub_enabled_record_shape(self):
        conn = _make_connector()
        mc = MagicMock()

        def _call_aws(fn, **kwargs):
            if fn is mc.describe_hub:
                return {
                    "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
                    "AutoEnableControls": True,
                    "ControlFindingGenerator": "SECURITY_CONTROL",
                }
            if fn is mc.get_enabled_standards:
                return {
                    "StandardsSubscriptions": [
                        {
                            "StandardsSubscriptionArn": (
                                "arn:aws:securityhub:us-east-1:123456789012:"
                                "subscription/aws-foundational-security-best-practices/v/1.0.0"
                            ),
                            "StandardsArn": (
                                "arn:aws:securityhub:us-east-1::standards/"
                                "aws-foundational-security-best-practices/v/1.0.0"
                            ),
                            "StandardsStatus": "READY",
                        }
                    ]
                }
            if fn is mc.list_enabled_products_for_import:
                return {"ProductSubscriptions": ["arn:prod1", "arn:prod2"]}
            if fn is mc.list_finding_aggregators:
                return {"FindingAggregators": []}
            if fn is mc.list_tags_for_resource:
                return {"Tags": {"team": "security"}}
            return {}

        conn._call_aws = _call_aws

        records = conn._fetch_securityhub_in_region(mc, "123456789012", "us-east-1")

        hub_records = [r for r in records if r["record_type"] == AWS_SECURITYHUB_ACCOUNT]
        assert len(hub_records) == 1
        h = hub_records[0]
        assert h["hub_enabled"] is True
        assert h["auto_enable_controls"] is True
        assert h["control_finding_generator"] == "SECURITY_CONTROL"
        assert h["enabled_standards_count"] == 1
        assert h["enabled_products_count"] == 2
        assert h["finding_aggregator_present"] is False
        assert h["tag_keys"] == ["team"]

        std_records = [r for r in records if r["record_type"] == AWS_SECURITYHUB_STANDARD_SUBSCRIPTION]
        assert len(std_records) == 1
        assert std_records[0]["standards_status"] == "READY"
        assert std_records[0]["standards_name_summary"] == "FSBP"

    def test_hub_not_enabled_returns_disabled_record(self):
        conn = _make_connector()
        conn._call_aws = MagicMock(
            side_effect=ConnectorError("InvalidAccessException", status_code=400)
        )
        mc = MagicMock()
        records = conn._fetch_securityhub_in_region(mc, "123456789012", "us-east-1")

        assert len(records) == 1
        assert records[0]["record_type"] == AWS_SECURITYHUB_ACCOUNT
        assert records[0]["hub_enabled"] is False

    def test_get_findings_never_called(self):
        conn = _make_connector()
        mc = MagicMock()
        called_fns: list = []

        def _call_aws(fn, **kwargs):
            called_fns.append(fn)
            if fn is mc.describe_hub:
                return {"AutoEnableControls": False, "ControlFindingGenerator": "STANDARD_CONTROL"}
            if fn is mc.get_enabled_standards:
                return {"StandardsSubscriptions": []}
            if fn is mc.list_enabled_products_for_import:
                return {"ProductSubscriptions": []}
            if fn is mc.list_finding_aggregators:
                return {"FindingAggregators": []}
            if fn is mc.list_tags_for_resource:
                return {"Tags": {}}
            return {}

        conn._call_aws = _call_aws
        conn._fetch_securityhub_in_region(mc, "123456789012", "us-east-1")

        # Verify mc.get_findings was never called
        assert mc.get_findings not in called_fns

    def test_finding_aggregator_record_shape(self):
        conn = _make_connector()
        mc = MagicMock()
        agg_arn = "arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/abc"

        def _call_aws(fn, **kwargs):
            if fn is mc.describe_hub:
                return {"AutoEnableControls": True, "ControlFindingGenerator": "STANDARD_CONTROL"}
            if fn is mc.get_enabled_standards:
                return {"StandardsSubscriptions": []}
            if fn is mc.list_enabled_products_for_import:
                return {"ProductSubscriptions": []}
            if fn is mc.list_finding_aggregators:
                return {"FindingAggregators": [{"FindingAggregatorArn": agg_arn}]}
            if fn is mc.get_finding_aggregator:
                return {
                    "RegionLinkingMode": "ALL_REGIONS",
                    "Regions": ["us-east-1", "eu-west-1"],
                }
            if fn is mc.list_tags_for_resource:
                return {"Tags": {}}
            return {}

        conn._call_aws = _call_aws
        records = conn._fetch_securityhub_in_region(mc, "123456789012", "us-east-1")

        agg_records = [r for r in records if r["record_type"] == AWS_SECURITYHUB_FINDING_AGGREGATOR]
        assert len(agg_records) == 1
        a = agg_records[0]
        assert a["linking_mode"] == "ALL_REGIONS"
        assert a["specified_regions_count"] == 2
        assert "us-east-1" in a["specified_regions"]


# ─────────────────────────────────────────────────────────────────────────────
# 19. Service inventory — M45 surfaces
# ─────────────────────────────────────────────────────────────────────────────

class TestM45ServiceInventory:
    def _make_inv(self, **kwargs):
        conn = _make_connector()

        def mock_selected_regions(creds):
            return ["us-east-1"]

        conn._selected_regions = mock_selected_regions
        return conn._fetch_service_inventory(
            _creds(),
            **kwargs,
        )

    def test_cloudtrail_in_enabled_surfaces(self):
        inv = self._make_inv()
        assert "cloudtrail" in inv["enabled_surfaces"]

    def test_guardduty_in_enabled_surfaces(self):
        inv = self._make_inv()
        assert "guardduty" in inv["enabled_surfaces"]

    def test_securityhub_in_enabled_surfaces(self):
        inv = self._make_inv()
        assert "security_hub" in inv["enabled_surfaces"]

    def test_cloudtrail_not_in_future_surfaces(self):
        inv = self._make_inv()
        assert "cloudtrail" not in inv.get("future_surfaces", [])

    def test_guardduty_not_in_future_surfaces(self):
        inv = self._make_inv()
        assert "guardduty" not in inv.get("future_surfaces", [])

    def test_securityhub_not_in_future_surfaces(self):
        inv = self._make_inv()
        assert "security_hub" not in inv.get("future_surfaces", [])

    def test_cloudtrail_trail_count_stored(self):
        inv = self._make_inv(cloudtrail_trail_count=3)
        assert inv.get("cloudtrail_trail_count") == 3

    def test_guardduty_detector_count_stored(self):
        inv = self._make_inv(guardduty_detector_count=2)
        assert inv.get("guardduty_detector_count") == 2

    def test_securityhub_hub_count_stored(self):
        inv = self._make_inv(securityhub_hub_count=1)
        assert inv.get("securityhub_hub_count") == 1


# ─────────────────────────────────────────────────────────────────────────────
# 20. Fail-soft — per-region errors
# ─────────────────────────────────────────────────────────────────────────────

class TestM45FailSoft:
    def test_cloudtrail_describe_fails_still_fetches_eds(self):
        """If DescribeTrails fails, event data stores still attempted."""
        conn = _make_connector()

        def mock_selected_regions(creds):
            return ["us-east-1"]

        conn._selected_regions = mock_selected_regions

        def mock_make_client(service, creds, region=None):
            mc = MagicMock()
            mc.describe_trails = MagicMock(side_effect=Exception("Boom"))
            mc.list_event_data_stores = MagicMock()
            return mc

        conn._make_client = mock_make_client

        def mock_call_aws(fn, **kwargs):
            fn_name = getattr(fn, "__name__", str(fn))
            if "describe_trails" in fn_name:
                raise ConnectorError("AccessDenied", status_code=403)
            if "list_event_data_stores" in fn_name:
                return {"EventDataStores": []}
            return {}

        conn._call_aws = mock_call_aws
        # Should not raise
        records = conn._fetch_cloudtrail_resources(_creds(), "123456789012")
        assert isinstance(records, list)

    def test_guardduty_region_failure_does_not_abort(self):
        """A region failure for GuardDuty should be swallowed, not raised."""
        conn = _make_connector()

        def mock_selected_regions(creds):
            return ["us-east-1", "eu-west-1"]

        conn._selected_regions = mock_selected_regions

        call_count = {"n": 0}

        def mock_make_client(service, creds, region=None):
            call_count["n"] += 1
            if region == "us-east-1":
                raise Exception("Network error")
            mc = MagicMock()
            return mc

        conn._make_client = mock_make_client
        conn._fetch_guardduty_in_region = MagicMock(return_value=[])

        records = conn._fetch_guardduty_resources(_creds(regions=["us-east-1", "eu-west-1"]), "123456789012")
        assert isinstance(records, list)

    def test_securityhub_region_failure_does_not_abort(self):
        conn = _make_connector()

        def mock_selected_regions(creds):
            return ["us-east-1", "ap-southeast-1"]

        conn._selected_regions = mock_selected_regions

        def mock_make_client(service, creds, region=None):
            if region == "us-east-1":
                raise Exception("Connection timeout")
            mc = MagicMock()
            return mc

        conn._make_client = mock_make_client
        conn._fetch_securityhub_in_region = MagicMock(return_value=[])

        records = conn._fetch_securityhub_resources(
            _creds(regions=["us-east-1", "ap-southeast-1"]), "123456789012"
        )
        assert isinstance(records, list)


# ─────────────────────────────────────────────────────────────────────────────
# 21. M44 regression guard
# ─────────────────────────────────────────────────────────────────────────────

class TestM44Regression:
    def test_wafv2_web_acl_still_dispatches(self):
        sev, _ = classify_aws_change({
            "record_type": AWS_WAFV2_WEB_ACL,
            "change_type": "removed",
            "field_path": None,
            "new_value": None,
            "prev_value": None,
            "provider_metadata": {
                "record_type": AWS_WAFV2_WEB_ACL,
                "record_name": "prod-waf",
            },
        })
        assert sev in ("critical", "high", "medium", "low")

    def test_m44_types_still_in_record_types(self):
        from app.connectors.aws_schema import (
            AWS_ELBV2_LOAD_BALANCER,
            AWS_ELBV2_TARGET_GROUP,
            AWS_ELBV2_LISTENER,
            AWS_ELBV2_LISTENER_RULE,
            AWS_ELB_CLASSIC_LOAD_BALANCER,
            AWS_WAFV2_WEB_ACL,
            AWS_WAFV2_WEB_ACL_ASSOCIATION,
        )
        for rt in (
            AWS_ELBV2_LOAD_BALANCER,
            AWS_ELBV2_TARGET_GROUP,
            AWS_ELBV2_LISTENER,
            AWS_ELBV2_LISTENER_RULE,
            AWS_ELB_CLASSIC_LOAD_BALANCER,
            AWS_WAFV2_WEB_ACL,
            AWS_WAFV2_WEB_ACL_ASSOCIATION,
        ):
            assert rt in AWS_RECORD_TYPES
