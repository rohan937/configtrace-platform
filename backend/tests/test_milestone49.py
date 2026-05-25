"""Milestone 49 tests — AWS CloudWatch Alarms + Observability Config.

Covers:
  1. Security hard rules  — forbidden API names NEVER appear in non-comment code.
  2. Schema registration  — all 8 M49 types in AWS_RECORD_TYPES.
  3. Diff service         — _tracked_fields_for returns non-empty tuples for all 8 types.
  4. Helper functions     — _summarize_alarm_action_types, _summarize_metric_dimensions,
                            _hash_dashboard_body, _count_dashboard_widgets,
                            _hash_filter_pattern, _summarize_subscription_destination_type,
                            _classify_observability_name_sensitivity.
  5. Risk classification  — classify_aws_change dispatch + field-level logic for all 8 types.
  6. Failure classifiers  — classify_aws_cloudwatch_failure, classify_aws_cloudwatch_logs_failure.
  7. Connector normalization — _fetch_cloudwatch_in_region, _fetch_cloudwatch_logs_in_region.
  8. Service inventory    — cloudwatch + cloudwatch_logs in enabled_surfaces.
  9. M48 regression       — classify_aws_change still handles all M48 types.
  10. Fail-soft           — region failures don't abort entire fetch.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# 1. Security hard rules
# ─────────────────────────────────────────────────────────────────────────────

_CONNECTOR_PATH = os.path.join(
    os.path.dirname(__file__), "..", "app", "connectors", "aws.py"
)

_FORBIDDEN_BOTO3_PATTERNS = [
    # CloudWatch metric data — NEVER read
    r"\.get_metric_data\b",
    r"\.get_metric_statistics\b",
    # CloudWatch Logs — log event access NEVER allowed
    r"\.get_log_events\b",
    r"\.filter_log_events\b",
    r"\.start_query\b",
    r"\.get_query_results\b",
    # X-Ray traces — never
    r"\.get_trace_summaries\b",
    r"\.batch_get_traces\b",
    # Metric datapoints
    r"\.list_metrics\b",
]


def _non_comment_lines(path: str) -> list[str]:
    with open(path) as f:
        return [
            line for line in f
            if not line.lstrip().startswith("#")
        ]


class TestSecurityHardRules:
    """Verify forbidden API calls never appear in connector non-comment code."""

    @pytest.mark.parametrize("pattern", _FORBIDDEN_BOTO3_PATTERNS)
    def test_forbidden_pattern_absent(self, pattern: str) -> None:
        lines = _non_comment_lines(_CONNECTOR_PATH)
        matches = [l.rstrip() for l in lines if re.search(pattern, l)]
        assert not matches, (
            f"Forbidden pattern '{pattern}' found in aws.py:\n"
            + "\n".join(matches)
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

from app.connectors.aws_schema import (
    AWS_RECORD_TYPES,
    AWS_CLOUDWATCH_METRIC_ALARM,
    AWS_CLOUDWATCH_COMPOSITE_ALARM,
    AWS_CLOUDWATCH_DASHBOARD,
    AWS_CLOUDWATCH_LOG_GROUP,
    AWS_CLOUDWATCH_METRIC_FILTER,
    AWS_CLOUDWATCH_SUBSCRIPTION_FILTER,
    AWS_CLOUDWATCH_METRIC_STREAM,
    AWS_CLOUDWATCH_ANOMALY_DETECTOR,
)

_M49_TYPES = [
    AWS_CLOUDWATCH_METRIC_ALARM,
    AWS_CLOUDWATCH_COMPOSITE_ALARM,
    AWS_CLOUDWATCH_DASHBOARD,
    AWS_CLOUDWATCH_LOG_GROUP,
    AWS_CLOUDWATCH_METRIC_FILTER,
    AWS_CLOUDWATCH_SUBSCRIPTION_FILTER,
    AWS_CLOUDWATCH_METRIC_STREAM,
    AWS_CLOUDWATCH_ANOMALY_DETECTOR,
]


class TestSchemaRegistration:
    @pytest.mark.parametrize("rt", _M49_TYPES)
    def test_type_in_aws_record_types(self, rt: str) -> None:
        assert rt in AWS_RECORD_TYPES, f"{rt} not in AWS_RECORD_TYPES"

    def test_constant_values(self) -> None:
        assert AWS_CLOUDWATCH_METRIC_ALARM == "aws_cloudwatch_metric_alarm"
        assert AWS_CLOUDWATCH_COMPOSITE_ALARM == "aws_cloudwatch_composite_alarm"
        assert AWS_CLOUDWATCH_DASHBOARD == "aws_cloudwatch_dashboard"
        assert AWS_CLOUDWATCH_LOG_GROUP == "aws_cloudwatch_log_group"
        assert AWS_CLOUDWATCH_METRIC_FILTER == "aws_cloudwatch_metric_filter"
        assert AWS_CLOUDWATCH_SUBSCRIPTION_FILTER == "aws_cloudwatch_subscription_filter"
        assert AWS_CLOUDWATCH_METRIC_STREAM == "aws_cloudwatch_metric_stream"
        assert AWS_CLOUDWATCH_ANOMALY_DETECTOR == "aws_cloudwatch_anomaly_detector"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

from app.services.diff_service import _tracked_fields_for


class TestDiffServiceTrackedFields:
    @pytest.mark.parametrize("rt", _M49_TYPES)
    def test_tracked_fields_non_empty(self, rt: str) -> None:
        fields = _tracked_fields_for({"record_type": rt})
        assert isinstance(fields, tuple)
        assert len(fields) > 0, f"_tracked_fields_for returned empty for {rt}"

    def test_metric_alarm_key_fields_present(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_METRIC_ALARM})
        for f in ("actions_enabled", "threshold", "alarm_state_value", "treat_missing_data",
                  "period", "alarm_action_count", "ok_action_count", "insufficient_data_action_count"):
            assert f in fields, f"{f} missing from metric_alarm tracked fields"

    def test_log_group_key_fields_present(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_LOG_GROUP})
        for f in ("retention_in_days", "retention_configured", "kms_key_id_present"):
            assert f in fields, f"{f} missing from log_group tracked fields"

    def test_metric_filter_key_fields_present(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_METRIC_FILTER})
        assert "filter_pattern_hash" in fields
        assert "metric_name" in fields

    def test_subscription_filter_key_fields_present(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_SUBSCRIPTION_FILTER})
        assert "destination_type" in fields
        assert "destination_arn_hash" in fields
        assert "role_arn_present" in fields
        assert "role_arn_hash" in fields
        assert "filter_pattern_present" in fields

    def test_dashboard_no_raw_body(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_DASHBOARD})
        # Raw body must never be tracked
        assert "dashboard_body" not in fields
        # Hash must be tracked
        assert "dashboard_body_hash" in fields

    def test_metric_stream_key_fields(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_METRIC_STREAM})
        assert "state" in fields
        assert "firehose_arn_hash" in fields
        assert "role_arn_hash" in fields

    def test_anomaly_detector_key_fields(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_ANOMALY_DETECTOR})
        assert "namespace" in fields
        assert "metric_name" in fields
        assert "state" in fields

    def test_composite_alarm_key_fields(self) -> None:
        fields = _tracked_fields_for({"record_type": AWS_CLOUDWATCH_COMPOSITE_ALARM})
        assert "alarm_rule_hash" in fields
        assert "alarm_rule_present" in fields
        assert "actions_enabled" in fields
        assert "alarm_action_count" in fields
        assert "alarm_state_reason_absent" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 4. Helper functions
# ─────────────────────────────────────────────────────────────────────────────

from app.connectors.aws import AWSConnector


def _build_connector() -> AWSConnector:
    conn = AWSConnector.__new__(AWSConnector)
    conn.account_id = "123456789012"
    # Bypass botocore import check in _call_aws
    conn._call_aws = lambda fn, *a, **kw: fn(*a, **kw)
    return conn


class TestHelpers:
    def test_summarize_alarm_action_types_empty(self) -> None:
        conn = _build_connector()
        result = conn._summarize_alarm_action_types([])
        assert result == {}

    def test_summarize_alarm_action_types_sns(self) -> None:
        conn = _build_connector()
        arns = [
            "arn:aws:sns:us-east-1:123456789012:my-topic",
            "arn:aws:sns:us-east-1:123456789012:another-topic",
        ]
        result = conn._summarize_alarm_action_types(arns)
        assert result.get("sns") == 2

    def test_summarize_alarm_action_types_mixed(self) -> None:
        conn = _build_connector()
        arns = [
            "arn:aws:sns:us-east-1:123:topic",
            "arn:aws:lambda:us-east-1:123:function:fn",
            "arn:aws:ssm:us-east-1:123:opsitem",
            "arn:aws:custom:us-east-1:123:thing",
        ]
        result = conn._summarize_alarm_action_types(arns)
        assert result.get("sns") == 1
        assert result.get("lambda") == 1
        assert result.get("ssm") == 1
        assert result.get("other") == 1

    def test_raw_arns_not_in_result(self) -> None:
        """Action type summarization must never return raw ARN strings."""
        conn = _build_connector()
        arn = "arn:aws:sns:us-east-1:123456789012:my-topic"
        result = conn._summarize_alarm_action_types([arn])
        # Keys are service types only
        for k in result:
            assert "arn:" not in k

    def test_summarize_metric_dimensions_keys_only(self) -> None:
        conn = _build_connector()
        dims = [
            {"Name": "InstanceId", "Value": "i-12345678"},
            {"Name": "AutoScalingGroupName", "Value": "my-asg"},
        ]
        result = conn._summarize_metric_dimensions(dims)
        assert "InstanceId" in result
        assert "AutoScalingGroupName" in result
        # Values must never be present
        assert "i-12345678" not in str(result)
        assert "my-asg" not in str(result)

    def test_summarize_metric_dimensions_empty(self) -> None:
        conn = _build_connector()
        assert conn._summarize_metric_dimensions([]) == []

    def test_hash_dashboard_body_deterministic(self) -> None:
        conn = _build_connector()
        body = json.dumps({"widgets": [{"type": "metric"}]})
        h1 = conn._hash_dashboard_body(body)
        h2 = conn._hash_dashboard_body(body)
        assert h1 == h2
        assert len(h1) == 12

    def test_hash_dashboard_body_different_inputs(self) -> None:
        conn = _build_connector()
        h1 = conn._hash_dashboard_body('{"widgets": []}')
        h2 = conn._hash_dashboard_body('{"widgets": [{"type":"metric"}]}')
        assert h1 != h2

    def test_hash_dashboard_body_raw_not_stored(self) -> None:
        """Hash output must never equal or contain the raw body."""
        conn = _build_connector()
        body = "sensitive dashboard content"
        result = conn._hash_dashboard_body(body)
        assert result != body
        assert "sensitive" not in result

    def test_count_dashboard_widgets_counts(self) -> None:
        conn = _build_connector()
        body = json.dumps({
            "widgets": [
                {"type": "metric"},
                {"type": "metric"},
                {"type": "text"},
                {"type": "alarm"},
            ]
        })
        count, types = conn._count_dashboard_widgets(body)
        assert count == 4
        assert types.get("metric") == 2
        assert types.get("text") == 1
        assert types.get("alarm") == 1

    def test_count_dashboard_widgets_invalid_body(self) -> None:
        conn = _build_connector()
        count, types = conn._count_dashboard_widgets("not-json")
        assert count == 0
        assert types == {}

    def test_hash_filter_pattern_deterministic(self) -> None:
        conn = _build_connector()
        pattern = '[ERROR]'
        h1 = conn._hash_filter_pattern(pattern)
        h2 = conn._hash_filter_pattern(pattern)
        assert h1 == h2
        assert len(h1) == 12

    def test_hash_filter_pattern_raw_not_stored(self) -> None:
        conn = _build_connector()
        pattern = "[ERROR] customer_id"
        result = conn._hash_filter_pattern(pattern)
        assert result != pattern
        assert "customer_id" not in result

    def test_hash_filter_pattern_different_patterns(self) -> None:
        conn = _build_connector()
        h1 = conn._hash_filter_pattern("[ERROR]")
        h2 = conn._hash_filter_pattern("[WARNING]")
        assert h1 != h2

    def test_summarize_subscription_destination_type_lambda(self) -> None:
        conn = _build_connector()
        arn = "arn:aws:lambda:us-east-1:123:function:my-fn"
        assert conn._summarize_subscription_destination_type(arn) == "lambda"

    def test_summarize_subscription_destination_type_kinesis(self) -> None:
        conn = _build_connector()
        arn = "arn:aws:kinesis:us-east-1:123:stream/my-stream"
        assert conn._summarize_subscription_destination_type(arn) == "kinesis"

    def test_summarize_subscription_destination_type_firehose(self) -> None:
        conn = _build_connector()
        arn = "arn:aws:firehose:us-east-1:123:deliverystream/my-ds"
        assert conn._summarize_subscription_destination_type(arn) == "firehose"

    def test_summarize_subscription_destination_type_opensearch(self) -> None:
        conn = _build_connector()
        arn = "arn:aws:es:us-east-1:123:domain/my-es"
        assert conn._summarize_subscription_destination_type(arn) == "opensearch"

    def test_summarize_subscription_destination_type_other(self) -> None:
        conn = _build_connector()
        arn = "arn:aws:custom:us-east-1:123:resource/thing"
        assert conn._summarize_subscription_destination_type(arn) == "other"

    def test_destination_arn_raw_not_returned(self) -> None:
        """destination type summarization must never return raw ARN string."""
        conn = _build_connector()
        arn = "arn:aws:lambda:us-east-1:123456789012:function:secret-handler"
        result = conn._summarize_subscription_destination_type(arn)
        assert "arn:" not in result
        assert "secret-handler" not in result

    def test_classify_observability_name_sensitivity_production(self) -> None:
        conn = _build_connector()
        assert conn._classify_observability_name_sensitivity("prod-cpu-alarm") == "production"
        assert conn._classify_observability_name_sensitivity("production-errors") == "production"

    def test_classify_observability_name_sensitivity_payment(self) -> None:
        conn = _build_connector()
        assert conn._classify_observability_name_sensitivity("payment-latency") == "payment"

    def test_classify_observability_name_sensitivity_auth(self) -> None:
        conn = _build_connector()
        assert conn._classify_observability_name_sensitivity("auth-errors") == "auth"

    def test_classify_observability_name_sensitivity_security(self) -> None:
        conn = _build_connector()
        assert conn._classify_observability_name_sensitivity("security-audit") == "security"

    def test_classify_observability_name_sensitivity_none(self) -> None:
        conn = _build_connector()
        assert conn._classify_observability_name_sensitivity("cpu-utilization") == "none"

    def test_classify_observability_name_sensitivity_empty(self) -> None:
        conn = _build_connector()
        assert conn._classify_observability_name_sensitivity("") == "none"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification
# ─────────────────────────────────────────────────────────────────────────────

from app.services.risk_rules.aws import classify_aws_change


def _make_change(
    record_type: str,
    change_type: str = "modified",
    field_path: str = "",
    new_value: Any = None,
    prev_value: Any = None,
    record_name: str = "test-alarm",
) -> dict:
    return {
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


class TestRiskClassificationMetricAlarm:
    def test_dispatch_metric_alarm(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_ALARM, "added")
        level, reason = classify_aws_change(change)
        assert isinstance(level, str)
        assert isinstance(reason, str)

    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_ALARM, "added")
        level, reason = classify_aws_change(change)
        assert level == "low"

    def test_removed_non_sensitive_is_medium(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_ALARM, "removed", record_name="cpu-alarm")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_sensitive_is_high(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_ALARM, "removed", record_name="prod-error-alarm")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_actions_disabled_sensitive_is_critical(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="actions_enabled", new_value=False,
            record_name="prod-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_actions_disabled_non_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="actions_enabled", new_value=False,
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_alarm_state_alarm_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="alarm_state_value", new_value="ALARM",
            record_name="prod-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_alarm_state_alarm_non_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="alarm_state_value", new_value="ALARM",
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_threshold_change_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="threshold", new_value=95.0, prev_value=80.0,
            record_name="prod-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_threshold_change_non_sensitive_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="threshold", new_value=95.0, prev_value=80.0,
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_reason_not_empty(self) -> None:
        for ct in ("added", "removed", "modified"):
            change = _make_change(AWS_CLOUDWATCH_METRIC_ALARM, ct, field_path="threshold")
            _, reason = classify_aws_change(change)
            assert reason

    def test_alarm_action_count_zero_sensitive_is_critical(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="alarm_action_count", new_value=0,
            record_name="prod-error-alarm",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert reason

    def test_alarm_action_count_zero_non_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="alarm_action_count", new_value=0,
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_alarm_action_count_non_zero_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="alarm_action_count", new_value=2,
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_treat_missing_data_notbreaching_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="treat_missing_data", new_value="notBreaching",
            record_name="prod-alarm",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "notBreaching" in reason or "not" in reason.lower()

    def test_treat_missing_data_notbreaching_non_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="treat_missing_data", new_value="notBreaching",
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_period_change_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="period", new_value=300, prev_value=60,
            record_name="prod-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_period_change_non_sensitive_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_ALARM, "modified",
            field_path="period", new_value=300, prev_value=60,
            record_name="cpu-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


class TestRiskClassificationCompositeAlarm:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_COMPOSITE_ALARM, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_COMPOSITE_ALARM, "removed",
            record_name="prod-composite-alarm",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_actions_disabled_non_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_COMPOSITE_ALARM, "modified",
            field_path="actions_enabled", new_value=False,
            record_name="cpu-composite",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_alarm_rule_change_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_COMPOSITE_ALARM, "modified",
            field_path="alarm_rule_hash", record_name="prod-composite",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_alarm_rule_change_non_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_COMPOSITE_ALARM, "modified",
            field_path="alarm_rule_hash", record_name="cpu-composite",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"


class TestRiskClassificationDashboard:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_DASHBOARD, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_DASHBOARD, "removed")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_body_hash_change_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_DASHBOARD, "modified",
            field_path="dashboard_body_hash",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_widget_count_change_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_DASHBOARD, "modified",
            field_path="widget_count", new_value=5, prev_value=3,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


class TestRiskClassificationLogGroup:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_LOG_GROUP, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "removed",
            record_name="/aws/lambda/prod-payment-handler",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_removed_non_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "removed",
            record_name="/aws/lambda/utility-job",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_retention_removed_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "modified",
            field_path="retention_configured", new_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_retention_reduced_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "modified",
            field_path="retention_in_days", new_value=7, prev_value=90,
            record_name="prod-app-logs",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_retention_increased_non_sensitive_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "modified",
            field_path="retention_in_days", new_value=180, prev_value=30,
            record_name="utility-logs",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_kms_removed_sensitive_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "modified",
            field_path="kms_key_id_present", new_value=False,
            record_name="prod-logs",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_kms_removed_non_sensitive_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_LOG_GROUP, "modified",
            field_path="kms_key_id_present", new_value=False,
            record_name="utility-logs",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"


class TestRiskClassificationMetricFilter:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_FILTER, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_FILTER, "removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_pattern_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_FILTER, "modified",
            field_path="filter_pattern_hash",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_metric_name_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_FILTER, "modified",
            field_path="metric_name",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"


class TestRiskClassificationSubscriptionFilter:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_SUBSCRIPTION_FILTER, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_SUBSCRIPTION_FILTER, "removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_destination_type_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_SUBSCRIPTION_FILTER, "modified",
            field_path="destination_type", new_value="kinesis",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_destination_arn_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_SUBSCRIPTION_FILTER, "modified",
            field_path="destination_arn_hash",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_role_arn_hash_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_SUBSCRIPTION_FILTER, "modified",
            field_path="role_arn_hash",
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert reason

    def test_role_arn_removed_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_SUBSCRIPTION_FILTER, "modified",
            field_path="role_arn_present", new_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"


class TestRiskClassificationMetricStream:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_STREAM, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_METRIC_STREAM, "removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_state_stopped_is_high(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_STREAM, "modified",
            field_path="state", new_value="stopped",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_firehose_arn_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_STREAM, "modified",
            field_path="firehose_arn_hash",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_role_arn_hash_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_STREAM, "modified",
            field_path="role_arn_hash",
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert reason

    def test_state_running_is_low(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_METRIC_STREAM, "modified",
            field_path="state", new_value="running",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


class TestRiskClassificationAnomalyDetector:
    def test_added_is_low(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_ANOMALY_DETECTOR, "added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self) -> None:
        change = _make_change(AWS_CLOUDWATCH_ANOMALY_DETECTOR, "removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_state_disabled_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_ANOMALY_DETECTOR, "modified",
            field_path="state", new_value="disabled",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_namespace_change_is_medium(self) -> None:
        change = _make_change(
            AWS_CLOUDWATCH_ANOMALY_DETECTOR, "modified",
            field_path="namespace", new_value="AWS/EC2",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Failure classifiers
# ─────────────────────────────────────────────────────────────────────────────

from app.core.failure_classifier import (
    classify_aws_cloudwatch_failure,
    classify_aws_cloudwatch_logs_failure,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)


class TestFailureClassifierCloudWatch:
    def test_auth_error_returns_access_denied(self) -> None:
        exc = AuthenticationError("no perms")
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.category == "authentication"
        assert fc.error_code == "aws_cloudwatch_access_denied"

    def test_403_connector_error_returns_access_denied(self) -> None:
        exc = ConnectorError("403", status_code=403)
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.category == "authentication"
        assert fc.error_code == "aws_cloudwatch_access_denied"

    def test_access_denied_response_returns_access_denied(self) -> None:
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied"}}
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.category == "authentication"

    def test_rate_limit(self) -> None:
        exc = RateLimitError("throttled")
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_cloudwatch_rate_limited"

    def test_network_error(self) -> None:
        exc = NetworkError("timeout")
        fc = classify_aws_cloudwatch_failure("ListDashboards", exc)
        assert fc.category == "network"
        assert fc.error_code == "network_error"

    def test_server_error(self) -> None:
        exc = ConnectorError("500", status_code=500)
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.category == "provider_unavailable"
        assert fc.error_code == "aws_cloudwatch_api_unavailable"

    def test_describe_alarms_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.error_code == "aws_cloudwatch_alarms_unavailable"

    def test_list_dashboards_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_failure("ListDashboards", exc)
        assert fc.error_code == "aws_cloudwatch_dashboards_unavailable"

    def test_get_dashboard_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_failure("GetDashboard", exc)
        assert fc.error_code == "aws_cloudwatch_dashboards_unavailable"

    def test_list_metric_streams_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_failure("ListMetricStreams", exc)
        assert fc.error_code == "aws_cloudwatch_metric_streams_unavailable"

    def test_describe_anomaly_detectors_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_failure("DescribeAnomalyDetectors", exc)
        assert fc.error_code == "aws_cloudwatch_anomaly_detectors_unavailable"

    def test_recommended_action_not_empty(self) -> None:
        exc = AuthenticationError("no perms")
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        assert fc.recommended_action
        assert len(fc.recommended_action) > 20

    def test_recommended_action_no_forbidden_words(self) -> None:
        """Recommended action must not mention metric datapoints or log event content."""
        exc = AuthenticationError("no perms")
        fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
        action = fc.recommended_action.lower()
        for word in ("getmetricdata", "filterlogevents", "startquery"):
            assert word not in action, f"Forbidden word '{word}' in recommended_action"


class TestFailureClassifierCloudWatchLogs:
    def test_auth_error_returns_access_denied(self) -> None:
        exc = AuthenticationError("no perms")
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.category == "authentication"
        assert fc.error_code == "aws_cloudwatch_logs_access_denied"

    def test_403_connector_error(self) -> None:
        exc = ConnectorError("403", status_code=403)
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.category == "authentication"

    def test_access_denied_response(self) -> None:
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied"}}
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.category == "authentication"

    def test_rate_limit(self) -> None:
        exc = RateLimitError("throttled")
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_cloudwatch_logs_rate_limited"

    def test_network_error(self) -> None:
        exc = NetworkError("timeout")
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.category == "network"

    def test_server_error(self) -> None:
        exc = ConnectorError("500", status_code=500)
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.category == "provider_unavailable"
        assert fc.error_code == "aws_cloudwatch_logs_api_unavailable"

    def test_describe_log_groups_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        assert fc.error_code == "aws_cloudwatch_logs_log_groups_unavailable"

    def test_describe_metric_filters_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_logs_failure("DescribeMetricFilters", exc)
        assert fc.error_code == "aws_cloudwatch_logs_metric_filters_unavailable"

    def test_describe_subscription_filters_code(self) -> None:
        exc = ConnectorError("err")
        fc = classify_aws_cloudwatch_logs_failure("DescribeSubscriptionFilters", exc)
        assert fc.error_code == "aws_cloudwatch_logs_subscription_filters_unavailable"

    def test_recommended_action_no_forbidden_log_words(self) -> None:
        """Recommended action must not mention forbidden log event APIs."""
        exc = AuthenticationError("no perms")
        fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
        action = fc.recommended_action.lower()
        for word in ("getlogevents", "filterlogevents", "startquery", "getqueryresults"):
            assert word not in action, f"Forbidden word '{word}' in recommended_action"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Connector normalization
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectorNormalizationCloudWatch:
    """Test _fetch_cloudwatch_in_region with a mock client."""

    def _build_cw_client(self) -> MagicMock:
        client = MagicMock()
        # DescribeAlarms: metric alarm
        def describe_alarms(**kwargs):
            alarm_types = kwargs.get("AlarmTypes", ["MetricAlarm"])
            if "MetricAlarm" in alarm_types or not alarm_types:
                return {
                    "MetricAlarms": [
                        {
                            "AlarmName": "prod-cpu-alarm",
                            "AlarmArn": "arn:aws:cloudwatch:us-east-1:123:alarm:prod-cpu-alarm",
                            "ActionsEnabled": True,
                            "StateValue": "OK",
                            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                            "Threshold": 80.0,
                            "EvaluationPeriods": 2,
                            "DatapointsToAlarm": 2,
                            "TreatMissingData": "missing",
                            "Statistic": "Average",
                            "Period": 60,
                            "Namespace": "AWS/EC2",
                            "MetricName": "CPUUtilization",
                            "Dimensions": [{"Name": "InstanceId", "Value": "i-12345"}],
                            "AlarmActions": ["arn:aws:sns:us-east-1:123:my-topic"],
                            "OKActions": [],
                            "InsufficientDataActions": [],
                        }
                    ],
                    "CompositeAlarms": [],
                }
            elif "CompositeAlarm" in alarm_types:
                return {
                    "MetricAlarms": [],
                    "CompositeAlarms": [
                        {
                            "AlarmName": "prod-composite",
                            "AlarmArn": "arn:aws:cloudwatch:us-east-1:123:alarm:prod-composite",
                            "ActionsEnabled": True,
                            "StateValue": "OK",
                            "AlarmRule": "ALARM(prod-cpu-alarm) AND ALARM(other-alarm)",
                            "AlarmActions": [],
                            "OKActions": [],
                            "InsufficientDataActions": [],
                        }
                    ],
                }
            return {"MetricAlarms": [], "CompositeAlarms": []}

        client.describe_alarms.side_effect = describe_alarms

        # ListDashboards
        client.list_dashboards.return_value = {
            "DashboardEntries": [
                {
                    "DashboardName": "MyDashboard",
                    "DashboardArn": "arn:aws:cloudwatch::123:dashboard/MyDashboard",
                }
            ]
        }
        # GetDashboard
        body = json.dumps({"widgets": [{"type": "metric"}, {"type": "text"}]})
        client.get_dashboard.return_value = {"DashboardBody": body}

        # ListMetricStreams
        client.list_metric_streams.return_value = {
            "Entries": [
                {
                    "Name": "my-stream",
                    "Arn": "arn:aws:cloudwatch:us-east-1:123:metric-stream/my-stream",
                    "State": "running",
                }
            ]
        }
        # GetMetricStream
        client.get_metric_stream.return_value = {
            "FirehoseArn": "arn:aws:firehose:us-east-1:123:deliverystream/ds",
            "RoleArn": "arn:aws:iam::123:role/metric-stream-role",
            "IncludeFilters": [],
            "ExcludeFilters": [{"Namespace": "AWS/S3"}],
            "OutputFormat": "json",
            "State": "running",
            "StatisticsConfigurations": [],
            "Tags": [{"Key": "env", "Value": "prod"}],
        }

        # DescribeAnomalyDetectors
        client.describe_anomaly_detectors.return_value = {
            "AnomalyDetectors": [
                {
                    "SingleMetricAnomalyDetector": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "Stat": "Average",
                        "Dimensions": [{"Name": "InstanceId", "Value": "i-abc"}],
                    },
                    "StateValue": "TRAINED",
                    "Configuration": {
                        "ExcludedTimeRanges": [],
                        "MetricTimezone": "UTC",
                    },
                }
            ]
        }

        # ListTagsForResource
        client.list_tags_for_resource.return_value = {
            "Tags": [{"Key": "Team", "Value": "platform"}]
        }
        return client

    def test_returns_list(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        assert isinstance(records, list)
        assert len(records) > 0

    def test_metric_alarm_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarms = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM]
        assert len(alarms) == 1
        alarm = alarms[0]
        assert alarm["name"] == "prod-cpu-alarm"
        assert alarm["namespace"] == "AWS/EC2"
        assert alarm["threshold"] == 80.0
        assert alarm["actions_enabled"] is True

    def test_metric_alarm_has_period(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarm = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM)
        assert "period" in alarm

    def test_metric_alarm_has_action_counts(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarm = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM)
        assert "alarm_action_count" in alarm
        assert "ok_action_count" in alarm
        assert "insufficient_data_action_count" in alarm
        # 1 SNS action in the mock
        assert alarm["alarm_action_count"] == 1
        assert alarm["ok_action_count"] == 0
        assert alarm["insufficient_data_action_count"] == 0

    def test_metric_alarm_no_raw_action_arns(self) -> None:
        """Raw alarm action ARNs must never be stored."""
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarms = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM]
        alarm = alarms[0]
        record_str = json.dumps(alarm)
        assert "arn:aws:sns" not in record_str

    def test_metric_alarm_action_type_counts_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarm = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM)
        assert alarm["alarm_action_type_counts"].get("sns") == 1

    def test_metric_alarm_dimension_keys_not_values(self) -> None:
        """Dimension values must never be stored — keys only."""
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarm = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM)
        dim_keys = alarm["dimension_key_names"]
        assert "InstanceId" in dim_keys
        assert "i-12345" not in str(dim_keys)

    def test_metric_alarm_tag_keys_only(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        alarm = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM)
        assert "Team" in alarm["tag_keys"]
        # Tag values must not be stored
        assert "platform" not in str(alarm["tag_keys"])

    def test_composite_alarm_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        composites = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_COMPOSITE_ALARM]
        assert len(composites) == 1
        c = composites[0]
        assert c["name"] == "prod-composite"
        assert "alarm_rule_hash" in c
        assert c.get("alarm_rule_component_count") >= 1

    def test_composite_alarm_has_rule_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        c = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_COMPOSITE_ALARM)
        assert "alarm_rule_present" in c
        assert c["alarm_rule_present"] is True

    def test_composite_alarm_has_action_counts(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        c = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_COMPOSITE_ALARM)
        assert "alarm_action_count" in c
        assert "ok_action_count" in c
        assert "insufficient_data_action_count" in c

    def test_composite_alarm_no_raw_rule(self) -> None:
        """Raw composite alarm rule must never be stored."""
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        c = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_COMPOSITE_ALARM)
        record_str = json.dumps(c)
        assert "ALARM(prod-cpu-alarm)" not in record_str

    def test_dashboard_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        dashes = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_DASHBOARD]
        assert len(dashes) == 1
        d = dashes[0]
        assert d["name"] == "MyDashboard"
        assert d["widget_count"] == 2

    def test_dashboard_no_raw_body(self) -> None:
        """Dashboard body must never be stored in plaintext."""
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        d = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_DASHBOARD)
        record_str = json.dumps(d)
        # The raw body JSON must not appear
        assert '"widgets":' not in record_str
        assert "dashboard_body_hash" in d

    def test_metric_stream_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        streams = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_STREAM]
        assert len(streams) == 1
        s = streams[0]
        assert s["name"] == "my-stream"
        assert s["state"] == "running"
        assert s["output_format"] == "json"

    def test_metric_stream_no_raw_firehose_arn(self) -> None:
        """Raw Firehose ARN must never be stored."""
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        s = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_STREAM)
        record_str = json.dumps(s)
        assert "arn:aws:firehose" not in record_str
        assert "firehose_arn_hash" in s

    def test_metric_stream_has_role_arn_hash(self) -> None:
        """Metric stream must include role_arn_hash field."""
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        s = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_STREAM)
        assert "role_arn_hash" in s

    def test_anomaly_detector_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        dets = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_ANOMALY_DETECTOR]
        assert len(dets) == 1
        d = dets[0]
        assert d["namespace"] == "AWS/EC2"
        assert d["metric_name"] == "CPUUtilization"
        assert d["stat"] == "Average"

    def test_anomaly_detector_dimension_keys_not_values(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        d = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_ANOMALY_DETECTOR)
        dim_keys = d["dimension_key_names"]
        assert "InstanceId" in dim_keys
        assert "i-abc" not in str(dim_keys)

    def test_all_records_have_required_fields(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        for r in records:
            assert "record_type" in r
            assert "record_id" in r
            assert "external_id" in r
            assert r["record_id"] == r["external_id"]

    def test_stable_id_uses_hash_not_raw_arn(self) -> None:
        conn = _build_connector()
        client = self._build_cw_client()
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        for r in records:
            rid = r.get("record_id", "")
            assert "arn:aws:" not in rid


class TestConnectorNormalizationCloudWatchLogs:
    """Test _fetch_cloudwatch_logs_in_region with a mock logs client."""

    def _build_logs_client(self) -> MagicMock:
        client = MagicMock()

        # DescribeLogGroups
        client.describe_log_groups.return_value = {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/prod-api-handler",
                    "retentionInDays": 90,
                    "kmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                    "storedBytes": 1024000,
                    "metricFilterCount": 1,
                }
            ]
        }

        # ListTagsLogGroup
        client.list_tags_log_group.return_value = {
            "tags": {"Team": "platform", "Env": "prod"}
        }

        # DescribeMetricFilters
        client.describe_metric_filters.return_value = {
            "metricFilters": [
                {
                    "filterName": "error-count-filter",
                    "filterPattern": '[ERROR]',
                    "metricTransformations": [
                        {
                            "metricName": "ErrorCount",
                            "metricNamespace": "MyApp",
                            "metricValue": "1",
                            "defaultValue": 0,
                            "unit": "Count",
                        }
                    ],
                }
            ]
        }

        # DescribeSubscriptionFilters
        client.describe_subscription_filters.return_value = {
            "subscriptionFilters": [
                {
                    "filterName": "to-lambda",
                    "filterPattern": "[ERROR]",
                    "destinationArn": "arn:aws:lambda:us-east-1:123:function:log-ingester",
                    "distribution": "Random",
                }
            ]
        }
        return client

    def test_returns_list(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        assert isinstance(records, list)
        assert len(records) > 0

    def test_log_group_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        lgs = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_LOG_GROUP]
        assert len(lgs) == 1
        lg = lgs[0]
        assert lg["name"] == "/aws/lambda/prod-api-handler"
        assert lg["retention_in_days"] == 90
        assert lg["retention_configured"] is True
        assert lg["kms_key_id_present"] is True

    def test_log_group_no_raw_kms_arn(self) -> None:
        """Raw KMS ARN must never be stored."""
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        lg = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_LOG_GROUP)
        record_str = json.dumps(lg)
        assert "arn:aws:kms" not in record_str
        assert "kms_key_id_hash" in lg

    def test_log_group_tag_keys_only(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        lg = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_LOG_GROUP)
        assert "Team" in lg["tag_keys"]
        assert "Env" in lg["tag_keys"]
        # Tag values must not be stored
        assert "platform" not in str(lg["tag_keys"])
        assert "prod" not in str(lg["tag_keys"])

    def test_log_group_name_not_stored_as_raw_in_stable_id(self) -> None:
        """Log group name should be hashed in stable ID (not appear verbatim)."""
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        lg = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_LOG_GROUP)
        # The name field contains the actual name (for display)
        # The record_id should NOT contain the raw log group name
        assert "/aws/lambda/prod-api-handler" not in lg["record_id"]

    def test_metric_filter_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        mfs = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_FILTER]
        assert len(mfs) == 1
        mf = mfs[0]
        assert mf["name"] == "error-count-filter"
        assert mf["metric_name"] == "ErrorCount"
        assert mf["metric_namespace"] == "MyApp"

    def test_metric_filter_no_raw_pattern(self) -> None:
        """Raw filter pattern must never be stored."""
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        mf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_FILTER)
        record_str = json.dumps(mf)
        # The raw pattern '[ERROR]' must not appear
        assert "[ERROR]" not in record_str
        assert "filter_pattern_hash" in mf

    def test_metric_filter_has_pattern_present(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        mf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_FILTER)
        assert "filter_pattern_present" in mf
        assert mf["filter_pattern_present"] is True

    def test_metric_filter_pattern_hash_correct(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        mf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_FILTER)
        expected_hash = hashlib.sha256(b"[ERROR]").hexdigest()[:12]
        assert mf["filter_pattern_hash"] == expected_hash

    def test_metric_filter_default_value_present(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        mf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_METRIC_FILTER)
        assert mf["default_value_present"] is True
        assert mf["unit_present"] is True

    def test_subscription_filter_record_present(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        sfs = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_SUBSCRIPTION_FILTER]
        assert len(sfs) == 1
        sf = sfs[0]
        assert sf["name"] == "to-lambda"
        assert sf["destination_type"] == "lambda"
        assert sf["distribution"] == "Random"

    def test_subscription_filter_no_raw_destination_arn(self) -> None:
        """Raw destination ARN must never be stored."""
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        sf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_SUBSCRIPTION_FILTER)
        record_str = json.dumps(sf)
        assert "arn:aws:lambda" not in record_str
        assert "destination_arn_hash" in sf

    def test_subscription_filter_no_raw_pattern(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        sf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_SUBSCRIPTION_FILTER)
        record_str = json.dumps(sf)
        assert "[ERROR]" not in record_str
        assert "filter_pattern_hash" in sf

    def test_subscription_filter_has_role_fields(self) -> None:
        """Subscription filter must include role_arn_present and role_arn_hash."""
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        sf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_SUBSCRIPTION_FILTER)
        assert "role_arn_present" in sf
        assert "role_arn_hash" in sf

    def test_subscription_filter_has_pattern_present(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        sf = next(r for r in records if r.get("record_type") == AWS_CLOUDWATCH_SUBSCRIPTION_FILTER)
        assert "filter_pattern_present" in sf
        assert sf["filter_pattern_present"] is True

    def test_all_records_have_required_fields(self) -> None:
        conn = _build_connector()
        client = self._build_logs_client()
        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        for r in records:
            assert "record_type" in r
            assert "record_id" in r
            assert "external_id" in r
            assert r["record_id"] == r["external_id"]


# ─────────────────────────────────────────────────────────────────────────────
# 8. Service inventory
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceInventory:
    def test_cloudwatch_in_enabled_surfaces(self) -> None:
        conn = _build_connector()
        inv = conn._fetch_service_inventory(credentials={"region": "us-east-1"})
        surfaces = inv.get("enabled_surfaces") or []
        assert "cloudwatch" in surfaces, "cloudwatch must be in enabled_surfaces"

    def test_cloudwatch_logs_in_enabled_surfaces(self) -> None:
        conn = _build_connector()
        inv = conn._fetch_service_inventory(credentials={"region": "us-east-1"})
        surfaces = inv.get("enabled_surfaces") or []
        assert "cloudwatch_logs" in surfaces, "cloudwatch_logs must be in enabled_surfaces"

    def test_cloudwatch_not_in_future_surfaces(self) -> None:
        conn = _build_connector()
        inv = conn._fetch_service_inventory(credentials={"region": "us-east-1"})
        # future_surfaces key must exist (so old milestone tests don't KeyError)
        assert "future_surfaces" in inv
        future = inv.get("future_surfaces") or []
        assert "cloudwatch" not in future, "cloudwatch should not be in future_surfaces (M49 implements it)"

    def test_cloudwatch_alarm_count_field(self) -> None:
        conn = _build_connector()
        inv = conn._fetch_service_inventory(
            credentials={"region": "us-east-1"},
            cloudwatch_alarm_count=5,
        )
        assert inv.get("cloudwatch_alarm_count") == 5

    def test_cloudwatch_log_group_count_field(self) -> None:
        conn = _build_connector()
        inv = conn._fetch_service_inventory(
            credentials={"region": "us-east-1"},
            cloudwatch_log_group_count=12,
        )
        assert inv.get("cloudwatch_log_group_count") == 12

    def test_service_inventory_zero_counts_default(self) -> None:
        conn = _build_connector()
        inv = conn._fetch_service_inventory(credentials={"region": "us-east-1"})
        assert inv.get("cloudwatch_alarm_count") == 0
        assert inv.get("cloudwatch_log_group_count") == 0


# ─────────────────────────────────────────────────────────────────────────────
# 9. M48 regression — ensure M48 types still dispatch correctly
# ─────────────────────────────────────────────────────────────────────────────

from app.connectors.aws_schema import (
    AWS_KMS_KEY,
    AWS_KMS_ALIAS,
    AWS_BACKUP_VAULT,
    AWS_BACKUP_PLAN,
    AWS_BACKUP_SELECTION,
    AWS_BACKUP_RECOVERY_POINT,
    AWS_ORGANIZATIONS_ORGANIZATION,
    AWS_ORGANIZATIONS_ACCOUNT,
    AWS_ORGANIZATIONS_OU,
    AWS_ORGANIZATIONS_SCP,
    AWS_ORGANIZATIONS_SCP_ATTACHMENT,
)

_M48_TYPES = [
    AWS_KMS_KEY,
    AWS_KMS_ALIAS,
    AWS_BACKUP_VAULT,
    AWS_BACKUP_PLAN,
    AWS_BACKUP_SELECTION,
    AWS_BACKUP_RECOVERY_POINT,
    AWS_ORGANIZATIONS_ORGANIZATION,
    AWS_ORGANIZATIONS_ACCOUNT,
    AWS_ORGANIZATIONS_OU,
    AWS_ORGANIZATIONS_SCP,
    AWS_ORGANIZATIONS_SCP_ATTACHMENT,
]


class TestM48Regression:
    @pytest.mark.parametrize("rt", _M48_TYPES)
    def test_m48_type_still_dispatches(self, rt: str) -> None:
        change = _make_change(rt, "added")
        level, reason = classify_aws_change(change)
        assert isinstance(level, str)
        assert level != ""
        assert isinstance(reason, str)
        assert reason != ""

    @pytest.mark.parametrize("rt", _M48_TYPES)
    def test_m48_type_removed_not_unknown_level(self, rt: str) -> None:
        change = _make_change(rt, "removed", record_name="test-resource")
        level, _ = classify_aws_change(change)
        assert level != "unknown", f"{rt} removed returned 'unknown' risk level"

    def test_kms_key_rotation_disabled_is_high_or_critical(self) -> None:
        change = _make_change(
            AWS_KMS_KEY, "modified",
            field_path="rotation_enabled", new_value=False,
            record_name="prod-cmk",
        )
        level, _ = classify_aws_change(change)
        assert level in ("high", "critical")

    def test_backup_vault_removed_is_high(self) -> None:
        change = _make_change(AWS_BACKUP_VAULT, "removed", record_name="my-vault")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_scp_attachment_removed_is_high(self) -> None:
        change = _make_change(AWS_ORGANIZATIONS_SCP_ATTACHMENT, "removed")
        level, _ = classify_aws_change(change)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Fail-soft
# ─────────────────────────────────────────────────────────────────────────────

class TestFailSoft:
    def test_cloudwatch_region_failure_does_not_abort(self) -> None:
        """A failing region should be logged and skipped; other regions continue."""
        conn = _build_connector()

        def make_client(service, credentials, region=None):
            client = MagicMock()
            if region == "us-east-1":
                # This region succeeds
                client.describe_alarms.return_value = {"MetricAlarms": [], "CompositeAlarms": []}
                client.list_dashboards.return_value = {"DashboardEntries": []}
                client.list_metric_streams.return_value = {"Entries": []}
                client.describe_anomaly_detectors.return_value = {"AnomalyDetectors": []}
                return client
            else:
                # This region raises on every call
                client.describe_alarms.side_effect = Exception("simulated region failure")
                client.list_dashboards.side_effect = Exception("simulated region failure")
                client.list_metric_streams.side_effect = Exception("simulated region failure")
                client.describe_anomaly_detectors.side_effect = Exception("simulated region failure")
                return client

        conn._make_client = make_client
        conn._selected_regions = lambda creds: ["us-east-1", "eu-west-1"]

        records = conn._fetch_cloudwatch_resources({}, "123456789012")
        # Should not raise; returns a list (possibly empty)
        assert isinstance(records, list)

    def test_cloudwatch_logs_region_failure_does_not_abort(self) -> None:
        conn = _build_connector()

        def make_client(service, credentials, region=None):
            client = MagicMock()
            if region == "us-east-1":
                client.describe_log_groups.return_value = {"logGroups": []}
                return client
            else:
                client.describe_log_groups.side_effect = Exception("region failure")
                return client

        conn._make_client = make_client
        conn._selected_regions = lambda creds: ["us-east-1", "eu-west-1"]

        records = conn._fetch_cloudwatch_logs_resources({}, "123456789012")
        assert isinstance(records, list)

    def test_single_alarm_describe_failure_skipped(self) -> None:
        """An exception during DescribeAlarms in a region is caught and logged."""
        conn = _build_connector()
        client = MagicMock()
        client.describe_alarms.side_effect = Exception("describe failed")
        client.list_dashboards.return_value = {"DashboardEntries": []}
        client.list_metric_streams.return_value = {"Entries": []}
        client.describe_anomaly_detectors.return_value = {"AnomalyDetectors": []}

        # Should not raise
        records = conn._fetch_cloudwatch_in_region(client, "123456789012", "us-east-1")
        assert isinstance(records, list)

    def test_describe_log_groups_failure_returns_empty(self) -> None:
        conn = _build_connector()
        client = MagicMock()
        client.describe_log_groups.side_effect = Exception("describe failed")

        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        assert isinstance(records, list)
        assert len(records) == 0

    def test_metric_filter_failure_does_not_abort_log_group(self) -> None:
        """A DescribeMetricFilters failure for one log group doesn't prevent the group from being returned."""
        conn = _build_connector()
        client = MagicMock()
        client.describe_log_groups.return_value = {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/my-fn",
                    "retentionInDays": 30,
                    "storedBytes": 0,
                    "metricFilterCount": 0,
                }
            ]
        }
        client.list_tags_log_group.return_value = {"tags": {}}
        client.describe_metric_filters.side_effect = Exception("filters failed")
        client.describe_subscription_filters.return_value = {"subscriptionFilters": []}

        records = conn._fetch_cloudwatch_logs_in_region(client, "123456789012", "us-east-1")
        # Log group itself should still be present
        lgs = [r for r in records if r.get("record_type") == AWS_CLOUDWATCH_LOG_GROUP]
        assert len(lgs) == 1
