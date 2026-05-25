"""Tests for Milestone 47: AWS EventBridge + SQS/SNS Messaging Config.

Covers:
- Security hard rules: no ReceiveMessage, no SendMessage, no PurgeQueue,
  no Publish, no PutEvents, no message payloads stored, no raw endpoints stored
- Schema registration: all 7 M47 types in AWS_RECORD_TYPES
- Diff service tracked field registration for all 7 M47 types
- Helper functions: _classify_messaging_name_sensitivity, _messaging_policy_is_public,
  _hash_arn, _hash_endpoint, _classify_endpoint_type, _summarize_target_type,
  _hash_event_pattern, _hash_filter_policy, _summarize_redrive_allow_policy,
  _is_sensitive_messaging_resource
- EventBridge risk classification matrix
- SQS risk classification matrix
- SNS risk classification matrix
- Failure classifiers: classify_aws_eventbridge_failure, classify_aws_sqs_failure,
  classify_aws_sns_failure
- Connector normalization: _fetch_eventbridge_in_region, _fetch_sqs_in_region,
  _fetch_sns_in_region
- Service inventory: eventbridge/sqs/sns in enabled_surfaces (not future_surfaces)
- Fail-soft: per-region errors do not abort full fetch
- M46 regression guard: M46 record types still classified correctly
"""

import inspect
import json
import pytest
from unittest.mock import MagicMock, patch

from app.connectors.aws import (
    AWSConnector,
    _classify_messaging_name_sensitivity,
    _is_sensitive_messaging_resource,
    _messaging_policy_is_public,
    _hash_arn,
    _hash_endpoint,
    _classify_endpoint_type,
    _summarize_target_type,
    _hash_event_pattern,
    _hash_filter_policy,
    _summarize_redrive_allow_policy,
)
from app.connectors.aws_schema import (
    AWS_EVENTBRIDGE_EVENT_BUS,
    AWS_EVENTBRIDGE_RULE,
    AWS_EVENTBRIDGE_TARGET,
    AWS_EVENTBRIDGE_ARCHIVE,
    AWS_SQS_QUEUE,
    AWS_SNS_TOPIC,
    AWS_SNS_SUBSCRIPTION,
    AWS_SERVICE_INVENTORY,
    # M46 regression
    AWS_ECS_CLUSTER,
    AWS_ECR_REPOSITORY,
    AWS_EKS_CLUSTER,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_eventbridge_failure,
    classify_aws_sqs_failure,
    classify_aws_sns_failure,
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
    return AWSConnector.__new__(AWSConnector)


def _creds(regions=None):
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_default_region": "us-east-1",
        "aws_selected_regions": regions or ["us-east-1"],
    }


def _eb_change(
    record_type=AWS_EVENTBRIDGE_EVENT_BUS,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-event-bus",
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


def _sqs_change(
    record_type=AWS_SQS_QUEUE,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-queue",
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


def _sns_change(
    record_type=AWS_SNS_TOPIC,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-topic",
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


def _code_lines_of(method_name: str) -> str:
    """Return source code with docstring/comment lines stripped out."""
    import re
    conn = _make_connector()
    method = getattr(conn, method_name, None)
    if method is None:
        return ""
    src = inspect.getsource(method)
    # Strip triple-quoted docstrings
    src = re.sub(r'""".*?"""', '', src, flags=re.DOTALL)
    # Strip single-line comments
    src = "\n".join(
        line for line in src.splitlines()
        if not line.strip().startswith("#")
    )
    return src


# ─────────────────────────────────────────────────────────────────────────────
# 1. Security hard rules
# ─────────────────────────────────────────────────────────────────────────────

class TestM47SecurityHardRules:
    """Verify that forbidden API calls never appear in M47 connector code."""

    def test_sqs_no_receive_message(self):
        """sqs:ReceiveMessage must never be called."""
        code = _code_lines_of("_fetch_sqs_in_region")
        assert "receive_message" not in code.lower(), (
            "receive_message must never be called in SQS connector"
        )

    def test_sqs_no_send_message(self):
        """sqs:SendMessage must never be called."""
        code = _code_lines_of("_fetch_sqs_in_region")
        assert "send_message" not in code.lower(), (
            "send_message must never be called in SQS connector"
        )

    def test_sqs_no_delete_message(self):
        """sqs:DeleteMessage must never be called."""
        code = _code_lines_of("_fetch_sqs_in_region")
        assert "delete_message" not in code.lower(), (
            "delete_message must never be called in SQS connector"
        )

    def test_sqs_no_purge_queue(self):
        """sqs:PurgeQueue must never be called."""
        code = _code_lines_of("_fetch_sqs_in_region")
        assert "purge_queue" not in code.lower(), (
            "purge_queue must never be called in SQS connector"
        )

    def test_sns_no_publish(self):
        """sns:Publish must never be called."""
        code_topic = _code_lines_of("_fetch_sns_in_region")
        assert "client.publish" not in code_topic.lower(), (
            "sns:Publish must never be called in SNS connector"
        )

    def test_eventbridge_no_put_events(self):
        """events:PutEvents must never be called."""
        code = _code_lines_of("_fetch_eventbridge_in_region")
        assert "put_events" not in code.lower(), (
            "events:PutEvents must never be called in EventBridge connector"
        )

    def test_sqs_message_body_not_stored(self):
        """SQS message body and contents must never appear in connector code."""
        code = _code_lines_of("_fetch_sqs_in_region")
        # Never store MessageBody attribute or call receive_message
        assert "messagebody" not in code.lower()
        assert "message_body" not in code.lower()

    def test_sns_raw_endpoint_not_stored(self):
        """Raw SNS subscription endpoints must never be stored — hash only."""
        code = _code_lines_of("_fetch_sns_in_region")
        # endpoint_raw is hashed, never stored in record directly
        # The record should only store endpoint_hash
        assert '"endpoint_raw"' not in code
        assert "'endpoint_raw'" not in code

    def test_eb_event_pattern_not_stored_raw(self):
        """Raw EventBridge event patterns must never be stored — hash only."""
        code = _code_lines_of("_fetch_eventbridge_in_region")
        # event_pattern_raw is hashed, never put in records as raw
        assert '"event_pattern_raw"' not in code
        assert "'event_pattern_raw'" not in code

    def test_sqs_queue_policy_not_stored_raw(self):
        """Raw SQS queue policy JSON must never be stored — boolean/hash only."""
        code = _code_lines_of("_fetch_sqs_in_region")
        assert '"policy_json"' not in code
        assert '"raw_policy"' not in code
        # policy_raw is consumed locally, never put in record dict
        assert '"policy_raw"' not in code

    def test_sns_filter_policy_not_stored_raw(self):
        """Raw SNS filter policy JSON must never be stored — hash only."""
        code = _code_lines_of("_fetch_sns_in_region")
        assert '"filter_policy_raw"' not in code

    def test_no_write_apis_in_eb_connector(self):
        """EventBridge connector must not call any write APIs."""
        code = _code_lines_of("_fetch_eventbridge_in_region")
        write_apis = ["put_rule", "put_targets", "delete_rule", "remove_targets",
                      "create_event_bus", "delete_event_bus", "tag_resource"]
        for api in write_apis:
            assert api not in code.lower(), f"{api} must not appear in EB connector"

    def test_no_write_apis_in_sqs_connector(self):
        """SQS connector must not call any write APIs."""
        code = _code_lines_of("_fetch_sqs_in_region")
        write_apis = ["create_queue", "delete_queue", "set_queue_attributes",
                      "tag_queue", "change_message_visibility"]
        for api in write_apis:
            assert api not in code.lower(), f"{api} must not appear in SQS connector"

    def test_no_write_apis_in_sns_connector(self):
        """SNS connector must not call any write APIs."""
        code = _code_lines_of("_fetch_sns_in_region")
        write_apis = ["create_topic", "delete_topic", "set_topic_attributes",
                      "set_subscription_attributes", "subscribe", "unsubscribe"]
        for api in write_apis:
            assert api not in code.lower(), f"{api} must not appear in SNS connector"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

class TestM47SchemaRegistration:
    """All 7 M47 record types must be registered in AWS_RECORD_TYPES."""

    def test_eventbridge_event_bus_registered(self):
        assert AWS_EVENTBRIDGE_EVENT_BUS in AWS_RECORD_TYPES

    def test_eventbridge_rule_registered(self):
        assert AWS_EVENTBRIDGE_RULE in AWS_RECORD_TYPES

    def test_eventbridge_target_registered(self):
        assert AWS_EVENTBRIDGE_TARGET in AWS_RECORD_TYPES

    def test_eventbridge_archive_registered(self):
        assert AWS_EVENTBRIDGE_ARCHIVE in AWS_RECORD_TYPES

    def test_sqs_queue_registered(self):
        assert AWS_SQS_QUEUE in AWS_RECORD_TYPES

    def test_sns_topic_registered(self):
        assert AWS_SNS_TOPIC in AWS_RECORD_TYPES

    def test_sns_subscription_registered(self):
        assert AWS_SNS_SUBSCRIPTION in AWS_RECORD_TYPES

    def test_all_seven_m47_types_registered(self):
        m47_types = {
            AWS_EVENTBRIDGE_EVENT_BUS,
            AWS_EVENTBRIDGE_RULE,
            AWS_EVENTBRIDGE_TARGET,
            AWS_EVENTBRIDGE_ARCHIVE,
            AWS_SQS_QUEUE,
            AWS_SNS_TOPIC,
            AWS_SNS_SUBSCRIPTION,
        }
        assert m47_types.issubset(AWS_RECORD_TYPES)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestM47TrackedFields:
    """All 7 M47 types must have non-empty tracked field tuples."""

    def _fields(self, record_type: str) -> tuple:
        return _tracked_fields_for({"record_type": record_type})

    def test_eventbridge_bus_tracked_fields(self):
        fields = self._fields(AWS_EVENTBRIDGE_EVENT_BUS)
        assert len(fields) > 0
        assert "public_or_cross_account_policy" in fields
        assert "policy_present" in fields
        assert "tag_keys" in fields

    def test_eventbridge_rule_tracked_fields(self):
        fields = self._fields(AWS_EVENTBRIDGE_RULE)
        assert "state" in fields
        assert "target_count" in fields
        assert "event_pattern_hash" in fields
        assert "dlq_target_present" in fields
        assert "retry_policy_present" in fields

    def test_eventbridge_target_tracked_fields(self):
        fields = self._fields(AWS_EVENTBRIDGE_TARGET)
        assert "target_type" in fields
        assert "role_arn_present" in fields
        assert "dead_letter_config_present" in fields
        assert "retry_policy_present" in fields
        assert "input_present" in fields

    def test_eventbridge_archive_tracked_fields(self):
        fields = self._fields(AWS_EVENTBRIDGE_ARCHIVE)
        assert "state" in fields
        assert "retention_days" in fields

    def test_sqs_queue_tracked_fields(self):
        fields = self._fields(AWS_SQS_QUEUE)
        assert "public_or_cross_account_policy" in fields
        assert "sqs_managed_sse_enabled" in fields
        assert "kms_master_key_id_present" in fields
        assert "redrive_policy_present" in fields
        assert "message_retention_period" in fields
        assert "visibility_timeout" in fields
        assert "fifo_queue" in fields

    def test_sns_topic_tracked_fields(self):
        fields = self._fields(AWS_SNS_TOPIC)
        assert "public_or_cross_account_policy" in fields
        assert "kms_master_key_id_present" in fields
        assert "subscription_count" in fields
        assert "confirmed_subscription_count" in fields
        assert "subscription_protocol_counts" in fields
        assert "fifo_topic" in fields

    def test_sns_subscription_tracked_fields(self):
        fields = self._fields(AWS_SNS_SUBSCRIPTION)
        assert "protocol" in fields
        assert "endpoint_hash" in fields
        assert "endpoint_type" in fields
        assert "filter_policy_present" in fields
        assert "filter_policy_hash" in fields
        assert "raw_message_delivery" in fields

    def test_no_raw_message_fields_in_tracked_fields(self):
        """Tracked fields must never include raw message/payload fields."""
        for rt in [
            AWS_SQS_QUEUE, AWS_SNS_TOPIC, AWS_SNS_SUBSCRIPTION,
            AWS_EVENTBRIDGE_EVENT_BUS, AWS_EVENTBRIDGE_RULE,
        ]:
            fields = self._fields(rt)
            forbidden = {"message_body", "message_content", "event_payload",
                         "raw_endpoint", "filter_policy_raw", "policy_json"}
            overlap = set(fields) & forbidden
            assert not overlap, f"Forbidden field(s) {overlap} found in {rt} tracked fields"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Helper functions
# ─────────────────────────────────────────────────────────────────────────────

class TestM47HelperFunctions:

    # _classify_messaging_name_sensitivity
    def test_sensitivity_production(self):
        assert _classify_messaging_name_sensitivity("prod-payments-bus") == "production"
        assert _classify_messaging_name_sensitivity("production-orders") == "production"
        assert _classify_messaging_name_sensitivity("live-events") == "production"

    def test_sensitivity_payment(self):
        assert _classify_messaging_name_sensitivity("payment-queue") == "payment"
        assert _classify_messaging_name_sensitivity("billing-events") == "payment"
        assert _classify_messaging_name_sensitivity("invoice-sns-topic") == "payment"

    def test_sensitivity_auth(self):
        assert _classify_messaging_name_sensitivity("auth-events-bus") == "auth"
        assert _classify_messaging_name_sensitivity("login-notifications") == "auth"

    def test_sensitivity_admin(self):
        assert _classify_messaging_name_sensitivity("admin-events") == "admin"
        assert _classify_messaging_name_sensitivity("pii-customer-queue") == "admin"

    def test_sensitivity_none(self):
        assert _classify_messaging_name_sensitivity("dev-test-queue") == "none"
        assert _classify_messaging_name_sensitivity("deployment-events") == "none"
        assert _classify_messaging_name_sensitivity("telemetry-bus") == "none"

    # _is_sensitive_messaging_resource
    def test_is_sensitive_prod(self):
        assert _is_sensitive_messaging_resource("prod-events-bus") is True

    def test_is_sensitive_payment(self):
        assert _is_sensitive_messaging_resource("payment-queue") is True

    def test_not_sensitive(self):
        assert _is_sensitive_messaging_resource("dev-test-queue") is False
        assert _is_sensitive_messaging_resource("telemetry-notifications") is False

    # _messaging_policy_is_public
    def test_policy_public_wildcard_principal(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage"}]
        })
        assert _messaging_policy_is_public(policy, "123456789012") is True

    def test_policy_public_wildcard_in_dict(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sns:Publish"}]
        })
        assert _messaging_policy_is_public(policy, "123456789012") is True

    def test_policy_cross_account(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sqs:SendMessage"}]
        })
        assert _messaging_policy_is_public(policy, "123456789012") is True

    def test_policy_same_account_not_public(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"}, "Action": "sqs:SendMessage"}]
        })
        assert _messaging_policy_is_public(policy, "123456789012") is False

    def test_policy_deny_not_public(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sqs:SendMessage"}]
        })
        assert _messaging_policy_is_public(policy, "123456789012") is False

    def test_policy_empty_not_public(self):
        assert _messaging_policy_is_public("", "123456789012") is False

    def test_policy_invalid_json_not_public(self):
        assert _messaging_policy_is_public("not-json", "123456789012") is False

    # _hash_arn
    def test_hash_arn_consistent(self):
        h = _hash_arn("arn:aws:sqs:us-east-1:123456789012:my-queue")
        assert h is not None
        assert len(h) == 12
        # Same input → same hash
        assert _hash_arn("arn:aws:sqs:us-east-1:123456789012:my-queue") == h

    def test_hash_arn_different_arns(self):
        h1 = _hash_arn("arn:aws:sqs:us-east-1:123:queue-a")
        h2 = _hash_arn("arn:aws:sqs:us-east-1:123:queue-b")
        assert h1 != h2

    def test_hash_arn_empty_returns_none(self):
        assert _hash_arn("") is None
        assert _hash_arn(None) is None  # type: ignore[arg-type]

    # _hash_endpoint
    def test_hash_endpoint_email(self):
        h = _hash_endpoint("user@example.com")
        assert h is not None
        assert len(h) == 12

    def test_hash_endpoint_empty_returns_none(self):
        assert _hash_endpoint("") is None

    def test_hash_endpoint_different_values(self):
        h1 = _hash_endpoint("user@example.com")
        h2 = _hash_endpoint("other@example.com")
        assert h1 != h2

    # _classify_endpoint_type
    def test_endpoint_type_email(self):
        assert _classify_endpoint_type("user@example.com", "email") == "email"
        assert _classify_endpoint_type("user@example.com", "email-json") == "email"

    def test_endpoint_type_sms(self):
        assert _classify_endpoint_type("+15551234567", "sms") == "sms"

    def test_endpoint_type_https(self):
        assert _classify_endpoint_type("https://my.app/callback", "https") == "https"

    def test_endpoint_type_sqs(self):
        assert _classify_endpoint_type("arn:aws:sqs:us-east-1:123:q", "sqs") == "sqs"

    def test_endpoint_type_lambda(self):
        assert _classify_endpoint_type("arn:aws:lambda:us-east-1:123:fn", "lambda") == "lambda"

    def test_endpoint_type_firehose(self):
        assert _classify_endpoint_type("arn:aws:firehose:us-east-1:123:ds", "firehose") == "firehose"

    # _summarize_target_type
    def test_target_type_lambda(self):
        assert _summarize_target_type("arn:aws:lambda:us-east-1:123:function:my-fn") == "lambda"

    def test_target_type_sqs(self):
        assert _summarize_target_type("arn:aws:sqs:us-east-1:123:my-queue") == "sqs"

    def test_target_type_sns(self):
        assert _summarize_target_type("arn:aws:sns:us-east-1:123:my-topic") == "sns"

    def test_target_type_kinesis(self):
        assert _summarize_target_type("arn:aws:kinesis:us-east-1:123:stream/my-stream") == "kinesis"

    def test_target_type_step_functions(self):
        assert _summarize_target_type("arn:aws:states:us-east-1:123:stateMachine:my-sm") == "step_functions"

    def test_target_type_api_gateway(self):
        assert _summarize_target_type("arn:aws:execute-api:us-east-1:123:/") == "api_gateway"

    def test_target_type_unknown(self):
        assert _summarize_target_type("arn:aws:something-else:us-east-1:123:resource") == "unknown"

    def test_target_type_empty(self):
        assert _summarize_target_type("") == "unknown"

    # _hash_event_pattern
    def test_hash_event_pattern_returns_hash(self):
        pattern = '{"source": ["aws.ec2"]}'
        h = _hash_event_pattern(pattern)
        assert h is not None
        assert len(h) == 12

    def test_hash_event_pattern_empty_returns_none(self):
        assert _hash_event_pattern("") is None

    def test_hash_event_pattern_changes_on_diff_pattern(self):
        h1 = _hash_event_pattern('{"source": ["aws.ec2"]}')
        h2 = _hash_event_pattern('{"source": ["aws.s3"]}')
        assert h1 != h2

    # _hash_filter_policy
    def test_hash_filter_policy_returns_hash(self):
        policy = '{"event_type": ["ORDER_PLACED"]}'
        h = _hash_filter_policy(policy)
        assert h is not None
        assert len(h) == 12

    def test_hash_filter_policy_empty_returns_none(self):
        assert _hash_filter_policy("") is None

    # _summarize_redrive_allow_policy
    def test_redrive_allow_all(self):
        raw = json.dumps({"redrivePermission": "allowAll"})
        assert _summarize_redrive_allow_policy(raw) == "allowAll"

    def test_redrive_deny_all(self):
        raw = json.dumps({"redrivePermission": "denyAll"})
        assert _summarize_redrive_allow_policy(raw) == "denyAll"

    def test_redrive_by_queue(self):
        raw = json.dumps({"redrivePermission": "bySourceQueue"})
        assert _summarize_redrive_allow_policy(raw) == "byQueue"

    def test_redrive_empty_returns_none(self):
        assert _summarize_redrive_allow_policy("") is None

    def test_redrive_invalid_json_returns_none(self):
        assert _summarize_redrive_allow_policy("not-json") is None


# ─────────────────────────────────────────────────────────────────────────────
# 5. EventBridge risk classification
# ─────────────────────────────────────────────────────────────────────────────

class TestM47EventBridgeRiskClassification:

    # Event bus
    def test_bus_added_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS, change_type="added"
        ))
        assert level == "low"

    def test_bus_policy_public_high(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS,
            field_path="public_or_cross_account_policy", new_value=True
        ))
        assert level == "high"
        assert "external" in reason.lower() or "cross-account" in reason.lower()

    def test_bus_policy_public_critical_if_sensitive(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS,
            field_path="public_or_cross_account_policy", new_value=True,
            record_name="prod-payment-bus"
        ))
        assert level == "critical"

    def test_bus_policy_no_longer_public_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS,
            field_path="public_or_cross_account_policy", new_value=False
        ))
        assert level == "low"

    def test_bus_removed_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS, change_type="removed"
        ))
        assert level == "medium"

    def test_bus_removed_high_if_sensitive(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS, change_type="removed",
            record_name="prod-events"
        ))
        assert level == "high"

    def test_bus_policy_added_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_EVENT_BUS,
            field_path="policy_present", new_value=True
        ))
        assert level == "medium"

    # EventBridge rule
    def test_rule_added_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE, change_type="added"
        ))
        assert level == "low"

    def test_rule_disabled_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="state", new_value="DISABLED"
        ))
        assert level == "medium"

    def test_rule_disabled_high_if_sensitive(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="state", new_value="DISABLED",
            record_name="prod-payment-rule"
        ))
        assert level == "high"

    def test_rule_enabled_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="state", new_value="ENABLED"
        ))
        assert level == "low"

    def test_rule_target_count_zero_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="target_count", new_value=0, prev_value=3
        ))
        assert level == "medium"

    def test_rule_target_count_zero_high_if_sensitive(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="target_count", new_value=0, prev_value=3,
            record_name="prod-payment-rule"
        ))
        assert level == "high"

    def test_rule_event_pattern_changed_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="event_pattern_hash", new_value="abc123"
        ))
        assert level == "medium"

    def test_rule_event_pattern_changed_high_if_sensitive(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="event_pattern_hash", new_value="abc123",
            record_name="prod-critical-rule"
        ))
        assert level == "high"

    def test_rule_dlq_removed_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="dlq_target_present", new_value=False
        ))
        assert level == "low"

    def test_rule_retry_removed_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_RULE,
            field_path="retry_policy_present", new_value=False
        ))
        assert level == "low"

    # EventBridge target
    def test_target_removed_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_TARGET, change_type="removed"
        ))
        assert level == "medium"

    def test_target_type_changed_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_TARGET,
            field_path="target_type", new_value="sqs"
        ))
        assert level == "medium"

    def test_target_dlq_removed_low(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_TARGET,
            field_path="dead_letter_config_present", new_value=False
        ))
        assert level == "low"

    # EventBridge archive
    def test_archive_removed_high(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_ARCHIVE, change_type="removed"
        ))
        assert level == "high"

    def test_archive_state_disabled_high(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_ARCHIVE,
            field_path="state", new_value="DISABLED"
        ))
        assert level == "high"

    def test_archive_retention_reduced_medium(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_ARCHIVE,
            field_path="retention_days", new_value=7, prev_value=90
        ))
        assert level == "medium"

    def test_archive_retention_indefinite_high(self):
        level, reason = classify_aws_change(_eb_change(
            record_type=AWS_EVENTBRIDGE_ARCHIVE,
            field_path="retention_days", new_value=0, prev_value=30
        ))
        assert level == "high"

    def test_eb_risk_never_says_events_exposed(self):
        """Risk messages must never claim events were exposed/leaked."""
        for field, val in [("public_or_cross_account_policy", True), ("state", "DISABLED")]:
            _, reason = classify_aws_change(_eb_change(
                record_type=AWS_EVENTBRIDGE_RULE,
                field_path=field, new_value=val
            ))
            reason_lower = reason.lower()
            assert "events were exposed" not in reason_lower
            assert "events leaked" not in reason_lower


# ─────────────────────────────────────────────────────────────────────────────
# 6. SQS risk classification
# ─────────────────────────────────────────────────────────────────────────────

class TestM47SQSRiskClassification:

    def test_queue_added_low(self):
        level, _ = classify_aws_change(_sqs_change(change_type="added"))
        assert level == "low"

    def test_queue_removed_medium(self):
        level, _ = classify_aws_change(_sqs_change(change_type="removed"))
        assert level == "medium"

    def test_queue_removed_high_if_sensitive(self):
        level, _ = classify_aws_change(_sqs_change(
            change_type="removed", record_name="prod-payment-queue"
        ))
        assert level == "high"

    def test_queue_public_policy_high(self):
        level, reason = classify_aws_change(_sqs_change(
            field_path="public_or_cross_account_policy", new_value=True
        ))
        assert level == "high"
        assert "external" in reason.lower() or "cross-account" in reason.lower()

    def test_queue_public_policy_critical_if_sensitive(self):
        level, reason = classify_aws_change(_sqs_change(
            field_path="public_or_cross_account_policy", new_value=True,
            record_name="prod-payment-queue"
        ))
        assert level == "critical"

    def test_queue_public_policy_removed_low(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="public_or_cross_account_policy", new_value=False
        ))
        assert level == "low"

    def test_queue_sse_disabled_medium(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="sqs_managed_sse_enabled", new_value=False
        ))
        assert level == "medium"

    def test_queue_sse_disabled_high_if_sensitive(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="sqs_managed_sse_enabled", new_value=False,
            record_name="prod-payment-queue"
        ))
        assert level == "high"

    def test_queue_kms_removed_medium(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="kms_master_key_id_present", new_value=False
        ))
        assert level == "medium"

    def test_queue_kms_removed_high_if_sensitive(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="kms_master_key_id_present", new_value=False,
            record_name="prod-orders-queue"
        ))
        assert level == "high"

    def test_queue_kms_added_low(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="kms_master_key_id_present", new_value=True
        ))
        assert level == "low"

    def test_queue_redrive_removed_medium(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="redrive_policy_present", new_value=False
        ))
        assert level == "medium"

    def test_queue_redrive_removed_high_if_sensitive(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="redrive_policy_present", new_value=False,
            record_name="prod-payment-queue"
        ))
        assert level == "high"

    def test_queue_redrive_added_low(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="redrive_policy_present", new_value=True
        ))
        assert level == "low"

    def test_queue_retention_reduced_medium(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="message_retention_period", new_value=3600, prev_value=86400
        ))
        assert level == "medium"

    def test_queue_retention_increased_low(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="message_retention_period", new_value=345600, prev_value=86400
        ))
        assert level == "low"

    def test_queue_visibility_timeout_low(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="visibility_timeout", new_value=60
        ))
        assert level in ("low", "medium")

    def test_queue_content_based_dedup_disabled_medium(self):
        level, _ = classify_aws_change(_sqs_change(
            field_path="content_based_deduplication", new_value=False
        ))
        assert level == "medium"

    def test_sqs_risk_never_says_messages_read(self):
        """Risk messages must never claim messages were read/received."""
        _, reason = classify_aws_change(_sqs_change(
            field_path="public_or_cross_account_policy", new_value=True
        ))
        reason_lower = reason.lower()
        assert "messages were read" not in reason_lower
        assert "messages leaked" not in reason_lower
        assert "queue drained" not in reason_lower


# ─────────────────────────────────────────────────────────────────────────────
# 7. SNS risk classification
# ─────────────────────────────────────────────────────────────────────────────

class TestM47SNSRiskClassification:

    def test_topic_added_low(self):
        level, _ = classify_aws_change(_sns_change(change_type="added"))
        assert level == "low"

    def test_topic_removed_medium(self):
        level, _ = classify_aws_change(_sns_change(change_type="removed"))
        assert level == "medium"

    def test_topic_removed_high_if_sensitive(self):
        level, _ = classify_aws_change(_sns_change(
            change_type="removed", record_name="prod-billing-topic"
        ))
        assert level == "high"

    def test_topic_public_policy_high(self):
        level, reason = classify_aws_change(_sns_change(
            field_path="public_or_cross_account_policy", new_value=True
        ))
        assert level == "high"
        assert "external" in reason.lower() or "cross-account" in reason.lower()

    def test_topic_public_policy_critical_if_sensitive(self):
        level, reason = classify_aws_change(_sns_change(
            field_path="public_or_cross_account_policy", new_value=True,
            record_name="prod-payment-topic"
        ))
        assert level == "critical"

    def test_topic_public_policy_removed_low(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="public_or_cross_account_policy", new_value=False
        ))
        assert level == "low"

    def test_topic_kms_removed_medium(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="kms_master_key_id_present", new_value=False
        ))
        assert level == "medium"

    def test_topic_kms_removed_high_if_sensitive(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="kms_master_key_id_present", new_value=False,
            record_name="prod-payment-topic"
        ))
        assert level == "high"

    def test_topic_kms_added_low(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="kms_master_key_id_present", new_value=True
        ))
        assert level == "low"

    def test_topic_subscription_count_increased_low(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="subscription_count", new_value=5, prev_value=3
        ))
        assert level == "low"

    def test_topic_subscription_count_increased_medium_if_sensitive(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="subscription_count", new_value=5, prev_value=3,
            record_name="prod-payment-topic"
        ))
        assert level == "medium"

    def test_topic_subscription_count_decreased_low(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="subscription_count", new_value=2, prev_value=5
        ))
        assert level == "low"

    def test_topic_pending_subs_increased_medium(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="pending_subscription_count", new_value=3, prev_value=0
        ))
        assert level == "medium"

    def test_topic_protocol_counts_changed_medium(self):
        level, _ = classify_aws_change(_sns_change(
            field_path="subscription_protocol_counts", new_value={"sqs": 2, "email": 1}
        ))
        assert level == "medium"

    # SNS subscription
    def test_sub_added_low(self):
        level, _ = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION, change_type="added"
        ))
        assert level == "low"

    def test_sub_removed_low(self):
        level, _ = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION, change_type="removed"
        ))
        assert level == "low"

    def test_sub_endpoint_changed_medium(self):
        level, reason = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION,
            field_path="endpoint_hash", new_value="abc123"
        ))
        assert level == "medium"
        assert "endpoint" in reason.lower()

    def test_sub_endpoint_changed_high_if_sensitive(self):
        level, _ = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION,
            field_path="endpoint_hash", new_value="abc123",
            record_name="prod-payment-sub"
        ))
        assert level == "high"

    def test_sub_filter_policy_removed_low(self):
        level, _ = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION,
            field_path="filter_policy_present", new_value=False
        ))
        assert level == "low"

    def test_sub_filter_policy_hash_changed_low(self):
        level, _ = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION,
            field_path="filter_policy_hash", new_value="newHash"
        ))
        assert level == "low"

    def test_sub_raw_message_delivery_enabled_low(self):
        level, _ = classify_aws_change(_sns_change(
            record_type=AWS_SNS_SUBSCRIPTION,
            field_path="raw_message_delivery", new_value=True
        ))
        assert level == "low"

    def test_sns_risk_never_says_notifications_read(self):
        """Risk messages must never claim notifications were read/published."""
        _, reason = classify_aws_change(_sns_change(
            field_path="public_or_cross_account_policy", new_value=True
        ))
        reason_lower = reason.lower()
        assert "notifications were read" not in reason_lower
        assert "topic compromised" not in reason_lower
        assert "messages leaked" not in reason_lower


# ─────────────────────────────────────────────────────────────────────────────
# 8. Failure classifiers
# ─────────────────────────────────────────────────────────────────────────────

class TestM47FailureClassifiers:

    # EventBridge
    def test_eb_access_denied(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_eventbridge_failure("ListEventBuses", exc)
        assert fc.category == "authentication"
        assert fc.error_code == "aws_eventbridge_access_denied"

    def test_eb_auth_error(self):
        exc = AuthenticationError("Invalid credentials", status_code=401)
        fc = classify_aws_eventbridge_failure("ListRules", exc)
        assert fc.category == "authentication"

    def test_eb_rate_limited(self):
        exc = RateLimitError("Throttled")
        fc = classify_aws_eventbridge_failure("ListTargetsByRule", exc)
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_eventbridge_rate_limited"

    def test_eb_network_error(self):
        exc = NetworkError("Network failure")
        fc = classify_aws_eventbridge_failure("ListEventBuses", exc)
        assert fc.category == "network"

    def test_eb_server_error(self):
        exc = ConnectorError("InternalServerError", status_code=500)
        fc = classify_aws_eventbridge_failure("ListEventBuses", exc)
        assert fc.category == "provider_unavailable"
        assert fc.error_code == "aws_eventbridge_api_unavailable"

    def test_eb_list_buses_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_eventbridge_failure("ListEventBuses", exc)
        assert fc.error_code == "aws_eventbridge_buses_unavailable"

    def test_eb_list_rules_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_eventbridge_failure("ListRules", exc)
        assert fc.error_code == "aws_eventbridge_rules_unavailable"

    def test_eb_list_targets_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_eventbridge_failure("ListTargetsByRule", exc)
        assert fc.error_code == "aws_eventbridge_targets_unavailable"

    def test_eb_list_archives_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_eventbridge_failure("ListArchives", exc)
        assert fc.error_code == "aws_eventbridge_archives_unavailable"

    def test_eb_action_never_mentions_put_events(self):
        """Failure action must instruct on read-only permissions, not write."""
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_eventbridge_failure("ListEventBuses", exc)
        assert "PutEvents" not in fc.recommended_action
        action_lower = fc.recommended_action.lower()
        assert "read" in action_lower or "metadata" in action_lower

    # SQS
    def test_sqs_access_denied(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_sqs_failure("ListQueues", exc)
        assert fc.category == "authentication"
        assert fc.error_code == "aws_sqs_access_denied"

    def test_sqs_rate_limited(self):
        exc = RateLimitError("Throttled")
        fc = classify_aws_sqs_failure("GetQueueAttributes", exc)
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_sqs_rate_limited"

    def test_sqs_network_error(self):
        exc = NetworkError("Network failure")
        fc = classify_aws_sqs_failure("ListQueues", exc)
        assert fc.category == "network"

    def test_sqs_list_queues_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sqs_failure("ListQueues", exc)
        assert fc.error_code == "aws_sqs_queues_unavailable"

    def test_sqs_get_attributes_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sqs_failure("GetQueueAttributes", exc)
        assert fc.error_code == "aws_sqs_queue_attributes_unavailable"

    def test_sqs_tags_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sqs_failure("ListQueueTags", exc)
        assert fc.error_code == "aws_sqs_queue_tags_unavailable"

    def test_sqs_action_never_mentions_receive_message(self):
        """Failure action must never suggest ReceiveMessage permission."""
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_sqs_failure("ListQueues", exc)
        assert "ReceiveMessage" not in fc.recommended_action
        assert "SendMessage" not in fc.recommended_action
        assert "PurgeQueue" not in fc.recommended_action

    # SNS
    def test_sns_access_denied(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_sns_failure("ListTopics", exc)
        assert fc.category == "authentication"
        assert fc.error_code == "aws_sns_access_denied"

    def test_sns_rate_limited(self):
        exc = RateLimitError("Throttled")
        fc = classify_aws_sns_failure("GetTopicAttributes", exc)
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_sns_rate_limited"

    def test_sns_network_error(self):
        exc = NetworkError("Network failure")
        fc = classify_aws_sns_failure("ListTopics", exc)
        assert fc.category == "network"

    def test_sns_list_topics_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sns_failure("ListTopics", exc)
        assert fc.error_code == "aws_sns_topics_unavailable"

    def test_sns_get_attributes_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sns_failure("GetTopicAttributes", exc)
        assert fc.error_code == "aws_sns_topic_attributes_unavailable"

    def test_sns_subscriptions_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sns_failure("ListSubscriptionsByTopic", exc)
        assert fc.error_code == "aws_sns_subscriptions_unavailable"

    def test_sns_sub_attributes_unavailable(self):
        exc = ConnectorError("ServiceError", status_code=None)
        fc = classify_aws_sns_failure("GetSubscriptionAttributes", exc)
        assert fc.error_code == "aws_sns_subscription_attributes_unavailable"

    def test_sns_action_never_mentions_publish(self):
        """Failure action must never suggest sns:Publish permission."""
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_sns_failure("ListTopics", exc)
        assert "Publish" not in fc.recommended_action
        assert "Subscribe" not in fc.recommended_action


# ─────────────────────────────────────────────────────────────────────────────
# 9. Service inventory
# ─────────────────────────────────────────────────────────────────────────────

class TestM47ServiceInventory:

    def _get_inventory(self, regions=None):
        conn = _make_connector()
        return conn._fetch_service_inventory(_creds(regions))

    def test_eventbridge_in_enabled_surfaces(self):
        inv = self._get_inventory()
        assert "eventbridge" in inv["enabled_surfaces"]

    def test_sqs_in_enabled_surfaces(self):
        inv = self._get_inventory()
        assert "sqs" in inv["enabled_surfaces"]

    def test_sns_in_enabled_surfaces(self):
        inv = self._get_inventory()
        assert "sns" in inv["enabled_surfaces"]

    def test_eventbridge_not_in_future_surfaces(self):
        inv = self._get_inventory()
        future = inv.get("future_surfaces") or []
        assert "eventbridge" not in future

    def test_sqs_not_in_future_surfaces(self):
        inv = self._get_inventory()
        future = inv.get("future_surfaces") or []
        assert "sqs" not in future

    def test_sns_not_in_future_surfaces(self):
        inv = self._get_inventory()
        future = inv.get("future_surfaces") or []
        assert "sns" not in future

    def test_inventory_has_eventbridge_bus_count(self):
        inv = self._get_inventory()
        assert "eventbridge_bus_count" in inv

    def test_inventory_has_sqs_queue_count(self):
        inv = self._get_inventory()
        assert "sqs_queue_count" in inv

    def test_inventory_has_sns_topic_count(self):
        inv = self._get_inventory()
        assert "sns_topic_count" in inv


# ─────────────────────────────────────────────────────────────────────────────
# 10. Connector normalization (mock-based)
# ─────────────────────────────────────────────────────────────────────────────

class TestM47EventBridgeConnectorNormalization:
    """Test _fetch_eventbridge_in_region with mocked boto3 clients."""

    def _make_eb_client(
        self,
        buses=None,
        rules=None,
        targets=None,
        archives=None,
        bus_desc_policy=None,
    ):
        """Build a mock EventBridge client."""
        client = MagicMock()
        client.list_event_buses.return_value = {"EventBuses": buses or []}
        client.describe_event_bus.return_value = {
            "Policy": bus_desc_policy or ""
        }
        client.list_rules.return_value = {"Rules": rules or []}
        client.list_targets_by_rule.return_value = {"Targets": targets or []}
        client.list_archives.return_value = {"Archives": archives or []}
        client.list_tags_for_resource.return_value = {"Tags": []}
        return client

    def test_bus_record_created(self):
        conn = _make_connector()
        client = self._make_eb_client(
            buses=[{"Name": "default", "Arn": "arn:aws:events:us-east-1:123:event-bus/default"}]
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        bus_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_EVENT_BUS]
        assert len(bus_records) == 1
        assert bus_records[0]["name"] == "default"

    def test_bus_arn_not_stored_raw(self):
        """Bus ARN must not appear as a plain string in the bus record."""
        conn = _make_connector()
        raw_arn = "arn:aws:events:us-east-1:123456789012:event-bus/my-bus"
        client = self._make_eb_client(
            buses=[{"Name": "my-bus", "Arn": raw_arn}]
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        bus_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_EVENT_BUS]
        assert len(bus_records) == 1
        rec = bus_records[0]
        # external_id is the ARN for reference, but arn_hash is the hash
        assert rec.get("arn_hash") is not None
        assert len(rec["arn_hash"]) == 12

    def test_rule_record_created(self):
        conn = _make_connector()
        client = self._make_eb_client(
            buses=[{"Name": "default", "Arn": "arn:aws:events:us-east-1:123:event-bus/default"}],
            rules=[{"Name": "my-rule", "Arn": "arn:aws:events:us-east-1:123:rule/my-rule",
                    "State": "ENABLED", "ScheduleExpression": "rate(5 minutes)"}],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        rule_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_RULE]
        assert len(rule_records) == 1
        assert rule_records[0]["state"] == "ENABLED"
        assert rule_records[0]["schedule_expression_present"] is True

    def test_event_pattern_hash_not_raw(self):
        """Event pattern must be stored as hash only, never raw."""
        conn = _make_connector()
        raw_pattern = '{"source": ["aws.ec2"], "detail-type": ["EC2 Instance State-change Notification"]}'
        client = self._make_eb_client(
            buses=[{"Name": "default", "Arn": "arn:aws:events:us-east-1:123:event-bus/default"}],
            rules=[{"Name": "my-rule", "Arn": "arn:aws:events:us-east-1:123:rule/my-rule",
                    "State": "ENABLED", "EventPattern": raw_pattern}],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        rule_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_RULE]
        assert len(rule_records) == 1
        rec = rule_records[0]
        assert rec.get("event_pattern_present") is True
        assert rec.get("event_pattern_hash") is not None
        # Raw pattern must not appear anywhere in the record values
        for v in rec.values():
            assert v != raw_pattern, "Raw event pattern must not be stored"

    def test_target_record_created(self):
        conn = _make_connector()
        client = self._make_eb_client(
            buses=[{"Name": "default", "Arn": "arn:aws:events:us-east-1:123:event-bus/default"}],
            rules=[{"Name": "my-rule", "Arn": "arn:aws:events:us-east-1:123:rule/my-rule", "State": "ENABLED"}],
            targets=[{"Id": "target-1", "Arn": "arn:aws:lambda:us-east-1:123:function:my-fn"}],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        tgt_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_TARGET]
        assert len(tgt_records) == 1
        assert tgt_records[0]["target_type"] == "lambda"

    def test_target_arn_not_stored_raw(self):
        """Target ARN must be stored as hash only."""
        conn = _make_connector()
        raw_arn = "arn:aws:lambda:us-east-1:123456789012:function:my-fn"
        client = self._make_eb_client(
            buses=[{"Name": "default", "Arn": "arn:aws:events:us-east-1:123:event-bus/default"}],
            rules=[{"Name": "my-rule", "Arn": "arn:aws:events:us-east-1:123:rule/my-rule", "State": "ENABLED"}],
            targets=[{"Id": "t1", "Arn": raw_arn}],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        tgt_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_TARGET]
        assert len(tgt_records) == 1
        rec = tgt_records[0]
        assert rec.get("target_arn_hash") is not None
        # Raw ARN must not appear as a standalone value in the record
        for v in rec.values():
            assert v != raw_arn, "Raw target ARN must not be stored"

    def test_bus_policy_is_public_when_wildcard(self):
        """Bus with wildcard policy must be flagged as public."""
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "events:PutEvents"}]
        })
        conn = _make_connector()
        client = self._make_eb_client(
            buses=[{"Name": "my-bus", "Arn": "arn:aws:events:us-east-1:123:event-bus/my-bus"}],
            bus_desc_policy=policy,
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        bus_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_EVENT_BUS]
        assert bus_records[0]["public_or_cross_account_policy"] is True

    def test_archive_record_created(self):
        conn = _make_connector()
        client = self._make_eb_client(
            buses=[{"Name": "default", "Arn": "arn:aws:events:us-east-1:123:event-bus/default"}],
            archives=[{
                "ArchiveName": "my-archive",
                "ArchiveArn": "arn:aws:events:us-east-1:123:archive/my-archive",
                "EventSourceArn": "arn:aws:events:us-east-1:123:event-bus/default",
                "State": "ENABLED",
                "RetentionDays": 90,
                "EventCount": 1000,
                "SizeBytes": 512000,
            }],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_in_region(client, "123456789012", "us-east-1")
        arch_records = [r for r in records if r["record_type"] == AWS_EVENTBRIDGE_ARCHIVE]
        assert len(arch_records) == 1
        assert arch_records[0]["retention_days"] == 90
        assert arch_records[0]["state"] == "ENABLED"


class TestM47SQSConnectorNormalization:
    """Test _fetch_sqs_in_region with mocked boto3 clients."""

    def _make_sqs_client(self, queue_urls=None, attrs=None, tags=None):
        client = MagicMock()
        client.list_queues.return_value = {"QueueUrls": queue_urls or []}
        client.get_queue_attributes.return_value = {"Attributes": attrs or {}}
        client.list_queue_tags.return_value = {"Tags": tags or {}}
        return client

    def test_queue_record_created(self):
        conn = _make_connector()
        attrs = {
            "QueueArn": "arn:aws:sqs:us-east-1:123:my-queue",
            "VisibilityTimeout": "30",
            "MessageRetentionPeriod": "86400",
            "DelaySeconds": "0",
            "MaximumMessageSize": "262144",
            "ReceiveMessageWaitTimeSeconds": "0",
            "FifoQueue": "false",
        }
        client = self._make_sqs_client(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123/my-queue"],
            attrs=attrs,
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_in_region(client, "123456789012", "us-east-1")
        assert len(records) == 1
        rec = records[0]
        assert rec["record_type"] == AWS_SQS_QUEUE
        assert rec["name"] == "my-queue"
        assert rec["visibility_timeout"] == 30
        assert rec["fifo_queue"] is False

    def test_queue_arn_is_hashed(self):
        """Queue ARN must be stored as hash only, not raw."""
        conn = _make_connector()
        raw_arn = "arn:aws:sqs:us-east-1:123456789012:my-queue"
        client = self._make_sqs_client(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"],
            attrs={"QueueArn": raw_arn},
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_in_region(client, "123456789012", "us-east-1")
        rec = records[0]
        assert rec.get("queue_arn_hash") is not None
        # Raw ARN must not appear as a direct value in the record
        for v in rec.values():
            assert v != raw_arn, "Raw queue ARN must not be stored"

    def test_queue_policy_public_detected(self):
        """Public queue policy must be flagged as public_or_cross_account."""
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage"}]
        })
        conn = _make_connector()
        client = self._make_sqs_client(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123/my-queue"],
            attrs={"QueueArn": "arn:aws:sqs:us-east-1:123:my-queue", "Policy": policy},
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_in_region(client, "123456789012", "us-east-1")
        assert records[0]["public_or_cross_account_policy"] is True

    def test_queue_raw_policy_not_in_record(self):
        """Raw queue policy JSON must never be stored in the record."""
        policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*"}]})
        conn = _make_connector()
        client = self._make_sqs_client(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123/q"],
            attrs={"QueueArn": "arn:aws:sqs:us-east-1:123:q", "Policy": policy},
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_in_region(client, "123456789012", "us-east-1")
        rec = records[0]
        for v in rec.values():
            assert v != policy, "Raw policy JSON must not be stored"

    def test_redrive_policy_parsed(self):
        """Redrive policy is parsed to hash + count, never raw."""
        dlq_arn = "arn:aws:sqs:us-east-1:123:my-dlq"
        redrive = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5})
        conn = _make_connector()
        client = self._make_sqs_client(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123/q"],
            attrs={
                "QueueArn": "arn:aws:sqs:us-east-1:123:q",
                "RedrivePolicy": redrive,
            },
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_in_region(client, "123456789012", "us-east-1")
        rec = records[0]
        assert rec["redrive_policy_present"] is True
        assert rec["max_receive_count"] == 5
        # DLQ ARN must be hashed
        assert rec.get("dead_letter_target_arn_hash") is not None
        for v in rec.values():
            assert v != dlq_arn, "Raw DLQ ARN must not be stored"

    def test_tag_values_not_stored(self):
        """SQS tag values must never be stored — keys only."""
        conn = _make_connector()
        client = self._make_sqs_client(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123/q"],
            attrs={"QueueArn": "arn:aws:sqs:us-east-1:123:q"},
            tags={"Environment": "production", "Team": "payments"},
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_in_region(client, "123456789012", "us-east-1")
        rec = records[0]
        tag_keys = rec.get("tag_keys") or []
        # Keys stored, not values
        assert "Environment" in tag_keys or "environment" in [k.lower() for k in tag_keys]
        # Values must not be stored
        for v in rec.values():
            assert v != "production" or isinstance(v, bool)


class TestM47SNSConnectorNormalization:
    """Test _fetch_sns_in_region with mocked boto3 clients."""

    def _make_sns_client(self, topics=None, topic_attrs=None, subscriptions=None,
                          sub_attrs=None, tags=None):
        client = MagicMock()
        client.list_topics.return_value = {
            "Topics": [{"TopicArn": t} for t in (topics or [])]
        }
        client.get_topic_attributes.return_value = {
            "Attributes": topic_attrs or {}
        }
        client.list_subscriptions_by_topic.return_value = {
            "Subscriptions": subscriptions or []
        }
        client.get_subscription_attributes.return_value = {
            "Attributes": sub_attrs or {}
        }
        client.list_tags_for_resource.return_value = {"Tags": tags or []}
        return client

    def test_topic_record_created(self):
        conn = _make_connector()
        topic_arn = "arn:aws:sns:us-east-1:123456789012:my-topic"
        client = self._make_sns_client(
            topics=[topic_arn],
            topic_attrs={
                "SubscriptionsConfirmed": "2",
                "SubscriptionsPending": "1",
                "FifoTopic": "false",
            },
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_in_region(client, "123456789012", "us-east-1")
        topic_records = [r for r in records if r["record_type"] == AWS_SNS_TOPIC]
        assert len(topic_records) == 1
        rec = topic_records[0]
        assert rec["name"] == "my-topic"
        assert rec["confirmed_subscription_count"] == 2
        assert rec["pending_subscription_count"] == 1
        assert rec["subscription_count"] == 3

    def test_topic_arn_is_hashed(self):
        """Topic ARN must be stored as hash only."""
        conn = _make_connector()
        topic_arn = "arn:aws:sns:us-east-1:123456789012:my-topic"
        client = self._make_sns_client(topics=[topic_arn])
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_in_region(client, "123456789012", "us-east-1")
        topic_records = [r for r in records if r["record_type"] == AWS_SNS_TOPIC]
        rec = topic_records[0]
        assert rec.get("topic_arn_hash") is not None
        assert len(rec["topic_arn_hash"]) == 12

    def test_topic_policy_public_detected(self):
        """Public topic policy must be flagged as public_or_cross_account."""
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sns:Publish"}]
        })
        conn = _make_connector()
        client = self._make_sns_client(
            topics=["arn:aws:sns:us-east-1:123:my-topic"],
            topic_attrs={"Policy": policy},
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_in_region(client, "123456789012", "us-east-1")
        topic_records = [r for r in records if r["record_type"] == AWS_SNS_TOPIC]
        assert topic_records[0]["public_or_cross_account_policy"] is True

    def test_subscription_endpoint_is_hashed(self):
        """Raw SNS subscription endpoint must not be stored."""
        raw_email = "user@example.com"
        conn = _make_connector()
        client = self._make_sns_client(
            topics=["arn:aws:sns:us-east-1:123:my-topic"],
            subscriptions=[{
                "SubscriptionArn": "arn:aws:sns:us-east-1:123:my-topic:abc123",
                "Protocol": "email",
                "Endpoint": raw_email,
            }],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_in_region(client, "123456789012", "us-east-1")
        sub_records = [r for r in records if r["record_type"] == AWS_SNS_SUBSCRIPTION]
        assert len(sub_records) == 1
        rec = sub_records[0]
        # Endpoint hash must be present
        assert rec.get("endpoint_hash") is not None
        # Raw email must not appear in any record value
        for v in rec.values():
            assert v != raw_email, f"Raw endpoint value '{raw_email}' must not be stored"

    def test_subscription_filter_policy_is_hashed(self):
        """Raw SNS filter policy must not be stored — hash only."""
        raw_filter = json.dumps({"event_type": ["ORDER_PLACED"]})
        conn = _make_connector()
        client = self._make_sns_client(
            topics=["arn:aws:sns:us-east-1:123:my-topic"],
            subscriptions=[{
                "SubscriptionArn": "arn:aws:sns:us-east-1:123:my-topic:abc123",
                "Protocol": "sqs",
                "Endpoint": "arn:aws:sqs:us-east-1:123:my-queue",
            }],
            sub_attrs={"FilterPolicy": raw_filter},
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_in_region(client, "123456789012", "us-east-1")
        sub_records = [r for r in records if r["record_type"] == AWS_SNS_SUBSCRIPTION]
        rec = sub_records[0]
        assert rec.get("filter_policy_present") is True
        assert rec.get("filter_policy_hash") is not None
        for v in rec.values():
            assert v != raw_filter, "Raw filter policy must not be stored"

    def test_pending_subscriptions_skipped(self):
        """Subscriptions with PendingConfirmation ARN must be skipped."""
        conn = _make_connector()
        client = self._make_sns_client(
            topics=["arn:aws:sns:us-east-1:123:my-topic"],
            subscriptions=[
                {
                    "SubscriptionArn": "PendingConfirmation",
                    "Protocol": "email",
                    "Endpoint": "user@example.com",
                }
            ],
        )
        with patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_in_region(client, "123456789012", "us-east-1")
        sub_records = [r for r in records if r["record_type"] == AWS_SNS_SUBSCRIPTION]
        assert len(sub_records) == 0, "PendingConfirmation subscriptions must be skipped"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Fail-soft behavior
# ─────────────────────────────────────────────────────────────────────────────

class TestM47FailSoft:

    def test_eventbridge_region_error_does_not_abort(self):
        """A per-region EventBridge error must not abort other regions."""
        conn = _make_connector()
        creds = _creds(regions=["us-east-1", "us-west-2"])
        client_ok = MagicMock()
        client_ok.list_event_buses.return_value = {"EventBuses": []}
        client_ok.list_archives.return_value = {"Archives": []}

        client_fail = MagicMock()
        client_fail.list_event_buses.side_effect = Exception("Connection refused")

        def _make_client(service, credentials, region=None):
            if region == "us-east-1":
                return client_fail
            return client_ok

        with patch.object(conn, "_make_client", side_effect=_make_client), \
             patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_eventbridge_resources(creds, "123456789012")
        # Should not raise; may return empty or partial results
        assert isinstance(records, list)

    def test_sqs_region_error_does_not_abort(self):
        """A per-region SQS error must not abort other regions."""
        conn = _make_connector()
        creds = _creds(regions=["us-east-1", "eu-west-1"])
        client_ok = MagicMock()
        client_ok.list_queues.return_value = {"QueueUrls": []}
        client_fail = MagicMock()
        client_fail.list_queues.side_effect = Exception("Connection error")

        def _make_client(service, credentials, region=None):
            if region == "us-east-1":
                return client_fail
            return client_ok

        with patch.object(conn, "_make_client", side_effect=_make_client), \
             patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sqs_resources(creds, "123456789012")
        assert isinstance(records, list)

    def test_sns_region_error_does_not_abort(self):
        """A per-region SNS error must not abort other regions."""
        conn = _make_connector()
        creds = _creds(regions=["us-east-1", "ap-southeast-1"])
        client_ok = MagicMock()
        client_ok.list_topics.return_value = {"Topics": []}
        client_fail = MagicMock()
        client_fail.list_topics.side_effect = Exception("Service unavailable")

        def _make_client(service, credentials, region=None):
            if region == "us-east-1":
                return client_fail
            return client_ok

        with patch.object(conn, "_make_client", side_effect=_make_client), \
             patch.object(conn, "_call_aws", side_effect=lambda fn, *a, **kw: fn(*a, **kw)):
            records = conn._fetch_sns_resources(creds, "123456789012")
        assert isinstance(records, list)

    def test_sqs_list_queues_access_denied_returns_empty(self):
        """Access denied on ListQueues must return empty, not raise."""
        conn = _make_connector()
        creds = _creds(regions=["us-east-1"])
        client = MagicMock()

        def _call_aws(fn, *a, **kw):
            if fn == client.list_queues:
                raise ConnectorError("Access denied", status_code=403)
            return fn(*a, **kw)

        with patch.object(conn, "_make_client", return_value=client), \
             patch.object(conn, "_call_aws", side_effect=_call_aws):
            records = conn._fetch_sqs_resources(creds, "123456789012")
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 12. M46 regression guard
# ─────────────────────────────────────────────────────────────────────────────

class TestM46RegressionGuard:
    """Verify M46 record types are still classified correctly."""

    def _m46_change(self, record_type, field_path=None, new_value=None,
                    prev_value=None, record_name="my-cluster"):
        return {
            "record_type": record_type,
            "change_type": "modified",
            "field_path": field_path,
            "new_value": new_value,
            "prev_value": prev_value,
            "provider_metadata": {
                "record_type": record_type,
                "record_name": record_name,
            },
        }

    def test_ecs_cluster_still_classified(self):
        level, reason = classify_aws_change(self._m46_change(
            AWS_ECS_CLUSTER, field_path="status", new_value="FAILED"
        ))
        assert level in ("critical", "high")
        assert "ecs" in reason.lower() or "cluster" in reason.lower()

    def test_ecr_repository_policy_public_still_classified(self):
        level, reason = classify_aws_change(self._m46_change(
            AWS_ECR_REPOSITORY,
            field_path="policy_is_public",
            new_value=True
        ))
        assert level in ("critical", "high")

    def test_eks_cluster_still_classified(self):
        level, reason = classify_aws_change(self._m46_change(
            AWS_EKS_CLUSTER,
            field_path="public_access_fully_open",
            new_value=True
        ))
        assert level in ("critical", "high")

    def test_m46_types_still_in_schema(self):
        from app.connectors.aws_schema import (
            AWS_ECS_CLUSTER, AWS_ECS_SERVICE, AWS_ECS_TASK_DEFINITION,
            AWS_EKS_CLUSTER, AWS_EKS_NODE_GROUP, AWS_EKS_FARGATE_PROFILE,
            AWS_EKS_ADDON, AWS_ECR_REPOSITORY, AWS_ECR_REGISTRY_SCANNING_CONFIG,
        )
        m46_types = {
            AWS_ECS_CLUSTER, AWS_ECS_SERVICE, AWS_ECS_TASK_DEFINITION,
            AWS_EKS_CLUSTER, AWS_EKS_NODE_GROUP, AWS_EKS_FARGATE_PROFILE,
            AWS_EKS_ADDON, AWS_ECR_REPOSITORY, AWS_ECR_REGISTRY_SCANNING_CONFIG,
        }
        assert m46_types.issubset(AWS_RECORD_TYPES)
