"""Tests for Milestone 43: AWS Lambda + API Gateway Runtime/API Config.

Covers:
- Security hard rules: no code download; env var values never stored; no write APIs
- Module-level helpers (_classify_lambda_name_sensitivity, _lambda_env_key_info,
  _lambda_event_source_type)
- Schema registration: all 8 M43 types in AWS_RECORD_TYPES
- Diff service tracked field registration for all 8 M43 types
- Risk classification: aws_lambda_function (full matrix)
- Risk classification: aws_lambda_alias
- Risk classification: aws_lambda_event_source_mapping
- Risk classification: aws_lambda_function_url (auth_type=NONE critical)
- Risk classification: aws_apigateway_rest_api
- Risk classification: aws_apigateway_rest_stage
- Risk classification: aws_apigatewayv2_api
- Risk classification: aws_apigatewayv2_stage
- Failure classification: classify_aws_lambda_failure + classify_aws_apigateway_failure
- Connector normalization: _fetch_lambda_in_region, _fetch_apigateway_in_region,
  _fetch_apigatewayv2_in_region
- Service inventory: lambda + api_gateway in enabled_surfaces, counts stored
- Fail-soft: per-region errors do not abort the full fetch
- M42 regression guard
"""

import pytest
from unittest.mock import MagicMock, patch

from app.connectors.aws import (
    AWSConnector,
    _classify_lambda_name_sensitivity,
    _lambda_env_key_info,
    _lambda_event_source_type,
    _hash_kms_key_id,
)
from app.connectors.aws_schema import (
    AWS_LAMBDA_FUNCTION,
    AWS_LAMBDA_ALIAS,
    AWS_LAMBDA_EVENT_SOURCE_MAPPING,
    AWS_LAMBDA_FUNCTION_URL,
    AWS_APIGATEWAY_REST_API,
    AWS_APIGATEWAY_REST_STAGE,
    AWS_APIGATEWAYV2_API,
    AWS_APIGATEWAYV2_STAGE,
    AWS_SERVICE_INVENTORY,
    AWS_RDS_DB_INSTANCE,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_lambda_failure,
    classify_aws_apigateway_failure,
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


def _lambda_change(
    record_type=AWS_LAMBDA_FUNCTION,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-function",
):
    """Build a minimal Lambda/API change dict for classify_aws_change."""
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
# 1. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

class TestM43Schema:
    def test_all_m43_types_in_record_types(self):
        for rt in (
            AWS_LAMBDA_FUNCTION,
            AWS_LAMBDA_ALIAS,
            AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            AWS_LAMBDA_FUNCTION_URL,
            AWS_APIGATEWAY_REST_API,
            AWS_APIGATEWAY_REST_STAGE,
            AWS_APIGATEWAYV2_API,
            AWS_APIGATEWAYV2_STAGE,
        ):
            assert rt in AWS_RECORD_TYPES, f"{rt} missing from AWS_RECORD_TYPES"

    def test_m43_string_values(self):
        assert AWS_LAMBDA_FUNCTION == "aws_lambda_function"
        assert AWS_LAMBDA_ALIAS == "aws_lambda_alias"
        assert AWS_LAMBDA_EVENT_SOURCE_MAPPING == "aws_lambda_event_source_mapping"
        assert AWS_LAMBDA_FUNCTION_URL == "aws_lambda_function_url"
        assert AWS_APIGATEWAY_REST_API == "aws_apigateway_rest_api"
        assert AWS_APIGATEWAY_REST_STAGE == "aws_apigateway_rest_stage"
        assert AWS_APIGATEWAYV2_API == "aws_apigatewayv2_api"
        assert AWS_APIGATEWAYV2_STAGE == "aws_apigatewayv2_stage"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestLambdaNameSensitivity:
    def test_production_category(self):
        assert _classify_lambda_name_sensitivity("prod-handler") == "production"
        assert _classify_lambda_name_sensitivity("live-payment-processor") == "production"

    def test_auth_category(self):
        assert _classify_lambda_name_sensitivity("auth-token-validator") == "auth"
        assert _classify_lambda_name_sensitivity("oauth-callback") == "auth"

    def test_payment_category(self):
        assert _classify_lambda_name_sensitivity("stripe-webhook") == "payment"
        assert _classify_lambda_name_sensitivity("billing-processor") == "payment"

    def test_admin_category(self):
        assert _classify_lambda_name_sensitivity("admin-dashboard-api") == "admin"

    def test_none_category(self):
        assert _classify_lambda_name_sensitivity("hello-world") == "none"
        assert _classify_lambda_name_sensitivity("test-function") == "none"

    def test_case_insensitive(self):
        result = _classify_lambda_name_sensitivity("PROD-API-HANDLER")
        assert result != "none"

    def test_empty_string(self):
        assert _classify_lambda_name_sensitivity("") == "none"


class TestLambdaEnvKeyInfo:
    def test_returns_key_names_count_sensitive_count(self):
        env = {"DATABASE_URL": "postgres://...", "SECRET_KEY": "abc", "LOG_LEVEL": "info"}
        key_names, count, sensitive_count = _lambda_env_key_info(env)
        assert count == 3
        assert "DATABASE_URL" in key_names
        assert "SECRET_KEY" in key_names
        assert "LOG_LEVEL" in key_names
        # Key names are returned, count and sensitive_count are ints
        assert isinstance(sensitive_count, int)
        assert sensitive_count >= 0

    def test_never_returns_values(self):
        """SECURITY: env var values must NEVER be accessible from _lambda_env_key_info output."""
        env = {
            "MY_SECRET": "SUPER_SECRET_VALUE_12345",
            "API_KEY": "live_secret_api_key_xyz",
            "DB_PASSWORD": "my-database-password",
        }
        key_names, count, sensitive_count = _lambda_env_key_info(env)
        # Values must never appear in key_names list or any output
        result_str = str(key_names) + str(count) + str(sensitive_count)
        assert "SUPER_SECRET_VALUE_12345" not in result_str
        assert "live_secret_api_key_xyz" not in result_str
        assert "my-database-password" not in result_str

    def test_empty_env(self):
        key_names, count, sensitive_count = _lambda_env_key_info({})
        assert key_names == []
        assert count == 0
        assert sensitive_count == 0

    def test_none_env(self):
        key_names, count, sensitive_count = _lambda_env_key_info(None)
        assert key_names == []
        assert count == 0
        assert sensitive_count == 0

    def test_key_names_sorted(self):
        env = {"Z_KEY": "v", "A_KEY": "v", "M_KEY": "v"}
        key_names, _, _ = _lambda_env_key_info(env)
        assert key_names == sorted(key_names)

    def test_sensitive_key_detection(self):
        env = {
            "PASSWORD": "value",
            "SECRET": "value",
            "API_TOKEN": "value",
            "LOG_LEVEL": "info",
        }
        _, _, sensitive_count = _lambda_env_key_info(env)
        # Should detect at least the secret-sounding keys
        assert sensitive_count >= 2


class TestLambdaEventSourceType:
    def test_dynamodb_stream(self):
        arn = "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable/stream/2024"
        assert _lambda_event_source_type(arn) == "dynamodb"

    def test_sqs_queue(self):
        arn = "arn:aws:sqs:us-east-1:123456789012:my-queue"
        assert _lambda_event_source_type(arn) == "sqs"

    def test_kinesis_stream(self):
        arn = "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream"
        assert _lambda_event_source_type(arn) == "kinesis"

    def test_unknown(self):
        arn = "arn:aws:s3:::my-bucket"
        result = _lambda_event_source_type(arn)
        assert isinstance(result, str)
        # Should return something, even if just "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestM43DiffServiceFields:
    def test_lambda_function_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_LAMBDA_FUNCTION})
        assert fields is not None
        # Security fields
        assert "role_arn_present" in fields
        assert "role_arn_hash" in fields
        assert "kms_key_arn_present" in fields
        assert "kms_key_arn_hash" in fields
        # Env var key names (NEVER values)
        assert "environment_key_names" in fields
        assert "environment_key_count" in fields
        assert "environment_sensitive_key_count" in fields
        # VPC
        assert "vpc_config_present" in fields
        # Runtime / config
        assert "runtime" in fields
        assert "reserved_concurrent_executions" in fields
        assert "tracing_mode" in fields
        # Must NOT track raw execution role ARN, deployment package URL, or env values
        assert "role_arn" not in fields
        assert "code_location" not in fields

    def test_lambda_alias_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_LAMBDA_ALIAS})
        assert fields is not None
        assert "function_version" in fields
        assert "routing_config_present" in fields

    def test_lambda_esm_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_LAMBDA_EVENT_SOURCE_MAPPING})
        assert fields is not None
        assert "state" in fields
        assert "enabled" in fields
        assert "event_source_arn_hash" in fields
        assert "batch_size" in fields
        # Must NOT store raw event source ARN
        assert "event_source_arn" not in fields

    def test_lambda_function_url_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_LAMBDA_FUNCTION_URL})
        assert fields is not None
        assert "auth_type" in fields
        assert "cors_wildcard_origin_present" in fields
        assert "cors_allow_credentials" in fields
        # Must not store raw function URL
        assert "function_url" not in fields
        assert "url" not in fields

    def test_rest_api_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_APIGATEWAY_REST_API})
        assert fields is not None
        assert "unauthenticated_method_count" in fields
        assert "authorizer_count" in fields
        assert "policy_summary" in fields
        assert "integration_type_counts" in fields
        # Must NOT store integration URIs
        assert "integration_uri" not in fields

    def test_rest_stage_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_APIGATEWAY_REST_STAGE})
        assert fields is not None
        assert "deployment_id_hash" in fields
        assert "tracing_enabled" in fields
        assert "access_logging_enabled" in fields
        assert "web_acl_arn_present" in fields
        assert "variables_key_names" in fields
        # Must NOT store stage variable values
        assert "variables" not in fields

    def test_v2_api_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_APIGATEWAYV2_API})
        assert fields is not None
        assert "unauthenticated_route_count" in fields
        assert "authorizer_count" in fields
        assert "cors_wildcard_origin_present" in fields
        assert "cors_allow_credentials" in fields

    def test_v2_stage_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_APIGATEWAYV2_STAGE})
        assert fields is not None
        assert "access_logging_enabled" in fields
        assert "detailed_metrics_enabled" in fields
        assert "auto_deploy" in fields
        assert "stage_variables_key_names" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk classification — aws_lambda_function
# ─────────────────────────────────────────────────────────────────────────────

class TestLambdaFunctionRisk:
    def test_added_is_low(self):
        change = _lambda_change(change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_nonsensitive_is_medium(self):
        change = _lambda_change(change_type="removed", record_name="test-function")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        change = _lambda_change(change_type="removed", record_name="prod-payment-handler")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_role_arn_hash_changed_is_medium(self):
        change = _lambda_change(field_path="role_arn_hash", new_value="newhash", prev_value="oldhash")
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert "role" in reason.lower()

    def test_role_arn_present_false_is_high(self):
        change = _lambda_change(field_path="role_arn_present", new_value=False, prev_value=True)
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_kms_key_arn_present_removed_sensitive_is_high(self):
        change = _lambda_change(
            field_path="kms_key_arn_present", new_value=False, prev_value=True,
            record_name="prod-auth-handler",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_kms_key_arn_present_removed_nonsensitive_is_medium(self):
        change = _lambda_change(
            field_path="kms_key_arn_present", new_value=False, prev_value=True,
            record_name="test-helper",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_kms_key_arn_present_added_is_low(self):
        change = _lambda_change(field_path="kms_key_arn_present", new_value=True, prev_value=False)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_kms_key_arn_hash_changed_is_medium(self):
        change = _lambda_change(field_path="kms_key_arn_hash", new_value="newhash")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_environment_key_names_added_is_medium(self):
        change = _lambda_change(
            field_path="environment_key_names",
            new_value=["DB_URL", "NEW_KEY"],
            prev_value=["DB_URL"],
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"
        # New key should be mentioned
        assert "NEW_KEY" in reason

    def test_environment_key_names_removed_is_low(self):
        change = _lambda_change(
            field_path="environment_key_names",
            new_value=["DB_URL"],
            prev_value=["DB_URL", "OLD_KEY"],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_environment_sensitive_key_count_increased_is_medium(self):
        change = _lambda_change(
            field_path="environment_sensitive_key_count",
            new_value=3, prev_value=1,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_vpc_config_removed_sensitive_is_medium(self):
        change = _lambda_change(
            field_path="vpc_config_present", new_value=False, prev_value=True,
            record_name="prod-internal-processor",
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert "vpc" in reason.lower() or "internet" in reason.lower()

    def test_vpc_config_removed_nonsensitive_is_low(self):
        change = _lambda_change(
            field_path="vpc_config_present", new_value=False, prev_value=True,
            record_name="test-helper",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_reserved_concurrency_zero_sensitive_is_high(self):
        change = _lambda_change(
            field_path="reserved_concurrent_executions", new_value=0, prev_value=100,
            record_name="prod-api-handler",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "throttled" in reason.lower() or "concurrenc" in reason.lower()

    def test_reserved_concurrency_zero_nonsensitive_is_medium(self):
        change = _lambda_change(
            field_path="reserved_concurrent_executions", new_value=0, prev_value=50,
            record_name="test-helper",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_reserved_concurrency_reduced_is_medium(self):
        change = _lambda_change(
            field_path="reserved_concurrent_executions", new_value=10, prev_value=100,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_reserved_concurrency_increased_is_low(self):
        change = _lambda_change(
            field_path="reserved_concurrent_executions", new_value=200, prev_value=100,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_runtime_changed_is_medium(self):
        change = _lambda_change(field_path="runtime", new_value="python3.12", prev_value="python3.9")
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert "runtime" in reason.lower()

    def test_tracing_passthrough_is_medium(self):
        change = _lambda_change(field_path="tracing_mode", new_value="PassThrough", prev_value="Active")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_dead_letter_removed_sensitive_is_medium(self):
        change = _lambda_change(
            field_path="dead_letter_target_present", new_value=False, prev_value=True,
            record_name="prod-async-worker",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_dead_letter_removed_nonsensitive_is_low(self):
        change = _lambda_change(
            field_path="dead_letter_target_present", new_value=False, prev_value=True,
            record_name="test-helper",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_timeout_changed_is_low(self):
        change = _lambda_change(field_path="timeout", new_value=300, prev_value=60)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_memory_size_changed_is_low(self):
        change = _lambda_change(field_path="memory_size", new_value=512, prev_value=256)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_layers_count_changed_is_low(self):
        change = _lambda_change(field_path="layers_count", new_value=2, prev_value=1)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_tag_keys_changed_is_low(self):
        change = _lambda_change(field_path="tag_keys", new_value=["env", "team"])
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unknown_field_is_low(self):
        change = _lambda_change(field_path="some_unknown_field_xyz", new_value="value")
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification — aws_lambda_alias
# ─────────────────────────────────────────────────────────────────────────────

class TestLambdaAliasRisk:
    def test_added_is_low(self):
        change = _lambda_change(record_type=AWS_LAMBDA_ALIAS, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_low(self):
        change = _lambda_change(record_type=AWS_LAMBDA_ALIAS, change_type="removed")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_function_version_changed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_ALIAS,
            field_path="function_version", new_value="2", prev_value="1",
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert "version" in reason.lower() or "alias" in reason.lower()

    def test_routing_config_removed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_ALIAS,
            field_path="routing_config_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_weights_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_ALIAS,
            field_path="additional_version_weights_count", new_value=1, prev_value=2,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unknown_field_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_ALIAS,
            field_path="unknown_field_xyz",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk classification — aws_lambda_event_source_mapping
# ─────────────────────────────────────────────────────────────────────────────

class TestLambdaEsmRisk:
    def test_added_is_low(self):
        change = _lambda_change(record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self):
        change = _lambda_change(record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING, change_type="removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_state_disabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="state", new_value="Disabled",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_enabled_false_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="enabled", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_event_source_arn_lost_is_high(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="event_source_arn_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_event_source_arn_hash_changed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="event_source_arn_hash", new_value="newhash", prev_value="oldhash",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_function_name_changed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="function_name", new_value="new-fn", prev_value="old-fn",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_filter_criteria_removed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="filter_criteria_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_batch_size_increased_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="batch_size", new_value=1000, prev_value=100,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_batch_size_decreased_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="batch_size", new_value=50, prev_value=100,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_starting_position_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_EVENT_SOURCE_MAPPING,
            field_path="starting_position", new_value="TRIM_HORIZON",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk classification — aws_lambda_function_url
# ─────────────────────────────────────────────────────────────────────────────

class TestLambdaFunctionUrlRisk:
    """Security-critical: auth_type=NONE means publicly invokable."""

    def test_added_auth_none_is_critical(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            change_type="added",
            new_value={"auth_type": "NONE"},
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "none" in reason.lower() or "public" in reason.lower()

    def test_added_auth_iam_is_medium(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            change_type="added",
            new_value={"auth_type": "AWS_IAM"},
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_is_low(self):
        change = _lambda_change(record_type=AWS_LAMBDA_FUNCTION_URL, change_type="removed")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_auth_type_changed_to_none_is_critical(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="auth_type", new_value="NONE", prev_value="AWS_IAM",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "none" in reason.lower() or "public" in reason.lower()

    def test_auth_type_none_to_iam_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="auth_type", new_value="AWS_IAM", prev_value="NONE",
        )
        level, reason = classify_aws_change(change)
        assert level == "low"
        assert "improvement" in reason.lower() or "authentication" in reason.lower()

    def test_auth_type_other_change_is_high(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="auth_type", new_value="JWT", prev_value="AWS_IAM",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_cors_wildcard_origin_added_is_high(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="cors_wildcard_origin_present", new_value=True, prev_value=False,
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "wildcard" in reason.lower() or "origin" in reason.lower()

    def test_cors_wildcard_origin_removed_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="cors_wildcard_origin_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_cors_allow_credentials_true_is_high(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="cors_allow_credentials", new_value=True, prev_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_invoke_mode_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_LAMBDA_FUNCTION_URL,
            field_path="invoke_mode", new_value="RESPONSE_STREAM", prev_value="BUFFERED",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Risk classification — aws_apigateway_rest_api
# ─────────────────────────────────────────────────────────────────────────────

class TestApiGatewayRestApiRisk:
    def test_added_sensitive_with_unauth_methods_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            change_type="added",
            new_value={"unauthenticated_method_count": 3},
            record_name="prod-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_added_nonsensitive_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            change_type="added",
            new_value={"unauthenticated_method_count": 0},
            record_name="test-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_sensitive_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            change_type="removed", record_name="prod-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_removed_nonsensitive_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            change_type="removed", record_name="test-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_unauth_method_count_increased_sensitive_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="unauthenticated_method_count",
            new_value=5, prev_value=2,
            record_name="prod-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_unauth_method_count_increased_nonsensitive_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="unauthenticated_method_count",
            new_value=5, prev_value=2,
            record_name="test-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_unauth_method_count_decreased_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="unauthenticated_method_count",
            new_value=1, prev_value=5,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_authorizer_count_to_zero_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="authorizer_count", new_value=0, prev_value=2,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_policy_wildcard_added_is_critical(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="policy_summary",
            new_value={"has_wildcard_principal": True},
            prev_value={"has_wildcard_principal": False},
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "wildcard" in reason.lower()

    def test_policy_wildcard_removed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="policy_summary",
            new_value={"has_wildcard_principal": False},
            prev_value={"has_wildcard_principal": True},
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_endpoint_type_changed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="endpoint_configuration_types",
            new_value=["PRIVATE"], prev_value=["REGIONAL"],
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_disable_endpoint_re_enabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="disable_execute_api_endpoint", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_tag_keys_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="tag_keys", new_value=["env"],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unknown_field_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_API,
            field_path="unknown_field_xyz",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Risk classification — aws_apigateway_rest_stage
# ─────────────────────────────────────────────────────────────────────────────

class TestApiGatewayRestStageRisk:
    def test_added_is_low(self):
        change = _lambda_change(record_type=AWS_APIGATEWAY_REST_STAGE, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self):
        change = _lambda_change(record_type=AWS_APIGATEWAY_REST_STAGE, change_type="removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_deployment_id_lost_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="deployment_id_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_deployment_id_hash_changed_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="deployment_id_hash", new_value="newhash", prev_value="oldhash",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_tracing_disabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="tracing_enabled", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_access_logging_disabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="access_logging_enabled", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_metrics_count_decreased_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="metrics_enabled_count", new_value=2, prev_value=5,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_waf_removed_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="web_acl_arn_present", new_value=False, prev_value=True,
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "waf" in reason.lower() or "web acl" in reason.lower()

    def test_cache_cluster_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="cache_cluster_enabled", new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_variables_key_names_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAY_REST_STAGE,
            field_path="variables_key_names", new_value=["KEY1"],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Risk classification — aws_apigatewayv2_api
# ─────────────────────────────────────────────────────────────────────────────

class TestApiGatewayV2ApiRisk:
    def test_added_sensitive_with_unauth_routes_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            change_type="added",
            new_value={"unauthenticated_route_count": 4},
            record_name="prod-http-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_added_nonsensitive_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            change_type="added",
            new_value={"unauthenticated_route_count": 0},
            record_name="test-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_sensitive_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            change_type="removed", record_name="prod-http-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_unauth_route_count_increased_sensitive_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="unauthenticated_route_count",
            new_value=5, prev_value=1,
            record_name="prod-http-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_unauth_route_count_increased_nonsensitive_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="unauthenticated_route_count",
            new_value=5, prev_value=1,
            record_name="test-api",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_authorizer_count_to_zero_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="authorizer_count", new_value=0, prev_value=1,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_cors_wildcard_origin_added_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="cors_wildcard_origin_present", new_value=True, prev_value=False,
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "cors" in reason.lower() or "wildcard" in reason.lower()

    def test_cors_wildcard_origin_removed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="cors_wildcard_origin_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_cors_allow_credentials_true_is_high(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="cors_allow_credentials", new_value=True, prev_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_tag_keys_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="tag_keys", new_value=["env"],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unknown_field_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_API,
            field_path="unknown_field_xyz",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Risk classification — aws_apigatewayv2_stage
# ─────────────────────────────────────────────────────────────────────────────

class TestApiGatewayV2StageRisk:
    def test_added_is_low(self):
        change = _lambda_change(record_type=AWS_APIGATEWAYV2_STAGE, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_medium(self):
        change = _lambda_change(record_type=AWS_APIGATEWAYV2_STAGE, change_type="removed")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_deployment_id_lost_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="deployment_id_present", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_auto_deploy_disabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="auto_deploy", new_value=False, prev_value=True,
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"
        assert "auto" in reason.lower() or "deploy" in reason.lower()

    def test_auto_deploy_enabled_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="auto_deploy", new_value=True, prev_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_access_logging_disabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="access_logging_enabled", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_detailed_metrics_disabled_is_medium(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="detailed_metrics_enabled", new_value=False, prev_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_stage_variables_key_names_changed_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="stage_variables_key_names", new_value=["KEY1"],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unknown_field_is_low(self):
        change = _lambda_change(
            record_type=AWS_APIGATEWAYV2_STAGE,
            field_path="unknown_field_xyz",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 12. Failure classification
# ─────────────────────────────────────────────────────────────────────────────

class TestLambdaFailureClassifier:
    def _auth_exc(self):
        return AuthenticationError("auth failed")

    def _403_exc(self):
        return ConnectorError("access denied", status_code=403)

    def _rate_exc(self):
        return RateLimitError("throttled")

    def _network_exc(self):
        return NetworkError("timeout")

    def test_list_functions_access_denied(self):
        fc = classify_aws_lambda_failure("ListFunctions", self._403_exc())
        assert fc.error_code == "aws_lambda_access_denied"
        assert "lambda:ListFunctions" in fc.recommended_action

    def test_list_aliases_access_denied(self):
        fc = classify_aws_lambda_failure("ListAliases", self._403_exc())
        assert fc.error_code == "aws_lambda_access_denied"

    def test_list_esms_access_denied(self):
        fc = classify_aws_lambda_failure("ListEventSourceMappings", self._403_exc())
        assert fc.error_code == "aws_lambda_access_denied"

    def test_list_url_configs_access_denied(self):
        fc = classify_aws_lambda_failure("ListFunctionUrlConfigs", self._403_exc())
        assert fc.error_code == "aws_lambda_access_denied"

    def test_recommended_action_never_invoke(self):
        """SECURITY: recommended action must never mention InvokeFunction."""
        fc = classify_aws_lambda_failure("ListFunctions", self._403_exc())
        assert "InvokeFunction" not in fc.recommended_action
        assert "lambda:Invoke" not in fc.recommended_action

    def test_recommended_action_never_get_function(self):
        """SECURITY: recommended action must not require lambda:GetFunction."""
        fc = classify_aws_lambda_failure("ListFunctions", self._403_exc())
        assert "lambda:GetFunction" not in fc.recommended_action

    def test_recommended_action_never_env_var_access(self):
        """SECURITY: recommended action must not suggest accessing env vars."""
        fc = classify_aws_lambda_failure("ListFunctions", self._403_exc())
        assert "environment" not in fc.recommended_action.lower() or \
               "GetFunctionConfiguration" not in fc.recommended_action

    def test_auth_error_produces_code(self):
        fc = classify_aws_lambda_failure("ListFunctions", self._auth_exc())
        assert fc.error_code != ""

    def test_rate_limit_produces_code(self):
        fc = classify_aws_lambda_failure("ListFunctions", self._rate_exc())
        assert fc.error_code != ""

    def test_network_error_produces_code(self):
        fc = classify_aws_lambda_failure("ListFunctions", self._network_exc())
        assert fc.error_code != ""

    def test_unknown_api_produces_generic_code(self):
        fc = classify_aws_lambda_failure("UnknownLambdaApi", self._403_exc())
        assert "lambda" in fc.error_code


class TestApiGatewayFailureClassifier:
    def _403_exc(self):
        return ConnectorError("access denied", status_code=403)

    def _rate_exc(self):
        return RateLimitError("throttled")

    def test_get_rest_apis_access_denied(self):
        fc = classify_aws_apigateway_failure("GetRestApis", self._403_exc())
        assert fc.error_code == "aws_apigateway_access_denied"
        assert "apigateway" in fc.recommended_action.lower() or "execute-api" in fc.recommended_action.lower() or "apigateway" in fc.recommended_action.lower()

    def test_get_stages_access_denied(self):
        fc = classify_aws_apigateway_failure("GetStages", self._403_exc())
        assert fc.error_code == "aws_apigateway_access_denied"

    def test_get_apis_v2_access_denied(self):
        fc = classify_aws_apigateway_failure("GetApis", self._403_exc())
        assert fc.error_code == "aws_apigateway_access_denied"

    def test_recommended_action_never_invoke(self):
        """SECURITY: recommended action must never suggest invoking an API endpoint."""
        fc = classify_aws_apigateway_failure("GetRestApis", self._403_exc())
        assert "execute-api:Invoke" not in fc.recommended_action
        assert "invoke" not in fc.recommended_action.lower()

    def test_recommended_action_never_read_logs(self):
        """SECURITY: recommended action must never suggest reading API logs/traffic."""
        fc = classify_aws_apigateway_failure("GetRestApis", self._403_exc())
        assert "logs:Get" not in fc.recommended_action
        assert "request bodies" not in fc.recommended_action.lower()

    def test_rate_limit_produces_code(self):
        fc = classify_aws_apigateway_failure("GetRestApis", self._rate_exc())
        assert fc.error_code != ""

    def test_unknown_api_produces_generic_code(self):
        fc = classify_aws_apigateway_failure("UnknownGatewayApi", self._403_exc())
        assert "apigateway" in fc.error_code


# ─────────────────────────────────────────────────────────────────────────────
# 13. Connector normalization — _fetch_lambda_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchLambdaInRegion:
    """Test that _fetch_lambda_in_region normalizes Lambda records correctly."""

    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    def _make_mock_client(self):
        return MagicMock()

    def _make_call_aws(self, mock_client,
                       list_fns_resp=None,
                       list_aliases_resp=None,
                       list_esm_resp=None,
                       list_url_resp=None):
        """Build a _call_aws dispatcher for Lambda mocks."""
        def _call_aws(fn, **kwargs):
            if fn is mock_client.list_functions:
                return list_fns_resp or {"Functions": []}
            if fn is mock_client.list_aliases:
                return list_aliases_resp or {"Aliases": []}
            if fn is mock_client.list_function_url_configs:
                return list_url_resp or {"FunctionUrlConfigs": []}
            if fn is mock_client.list_event_source_mappings:
                return list_esm_resp or {"EventSourceMappings": []}
            return {}
        return _call_aws

    def test_lambda_function_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {
            "Functions": [{
                "FunctionName": "prod-payment-handler",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:prod-payment-handler",
                "Runtime": "python3.12",
                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                "Handler": "lambda_function.lambda_handler",
                "CodeSize": 102400,
                "Timeout": 30,
                "MemorySize": 256,
                "LastModified": "2024-01-01T00:00:00.000+0000",
                "Environment": {
                    "Variables": {
                        "DB_HOST": "postgres.internal",
                        "SECRET_KEY": "should-never-be-stored",
                        "LOG_LEVEL": "info",
                    }
                },
                "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/test-key",
                "TracingConfig": {"Mode": "Active"},
                "Tags": {"env": "prod", "team": "payments"},
                "Architectures": ["x86_64"],
                "EphemeralStorage": {"Size": 512},
                "PackageType": "Zip",
                "Layers": [
                    {"Arn": "arn:aws:lambda:us-east-1:123456789012:layer:my-layer:1"}
                ],
            }],
        }
        conn._call_aws = self._make_call_aws(client, list_fns_resp=fn_resp)
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)

        fn_records = [r for r in records if r["record_type"] == AWS_LAMBDA_FUNCTION]
        assert len(fn_records) == 1
        r = fn_records[0]

        assert r["record_type"] == AWS_LAMBDA_FUNCTION
        assert r["function_name"] == "prod-payment-handler"
        assert r["runtime"] == "python3.12"
        assert r["timeout"] == 30
        assert r["memory_size"] == 256
        assert r["tracing_mode"] == "Active"
        assert r["account_id"] == self.ACCOUNT_ID
        assert r["region"] == self.REGION
        assert r["tag_keys"] == ["env", "team"]

        # SECURITY: env var values must NEVER be stored
        flat = str(r)
        assert "should-never-be-stored" not in flat, (
            "SECURITY VIOLATION: env var value was stored in Lambda record"
        )
        # Key names should be stored (not values)
        assert r["environment_key_count"] == 3
        assert "DB_HOST" in r["environment_key_names"]
        assert "SECRET_KEY" in r["environment_key_names"]

        # SECURITY: KMS key ARN must be hashed, not stored raw
        raw_kms = "arn:aws:kms:us-east-1:123456789012:key/test-key"
        assert raw_kms not in flat
        assert r["kms_key_arn_present"] is True
        assert r["kms_key_arn_hash"] is not None
        assert r["kms_key_arn_hash"] != raw_kms

        # Role ARN hashed
        raw_role = "arn:aws:iam::123456789012:role/lambda-role"
        assert r["role_arn_present"] is True
        assert r["role_arn_hash"] is not None
        assert r["role_arn_hash"] != raw_role

    def test_env_var_values_never_stored(self):
        """SECURITY: the most critical rule — env var values must NEVER appear in output."""
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {
            "Functions": [{
                "FunctionName": "test-fn",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "Runtime": "python3.11",
                "Role": "arn:aws:iam::123456789012:role/test-role",
                "CodeSize": 1024,
                "Timeout": 3,
                "MemorySize": 128,
                "Environment": {
                    "Variables": {
                        "DATABASE_PASSWORD": "super_secret_db_password_12345",
                        "API_KEY": "live_secret_api_key_abcdef",
                        "STRIPE_SECRET": "sk_live_stripe_key_xyz",
                    }
                },
            }],
        }
        conn._call_aws = self._make_call_aws(client, list_fns_resp=fn_resp)
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)
        r = [r for r in records if r["record_type"] == AWS_LAMBDA_FUNCTION][0]

        flat = str(r)
        # None of these secret values should appear ANYWHERE in the record
        assert "super_secret_db_password_12345" not in flat
        assert "live_secret_api_key_abcdef" not in flat
        assert "sk_live_stripe_key_xyz" not in flat

    def test_get_function_never_called(self):
        """SECURITY: GetFunction (which returns signed code URL) must never be called."""
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {
            "Functions": [{
                "FunctionName": "test-fn",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "Runtime": "python3.11",
                "Role": "arn:aws:iam::123456789012:role/test-role",
                "CodeSize": 1024,
                "Timeout": 3,
                "MemorySize": 128,
            }],
        }
        called_fns = []
        original_call_aws = self._make_call_aws(client, list_fns_resp=fn_resp)

        def tracking_call_aws(fn, **kwargs):
            called_fns.append(getattr(fn, "__name__", str(fn)))
            return original_call_aws(fn, **kwargs)

        conn._call_aws = tracking_call_aws
        conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)

        for fn_name in called_fns:
            assert "get_function" not in fn_name.lower(), (
                f"SECURITY VIOLATION: GetFunction was called: {fn_name}"
            )

    def test_no_write_apis_called(self):
        """SECURITY: no write/mutate Lambda APIs should ever be called."""
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {
            "Functions": [{
                "FunctionName": "test-fn",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "Runtime": "python3.11",
                "Role": "arn:aws:iam::123456789012:role/test-role",
                "CodeSize": 1024,
                "Timeout": 3,
                "MemorySize": 128,
            }],
        }
        called_fns = []
        original_call_aws = self._make_call_aws(client, list_fns_resp=fn_resp)

        def tracking_call_aws(fn, **kwargs):
            called_fns.append(getattr(fn, "__name__", str(fn)))
            return original_call_aws(fn, **kwargs)

        conn._call_aws = tracking_call_aws
        conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)

        write_prefixes = (
            "create_", "update_", "delete_", "invoke", "publish_",
            "add_permission", "remove_permission", "put_", "tag_resource",
        )
        for fn_name in called_fns:
            for prefix in write_prefixes:
                assert not fn_name.lower().startswith(prefix), (
                    f"SECURITY VIOLATION: Write API called: {fn_name}"
                )

    def test_lambda_function_url_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {
            "Functions": [{
                "FunctionName": "test-fn",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "Runtime": "python3.11",
                "Role": "arn:aws:iam::123456789012:role/test-role",
                "CodeSize": 1024,
                "Timeout": 3,
                "MemorySize": 128,
            }],
        }
        url_resp = {
            "FunctionUrlConfigs": [{
                "FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "AuthType": "NONE",
                "InvokeMode": "BUFFERED",
                "Cors": {
                    "AllowOrigins": ["*"],
                    "AllowCredentials": False,
                },
            }],
        }
        conn._call_aws = self._make_call_aws(
            client, list_fns_resp=fn_resp, list_url_resp=url_resp
        )
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)

        url_records = [r for r in records if r["record_type"] == AWS_LAMBDA_FUNCTION_URL]
        assert len(url_records) == 1
        r = url_records[0]

        assert r["auth_type"] == "NONE"
        assert r["invoke_mode"] == "BUFFERED"
        assert r["cors_present"] is True
        assert r["cors_wildcard_origin_present"] is True
        assert r["cors_allow_credentials"] is False

        # SECURITY: raw function URL must not be stored
        flat = str(r)
        assert "abc123.lambda-url.us-east-1.on.aws" not in flat

    def test_lambda_alias_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {
            "Functions": [{
                "FunctionName": "test-fn",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "Runtime": "python3.11",
                "Role": "arn:aws:iam::123456789012:role/test-role",
                "CodeSize": 1024,
                "Timeout": 3,
                "MemorySize": 128,
            }],
        }
        alias_resp = {
            "Aliases": [{
                "AliasArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn:live",
                "Name": "live",
                "FunctionVersion": "5",
                "RoutingConfig": {
                    "AdditionalVersionWeights": {"4": 0.1},
                },
            }],
        }
        conn._call_aws = self._make_call_aws(
            client, list_fns_resp=fn_resp, list_aliases_resp=alias_resp
        )
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)

        alias_records = [r for r in records if r["record_type"] == AWS_LAMBDA_ALIAS]
        assert len(alias_records) == 1
        r = alias_records[0]

        assert r["function_version"] == "5"
        assert r["routing_config_present"] is True
        assert r["additional_version_weights_count"] == 1

    def test_esm_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        fn_resp = {"Functions": []}
        esm_resp = {
            "EventSourceMappings": [{
                "UUID": "abc-123-def",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                "EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:my-queue",
                "State": "Enabled",
                "BatchSize": 100,
                "StartingPosition": "LATEST",
            }],
        }
        conn._call_aws = self._make_call_aws(
            client, list_fns_resp=fn_resp, list_esm_resp=esm_resp
        )
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)

        esm_records = [r for r in records if r["record_type"] == AWS_LAMBDA_EVENT_SOURCE_MAPPING]
        assert len(esm_records) == 1
        r = esm_records[0]

        assert r["state"] == "Enabled"
        assert r["batch_size"] == 100
        assert r["event_source_type"] == "sqs"
        assert r["event_source_arn_present"] is True
        assert r["event_source_arn_hash"] is not None

        # SECURITY: raw SQS ARN must not be stored
        raw_arn = "arn:aws:sqs:us-east-1:123456789012:my-queue"
        assert r.get("event_source_arn") != raw_arn
        flat = str(r)
        assert raw_arn not in flat

    def test_empty_responses_return_empty(self):
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client)  # all empty
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)
        assert records == []

    def test_record_id_is_stable(self):
        conn = _make_connector()
        client = self._make_mock_client()
        fn_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-fn"
        fn_resp = {
            "Functions": [{
                "FunctionName": "test-fn",
                "FunctionArn": fn_arn,
                "Runtime": "python3.11",
                "Role": "arn:aws:iam::123456789012:role/role",
                "CodeSize": 1024,
                "Timeout": 3,
                "MemorySize": 128,
            }],
        }
        conn._call_aws = self._make_call_aws(client, list_fns_resp=fn_resp)
        records = conn._fetch_lambda_in_region(client, self.ACCOUNT_ID, self.REGION)
        r = [r for r in records if r["record_type"] == AWS_LAMBDA_FUNCTION][0]
        # Stable record_id is based on account_id/region/fn_arn
        assert self.ACCOUNT_ID in r["record_id"]
        assert self.REGION in r["record_id"]


# ─────────────────────────────────────────────────────────────────────────────
# 14. Connector normalization — _fetch_apigateway_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchApigatewayInRegion:
    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    def _make_mock_client(self):
        return MagicMock()

    def _make_call_aws(self, mock_client,
                       get_rest_apis_resp=None,
                       get_authorizers_resp=None,
                       get_resources_resp=None,
                       get_stages_resp=None):
        def _call_aws(fn, **kwargs):
            if fn is mock_client.get_rest_apis:
                return get_rest_apis_resp or {"items": []}
            if fn is mock_client.get_authorizers:
                return get_authorizers_resp or {"items": []}
            if fn is mock_client.get_resources:
                return get_resources_resp or {"items": []}
            if fn is mock_client.get_stages:
                return get_stages_resp or {"item": []}
            return {}
        return _call_aws

    def test_rest_api_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        api_resp = {
            "items": [{
                "id": "abc123",
                "name": "prod-rest-api",
                "endpointConfiguration": {"types": ["REGIONAL"]},
                "disableExecuteApiEndpoint": False,
                "tags": {"env": "prod"},
            }],
        }
        authorizer_resp = {"items": [{"id": "auth-1"}, {"id": "auth-2"}]}
        resources_resp = {
            "items": [
                {
                    "id": "r1",
                    "resourceMethods": {
                        "GET": {
                            "authorizationType": "NONE",
                            "methodIntegration": {"type": "HTTP_PROXY"},
                        },
                        "POST": {
                            "authorizationType": "AWS_IAM",
                            "methodIntegration": {"type": "AWS_PROXY"},
                        },
                    },
                }
            ]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_rest_apis_resp=api_resp,
            get_authorizers_resp=authorizer_resp,
            get_resources_resp=resources_resp,
        )
        records = conn._fetch_apigateway_in_region(client, self.ACCOUNT_ID, self.REGION)

        api_records = [r for r in records if r["record_type"] == AWS_APIGATEWAY_REST_API]
        assert len(api_records) == 1
        r = api_records[0]

        assert r["name"] == "prod-rest-api"
        assert r["endpoint_configuration_types"] == ["REGIONAL"]
        assert r["authorizer_count"] == 2
        assert r["method_count"] == 2
        assert r["unauthenticated_method_count"] == 1  # only the GET method
        # integration_type_counts should have type keys but never URIs
        assert "HTTP_PROXY" in r["integration_type_counts"] or len(r["integration_type_counts"]) > 0
        assert r["account_id"] == self.ACCOUNT_ID
        assert r["region"] == self.REGION

    def test_integration_uri_never_stored(self):
        """SECURITY: integration URIs must never be stored in REST API records."""
        conn = _make_connector()
        client = self._make_mock_client()
        api_resp = {"items": [{"id": "abc", "name": "test-api"}]}
        resources_resp = {
            "items": [{
                "id": "r1",
                "resourceMethods": {
                    "GET": {
                        "authorizationType": "NONE",
                        "methodIntegration": {
                            "type": "HTTP",
                            "uri": "https://internal-backend.example.com/secret-endpoint",
                        },
                    },
                },
            }]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_rest_apis_resp=api_resp,
            get_resources_resp=resources_resp,
        )
        records = conn._fetch_apigateway_in_region(client, self.ACCOUNT_ID, self.REGION)

        flat = str(records)
        assert "https://internal-backend.example.com/secret-endpoint" not in flat, (
            "SECURITY VIOLATION: integration URI stored in API Gateway record"
        )

    def test_stage_variables_values_never_stored(self):
        """SECURITY: stage variable values must never be stored (keys only)."""
        conn = _make_connector()
        client = self._make_mock_client()
        api_resp = {"items": [{"id": "abc", "name": "test-api"}]}
        stages_resp = {
            "item": [{
                "stageName": "prod",
                "deploymentId": "dep-abc",
                "tracingEnabled": True,
                "variables": {
                    "DB_URL": "postgres://secret-host:5432/mydb",
                    "API_KEY": "sk_live_super_secret_key",
                },
            }]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_rest_apis_resp=api_resp,
            get_stages_resp=stages_resp,
        )
        records = conn._fetch_apigateway_in_region(client, self.ACCOUNT_ID, self.REGION)

        flat = str(records)
        assert "postgres://secret-host:5432/mydb" not in flat, (
            "SECURITY VIOLATION: stage variable value stored in API Gateway record"
        )
        assert "sk_live_super_secret_key" not in flat, (
            "SECURITY VIOLATION: stage variable value stored in API Gateway record"
        )

    def test_rest_stage_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        api_resp = {"items": [{"id": "abc123", "name": "test-api"}]}
        stages_resp = {
            "item": [{
                "stageName": "v1",
                "deploymentId": "dep-xyz",
                "tracingEnabled": True,
                "accessLogSettings": {"destinationArn": "arn:aws:logs:..."},
                "methodSettings": {},
                "variables": {"ENV": "prod"},
                "tags": {},
            }]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_rest_apis_resp=api_resp,
            get_stages_resp=stages_resp,
        )
        records = conn._fetch_apigateway_in_region(client, self.ACCOUNT_ID, self.REGION)

        stage_records = [r for r in records if r["record_type"] == AWS_APIGATEWAY_REST_STAGE]
        assert len(stage_records) == 1
        r = stage_records[0]

        assert r["tracing_enabled"] is True
        assert r["access_logging_enabled"] is True
        assert r["deployment_id_present"] is True
        assert r["variables_key_count"] == 1
        assert "ENV" in r["variables_key_names"]

    def test_no_write_apis_called(self):
        """SECURITY: no write APIs should be called during fetch."""
        conn = _make_connector()
        client = self._make_mock_client()
        api_resp = {"items": [{"id": "abc", "name": "test-api"}]}

        called_fns = []
        original = self._make_call_aws(client, get_rest_apis_resp=api_resp)

        def tracking(fn, **kwargs):
            called_fns.append(getattr(fn, "__name__", str(fn)))
            return original(fn, **kwargs)

        conn._call_aws = tracking
        conn._fetch_apigateway_in_region(client, self.ACCOUNT_ID, self.REGION)

        write_prefixes = ("create_", "update_", "delete_", "put_", "import_", "tag_")
        for fn_name in called_fns:
            for prefix in write_prefixes:
                assert not fn_name.lower().startswith(prefix), (
                    f"SECURITY VIOLATION: Write API called: {fn_name}"
                )

    def test_empty_apis_returns_empty(self):
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client)
        records = conn._fetch_apigateway_in_region(client, self.ACCOUNT_ID, self.REGION)
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 15. Connector normalization — _fetch_apigatewayv2_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchApigatewayV2InRegion:
    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    def _make_mock_client(self):
        return MagicMock()

    def _make_call_aws(self, mock_client,
                       get_apis_resp=None,
                       get_routes_resp=None,
                       get_authorizers_resp=None,
                       get_integrations_resp=None,
                       get_stages_resp=None):
        def _call_aws(fn, **kwargs):
            if fn is mock_client.get_apis:
                return get_apis_resp or {"Items": []}
            if fn is mock_client.get_routes:
                return get_routes_resp or {"Items": []}
            if fn is mock_client.get_authorizers:
                return get_authorizers_resp or {"Items": []}
            if fn is mock_client.get_integrations:
                return get_integrations_resp or {"Items": []}
            if fn is mock_client.get_stages:
                return get_stages_resp or {"Items": []}
            return {}
        return _call_aws

    def test_v2_api_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        apis_resp = {
            "Items": [{
                "ApiId": "xyz789",
                "Name": "prod-http-api",
                "ProtocolType": "HTTP",
                "ApiEndpoint": "https://xyz789.execute-api.us-east-1.amazonaws.com",
                "RouteSelectionExpression": "$request.method $request.path",
                "DisableExecuteApiEndpoint": False,
                "CorsConfiguration": {
                    "AllowOrigins": ["https://example.com"],
                    "AllowCredentials": False,
                },
                "Tags": {"env": "prod"},
            }],
        }
        routes_resp = {
            "Items": [
                {"RouteKey": "GET /public", "AuthorizationType": "NONE"},
                {"RouteKey": "POST /private", "AuthorizationType": "JWT"},
            ]
        }
        authorizer_resp = {"Items": [{"AuthorizerId": "jwt-auth"}]}
        integrations_resp = {
            "Items": [
                {
                    "IntegrationId": "i1",
                    "IntegrationType": "AWS_PROXY",
                    "IntegrationUri": "arn:aws:lambda:us-east-1:123456789012:function:test-fn",
                },
            ]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_apis_resp=apis_resp,
            get_routes_resp=routes_resp,
            get_authorizers_resp=authorizer_resp,
            get_integrations_resp=integrations_resp,
        )
        records = conn._fetch_apigatewayv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        api_records = [r for r in records if r["record_type"] == AWS_APIGATEWAYV2_API]
        assert len(api_records) == 1
        r = api_records[0]

        assert r["name"] == "prod-http-api"
        assert r["protocol_type"] == "HTTP"
        assert r["route_count"] == 2
        assert r["unauthenticated_route_count"] == 1
        assert r["authorizer_count"] == 1
        assert r["cors_present"] is True
        assert r["cors_wildcard_origin_present"] is False
        # integration type counts — no URIs stored
        assert "AWS_PROXY" in r["integration_type_counts"] or len(r["integration_type_counts"]) >= 1

    def test_integration_uri_never_stored_v2(self):
        """SECURITY: IntegrationUri must never be stored in V2 API records."""
        conn = _make_connector()
        client = self._make_mock_client()
        apis_resp = {"Items": [{"ApiId": "abc", "Name": "test-api", "ProtocolType": "HTTP"}]}
        integrations_resp = {
            "Items": [{
                "IntegrationId": "i1",
                "IntegrationType": "HTTP_PROXY",
                "IntegrationUri": "https://super-secret-backend.internal/endpoint",
            }]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_apis_resp=apis_resp,
            get_integrations_resp=integrations_resp,
        )
        records = conn._fetch_apigatewayv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        flat = str(records)
        assert "https://super-secret-backend.internal/endpoint" not in flat, (
            "SECURITY VIOLATION: integration URI stored in V2 API Gateway record"
        )

    def test_stage_variables_values_never_stored_v2(self):
        """SECURITY: stage variable values must never be stored."""
        conn = _make_connector()
        client = self._make_mock_client()
        apis_resp = {"Items": [{"ApiId": "abc", "Name": "test-api", "ProtocolType": "HTTP"}]}
        stages_resp = {
            "Items": [{
                "StageName": "prod",
                "DeploymentId": "dep-123",
                "AutoDeploy": True,
                "StageVariables": {
                    "BACKEND_URL": "https://secret-backend.internal",
                    "DB_PASSWORD": "super_secret_password",
                },
            }]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_apis_resp=apis_resp,
            get_stages_resp=stages_resp,
        )
        records = conn._fetch_apigatewayv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        flat = str(records)
        assert "https://secret-backend.internal" not in flat
        assert "super_secret_password" not in flat

    def test_v2_stage_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        apis_resp = {"Items": [{"ApiId": "abc", "Name": "test-api", "ProtocolType": "HTTP"}]}
        stages_resp = {
            "Items": [{
                "StageName": "$default",
                "AutoDeploy": True,
                "AccessLogSettings": {"DestinationArn": "arn:aws:logs:..."},
                "DefaultRouteSettings": {"DetailedMetricsEnabled": True},
                "StageVariables": {"KEY1": "value1"},
            }]
        }
        conn._call_aws = self._make_call_aws(
            client,
            get_apis_resp=apis_resp,
            get_stages_resp=stages_resp,
        )
        records = conn._fetch_apigatewayv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        stage_records = [r for r in records if r["record_type"] == AWS_APIGATEWAYV2_STAGE]
        assert len(stage_records) == 1
        r = stage_records[0]

        assert r["auto_deploy"] is True
        assert r["access_logging_enabled"] is True
        assert r["detailed_metrics_enabled"] is True
        assert r["stage_variables_key_count"] == 1
        assert "KEY1" in r["stage_variables_key_names"]

    def test_empty_apis_returns_empty(self):
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client)
        records = conn._fetch_apigatewayv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 16. Fail-soft — per-region errors do not abort
# ─────────────────────────────────────────────────────────────────────────────

class TestM43FailSoft:
    def test_lambda_region_failure_does_not_abort(self):
        conn = _make_connector()
        credentials = _creds(regions=["us-east-1", "eu-west-1"])

        def _make_client(service, creds, region=None):
            return MagicMock()

        conn._make_client = _make_client

        call_count = [0]

        def fake_fetch_in_region(client, account_id, region):
            call_count[0] += 1
            if region == "us-east-1":
                raise ConnectorError("access denied", status_code=403)
            return [{"record_type": AWS_LAMBDA_FUNCTION, "region": region}]

        conn._fetch_lambda_in_region = fake_fetch_in_region
        records = conn._fetch_lambda_resources(credentials, "123456789012")
        eu_records = [r for r in records if r.get("region") == "eu-west-1"]
        assert len(eu_records) == 1

    def test_apigw_region_failure_does_not_abort(self):
        conn = _make_connector()
        credentials = _creds(regions=["us-east-1", "eu-west-1"])

        def _make_client(service, creds, region=None):
            return MagicMock()

        conn._make_client = _make_client

        call_count = [0]

        def fake_fetch_in_region(client, account_id, region):
            call_count[0] += 1
            if region == "us-east-1":
                raise ConnectorError("network error", status_code=503)
            return [{"record_type": AWS_APIGATEWAY_REST_API, "region": region}]

        conn._fetch_apigateway_in_region = fake_fetch_in_region
        records = conn._fetch_apigateway_resources(credentials, "123456789012")
        eu_records = [r for r in records if r.get("region") == "eu-west-1"]
        assert len(eu_records) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 17. Service inventory — lambda + api_gateway
# ─────────────────────────────────────────────────────────────────────────────

class TestM43ServiceInventory:
    def test_lambda_in_enabled_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds, lambda_function_count=3)
        assert "lambda" in inv["enabled_surfaces"]

    def test_api_gateway_in_enabled_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds, apigw_rest_api_count=2, apigwv2_api_count=1)
        assert "api_gateway" in inv["enabled_surfaces"]

    def test_lambda_not_in_future_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert "lambda" not in inv.get("future_surfaces", [])

    def test_api_gateway_not_in_future_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert "api_gateway" not in inv.get("future_surfaces", [])

    def test_lambda_counts_stored(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds, lambda_function_count=7, apigw_rest_api_count=3, apigwv2_api_count=2)
        assert inv["lambda_function_count"] == 7
        assert inv["apigw_rest_api_count"] == 3
        assert inv["apigwv2_api_count"] == 2

    def test_lambda_counts_default_zero(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert inv["lambda_function_count"] == 0
        assert inv["apigw_rest_api_count"] == 0
        assert inv["apigwv2_api_count"] == 0

    def test_m42_surfaces_still_present(self):
        """Regression: M42 surfaces must not be removed."""
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert "rds" in inv["enabled_surfaces"]


# ─────────────────────────────────────────────────────────────────────────────
# 18. Security hard rules — explicit summary
# ─────────────────────────────────────────────────────────────────────────────

class TestM43SecurityHardRules:
    """Explicit tests for all M43 security constraints."""

    def test_env_key_info_never_exposes_values(self):
        """_lambda_env_key_info must never return env var values."""
        sensitive_env = {
            "DB_PASSWORD": "my_secret_password_12345",
            "API_TOKEN": "Bearer eyJhbGciOiJSUzI1NiJ9...",
            "STRIPE_KEY": "sk_live_AbCdEfGh",
        }
        key_names, count, sensitive_count = _lambda_env_key_info(sensitive_env)
        result_str = str(key_names) + str(count) + str(sensitive_count)
        assert "my_secret_password_12345" not in result_str
        assert "Bearer eyJhbGciOiJSUzI1NiJ9" not in result_str
        assert "sk_live_AbCdEfGh" not in result_str

    def test_lambda_failure_classifier_never_suggests_write_perms(self):
        """Lambda failure classifier must never suggest write permissions."""
        write_perms = [
            "lambda:CreateFunction", "lambda:UpdateFunctionCode",
            "lambda:DeleteFunction", "lambda:InvokeFunction",
            "lambda:GetFunction",  # returns signed code URL — must not be suggested
            "secretsmanager:GetSecretValue",
        ]
        exc = ConnectorError("access denied", status_code=403)
        for api in ["ListFunctions", "ListAliases", "ListEventSourceMappings", "ListFunctionUrlConfigs"]:
            fc = classify_aws_lambda_failure(api, exc)
            for bad in write_perms:
                assert bad not in fc.recommended_action, (
                    f"API {api}: recommended_action mentions forbidden permission {bad!r}"
                )

    def test_apigateway_failure_classifier_never_suggests_invoke(self):
        """API Gateway failure classifier must never suggest invoking APIs."""
        forbidden = [
            "execute-api:Invoke",
            "lambda:InvokeFunction",
            "request bodies",
            "response bodies",
        ]
        exc = ConnectorError("access denied", status_code=403)
        for api in ["GetRestApis", "GetStages", "GetApis"]:
            fc = classify_aws_apigateway_failure(api, exc)
            for bad in forbidden:
                assert bad not in fc.recommended_action, (
                    f"API {api}: recommended_action mentions forbidden content {bad!r}"
                )

    def test_kms_key_hashing(self):
        """KMS key IDs must be hashed to 12-char hex prefix."""
        raw = "arn:aws:kms:us-east-1:123456789012:key/abcdef12-3456-7890-abcd-ef1234567890"
        hashed = _hash_kms_key_id(raw)
        assert hashed != raw
        assert len(hashed) == 12


# ─────────────────────────────────────────────────────────────────────────────
# 19. M42 regression guard
# ─────────────────────────────────────────────────────────────────────────────

class TestM42Regression:
    def test_m42_schema_still_present(self):
        assert AWS_RDS_DB_INSTANCE in AWS_RECORD_TYPES

    def test_m42_tracked_fields_still_registered(self):
        from app.services.diff_service import _tracked_fields_for
        fields = _tracked_fields_for({"record_type": AWS_RDS_DB_INSTANCE})
        assert fields is not None
        assert "publicly_accessible" in fields
        assert "storage_encrypted" in fields

    def test_m42_risk_classification_still_works(self):
        change = {
            "record_type": AWS_RDS_DB_INSTANCE,
            "change_type": "modified",
            "field_path": "publicly_accessible",
            "new_value": True,
            "prev_value": False,
            "name": "prod-db",
            "provider_metadata": {
                "record_type": AWS_RDS_DB_INSTANCE,
                "record_name": "prod-db",
            },
        }
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")
        assert reason != ""
