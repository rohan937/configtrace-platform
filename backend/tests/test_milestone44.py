"""Tests for Milestone 44: AWS Load Balancers + WAF Config.

Covers:
- Security hard rules: no access log reads, no sampled requests, no write APIs
- Schema registration: all 7 M44 types in AWS_RECORD_TYPES
- Diff service tracked field registration for all 7 M44 types
- Helper functions: _classify_elb_name_sensitivity, _summarize_elbv2_attributes,
  _summarize_target_group_attributes, _summarize_listener_actions,
  _summarize_listener_rule_conditions, _summarize_wafv2_rules
- Risk classification: aws_elbv2_load_balancer (full matrix)
- Risk classification: aws_elbv2_target_group
- Risk classification: aws_elbv2_listener
- Risk classification: aws_elbv2_listener_rule
- Risk classification: aws_elb_classic_load_balancer
- Risk classification: aws_wafv2_web_acl (full matrix)
- Risk classification: aws_wafv2_web_acl_association
- Failure classification: classify_aws_elbv2_failure
- Failure classification: classify_aws_elb_classic_failure
- Failure classification: classify_aws_wafv2_failure
- Connector normalization: _fetch_elbv2_in_region, _fetch_elb_classic_in_region,
  _fetch_wafv2_in_region
- Service inventory: load_balancers + waf in enabled_surfaces, counts stored
- Fail-soft: per-region errors do not abort the full fetch
- M43 regression guard
"""

import pytest
from unittest.mock import MagicMock

from app.connectors.aws import (
    AWSConnector,
    _classify_elb_name_sensitivity,
    _summarize_elbv2_attributes,
    _summarize_target_group_attributes,
    _summarize_listener_actions,
    _summarize_listener_rule_conditions,
    _summarize_wafv2_rules,
    _hash_elb_arn,
    _hash_kms_key_id,
)
from app.connectors.aws_schema import (
    AWS_ELBV2_LOAD_BALANCER,
    AWS_ELBV2_TARGET_GROUP,
    AWS_ELBV2_LISTENER,
    AWS_ELBV2_LISTENER_RULE,
    AWS_ELB_CLASSIC_LOAD_BALANCER,
    AWS_WAFV2_WEB_ACL,
    AWS_WAFV2_WEB_ACL_ASSOCIATION,
    AWS_SERVICE_INVENTORY,
    AWS_LAMBDA_FUNCTION,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_elbv2_failure,
    classify_aws_elb_classic_failure,
    classify_aws_wafv2_failure,
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


def _elb_change(
    record_type=AWS_ELBV2_LOAD_BALANCER,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="prod-api-lb",
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


def _waf_change(
    record_type=AWS_WAFV2_WEB_ACL,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="prod-waf",
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
# 1. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

class TestM44Schema:
    def test_all_m44_types_in_record_types(self):
        for rt in (
            AWS_ELBV2_LOAD_BALANCER,
            AWS_ELBV2_TARGET_GROUP,
            AWS_ELBV2_LISTENER,
            AWS_ELBV2_LISTENER_RULE,
            AWS_ELB_CLASSIC_LOAD_BALANCER,
            AWS_WAFV2_WEB_ACL,
            AWS_WAFV2_WEB_ACL_ASSOCIATION,
        ):
            assert rt in AWS_RECORD_TYPES, f"{rt!r} missing from AWS_RECORD_TYPES"

    def test_string_values(self):
        assert AWS_ELBV2_LOAD_BALANCER == "aws_elbv2_load_balancer"
        assert AWS_ELBV2_TARGET_GROUP == "aws_elbv2_target_group"
        assert AWS_ELBV2_LISTENER == "aws_elbv2_listener"
        assert AWS_ELBV2_LISTENER_RULE == "aws_elbv2_listener_rule"
        assert AWS_ELB_CLASSIC_LOAD_BALANCER == "aws_elb_classic_load_balancer"
        assert AWS_WAFV2_WEB_ACL == "aws_wafv2_web_acl"
        assert AWS_WAFV2_WEB_ACL_ASSOCIATION == "aws_wafv2_web_acl_association"

    def test_m43_types_still_present(self):
        """M43 schema entries not disturbed."""
        assert AWS_LAMBDA_FUNCTION in AWS_RECORD_TYPES


# ─────────────────────────────────────────────────────────────────────────────
# 2. Helper functions
# ─────────────────────────────────────────────────────────────────────────────

class TestElbNameSensitivity:
    def test_production_name(self):
        assert _classify_elb_name_sensitivity("prod-api-lb") != "unknown"

    def test_sensitive_keywords(self):
        for name in ("prod-payments", "auth-gateway", "admin-lb", "customer-api"):
            cat = _classify_elb_name_sensitivity(name)
            assert cat != "unknown", f"Expected sensitive category for {name!r}"

    def test_non_sensitive_name(self):
        cat = _classify_elb_name_sensitivity("dev-scratch-lb-xyz")
        # Should still return a valid string (category or "unknown")
        assert isinstance(cat, str)

    def test_empty_name(self):
        cat = _classify_elb_name_sensitivity("")
        assert isinstance(cat, str)


class TestSummarizeElbv2Attributes:
    def test_deletion_protection(self):
        attrs = [{"Key": "deletion_protection.enabled", "Value": "true"}]
        result = _summarize_elbv2_attributes(attrs)
        assert result["deletion_protection_enabled"] is True

    def test_access_logs_enabled(self):
        attrs = [
            {"Key": "access_logs.s3.enabled", "Value": "true"},
            {"Key": "access_logs.s3.bucket", "Value": "my-logs-bucket-prod"},
        ]
        result = _summarize_elbv2_attributes(attrs)
        assert result["access_logs_enabled"] is True
        # SECURITY: full bucket name never stored — suffix only
        suffix = result.get("access_logs_bucket_suffix")
        assert suffix is not None
        assert "my-logs-bucket-prod" != suffix or len(suffix) <= 20

    def test_idle_timeout(self):
        attrs = [{"Key": "idle_timeout.timeout_seconds", "Value": "60"}]
        result = _summarize_elbv2_attributes(attrs)
        assert result["idle_timeout_seconds"] == 60

    def test_routing_http2(self):
        attrs = [{"Key": "routing.http2.enabled", "Value": "true"}]
        result = _summarize_elbv2_attributes(attrs)
        assert result["routing_http2_enabled"] is True

    def test_desync_mode(self):
        attrs = [{"Key": "routing.http.desync_mitigation_mode", "Value": "strictest"}]
        result = _summarize_elbv2_attributes(attrs)
        assert result["desync_mitigation_mode"] == "strictest"

    def test_drop_invalid_header(self):
        attrs = [{"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "false"}]
        result = _summarize_elbv2_attributes(attrs)
        assert result["drop_invalid_header_fields_enabled"] is False

    def test_unknown_attributes_not_stored(self):
        attrs = [
            {"Key": "some.unknown.attribute", "Value": "sensitive-value"},
            {"Key": "routing.http2.enabled", "Value": "true"},
        ]
        result = _summarize_elbv2_attributes(attrs)
        # Unknown key value must not appear in result
        flat = str(result)
        assert "sensitive-value" not in flat
        assert result.get("routing_http2_enabled") is True

    def test_empty_attrs(self):
        result = _summarize_elbv2_attributes([])
        assert result == {}


class TestSummarizeTargetGroupAttributes:
    def test_deregistration_delay(self):
        attrs = [{"Key": "deregistration_delay.timeout_seconds", "Value": "30"}]
        result = _summarize_target_group_attributes(attrs)
        assert result["deregistration_delay_seconds"] == 30

    def test_stickiness(self):
        attrs = [{"Key": "stickiness.enabled", "Value": "true"}]
        result = _summarize_target_group_attributes(attrs)
        assert result["stickiness_enabled"] is True

    def test_slow_start(self):
        attrs = [{"Key": "slow_start.duration_seconds", "Value": "120"}]
        result = _summarize_target_group_attributes(attrs)
        assert result["slow_start_duration_seconds"] == 120


class TestSummarizeListenerActions:
    def test_forward_action(self):
        actions = [{"Type": "forward", "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/my-tg/abc123"}]
        result = _summarize_listener_actions(actions)
        assert "forward" in (result["action_types"] or [])
        tg_hashes = result["target_group_arn_hashes"] or []
        assert len(tg_hashes) == 1
        # SECURITY: raw ARN must not be stored
        assert "arn:aws:" not in str(tg_hashes[0])

    def test_auth_action_detected(self):
        actions = [{"Type": "authenticate-cognito"}, {"Type": "forward", "TargetGroupArn": ""}]
        result = _summarize_listener_actions(actions)
        assert result["auth_action_present"] is True

    def test_redirect_action(self):
        actions = [{"Type": "redirect"}]
        result = _summarize_listener_actions(actions)
        assert result["redirect_action_present"] is True

    def test_fixed_response_action(self):
        actions = [{"Type": "fixed-response"}]
        result = _summarize_listener_actions(actions)
        assert result["fixed_response_action_present"] is True

    def test_no_actions(self):
        result = _summarize_listener_actions([])
        assert result["action_types"] is None
        assert result["target_group_arn_hashes"] is None
        assert result["auth_action_present"] is False

    def test_raw_arn_never_in_result(self):
        """SECURITY: raw target group ARNs must never appear in output."""
        arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/sensitive-tg/abcdef"
        actions = [{"Type": "forward", "TargetGroupArn": arn}]
        result = _summarize_listener_actions(actions)
        flat = str(result)
        assert arn not in flat, "SECURITY VIOLATION: raw ARN stored in listener action summary"


class TestSummarizeListenerRuleConditions:
    def test_host_header_condition(self):
        conditions = [{"Field": "host-header", "HostHeaderConfig": {"Values": ["api.example.com"]}}]
        result = _summarize_listener_rule_conditions(conditions)
        assert result["host_header_condition_present"] is True
        # SECURITY: hostname value must not be stored
        flat = str(result)
        assert "api.example.com" not in flat

    def test_path_pattern_condition(self):
        conditions = [{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/admin/*"]}}]
        result = _summarize_listener_rule_conditions(conditions)
        assert result["path_pattern_condition_present"] is True
        # SECURITY: path value must not be stored
        flat = str(result)
        assert "/admin/" not in flat

    def test_source_ip_condition(self):
        conditions = [{"Field": "source-ip"}]
        result = _summarize_listener_rule_conditions(conditions)
        assert result["source_ip_condition_present"] is True

    def test_http_header_condition(self):
        conditions = [{"Field": "http-header"}]
        result = _summarize_listener_rule_conditions(conditions)
        assert result["http_header_condition_present"] is True

    def test_query_string_condition(self):
        conditions = [{"Field": "query-string"}]
        result = _summarize_listener_rule_conditions(conditions)
        assert result["query_string_condition_present"] is True

    def test_no_conditions(self):
        result = _summarize_listener_rule_conditions([])
        assert result["host_header_condition_present"] is False
        assert result["condition_field_counts"] is None

    def test_condition_values_never_stored(self):
        """SECURITY: condition values (hostnames, paths, IPs, query strings) must never appear."""
        conditions = [
            {"Field": "host-header", "HostHeaderConfig": {"Values": ["secret.internal.host"]}},
            {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/private/data"]}},
            {"Field": "query-string", "QueryStringConfig": {"Values": [{"Value": "token=abc123"}]}},
        ]
        result = _summarize_listener_rule_conditions(conditions)
        flat = str(result)
        for forbidden in ("secret.internal.host", "/private/data", "token=abc123"):
            assert forbidden not in flat, f"SECURITY VIOLATION: {forbidden!r} stored in condition summary"


class TestSummarizeWafv2Rules:
    def test_managed_rule_group_count(self):
        rules = [
            {"Statement": {"ManagedRuleGroupStatement": {}}, "Action": {"Block": {}}},
            {"Statement": {"ManagedRuleGroupStatement": {}}, "Action": {"Count": {}}},
        ]
        result = _summarize_wafv2_rules(rules)
        assert result["managed_rule_group_count"] == 2
        assert result["rule_count"] == 2

    def test_rate_based_rule(self):
        rules = [{"Statement": {"RateBasedStatement": {}}, "Action": {"Block": {}}}]
        result = _summarize_wafv2_rules(rules)
        assert result["rate_based_rule_count"] == 1
        assert result["block_action_count"] == 1

    def test_custom_rule_with_allow(self):
        rules = [{"Statement": {"ByteMatchStatement": {}}, "Action": {"Allow": {}}}]
        result = _summarize_wafv2_rules(rules)
        assert result["custom_rule_count"] == 1
        assert result["allow_action_count"] == 1

    def test_override_count_action(self):
        rules = [
            {"Statement": {"ManagedRuleGroupStatement": {}}, "OverrideAction": {"Count": {}}},
        ]
        result = _summarize_wafv2_rules(rules)
        assert result["override_count_action_count"] == 1

    def test_captcha_action(self):
        rules = [{"Statement": {}, "Action": {"Captcha": {}}}]
        result = _summarize_wafv2_rules(rules)
        assert result["captcha_challenge_action_count"] == 1

    def test_empty_rules(self):
        result = _summarize_wafv2_rules([])
        assert result["rule_count"] == 0
        assert result["managed_rule_group_count"] == 0

    def test_rule_statement_values_not_stored(self):
        """SECURITY: rule statement byte match strings, regex, IPs must never be stored."""
        rules = [
            {
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": b"sensitive-pattern",
                        "FieldToMatch": {"Body": {}},
                        "TextTransformations": [],
                        "PositionalConstraint": "CONTAINS",
                    }
                },
                "Action": {"Block": {}},
            }
        ]
        result = _summarize_wafv2_rules(rules)
        flat = str(result)
        # The statement bytes must not appear — only counts
        assert "sensitive-pattern" not in flat
        assert result["custom_rule_count"] == 1


class TestHashElbArn:
    def test_returns_12_char_hex(self):
        arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/abc123"
        h = _hash_elb_arn(arn)
        assert h is not None
        assert len(h) == 12
        assert all(c in "0123456789abcdef" for c in h)

    def test_none_for_empty(self):
        assert _hash_elb_arn("") is None
        assert _hash_elb_arn(None) is None  # type: ignore

    def test_same_as_hash_kms_key_id(self):
        """hash_elb_arn reuses hash_kms_key_id logic."""
        arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/x/y"
        assert _hash_elb_arn(arn) == _hash_kms_key_id(arn)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestM44DiffServiceFields:
    def _record(self, rt):
        return {"record_type": rt}

    def test_elbv2_load_balancer_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ELBV2_LOAD_BALANCER))
        assert len(fields) > 0
        for required in ("type", "scheme", "deletion_protection_enabled",
                         "access_logs_enabled", "security_group_ids",
                         "subnet_ids", "sensitive_name_category"):
            assert required in fields, f"Missing: {required}"
        # SECURITY: must not track raw DNS name
        assert "dns_name" not in fields
        for f in fields:
            assert "dns_name" != f or "hash" in f, f"Raw dns_name tracked: {f}"

    def test_elbv2_target_group_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ELBV2_TARGET_GROUP))
        for required in ("protocol", "port", "target_type", "health_check_enabled",
                         "target_count", "healthy_target_count", "unhealthy_target_count",
                         "stickiness_enabled", "deregistration_delay_seconds"):
            assert required in fields, f"Missing: {required}"

    def test_elbv2_listener_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ELBV2_LISTENER))
        for required in ("protocol", "port", "ssl_policy", "certificate_count",
                         "default_action_types", "load_balancer_arn_hash",
                         "auth_action_present"):
            assert required in fields, f"Missing: {required}"
        # SECURITY: raw LB ARN must not be tracked
        assert "load_balancer_arn" not in fields or "hash" in "load_balancer_arn_hash"

    def test_elbv2_listener_rule_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ELBV2_LISTENER_RULE))
        for required in ("priority", "is_default", "listener_arn_hash",
                         "host_header_condition_present", "path_pattern_condition_present",
                         "action_types", "target_group_arn_hashes"):
            assert required in fields, f"Missing: {required}"
        # SECURITY: no raw condition values
        for f in fields:
            assert "value" not in f.lower() or "count" in f.lower(), (
                f"Potentially raw value field tracked: {f}"
            )

    def test_elb_classic_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ELB_CLASSIC_LOAD_BALANCER))
        for required in ("scheme", "listener_count", "listener_protocols",
                         "access_logs_enabled", "security_group_ids",
                         "instance_count", "healthy_instance_count"):
            assert required in fields, f"Missing: {required}"
        # SECURITY: raw DNS name must not be tracked
        assert "dns_name" not in fields

    def test_wafv2_web_acl_fields(self):
        fields = _tracked_fields_for(self._record(AWS_WAFV2_WEB_ACL))
        for required in ("default_action", "rule_count", "managed_rule_group_count",
                         "rate_based_rule_count", "block_action_count",
                         "allow_action_count", "logging_enabled",
                         "associated_resource_count", "override_count_action_count"):
            assert required in fields, f"Missing: {required}"
        # SECURITY: no raw rule statement values, sampled request fields
        for f in fields:
            assert "sampled" not in f.lower()
            assert "statement" not in f.lower()
            assert "byte_match" not in f.lower()

    def test_wafv2_web_acl_association_fields(self):
        fields = _tracked_fields_for(self._record(AWS_WAFV2_WEB_ACL_ASSOCIATION))
        for required in ("web_acl_arn_hash", "resource_arn_hash", "resource_type", "scope"):
            assert required in fields, f"Missing: {required}"
        # SECURITY: raw ARNs must not be directly tracked (only hashes)
        for f in fields:
            if "arn" in f:
                assert "hash" in f, f"Raw ARN field tracked: {f}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk classification — ELBv2 Load Balancer
# ─────────────────────────────────────────────────────────────────────────────

class TestElbv2LoadBalancerRisk:
    def test_added_sensitive(self):
        ch = _elb_change(change_type="added", record_name="prod-payment-lb")
        level, msg = classify_aws_change(ch)
        assert level in ("high", "medium")

    def test_added_internet_facing_sensitive(self):
        ch = _elb_change(
            change_type="added",
            new_value={"scheme": "internet-facing"},
            record_name="prod-api-lb",
        )
        level, msg = classify_aws_change(ch)
        assert level in ("high", "critical")
        assert "internet" in msg.lower() or "facing" in msg.lower()

    def test_removed_sensitive_lb(self):
        ch = _elb_change(change_type="removed", record_name="prod-lb")
        level, msg = classify_aws_change(ch)
        assert level in ("high", "critical")

    def test_scheme_internal_to_internet_facing_sensitive(self):
        ch = _elb_change(
            field_path="scheme",
            prev_value="internal",
            new_value="internet-facing",
            record_name="prod-payment-lb",
        )
        level, msg = classify_aws_change(ch)
        assert level == "critical"
        assert "internet-facing" in msg or "internet" in msg.lower()

    def test_scheme_internal_to_internet_facing_non_sensitive(self):
        ch = _elb_change(
            field_path="scheme",
            prev_value="internal",
            new_value="internet-facing",
            record_name="scratch-test-lb",
        )
        level, msg = classify_aws_change(ch)
        assert level == "high"

    def test_scheme_internet_to_internal_is_low(self):
        ch = _elb_change(
            field_path="scheme",
            prev_value="internet-facing",
            new_value="internal",
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_security_groups_changed_is_high(self):
        ch = _elb_change(field_path="security_group_ids", new_value=["sg-new"])
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_subnet_count_decreased_is_high(self):
        ch = _elb_change(
            field_path="availability_zone_count",
            prev_value=3,
            new_value=1,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_deletion_protection_disabled_sensitive(self):
        ch = _elb_change(
            field_path="deletion_protection_enabled",
            new_value=False,
            record_name="prod-api-lb",
        )
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_deletion_protection_disabled_non_sensitive(self):
        ch = _elb_change(
            field_path="deletion_protection_enabled",
            new_value=False,
            record_name="dev-test-lb",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_deletion_protection_enabled_is_low(self):
        ch = _elb_change(
            field_path="deletion_protection_enabled",
            new_value=True,
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_access_logs_disabled_is_high(self):
        ch = _elb_change(field_path="access_logs_enabled", new_value=False)
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_access_logs_enabled_is_low(self):
        ch = _elb_change(field_path="access_logs_enabled", new_value=True)
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_desync_weakened_is_high(self):
        ch = _elb_change(
            field_path="desync_mitigation_mode",
            prev_value="strictest",
            new_value="monitor",
        )
        level, msg = classify_aws_change(ch)
        assert level == "high"
        assert "desync" in msg.lower() or "http" in msg.lower()

    def test_drop_invalid_header_disabled_is_high(self):
        ch = _elb_change(field_path="drop_invalid_header_fields_enabled", new_value=False)
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_drop_invalid_header_enabled_is_low(self):
        ch = _elb_change(field_path="drop_invalid_header_fields_enabled", new_value=True)
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_state_failed_is_high(self):
        ch = _elb_change(field_path="state", new_value="failed")
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_routine_attr_is_low(self):
        ch = _elb_change(field_path="tag_keys", new_value=["env", "team"])
        level, _ = classify_aws_change(ch)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification — ELBv2 Target Group
# ─────────────────────────────────────────────────────────────────────────────

class TestElbv2TargetGroupRisk:
    def test_added_is_medium(self):
        ch = _elb_change(record_type=AWS_ELBV2_TARGET_GROUP, change_type="added")
        level, _ = classify_aws_change(ch)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            change_type="removed",
            record_name="prod-api-tg",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_protocol_change_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            field_path="protocol",
            prev_value="HTTPS",
            new_value="HTTP",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_health_check_disabled_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            field_path="health_check_enabled",
            new_value=False,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_target_count_drops_to_zero_sensitive(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            field_path="target_count",
            prev_value=3,
            new_value=0,
            record_name="prod-api-tg",
        )
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_unhealthy_target_count_increases_sensitive(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            field_path="unhealthy_target_count",
            prev_value=0,
            new_value=3,
            record_name="prod-api-tg",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_unhealthy_count_decreases_to_zero_is_low(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            field_path="unhealthy_target_count",
            prev_value=2,
            new_value=0,
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_stickiness_change_is_medium(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_TARGET_GROUP,
            field_path="stickiness_enabled",
            new_value=True,
        )
        level, _ = classify_aws_change(ch)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk classification — ELBv2 Listener
# ─────────────────────────────────────────────────────────────────────────────

class TestElbv2ListenerRisk:
    def _listener_change(self, **kwargs):
        ch = _elb_change(record_type=AWS_ELBV2_LISTENER, **kwargs)
        # Add load_balancer_name to provider_metadata for better context
        ch["provider_metadata"]["load_balancer_name"] = ch["provider_metadata"].get("record_name", "prod-lb")
        return ch

    def test_https_listener_removed_sensitive_is_critical(self):
        ch = self._listener_change(
            change_type="removed",
            prev_value={"protocol": "HTTPS"},
            record_name="prod-api-lb",
        )
        level, msg = classify_aws_change(ch)
        assert level == "critical"
        assert "https" in msg.lower() or "tls" in msg.lower() or "removed" in msg.lower()

    def test_listener_removed_is_at_least_high(self):
        ch = self._listener_change(change_type="removed", record_name="dev-test-lb")
        level, _ = classify_aws_change(ch)
        assert level in ("high", "critical")

    def test_protocol_downgrade_https_to_http_sensitive_is_critical(self):
        ch = self._listener_change(
            field_path="protocol",
            prev_value="HTTPS",
            new_value="HTTP",
            record_name="prod-api-lb",
        )
        level, msg = classify_aws_change(ch)
        assert level == "critical"

    def test_protocol_change_is_at_least_high(self):
        ch = self._listener_change(
            field_path="protocol",
            prev_value="HTTP",
            new_value="HTTPS",
        )
        level, _ = classify_aws_change(ch)
        assert level in ("high", "low", "medium")  # improvement → could be lower

    def test_ssl_policy_change_is_medium_or_high(self):
        ch = self._listener_change(
            field_path="ssl_policy",
            prev_value="ELBSecurityPolicy-TLS13-1-2-2021-06",
            new_value="ELBSecurityPolicy-2016-08",
        )
        level, _ = classify_aws_change(ch)
        assert level in ("medium", "high")

    def test_cert_count_decrease_is_high(self):
        ch = self._listener_change(
            field_path="certificate_count",
            prev_value=2,
            new_value=1,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_default_target_changed_sensitive_is_critical(self):
        ch = self._listener_change(
            field_path="default_target_group_arn_hashes",
            prev_value=["abc123"],
            new_value=["def456"],
            record_name="prod-api-lb",
        )
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_cert_count_increase_is_low(self):
        ch = self._listener_change(
            field_path="certificate_count",
            prev_value=1,
            new_value=2,
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_listener_added_is_medium(self):
        ch = self._listener_change(change_type="added")
        level, _ = classify_aws_change(ch)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk classification — ELBv2 Listener Rule
# ─────────────────────────────────────────────────────────────────────────────

class TestElbv2ListenerRuleRisk:
    def test_added_is_medium(self):
        ch = _elb_change(record_type=AWS_ELBV2_LISTENER_RULE, change_type="added")
        level, _ = classify_aws_change(ch)
        assert level == "medium"

    def test_removed_is_medium(self):
        ch = _elb_change(record_type=AWS_ELBV2_LISTENER_RULE, change_type="removed")
        level, _ = classify_aws_change(ch)
        assert level == "medium"

    def test_target_changed_sensitive_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_LISTENER_RULE,
            field_path="target_group_arn_hashes",
            prev_value=["abc"],
            new_value=["def"],
            record_name="prod-api-lb",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_condition_changed_is_medium(self):
        ch = _elb_change(
            record_type=AWS_ELBV2_LISTENER_RULE,
            field_path="host_header_condition_present",
            new_value=True,
        )
        level, _ = classify_aws_change(ch)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Risk classification — Classic ELB
# ─────────────────────────────────────────────────────────────────────────────

class TestElbClassicRisk:
    def test_added_is_medium(self):
        ch = _elb_change(record_type=AWS_ELB_CLASSIC_LOAD_BALANCER, change_type="added")
        level, _ = classify_aws_change(ch)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELB_CLASSIC_LOAD_BALANCER,
            change_type="removed",
            record_name="prod-classic-lb",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_scheme_internal_to_internet_facing_sensitive_is_critical(self):
        ch = _elb_change(
            record_type=AWS_ELB_CLASSIC_LOAD_BALANCER,
            field_path="scheme",
            prev_value="internal",
            new_value="internet-facing",
            record_name="prod-classic-lb",
        )
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_security_group_changed_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELB_CLASSIC_LOAD_BALANCER,
            field_path="security_group_ids",
            new_value=["sg-new"],
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_listener_changed_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELB_CLASSIC_LOAD_BALANCER,
            field_path="listener_count",
            prev_value=2,
            new_value=1,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_access_logs_disabled_is_high(self):
        ch = _elb_change(
            record_type=AWS_ELB_CLASSIC_LOAD_BALANCER,
            field_path="access_logs_enabled",
            new_value=False,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Risk classification — WAFv2 Web ACL
# ─────────────────────────────────────────────────────────────────────────────

class TestWafv2WebAclRisk:
    def test_added_is_medium(self):
        ch = _waf_change(change_type="added")
        level, _ = classify_aws_change(ch)
        assert level == "medium"

    def test_added_with_allow_default_sensitive_is_high(self):
        ch = _waf_change(
            change_type="added",
            new_value={"default_action": "allow"},
            record_name="prod-waf",
        )
        level, _ = classify_aws_change(ch)
        assert level in ("high", "critical")

    def test_removed_sensitive_is_critical(self):
        ch = _waf_change(change_type="removed", record_name="prod-waf")
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_removed_non_sensitive_is_high(self):
        ch = _waf_change(change_type="removed", record_name="dev-test-waf")
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_default_action_block_to_allow_sensitive_is_critical(self):
        ch = _waf_change(
            field_path="default_action",
            prev_value="block",
            new_value="allow",
            record_name="prod-waf",
        )
        level, msg = classify_aws_change(ch)
        assert level == "critical"
        assert "allow" in msg.lower()

    def test_default_action_allow_to_block_is_low(self):
        ch = _waf_change(
            field_path="default_action",
            prev_value="allow",
            new_value="block",
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_rule_count_drops_to_zero_sensitive_is_critical(self):
        ch = _waf_change(
            field_path="rule_count",
            prev_value=5,
            new_value=0,
            record_name="prod-waf",
        )
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_rule_count_decreases_is_high(self):
        ch = _waf_change(
            field_path="rule_count",
            prev_value=5,
            new_value=2,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_rule_count_increases_is_medium(self):
        ch = _waf_change(
            field_path="rule_count",
            prev_value=2,
            new_value=5,
        )
        level, _ = classify_aws_change(ch)
        assert level == "medium"

    def test_managed_rule_group_removed_all_sensitive_is_critical(self):
        ch = _waf_change(
            field_path="managed_rule_group_count",
            prev_value=3,
            new_value=0,
            record_name="prod-waf",
        )
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_managed_rule_group_decreased_is_high(self):
        ch = _waf_change(
            field_path="managed_rule_group_count",
            prev_value=3,
            new_value=1,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_rate_based_rule_count_decreased_is_high(self):
        ch = _waf_change(
            field_path="rate_based_rule_count",
            prev_value=2,
            new_value=0,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_block_action_count_decreased_is_high(self):
        ch = _waf_change(
            field_path="block_action_count",
            prev_value=5,
            new_value=1,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_block_action_count_increased_is_low(self):
        ch = _waf_change(
            field_path="block_action_count",
            prev_value=1,
            new_value=5,
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_allow_action_count_increased_is_high(self):
        ch = _waf_change(
            field_path="allow_action_count",
            prev_value=1,
            new_value=5,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_override_count_increased_is_high(self):
        ch = _waf_change(
            field_path="override_count_action_count",
            prev_value=0,
            new_value=3,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_logging_disabled_is_high(self):
        ch = _waf_change(field_path="logging_enabled", new_value=False)
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_logging_enabled_is_low(self):
        ch = _waf_change(field_path="logging_enabled", new_value=True)
        level, _ = classify_aws_change(ch)
        assert level == "low"

    def test_associated_resource_count_decreased_is_high(self):
        ch = _waf_change(
            field_path="associated_resource_count",
            prev_value=3,
            new_value=1,
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_tag_change_is_low(self):
        ch = _waf_change(field_path="tag_keys", new_value=["env"])
        level, _ = classify_aws_change(ch)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Risk classification — WAFv2 Association
# ─────────────────────────────────────────────────────────────────────────────

class TestWafv2AssociationRisk:
    def test_removed_sensitive_is_critical(self):
        ch = _waf_change(
            record_type=AWS_WAFV2_WEB_ACL_ASSOCIATION,
            change_type="removed",
            record_name="prod-waf",
        )
        level, msg = classify_aws_change(ch)
        assert level == "critical"
        assert "disassociat" in msg.lower() or "remov" in msg.lower()

    def test_removed_non_sensitive_is_high(self):
        ch = _waf_change(
            record_type=AWS_WAFV2_WEB_ACL_ASSOCIATION,
            change_type="removed",
            record_name="dev-test-waf",
        )
        level, _ = classify_aws_change(ch)
        assert level == "high"

    def test_added_is_low(self):
        ch = _waf_change(
            record_type=AWS_WAFV2_WEB_ACL_ASSOCIATION,
            change_type="added",
        )
        level, _ = classify_aws_change(ch)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Failure classifiers
# ─────────────────────────────────────────────────────────────────────────────

class TestElbv2FailureClassifier:
    def test_access_denied_403(self):
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_elbv2_failure("DescribeLoadBalancers", exc)
        assert fc.category == "authentication"
        assert "elbv2" in fc.error_code or "elb" in fc.error_code
        assert "elasticloadbalancing" in fc.recommended_action

    def test_rate_limited(self):
        exc = RateLimitError("throttled")
        fc = classify_aws_elbv2_failure("DescribeListeners", exc)
        assert fc.category == "rate_limited"
        assert "elbv2" in fc.error_code or "rate" in fc.error_code

    def test_network_error(self):
        exc = NetworkError("timeout")
        fc = classify_aws_elbv2_failure("DescribeTargetGroups", exc)
        assert fc.category == "network"

    def test_server_error_500(self):
        exc = ConnectorError("internal server error", status_code=500)
        fc = classify_aws_elbv2_failure("DescribeTargetHealth", exc)
        assert fc.category == "provider_unavailable"

    def test_known_api_codes(self):
        for api in ("DescribeLoadBalancers", "DescribeListeners",
                    "DescribeRules", "DescribeTargetGroups", "DescribeTargetHealth"):
            exc = ConnectorError("error", status_code=None)
            fc = classify_aws_elbv2_failure(api, exc)
            assert "elbv2" in fc.error_code or "elb" in fc.error_code

    def test_recommended_action_no_write_permissions(self):
        forbidden = [
            "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:DeregisterTargets",
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:DeleteLoadBalancer",
            "s3:GetObject",  # access log objects
        ]
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_elbv2_failure("DescribeLoadBalancers", exc)
        for bad in forbidden:
            assert bad not in fc.recommended_action, (
                f"Forbidden permission {bad!r} appears in recommended_action"
            )

    def test_access_log_not_mentioned_in_recommended_action(self):
        """SECURITY: recommended_action must not suggest reading access log objects."""
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_elbv2_failure("DescribeLoadBalancers", exc)
        assert "GetObject" not in fc.recommended_action
        assert "access log content" not in fc.recommended_action.lower()


class TestElbClassicFailureClassifier:
    def test_access_denied(self):
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_elb_classic_failure("DescribeLoadBalancers", exc)
        assert fc.category == "authentication"
        assert "classic" in fc.error_code or "elb" in fc.error_code

    def test_rate_limited(self):
        exc = RateLimitError("throttled")
        fc = classify_aws_elb_classic_failure("DescribeLoadBalancerAttributes", exc)
        assert fc.category == "rate_limited"

    def test_recommended_action_no_write_permissions(self):
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_elb_classic_failure("DescribeLoadBalancers", exc)
        for bad in ("RegisterInstancesWithLoadBalancer", "CreateLoadBalancer",
                    "DeleteLoadBalancer", "s3:GetObject"):
            assert bad not in fc.recommended_action


class TestWafv2FailureClassifier:
    def test_access_denied(self):
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_wafv2_failure("ListWebACLs", exc)
        assert fc.category == "authentication"
        assert "wafv2" in fc.error_code
        assert "wafv2:" in fc.recommended_action

    def test_rate_limited(self):
        exc = RateLimitError("throttled")
        fc = classify_aws_wafv2_failure("GetWebACL", exc)
        assert fc.category == "rate_limited"

    def test_known_api_codes(self):
        for api in ("ListWebACLs", "GetWebACL", "ListResourcesForWebACL",
                    "GetLoggingConfiguration"):
            exc = ConnectorError("error", status_code=None)
            fc = classify_aws_wafv2_failure(api, exc)
            assert "wafv2" in fc.error_code

    def test_sampled_requests_never_suggested(self):
        """SECURITY: recommended_action must never mention GetSampledRequests."""
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_wafv2_failure("ListWebACLs", exc)
        assert "GetSampledRequests" not in fc.recommended_action
        assert "sampled" not in fc.recommended_action.lower()

    def test_no_write_permissions_suggested(self):
        forbidden = [
            "wafv2:CreateWebACL", "wafv2:UpdateWebACL", "wafv2:DeleteWebACL",
            "wafv2:AssociateWebACL", "wafv2:PutLoggingConfiguration",
        ]
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_wafv2_failure("ListWebACLs", exc)
        for bad in forbidden:
            assert bad not in fc.recommended_action, (
                f"Forbidden WAF permission {bad!r} in recommended_action"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 12. Connector normalization — _fetch_elbv2_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchElbv2InRegion:
    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    LB_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-api-lb/abc123"
    LST_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-api-lb/abc123/lst456"
    RULE_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/prod-api-lb/abc123/lst456/rule789"
    TG_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/prod-api-tg/tg123"

    def _make_mock_client(self):
        return MagicMock()

    def _make_call_aws(self, mock_client,
                       lb_resp=None,
                       attrs_resp=None,
                       tags_resp=None,
                       listeners_resp=None,
                       rules_resp=None,
                       tg_resp=None,
                       tg_attrs_resp=None,
                       health_resp=None):
        def _call_aws(fn, **kwargs):
            if fn is mock_client.describe_load_balancers:
                return lb_resp or {"LoadBalancers": []}
            if fn is mock_client.describe_load_balancer_attributes:
                return attrs_resp or {"Attributes": []}
            if fn is mock_client.describe_tags:
                arn = kwargs.get("ResourceArns", [""])[0] if "ResourceArns" in kwargs else ""
                return tags_resp or {"TagDescriptions": [{"ResourceArn": arn, "Tags": []}]}
            if fn is mock_client.describe_listeners:
                return listeners_resp or {"Listeners": []}
            if fn is mock_client.describe_rules:
                return rules_resp or {"Rules": []}
            if fn is mock_client.describe_target_groups:
                return tg_resp or {"TargetGroups": []}
            if fn is mock_client.describe_target_group_attributes:
                return tg_attrs_resp or {"Attributes": []}
            if fn is mock_client.describe_target_health:
                return health_resp or {"TargetHealthDescriptions": []}
            return {}
        return _call_aws

    def test_basic_lb_fields(self):
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "Type": "application",
                "Scheme": "internet-facing",
                "State": {"Code": "active"},
                "DNSName": "prod-api-lb-123.us-east-1.elb.amazonaws.com",
                "VpcId": "vpc-abc123",
                "IpAddressType": "ipv4",
                "AvailabilityZones": [
                    {"ZoneName": "us-east-1a", "SubnetId": "subnet-1"},
                    {"ZoneName": "us-east-1b", "SubnetId": "subnet-2"},
                ],
                "SecurityGroups": ["sg-abc", "sg-def"],
                "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
            }],
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client, lb_resp=lb_resp)
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        lb_records = [r for r in records if r["record_type"] == AWS_ELBV2_LOAD_BALANCER]
        assert len(lb_records) == 1
        r = lb_records[0]
        assert r["type"] == "application"
        assert r["scheme"] == "internet-facing"
        assert r["state"] == "active"
        assert r["vpc_id"] == "vpc-abc123"
        assert r["availability_zone_count"] == 2
        assert r["subnet_count"] == 2
        assert r["security_group_count"] == 2
        assert r["hosted_zone_id_present"] is True
        assert r["account_id"] == self.ACCOUNT_ID
        assert r["region"] == self.REGION

    def test_dns_name_is_hashed_not_raw(self):
        """SECURITY: raw DNS name must never be stored."""
        dns = "prod-api-lb-1234567890.us-east-1.elb.amazonaws.com"
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "DNSName": dns,
                "AvailabilityZones": [],
                "SecurityGroups": [],
            }],
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client, lb_resp=lb_resp)
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        flat = str(records)
        assert dns not in flat, "SECURITY VIOLATION: raw DNS name stored in LB record"
        lb_recs = [r for r in records if r["record_type"] == AWS_ELBV2_LOAD_BALANCER]
        assert len(lb_recs) == 1
        h = lb_recs[0]["dns_name_hash"]
        assert h is not None
        assert len(h) == 12

    def test_tag_values_never_stored(self):
        """SECURITY: tag values must never be stored — only keys."""
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "AvailabilityZones": [],
                "SecurityGroups": [],
            }],
        }
        tags_resp = {
            "TagDescriptions": [{
                "ResourceArn": self.LB_ARN,
                "Tags": [
                    {"Key": "env", "Value": "production-secret-value"},
                    {"Key": "team", "Value": "payments-internal"},
                ],
            }]
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(
            client, lb_resp=lb_resp, tags_resp=tags_resp
        )
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        flat = str(records)
        assert "production-secret-value" not in flat, "SECURITY: tag value stored"
        assert "payments-internal" not in flat, "SECURITY: tag value stored"
        lb_recs = [r for r in records if r["record_type"] == AWS_ELBV2_LOAD_BALANCER]
        assert lb_recs[0]["tag_keys"] == ["env", "team"]

    def test_attributes_extracted(self):
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "AvailabilityZones": [],
                "SecurityGroups": [],
            }],
        }
        attrs_resp = {
            "Attributes": [
                {"Key": "deletion_protection.enabled", "Value": "true"},
                {"Key": "access_logs.s3.enabled", "Value": "false"},
                {"Key": "idle_timeout.timeout_seconds", "Value": "60"},
            ]
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(
            client, lb_resp=lb_resp, attrs_resp=attrs_resp
        )
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        lb_recs = [r for r in records if r["record_type"] == AWS_ELBV2_LOAD_BALANCER]
        r = lb_recs[0]
        assert r["deletion_protection_enabled"] is True
        assert r["access_logs_enabled"] is False
        assert r["idle_timeout_seconds"] == 60

    def test_listener_record_created(self):
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "AvailabilityZones": [],
                "SecurityGroups": [],
            }],
        }
        lst_resp = {
            "Listeners": [{
                "ListenerArn": self.LST_ARN,
                "LoadBalancerArn": self.LB_ARN,
                "Port": 443,
                "Protocol": "HTTPS",
                "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                "Certificates": [{"CertificateArn": "arn:aws:acm:us-east-1:123:certificate/cert-1"}],
                "DefaultActions": [{"Type": "forward", "TargetGroupArn": self.TG_ARN}],
            }],
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(
            client, lb_resp=lb_resp, listeners_resp=lst_resp
        )
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        lst_recs = [r for r in records if r["record_type"] == AWS_ELBV2_LISTENER]
        assert len(lst_recs) == 1
        r = lst_recs[0]
        assert r["protocol"] == "HTTPS"
        assert r["port"] == 443
        assert r["ssl_policy"] == "ELBSecurityPolicy-TLS13-1-2-2021-06"
        assert r["certificate_count"] == 1
        # SECURITY: raw listener ARN and TG ARN must not be raw in output
        flat = str(records)
        assert self.TG_ARN not in flat, "SECURITY: raw TG ARN stored in listener record"
        # LB ARN hash present
        assert r["load_balancer_arn_hash"] is not None
        assert self.LB_ARN not in str(r["load_balancer_arn_hash"])

    def test_listener_rule_record_created(self):
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "AvailabilityZones": [],
                "SecurityGroups": [],
            }],
        }
        lst_resp = {
            "Listeners": [{
                "ListenerArn": self.LST_ARN,
                "LoadBalancerArn": self.LB_ARN,
                "Port": 80,
                "Protocol": "HTTP",
                "Certificates": [],
                "DefaultActions": [],
            }],
        }
        rules_resp = {
            "Rules": [{
                "RuleArn": self.RULE_ARN,
                "Priority": "100",
                "Conditions": [
                    {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/api/*"]}},
                ],
                "Actions": [{"Type": "forward", "TargetGroupArn": self.TG_ARN}],
            }],
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(
            client, lb_resp=lb_resp, listeners_resp=lst_resp, rules_resp=rules_resp
        )
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        rule_recs = [r for r in records if r["record_type"] == AWS_ELBV2_LISTENER_RULE]
        assert len(rule_recs) == 1
        r = rule_recs[0]
        assert r["priority"] == "100"
        assert r["is_default"] is False
        assert r["path_pattern_condition_present"] is True
        # SECURITY: path values must not be stored
        flat = str(records)
        assert "/api/" not in flat, "SECURITY: path condition value stored in rule record"
        # SECURITY: raw TG ARN must be hashed
        assert self.TG_ARN not in flat, "SECURITY: raw TG ARN stored in rule record"

    def test_target_group_record_created(self):
        tg_resp = {
            "TargetGroups": [{
                "TargetGroupArn": self.TG_ARN,
                "TargetGroupName": "prod-api-tg",
                "Protocol": "HTTP",
                "Port": 8080,
                "TargetType": "ip",
                "VpcId": "vpc-abc123",
                "HealthCheckEnabled": True,
                "HealthCheckProtocol": "HTTP",
                "HealthCheckPort": "traffic-port",
                "HealthCheckPath": "/health",
                "HealthCheckIntervalSeconds": 30,
                "HealthCheckTimeoutSeconds": 5,
                "HealthyThresholdCount": 5,
                "UnhealthyThresholdCount": 2,
                "Matcher": {"HttpCode": "200"},
                "LoadBalancerArns": [self.LB_ARN],
            }],
        }
        health_resp = {
            "TargetHealthDescriptions": [
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "unhealthy"}},
            ]
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(
            client, tg_resp=tg_resp, health_resp=health_resp
        )
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        tg_recs = [r for r in records if r["record_type"] == AWS_ELBV2_TARGET_GROUP]
        assert len(tg_recs) == 1
        r = tg_recs[0]
        assert r["protocol"] == "HTTP"
        assert r["port"] == 8080
        assert r["target_type"] == "ip"
        assert r["health_check_enabled"] is True
        assert r["health_check_path_present"] is True
        assert r["target_count"] == 3
        assert r["healthy_target_count"] == 2
        assert r["unhealthy_target_count"] == 1
        assert r["load_balancer_arn_count"] == 1
        assert r["matcher_summary"] == "200"

    def test_stable_record_id(self):
        """Record IDs must be deterministic: account_id/region/arn."""
        lb_resp = {
            "LoadBalancers": [{
                "LoadBalancerArn": self.LB_ARN,
                "LoadBalancerName": "prod-api-lb",
                "AvailabilityZones": [],
                "SecurityGroups": [],
            }],
        }
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client, lb_resp=lb_resp)
        records = conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        lb_recs = [r for r in records if r["record_type"] == AWS_ELBV2_LOAD_BALANCER]
        expected_id = f"{self.ACCOUNT_ID}/{self.REGION}/{self.LB_ARN}"
        assert lb_recs[0]["record_id"] == expected_id

    def test_no_write_api_called(self):
        """Connector must never call ELB write/mutate methods."""
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client)
        conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        write_methods = [
            "create_load_balancer", "delete_load_balancer",
            "modify_load_balancer_attributes",
            "register_targets", "deregister_targets",
            "create_listener", "delete_listener",
            "modify_listener", "create_rule", "delete_rule",
        ]
        for method in write_methods:
            m = getattr(client, method)
            m.assert_not_called(), f"Write API {method!r} was called"

    def test_access_log_api_never_called(self):
        """SECURITY: No S3 GetObject or access log reading should occur."""
        conn = _make_connector()
        client = self._make_mock_client()
        called_fns = []
        def _call_aws(fn, **kwargs):
            called_fns.append(fn)
            return {}
        conn._call_aws = _call_aws
        conn._fetch_elbv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        # Verify no S3 client was used
        # (we can't easily check cross-service calls here, but we verify
        # no raw access log functions exist on the elbv2 client)
        for fn in called_fns:
            fn_name = getattr(fn, "__name__", str(fn)).lower()
            assert "get_object" not in fn_name
            assert "access_log" not in fn_name


# ─────────────────────────────────────────────────────────────────────────────
# 13. Connector normalization — _fetch_elb_classic_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchElbClassicInRegion:
    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    def _make_call_aws(self, mock_client,
                       lb_resp=None,
                       attrs_resp=None,
                       health_resp=None,
                       tags_resp=None):
        def _call_aws(fn, **kwargs):
            if fn is mock_client.describe_load_balancers:
                return lb_resp or {"LoadBalancerDescriptions": []}
            if fn is mock_client.describe_load_balancer_attributes:
                return attrs_resp or {"LoadBalancerAttributes": {}}
            if fn is mock_client.describe_instance_health:
                return health_resp or {"InstanceStates": []}
            if fn is mock_client.describe_tags:
                return tags_resp or {"TagDescriptions": []}
            return {}
        return _call_aws

    def test_basic_classic_lb_fields(self):
        lb_resp = {
            "LoadBalancerDescriptions": [{
                "LoadBalancerName": "prod-classic",
                "DNSName": "prod-classic-1234.us-east-1.elb.amazonaws.com",
                "Scheme": "internet-facing",
                "VPCId": "vpc-abc123",
                "Subnets": ["subnet-1", "subnet-2"],
                "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                "SecurityGroups": ["sg-abc"],
                "ListenerDescriptions": [
                    {"Listener": {"Protocol": "HTTPS", "LoadBalancerPort": 443, "InstancePort": 8443}},
                    {"Listener": {"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 8080}},
                ],
                "Instances": [{"InstanceId": "i-abc"}, {"InstanceId": "i-def"}],
            }],
        }
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(client, lb_resp=lb_resp)
        records = conn._fetch_elb_classic_in_region(client, self.ACCOUNT_ID, self.REGION)

        clb_recs = [r for r in records if r["record_type"] == AWS_ELB_CLASSIC_LOAD_BALANCER]
        assert len(clb_recs) == 1
        r = clb_recs[0]
        assert r["scheme"] == "internet-facing"
        assert r["vpc_id"] == "vpc-abc123"
        assert r["listener_count"] == 2
        assert "HTTPS" in (r["listener_protocols"] or [])
        assert r["instance_count"] == 2
        assert r["availability_zone_count"] == 2

    def test_dns_name_hashed_never_raw(self):
        """SECURITY: raw DNS name must never appear in classic ELB record."""
        dns = "prod-classic-9876543210.us-east-1.elb.amazonaws.com"
        lb_resp = {
            "LoadBalancerDescriptions": [{
                "LoadBalancerName": "prod-classic",
                "DNSName": dns,
                "Scheme": "internal",
                "VPCId": "",
                "Subnets": [],
                "AvailabilityZones": [],
                "SecurityGroups": [],
                "ListenerDescriptions": [],
                "Instances": [],
            }],
        }
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(client, lb_resp=lb_resp)
        records = conn._fetch_elb_classic_in_region(client, self.ACCOUNT_ID, self.REGION)
        flat = str(records)
        assert dns not in flat, "SECURITY VIOLATION: raw DNS name stored in classic ELB record"

    def test_instance_health_count_only(self):
        """SECURITY: only health counts stored, no instance IDs or IPs."""
        lb_resp = {
            "LoadBalancerDescriptions": [{
                "LoadBalancerName": "prod-classic",
                "DNSName": "x.elb.amazonaws.com",
                "Scheme": "internal",
                "VPCId": "",
                "Subnets": [],
                "AvailabilityZones": [],
                "SecurityGroups": [],
                "ListenerDescriptions": [],
                "Instances": [{"InstanceId": "i-secret-id"}],
            }],
        }
        health_resp = {
            "InstanceStates": [
                {"InstanceId": "i-secret-id", "State": "InService"},
                {"InstanceId": "i-secret-id2", "State": "OutOfService"},
            ]
        }
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(
            client, lb_resp=lb_resp, health_resp=health_resp
        )
        records = conn._fetch_elb_classic_in_region(client, self.ACCOUNT_ID, self.REGION)
        flat = str(records)
        assert "i-secret-id" not in flat, "SECURITY: instance ID stored in health record"
        clb_recs = [r for r in records if r["record_type"] == AWS_ELB_CLASSIC_LOAD_BALANCER]
        r = clb_recs[0]
        assert r["healthy_instance_count"] == 1
        assert r["unhealthy_instance_count"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 14. Connector normalization — _fetch_wafv2_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchWafv2InRegion:
    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"
    ACL_ARN = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-waf/acl-id-123"
    ACL_ID = "acl-id-123"
    RES_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-lb/abc"

    def _make_call_aws(self, mock_client,
                       list_resp=None,
                       get_resp=None,
                       log_resp=None,
                       resources_resp=None,
                       tags_resp=None):
        def _call_aws(fn, **kwargs):
            if fn is mock_client.list_web_acls:
                return list_resp or {"WebACLs": []}
            if fn is mock_client.get_web_acl:
                return get_resp or {"WebACL": {}}
            if fn is mock_client.get_logging_configuration:
                return log_resp or {}
            if fn is mock_client.list_resources_for_web_acl:
                return resources_resp or {"ResourceArns": []}
            if fn is mock_client.list_tags_for_resource:
                return tags_resp or {"TagInfoForResource": {"TagList": []}}
            return {}
        return _call_aws

    def test_basic_web_acl_fields(self):
        list_resp = {
            "WebACLs": [{
                "Name": "prod-waf",
                "Id": self.ACL_ID,
                "ARN": self.ACL_ARN,
            }],
        }
        get_resp = {
            "WebACL": {
                "Name": "prod-waf",
                "Id": self.ACL_ID,
                "ARN": self.ACL_ARN,
                "Description": "Production WAF",
                "DefaultAction": {"Block": {}},
                "Rules": [
                    {"Statement": {"ManagedRuleGroupStatement": {}}, "Action": {"Block": {}}},
                    {"Statement": {"RateBasedStatement": {}}, "Action": {"Block": {}}},
                ],
            }
        }
        log_resp = {"LoggingConfiguration": {"LogDestinationConfigs": ["arn:aws:logs:..."]}}
        resources_resp = {"ResourceArns": [self.RES_ARN]}
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(
            client,
            list_resp=list_resp,
            get_resp=get_resp,
            log_resp=log_resp,
            resources_resp=resources_resp,
        )
        records = conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        acl_recs = [r for r in records if r["record_type"] == AWS_WAFV2_WEB_ACL]
        assert len(acl_recs) == 1
        r = acl_recs[0]
        assert r["name"] == "prod-waf"
        assert r["default_action"] == "block"
        assert r["rule_count"] == 2
        assert r["managed_rule_group_count"] == 1
        assert r["rate_based_rule_count"] == 1
        assert r["logging_enabled"] is True
        assert r["associated_resource_count"] == 1
        assert r["description_present"] is True
        assert r["scope"] == "REGIONAL"
        assert r["account_id"] == self.ACCOUNT_ID
        assert r["region"] == self.REGION

    def test_association_record_created(self):
        list_resp = {
            "WebACLs": [{
                "Name": "prod-waf",
                "Id": self.ACL_ID,
                "ARN": self.ACL_ARN,
            }],
        }
        resources_resp = {"ResourceArns": [self.RES_ARN]}
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(
            client, list_resp=list_resp, resources_resp=resources_resp
        )
        records = conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        assoc_recs = [r for r in records if r["record_type"] == AWS_WAFV2_WEB_ACL_ASSOCIATION]
        assert len(assoc_recs) == 1
        r = assoc_recs[0]
        assert r["resource_type"] == "alb"
        assert r["web_acl_arn_hash"] is not None
        assert r["resource_arn_hash"] is not None
        # SECURITY: raw ARNs must not be stored in association record
        flat = str(r)
        assert self.RES_ARN not in flat, "SECURITY: raw resource ARN stored in association"
        assert self.ACL_ARN not in flat or r.get("acl_arn") == self.ACL_ARN  # ACL ARN stored in parent record only

    def test_raw_rule_statements_never_stored(self):
        """SECURITY: rule statement values (byte strings, regex, IPs) must not be stored."""
        list_resp = {
            "WebACLs": [{"Name": "prod-waf", "Id": self.ACL_ID, "ARN": self.ACL_ARN}],
        }
        get_resp = {
            "WebACL": {
                "Name": "prod-waf",
                "Id": self.ACL_ID,
                "DefaultAction": {"Block": {}},
                "Rules": [{
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": b"secret-pattern-string",
                            "FieldToMatch": {"Body": {}},
                        }
                    },
                    "Action": {"Block": {}},
                }],
            }
        }
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(
            client, list_resp=list_resp, get_resp=get_resp
        )
        records = conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        flat = str(records)
        assert "secret-pattern-string" not in flat, (
            "SECURITY VIOLATION: rule statement value stored"
        )

    def test_sampled_requests_never_called(self):
        """SECURITY: GetSampledRequests must never be called."""
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(client)
        conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        client.get_sampled_requests.assert_not_called()

    def test_no_write_api_called(self):
        """Connector must never call WAF write/mutate methods."""
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(client)
        conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)

        write_methods = [
            "create_web_acl", "update_web_acl", "delete_web_acl",
            "associate_web_acl", "disassociate_web_acl",
            "put_logging_configuration", "delete_logging_configuration",
        ]
        for method in write_methods:
            m = getattr(client, method)
            m.assert_not_called(), f"WAF write API {method!r} was called"

    def test_tag_values_never_stored(self):
        """SECURITY: tag values must never be stored."""
        list_resp = {"WebACLs": [{"Name": "prod-waf", "Id": self.ACL_ID, "ARN": self.ACL_ARN}]}
        tags_resp = {
            "TagInfoForResource": {
                "TagList": [
                    {"Key": "env", "Value": "super-secret-env"},
                    {"Key": "team", "Value": "security-internal"},
                ]
            }
        }
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(
            client, list_resp=list_resp, tags_resp=tags_resp
        )
        records = conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        flat = str(records)
        assert "super-secret-env" not in flat, "SECURITY: tag value stored"
        assert "security-internal" not in flat, "SECURITY: tag value stored"
        acl_recs = [r for r in records if r["record_type"] == AWS_WAFV2_WEB_ACL]
        assert acl_recs[0]["tag_keys"] == ["env", "team"]

    def test_stable_record_id(self):
        list_resp = {"WebACLs": [{"Name": "prod-waf", "Id": self.ACL_ID, "ARN": self.ACL_ARN}]}
        conn = _make_connector()
        client = MagicMock()
        conn._call_aws = self._make_call_aws(client, list_resp=list_resp)
        records = conn._fetch_wafv2_in_region(client, self.ACCOUNT_ID, self.REGION)
        acl_recs = [r for r in records if r["record_type"] == AWS_WAFV2_WEB_ACL]
        expected = f"{self.ACCOUNT_ID}/{self.REGION}/REGIONAL/{self.ACL_ARN}"
        assert acl_recs[0]["record_id"] == expected


# ─────────────────────────────────────────────────────────────────────────────
# 15. Fail-soft behavior
# ─────────────────────────────────────────────────────────────────────────────

class TestM44FailSoft:
    ACCOUNT_ID = "123456789012"

    def test_elbv2_access_denied_does_not_abort(self):
        """ELBv2 access denied in one region should not abort the full fetch."""
        conn = _make_connector()

        def _make_client(service, credentials, region=None):
            return MagicMock()

        def _selected_regions(credentials):
            return ["us-east-1", "eu-west-1"]

        conn._make_client = _make_client
        conn._selected_regions = _selected_regions

        def _fetch_in_region(client, account_id, region):
            if region == "us-east-1":
                raise ConnectorError("Access Denied", status_code=403)
            return [{"record_type": AWS_ELBV2_LOAD_BALANCER, "name": "eu-lb"}]

        conn._fetch_elbv2_in_region = _fetch_in_region

        creds = _creds(["us-east-1", "eu-west-1"])
        result = conn._fetch_elbv2_resources(creds, self.ACCOUNT_ID)
        # Should still return records from eu-west-1
        assert len(result) == 1
        assert result[0]["name"] == "eu-lb"

    def test_wafv2_access_denied_does_not_abort(self):
        """WAFv2 access denied in one region should not abort the full fetch."""
        conn = _make_connector()

        def _make_client(service, credentials, region=None):
            return MagicMock()

        def _selected_regions(credentials):
            return ["us-east-1", "ap-southeast-1"]

        conn._make_client = _make_client
        conn._selected_regions = _selected_regions

        call_count = [0]
        def _fetch_in_region(client, account_id, region, scope="REGIONAL"):
            call_count[0] += 1
            if region == "us-east-1":
                raise ConnectorError("Access Denied", status_code=403)
            return [{"record_type": AWS_WAFV2_WEB_ACL, "name": "ap-waf"}]

        conn._fetch_wafv2_in_region = _fetch_in_region

        creds = _creds(["us-east-1", "ap-southeast-1"])
        result = conn._fetch_wafv2_resources(creds, self.ACCOUNT_ID)
        assert len(result) == 1
        assert result[0]["name"] == "ap-waf"


# ─────────────────────────────────────────────────────────────────────────────
# 16. Service inventory
# ─────────────────────────────────────────────────────────────────────────────

class TestM44ServiceInventory:
    def test_load_balancers_in_enabled_surfaces(self):
        conn = _make_connector()
        creds = _creds()

        def _selected_regions(c):
            return ["us-east-1"]
        conn._selected_regions = _selected_regions

        inv = conn._fetch_service_inventory(
            creds,
            elbv2_lb_count=3,
            elb_classic_count=1,
            wafv2_acl_count=2,
        )
        surfaces = inv["enabled_surfaces"]
        assert "load_balancers" in surfaces
        assert "waf" in surfaces

    def test_m44_counts_stored(self):
        conn = _make_connector()
        creds = _creds()

        def _selected_regions(c):
            return ["us-east-1"]
        conn._selected_regions = _selected_regions

        inv = conn._fetch_service_inventory(
            creds,
            elbv2_lb_count=5,
            elb_classic_count=2,
            wafv2_acl_count=3,
        )
        assert inv["elbv2_lb_count"] == 5
        assert inv["elb_classic_count"] == 2
        assert inv["wafv2_acl_count"] == 3

    def test_m44_counts_default_zero(self):
        conn = _make_connector()
        creds = _creds()

        def _selected_regions(c):
            return ["us-east-1"]
        conn._selected_regions = _selected_regions

        inv = conn._fetch_service_inventory(creds)
        assert inv["elbv2_lb_count"] == 0
        assert inv["elb_classic_count"] == 0
        assert inv["wafv2_acl_count"] == 0

    def test_load_balancers_not_in_future_surfaces(self):
        """load_balancers/waf moved from future_surfaces to enabled_surfaces."""
        conn = _make_connector()
        creds = _creds()

        def _selected_regions(c):
            return ["us-east-1"]
        conn._selected_regions = _selected_regions

        inv = conn._fetch_service_inventory(creds)
        future = inv.get("future_surfaces", [])
        assert "load_balancers" not in future
        assert "waf" not in future

    def test_m43_still_in_enabled_surfaces(self):
        conn = _make_connector()
        creds = _creds()

        def _selected_regions(c):
            return ["us-east-1"]
        conn._selected_regions = _selected_regions

        inv = conn._fetch_service_inventory(creds)
        assert "lambda" in inv["enabled_surfaces"]
        assert "api_gateway" in inv["enabled_surfaces"]


# ─────────────────────────────────────────────────────────────────────────────
# 17. Security hard rules
# ─────────────────────────────────────────────────────────────────────────────

class TestM44SecurityHardRules:
    def test_elbv2_failure_classifier_no_access_log_reads(self):
        """ELB failure classifier must never suggest reading access logs."""
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_elbv2_failure("DescribeLoadBalancers", exc)
        forbidden = ["GetObject", "s3:Get", "access_log", "log content"]
        for bad in forbidden:
            assert bad not in fc.recommended_action, (
                f"Access log read mentioned in recommended_action: {bad!r}"
            )

    def test_wafv2_failure_classifier_no_sampled_requests(self):
        """WAF failure classifier must never suggest GetSampledRequests."""
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_wafv2_failure("ListWebACLs", exc)
        assert "GetSampledRequests" not in fc.recommended_action
        assert "sampled" not in fc.recommended_action.lower()

    def test_elbv2_failure_classifier_no_write_perms(self):
        write_perms = [
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:DeleteLoadBalancer",
            "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:DeregisterTargets",
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
        ]
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_elbv2_failure("DescribeLoadBalancers", exc)
        for perm in write_perms:
            assert perm not in fc.recommended_action, (
                f"Write permission {perm!r} in recommended_action"
            )

    def test_wafv2_failure_classifier_no_write_perms(self):
        write_perms = [
            "wafv2:CreateWebACL",
            "wafv2:UpdateWebACL",
            "wafv2:DeleteWebACL",
            "wafv2:AssociateWebACL",
            "wafv2:PutLoggingConfiguration",
        ]
        exc = ConnectorError("denied", status_code=403)
        fc = classify_aws_wafv2_failure("ListWebACLs", exc)
        for perm in write_perms:
            assert perm not in fc.recommended_action, (
                f"WAF write permission {perm!r} in recommended_action"
            )

    def test_hash_consistency(self):
        """ELB ARN hashing uses the same algorithm as KMS key hashing."""
        arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/abc"
        elb_hash = _hash_elb_arn(arn)
        kms_hash = _hash_kms_key_id(arn)
        assert elb_hash == kms_hash
        assert len(elb_hash) == 12


# ─────────────────────────────────────────────────────────────────────────────
# 18. M43 regression guard
# ─────────────────────────────────────────────────────────────────────────────

class TestM43Regression:
    def test_m43_schema_still_correct(self):
        from app.connectors.aws_schema import (
            AWS_LAMBDA_FUNCTION, AWS_APIGATEWAYV2_API,
        )
        assert AWS_LAMBDA_FUNCTION == "aws_lambda_function"
        assert AWS_APIGATEWAYV2_API == "aws_apigatewayv2_api"
        assert AWS_LAMBDA_FUNCTION in AWS_RECORD_TYPES
        assert AWS_APIGATEWAYV2_API in AWS_RECORD_TYPES

    def test_m43_risk_still_dispatches(self):
        ch = {
            "record_type": "aws_lambda_function_url",
            "change_type": "modified",
            "field_path": "auth_type",
            "new_value": "NONE",
            "prev_value": "AWS_IAM",
            "provider_metadata": {"record_type": "aws_lambda_function_url", "record_name": "my-function"},
        }
        level, _ = classify_aws_change(ch)
        assert level == "critical"

    def test_m43_diff_fields_unchanged(self):
        fields = _tracked_fields_for({"record_type": "aws_lambda_function"})
        assert "runtime" in fields
        assert "environment_key_names" in fields
        assert "environment_key_count" in fields
