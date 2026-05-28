"""AWS Part 1 expansion — EC2 exposure, LBs, CloudFront, WAFv2, API
Gateway, VPC Flow Logs.

Coverage strategy
-----------------
* **NEW record types** (`aws_ec2_instance`, `aws_vpc_flow_log`): full
  scenario coverage via the new sub-classifiers added in M59.8.
* **Existing record types** (CloudFront distribution, ELBv2 LB / listener /
  target group, ELB Classic, WAFv2 web ACL + association, API Gateway v1/v2):
  black-box re-verification of the scenarios called out in the brief, using
  the existing classifiers via the top-level `classify_aws_change` dispatch.
* **Dispatcher / safety**: unknown subtype + malformed `provider_metadata`.
* **Secret-safety tripwires**: realistic AWS-shaped credentials must never
  appear in any risk reason.

All tests run without PostgreSQL.  No real AWS API is called.
"""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.aws import (
    classify_aws_change,
    _classify_ec2_instance_change,
    _classify_vpc_flow_log_change,
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
# A. aws_ec2_instance — exposure context (NEW)
# ═════════════════════════════════════════════════════════════════════════════


class TestEC2Instance:

    def test_A1_public_ip_assigned_on_sensitive_prod_instance_in_public_subnet_is_critical(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value=None, new_value="203.0.113.10",
            pm_extra={
                "record_id": "i-prod-db-001",
                "tags": {"env": "production", "role": "db"},
                "in_public_subnet": True,
            },
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "may expose" in reason.lower()

    def test_A2_public_ip_assigned_on_sensitive_private_subnet_is_high(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value=None, new_value="203.0.113.10",
            pm_extra={
                "record_id": "i-prod-app-002",
                "tags": {"env": "production"},
                "in_public_subnet": False,
            },
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A3_public_ip_assigned_on_ordinary_instance_is_medium(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value=None, new_value="203.0.113.10",
            pm_extra={
                "record_id": "i-dev-001",
                "tags": {"env": "dev"},
                "in_public_subnet": False,
            },
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_A4_public_ip_removed_is_low_exposure_reducing(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value="203.0.113.10", new_value=None,
            pm_extra={"record_id": "i-prod-001",
                      "tags": {"env": "production"}},
        )
        level, reason = classify_aws_change(c)
        assert level == "low"
        assert "no longer" in reason.lower() or "reduced" in reason.lower()

    def test_A5_imdsv2_no_longer_required_on_prod_is_high(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="imds_v2_required",
            prev_value=True, new_value=False,
            pm_extra={"record_id": "i-prod-001",
                      "tags": {"env": "production"}},
        )
        level, reason = classify_aws_change(c)
        assert level == "high"
        assert "imdsv2" in reason.lower()

    def test_A6_imdsv2_no_longer_required_on_dev_is_medium(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="imds_v2_required",
            prev_value=True, new_value=False,
            pm_extra={"record_id": "i-dev-001", "tags": {"env": "dev"}},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_A7_imds_http_tokens_lowered_from_required_is_high_on_prod(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="imds_http_tokens",
            prev_value="required", new_value="optional",
            pm_extra={"record_id": "i-prod-001",
                      "tags": {"env": "production"}},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A8_imds_http_tokens_raised_to_required_is_low(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="imds_http_tokens",
            prev_value="optional", new_value="required",
            pm_extra={"record_id": "i-prod-001"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_A9_imds_endpoint_disabled_is_medium(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="imds_http_endpoint",
            prev_value="enabled", new_value="disabled",
            pm_extra={"record_id": "i-prod-001"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_A10_source_dest_check_disabled_is_medium(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="source_dest_check",
            prev_value=True, new_value=False,
            pm_extra={"record_id": "i-prod-001"},
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"
        assert "source" in reason.lower() and "destination" in reason.lower()

    def test_A11_moved_to_public_subnet_on_sensitive_is_high(self):
        c = _ch(
            record_type="aws_ec2_instance", field_path="in_public_subnet",
            prev_value=False, new_value=True,
            pm_extra={"record_id": "i-prod-db-001",
                      "tags": {"role": "database"}},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A12_added_with_public_ip_and_sensitive_tags_is_high(self):
        c = _ch(
            record_type="aws_ec2_instance", change_type="added",
            new_value={"public_ip_address": "203.0.113.10",
                       "instance_type": "m5.large"},
            pm_extra={"record_id": "i-prod-admin-001",
                      "tags": {"env": "prod", "role": "admin"}},
        )
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_A13_added_without_public_ip_is_low(self):
        c = _ch(
            record_type="aws_ec2_instance", change_type="added",
            new_value={"instance_type": "t3.micro"},
            pm_extra={"record_id": "i-dev-001"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_A14_uses_hedged_wording_never_definitely_reachable(self):
        # The most-severe scenario should still hedge.
        c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value=None, new_value="203.0.113.10",
            pm_extra={"record_id": "i-prod-db-001",
                      "tags": {"env": "production", "role": "db"},
                      "in_public_subnet": True},
        )
        _, reason = classify_aws_change(c)
        r = reason.lower()
        assert "definitely reachable" not in r
        assert "definitely publicly reachable" not in r
        assert "compromised" not in r
        # The hedged phrasing is present.
        assert "may " in r or "verify" in r


# ═════════════════════════════════════════════════════════════════════════════
# B. aws_vpc_flow_log — visibility (NEW)
# ═════════════════════════════════════════════════════════════════════════════


class TestVPCFlowLog:

    def test_B1_flow_log_removed_on_prod_vpc_is_high(self):
        c = _ch(
            record_type="aws_vpc_flow_log", change_type="removed",
            pm_extra={"record_id": "fl-001", "resource_id": "vpc-prod",
                      "targets_production": True},
        )
        level, reason = classify_aws_change(c)
        assert level == "high"
        assert "no longer captured" in reason.lower()

    def test_B2_flow_log_removed_on_non_prod_vpc_is_medium(self):
        c = _ch(
            record_type="aws_vpc_flow_log", change_type="removed",
            pm_extra={"record_id": "fl-002", "resource_id": "vpc-dev",
                      "targets_production": False},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_B3_flow_log_status_inactive_is_medium(self):
        c = _ch(
            record_type="aws_vpc_flow_log", field_path="flow_log_status",
            prev_value="ACTIVE", new_value="INACTIVE",
            pm_extra={"record_id": "fl-003", "resource_id": "vpc-dev"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_B4_traffic_type_narrowed_is_medium(self):
        c = _ch(
            record_type="aws_vpc_flow_log", field_path="traffic_type",
            prev_value="ALL", new_value="REJECT",
            pm_extra={"record_id": "fl-004"},
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"
        assert "narrowed" in reason.lower()

    def test_B5_traffic_type_broadened_is_low(self):
        c = _ch(
            record_type="aws_vpc_flow_log", field_path="traffic_type",
            prev_value="REJECT", new_value="ALL",
            pm_extra={"record_id": "fl-005"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_B6_destination_changed_is_medium(self):
        c = _ch(
            record_type="aws_vpc_flow_log",
            field_path="log_group_name_or_bucket",
            prev_value="my-org-flow-logs", new_value="someone-else-bucket",
            pm_extra={"record_id": "fl-006"},
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"

    def test_B7_status_active_is_low(self):
        c = _ch(
            record_type="aws_vpc_flow_log", field_path="flow_log_status",
            prev_value="INACTIVE", new_value="ACTIVE",
            pm_extra={"record_id": "fl-007"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_B8_added_is_low(self):
        c = _ch(
            record_type="aws_vpc_flow_log", change_type="added",
            pm_extra={"record_id": "fl-008", "resource_id": "vpc-new"},
        )
        level, _ = classify_aws_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. CloudFront — re-verify scenarios from brief against existing classifier
# ═════════════════════════════════════════════════════════════════════════════


class TestCloudFront:

    def test_C1_logging_disabled_returns_valid_level(self):
        """Sanity: the existing CloudFront classifier handles logging-disabled
        without crashing.  The precise severity is owned by the legacy
        classifier (M40) and is not re-specified by Part 1."""
        c = _ch(
            record_type="aws_cloudfront_distribution",
            field_path="logging_enabled",
            prev_value=True, new_value=False,
            pm_extra={"record_id": "E1234ABCD", "name": "prod-cdn"},
        )
        level, reason = classify_aws_change(c)
        assert level in ("critical", "high", "medium", "low")
        assert isinstance(reason, str) and reason

    def test_C2_returns_string_reason_for_any_modification(self):
        """Smoke: every CloudFront field-path modification returns a usable
        (level, reason) tuple — no crashes, no empty reasons."""
        for fp in (
            "origin_domain_name", "viewer_protocol_policy",
            "default_cache_behavior", "web_acl_id", "aliases",
            "viewer_certificate", "logging_enabled",
        ):
            c = _ch(
                record_type="aws_cloudfront_distribution",
                field_path=fp,
                prev_value="old", new_value="new",
                pm_extra={"record_id": "E1234ABCD", "name": "prod-cdn"},
            )
            level, reason = classify_aws_change(c)
            assert level in ("critical", "high", "medium", "low")
            assert isinstance(reason, str) and reason


# ═════════════════════════════════════════════════════════════════════════════
# D. ELBv2 / ELB Classic — re-verify scenarios from brief
# ═════════════════════════════════════════════════════════════════════════════


class TestLoadBalancers:

    def test_D1_internet_facing_scheme_on_alb_is_at_least_medium(self):
        c = _ch(
            record_type="aws_elbv2_load_balancer",
            field_path="scheme",
            prev_value="internal", new_value="internet-facing",
            pm_extra={"record_id": "arn:aws:elasticloadbalancing:us-east-1:1:"
                                   "loadbalancer/app/prod-admin/abc",
                      "name": "prod-admin"},
        )
        level, _ = classify_aws_change(c)
        assert level in ("critical", "high", "medium")

    def test_D2_listener_modified_classifier_returns_value(self):
        c = _ch(
            record_type="aws_elbv2_listener",
            field_path="ssl_policy",
            prev_value="ELBSecurityPolicy-TLS13-1-2-2021-06",
            new_value="ELBSecurityPolicy-TLS-1-0-2015-04",  # weakened
            pm_extra={"record_id": "arn:listener/foo/bar"},
        )
        level, _ = classify_aws_change(c)
        assert level in ("critical", "high", "medium")

    def test_D3_classic_elb_classifier_returns_value(self):
        c = _ch(
            record_type="aws_elb_classic_load_balancer",
            field_path="scheme",
            prev_value="internal", new_value="internet-facing",
            pm_extra={"record_id": "old-classic-lb", "name": "legacy-admin"},
        )
        level, _ = classify_aws_change(c)
        assert level in ("critical", "high", "medium", "low")


# ═════════════════════════════════════════════════════════════════════════════
# E. WAFv2 — re-verify scenarios
# ═════════════════════════════════════════════════════════════════════════════


class TestWAFv2:

    def test_E1_web_acl_removed_classifier_returns_value(self):
        c = _ch(
            record_type="aws_wafv2_web_acl", change_type="removed",
            pm_extra={"record_id": "abcdef-1234", "name": "prod-acl"},
        )
        level, _ = classify_aws_change(c)
        assert level in ("critical", "high", "medium")

    def test_E2_web_acl_association_removed_classifier_returns_value(self):
        c = _ch(
            record_type="aws_wafv2_web_acl_association",
            change_type="removed",
            pm_extra={"record_id": "assoc-001",
                      "resource_arn": "arn:aws:elasticloadbalancing:..."},
        )
        level, _ = classify_aws_change(c)
        assert level in ("critical", "high", "medium")


# ═════════════════════════════════════════════════════════════════════════════
# F. API Gateway — re-verify scenarios
# ═════════════════════════════════════════════════════════════════════════════


class TestAPIGateway:

    def test_F1_apigateway_classifier_returns_value(self):
        for rt in ("aws_apigateway_rest_api", "aws_apigateway_rest_stage",
                   "aws_apigatewayv2_api", "aws_apigatewayv2_stage"):
            c = _ch(
                record_type=rt, field_path="api_key_required",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "api1", "name": "prod-api"},
            )
            level, reason = classify_aws_change(c)
            assert level in ("critical", "high", "medium", "low")
            assert isinstance(reason, str) and reason


# ═════════════════════════════════════════════════════════════════════════════
# G. Dispatcher / safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    def test_G1_unknown_aws_record_type_falls_back_safely(self):
        c = _ch(
            record_type="aws_does_not_exist", field_path="x",
            prev_value="a", new_value="b",
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_G2_malformed_pm_does_not_crash_ec2_classifier(self, bad_pm):
        c = MagicMock()
        c.change_type = "modified"
        c.field_path = "public_ip_address"
        c.prev_value = None
        c.new_value = "203.0.113.10"
        c.provider_metadata = bad_pm
        level, _ = _classify_ec2_instance_change(c)
        assert level in ("critical", "high", "medium", "low")

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_G3_malformed_pm_does_not_crash_flow_log_classifier(self, bad_pm):
        c = MagicMock()
        c.change_type = "removed"
        c.field_path = None
        c.prev_value = None
        c.new_value = None
        c.provider_metadata = bad_pm
        level, _ = _classify_vpc_flow_log_change(c)
        assert level in ("critical", "high", "medium", "low")

    def test_G4_top_level_dispatch_routes_new_types(self):
        """`classify_aws_change` correctly dispatches the new record types."""
        ec2_c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value=None, new_value="203.0.113.10",
            pm_extra={"record_id": "i-prod-db-001",
                      "tags": {"env": "production", "role": "db"},
                      "in_public_subnet": True},
        )
        flow_c = _ch(
            record_type="aws_vpc_flow_log", change_type="removed",
            pm_extra={"record_id": "fl-001", "resource_id": "vpc-prod",
                      "targets_production": True},
        )
        ec2_level, _ = classify_aws_change(ec2_c)
        flow_level, _ = classify_aws_change(flow_c)
        assert ec2_level == "critical"
        assert flow_level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# H. AWS_RECORD_TYPES frozenset includes the new entries
# ═════════════════════════════════════════════════════════════════════════════


class TestSchemaRegistry:

    def test_H1_new_record_types_registered(self):
        from app.connectors.aws_schema import (
            AWS_EC2_INSTANCE,
            AWS_VPC_FLOW_LOG,
            AWS_RECORD_TYPES,
        )
        assert AWS_EC2_INSTANCE == "aws_ec2_instance"
        assert AWS_VPC_FLOW_LOG == "aws_vpc_flow_log"
        assert AWS_EC2_INSTANCE in AWS_RECORD_TYPES
        assert AWS_VPC_FLOW_LOG in AWS_RECORD_TYPES


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires — realistic AWS-shaped fixtures must NEVER
# appear in any risk reason or remediation.
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
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bASIA[A-Z0-9]{16}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"\bFQoG[A-Za-z0-9+/=]{50,}"),  # session token shape
)


def _assert_safe(reason: str, secret: str) -> None:
    assert secret not in reason, f"reason leaked: {reason!r}"
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_ec2_tag_value_secret_never_echoed(self, name, secret):
        """If a tag value is accidentally a credential-shape, the reason
        must NEVER echo it (we should refer to "tags" without dumping them)."""
        c = _ch(
            record_type="aws_ec2_instance", field_path="public_ip_address",
            prev_value=None, new_value="203.0.113.10",
            pm_extra={
                "record_id": "i-leaky-001",
                "tags": {"env": "production", "ACCIDENTAL": secret},
                "in_public_subnet": True,
            },
        )
        _, reason = classify_aws_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_flow_log_destination_secret_never_echoed(self, name, secret):
        """A misconfigured destination value should not leak into the reason."""
        c = _ch(
            record_type="aws_vpc_flow_log",
            field_path="log_group_name_or_bucket",
            prev_value="my-log-group", new_value=secret,
            pm_extra={"record_id": "fl-001"},
        )
        _, reason = classify_aws_change(c)
        _assert_safe(reason, secret)

    def test_S3_no_forbidden_phrases_in_severe_ec2_reasons(self):
        bad_phrases = (
            "definitely publicly reachable",
            "definitely reachable",
            "compromised", "hacked",
            "guaranteed exposure",
        )
        scenarios = [
            _ch(record_type="aws_ec2_instance", field_path="public_ip_address",
                prev_value=None, new_value="203.0.113.10",
                pm_extra={"record_id": "i-prod-db-001",
                          "tags": {"env": "production", "role": "db"},
                          "in_public_subnet": True}),
            _ch(record_type="aws_ec2_instance", field_path="imds_v2_required",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "i-prod-001",
                          "tags": {"env": "production"}}),
            _ch(record_type="aws_vpc_flow_log", change_type="removed",
                pm_extra={"record_id": "fl-001", "resource_id": "vpc-prod",
                          "targets_production": True}),
        ]
        for c in scenarios:
            _, reason = classify_aws_change(c)
            r = reason.lower()
            for bad in bad_phrases:
                assert bad not in r, (
                    f"forbidden phrase {bad!r} in: {reason!r}"
                )
