"""Tests for Milestone 40: AWS Route53 DNS + CloudFront CDN Routing Config.

Covers:
- Module-level helpers (_hash_dns_values, _detect_routing_policy, etc.)
- Diff service tracked field registration
- Route53 risk classification (hosted zones + records)
- CloudFront risk classification (distributions)
- Failure classification (Route53 + CloudFront)
- Connector normalization (mocked boto3 responses)
- Service inventory (route53/cloudfront in enabled_surfaces)
- M36-M39 regression guards
"""

import hashlib
import pytest
from unittest.mock import MagicMock, patch, call

from app.connectors.aws import (
    AWSConnector,
    _hash_dns_values,
    _values_summary,
    _detect_routing_policy,
    _classify_cf_origin_type,
    _extract_dmarc_policy,
)
from app.connectors.aws_schema import (
    AWS_ROUTE53_HOSTED_ZONE,
    AWS_ROUTE53_RECORD,
    AWS_CLOUDFRONT_DISTRIBUTION,
    AWS_SERVICE_INVENTORY,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_route53_failure,
    classify_aws_cloudfront_failure,
)
from app.connectors.exceptions import ConnectorError, AuthenticationError, RateLimitError, NetworkError


# ---------------------------------------------------------------------------
# Helper used by TestM40RouteClassifier
# ---------------------------------------------------------------------------

def _change(record_type, change_type="modified", field_path=None, new_value=None, previous_value=None, **pm_extra):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "previous_value": previous_value,
        "provider_metadata": {
            "record_type": record_type,
            "name": pm_extra.get("name", "example.com"),
            "zone_name": pm_extra.get("zone_name", "example.com"),
            "record_name": pm_extra.get("record_name", ""),
            "dns_record_type": pm_extra.get("dns_record_type", ""),
            **{k: v for k, v in pm_extra.items() if k not in ("name", "zone_name", "record_name", "dns_record_type")},
        },
    }


# ===========================================================================
# Class 1: Helper functions
# ===========================================================================

class TestM40Helpers:
    def test_hash_dns_values_stable(self):
        """Same values in different order produce same hash."""
        h1 = _hash_dns_values(["192.0.2.1", "192.0.2.2"])
        h2 = _hash_dns_values(["192.0.2.2", "192.0.2.1"])
        assert h1 == h2

    def test_hash_dns_values_different(self):
        """Different values produce different hashes."""
        h1 = _hash_dns_values(["192.0.2.1"])
        h2 = _hash_dns_values(["192.0.2.2"])
        assert h1 != h2

    def test_hash_dns_values_length(self):
        """Hash is exactly 16 hex characters."""
        h = _hash_dns_values(["example.com"])
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_values_summary_truncation(self):
        """values_summary caps at max_items and appends count."""
        result = _values_summary(["a", "b", "c", "d", "e"], max_items=3)
        assert len(result) == 4
        assert "+2 more" in result[-1]

    def test_values_summary_no_truncation(self):
        """values_summary returns all items when under limit."""
        result = _values_summary(["a", "b"], max_items=3)
        assert result == ["a", "b"]

    def test_detect_routing_policy_simple(self):
        assert _detect_routing_policy({}) == "simple"

    def test_detect_routing_policy_weighted(self):
        assert _detect_routing_policy({"Weight": 100}) == "weighted"

    def test_detect_routing_policy_latency(self):
        assert _detect_routing_policy({"Region": "us-east-1"}) == "latency"

    def test_detect_routing_policy_failover(self):
        assert _detect_routing_policy({"Failover": "PRIMARY"}) == "failover"

    def test_detect_routing_policy_geolocation(self):
        assert _detect_routing_policy({"GeoLocation": {"CountryCode": "US"}}) == "geolocation"

    def test_detect_routing_policy_multivalue(self):
        assert _detect_routing_policy({"MultiValueAnswer": True}) == "multivalue"

    def test_classify_cf_origin_s3(self):
        assert _classify_cf_origin_type("mybucket.s3.amazonaws.com") == "s3"

    def test_classify_cf_origin_s3_regional(self):
        assert _classify_cf_origin_type("mybucket.s3.us-east-1.amazonaws.com") == "s3"

    def test_classify_cf_origin_elb(self):
        assert _classify_cf_origin_type("my-lb-123.us-east-1.elb.amazonaws.com") == "load_balancer"

    def test_classify_cf_origin_api_gateway(self):
        assert _classify_cf_origin_type("abc123.execute-api.us-east-1.amazonaws.com") == "api_gateway"

    def test_classify_cf_origin_custom(self):
        assert _classify_cf_origin_type("api.example.com") == "custom"

    def test_extract_dmarc_policy_none(self):
        assert _extract_dmarc_policy(['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"']) == "none"

    def test_extract_dmarc_policy_quarantine(self):
        assert _extract_dmarc_policy(['"v=DMARC1; p=quarantine"']) == "quarantine"

    def test_extract_dmarc_policy_reject(self):
        assert _extract_dmarc_policy(['"v=DMARC1; p=reject"']) == "reject"

    def test_extract_dmarc_policy_missing(self):
        """Returns None if no DMARC TXT record present."""
        assert _extract_dmarc_policy(['"v=spf1 include:example.com ~all"']) is None

    def test_extract_dmarc_policy_case_insensitive(self):
        """v=DMARC1 matching is case-insensitive."""
        assert _extract_dmarc_policy(["v=dmarc1; p=reject"]) == "reject"


# ===========================================================================
# Class 2: Diff service tracked fields
# ===========================================================================

class TestM40DiffTracking:
    def _record(self, record_type: str) -> dict:
        return {"record_type": record_type, "record_id": "test"}

    def test_hosted_zone_tracked_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ROUTE53_HOSTED_ZONE))
        assert "zone_type" in fields
        assert "private_zone" in fields
        assert "resource_record_set_count" in fields
        assert "name_servers" in fields
        assert "tag_keys" in fields
        assert "config_fetch_warnings" in fields

    def test_route53_record_tracked_fields(self):
        fields = _tracked_fields_for(self._record(AWS_ROUTE53_RECORD))
        assert "ttl" in fields
        assert "value_hash" in fields
        assert "alias_target_dns_name" in fields
        assert "dmarc_policy" in fields
        assert "routing_policy" in fields
        assert "evaluate_target_health" in fields

    def test_cloudfront_tracked_fields(self):
        fields = _tracked_fields_for(self._record(AWS_CLOUDFRONT_DISTRIBUTION))
        assert "enabled" in fields
        assert "web_acl_id" in fields
        assert "viewer_certificate_summary" in fields
        assert "origins_summary" in fields
        assert "default_cache_behavior_summary" in fields
        assert "logging_enabled" in fields
        assert "tag_keys" in fields


# ===========================================================================
# Class 3: Route53 risk classification
# ===========================================================================

class TestM40RouteClassifier:
    # --- Hosted zone tests ---

    def test_hosted_zone_deleted_is_critical(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, change_type="removed")
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "deleted" in reason.lower() or "removed" in reason.lower()

    def test_hosted_zone_ns_changed_is_critical(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, field_path="name_servers", new_value=["ns1.new.com"], previous_value=["ns1.old.com"])
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "name server" in reason.lower()

    def test_hosted_zone_public_to_private_is_high(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, field_path="zone_type", new_value="private", previous_value="public")
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_hosted_zone_private_to_public_is_high(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, field_path="zone_type", new_value="public", previous_value="private")
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_hosted_zone_record_count_decreased_is_high(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, field_path="resource_record_set_count", new_value=5, previous_value=10)
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_hosted_zone_linked_vpc_decreased_is_medium(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, field_path="linked_vpc_count", new_value=0, previous_value=2)
        level, reason = classify_aws_change(c)
        assert level == "medium"

    def test_hosted_zone_comment_changed_is_low(self):
        c = _change(AWS_ROUTE53_HOSTED_ZONE, field_path="comment", new_value="new comment", previous_value="old comment")
        level, reason = classify_aws_change(c)
        assert level == "low"

    # --- DNS record tests ---

    def test_mx_record_removed_is_critical(self):
        c = _change(AWS_ROUTE53_RECORD, change_type="removed", dns_record_type="MX", record_name="example.com")
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "mx" in reason.lower() or "email" in reason.lower()

    def test_apex_a_record_removed_is_critical(self):
        c = _change(
            AWS_ROUTE53_RECORD, change_type="removed",
            dns_record_type="A", record_name="example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_ns_record_value_changed_is_critical(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="value_hash",
            new_value="abc123", previous_value="def456",
            dns_record_type="NS", record_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "ns" in reason.lower() or "nameserver" in reason.lower()

    def test_dmarc_none_is_critical(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="dmarc_policy",
            new_value="none", previous_value="reject",
            record_name="_dmarc.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "dmarc" in reason.lower() or "phishing" in reason.lower() or "spoofing" in reason.lower()

    def test_dmarc_weakened_reject_to_quarantine_is_high(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="dmarc_policy",
            new_value="quarantine", previous_value="reject",
            record_name="_dmarc.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_dmarc_strengthened_none_to_reject_is_low(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="dmarc_policy",
            new_value="reject", previous_value="none",
            record_name="_dmarc.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "low"

    def test_apex_a_value_changed_is_critical(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="value_hash",
            new_value="abc123", previous_value="def456",
            dns_record_type="A", record_name="example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_sensitive_record_value_changed_is_high(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="value_hash",
            new_value="abc123", previous_value="def456",
            dns_record_type="CNAME", record_name="checkout.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_ordinary_record_value_changed_is_medium(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="value_hash",
            new_value="abc123", previous_value="def456",
            dns_record_type="A", record_name="blog.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"

    def test_alias_target_changed_sensitive_is_critical(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="alias_target_dns_name",
            new_value="new-alb.elb.amazonaws.com", previous_value="old-alb.elb.amazonaws.com",
            dns_record_type="A", record_name="api.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_ttl_very_short_is_medium(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="ttl",
            new_value=30, previous_value=300,
            dns_record_type="A", record_name="www.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"

    def test_ttl_normal_change_is_low(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="ttl",
            new_value=600, previous_value=300,
            dns_record_type="A", record_name="www.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "low"

    def test_routing_policy_changed_is_medium(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="routing_policy",
            new_value="weighted", previous_value="simple",
            dns_record_type="A", record_name="www.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"

    def test_health_check_removed_is_medium(self):
        c = _change(
            AWS_ROUTE53_RECORD, field_path="health_check_id",
            new_value=None, previous_value="hc-abc123",
            dns_record_type="A", record_name="www.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"


# ===========================================================================
# Class 4: CloudFront risk classification
# ===========================================================================

class TestM40CloudFrontClassifier:
    def _cf_change(self, field_path=None, new_value=None, previous_value=None, change_type="modified", **pm_extra):
        return {
            "record_type": AWS_CLOUDFRONT_DISTRIBUTION,
            "change_type": change_type,
            "field_path": field_path,
            "new_value": new_value,
            "previous_value": previous_value,
            "provider_metadata": {
                "record_type": AWS_CLOUDFRONT_DISTRIBUTION,
                "name": pm_extra.get("name", "d1234567890123.cloudfront.net"),
                "aliases": pm_extra.get("aliases", []),
                **{k: v for k, v in pm_extra.items() if k not in ("name", "aliases")},
            },
        }

    def test_distribution_removed_is_critical(self):
        c = self._cf_change(change_type="removed")
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_distribution_disabled_sensitive_is_critical(self):
        c = self._cf_change(
            field_path="enabled", new_value=False, previous_value=True,
            name="checkout.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_distribution_disabled_non_sensitive_is_high(self):
        c = self._cf_change(
            field_path="enabled", new_value=False, previous_value=True,
            name="d1234567890123.cloudfront.net",
        )
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_allow_all_viewer_protocol_is_critical(self):
        c = self._cf_change(
            field_path="default_cache_behavior_summary",
            new_value={"viewer_protocol_policy": "allow-all"},
            previous_value={"viewer_protocol_policy": "redirect-to-https"},
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "allow-all" in reason.lower() or "http" in reason.lower()

    def test_waf_removed_is_high(self):
        c = self._cf_change(
            field_path="web_acl_id",
            new_value=None,
            previous_value="arn:aws:wafv2:us-east-1:123456789012:global/webacl/my-acl/abc123",
        )
        level, reason = classify_aws_change(c)
        assert level == "high"
        assert "waf" in reason.lower()

    def test_waf_changed_is_medium(self):
        c = self._cf_change(
            field_path="web_acl_id",
            new_value="arn:aws:wafv2:us-east-1:123456789012:global/webacl/new-acl/xyz789",
            previous_value="arn:aws:wafv2:us-east-1:123456789012:global/webacl/old-acl/abc123",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"

    def test_tls_weakened_is_high(self):
        c = self._cf_change(
            field_path="viewer_certificate_summary",
            new_value={"minimum_protocol_version": "TLSv1", "ssl_support_method": "sni-only"},
            previous_value={"minimum_protocol_version": "TLSv1.2_2021", "ssl_support_method": "sni-only"},
        )
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_origins_changed_sensitive_is_critical(self):
        c = self._cf_change(
            field_path="origins_summary",
            new_value=[{"domain": "new.example.com", "origin_type": "custom"}],
            previous_value=[{"domain": "old.example.com", "origin_type": "custom"}],
            name="api.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_origins_changed_non_sensitive_is_high(self):
        c = self._cf_change(
            field_path="origins_summary",
            new_value=[{"domain": "new.example.com", "origin_type": "custom"}],
            previous_value=[{"domain": "old.example.com", "origin_type": "custom"}],
            name="blog.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_aliases_changed_is_high(self):
        c = self._cf_change(
            field_path="aliases",
            new_value=["www.example.com"],
            previous_value=["www.example.com", "static.example.com"],
        )
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_logging_disabled_is_medium(self):
        c = self._cf_change(
            field_path="logging_enabled",
            new_value=False, previous_value=True,
        )
        level, reason = classify_aws_change(c)
        assert level == "medium"

    def test_price_class_changed_is_low(self):
        c = self._cf_change(
            field_path="price_class",
            new_value="PriceClass_100", previous_value="PriceClass_All",
        )
        level, reason = classify_aws_change(c)
        assert level == "low"

    def test_tag_keys_changed_is_low(self):
        c = self._cf_change(
            field_path="tag_keys",
            new_value=["env"], previous_value=["env", "owner"],
        )
        level, reason = classify_aws_change(c)
        assert level == "low"


# ===========================================================================
# Class 5: Failure classification
# ===========================================================================

class TestM40FailureClassification:
    def test_route53_403_is_access_denied(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_route53_failure("ListHostedZones", exc)
        assert fc.error_code == "aws_route53_access_denied"

    def test_route53_auth_error_is_access_denied(self):
        exc = AuthenticationError("invalid credentials")
        fc = classify_aws_route53_failure("ListHostedZones", exc)
        assert fc.error_code == "aws_route53_access_denied"

    def test_route53_rate_limit_is_rate_limited(self):
        exc = RateLimitError("throttled")
        fc = classify_aws_route53_failure("ListHostedZones", exc)
        assert fc.error_code == "aws_route53_rate_limited"

    def test_route53_network_error(self):
        exc = NetworkError("timeout")
        fc = classify_aws_route53_failure("ListHostedZones", exc)
        assert fc.error_code == "network_error"

    def test_route53_list_zones_maps_to_zones_unavailable(self):
        # Use a plain Exception (not a typed ConnectorError) to trigger the
        # per-API code lookup; 5xx ConnectorErrors go to the generic handler.
        exc = Exception("unexpected AWS error")
        fc = classify_aws_route53_failure("ListHostedZones", exc)
        assert fc.error_code == "aws_route53_hosted_zones_unavailable"

    def test_route53_list_records_maps_to_records_unavailable(self):
        exc = Exception("unexpected AWS error")
        fc = classify_aws_route53_failure("ListResourceRecordSets", exc)
        assert fc.error_code == "aws_route53_records_unavailable"

    def test_cloudfront_403_is_access_denied(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_cloudfront_failure("ListDistributions", exc)
        assert fc.error_code == "aws_cloudfront_access_denied"

    def test_cloudfront_auth_error_is_access_denied(self):
        exc = AuthenticationError("invalid credentials")
        fc = classify_aws_cloudfront_failure("ListDistributions", exc)
        assert fc.error_code == "aws_cloudfront_access_denied"

    def test_cloudfront_rate_limit_is_rate_limited(self):
        exc = RateLimitError("throttled")
        fc = classify_aws_cloudfront_failure("ListDistributions", exc)
        assert fc.error_code == "aws_cloudfront_rate_limited"

    def test_cloudfront_network_error(self):
        exc = NetworkError("timeout")
        fc = classify_aws_cloudfront_failure("ListDistributions", exc)
        assert fc.error_code == "network_error"

    def test_cloudfront_list_distributions_maps_to_unavailable(self):
        # Use a plain Exception to trigger the per-API code lookup;
        # 5xx ConnectorErrors go to the generic handler.
        exc = Exception("unexpected AWS error")
        fc = classify_aws_cloudfront_failure("ListDistributions", exc)
        assert fc.error_code == "aws_cloudfront_distributions_unavailable"

    def test_cloudfront_get_config_maps_to_config_unavailable(self):
        exc = Exception("unexpected AWS error")
        fc = classify_aws_cloudfront_failure("GetDistributionConfig", exc)
        assert fc.error_code == "aws_cloudfront_distribution_config_unavailable"


# ===========================================================================
# Class 6: Connector normalization
# ===========================================================================

class TestM40ConnectorNormalization:
    def _credentials(self):
        return {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_default_region": "us-east-1",
            "aws_selected_regions": ["us-east-1"],
        }

    def _make_connector(self):
        return AWSConnector()

    def test_fetch_hosted_zones_returns_records(self):
        """_fetch_hosted_zones returns properly normalized aws_route53_hosted_zone records."""
        connector = self._make_connector()
        mock_client = MagicMock()

        connector._call_aws = MagicMock(return_value={
            "HostedZones": [
                {
                    "Id": "/hostedzone/Z1234567890ABC",
                    "Name": "example.com.",
                    "Config": {"PrivateZone": False, "Comment": "main zone"},
                    "ResourceRecordSetCount": 5,
                }
            ],
            "IsTruncated": False,
        })

        records = connector._fetch_hosted_zones(mock_client, "123456789012")

        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == AWS_ROUTE53_HOSTED_ZONE
        assert r["zone_id"] == "Z1234567890ABC"
        assert r["name"] == "example.com"  # trailing dot stripped
        assert r["private_zone"] is False
        assert r["zone_type"] == "public"
        assert r["resource_record_set_count"] == 5
        assert r["comment"] == "main zone"
        assert r["record_id"] == "123456789012/Z1234567890ABC"
        assert "_zone_id" in r  # internal helper field present before stripping

    def test_fetch_hosted_zones_private(self):
        """Private zone sets zone_type='private'."""
        connector = self._make_connector()
        mock_client = MagicMock()
        connector._call_aws = MagicMock(return_value={
            "HostedZones": [
                {
                    "Id": "/hostedzone/ZPRIVATE",
                    "Name": "internal.example.com.",
                    "Config": {"PrivateZone": True},
                    "ResourceRecordSetCount": 2,
                }
            ],
            "IsTruncated": False,
        })
        records = connector._fetch_hosted_zones(mock_client, "123456789012")
        assert records[0]["private_zone"] is True
        assert records[0]["zone_type"] == "private"

    def test_fetch_zone_records_a_record(self):
        """_fetch_zone_records normalizes A records correctly."""
        connector = self._make_connector()
        mock_client = MagicMock()
        connector._call_aws = MagicMock(return_value={
            "ResourceRecordSets": [
                {
                    "Name": "www.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "192.0.2.1"}, {"Value": "192.0.2.2"}],
                }
            ],
            "IsTruncated": False,
        })

        records = connector._fetch_zone_records(
            mock_client, "Z1234567890ABC", "example.com", "123456789012"
        )

        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == AWS_ROUTE53_RECORD
        assert r["dns_record_type"] == "A"
        assert r["record_name"] == "www.example.com"  # trailing dot stripped
        assert r["ttl"] == 300
        # value_hash is set (not None) for A records with values
        assert r["value_hash"] is not None
        assert len(r["value_hash"]) == 16
        assert r["alias_target_dns_name"] is None
        assert r["dmarc_policy"] is None

    def test_fetch_zone_records_alias_record(self):
        """Alias records populate alias fields; value_hash is None."""
        connector = self._make_connector()
        mock_client = MagicMock()
        connector._call_aws = MagicMock(return_value={
            "ResourceRecordSets": [
                {
                    "Name": "example.com.",
                    "Type": "A",
                    "AliasTarget": {
                        "DNSName": "my-alb-123.us-east-1.elb.amazonaws.com.",
                        "HostedZoneId": "Z35SXDOTRQ7X7K",
                        "EvaluateTargetHealth": True,
                    },
                }
            ],
            "IsTruncated": False,
        })
        records = connector._fetch_zone_records(
            mock_client, "Z1234567890ABC", "example.com", "123456789012"
        )
        r = records[0]
        assert r["alias_target_dns_name"] == "my-alb-123.us-east-1.elb.amazonaws.com"  # trailing dot stripped
        assert r["alias_hosted_zone_id"] == "Z35SXDOTRQ7X7K"
        assert r["evaluate_target_health"] is True
        assert r["value_hash"] is None

    def test_fetch_zone_records_txt_uses_hash(self):
        """TXT records populate value_hash, never the raw values."""
        connector = self._make_connector()
        mock_client = MagicMock()
        connector._call_aws = MagicMock(return_value={
            "ResourceRecordSets": [
                {
                    "Name": "example.com.",
                    "Type": "TXT",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": '"v=spf1 include:example.com ~all"'}],
                }
            ],
            "IsTruncated": False,
        })
        records = connector._fetch_zone_records(
            mock_client, "Z1234567890ABC", "example.com", "123456789012"
        )
        r = records[0]
        assert r["value_hash"] is not None
        # Raw value is NOT stored in the record
        assert "v=spf1" not in str(r)

    def test_fetch_zone_records_dmarc_txt(self):
        """DMARC TXT records extract dmarc_policy."""
        connector = self._make_connector()
        mock_client = MagicMock()
        connector._call_aws = MagicMock(return_value={
            "ResourceRecordSets": [
                {
                    "Name": "_dmarc.example.com.",
                    "Type": "TXT",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'}],
                }
            ],
            "IsTruncated": False,
        })
        records = connector._fetch_zone_records(
            mock_client, "Z1234567890ABC", "example.com", "123456789012"
        )
        r = records[0]
        assert r["dmarc_policy"] == "reject"

    def test_fetch_distributions_basic(self):
        """_fetch_distributions returns aws_cloudfront_distribution records."""
        connector = self._make_connector()
        mock_client = MagicMock()
        connector._call_aws = MagicMock(return_value={
            "DistributionList": {
                "Items": [
                    {
                        "Id": "E1ABCDEF12345",
                        "DomainName": "d1234567890123.cloudfront.net",
                        "Enabled": True,
                        "Status": "Deployed",
                        "Aliases": {"Items": ["www.example.com"], "Quantity": 1},
                        "Origins": {
                            "Items": [
                                {
                                    "Id": "myS3Origin",
                                    "DomainName": "mybucket.s3.amazonaws.com",
                                    "OriginPath": "",
                                }
                            ],
                            "Quantity": 1,
                        },
                        "DefaultCacheBehavior": {
                            "ViewerProtocolPolicy": "redirect-to-https",
                            "Compress": True,
                            "AllowedMethods": {"CachedMethods": {"Items": ["GET", "HEAD"]}},
                        },
                        "CacheBehaviors": {"Items": [], "Quantity": 0},
                        "ViewerCertificate": {
                            "CloudFrontDefaultCertificate": False,
                            "MinimumProtocolVersion": "TLSv1.2_2021",
                            "SSLSupportMethod": "sni-only",
                            "CertificateSource": "acm",
                        },
                        "WebACLId": "arn:aws:wafv2:us-east-1:123:global/webacl/my-acl/abc",
                        "PriceClass": "PriceClass_All",
                        "HttpVersion": "http2",
                        "IsIPV6Enabled": True,
                        "DefaultRootObject": "index.html",
                        "CustomErrorResponses": {"Items": [], "Quantity": 0},
                        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
                    }
                ],
                "IsTruncated": False,
            }
        })

        records = connector._fetch_distributions(mock_client, "123456789012")

        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == AWS_CLOUDFRONT_DISTRIBUTION
        assert r["distribution_id"] == "E1ABCDEF12345"
        assert r["enabled"] is True
        assert r["aliases"] == ["www.example.com"]
        assert r["web_acl_id"] == "arn:aws:wafv2:us-east-1:123:global/webacl/my-acl/abc"
        assert r["ipv6_enabled"] is True
        assert r["default_root_object"] == "index.html"
        assert r["origin_count"] == 1
        origins = r["origins_summary"]
        assert len(origins) == 1
        assert origins[0]["origin_type"] == "s3"
        assert r["record_id"] == "123456789012/E1ABCDEF12345"
        dcb = r["default_cache_behavior_summary"]
        assert dcb["viewer_protocol_policy"] == "redirect-to-https"
        vc = r["viewer_certificate_summary"]
        assert vc["minimum_protocol_version"] == "TLSv1.2_2021"

    def test_fetch_route53_resources_403_returns_empty(self):
        """Route53 403 -> fail-soft empty list."""
        connector = self._make_connector()

        with patch.object(connector, "_make_client") as mock_make_client:
            mock_client = MagicMock()
            mock_make_client.return_value = mock_client

            connector._call_aws = MagicMock(
                side_effect=ConnectorError("AccessDenied", status_code=403)
            )

            records = connector._fetch_route53_resources(self._credentials(), "123456789012")
            assert records == []

    def test_fetch_cloudfront_resources_403_returns_empty(self):
        """CloudFront 403 -> fail-soft empty list."""
        connector = self._make_connector()

        with patch.object(connector, "_make_client") as mock_make_client:
            mock_client = MagicMock()
            mock_make_client.return_value = mock_client

            connector._call_aws = MagicMock(
                side_effect=ConnectorError("AccessDenied", status_code=403)
            )

            records = connector._fetch_cloudfront_resources(self._credentials(), "123456789012")
            assert records == []


# ===========================================================================
# Class 7: Service inventory
# ===========================================================================

class TestM40ServiceInventory:
    def test_route53_cloudfront_in_enabled_surfaces(self):
        """Service inventory includes route53 and cloudfront in enabled_surfaces."""
        connector = AWSConnector()
        credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_default_region": "us-east-1",
            "aws_selected_regions": ["us-east-1"],
        }
        record = connector._fetch_service_inventory(
            credentials,
            route53_zone_count=3,
            cloudfront_distribution_count=2,
        )
        assert record["record_type"] == AWS_SERVICE_INVENTORY
        assert "route53" in record["enabled_surfaces"]
        assert "cloudfront" in record["enabled_surfaces"]
        assert record["route53_zone_count"] == 3
        assert record["cloudfront_distribution_count"] == 2
        # route53/cloudfront should NOT appear in future_surfaces
        assert "route53" not in record["future_surfaces"]
        assert "cloudfront" not in record["future_surfaces"]


# ===========================================================================
# Class 8: Regression guards (M36-M39)
# ===========================================================================

class TestM40RegressionGuards:
    def test_m36_account_identity_still_works(self):
        from app.connectors.aws_schema import AWS_ACCOUNT_IDENTITY
        c = {
            "record_type": AWS_ACCOUNT_IDENTITY,
            "change_type": "modified",
            "field_path": "principal_arn",
            "new_value": "arn:aws:iam::123:user/new",
            "previous_value": "arn:aws:iam::123:user/old",
            "provider_metadata": {"record_type": AWS_ACCOUNT_IDENTITY},
        }
        level, reason = classify_aws_change(c)
        assert level in ("high", "critical")

    def test_m37_s3_public_still_critical(self):
        from app.connectors.aws_schema import AWS_S3_BUCKET
        c = {
            "record_type": AWS_S3_BUCKET,
            "change_type": "modified",
            "field_path": "policy_status_is_public",
            "new_value": True,
            "previous_value": False,
            "provider_metadata": {
                "record_type": AWS_S3_BUCKET,
                "name": "prod-customer-data",
            },
        }
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_m38_public_ssh_still_critical(self):
        from app.connectors.aws_schema import AWS_SECURITY_GROUP_RULE
        # M38 classifier reads direction from new_value dict;
        # it expects "ingress" (not "inbound") matching the connector output.
        c = {
            "record_type": AWS_SECURITY_GROUP_RULE,
            "change_type": "added",
            "field_path": None,
            "new_value": {
                "direction": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr": "0.0.0.0/0",
                "port_category": "admin",
                "is_public": True,
            },
            "prev_value": None,
            "provider_metadata": {
                "record_type": AWS_SECURITY_GROUP_RULE,
                "direction": "ingress",
                "is_public": True,
                "port_category": "admin",
            },
        }
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_m39_root_mfa_disabled_still_critical(self):
        from app.connectors.aws_schema import AWS_IAM_ACCOUNT_SUMMARY
        # M39 classifier uses _get(change, "prev_value") — not "previous_value".
        c = {
            "record_type": AWS_IAM_ACCOUNT_SUMMARY,
            "change_type": "modified",
            "field_path": "mfa_enabled_for_root",
            "new_value": False,
            "prev_value": True,
            "provider_metadata": {"record_type": AWS_IAM_ACCOUNT_SUMMARY},
        }
        level, _ = classify_aws_change(c)
        assert level == "critical"


# ===========================================================================
# Class 9: Wildcard DNS + CAA record handling
# ===========================================================================

class TestM40WildcardAndCAA:
    """Wildcard detection (literal *.x and escaped \\052.x) and CAA handling."""

    # ── Wildcard added ────────────────────────────────────────────────────────

    def test_wildcard_literal_added_non_sensitive_is_high(self):
        """Literal *.example.com added to a non-sensitive zone → High."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="*.example.com",
            dns_record_type="A",
            dns_record_name="*.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high", reason
        assert "wildcard" in reason.lower()

    def test_wildcard_escaped_added_non_sensitive_is_high(self):
        """AWS-escaped \\052.example.com added to a non-sensitive zone → High."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="\\052.example.com",
            dns_record_type="CNAME",
            dns_record_name="\\052.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high", reason
        assert "wildcard" in reason.lower()

    def test_wildcard_literal_sensitive_zone_added_is_critical(self):
        """Wildcard added to sensitive zone (api.*) → Critical."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="*.api.example.com",
            dns_record_type="CNAME",
            dns_record_name="*.api.example.com",
            zone_name="api.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical", reason
        assert "wildcard" in reason.lower()

    def test_wildcard_escaped_prod_zone_added_is_critical(self):
        """AWS-escaped \\052 in prod zone → Critical."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="\\052.prod.example.com",
            dns_record_type="CNAME",
            dns_record_name="\\052.prod.example.com",
            zone_name="prod.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical", reason
        assert "wildcard" in reason.lower()

    # ── Wildcard value_hash changed ───────────────────────────────────────────

    def test_wildcard_value_changed_non_sensitive_is_high(self):
        """Wildcard value_hash changed in non-sensitive zone → High."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="newHash123",
            previous_value="oldHash456",
            record_name="*.example.com",
            dns_record_type="CNAME",
            dns_record_name="*.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high", reason
        assert "wildcard" in reason.lower()

    def test_wildcard_value_changed_sensitive_is_critical(self):
        """Wildcard value_hash changed in sensitive zone → Critical."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="newHash123",
            previous_value="oldHash456",
            record_name="*.auth.example.com",
            dns_record_type="CNAME",
            dns_record_name="*.auth.example.com",
            zone_name="auth.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical", reason
        assert "wildcard" in reason.lower()

    # ── Wildcard removed ──────────────────────────────────────────────────────

    def test_wildcard_removed_non_sensitive_is_medium(self):
        """Wildcard removed from non-sensitive zone → Medium."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="*.example.com",
            dns_record_type="CNAME",
            dns_record_name="*.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium", reason
        assert "wildcard" in reason.lower()

    def test_wildcard_removed_sensitive_is_high(self):
        """Wildcard removed from sensitive zone → High."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="*.api.example.com",
            dns_record_type="CNAME",
            dns_record_name="*.api.example.com",
            zone_name="api.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high", reason
        assert "wildcard" in reason.lower()

    def test_wildcard_escaped_removed_non_sensitive_is_medium(self):
        """Escaped \\052 wildcard removed → Medium for non-sensitive zone."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="\\052.example.com",
            dns_record_type="CNAME",
            dns_record_name="\\052.example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium", reason
        assert "wildcard" in reason.lower()

    # ── CAA record handling ───────────────────────────────────────────────────

    def test_caa_removed_normal_zone_is_medium(self):
        """CAA record removed from a normal zone → Medium."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="example.com",
            dns_record_type="CAA",
            dns_record_name="example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium", reason
        assert "caa" in reason.lower() or "certificate" in reason.lower()

    def test_caa_removed_prod_zone_is_high(self):
        """CAA record removed from a prod/sensitive zone → High."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="prod.example.com",
            dns_record_type="CAA",
            dns_record_name="prod.example.com",
            zone_name="prod.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high", reason
        assert "caa" in reason.lower() or "certificate" in reason.lower()

    def test_caa_added_is_low(self):
        """CAA record added → Low (restricts certificate issuance)."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="example.com",
            dns_record_type="CAA",
            dns_record_name="example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "low", reason
        assert "caa" in reason.lower() or "certificate" in reason.lower()

    def test_caa_value_modified_normal_zone_is_medium(self):
        """CAA value_hash changed in a normal zone → Medium."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="newHash",
            previous_value="oldHash",
            record_name="example.com",
            dns_record_type="CAA",
            dns_record_name="example.com",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "medium", reason
        assert "caa" in reason.lower() or "certificate" in reason.lower()

    def test_caa_value_modified_prod_zone_is_high(self):
        """CAA value_hash changed in a prod zone → High."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="newHash",
            previous_value="oldHash",
            record_name="prod.example.com",
            dns_record_type="CAA",
            dns_record_name="prod.example.com",
            zone_name="prod.example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "high", reason
        assert "caa" in reason.lower() or "certificate" in reason.lower()

    # ── Ordinary records unaffected ───────────────────────────────────────────

    def test_normal_cname_added_is_low(self):
        """Non-wildcard, non-sensitive CNAME added → Low."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="blog.example.com",
            dns_record_type="CNAME",
            dns_record_name="blog.example.com",
            zone_name="example.com",
        )
        level, _ = classify_aws_change(c)
        assert level == "low"

    def test_sensitive_non_wildcard_cname_added_is_medium(self):
        """Sensitive non-wildcard record (api.*) added → Medium."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="api.example.com",
            dns_record_type="CNAME",
            dns_record_name="api.example.com",
            zone_name="example.com",
        )
        level, _ = classify_aws_change(c)
        assert level == "medium"


# ===========================================================================
# Class 10: Message format validation
# ===========================================================================

class TestM40MessageFormat:
    """Risk messages must not contain empty type labels '()' or empty zone
    labels \"zone ''\", and must not use overclaiming language."""

    def test_no_empty_type_label_when_dns_type_missing_removed(self):
        """Removed record with no dns_record_type should not produce '()' in message."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="www.example.com",
            dns_record_type="",          # deliberately empty
            zone_name="example.com",
        )
        _, reason = classify_aws_change(c)
        assert "()" not in reason, f"Empty type label in: {reason!r}"

    def test_no_empty_zone_label_when_zone_missing_removed(self):
        """Removed record with no zone_name should not produce \"zone ''\" in message."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="www.example.com",
            dns_record_type="A",
            zone_name="",               # deliberately empty
        )
        _, reason = classify_aws_change(c)
        assert "zone ''" not in reason, f"Empty zone label in: {reason!r}"
        # Should fall back to a human-readable phrase
        assert "the hosted zone" in reason, f"Expected fallback label in: {reason!r}"

    def test_no_empty_type_label_when_dns_type_missing_modified(self):
        """value_hash change with no dns_record_type should not produce '()' in message."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="abc", previous_value="def",
            record_name="www.example.com",
            dns_record_type="",
            zone_name="example.com",
        )
        _, reason = classify_aws_change(c)
        assert "()" not in reason, f"Empty type label in: {reason!r}"

    def test_no_empty_zone_label_when_zone_missing_modified(self):
        """value_hash change with no zone_name should use fallback, not \"zone ''\"."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="abc", previous_value="def",
            record_name="www.example.com",
            dns_record_type="A",
            zone_name="",
        )
        _, reason = classify_aws_change(c)
        assert "zone ''" not in reason, f"Empty zone label in: {reason!r}"
        assert "the hosted zone" in reason, f"Expected fallback label in: {reason!r}"

    def test_caa_removed_empty_zone_no_empty_labels(self):
        """CAA removed with empty zone_name uses 'the hosted zone', no '()' or \"zone ''\"."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="CAA example.com",
            dns_record_type="CAA",
            zone_name="",
        )
        _, reason = classify_aws_change(c)
        assert "()" not in reason, f"Empty type label in: {reason!r}"
        assert "zone ''" not in reason, f"Empty zone label in: {reason!r}"

    def test_wildcard_added_message_does_not_overclaim(self):
        """Wildcard added message uses hedged language, not absolute claims of harm."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="added",
            record_name="*.example.com",
            dns_record_type="CNAME",
            dns_record_name="*.example.com",
            zone_name="example.com",
        )
        _, reason = classify_aws_change(c)
        lower = reason.lower()
        for bad_phrase in ("will compromise", "will hijack", "data leak", "certificate compromise"):
            assert bad_phrase not in lower, f"Overclaiming phrase {bad_phrase!r} in: {reason!r}"
        # Must use hedged language
        assert "may" in lower or "could" in lower or "confirm" in lower, (
            f"Expected hedged language ('may'/'could'/'confirm') in: {reason!r}"
        )

    def test_caa_removed_message_does_not_overclaim(self):
        """CAA removed message mentions certificate authorities, not catastrophic outcomes."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="example.com",
            dns_record_type="CAA",
            zone_name="example.com",
        )
        _, reason = classify_aws_change(c)
        lower = reason.lower()
        for bad_phrase in ("will compromise", "data leak", "account takeover"):
            assert bad_phrase not in lower, f"Overclaiming phrase {bad_phrase!r} in: {reason!r}"
        assert "certificate" in lower or "caa" in lower

    def test_existing_mx_removed_message_unchanged(self):
        """MX removal message still mentions email delivery (regression guard)."""
        c = _change(
            AWS_ROUTE53_RECORD,
            change_type="removed",
            record_name="example.com",
            dns_record_type="MX",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "email" in reason.lower() or "mx" in reason.lower()

    def test_existing_ns_changed_message_unchanged(self):
        """NS value_hash change is still Critical (regression guard)."""
        c = _change(
            AWS_ROUTE53_RECORD,
            field_path="value_hash",
            new_value="abc", previous_value="def",
            record_name="example.com",
            dns_record_type="NS",
            zone_name="example.com",
        )
        level, reason = classify_aws_change(c)
        assert level == "critical"
        assert "ns" in reason.lower() or "nameserver" in reason.lower()
