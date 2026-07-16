"""AWS detection-QA regression coverage (message-1 detection pass).

This file covers bugs found while auditing the AWS connector -> diff ->
classify_aws_change pipeline for structural correctness (routing, tracked
fields, Change shape, unknown-coercion). Full transition-severity and
restoration calibration is reserved for the dedicated AWS change-
classification pass (message 2).

Bugs fixed and covered here:

  1. ``_classify_route53_hosted_zone_change``, ``_classify_route53_record_
     change``, and ``_classify_cloudfront_distribution_change`` all read the
     previous value via ``_get(change, "previous_value")`` — a field real
     ``compute_diff()`` Changes never carry (the actual field is
     ``prev_value``). This silently broke every prev->new transition check
     in these three classifiers (e.g. public/private zone flips, CloudFront
     ``enabled`` True->False detection) since ``pv`` was always ``None``.
  2. ``_classify_config_recorder_change`` (``resource_types_count``) and
     ``_classify_acm_certificate_change`` (``days_to_expiry``,
     ``subject_alternative_names_count``) used ``int(v or 0)`` with a
     ``TypeError``/``ValueError`` fallback to ``0`` — conflating a missing/
     unparseable value with a genuine zero. For ACM ``days_to_expiry`` this
     meant a missing value would falsely report "certificate has expired"
     at critical/high severity. Fixed to preserve unknown explicitly.
  3. Several "added" branches (RDS DB instance/cluster, SQS queue, SNS
     topic, ECR repository, KMS key, EventBridge event bus) returned a flat
     "was added to monitoring" / generic low severity regardless of the new
     record's actual posture (public accessibility, encryption, public
     resource policy). Fixed to inspect the full new record (``new_value``
     on an "added" Change) and escalate when the newly discovered resource
     is already risky.

These tests exercise the REAL compute_diff() -> classify_aws_change()
pipeline (not hand-built Change objects with fabricated field names).
"""

from __future__ import annotations

from app.services.diff_service import compute_diff
from app.services.risk_rules.aws import classify_aws_change


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


# ── prev_value / previous_value field-name bug ───────────────────────────────

class TestRoute53HostedZonePrevValueHandling:
    _BASE = {
        "record_type": "aws_route53_hosted_zone", "record_id": "Z123/hosted_zone",
        "name": "example.com", "zone_id": "Z123", "zone_type": "public",
        "private_zone": False, "resource_record_set_count": 10,
        "linked_vpc_count": 0, "comment": "", "name_servers": ["ns-1.example."],
        "tag_keys": [],
    }

    def test_zone_type_public_to_private_is_detected_correctly(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "zone_type": "private"}]
        level, reason = _classify_field(prev, new, "zone_type")
        assert level == "high"
        assert "private" in reason.lower()

    def test_private_zone_false_to_true_is_detected_correctly(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "private_zone": True}]
        level, reason = _classify_field(prev, new, "private_zone")
        assert level == "high"
        assert "now private" in reason.lower()

    def test_record_count_decrease_shows_real_previous_value(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "resource_record_set_count": 3}]
        level, reason = _classify_field(prev, new, "resource_record_set_count")
        assert level == "high"
        assert "(10 → 3)" in reason


class TestRoute53RecordPrevValueHandling:
    _BASE = {
        "record_type": "aws_route53_record", "record_id": "Z123/www.example.com/A",
        "name": "A www.example.com", "zone_id": "Z123", "zone_name": "example.com",
        "dns_record_type": "A", "dns_record_name": "www.example.com",
        "ttl": 300, "value_hash": "h1", "alias_target_dns_name": None,
        "alias_hosted_zone_id": None, "evaluate_target_health": None,
        "routing_policy": "simple", "weight": None, "region": None,
        "failover": None, "geo_location_summary": None, "health_check_id": None,
        "dmarc_policy": None,
    }

    def test_ttl_change_uses_real_previous_value(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "ttl": 60}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "ttl"]
        assert len(matching) == 1
        # prev_value must be the real previous value, not None from the
        # stale "previous_value" key bug.
        assert matching[0]["prev_value"] == 300


class TestCloudFrontDistributionPrevValueHandling:
    _BASE = {
        "record_type": "aws_cloudfront_distribution", "record_id": "E123",
        "name": "d123.cloudfront.net", "distribution_id": "E123",
        "domain_name": "d123.cloudfront.net", "enabled": True, "status": "Deployed",
        "aliases": [], "alias_count": 0, "default_root_object": "",
        "price_class": "PriceClass_All", "http_version": "http2",
        "ipv6_enabled": True, "web_acl_id": None,
        "viewer_certificate_summary": "default", "origin_count": 1,
        "origins_summary": "s3", "default_cache_behavior_summary": "default",
        "ordered_cache_behavior_count": 0, "ordered_cache_behaviors_summary": "",
        "logging_enabled": False, "logging_bucket_domain": None,
        "custom_error_response_count": 0, "restrictions_summary": "none",
        "tag_keys": [],
    }

    def test_enabled_true_to_false_is_detected_correctly(self):
        """The core regression: `pv` was always None due to the stale
        "previous_value" key, so this True->False transition could never
        be detected — it always fell through to a generic branch."""
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "enabled": False}]
        level, reason = _classify_field(prev, new, "enabled")
        assert level in ("critical", "high")
        assert "removed" not in reason.lower()


# ── Unsafe int(v or 0) numeric-unknown coercion ──────────────────────────────

class TestConfigRecorderUnknownHandling:
    _BASE = {
        "record_type": "aws_config_recorder", "record_id": "default/us-east-1",
        "name": "default", "region": "us-east-1", "recording": True,
        "records_global_resources": True, "resource_types_count": 10,
    }

    def test_resource_types_count_becoming_unknown_is_not_reported_as_narrowed(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "resource_types_count": None}]
        level, reason = _classify_field(prev, new, "resource_types_count")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "narrowed" not in reason.lower()

    def test_resource_types_count_decrease_still_detected(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "resource_types_count": 3}]
        level, reason = _classify_field(prev, new, "resource_types_count")
        assert level == "high"
        assert "narrowed from 10 to 3" in reason


class TestAcmCertificateUnknownHandling:
    _BASE = {
        "record_type": "aws_acm_certificate", "record_id": "cert-1",
        "name": "cert-1", "domain_name": "internal-tool.example.com",
        "status": "ISSUED", "days_to_expiry": 90, "key_algorithm": "RSA_2048",
        "subject_alternative_names_count": 1,
    }

    def test_days_to_expiry_becoming_unknown_is_not_reported_as_expired(self):
        """The core regression: `int(nv or 0)` coerced a missing expiry
        value to 0, and `new_n <= 0` then falsely reported "has expired"
        at critical/high severity."""
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "days_to_expiry": None}]
        level, reason = _classify_field(prev, new, "days_to_expiry")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "expired" not in reason.lower()

    def test_days_to_expiry_zero_still_reports_expired(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "days_to_expiry": 0}]
        level, reason = _classify_field(prev, new, "days_to_expiry")
        assert level in ("critical", "high")
        assert "expired" in reason.lower()

    def test_san_count_becoming_unknown_is_not_reported_as_change(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "subject_alternative_names_count": None}]
        level, reason = _classify_field(prev, new, "subject_alternative_names_count")
        assert "could not be determined" in reason.lower()


# ── Added-record posture inspection ──────────────────────────────────────────

class TestRdsAddedPostureInspection:
    def test_added_publicly_accessible_instance_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_rds_db_instance", "record_id": "db-1",
            "name": "prod-db", "publicly_accessible": True,
            "storage_encrypted": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")
        assert "publicly accessible" in reason.lower()

    def test_added_safe_instance_is_low(self):
        new = [{
            "record_type": "aws_rds_db_instance", "record_id": "db-2",
            "name": "prod-db-2", "publicly_accessible": False,
            "storage_encrypted": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, _ = classify_aws_change(added[0])
        assert level == "low"

    def test_added_publicly_accessible_cluster_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_rds_db_cluster", "record_id": "cluster-1",
            "name": "prod-cluster", "publicly_accessible": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")
        assert "publicly accessible" in reason.lower()


class TestMessagingAddedPostureInspection:
    def test_added_public_sqs_queue_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_sqs_queue", "record_id": "queue-1",
            "name": "orders-queue", "public_or_cross_account_policy": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")
        assert "external principals" in reason.lower()

    def test_added_public_sns_topic_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_sns_topic", "record_id": "topic-1",
            "name": "alerts-topic", "public_or_cross_account_policy": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")
        assert "external principals" in reason.lower()


class TestEcrKmsEventBridgeAddedPostureInspection:
    def test_added_public_ecr_repository_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_ecr_repository", "record_id": "repo-1",
            "name": "internal-app", "policy_is_public": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")
        assert "external principals" in reason.lower()

    def test_added_public_kms_key_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_kms_key", "record_id": "key-1",
            "name": "app-key", "public_or_cross_account_policy": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")

    def test_added_public_eventbridge_bus_is_high_not_generic_low(self):
        new = [{
            "record_type": "aws_eventbridge_event_bus", "record_id": "bus-1",
            "name": "custom-bus", "public_or_cross_account_policy": True,
        }]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_aws_change(added[0])
        assert level in ("critical", "high")
