"""M82C — Datadog monitor/webhook risk expansion tests.

Verifies the 14 new M82C Datadog security rules, safe schema/connector
expansions for monitors and webhooks, registry/confidence/pack/coverage
wiring, capability matrix update, expansion framework pointer, and frontend
catalog parity.

Privacy guarantees verified by these tests
------------------------------------------
- Monitor schema expansions store only booleans, counts, and safe categories
  derived from raw query/message before discarding; raw strings NEVER stored
- Monitor notification_routing_present and notification_count are derived from
  @ characters only — notification handles NEVER stored
- Monitor query_uses_wildcard_scope and query_group_by_count are derived from
  query structure — raw query NEVER stored
- Monitor message_template_present derived from {{ presence — raw message
  NEVER stored
- Webhook url_scheme_category stores only the scheme category — URL NEVER stored
- Webhook auth_material_present derived from header key patterns only — header
  names and values NEVER stored
- Webhook custom_header_count and secret_headers_count are counts only —
  header names/values NEVER stored
- Webhook payload_template_length_category is a category — content NEVER stored
- Rule evidence never contains API keys, app keys, tokens, webhook URLs,
  header names/values, query strings, message text, emails, user IDs,
  notification destinations, customer data, or PII

Sections
--------
  A. Rule key taxonomy — 14 new M82C rules + total 31
  B. Schema/connector expansions — safe fields only
  C. Monitor M82C rule trigger tests
  D. Monitor M82C rule non-trigger tests
  E. Webhook M82C rule trigger tests
  F. Webhook M82C rule non-trigger tests
  G. Evidence privacy scan
  H. Registry / confidence / pack / coverage wiring
  I. Capability matrix + expansion framework
  J. Frontend catalog
  K. Forbidden wording scan
  L. Secret-shape grep
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.security_rules.datadog import (
    DATADOG_RULE_KEYS,
    evaluate,
)
from app.connectors.datadog_schema import (
    DATADOG_MONITOR,
    DATADOG_WEBHOOK_INTEGRATION,
)

# ── Test constants ─────────────────────────────────────────────────────────────

_MONITOR_ID = "DATADOG_TEST_MONITOR_ID"
_WEBHOOK_ID = "DATADOG_TEST_WEBHOOK_ID"

# Expected M82C new rule keys
M82C_RULE_KEYS = frozenset({
    "datadog_monitor_no_notifications",
    "datadog_monitor_message_template_present",
    "datadog_monitor_no_warning_threshold",
    "datadog_monitor_no_recovery_threshold",
    "datadog_monitor_silenced_scopes_present",
    "datadog_monitor_notify_audit_disabled",
    "datadog_monitor_require_full_window_disabled",
    "datadog_monitor_query_wildcard_scope",
    "datadog_monitor_broad_group_by",
    "datadog_monitor_long_no_data_timeframe",
    "datadog_webhook_custom_headers_without_secret_headers",
    "datadog_webhook_large_payload_template",
    "datadog_webhook_auth_material_present",
    "datadog_webhook_non_https_endpoint",
})

# Evidence fields that must NEVER appear in any finding
_FORBIDDEN_EVIDENCE_KEYS = frozenset({
    "api_key", "application_key", "key_value", "secret", "token", "bearer",
    "authorization", "query", "message", "url", "webhook_url",
    "email", "user_email", "user_id", "user_name", "username",
    "member_email", "member_id", "member_name", "handle",
    "channel", "channel_name", "service_key", "service_id",
    "account_id", "project_id", "tenant_id", "last4",
    "header_name", "header_value", "custom_header",
})


# ── Record builder helpers ─────────────────────────────────────────────────────

def _monitor(**kwargs) -> dict[str, Any]:
    """Build a healthy monitor record with all M82C fields."""
    defaults = {
        "record_type": DATADOG_MONITOR,
        "provider": "datadog",
        "record_id": _MONITOR_ID,
        "resource_id": _MONITOR_ID,
        "resource_name": "CPU alert",
        "monitor_type": "metric alert",
        "enabled": True,
        "status": "OK",
        "priority_category": "medium",
        "query_present": True,
        "query_complexity_category": "short",
        # M82C fields
        "query_uses_wildcard_scope": False,
        "query_group_by_count": 1,
        "message_present": True,
        "message_length_category": "short",
        "notification_routing_present": True,
        "notification_count": 2,
        "message_template_present": True,
        "tag_count": 2,
        "threshold_count": 2,
        "threshold_critical_present": True,
        "threshold_warning_present": True,
        "threshold_recovery_present": True,
        "renotify_enabled": True,
        "renotify_interval_category": "medium",
        "restricted_roles_count": 1,
        "notify_no_data": True,
        "include_tags": True,
        "notify_audit": True,
        "require_full_window": True,
        "evaluation_delay_category": "none",
        "silenced_scope_count": 0,
        "no_data_timeframe_category": "short",
    }
    defaults.update(kwargs)
    return defaults


def _webhook(**kwargs) -> dict[str, Any]:
    """Build a healthy webhook record with all M82C fields."""
    defaults = {
        "record_type": DATADOG_WEBHOOK_INTEGRATION,
        "provider": "datadog",
        "record_id": _WEBHOOK_ID,
        "resource_id": _WEBHOOK_ID,
        "resource_name": "my-webhook",
        "url_present": True,
        "url_scheme_category": "https",
        "custom_headers_present": False,
        "custom_header_count": 0,
        "auth_material_present": False,
        "payload_template_present": False,
        "payload_template_length_category": "absent",
        "secret_headers_present": True,
        "secret_headers_count": 1,
        "encode_as_category": "json",
    }
    defaults.update(kwargs)
    return defaults


def _rule_keys(findings: list) -> set[str]:
    return {f.rule_key for f in findings}


# ── Section A: Rule key taxonomy ──────────────────────────────────────────────


class TestRuleKeyTaxonomy:
    def test_m82c_rule_keys_set_is_14(self):
        assert len(M82C_RULE_KEYS) == 14

    def test_all_m82c_rule_keys_in_datadog_rule_keys(self):
        for key in M82C_RULE_KEYS:
            assert key in DATADOG_RULE_KEYS, f"M82C key {key!r} missing from DATADOG_RULE_KEYS"

    def test_total_datadog_rule_count_is_31(self):
        assert len(DATADOG_RULE_KEYS) == 31

    def test_all_m82c_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in M82C_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"M82C key {key!r} missing from KNOWN_RULE_KEYS"


# ── Section B: Schema/connector expansions ────────────────────────────────────


class TestSchemaConnectorExpansions:
    """Verify the M82C safe derived fields in the connector normalizers."""

    def test_monitor_normalizer_produces_notification_routing_present(self):
        from app.connectors.datadog import DatadogConnector
        raw = {
            "id": 1, "name": "X", "type": "metric alert",
            "message": "@slack-channel alert!",
            "query": "avg:cpu{*}", "options": {},
        }
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert "notification_routing_present" in rec
        assert rec["notification_routing_present"] is True

    def test_monitor_normalizer_notification_routing_false_when_no_at(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 2, "name": "X", "type": "metric alert", "message": "no mentions here", "query": "", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["notification_routing_present"] is False
        assert rec["notification_count"] == 0

    def test_monitor_normalizer_notification_count_counts_at(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 3, "name": "X", "type": "metric alert",
               "message": "@pagerduty and @slack-channel", "query": "", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["notification_count"] == 2

    def test_monitor_normalizer_message_template_present_true(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 4, "name": "X", "type": "metric alert",
               "message": "Alert: {{value}} exceeded {{threshold}}", "query": "", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["message_template_present"] is True

    def test_monitor_normalizer_message_template_false_when_no_braces(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 5, "name": "X", "type": "metric alert",
               "message": "Simple alert message", "query": "", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["message_template_present"] is False

    def test_monitor_normalizer_threshold_booleans(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 6, "name": "X", "type": "metric alert", "query": "", "options": {
            "thresholds": {"critical": 90, "warning": 70, "critical_recovery": 75}
        }}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["threshold_critical_present"] is True
        assert rec["threshold_warning_present"] is True
        assert rec["threshold_recovery_present"] is True

    def test_monitor_normalizer_threshold_booleans_absent(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 7, "name": "X", "type": "metric alert", "query": "", "options": {"thresholds": {}}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["threshold_critical_present"] is False
        assert rec["threshold_warning_present"] is False
        assert rec["threshold_recovery_present"] is False

    def test_monitor_normalizer_silenced_scope_count(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 8, "name": "X", "type": "metric alert", "query": "", "options": {
            "silenced": {"host:web01": 1700000000, "host:web02": 1700000001}
        }}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["silenced_scope_count"] == 2

    def test_monitor_normalizer_query_wildcard_scope_true(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 9, "name": "X", "type": "metric alert",
               "query": "avg:system.cpu.user{*}", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["query_uses_wildcard_scope"] is True

    def test_monitor_normalizer_query_wildcard_scope_false(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 10, "name": "X", "type": "metric alert",
               "query": "avg:system.cpu.user{env:prod}", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["query_uses_wildcard_scope"] is False

    def test_monitor_normalizer_query_group_by_count(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 11, "name": "X", "type": "metric alert",
               "query": "avg:metric{*} by {host} by {service} by {env}", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["query_group_by_count"] == 3

    def test_monitor_normalizer_no_data_timeframe_category(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 12, "name": "X", "type": "metric alert", "query": "", "options": {
            "no_data_timeframe": 180  # 180 minutes = 3 hours → "extended"
        }}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["no_data_timeframe_category"] == "extended"

    def test_monitor_normalizer_no_raw_query_stored(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 13, "name": "X", "type": "metric alert",
               "query": "avg:system.cpu.user{env:prod} by {host}", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert "query" not in rec
        assert "avg:system.cpu.user" not in str(rec)

    def test_monitor_normalizer_no_raw_message_stored(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"id": 14, "name": "X", "type": "metric alert",
               "message": "@secret-channel secret message content here", "query": "", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert "message" not in rec
        assert "secret message content" not in str(rec)
        assert "secret-channel" not in str(rec)

    def test_webhook_normalizer_url_scheme_category_https(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook1", "url": "https://example.com/webhook"}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["url_scheme_category"] == "https"
        assert "url" not in rec or rec.get("url") is None
        assert "https://example.com" not in str(rec.get("url_scheme_category", ""))

    def test_webhook_normalizer_url_scheme_category_http(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook2", "url": "http://example.com/webhook"}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["url_scheme_category"] == "http"

    def test_webhook_normalizer_url_scheme_category_absent(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook3", "url": ""}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["url_scheme_category"] == "absent"

    def test_webhook_normalizer_no_url_stored(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook4", "url": "https://secret-endpoint.example.com/path"}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        # The full URL must never appear in the record
        assert "secret-endpoint.example.com" not in str(rec)
        assert "https://secret-endpoint.example.com" not in str(rec)

    def test_webhook_normalizer_custom_header_count(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook5", "url": "https://x.com",
               "custom_headers": '{"X-Custom": "val1", "X-Extra": "val2"}'}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["custom_header_count"] == 2
        assert "X-Custom" not in str(rec)
        assert "val1" not in str(rec)

    def test_webhook_normalizer_auth_material_present_true(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook6", "url": "https://x.com",
               "custom_headers": '{"Authorization": "Bearer token123", "X-Custom": "value"}'}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["auth_material_present"] is True
        # Header names and values must not be in the record
        assert "Authorization" not in str(rec)
        assert "Bearer" not in str(rec)
        assert "token123" not in str(rec)

    def test_webhook_normalizer_auth_material_present_false_for_safe_headers(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook7", "url": "https://x.com",
               "custom_headers": '{"X-Correlation-ID": "abc123", "Content-Type": "application/json"}'}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["auth_material_present"] is False

    def test_webhook_normalizer_payload_template_length_category(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook8", "url": "https://x.com",
               "payload": '{"value": "{{value}}", "host": "{{host.name}}"}'}  # short
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["payload_template_length_category"] in ("absent", "short", "medium", "long")
        assert '{"value"' not in str(rec)  # payload content never stored

    def test_webhook_normalizer_secret_headers_count(self):
        from app.connectors.datadog import DatadogConnector
        raw = {"name": "hook9", "url": "https://x.com",
               "secret_headers": '{"X-Secret-1": "s1", "X-Secret-2": "s2"}'}
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["secret_headers_count"] == 2
        assert "X-Secret-1" not in str(rec)
        assert "s1" not in str(rec)

    def test_webhook_normalizer_encode_as_category(self):
        from app.connectors.datadog import DatadogConnector
        for encode_val, expected in [("json", "json"), ("form", "form"), ("", "unknown"), (None, "unknown")]:
            raw = {"name": "hook10", "url": "https://x.com", "encode_as": encode_val}
            rec = DatadogConnector._normalize_webhook(raw)
            if rec:
                assert rec["encode_as_category"] == expected


# ── Section C: Monitor M82C rule trigger tests ────────────────────────────────


class TestMonitorM82CRulesTrigger:

    def test_monitor_no_notifications_fires_when_routing_absent(self):
        keys = _rule_keys(evaluate(_monitor(notification_routing_present=False, notification_count=0)))
        assert "datadog_monitor_no_notifications" in keys

    def test_monitor_message_template_fires_when_present(self):
        keys = _rule_keys(evaluate(_monitor(message_template_present=True)))
        assert "datadog_monitor_message_template_present" in keys

    def test_monitor_no_warning_threshold_fires(self):
        keys = _rule_keys(evaluate(_monitor(
            threshold_critical_present=True,
            threshold_warning_present=False,
        )))
        assert "datadog_monitor_no_warning_threshold" in keys

    def test_monitor_no_recovery_threshold_fires(self):
        keys = _rule_keys(evaluate(_monitor(
            threshold_critical_present=True,
            threshold_recovery_present=False,
        )))
        assert "datadog_monitor_no_recovery_threshold" in keys

    def test_monitor_silenced_scopes_fires_when_count_positive(self):
        keys = _rule_keys(evaluate(_monitor(silenced_scope_count=2)))
        assert "datadog_monitor_silenced_scopes_present" in keys

    def test_monitor_notify_audit_disabled_fires(self):
        keys = _rule_keys(evaluate(_monitor(notify_audit=False)))
        assert "datadog_monitor_notify_audit_disabled" in keys

    def test_monitor_require_full_window_disabled_fires(self):
        keys = _rule_keys(evaluate(_monitor(require_full_window=False)))
        assert "datadog_monitor_require_full_window_disabled" in keys

    def test_monitor_query_wildcard_scope_fires_when_true(self):
        keys = _rule_keys(evaluate(_monitor(query_uses_wildcard_scope=True)))
        assert "datadog_monitor_query_wildcard_scope" in keys

    def test_monitor_broad_group_by_fires_at_threshold(self):
        keys = _rule_keys(evaluate(_monitor(query_group_by_count=3)))
        assert "datadog_monitor_broad_group_by" in keys

    def test_monitor_broad_group_by_fires_above_threshold(self):
        keys = _rule_keys(evaluate(_monitor(query_group_by_count=5)))
        assert "datadog_monitor_broad_group_by" in keys

    def test_monitor_long_no_data_timeframe_fires_for_extended(self):
        keys = _rule_keys(evaluate(_monitor(no_data_timeframe_category="extended")))
        assert "datadog_monitor_long_no_data_timeframe" in keys

    def test_all_m82c_monitor_rules_can_fire_together(self):
        record = _monitor(
            notification_routing_present=False,
            message_template_present=True,
            threshold_critical_present=True,
            threshold_warning_present=False,
            threshold_recovery_present=False,
            silenced_scope_count=1,
            notify_audit=False,
            require_full_window=False,
            query_uses_wildcard_scope=True,
            query_group_by_count=3,
            no_data_timeframe_category="extended",
        )
        keys = _rule_keys(evaluate(record))
        for expected_key in [
            "datadog_monitor_no_notifications",
            "datadog_monitor_message_template_present",
            "datadog_monitor_no_warning_threshold",
            "datadog_monitor_no_recovery_threshold",
            "datadog_monitor_silenced_scopes_present",
            "datadog_monitor_notify_audit_disabled",
            "datadog_monitor_require_full_window_disabled",
            "datadog_monitor_query_wildcard_scope",
            "datadog_monitor_broad_group_by",
            "datadog_monitor_long_no_data_timeframe",
        ]:
            assert expected_key in keys, f"Expected rule {expected_key!r} did not fire"


# ── Section D: Monitor M82C rule non-trigger tests ────────────────────────────


class TestMonitorM82CRulesNotTrigger:

    def test_monitor_no_notifications_does_not_fire_when_routing_present(self):
        keys = _rule_keys(evaluate(_monitor(notification_routing_present=True)))
        assert "datadog_monitor_no_notifications" not in keys

    def test_monitor_message_template_does_not_fire_when_absent(self):
        keys = _rule_keys(evaluate(_monitor(message_template_present=False)))
        assert "datadog_monitor_message_template_present" not in keys

    def test_monitor_no_warning_does_not_fire_without_critical(self):
        keys = _rule_keys(evaluate(_monitor(
            threshold_critical_present=False,
            threshold_warning_present=False,
        )))
        assert "datadog_monitor_no_warning_threshold" not in keys

    def test_monitor_no_warning_does_not_fire_when_warning_present(self):
        keys = _rule_keys(evaluate(_monitor(
            threshold_critical_present=True,
            threshold_warning_present=True,
        )))
        assert "datadog_monitor_no_warning_threshold" not in keys

    def test_monitor_no_recovery_does_not_fire_without_critical(self):
        keys = _rule_keys(evaluate(_monitor(
            threshold_critical_present=False,
            threshold_recovery_present=False,
        )))
        assert "datadog_monitor_no_recovery_threshold" not in keys

    def test_monitor_no_recovery_does_not_fire_when_recovery_present(self):
        keys = _rule_keys(evaluate(_monitor(
            threshold_critical_present=True,
            threshold_recovery_present=True,
        )))
        assert "datadog_monitor_no_recovery_threshold" not in keys

    def test_silenced_scopes_does_not_fire_when_count_zero(self):
        keys = _rule_keys(evaluate(_monitor(silenced_scope_count=0)))
        assert "datadog_monitor_silenced_scopes_present" not in keys

    def test_notify_audit_does_not_fire_when_true(self):
        keys = _rule_keys(evaluate(_monitor(notify_audit=True)))
        assert "datadog_monitor_notify_audit_disabled" not in keys

    def test_require_full_window_does_not_fire_when_true(self):
        keys = _rule_keys(evaluate(_monitor(require_full_window=True)))
        assert "datadog_monitor_require_full_window_disabled" not in keys

    def test_query_wildcard_scope_does_not_fire_when_false(self):
        keys = _rule_keys(evaluate(_monitor(query_uses_wildcard_scope=False)))
        assert "datadog_monitor_query_wildcard_scope" not in keys

    def test_broad_group_by_does_not_fire_below_threshold(self):
        for count in (0, 1, 2):
            keys = _rule_keys(evaluate(_monitor(query_group_by_count=count)))
            assert "datadog_monitor_broad_group_by" not in keys, f"fired for count={count}"

    def test_long_no_data_does_not_fire_for_other_categories(self):
        for cat in ("none", "short", "medium"):
            keys = _rule_keys(evaluate(_monitor(no_data_timeframe_category=cat)))
            assert "datadog_monitor_long_no_data_timeframe" not in keys, f"fired for {cat!r}"

    def test_healthy_monitor_produces_no_m82c_findings(self):
        """A healthy monitor with all good values produces no M82C findings."""
        record = _monitor(
            notification_routing_present=True,
            message_template_present=False,
            threshold_critical_present=True,
            threshold_warning_present=True,
            threshold_recovery_present=True,
            silenced_scope_count=0,
            notify_audit=True,
            require_full_window=True,
            query_uses_wildcard_scope=False,
            query_group_by_count=1,
            no_data_timeframe_category="short",
        )
        keys = _rule_keys(evaluate(record))
        for key in M82C_RULE_KEYS:
            if key.startswith("datadog_monitor"):
                assert key not in keys, f"M82C monitor rule {key!r} fired on healthy record"


# ── Section E: Webhook M82C rule trigger tests ────────────────────────────────


class TestWebhookM82CRulesTrigger:

    def test_webhook_non_https_fires_for_http_scheme(self):
        keys = _rule_keys(evaluate(_webhook(url_present=True, url_scheme_category="http")))
        assert "datadog_webhook_non_https_endpoint" in keys

    def test_webhook_custom_headers_no_secret_fires(self):
        keys = _rule_keys(evaluate(_webhook(
            custom_headers_present=True,
            custom_header_count=2,
            secret_headers_present=False,
        )))
        assert "datadog_webhook_custom_headers_without_secret_headers" in keys

    def test_webhook_large_payload_template_fires_for_long(self):
        keys = _rule_keys(evaluate(_webhook(
            payload_template_present=True,
            payload_template_length_category="long",
        )))
        assert "datadog_webhook_large_payload_template" in keys

    def test_webhook_auth_material_fires_when_true(self):
        keys = _rule_keys(evaluate(_webhook(auth_material_present=True)))
        assert "datadog_webhook_auth_material_present" in keys

    def test_all_m82c_webhook_rules_can_fire_together(self):
        record = _webhook(
            url_scheme_category="http",
            custom_headers_present=True,
            custom_header_count=2,
            auth_material_present=True,
            secret_headers_present=False,
            payload_template_present=True,
            payload_template_length_category="long",
        )
        keys = _rule_keys(evaluate(record))
        for key in [
            "datadog_webhook_non_https_endpoint",
            "datadog_webhook_custom_headers_without_secret_headers",
            "datadog_webhook_large_payload_template",
            "datadog_webhook_auth_material_present",
        ]:
            assert key in keys, f"Expected rule {key!r} did not fire"


# ── Section F: Webhook M82C rule non-trigger tests ────────────────────────────


class TestWebhookM82CRulesNotTrigger:

    def test_webhook_non_https_does_not_fire_for_https(self):
        keys = _rule_keys(evaluate(_webhook(url_scheme_category="https")))
        assert "datadog_webhook_non_https_endpoint" not in keys

    def test_webhook_non_https_does_not_fire_for_absent(self):
        keys = _rule_keys(evaluate(_webhook(url_scheme_category="absent")))
        assert "datadog_webhook_non_https_endpoint" not in keys

    def test_webhook_non_https_does_not_fire_for_unknown(self):
        keys = _rule_keys(evaluate(_webhook(url_scheme_category="unknown")))
        assert "datadog_webhook_non_https_endpoint" not in keys

    def test_webhook_custom_headers_no_secret_does_not_fire_when_no_custom_headers(self):
        keys = _rule_keys(evaluate(_webhook(
            custom_headers_present=False,
            secret_headers_present=False,
        )))
        assert "datadog_webhook_custom_headers_without_secret_headers" not in keys

    def test_webhook_custom_headers_no_secret_does_not_fire_when_secret_present(self):
        keys = _rule_keys(evaluate(_webhook(
            custom_headers_present=True,
            secret_headers_present=True,
        )))
        assert "datadog_webhook_custom_headers_without_secret_headers" not in keys

    def test_webhook_large_payload_does_not_fire_for_short_or_medium(self):
        for cat in ("absent", "short", "medium"):
            keys = _rule_keys(evaluate(_webhook(payload_template_length_category=cat)))
            assert "datadog_webhook_large_payload_template" not in keys, f"fired for {cat!r}"

    def test_webhook_auth_material_does_not_fire_when_false(self):
        keys = _rule_keys(evaluate(_webhook(auth_material_present=False)))
        assert "datadog_webhook_auth_material_present" not in keys

    def test_healthy_webhook_produces_no_m82c_findings(self):
        record = _webhook(
            url_scheme_category="https",
            custom_headers_present=False,
            auth_material_present=False,
            secret_headers_present=True,
            payload_template_length_category="absent",
        )
        keys = _rule_keys(evaluate(record))
        for key in M82C_RULE_KEYS:
            if key.startswith("datadog_webhook"):
                assert key not in keys, f"M82C webhook rule {key!r} fired on healthy record"


# ── Section G: Evidence privacy scan ─────────────────────────────────────────


class TestEvidencePrivacy:

    def _all_m82c_findings(self) -> list:
        records = [
            _monitor(notification_routing_present=False),
            _monitor(message_template_present=True),
            _monitor(threshold_critical_present=True, threshold_warning_present=False),
            _monitor(threshold_critical_present=True, threshold_recovery_present=False),
            _monitor(silenced_scope_count=3),
            _monitor(notify_audit=False),
            _monitor(require_full_window=False),
            _monitor(query_uses_wildcard_scope=True),
            _monitor(query_group_by_count=3),
            _monitor(no_data_timeframe_category="extended"),
            _webhook(url_scheme_category="http"),
            _webhook(custom_headers_present=True, custom_header_count=2, secret_headers_present=False),
            _webhook(payload_template_present=True, payload_template_length_category="long"),
            _webhook(auth_material_present=True),
        ]
        all_findings = []
        for rec in records:
            all_findings.extend(evaluate(rec))
        # Keep only M82C findings
        return [f for f in all_findings if f.rule_key in M82C_RULE_KEYS]

    def test_no_forbidden_keys_in_any_evidence(self):
        for finding in self._all_m82c_findings():
            for key in finding.evidence:
                assert key not in _FORBIDDEN_EVIDENCE_KEYS, (
                    f"Forbidden field {key!r} in evidence for rule {finding.rule_key!r}"
                )

    def test_no_raw_query_in_monitor_evidence(self):
        findings = [f for f in evaluate(_monitor(query_uses_wildcard_scope=True, query_group_by_count=3))
                    if f.rule_key in M82C_RULE_KEYS]
        for f in findings:
            assert "query" not in f.evidence
            assert "avg:system.cpu" not in str(f.evidence)

    def test_no_raw_message_in_monitor_evidence(self):
        findings = [f for f in evaluate(_monitor(
            notification_routing_present=False,
            message_template_present=True,
        )) if f.rule_key in M82C_RULE_KEYS]
        for f in findings:
            assert "message" not in f.evidence

    def test_no_webhook_url_in_evidence(self):
        findings = [f for f in evaluate(_webhook(url_scheme_category="http"))
                    if f.rule_key in M82C_RULE_KEYS]
        for f in findings:
            ev_str = str(f.evidence)
            assert "http://" not in ev_str
            assert "https://" not in ev_str
            assert "example.com" not in ev_str

    def test_no_header_names_or_values_in_evidence(self):
        findings = [f for f in evaluate(_webhook(
            custom_headers_present=True,
            custom_header_count=2,
            secret_headers_present=False,
            auth_material_present=True,
        )) if f.rule_key in M82C_RULE_KEYS]
        for f in findings:
            ev_str = str(f.evidence)
            assert "Authorization" not in ev_str
            assert "Bearer" not in ev_str
            assert "X-API-Key" not in ev_str
            assert "token" not in ev_str.lower() or "token" in f.evidence.get("rule", "")

    def test_no_payload_template_content_in_evidence(self):
        findings = [f for f in evaluate(_webhook(
            payload_template_present=True,
            payload_template_length_category="long",
        )) if f.rule_key in M82C_RULE_KEYS]
        for f in findings:
            assert "payload" not in f.evidence or f.evidence.get("payload") is None

    def test_all_m82c_findings_have_provider_datadog(self):
        for finding in self._all_m82c_findings():
            assert finding.provider == "datadog"


# ── Section H: Registry / confidence / pack / coverage wiring ────────────────


class TestRegistryWiring:

    def test_all_m82c_rule_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in M82C_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS

    def test_all_m82c_rule_keys_in_rule_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in M82C_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"Key {key!r} missing from RULE_CONFIDENCE"

    def test_all_m82c_confidence_levels_are_high_or_medium(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE, HIGH, MEDIUM
        for key in M82C_RULE_KEYS:
            conf, _ = RULE_CONFIDENCE.get(key, (None, None))
            assert conf in (HIGH, MEDIUM), f"Key {key!r} has unexpected confidence: {conf!r}"

    def test_all_m82c_rule_keys_in_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        for key in M82C_RULE_KEYS:
            assert key in _RULE_META, f"Key {key!r} missing from _RULE_META"

    def test_all_m82c_pack_entries_have_datadog_provider(self):
        from app.services.security_rule_pack import _RULE_META
        for key in M82C_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "datadog"

    def test_all_m82c_rule_keys_in_coverage_rule_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in M82C_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"Key {key!r} missing from RULE_RECORD_TYPES"

    def test_m82c_monitor_rules_map_to_datadog_monitor(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in M82C_RULE_KEYS:
            if "monitor" in key:
                assert "datadog_monitor" in RULE_RECORD_TYPES[key], \
                    f"Rule {key!r} should map to datadog_monitor"

    def test_m82c_webhook_rules_map_to_datadog_webhook_integration(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in M82C_RULE_KEYS:
            if "webhook" in key:
                assert "datadog_webhook_integration" in RULE_RECORD_TYPES[key], \
                    f"Rule {key!r} should map to datadog_webhook_integration"


# ── Section I: Capability matrix + expansion framework ───────────────────────


class TestCapabilityAndFramework:

    def test_capability_matrix_datadog_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("datadog")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_capability_matrix_datadog_drift_risk_classification_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("datadog")
        assert cap is not None
        assert cap.drift.drift_risk_classification is True

    def test_capability_matrix_datadog_activity_ingestion(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("datadog")
        assert cap is not None
        # M82D set activity_ingestion=True (Datadog config-state activity ingestion added)
        assert cap.security.activity_ingestion is True
        # M82E set activity_signals=True (Datadog activity signal generation added)
        assert cap.security.activity_signals is True
        # M82F set risk_activity_correlations=True (Datadog risk × activity correlations added)
        assert cap.security.risk_activity_correlations is True
        assert cap.security.demo_seed_clear is False

    def test_capability_matrix_notes_mention_m82c(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("datadog")
        assert cap is not None
        assert "M82C" in cap.notes

    def test_expansion_framework_planned_next_stage_is_m82d(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M82D" in stage or "Activity" in stage or "Datadog" in stage

    def test_expansion_framework_datadog_not_in_queue(self):
        from app.services.provider_expansion_framework import RECOMMENDED_NEXT_PROVIDERS
        providers = [p.provider for p in RECOMMENDED_NEXT_PROVIDERS]
        assert "datadog" not in providers


# ── Section J: Frontend catalog ───────────────────────────────────────────────


class TestFrontendCatalog:

    def _catalog_content(self) -> str:
        path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
        )
        if not path.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        return path.read_text()

    def test_all_m82c_rule_keys_in_catalog(self):
        content = self._catalog_content()
        for key in M82C_RULE_KEYS:
            assert f'key: "{key}"' in content, (
                f"M82C rule key {key!r} not found in securityRuleCatalog.ts"
            )

    def test_no_forbidden_phrases_in_m82c_catalog_entries(self):
        content = self._catalog_content()
        datadog_section_start = content.find('key: "datadog_monitor_no_notifications"')
        if datadog_section_start < 0:
            pytest.skip("M82C section not found")
        section = content[datadog_section_start:]
        for phrase in [
            "compromise confirmed", "secret leaked", "data leaked",
            "unauthorized access confirmed", "breach detected",
        ]:
            assert phrase not in section.lower(), (
                f"Forbidden phrase {phrase!r} in M82C catalog entries"
            )


# ── Section K: Forbidden wording scan ────────────────────────────────────────


FORBIDDEN_CLAIM_PHRASES = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]


class TestForbiddenWording:

    def test_no_forbidden_phrases_in_datadog_rules_file(self):
        path = Path(__file__).parent.parent / "app/services/security_rules/datadog.py"
        content = path.read_text().lower()
        for phrase in FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in content

    def test_no_forbidden_phrases_in_connector(self):
        path = Path(__file__).parent.parent / "app/connectors/datadog.py"
        content = path.read_text().lower()
        for phrase in FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in content


# ── Section L: Secret-shape grep ─────────────────────────────────────────────


SECRET_PATTERNS = [
    r"eyJ[A-Za-z0-9_-]{10,}",
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"AC[0-9a-fA-F]{32}",
    r"SK[0-9a-fA-F]{32}",
]


class TestSecretShapeGrep:

    def test_no_secret_shapes_in_datadog_rules(self):
        path = Path(__file__).parent.parent / "app/services/security_rules/datadog.py"
        content = path.read_text()
        for pattern in SECRET_PATTERNS:
            assert re.search(pattern, content) is None

    def test_no_secret_shapes_in_datadog_connector(self):
        path = Path(__file__).parent.parent / "app/connectors/datadog.py"
        content = path.read_text()
        for pattern in SECRET_PATTERNS:
            assert re.search(pattern, content) is None

    def test_test_constants_are_safe_placeholders(self):
        for pattern in SECRET_PATTERNS:
            assert re.search(pattern, _MONITOR_ID) is None
            assert re.search(pattern, _WEBHOOK_ID) is None


# ── Section: M82B regression ──────────────────────────────────────────────────


class TestM82BRegression:

    def test_all_m82b_rules_still_in_datadog_rule_keys(self):
        m82b_keys = {
            "datadog_monitor_disabled",
            "datadog_monitor_unrestricted_roles",
            "datadog_monitor_notify_no_data_disabled",
            "datadog_monitor_long_query",
            "datadog_slo_no_monitors",
            "datadog_slo_low_target",
            "datadog_dashboard_public_url_present",
            "datadog_dashboard_unrestricted_roles",
            "datadog_webhook_without_secret_headers",
            "datadog_webhook_payload_template_present",
            "datadog_notification_integration_no_channels",
            "datadog_application_key_broad_scopes",
            "datadog_api_key_disabled",
            "datadog_role_high_permission_count",
            "datadog_team_no_members",
            "datadog_cloud_integration_broad_collection",
            "datadog_cloud_integration_log_collection_enabled",
        }
        for key in m82b_keys:
            assert key in DATADOG_RULE_KEYS

    def test_m82b_webhook_without_secret_still_fires(self):
        from app.connectors.datadog_schema import DATADOG_WEBHOOK_INTEGRATION
        record = {
            "record_type": DATADOG_WEBHOOK_INTEGRATION,
            "provider": "datadog",
            "record_id": "test-webhook",
            "resource_id": "test-webhook",
            "resource_name": "test-webhook",
            "url_present": True,
            "url_scheme_category": "https",
            "custom_headers_present": False,
            "custom_header_count": 0,
            "auth_material_present": False,
            "payload_template_present": False,
            "payload_template_length_category": "absent",
            "secret_headers_present": False,
            "secret_headers_count": 0,
            "encode_as_category": "json",
        }
        keys = _rule_keys(evaluate(record))
        assert "datadog_webhook_without_secret_headers" in keys
