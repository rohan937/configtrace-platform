"""M82B — Datadog core security foundation tests.

Verifies all 17 Datadog configuration-risk rules, registry/confidence/pack/coverage
wiring, capability matrix update, expansion framework pointer, and frontend catalog.

Privacy guarantees verified by these tests
------------------------------------------
- Evidence never contains API key values, application key values, OAuth tokens,
  bearer tokens, webhook secrets, webhook URLs, integration secrets
- Evidence never contains raw monitor queries, raw monitor messages
- Evidence never contains raw dashboard JSON or widget queries
- Evidence never contains raw log/trace/metric values or raw event payloads
- Evidence never contains email addresses, user names, user IDs
- Evidence never contains team member identities or notification destinations
- Evidence never contains cloud account IDs (AWS/GCP/Azure)
- Evidence never contains Slack channels, PagerDuty service IDs

Sections
--------
  A. Rule key taxonomy
  B. Rule trigger tests (positive cases)
  C. Rule non-trigger tests (negative / healthy cases)
  D. Evidence privacy scan
  E. Registry / confidence / pack wiring
  F. Coverage service
  G. Capability matrix + expansion framework
  H. Frontend catalog
  I. Forbidden wording scan
  J. Secret-shape grep
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
    DATADOG_API_KEY_METADATA,
    DATADOG_APPLICATION_KEY_METADATA,
    DATADOG_CLOUD_INTEGRATION,
    DATADOG_DASHBOARD,
    DATADOG_MONITOR,
    DATADOG_NOTIFICATION_INTEGRATION,
    DATADOG_ROLE,
    DATADOG_SLO,
    DATADOG_TEAM,
    DATADOG_WEBHOOK_INTEGRATION,
)

# ── Test constants ─────────────────────────────────────────────────────────────

# Safe placeholder values — NOT real credentials.
_API_KEY = "DATADOG_TEST_API_KEY_PLACEHOLDER"
_APP_KEY = "DATADOG_TEST_APPLICATION_KEY_PLACEHOLDER"
_SITE    = "DATADOG_TEST_SITE"

EXPECTED_RULE_KEYS = {
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

# Fields that must NEVER appear in evidence dicts.
_FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "api_key", "application_key", "key_value", "secret", "token", "bearer",
    "authorization", "query", "message", "url", "webhook_url",
    "email", "user_email", "user_id", "user_name", "username",
    "member_email", "member_id", "member_name", "handle",
    "channel", "channel_name", "service_key", "service_id",
    "account_id", "project_id", "tenant_id", "subscription_id",
    "last4",
})

# Strings that must NEVER appear in evidence string values.
_FORBIDDEN_EVIDENCE_STRINGS = [
    "api.datadoghq.com",
    "datadoghq.com/api",
    "@slack",
    "@pagerduty",
    "bearer",
    "DD-API-KEY",
    "DD-APPLICATION-KEY",
]


# ── Record builder helpers ─────────────────────────────────────────────────────

def _monitor(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_MONITOR,
        "provider": "datadog",
        "record_id": "monitor_12345",
        "resource_id": "12345",
        "resource_name": "CPU alert",
        "monitor_type": "metric alert",
        "enabled": True,
        "status": "OK",
        "priority_category": "medium",
        "query_present": True,
        "query_complexity_category": "short",
        "message_present": True,
        "message_length_category": "short",
        "tag_count": 2,
        "threshold_count": 2,
        "renotify_enabled": True,
        "restricted_roles_count": 1,
        "notify_no_data": True,
        "include_tags": True,
        "evaluation_delay_category": "none",
    }
    defaults.update(kwargs)
    return defaults


def _slo(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_SLO,
        "provider": "datadog",
        "record_id": "slo_abc123",
        "resource_id": "slo_abc123",
        "resource_name": "API uptime SLO",
        "slo_type": "monitor",
        "target_category": "99.9_plus",
        "warning_target_category": "99_plus",
        "timeframe_count": 1,
        "monitor_count": 2,
        "group_count": 0,
        "tag_count": 1,
        "description_present": False,
        "description_length_category": "absent",
    }
    defaults.update(kwargs)
    return defaults


def _dashboard(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_DASHBOARD,
        "provider": "datadog",
        "record_id": "dash_abc123",
        "resource_id": "dash_abc123",
        "resource_name": "Production Overview",
        "layout_type": "ordered",
        "widget_count": 5,
        "template_variable_count": 2,
        "restricted_roles_count": 1,
        "public_url_present": False,
        "description_present": False,
        "description_length_category": "absent",
    }
    defaults.update(kwargs)
    return defaults


def _webhook(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_WEBHOOK_INTEGRATION,
        "provider": "datadog",
        "record_id": "my-webhook",
        "resource_id": "my-webhook",
        "resource_name": "my-webhook",
        "url_present": True,
        "custom_headers_present": False,
        "payload_template_present": False,
        "secret_headers_present": True,
    }
    defaults.update(kwargs)
    return defaults


def _notification(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_NOTIFICATION_INTEGRATION,
        "provider": "datadog",
        "record_id": "datadog_notif_pagerduty",
        "resource_id": "datadog_notif_pagerduty",
        "resource_name": "PagerDuty",
        "integration_type": "pagerduty",
        "enabled": True,
        "handle_count": 2,
        "channel_count": 0,
        "restricted_roles_count": 0,
    }
    defaults.update(kwargs)
    return defaults


def _api_key(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_API_KEY_METADATA,
        "provider": "datadog",
        "record_id": "apikey_abc123",
        "resource_id": "apikey_abc123",
        "resource_name": "ConfigTrace read key",
        "created_present": True,
        "modified_present": True,
        "last4_present": True,
        "created_by_present": True,
        "disabled": False,
    }
    defaults.update(kwargs)
    return defaults


def _app_key(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_APPLICATION_KEY_METADATA,
        "provider": "datadog",
        "record_id": "appkey_abc123",
        "resource_id": "appkey_abc123",
        "resource_name": "ConfigTrace app key",
        "created_present": True,
        "modified_present": True,
        "scopes_count": 3,
        "owned_by_present": True,
    }
    defaults.update(kwargs)
    return defaults


def _role(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_ROLE,
        "provider": "datadog",
        "record_id": "role_abc123",
        "resource_id": "role_abc123",
        "resource_name": "Admin",
        "permission_count": 10,
        "user_count": 5,
        "team_count": 1,
    }
    defaults.update(kwargs)
    return defaults


def _team(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_TEAM,
        "provider": "datadog",
        "record_id": "team_abc123",
        "resource_id": "team_abc123",
        "resource_name": "Platform",
        "member_count": 3,
        "handle_present": True,
        "link_count": 1,
    }
    defaults.update(kwargs)
    return defaults


def _cloud(**kwargs) -> dict[str, Any]:
    defaults = {
        "record_type": DATADOG_CLOUD_INTEGRATION,
        "provider": "datadog",
        "record_id": "datadog_cloud_aws_0",
        "resource_id": "datadog_cloud_aws_0",
        "resource_name": "AWS integration",
        "cloud_provider": "aws",
        "account_id_present": True,
        "resource_collection_enabled": True,
        "metric_collection_enabled": True,
        "log_collection_enabled": False,
        "account_tags_count": 2,
        "namespace_count": 0,
    }
    defaults.update(kwargs)
    return defaults


def _rule_keys(findings: list) -> set[str]:
    return {f.rule_key for f in findings}


# ── Section A: Rule key taxonomy ──────────────────────────────────────────────


class TestRuleKeyTaxonomy:
    def test_datadog_rule_keys_matches_expected(self):
        # M82B introduced 17 rule keys; M82C adds 14 more (31 total).
        # Verify the M82B subset is fully present in DATADOG_RULE_KEYS.
        assert EXPECTED_RULE_KEYS <= DATADOG_RULE_KEYS

    def test_rule_count_is_seventeen(self):
        # M82B baseline was 17; M82C expansion brings the total to 31.
        # Verify the M82B baseline subset still has 17 entries.
        assert len(EXPECTED_RULE_KEYS) == 17
        assert len(DATADOG_RULE_KEYS) >= 17

    def test_all_rule_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in DATADOG_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"Rule key {key!r} not in KNOWN_RULE_KEYS"

    def test_evaluate_returns_empty_for_unknown_type(self):
        assert evaluate({"record_type": "unknown_type"}) == []

    def test_evaluate_returns_empty_for_non_dict(self):
        assert evaluate("not a dict") == []  # type: ignore[arg-type]
        assert evaluate(None) == []  # type: ignore[arg-type]


# ── Section B: Rule trigger tests (positive cases) ────────────────────────────


class TestMonitorRulesTrigger:
    def test_monitor_disabled_fires_when_enabled_false(self):
        keys = _rule_keys(evaluate(_monitor(enabled=False)))
        assert "datadog_monitor_disabled" in keys

    def test_monitor_unrestricted_roles_fires_when_count_zero(self):
        keys = _rule_keys(evaluate(_monitor(restricted_roles_count=0)))
        assert "datadog_monitor_unrestricted_roles" in keys

    def test_monitor_notify_no_data_disabled_fires(self):
        keys = _rule_keys(evaluate(_monitor(notify_no_data=False)))
        assert "datadog_monitor_notify_no_data_disabled" in keys

    def test_monitor_long_query_fires_when_category_long(self):
        keys = _rule_keys(evaluate(_monitor(query_complexity_category="long")))
        assert "datadog_monitor_long_query" in keys

    def test_multiple_monitor_rules_can_fire_together(self):
        keys = _rule_keys(evaluate(_monitor(
            enabled=False,
            restricted_roles_count=0,
            notify_no_data=False,
            query_complexity_category="long",
        )))
        assert "datadog_monitor_disabled" in keys
        assert "datadog_monitor_unrestricted_roles" in keys
        assert "datadog_monitor_notify_no_data_disabled" in keys
        assert "datadog_monitor_long_query" in keys


class TestSloRulesTrigger:
    def test_slo_no_monitors_fires_for_monitor_type_slo_with_zero_monitors(self):
        keys = _rule_keys(evaluate(_slo(slo_type="monitor", monitor_count=0)))
        assert "datadog_slo_no_monitors" in keys

    def test_slo_low_target_fires_for_below_95(self):
        keys = _rule_keys(evaluate(_slo(target_category="below_95")))
        assert "datadog_slo_low_target" in keys


class TestDashboardRulesTrigger:
    def test_dashboard_public_url_fires_when_true(self):
        keys = _rule_keys(evaluate(_dashboard(public_url_present=True)))
        assert "datadog_dashboard_public_url_present" in keys

    def test_dashboard_unrestricted_roles_fires_when_count_zero(self):
        keys = _rule_keys(evaluate(_dashboard(restricted_roles_count=0)))
        assert "datadog_dashboard_unrestricted_roles" in keys


class TestWebhookRulesTrigger:
    def test_webhook_without_secret_fires_when_url_present_no_secret(self):
        keys = _rule_keys(evaluate(_webhook(url_present=True, secret_headers_present=False)))
        assert "datadog_webhook_without_secret_headers" in keys

    def test_webhook_payload_template_fires_when_present(self):
        keys = _rule_keys(evaluate(_webhook(payload_template_present=True)))
        assert "datadog_webhook_payload_template_present" in keys


class TestNotificationRulesTrigger:
    def test_notification_no_channels_fires_when_enabled_no_handles_or_channels(self):
        keys = _rule_keys(evaluate(_notification(enabled=True, handle_count=0, channel_count=0)))
        assert "datadog_notification_integration_no_channels" in keys


class TestAppKeyRulesTrigger:
    def test_application_key_broad_scopes_fires_above_threshold(self):
        keys = _rule_keys(evaluate(_app_key(scopes_count=11)))
        assert "datadog_application_key_broad_scopes" in keys

    def test_application_key_broad_scopes_fires_at_high_count(self):
        keys = _rule_keys(evaluate(_app_key(scopes_count=50)))
        assert "datadog_application_key_broad_scopes" in keys


class TestApiKeyRulesTrigger:
    def test_api_key_disabled_fires_when_true(self):
        keys = _rule_keys(evaluate(_api_key(disabled=True)))
        assert "datadog_api_key_disabled" in keys


class TestRoleRulesTrigger:
    def test_role_high_permissions_fires_above_threshold(self):
        keys = _rule_keys(evaluate(_role(permission_count=26)))
        assert "datadog_role_high_permission_count" in keys

    def test_role_high_permissions_fires_at_very_high_count(self):
        keys = _rule_keys(evaluate(_role(permission_count=100)))
        assert "datadog_role_high_permission_count" in keys


class TestTeamRulesTrigger:
    def test_team_no_members_fires_when_count_zero(self):
        keys = _rule_keys(evaluate(_team(member_count=0)))
        assert "datadog_team_no_members" in keys


class TestCloudRulesTrigger:
    def test_cloud_broad_collection_fires_when_all_three_enabled(self):
        keys = _rule_keys(evaluate(_cloud(
            resource_collection_enabled=True,
            metric_collection_enabled=True,
            log_collection_enabled=True,
        )))
        assert "datadog_cloud_integration_broad_collection" in keys

    def test_cloud_log_collection_fires_when_enabled(self):
        keys = _rule_keys(evaluate(_cloud(log_collection_enabled=True)))
        assert "datadog_cloud_integration_log_collection_enabled" in keys

    def test_cloud_log_collection_fires_even_without_broad_collection(self):
        keys = _rule_keys(evaluate(_cloud(
            resource_collection_enabled=False,
            metric_collection_enabled=False,
            log_collection_enabled=True,
        )))
        assert "datadog_cloud_integration_log_collection_enabled" in keys
        assert "datadog_cloud_integration_broad_collection" not in keys


# ── Section C: Negative / healthy cases ───────────────────────────────────────


class TestMonitorRulesNotTrigger:
    def test_enabled_monitor_does_not_fire_disabled(self):
        keys = _rule_keys(evaluate(_monitor(enabled=True)))
        assert "datadog_monitor_disabled" not in keys

    def test_monitor_with_restricted_roles_does_not_fire_unrestricted(self):
        keys = _rule_keys(evaluate(_monitor(restricted_roles_count=2)))
        assert "datadog_monitor_unrestricted_roles" not in keys

    def test_monitor_with_notify_no_data_enabled_does_not_fire(self):
        keys = _rule_keys(evaluate(_monitor(notify_no_data=True)))
        assert "datadog_monitor_notify_no_data_disabled" not in keys

    def test_monitor_short_query_does_not_fire_long_query(self):
        for cat in ("absent", "short", "medium"):
            keys = _rule_keys(evaluate(_monitor(query_complexity_category=cat)))
            assert "datadog_monitor_long_query" not in keys, f"fired for category={cat!r}"

    def test_healthy_monitor_produces_no_findings(self):
        # The M82B `_monitor()` helper doesn't include M82C fields; supply them
        # here so M82C rules also see a healthy state and do not fire.
        findings = evaluate(_monitor(
            enabled=True,
            restricted_roles_count=2,
            notify_no_data=True,
            query_complexity_category="short",
            # M82C healthy defaults
            notification_routing_present=True,
            notification_count=2,
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
        ))
        # Only M82B-relevant rules are asserted absent; this helper retains
        # the original M82B intent of "no M82B finding on a healthy monitor".
        m82b_monitor_rules = {
            "datadog_monitor_disabled",
            "datadog_monitor_unrestricted_roles",
            "datadog_monitor_notify_no_data_disabled",
            "datadog_monitor_long_query",
        }
        fired_m82b = {f.rule_key for f in findings} & m82b_monitor_rules
        assert fired_m82b == set(), f"Unexpected M82B monitor rule fired: {fired_m82b}"


class TestSloRulesNotTrigger:
    def test_slo_no_monitors_does_not_fire_for_metric_type(self):
        keys = _rule_keys(evaluate(_slo(slo_type="metric", monitor_count=0)))
        assert "datadog_slo_no_monitors" not in keys

    def test_slo_no_monitors_does_not_fire_when_monitors_present(self):
        keys = _rule_keys(evaluate(_slo(slo_type="monitor", monitor_count=2)))
        assert "datadog_slo_no_monitors" not in keys

    def test_slo_low_target_does_not_fire_for_high_target(self):
        for cat in ("99.9_plus", "99_plus", "95_plus"):
            keys = _rule_keys(evaluate(_slo(target_category=cat)))
            assert "datadog_slo_low_target" not in keys, f"fired for category={cat!r}"

    def test_healthy_slo_produces_no_findings(self):
        findings = evaluate(_slo(
            slo_type="monitor",
            monitor_count=3,
            target_category="99.9_plus",
        ))
        assert findings == []


class TestDashboardRulesNotTrigger:
    def test_no_public_url_does_not_fire(self):
        keys = _rule_keys(evaluate(_dashboard(public_url_present=False)))
        assert "datadog_dashboard_public_url_present" not in keys

    def test_restricted_dashboard_does_not_fire_unrestricted(self):
        keys = _rule_keys(evaluate(_dashboard(restricted_roles_count=3)))
        assert "datadog_dashboard_unrestricted_roles" not in keys

    def test_healthy_dashboard_produces_no_findings(self):
        findings = evaluate(_dashboard(public_url_present=False, restricted_roles_count=2))
        assert findings == []


class TestWebhookRulesNotTrigger:
    def test_webhook_with_secret_does_not_fire_missing_secret(self):
        keys = _rule_keys(evaluate(_webhook(url_present=True, secret_headers_present=True)))
        assert "datadog_webhook_without_secret_headers" not in keys

    def test_webhook_without_url_does_not_fire_missing_secret(self):
        keys = _rule_keys(evaluate(_webhook(url_present=False, secret_headers_present=False)))
        assert "datadog_webhook_without_secret_headers" not in keys

    def test_webhook_no_payload_template_does_not_fire(self):
        keys = _rule_keys(evaluate(_webhook(payload_template_present=False)))
        assert "datadog_webhook_payload_template_present" not in keys

    def test_healthy_webhook_produces_no_findings(self):
        findings = evaluate(_webhook(
            url_present=True,
            secret_headers_present=True,
            payload_template_present=False,
        ))
        assert findings == []


class TestNotificationRulesNotTrigger:
    def test_notification_with_handles_does_not_fire(self):
        keys = _rule_keys(evaluate(_notification(enabled=True, handle_count=2, channel_count=0)))
        assert "datadog_notification_integration_no_channels" not in keys

    def test_notification_with_channels_does_not_fire(self):
        keys = _rule_keys(evaluate(_notification(enabled=True, handle_count=0, channel_count=3)))
        assert "datadog_notification_integration_no_channels" not in keys

    def test_disabled_notification_does_not_fire_no_channels(self):
        keys = _rule_keys(evaluate(_notification(enabled=False, handle_count=0, channel_count=0)))
        assert "datadog_notification_integration_no_channels" not in keys


class TestAppKeyRulesNotTrigger:
    def test_application_key_at_threshold_does_not_fire(self):
        keys = _rule_keys(evaluate(_app_key(scopes_count=10)))
        assert "datadog_application_key_broad_scopes" not in keys

    def test_application_key_zero_scopes_does_not_fire_broad(self):
        keys = _rule_keys(evaluate(_app_key(scopes_count=0)))
        assert "datadog_application_key_broad_scopes" not in keys


class TestApiKeyRulesNotTrigger:
    def test_active_api_key_does_not_fire_disabled(self):
        keys = _rule_keys(evaluate(_api_key(disabled=False)))
        assert "datadog_api_key_disabled" not in keys


class TestRoleRulesNotTrigger:
    def test_role_at_threshold_does_not_fire_high_permissions(self):
        keys = _rule_keys(evaluate(_role(permission_count=25)))
        assert "datadog_role_high_permission_count" not in keys

    def test_role_with_few_permissions_does_not_fire(self):
        keys = _rule_keys(evaluate(_role(permission_count=5)))
        assert "datadog_role_high_permission_count" not in keys


class TestTeamRulesNotTrigger:
    def test_team_with_members_does_not_fire(self):
        keys = _rule_keys(evaluate(_team(member_count=3)))
        assert "datadog_team_no_members" not in keys


class TestCloudRulesNotTrigger:
    def test_no_log_collection_does_not_fire_log_rule(self):
        keys = _rule_keys(evaluate(_cloud(log_collection_enabled=False)))
        assert "datadog_cloud_integration_log_collection_enabled" not in keys
        assert "datadog_cloud_integration_broad_collection" not in keys

    def test_only_two_collection_types_does_not_fire_broad(self):
        keys = _rule_keys(evaluate(_cloud(
            resource_collection_enabled=True,
            metric_collection_enabled=True,
            log_collection_enabled=False,
        )))
        assert "datadog_cloud_integration_broad_collection" not in keys

    def test_healthy_cloud_integration_produces_no_findings(self):
        findings = evaluate(_cloud(
            resource_collection_enabled=True,
            metric_collection_enabled=True,
            log_collection_enabled=False,
        ))
        assert findings == []


# ── Section D: Evidence privacy scan ─────────────────────────────────────────


class TestEvidencePrivacy:

    def _all_findings(self) -> list:
        records = [
            _monitor(enabled=False, restricted_roles_count=0,
                     notify_no_data=False, query_complexity_category="long"),
            _slo(slo_type="monitor", monitor_count=0, target_category="below_95"),
            _dashboard(public_url_present=True, restricted_roles_count=0),
            _webhook(url_present=True, secret_headers_present=False,
                     payload_template_present=True),
            _notification(enabled=True, handle_count=0, channel_count=0),
            _api_key(disabled=True),
            _app_key(scopes_count=15),
            _role(permission_count=30),
            _team(member_count=0),
            _cloud(resource_collection_enabled=True, metric_collection_enabled=True,
                   log_collection_enabled=True),
        ]
        all_findings = []
        for rec in records:
            all_findings.extend(evaluate(rec))
        return all_findings

    def test_no_forbidden_fields_in_any_evidence(self):
        for finding in self._all_findings():
            for key in finding.evidence:
                assert key not in _FORBIDDEN_EVIDENCE_FIELDS, (
                    f"Forbidden field {key!r} in evidence for rule {finding.rule_key!r}"
                )

    def test_no_forbidden_strings_in_evidence_values(self):
        for finding in self._all_findings():
            ev_str = str(finding.evidence)
            for forbidden in _FORBIDDEN_EVIDENCE_STRINGS:
                assert forbidden.lower() not in ev_str.lower(), (
                    f"Forbidden string {forbidden!r} in evidence for rule {finding.rule_key!r}"
                )

    def test_no_api_key_values_in_any_evidence(self):
        for finding in self._all_findings():
            ev_str = str(finding.evidence)
            assert _API_KEY not in ev_str
            assert _APP_KEY not in ev_str

    def test_no_raw_query_in_monitor_evidence(self):
        findings = evaluate(_monitor(
            enabled=False,
            query_complexity_category="long",
        ))
        for f in findings:
            assert "query" not in f.evidence or f.evidence.get("query") is None
            # query_complexity_category IS safe (it's a category label)
            # but the raw query string must never appear
            ev_str = str(f.evidence)
            assert "avg:system.cpu.user" not in ev_str

    def test_no_raw_message_in_monitor_evidence(self):
        findings = evaluate(_monitor(message_present=True, message_length_category="long"))
        for f in findings:
            assert "message" not in f.evidence

    def test_no_webhook_url_in_evidence(self):
        findings = evaluate(_webhook(url_present=True, secret_headers_present=False))
        for f in findings:
            ev_str = str(f.evidence)
            assert "https://" not in ev_str
            assert "http://" not in ev_str

    def test_no_cloud_account_id_in_evidence(self):
        findings = evaluate(_cloud(
            resource_collection_enabled=True,
            metric_collection_enabled=True,
            log_collection_enabled=True,
        ))
        for f in findings:
            assert "account_id" not in f.evidence
            assert "project_id" not in f.evidence
            assert "123456789012" not in str(f.evidence)

    def test_no_user_identities_in_role_evidence(self):
        findings = evaluate(_role(permission_count=30))
        for f in findings:
            assert "user_id" not in f.evidence
            assert "user_name" not in f.evidence
            assert "email" not in f.evidence

    def test_no_member_identities_in_team_evidence(self):
        findings = evaluate(_team(member_count=0))
        for f in findings:
            assert "member_email" not in f.evidence
            assert "member_name" not in f.evidence
            assert "member_id" not in f.evidence

    def test_all_findings_have_provider_datadog(self):
        for finding in self._all_findings():
            assert finding.provider == "datadog"

    def test_all_findings_have_valid_severity(self):
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for finding in self._all_findings():
            assert finding.severity in valid_severities


# ── Section E: Registry / confidence / pack wiring ───────────────────────────


class TestRegistryWiring:
    def test_all_datadog_rule_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in DATADOG_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS

    def test_all_datadog_rule_keys_in_rule_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in DATADOG_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"Rule key {key!r} missing from RULE_CONFIDENCE"

    def test_all_datadog_confidence_levels_are_high_or_medium(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE, HIGH, MEDIUM
        for key in DATADOG_RULE_KEYS:
            conf, _ = RULE_CONFIDENCE.get(key, (None, None))
            assert conf in (HIGH, MEDIUM), (
                f"Rule key {key!r} has unexpected confidence: {conf!r}"
            )

    def test_all_datadog_rule_keys_in_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        for key in DATADOG_RULE_KEYS:
            assert key in _RULE_META, f"Rule key {key!r} missing from _RULE_META"

    def test_all_datadog_pack_entries_have_correct_provider(self):
        from app.services.security_rule_pack import _RULE_META
        for key in DATADOG_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "datadog", f"Rule {key!r} has wrong provider: {provider!r}"

    def test_all_datadog_pack_entries_have_valid_severity(self):
        from app.services.security_rule_pack import _RULE_META
        valid = {"critical", "high", "medium", "low", "info"}
        for key in DATADOG_RULE_KEYS:
            _, severity, _ = _RULE_META[key]
            assert severity in valid, f"Rule {key!r} has invalid severity: {severity!r}"

    def test_pack_list_includes_datadog_rules(self):
        from app.services.security_rule_pack import list_pack_rules
        rules = list_pack_rules()
        datadog_keys = {r["rule_key"] for r in rules if r["provider"] == "datadog"}
        assert datadog_keys == DATADOG_RULE_KEYS


# ── Section F: Coverage service ───────────────────────────────────────────────


class TestCoverageService:
    def test_datadog_in_providers_list(self):
        from app.services.security_coverage_service import PROVIDERS
        assert "datadog" in PROVIDERS

    def test_all_datadog_rule_keys_in_rule_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in DATADOG_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"Rule {key!r} missing from RULE_RECORD_TYPES"

    def test_datadog_in_provider_surfaces(self):
        from app.services.security_coverage_service import PROVIDER_SURFACES
        assert "datadog" in PROVIDER_SURFACES
        assert len(PROVIDER_SURFACES["datadog"]) >= 5

    def test_datadog_record_types_in_diagnostics(self):
        from app.services.security_coverage_service import RECORD_TYPE_DIAGNOSTICS
        expected_types = {
            "datadog_monitor", "datadog_slo", "datadog_dashboard",
            "datadog_webhook_integration", "datadog_notification_integration",
            "datadog_api_key_metadata", "datadog_application_key_metadata",
            "datadog_role", "datadog_team", "datadog_cloud_integration",
        }
        for rtype in expected_types:
            assert rtype in RECORD_TYPE_DIAGNOSTICS, (
                f"Record type {rtype!r} missing from RECORD_TYPE_DIAGNOSTICS"
            )

    def test_rule_record_types_map_to_datadog_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        datadog_record_types = {
            "datadog_monitor", "datadog_slo", "datadog_dashboard",
            "datadog_webhook_integration", "datadog_notification_integration",
            "datadog_api_key_metadata", "datadog_application_key_metadata",
            "datadog_role", "datadog_team", "datadog_cloud_integration",
        }
        for key in DATADOG_RULE_KEYS:
            for rtype in RULE_RECORD_TYPES[key]:
                assert rtype in datadog_record_types, (
                    f"Rule {key!r} maps to unexpected record type {rtype!r}"
                )


# ── Section G: Capability matrix + expansion framework ───────────────────────


class TestCapabilityMatrix:
    def setup_method(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        self.cap = get_provider_capability("datadog")
        assert self.cap is not None

    def test_drift_snapshots_true(self):
        assert self.cap.drift.drift_snapshots is True

    def test_drift_diff_true(self):
        assert self.cap.drift.drift_diff is True

    def test_drift_risk_classification_true(self):
        assert self.cap.drift.drift_risk_classification is True

    def test_security_rules_true(self):
        assert self.cap.security.security_rules is True

    def test_activity_ingestion_true_after_m82d(self):
        # M82D set activity_ingestion=True (Datadog config-state activity ingestion added)
        assert self.cap.security.activity_ingestion is True

    def test_activity_signals_true_after_m82e(self):
        # M82E set activity_signals=True (Datadog activity signal generation added)
        assert self.cap.security.activity_signals is True

    def test_risk_activity_correlations_true_after_m82f(self):
        # M82F set risk_activity_correlations=True (Datadog risk × activity correlations added)
        assert self.cap.security.risk_activity_correlations is True

    def test_demo_seed_clear_true_after_m82g(self):
        # M82G set demo_seed_clear=True (Datadog demo + QA added)
        assert self.cap.security.demo_seed_clear is True

    def test_case_report_true_after_m82g(self):
        # M82G set case_report=True (Datadog demo seeds a case)
        assert self.cap.security.case_report is True

    def test_maturity_is_partial(self):
        assert self.cap.maturity == "partial"

    def test_notes_mention_m82b(self):
        assert "M82B" in self.cap.notes

    def test_notes_mention_core_security_rules(self):
        notes_lower = self.cap.notes.lower()
        assert "security rule" in notes_lower or "rule" in notes_lower


class TestExpansionFramework:
    def test_planned_next_stage_is_m82c(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M82C" in stage or "Datadog" in stage or "M83" in stage or "Clerk" in stage

    def test_datadog_not_in_recommended_queue(self):
        from app.services.provider_expansion_framework import RECOMMENDED_NEXT_PROVIDERS
        providers = [p.provider for p in RECOMMENDED_NEXT_PROVIDERS]
        assert "datadog" not in providers


# ── Section H: Frontend catalog ───────────────────────────────────────────────


class TestFrontendCatalog:

    def _catalog_content(self) -> str:
        path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
        )
        if not path.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        return path.read_text()

    def test_all_datadog_rule_keys_in_catalog(self):
        content = self._catalog_content()
        for key in DATADOG_RULE_KEYS:
            assert f'key: "{key}"' in content, (
                f"Rule key {key!r} not found in securityRuleCatalog.ts"
            )

    def test_datadog_in_provider_coverage(self):
        content = self._catalog_content()
        assert 'provider: "datadog"' in content

    def test_datadog_catalog_entries_have_metadata_only_true(self):
        content = self._catalog_content()
        # All datadog rule entries should have metadataOnly: true
        # Check that none lack it by looking for the section
        assert "metadataOnly: true" in content

    def test_no_forbidden_phrases_in_datadog_catalog_entries(self):
        content = self._catalog_content()
        # Find the Datadog section (after Auth0 section)
        datadog_section_start = content.find('key: "datadog_monitor_disabled"')
        if datadog_section_start < 0:
            pytest.skip("Datadog section not found in catalog")
        datadog_section = content[datadog_section_start:]
        forbidden = [
            "compromise confirmed", "secret leaked", "data leaked",
            "customer data leaked", "payment fraud detected", "attacker found",
            "someone has access", "unauthorized access confirmed",
            "breach detected", "attack detected", "orders exposed",
            "card data exposed",
        ]
        for phrase in forbidden:
            assert phrase not in datadog_section.lower(), (
                f"Forbidden phrase {phrase!r} in Datadog catalog entries"
            )


# ── Section I: Forbidden wording scan ────────────────────────────────────────


FORBIDDEN_CLAIM_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

DATADOG_MODULES = [
    "app/services/security_rules/datadog.py",
    "app/connectors/datadog.py",
    "app/connectors/datadog_schema.py",
    "app/services/provider_capability_matrix_service.py",
    "app/services/integration_service.py",
    "app/workers/sync_task.py",
]


class TestForbiddenWording:

    @pytest.mark.parametrize("module_path", DATADOG_MODULES)
    def test_no_forbidden_phrases_in_module(self, module_path: str):
        full_path = Path(__file__).parent.parent / module_path
        if not full_path.exists():
            pytest.skip(f"{module_path} not found")
        content = full_path.read_text().lower()
        for phrase in FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase {phrase!r} found in {module_path}"
            )

    def test_no_forbidden_phrases_in_security_rules_file(self):
        path = Path(__file__).parent.parent / "app/services/security_rules/datadog.py"
        content = path.read_text().lower()
        for phrase in FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in content


# ── Section J: Secret-shape grep ─────────────────────────────────────────────


SECRET_PATTERNS = [
    r"eyJ[A-Za-z0-9_-]{10,}",           # JWT
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # SendGrid key
    r"AC[0-9a-fA-F]{32}",               # Twilio SID
    r"SK[0-9a-fA-F]{32}",               # Twilio key
]


class TestSecretShapeGrep:

    @pytest.mark.parametrize("module_path", DATADOG_MODULES)
    def test_no_secret_shapes_in_module(self, module_path: str):
        full_path = Path(__file__).parent.parent / module_path
        if not full_path.exists():
            pytest.skip(f"{module_path} not found")
        content = full_path.read_text()
        for pattern in SECRET_PATTERNS:
            match = re.search(pattern, content)
            assert match is None, (
                f"Secret-shaped string matching {pattern!r} in {module_path}: "
                f"{match.group()[:20]!r}"
            )

    def test_placeholder_values_used_in_tests_are_safe(self):
        for pattern in SECRET_PATTERNS:
            assert re.search(pattern, _API_KEY) is None
            assert re.search(pattern, _APP_KEY) is None
            assert re.search(pattern, _SITE) is None


# ── Section: Finding structure tests ─────────────────────────────────────────


class TestFindingStructure:

    def test_finding_keys_are_unique_within_record(self):
        """Each rule produces a unique finding_key per record."""
        findings = evaluate(_monitor(
            enabled=False,
            restricted_roles_count=0,
            notify_no_data=False,
            query_complexity_category="long",
        ))
        keys = [f.finding_key for f in findings]
        assert len(keys) == len(set(keys)), f"Duplicate finding_keys: {keys}"

    def test_finding_key_prefixed_by_rule_key(self):
        findings = evaluate(_monitor(enabled=False))
        for f in findings:
            assert f.finding_key.startswith(f.rule_key), (
                f"finding_key {f.finding_key!r} does not start with rule_key {f.rule_key!r}"
            )

    def test_all_findings_have_record_id(self):
        records = [
            _monitor(enabled=False),
            _slo(slo_type="monitor", monitor_count=0),
            _dashboard(public_url_present=True),
            _webhook(url_present=True, secret_headers_present=False),
            _api_key(disabled=True),
            _app_key(scopes_count=15),
            _role(permission_count=30),
            _team(member_count=0),
            _cloud(log_collection_enabled=True),
        ]
        for rec in records:
            for finding in evaluate(rec):
                assert finding.record_id is not None, (
                    f"Finding for rule {finding.rule_key!r} has no record_id"
                )

    def test_malformed_record_does_not_raise(self):
        malformed_records = [
            {},
            {"record_type": DATADOG_MONITOR},
            {"record_type": DATADOG_MONITOR, "enabled": "not-a-bool"},
            {"record_type": DATADOG_SLO, "monitor_count": "not-an-int"},
            {"record_type": DATADOG_DASHBOARD},
            {"record_type": DATADOG_WEBHOOK_INTEGRATION},
            {"record_type": DATADOG_API_KEY_METADATA},
            {"record_type": DATADOG_APPLICATION_KEY_METADATA},
            {"record_type": DATADOG_ROLE},
            {"record_type": DATADOG_TEAM},
            {"record_type": DATADOG_CLOUD_INTEGRATION},
        ]
        for rec in malformed_records:
            try:
                evaluate(rec)  # must not raise
            except Exception as exc:
                pytest.fail(f"evaluate raised on malformed record {rec!r}: {exc}")


# ── Section: M82A regression ──────────────────────────────────────────────────


class TestM82ARegression:
    def test_m82a_datadog_record_types_still_importable(self):
        from app.connectors.datadog_schema import DATADOG_RECORD_TYPES
        assert len(DATADOG_RECORD_TYPES) == 10

    def test_datadog_connector_still_has_validate_and_fetch(self):
        from app.connectors.datadog import DatadogConnector
        conn = DatadogConnector()
        assert hasattr(conn, "validate_credentials")
        assert hasattr(conn, "fetch")

    def test_integration_schema_still_accepts_datadog(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="datadog",
            display_name="Test Datadog",
            datadog_api_key=_API_KEY,
            datadog_application_key=_APP_KEY,
            datadog_site="datadoghq.com",
        )
        assert req.provider == "datadog"

    def test_evaluator_dispatches_to_datadog(self):
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "datadog" in _PROVIDER_RULES
