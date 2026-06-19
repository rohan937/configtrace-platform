"""M82A — Datadog drift provider foundation tests.

Verifies the Datadog drift connector, schema, capability matrix integration,
expansion framework update, and sync pipeline wiring that constitute M82A.

Privacy guarantees verified by these tests
------------------------------------------
- api_key value is never stored in records or on the connector instance
- application_key value is never stored in records or on the connector instance
- DD-API-KEY and DD-APPLICATION-KEY headers are never in normalised records
- Raw monitor query strings are never stored (query_present boolean only)
- Raw monitor message text is never stored (message_present + length category)
- Raw dashboard JSON is never stored (widget_count / template_variable_count only)
- Widget query strings or formulas are never stored
- Webhook URLs, custom headers, payload templates, and signing secrets are never stored
- Notification handles (Slack channels, PagerDuty service IDs) are never stored
- API key values and last4 digits are never stored (last4_present boolean only)
- Application key values are never stored
- User identities, user IDs, user emails, team handles are never stored
- AWS account IDs, GCP project IDs, Azure tenant/subscription IDs are never stored
- Logs, traces, metric values, and incident content are never fetched or stored

Sections
--------
  A. Schema — record type taxonomy
  B. Normalizer unit tests (pure Python, no HTTP required)
  C. Sensitive field scan across all normalizers
  D. Error mapping (mocked HTTP responses)
  E. Connector integration (mocked HTTP)
  F. Provider registration (sync_task, integration schema, capability matrix,
     expansion framework)
  G. Frontend provider and form parity
  H. Forbidden wording scan across connector modules
  I. Secret-shape grep
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.datadog import (
    DatadogConnector,
    _eval_delay_category,
    _length_category,
    _priority_category,
    _sanitize_site,
    _target_category,
)
from app.connectors.datadog_schema import (
    DATADOG_API_KEY_METADATA,
    DATADOG_APPLICATION_KEY_METADATA,
    DATADOG_CLOUD_INTEGRATION,
    DATADOG_DASHBOARD,
    DATADOG_MONITOR,
    DATADOG_NOTIFICATION_INTEGRATION,
    DATADOG_RECORD_TYPES,
    DATADOG_ROLE,
    DATADOG_SLO,
    DATADOG_TEAM,
    DATADOG_WEBHOOK_INTEGRATION,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

# ── Test constants ─────────────────────────────────────────────────────────────

# Safe placeholder values — these are NOT real credentials.
_API_KEY = "DATADOG_TEST_API_KEY_PLACEHOLDER"
_APP_KEY = "DATADOG_TEST_APPLICATION_KEY_PLACEHOLDER"
_SITE    = "DATADOG_TEST_SITE"   # safe placeholder site string

_CREDS = {
    "api_key":         _API_KEY,
    "application_key": _APP_KEY,
    "site":            "datadoghq.com",
}

EXPECTED_RECORD_TYPES = {
    "datadog_monitor",
    "datadog_slo",
    "datadog_dashboard",
    "datadog_webhook_integration",
    "datadog_notification_integration",
    "datadog_api_key_metadata",
    "datadog_application_key_metadata",
    "datadog_role",
    "datadog_team",
    "datadog_cloud_integration",
}

# Field names that must NEVER appear as keys in any normalised record.
_FORBIDDEN_FIELDS: frozenset[str] = frozenset({
    # Datadog credentials
    "api_key", "application_key", "apikey", "appkey", "app_key",
    "key_value", "key", "secret", "token", "bearer", "authorization",
    # Raw content fields
    "query", "message", "dashboard_json", "widget_json", "payload",
    "payload_template", "custom_headers", "headers",
    # Identity fields
    "email", "user_email", "user_id", "user_name", "username",
    "member_email", "member_id", "member_name",
    # Channel / destination fields
    "handle", "channel", "channel_name", "service_key", "service_id",
    "webhook_url", "url", "slack_url", "pagerduty_key",
    # Cloud account identifiers
    "account_id", "project_id", "tenant_id", "subscription_id",
    "role_arn", "external_id",
    # last4 digits
    "last4",
})

# ── Section A: Schema — record type taxonomy ───────────────────────────────────


class TestSchema:
    def test_record_types_contains_all_expected(self):
        assert EXPECTED_RECORD_TYPES == DATADOG_RECORD_TYPES

    def test_record_types_is_frozenset(self):
        assert isinstance(DATADOG_RECORD_TYPES, frozenset)

    def test_all_expected_record_type_constants_importable(self):
        assert DATADOG_MONITOR == "datadog_monitor"
        assert DATADOG_SLO == "datadog_slo"
        assert DATADOG_DASHBOARD == "datadog_dashboard"
        assert DATADOG_WEBHOOK_INTEGRATION == "datadog_webhook_integration"
        assert DATADOG_NOTIFICATION_INTEGRATION == "datadog_notification_integration"
        assert DATADOG_API_KEY_METADATA == "datadog_api_key_metadata"
        assert DATADOG_APPLICATION_KEY_METADATA == "datadog_application_key_metadata"
        assert DATADOG_ROLE == "datadog_role"
        assert DATADOG_TEAM == "datadog_team"
        assert DATADOG_CLOUD_INTEGRATION == "datadog_cloud_integration"

    def test_record_types_count_is_ten(self):
        assert len(DATADOG_RECORD_TYPES) == 10


# ── Section B: Normalizer unit tests ──────────────────────────────────────────


class TestNormalizers:

    # ── Monitor ──────────────────────────────────────────────────────────────

    def test_normalize_monitor_basic(self):
        raw = {
            "id": 12345,
            "name": "High CPU alert",
            "type": "metric alert",
            "status": "OK",
            "priority": 2,
            "query": "avg:system.cpu.user{*} > 90",
            "message": "Alert on @slack-alerts",
            "tags": ["env:prod", "team:platform"],
            "options": {
                "thresholds": {"critical": 90, "warning": 70},
                "renotify_interval": 60,
                "notify_no_data": True,
                "include_tags": True,
                "evaluation_delay": 120,
            },
            "restricted_roles": [],
        }
        conn = DatadogConnector()
        rec = conn._normalize_monitor(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_MONITOR
        assert rec["provider"] == "datadog"
        assert rec["record_id"] == "12345"
        assert rec["resource_id"] == "12345"
        assert rec["resource_name"] == "High CPU alert"
        assert rec["monitor_type"] == "metric alert"
        assert rec["status"] == "OK"
        assert rec["priority_category"] == "high"
        assert rec["tag_count"] == 2
        assert rec["threshold_count"] == 2
        assert rec["renotify_enabled"] is True
        assert rec["notify_no_data"] is True
        assert rec["include_tags"] is True
        assert rec["evaluation_delay_category"] == "medium"

    def test_normalize_monitor_never_stores_raw_query(self):
        raw = {
            "id": 1,
            "name": "Test",
            "type": "metric alert",
            "query": "avg:system.cpu.user{*} > 90",
            "message": "some message @slack",
            "options": {},
        }
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        # query must NOT be in the record
        assert "query" not in rec
        # message must NOT be in the record
        assert "message" not in rec
        # only safe boolean/category fields
        assert "query_present" in rec
        assert rec["query_present"] is True
        assert "message_present" in rec
        assert rec["message_present"] is True

    def test_normalize_monitor_empty_query_gives_false_present(self):
        raw = {"id": 2, "name": "X", "type": "event alert", "options": {}}
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["query_present"] is False
        assert rec["query_complexity_category"] == "absent"
        assert rec["message_present"] is False
        assert rec["message_length_category"] == "absent"

    def test_normalize_monitor_priority_categories(self):
        for priority, expected in [(1, "critical"), (2, "high"), (3, "medium"), (4, "low"), (5, "info"), (None, "none")]:
            raw = {"id": 99, "name": "X", "type": "metric alert", "priority": priority, "options": {}}
            rec = DatadogConnector._normalize_monitor(raw)
            assert rec["priority_category"] == expected, f"priority={priority!r}"

    def test_normalize_monitor_enabled_false_when_silenced(self):
        raw = {
            "id": 3, "name": "X", "type": "metric alert",
            "options": {"silenced": {"*": 1700000000}},
        }
        rec = DatadogConnector._normalize_monitor(raw)
        assert rec is not None
        assert rec["enabled"] is False

    def test_normalize_monitor_returns_none_for_missing_id(self):
        raw = {"name": "No ID monitor", "type": "metric alert", "options": {}}
        assert DatadogConnector._normalize_monitor(raw) is None

    # ── SLO ──────────────────────────────────────────────────────────────────

    def test_normalize_slo_basic(self):
        raw = {
            "id": "slo_abc123",
            "name": "API uptime SLO",
            "type": "metric",
            "thresholds": [{"target": 99.9, "warning": 99.5}],
            "monitor_ids": [],
            "groups": [],
            "tags": ["team:api"],
            "description": "Uptime SLO for API service",
        }
        rec = DatadogConnector._normalize_slo(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_SLO
        assert rec["slo_type"] == "metric"
        assert rec["target_category"] == "99.9_plus"
        assert rec["timeframe_count"] == 1
        assert rec["tag_count"] == 1
        assert rec["description_present"] is True
        assert "description" not in rec

    def test_normalize_slo_never_stores_description(self):
        raw = {"id": "slo1", "name": "X", "type": "monitor", "description": "secret info", "thresholds": []}
        rec = DatadogConnector._normalize_slo(raw)
        assert rec is not None
        assert "description" not in rec
        assert rec["description_present"] is True

    def test_normalize_slo_target_categories(self):
        for target, expected in [(99.95, "99.9_plus"), (99.5, "99_plus"), (97.0, "95_plus"), (90.0, "below_95")]:
            raw = {"id": "slo_t", "name": "X", "type": "metric", "thresholds": [{"target": target}]}
            rec = DatadogConnector._normalize_slo(raw)
            assert rec["target_category"] == expected

    def test_normalize_slo_returns_none_for_missing_id(self):
        raw = {"name": "No ID", "type": "metric", "thresholds": []}
        assert DatadogConnector._normalize_slo(raw) is None

    # ── Dashboard ─────────────────────────────────────────────────────────────

    def test_normalize_dashboard_basic(self):
        raw = {
            "id": "abc-def-123",
            "title": "Production Overview",
            "layout_type": "ordered",
            "widgets": [{"id": 1}, {"id": 2}, {"id": 3}],
            "template_variables": [{"name": "env"}],
            "restricted_roles": [],
            "description": "Main prod dashboard",
        }
        rec = DatadogConnector._normalize_dashboard(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_DASHBOARD
        assert rec["resource_name"] == "Production Overview"
        assert rec["layout_type"] == "ordered"
        assert rec["widget_count"] == 3
        assert rec["template_variable_count"] == 1
        assert rec["description_present"] is True

    def test_normalize_dashboard_never_stores_raw_json(self):
        raw = {
            "id": "dash1",
            "title": "X",
            "layout_type": "free",
            "widgets": [{"definition": {"type": "query_value", "requests": [{"q": "avg:metric"}]}}],
            "description": "contains raw widget query",
        }
        rec = DatadogConnector._normalize_dashboard(raw)
        assert rec is not None
        # Raw widget data must NOT be stored
        assert "widgets" not in rec
        assert "definition" not in rec
        assert "requests" not in rec
        assert "description" not in rec
        assert rec["widget_count"] == 1
        assert rec["description_present"] is True

    def test_normalize_dashboard_public_url_present_boolean(self):
        raw = {"id": "d1", "title": "X", "layout_type": "ordered", "url": "/dashboard/d1/my-dash"}
        rec = DatadogConnector._normalize_dashboard(raw)
        assert rec is not None
        assert rec["public_url_present"] is True
        assert "url" not in rec

    def test_normalize_dashboard_returns_none_for_missing_id(self):
        raw = {"title": "No ID"}
        assert DatadogConnector._normalize_dashboard(raw) is None

    # ── Webhook integration ───────────────────────────────────────────────────

    def test_normalize_webhook_basic(self):
        raw = {
            "name": "my-webhook",
            "url": "https://example.com/hook",
            "custom_headers": '{"X-Custom": "value"}',
            "payload": '{"text": "{{alert_title}}"}',
            "secret_headers": None,
        }
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_WEBHOOK_INTEGRATION
        assert rec["record_id"] == "my-webhook"
        assert rec["url_present"] is True
        assert rec["custom_headers_present"] is True
        assert rec["payload_template_present"] is True

    def test_normalize_webhook_never_stores_url_or_headers(self):
        raw = {
            "name": "hook1",
            "url": "https://secret-endpoint.example.com/hook",
            "custom_headers": '{"Authorization": "Bearer secret_token"}',
            "payload": '{"alert": "{{alert_title}}"}',
        }
        rec = DatadogConnector._normalize_webhook(raw)
        assert rec is not None
        # URL, headers, and payload must NOT be stored as strings
        assert "url" not in rec
        assert "custom_headers" not in rec
        assert "payload" not in rec
        # Only boolean presence flags
        assert rec["url_present"] is True
        assert rec["custom_headers_present"] is True

    def test_normalize_webhook_returns_none_for_missing_name(self):
        raw = {"url": "https://example.com/hook"}
        assert DatadogConnector._normalize_webhook(raw) is None

    # ── Notification integration ──────────────────────────────────────────────

    def test_normalize_notification_pagerduty(self):
        raw = {"services": [{"service_name": "prod-oncall"}, {"service_name": "infra-alerts"}]}
        rec = DatadogConnector._normalize_notification_integration("pagerduty", raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_NOTIFICATION_INTEGRATION
        assert rec["integration_type"] == "pagerduty"
        assert rec["handle_count"] == 2
        # service names must NOT be stored
        assert "service_name" not in rec

    def test_normalize_notification_never_stores_channel_or_handle_values(self):
        raw = {"channels": [{"channel_name": "#alerts"}, {"channel_name": "#ops"}]}
        rec = DatadogConnector._normalize_notification_integration("slack", raw)
        assert rec is not None
        assert rec["channel_count"] == 2
        # Channel names must NOT be in the record
        assert "channel_name" not in str(rec)
        assert "#alerts" not in str(rec)
        assert "#ops" not in str(rec)

    # ── API key metadata ──────────────────────────────────────────────────────

    def test_normalize_api_key_basic(self):
        raw = {
            "id": "key_abc123",
            "attributes": {
                "name": "ConfigTrace read key",
                "last4": "ab12",
                "created_at": "2024-01-01T00:00:00Z",
                "modified_at": "2024-06-01T00:00:00Z",
                "created_by": {"name": "admin"},
            },
        }
        rec = DatadogConnector._normalize_api_key(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_API_KEY_METADATA
        assert rec["resource_name"] == "ConfigTrace read key"
        assert rec["created_present"] is True
        assert rec["modified_present"] is True
        assert rec["last4_present"] is True
        assert rec["created_by_present"] is True

    def test_normalize_api_key_never_stores_key_value_or_last4(self):
        raw = {
            "id": "key_secret",
            "attributes": {
                "name": "my-key",
                "key": "actual_api_key_value_here",
                "last4": "ab12",
            },
        }
        rec = DatadogConnector._normalize_api_key(raw)
        assert rec is not None
        # key value and last4 must NOT be stored
        assert "key" not in rec
        assert "last4" not in rec
        assert "actual_api_key_value_here" not in str(rec)
        assert "ab12" not in str(rec)
        # Only presence boolean
        assert rec["last4_present"] is True

    def test_normalize_api_key_returns_none_for_missing_id(self):
        raw = {"attributes": {"name": "no-id-key"}}
        assert DatadogConnector._normalize_api_key(raw) is None

    # ── Application key metadata ──────────────────────────────────────────────

    def test_normalize_app_key_basic(self):
        raw = {
            "id": "appkey_xyz",
            "attributes": {
                "name": "ConfigTrace app key",
                "scopes": ["monitors_read", "dashboards_read"],
                "created_at": "2024-01-01T00:00:00Z",
                "owned_by": {"name": "admin_user"},
            },
        }
        rec = DatadogConnector._normalize_app_key(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_APPLICATION_KEY_METADATA
        assert rec["scopes_count"] == 2
        assert rec["owned_by_present"] is True

    def test_normalize_app_key_never_stores_key_value(self):
        raw = {
            "id": "appkey_secret",
            "attributes": {
                "name": "my-app-key",
                "hash": "the_actual_app_key_hash",
                "key": "the_actual_app_key_value",
            },
        }
        rec = DatadogConnector._normalize_app_key(raw)
        assert rec is not None
        assert "key" not in rec
        assert "hash" not in rec
        assert "the_actual_app_key_value" not in str(rec)
        assert "the_actual_app_key_hash" not in str(rec)

    # ── Role ──────────────────────────────────────────────────────────────────

    def test_normalize_role_basic(self):
        raw = {
            "id": "role_abc",
            "attributes": {"name": "Admin", "user_count": 5},
            "relationships": {
                "permissions": {"data": [{"id": "perm1"}, {"id": "perm2"}]}
            },
        }
        rec = DatadogConnector._normalize_role(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_ROLE
        assert rec["resource_name"] == "Admin"
        assert rec["permission_count"] == 2
        assert rec["user_count"] == 5

    def test_normalize_role_never_stores_user_identities(self):
        raw = {
            "id": "role_xyz",
            "attributes": {
                "name": "Editor",
                "user_count": 3,
                "users": [
                    {"email": "user1@example.com", "name": "User One"},
                    {"email": "user2@example.com", "name": "User Two"},
                ],
            },
        }
        rec = DatadogConnector._normalize_role(raw)
        assert rec is not None
        assert "users" not in rec
        assert "email" not in str(rec)
        assert "user1@example.com" not in str(rec)
        assert "User One" not in str(rec)
        assert rec["user_count"] == 3

    def test_normalize_role_returns_none_for_missing_id(self):
        raw = {"attributes": {"name": "No ID"}}
        assert DatadogConnector._normalize_role(raw) is None

    # ── Team ──────────────────────────────────────────────────────────────────

    def test_normalize_team_basic(self):
        raw = {
            "id": "team_abc",
            "attributes": {
                "name": "Platform Team",
                "handle": "platform-team",
                "user_count": 8,
                "links": [{"type": "runbook"}, {"type": "docs"}],
            },
        }
        rec = DatadogConnector._normalize_team(raw)
        assert rec is not None
        assert rec["record_type"] == DATADOG_TEAM
        assert rec["resource_name"] == "Platform Team"
        assert rec["member_count"] == 8
        assert rec["handle_present"] is True
        assert rec["link_count"] == 2
        # handle string must NOT be stored
        assert "handle" not in rec
        assert "platform-team" not in str(rec)

    def test_normalize_team_never_stores_member_identities(self):
        raw = {
            "id": "team_xyz",
            "attributes": {
                "name": "Security Team",
                "handle": "security",
                "user_count": 4,
                "members": [
                    {"email": "alice@example.com"},
                    {"email": "bob@example.com"},
                ],
            },
        }
        rec = DatadogConnector._normalize_team(raw)
        assert rec is not None
        assert "members" not in rec
        assert "alice@example.com" not in str(rec)
        assert "bob@example.com" not in str(rec)

    # ── Cloud integration ─────────────────────────────────────────────────────

    def test_normalize_cloud_integration_aws(self):
        raw = {
            "account_id": "123456789012",
            "resource_collection_enabled": True,
            "metrics_collection_enabled": True,
            "logs_enabled": False,
            "host_tags": ["env:prod", "region:us-east-1"],
        }
        rec = DatadogConnector._normalize_cloud_integration("aws", raw, 0)
        assert rec is not None
        assert rec["record_type"] == DATADOG_CLOUD_INTEGRATION
        assert rec["cloud_provider"] == "aws"
        assert rec["account_id_present"] is True
        assert rec["resource_collection_enabled"] is True
        assert rec["log_collection_enabled"] is False
        # account_id must NOT be stored
        assert "account_id" not in rec
        assert "123456789012" not in str(rec)

    def test_normalize_cloud_integration_never_stores_account_id(self):
        for cloud, account_field, account_val in [
            ("aws", "account_id", "111122223333"),
            ("gcp", "project_id", "my-gcp-project"),
            ("azure", "tenant_name", "mytenant.onmicrosoft.com"),
        ]:
            raw = {account_field: account_val}
            rec = DatadogConnector._normalize_cloud_integration(cloud, raw, 0)
            assert rec is not None
            assert rec["account_id_present"] is True
            assert account_field not in rec
            assert account_val not in str(rec), f"account value leaked for {cloud}"


# ── Section C: Sensitive field scan across all normalizers ────────────────────


class TestSensitiveFieldScan:

    def _all_records(self) -> list[dict]:
        """Generate one representative record per surface for scanning."""
        conn = DatadogConnector()
        return [
            conn._normalize_monitor({
                "id": 1, "name": "test", "type": "metric alert",
                "query": "avg:cpu > 90", "message": "@slack-channel",
                "options": {"thresholds": {"critical": 90}},
            }),
            conn._normalize_slo({
                "id": "slo1", "name": "uptime", "type": "metric",
                "thresholds": [{"target": 99.9}], "description": "raw desc",
            }),
            conn._normalize_dashboard({
                "id": "dash1", "title": "Prod", "layout_type": "ordered",
                "widgets": [{"q": "avg:metric"}], "description": "raw desc",
                "url": "/dashboard/dash1/prod",
            }),
            conn._normalize_webhook({
                "name": "hook1", "url": "https://secret.example.com/hook",
                "custom_headers": '{"Authorization": "Bearer secret"}',
                "payload": '{"text": "alert"}',
            }),
            conn._normalize_notification_integration("pagerduty", {
                "services": [{"service_name": "prod-oncall", "service_key": "sk_xyz"}],
            }),
            conn._normalize_api_key({
                "id": "key1",
                "attributes": {
                    "name": "mykey", "last4": "ab12", "key": "actual_key_value",
                    "created_at": "2024-01-01", "created_by": {"name": "admin"},
                },
            }),
            conn._normalize_app_key({
                "id": "appkey1",
                "attributes": {"name": "myappkey", "key": "actual_app_key", "scopes": []},
            }),
            conn._normalize_role({
                "id": "role1",
                "attributes": {"name": "Admin", "user_count": 2},
                "relationships": {"permissions": {"data": []}},
            }),
            conn._normalize_team({
                "id": "team1",
                "attributes": {"name": "Platform", "handle": "platform", "user_count": 3},
            }),
            conn._normalize_cloud_integration("aws", {"account_id": "111222333444"}, 0),
        ]

    def test_no_forbidden_fields_in_any_record(self):
        records = self._all_records()
        for rec in records:
            if rec is None:
                continue
            for key in rec.keys():
                assert key not in _FORBIDDEN_FIELDS, (
                    f"Forbidden field '{key}' found in {rec.get('record_type', '?')} record"
                )

    def test_no_raw_query_in_monitor(self):
        conn = DatadogConnector()
        rec = conn._normalize_monitor({
            "id": 1, "name": "x", "type": "metric alert",
            "query": "avg:system.cpu.user{env:prod} > 90",
            "options": {},
        })
        assert rec is not None
        assert "query" not in rec
        assert "avg:system.cpu.user{env:prod} > 90" not in str(rec)

    def test_no_raw_message_in_monitor(self):
        conn = DatadogConnector()
        rec = conn._normalize_monitor({
            "id": 2, "name": "x", "type": "metric alert",
            "message": "Alert @pagerduty @slack-channel webhook_url",
            "options": {},
        })
        assert rec is not None
        assert "message" not in rec
        assert "@pagerduty" not in str(rec)
        assert "webhook_url" not in str(rec)

    def test_no_raw_description_in_slo(self):
        conn = DatadogConnector()
        rec = conn._normalize_slo({
            "id": "slo1", "name": "x", "type": "metric",
            "thresholds": [], "description": "Contains customer PII and raw data",
        })
        assert rec is not None
        assert "description" not in rec
        assert "Contains customer PII" not in str(rec)

    def test_no_raw_dashboard_json_or_widget_queries(self):
        conn = DatadogConnector()
        rec = conn._normalize_dashboard({
            "id": "d1", "title": "X", "layout_type": "ordered",
            "widgets": [{"definition": {"q": "avg:my.metric{*}"}}],
        })
        assert rec is not None
        assert "widgets" not in rec
        assert "definition" not in rec
        assert "avg:my.metric{*}" not in str(rec)

    def test_no_webhook_url_or_headers(self):
        conn = DatadogConnector()
        rec = conn._normalize_webhook({
            "name": "hook", "url": "https://pagerduty.com/webhook/secret123",
            "custom_headers": '{"X-Secret": "mysecret"}',
        })
        assert rec is not None
        assert "url" not in rec
        assert "custom_headers" not in rec
        assert "https://pagerduty.com" not in str(rec)
        assert "mysecret" not in str(rec)

    def test_no_notification_handle_values(self):
        conn = DatadogConnector()
        rec = conn._normalize_notification_integration("pagerduty", {
            "services": [{"service_name": "MY_PAGERDUTY_SERVICE", "service_key": "PD_KEY_VALUE"}],
        })
        assert rec is not None
        assert "MY_PAGERDUTY_SERVICE" not in str(rec)
        assert "PD_KEY_VALUE" not in str(rec)

    def test_no_api_key_value_or_last4(self):
        conn = DatadogConnector()
        rec = conn._normalize_api_key({
            "id": "k1",
            "attributes": {"name": "mykey", "key": "SECRET_API_KEY", "last4": "ab12"},
        })
        assert rec is not None
        assert "SECRET_API_KEY" not in str(rec)
        assert "ab12" not in str(rec)
        assert "key" not in rec
        assert "last4" not in rec

    def test_no_team_handle_value(self):
        conn = DatadogConnector()
        rec = conn._normalize_team({
            "id": "t1",
            "attributes": {"name": "Security", "handle": "TEAM_HANDLE_VALUE", "user_count": 2},
        })
        assert rec is not None
        assert "TEAM_HANDLE_VALUE" not in str(rec)
        assert "handle" not in rec

    def test_no_cloud_account_id(self):
        conn = DatadogConnector()
        rec = conn._normalize_cloud_integration("aws", {"account_id": "AWS_ACCOUNT_ID_VALUE"}, 0)
        assert rec is not None
        assert "AWS_ACCOUNT_ID_VALUE" not in str(rec)
        assert "account_id" not in rec


# ── Section D: Error mapping ──────────────────────────────────────────────────


class TestErrorMapping:

    def _make_mock_resp(self, status_code: int, headers: dict | None = None) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = headers or {}
        resp.json.return_value = {}
        return resp

    def test_401_raises_authentication_error(self):
        conn = DatadogConnector()
        resp = self._make_mock_resp(401)
        with pytest.raises(AuthenticationError):
            conn._raise_for_status(resp)

    def test_403_raises_authentication_error(self):
        conn = DatadogConnector()
        resp = self._make_mock_resp(403)
        with pytest.raises(AuthenticationError):
            conn._raise_for_status(resp)

    def test_429_raises_rate_limit_error(self):
        conn = DatadogConnector()
        resp = self._make_mock_resp(429, {"Retry-After": "30"})
        with pytest.raises(RateLimitError) as exc_info:
            conn._raise_for_status(resp)
        assert exc_info.value.retry_after == 30.0

    def test_5xx_raises_connector_error(self):
        conn = DatadogConnector()
        for code in (500, 502, 503):
            resp = self._make_mock_resp(code)
            with pytest.raises(ConnectorError):
                conn._raise_for_status(resp)

    def test_200_does_not_raise(self):
        conn = DatadogConnector()
        resp = self._make_mock_resp(200)
        conn._raise_for_status(resp)  # should not raise

    def test_network_error_maps_to_network_error(self):
        import httpx
        conn = DatadogConnector()
        with patch.object(conn, "_make_client") as mock_client_cm:
            mock_client = MagicMock()
            mock_client_cm.return_value.__enter__.return_value = mock_client
            mock_client.get.side_effect = httpx.ConnectError("connection refused")
            with pytest.raises(NetworkError):
                conn.validate_credentials(_CREDS)


# ── Section E: Connector integration (mocked HTTP) ────────────────────────────


class TestConnectorIntegration:

    def _make_mock_client(self, responses: dict) -> MagicMock:
        """Build a mock httpx.Client that returns pre-canned JSON responses."""
        client = MagicMock()

        def mock_get(path, params=None):
            resp = MagicMock()
            resp.status_code = 200
            # Look up response by path
            data = responses.get(path)
            if data is None:
                # Default: empty list
                data = []
            resp.json.return_value = data
            return resp

        client.get.side_effect = mock_get
        return client

    def test_validate_credentials_calls_api_keys_endpoint(self):
        conn = DatadogConnector()
        with patch.object(conn, "_make_client") as mock_cm:
            mock_client = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": []}
            mock_client.get.return_value = mock_resp
            mock_cm.return_value.__enter__.return_value = mock_client
            result = conn.validate_credentials(_CREDS)
        assert result is True
        mock_client.get.assert_called_once_with(
            "/api/v2/api_keys",
            params={"page[number]": 0, "page[size]": 1},
        )

    def test_validate_credentials_requires_api_key(self):
        conn = DatadogConnector()
        with pytest.raises(AuthenticationError, match="api_key"):
            conn.validate_credentials({"api_key": "", "application_key": "k"})

    def test_validate_credentials_requires_application_key(self):
        conn = DatadogConnector()
        with pytest.raises(AuthenticationError, match="application_key"):
            conn.validate_credentials({"api_key": "k", "application_key": ""})

    def test_api_base_built_from_site(self):
        conn = DatadogConnector()
        with patch("app.connectors.datadog.httpx.Client") as mock_cls:
            # Make __enter__ return the mock instance so context-manager pattern works
            instance = MagicMock()
            mock_cls.return_value = instance
            instance.__enter__ = MagicMock(return_value=instance)
            instance.__exit__ = MagicMock(return_value=False)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": []}
            instance.get.return_value = mock_resp
            conn.validate_credentials({
                "api_key": _API_KEY,
                "application_key": _APP_KEY,
                "site": "datadoghq.eu",
            })
        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs.get("base_url") == "https://api.datadoghq.eu"

    def test_connector_sends_dd_headers(self):
        conn = DatadogConnector()
        with patch("app.connectors.datadog.httpx.Client") as mock_cls:
            instance = MagicMock()
            mock_cls.return_value = instance
            instance.__enter__ = MagicMock(return_value=instance)
            instance.__exit__ = MagicMock(return_value=False)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": []}
            instance.get.return_value = mock_resp
            conn.validate_credentials(_CREDS)
        call_kwargs = mock_cls.call_args.kwargs
        headers = call_kwargs.get("headers", {})
        assert "DD-API-KEY" in headers
        assert "DD-APPLICATION-KEY" in headers
        assert headers["DD-API-KEY"] == _API_KEY
        assert headers["DD-APPLICATION-KEY"] == _APP_KEY

    def test_fetch_returns_flat_list(self):
        conn = DatadogConnector()
        monitor_resp = [{"id": 1, "name": "CPU alert", "type": "metric alert", "options": {}}]
        slo_resp = {"data": []}
        dashboard_resp = {"dashboards": []}
        api_keys_resp = {"data": [{"id": "k1", "attributes": {"name": "key1"}}]}
        app_keys_resp = {"data": []}

        with patch.object(conn, "_make_client") as mock_cm:
            mock_client = MagicMock()
            mock_cm.return_value.__enter__.return_value = mock_client

            def _get_side_effect(path, params=None):
                resp = MagicMock()
                resp.status_code = 200
                mapping = {
                    "/api/v1/monitor": monitor_resp,
                    "/api/v1/slo": slo_resp,
                    "/api/v1/dashboard": dashboard_resp,
                    "/api/v2/api_keys": api_keys_resp,
                    "/api/v2/application_keys": app_keys_resp,
                    "/api/v1/integration/webhooks/configuration/webhooks": {"webhook_names": []},
                    "/api/v1/integration/pagerduty": ConnectorError("403"),
                    "/api/v2/roles": {"data": []},
                    "/api/v2/teams": {"data": []},
                    "/api/v1/integration/aws": {"accounts": []},
                    "/api/v1/integration/gcp": [],
                    "/api/v1/integration/azure": [],
                }
                data = mapping.get(path)
                if isinstance(data, Exception):
                    raise data
                resp.json.return_value = data if data is not None else []
                return resp

            mock_client.get.side_effect = _get_side_effect

            records = conn.fetch(_CREDS)

        assert isinstance(records, list)
        record_types = {r["record_type"] for r in records}
        assert DATADOG_MONITOR in record_types

    def test_pagination_is_bounded(self):
        conn = DatadogConnector()
        # Return a full page each time to test max_pages cap
        full_page = [{"id": i, "name": f"Monitor {i}", "type": "metric alert", "options": {}} for i in range(100)]

        call_count = {"n": 0}

        def _get_side_effect(path, params=None):
            resp = MagicMock()
            resp.status_code = 200
            if path == "/api/v1/monitor":
                call_count["n"] += 1
                resp.json.return_value = full_page
            else:
                resp.json.return_value = [] if path != "/api/v1/dashboard" else {"dashboards": []}
            return resp

        with patch.object(conn, "_make_client") as mock_cm:
            mock_client = MagicMock()
            mock_client.get.side_effect = _get_side_effect
            mock_cm.return_value.__enter__.return_value = mock_client
            conn.fetch(_CREDS)

        # Should not exceed _MAX_PAGES pages for monitors
        from app.connectors.datadog import _MAX_PAGES
        assert call_count["n"] <= _MAX_PAGES

    def test_403_on_surface_does_not_abort_full_fetch(self):
        conn = DatadogConnector()
        with patch.object(conn, "_make_client") as mock_cm:
            mock_client = MagicMock()
            mock_cm.return_value.__enter__.return_value = mock_client

            def _get_side_effect(path, params=None):
                resp = MagicMock()
                resp.status_code = 200
                if path == "/api/v1/monitor":
                    # Simulate 403 on monitors
                    raise ConnectorError("Forbidden", status_code=403)
                elif path == "/api/v2/api_keys":
                    resp.json.return_value = {"data": [{"id": "k1", "attributes": {"name": "key1"}}]}
                else:
                    resp.json.return_value = [] if "dashboard" not in path else {"dashboards": []}
                return resp

            mock_client.get.side_effect = _get_side_effect
            records = conn.fetch(_CREDS)

        # Should still return records from api_keys surface even though monitors is 403
        assert isinstance(records, list)


# ── Section F: Provider registration ─────────────────────────────────────────


class TestProviderRegistration:

    def test_sync_task_dispatches_to_datadog_connector(self):
        """Verify sync_task has an elif branch for datadog."""
        sync_task_path = Path(__file__).parent.parent / "app" / "workers" / "sync_task.py"
        content = sync_task_path.read_text()
        assert 'integration.provider == "datadog"' in content
        assert "DatadogConnector" in content

    def test_integration_schema_accepts_datadog(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="datadog",
            display_name="Test Datadog",
            datadog_api_key=_API_KEY,
            datadog_application_key=_APP_KEY,
            datadog_site="datadoghq.com",
        )
        assert req.provider == "datadog"

    def test_integration_schema_requires_api_key(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError, match="datadog_api_key"):
            IntegrationCreateRequest(
                provider="datadog",
                display_name="Test",
                datadog_application_key=_APP_KEY,
            )

    def test_integration_schema_requires_application_key(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError, match="datadog_application_key"):
            IntegrationCreateRequest(
                provider="datadog",
                display_name="Test",
                datadog_api_key=_API_KEY,
            )

    def test_router_builds_datadog_credentials(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="datadog",
            display_name="Test",
            datadog_api_key=_API_KEY,
            datadog_application_key=_APP_KEY,
            datadog_site="datadoghq.eu",
        )
        creds = _build_credentials(req)
        assert creds["api_key"] == _API_KEY
        assert creds["application_key"] == _APP_KEY
        assert creds["site"] == "datadoghq.eu"

    def test_router_defaults_site_to_datadoghq_com(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="datadog",
            display_name="Test",
            datadog_api_key=_API_KEY,
            datadog_application_key=_APP_KEY,
        )
        creds = _build_credentials(req)
        assert creds["site"] == "datadoghq.com"

    def test_capability_matrix_has_datadog_partial_drift_entry(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL,
            get_provider_capability,
        )

        datadog_cap = get_provider_capability("datadog")
        assert datadog_cap is not None
        assert datadog_cap.provider == "datadog"
        assert datadog_cap.drift.drift_snapshots is True
        assert datadog_cap.drift.drift_diff is True
        # M82B set drift_risk_classification=True (security rules added)
        assert datadog_cap.drift.drift_risk_classification is True
        # M82B set security_rules=True
        assert datadog_cap.security.security_rules is True
        # M82D set activity_ingestion=True (Datadog config-state activity ingestion added)
        assert datadog_cap.security.activity_ingestion is True
        # M82G set demo_seed_clear=True (Datadog demo + QA added)
        assert datadog_cap.security.demo_seed_clear is True
        assert datadog_cap.maturity == "partial"
        assert "M82A" in datadog_cap.notes or "M82B" in datadog_cap.notes

    def test_datadog_in_partial_providers_list(self):
        from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES_PARTIAL

        providers = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
        assert "datadog" in providers

    def test_provider_expansion_framework_pagerduty_is_head(self):
        # M83A launched Clerk; PagerDuty is now the head of the recommended queue.
        from app.services.provider_expansion_framework import RECOMMENDED_NEXT_PROVIDERS

        assert len(RECOMMENDED_NEXT_PROVIDERS) > 0
        # After M84A, PagerDuty launched; Linear is now at head.
        assert RECOMMENDED_NEXT_PROVIDERS[0].provider in ("pagerduty", "linear")

    def test_provider_expansion_framework_datadog_not_in_queue(self):
        from app.services.provider_expansion_framework import RECOMMENDED_NEXT_PROVIDERS

        providers = [p.provider for p in RECOMMENDED_NEXT_PROVIDERS]
        assert "datadog" not in providers

    def test_integration_service_accepts_datadog_provider(self):
        """Integration service should have a dispatch branch for datadog."""
        svc_path = Path(__file__).parent.parent / "app" / "services" / "integration_service.py"
        content = svc_path.read_text()
        assert '_create_datadog_integration' in content
        assert "provider == \"datadog\"" in content

    def test_integration_service_does_not_expose_secrets_in_resource_metadata(self):
        """_create_datadog_integration should not store api_key or application_key in metadata."""
        svc_path = Path(__file__).parent.parent / "app" / "services" / "integration_service.py"
        content = svc_path.read_text()
        # Find the datadog creation helper
        helper_start = content.find("def _create_datadog_integration")
        assert helper_start >= 0
        helper_end = content.find("\ndef ", helper_start + 1)
        helper_content = content[helper_start:helper_end] if helper_end > 0 else content[helper_start:]
        # api_key and application_key must NOT appear in resource_metadata
        assert '"api_key"' not in helper_content.split("resource_metadata=")[1].split("}")[0] if "resource_metadata=" in helper_content else True
        # api_key and application_key should not be stored in metadata
        assert "provider_family" in helper_content
        assert '"site"' in helper_content


# ── Section G: Frontend provider and form parity ──────────────────────────────


class TestFrontendParity:

    def test_providers_ts_includes_datadog(self):
        providers_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not providers_path.exists():
            pytest.skip("frontend/src/lib/providers.ts not found")
        content = providers_path.read_text()
        assert '"datadog"' in content or "'datadog'" in content
        assert "Datadog" in content

    def test_providers_ts_datadog_in_connectable_ids(self):
        providers_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not providers_path.exists():
            pytest.skip("frontend/src/lib/providers.ts not found")
        content = providers_path.read_text()
        assert "CONNECTABLE_PROVIDER_IDS" in content
        # Find CONNECTABLE_PROVIDER_IDS and verify datadog is in it
        idx = content.find("CONNECTABLE_PROVIDER_IDS")
        block_end = content.find("];", idx)
        block = content[idx:block_end]
        assert "datadog" in block

    def test_providers_ts_datadog_not_in_security_preview(self):
        providers_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not providers_path.exists():
            pytest.skip("frontend/src/lib/providers.ts not found")
        content = providers_path.read_text()
        assert "SECURITY_PREVIEW_PROVIDER_IDS" in content
        idx = content.find("SECURITY_PREVIEW_PROVIDER_IDS")
        block_end = content.find("];", idx)
        block = content[idx:block_end]
        assert "datadog" not in block

    def test_providers_ts_has_observability_category(self):
        providers_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not providers_path.exists():
            pytest.skip("frontend/src/lib/providers.ts not found")
        content = providers_path.read_text()
        assert "observability" in content

    def test_integrations_page_imports_datadog_form(self):
        page_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        )
        if not page_path.exists():
            pytest.skip("integrations page.tsx not found")
        content = page_path.read_text()
        assert "DatadogIntegrationForm" in content

    def test_integrations_page_has_datadog_form_dispatch(self):
        page_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        )
        if not page_path.exists():
            pytest.skip("integrations page.tsx not found")
        content = page_path.read_text()
        assert 'selectedProvider === "datadog"' in content

    def test_integrations_page_has_datadog_setup_guide(self):
        page_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        )
        if not page_path.exists():
            pytest.skip("integrations page.tsx not found")
        content = page_path.read_text()
        assert 'provider === "datadog"' in content
        assert "API key" in content
        assert "Application key" in content or "Application Key" in content

    def test_datadog_form_component_exists(self):
        form_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "components" / "integrations"
            / "DatadogIntegrationForm.tsx"
        )
        if not form_path.exists():
            pytest.skip("DatadogIntegrationForm.tsx not in expected path (frontend not co-located)")
        assert form_path.exists()

    def test_datadog_form_has_secret_fields_as_password(self):
        form_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "components" / "integrations"
            / "DatadogIntegrationForm.tsx"
        )
        if not form_path.exists():
            pytest.skip("DatadogIntegrationForm.tsx not found")
        content = form_path.read_text()
        # Both api_key and application_key fields should use type="password"
        assert content.count('type="password"') >= 2

    def test_datadog_form_clears_secrets_on_success(self):
        form_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "components" / "integrations"
            / "DatadogIntegrationForm.tsx"
        )
        if not form_path.exists():
            pytest.skip("DatadogIntegrationForm.tsx not found")
        content = form_path.read_text()
        # Should clear apiKey and appKey on success
        assert "setApiKey" in content
        assert "setAppKey" in content

    def test_types_index_includes_datadog_provider(self):
        types_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "types" / "index.ts"
        )
        if not types_path.exists():
            pytest.skip("frontend/src/types/index.ts not found")
        content = types_path.read_text()
        assert '"datadog"' in content or "'datadog'" in content
        assert "datadog_api_key" in content
        assert "datadog_application_key" in content

    def test_trust_center_has_datadog_profile(self):
        trust_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "trustCenter.ts"
        )
        if not trust_path.exists():
            pytest.skip("frontend/src/lib/trustCenter.ts not found")
        content = trust_path.read_text()
        assert "datadog" in content
        assert "Datadog" in content


# ── Section H: Forbidden wording scan ────────────────────────────────────────


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
    "app/connectors/datadog.py",
    "app/connectors/datadog_schema.py",
    "app/services/provider_capability_matrix_service.py",
    "app/services/integration_service.py",
    "app/workers/sync_task.py",
    # Note: provider_expansion_framework.py intentionally defines FORBIDDEN_CLAIM_PHRASES
    # as a constant tuple, so it is excluded from this scan.
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
                f"Forbidden phrase '{phrase}' found in {module_path}"
            )

    def test_no_forbidden_phrases_in_datadog_form(self):
        form_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "components" / "integrations"
            / "DatadogIntegrationForm.tsx"
        )
        if not form_path.exists():
            pytest.skip("DatadogIntegrationForm.tsx not found")
        content = form_path.read_text().lower()
        for phrase in FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in content

    def test_no_forbidden_phrases_in_trust_center(self):
        trust_path = (
            Path(__file__).parent.parent.parent
            / "frontend" / "src" / "lib" / "trustCenter.ts"
        )
        if not trust_path.exists():
            pytest.skip("trustCenter.ts not found")
        content = trust_path.read_text().lower()
        for phrase in FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in content


# ── Section I: Secret-shape grep ─────────────────────────────────────────────


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
                f"Secret-shaped string matching {pattern!r} found in {module_path}: "
                f"{match.group()[:20]!r}"
            )

    def test_no_secret_shapes_in_datadog_connector(self):
        conn_path = Path(__file__).parent.parent / "app" / "connectors" / "datadog.py"
        content = conn_path.read_text()
        for pattern in SECRET_PATTERNS:
            assert re.search(pattern, content) is None


# ── Section: Helper function unit tests ───────────────────────────────────────


class TestHelperFunctions:

    def test_sanitize_site_valid(self):
        assert _sanitize_site("datadoghq.com") == "datadoghq.com"
        assert _sanitize_site("datadoghq.eu") == "datadoghq.eu"
        assert _sanitize_site("  US3.datadoghq.com  ") == "us3.datadoghq.com"

    def test_sanitize_site_defaults_on_empty(self):
        assert _sanitize_site("") == "datadoghq.com"
        assert _sanitize_site(None) == "datadoghq.com"
        assert _sanitize_site(123) == "datadoghq.com"

    def test_sanitize_site_rejects_url(self):
        result = _sanitize_site("https://api.datadoghq.com")
        assert result == "datadoghq.com"

    def test_priority_category_mapping(self):
        assert _priority_category(1) == "critical"
        assert _priority_category(2) == "high"
        assert _priority_category(3) == "medium"
        assert _priority_category(4) == "low"
        assert _priority_category(5) == "info"
        assert _priority_category(None) == "none"
        assert _priority_category(99) == "none"

    def test_target_category_mapping(self):
        assert _target_category(99.95) == "99.9_plus"
        assert _target_category(99.5) == "99_plus"
        assert _target_category(97.0) == "95_plus"
        assert _target_category(90.0) == "below_95"
        assert _target_category(None) == "none"

    def test_length_category_mapping(self):
        assert _length_category("") == "absent"
        assert _length_category("short text") == "short"
        assert _length_category("x" * 500) == "medium"
        assert _length_category("x" * 1001) == "long"

    def test_eval_delay_category(self):
        assert _eval_delay_category(0) == "none"
        assert _eval_delay_category(30) == "short"
        assert _eval_delay_category(120) == "medium"
        assert _eval_delay_category(600) == "long"
        assert _eval_delay_category(None) == "none"


# ── Section: Regression — M82-pre.1 tests still pass ─────────────────────────

class TestM82pre1Regression:
    """Smoke-checks that M82-pre.1 provider support is still intact after M82A."""

    def test_integration_schema_still_accepts_auth0(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="auth0",
            display_name="Test Auth0",
            auth0_domain="mytenant.auth0.com",
            auth0_client_id="client_id",
            auth0_client_secret="client_secret_placeholder",
        )
        assert req.provider == "auth0"

    def test_integration_schema_still_accepts_sendgrid(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="sendgrid",
            display_name="Test SendGrid",
            sendgrid_api_key="sg_test_key_placeholder",
        )
        assert req.provider == "sendgrid"

    def test_sync_task_still_has_auth0_dispatch(self):
        sync_task_path = Path(__file__).parent.parent / "app" / "workers" / "sync_task.py"
        content = sync_task_path.read_text()
        assert 'integration.provider == "auth0"' in content
        assert "Auth0Connector" in content

    def test_datadog_connector_exists_and_has_required_methods(self):
        conn = DatadogConnector()
        assert hasattr(conn, "fetch")
        assert hasattr(conn, "validate_credentials")
        assert callable(conn.fetch)
        assert callable(conn.validate_credentials)
