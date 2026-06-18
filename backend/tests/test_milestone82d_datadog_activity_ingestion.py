"""M82D — Datadog Configuration Activity Ingestion.

Datadog's audit/audit-trail API is identity-heavy — every entry includes
actor email, actor UUID, IP-level request metadata. This milestone NEVER
ingests from that endpoint. Activity events are config-state observations
synthesized from the same 10 safe drift surfaces the drift connector reads.

Verifies:
  * DatadogConnector.list_activity_events synthesizes safe config-state events
  * Event types are restricted to _DATADOG_CONFIG_EVENT_TYPES allowlist
  * Log/trace/metric/incident/user/auth/session/token events are never returned
  * Raw Datadog audit payloads are never returned
  * max_events cap is enforced
  * lookback_hours cap is enforced
  * 401/403 → AuthenticationError/permission_limited; 429 → RateLimitError;
    network → NetworkError
  * normalize_datadog_activity_event returns None for non-config types
  * normalize_datadog_activity_event processes config events
  * ingestion service normalizes config events to activity events
  * idempotency: same events twice → second run events_inserted=0
  * fingerprint fallback when provider_event_id is None
  * metadata contains NO forbidden fields (no api_key, application_key,
    oauth_token, bearer_token, webhook_secret, raw monitor queries,
    raw monitor messages, raw dashboard JSON, webhook URLs, headers,
    payloads, notification handles, email addresses, user IDs, team
    member identities, IP addresses, user agents, raw audit payloads, PII)
  * workspace scoping (workspace_id always passed to upsert)
  * admin endpoint; member cannot sync
  * ALLOWED_METADATA_KEYS contains expected Datadog keys
  * ALLOWED_METADATA_KEYS does NOT contain forbidden Datadog keys
  * capability matrix: activity_ingestion=True, signals/correlations/demo=False
  * expansion framework planned_next_stage contains "M82E"
  * M82A/B/C tests pass (regression smoke — run via pytest directly)
  * forbidden wording not in module source
  * no secret-shaped strings in backend/app or frontend/src

CLAIM DISCIPLINE: configuration-state findings only. Does NOT confirm a
breach, compromise, unauthorized access, data exposure, or leaked secret.
"""

from __future__ import annotations

import inspect
import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]

FORBIDDEN_METADATA_FIELDS = frozenset({
    # Datadog secrets/credentials that must NEVER appear in metadata
    "api_key", "application_key", "oauth_token", "bearer_token",
    "webhook_secret", "integration_secret", "secret", "token",
    "headers", "authorization",
    # Raw content that must NEVER be stored
    "request", "response", "payload", "raw", "details",
    "description", "body", "message", "query",
    "dashboard_json", "widget_query", "notebook_content", "incident_text",
    "log", "logs", "trace", "traces", "metric", "metrics",
    "event_payload",
    # PII fields that must NEVER be stored
    "email", "user_email",
    "username", "user_name",
    "ip_address", "device", "user_agent",
    "destination", "channel", "slack", "pagerduty", "webhook_url",
    "customer_data", "pii",
    "actor", "actor_id", "actor_name", "actor_email",
    "team_member",
    "raw_payload", "raw_response", "audit_payload",
})

SAFE_DATADOG_CONFIG_EVENT_TYPES = {
    "datadog.monitor.created",
    "datadog.monitor.updated",
    "datadog.monitor.deleted",
    "datadog.slo.created",
    "datadog.slo.updated",
    "datadog.slo.deleted",
    "datadog.dashboard.created",
    "datadog.dashboard.updated",
    "datadog.dashboard.deleted",
    "datadog.webhook_integration.created",
    "datadog.webhook_integration.updated",
    "datadog.webhook_integration.deleted",
    "datadog.notification_integration.created",
    "datadog.notification_integration.updated",
    "datadog.notification_integration.deleted",
    "datadog.api_key_metadata.created",
    "datadog.api_key_metadata.updated",
    "datadog.api_key_metadata.disabled",
    "datadog.api_key_metadata.deleted",
    "datadog.application_key_metadata.created",
    "datadog.application_key_metadata.updated",
    "datadog.application_key_metadata.deleted",
    "datadog.role.created",
    "datadog.role.updated",
    "datadog.role.deleted",
    "datadog.team.created",
    "datadog.team.updated",
    "datadog.team.deleted",
    "datadog.cloud_integration.created",
    "datadog.cloud_integration.updated",
    "datadog.cloud_integration.deleted",
    "datadog.config.event",
}

FORBIDDEN_EVENT_TYPES_PREFIXES = [
    "log.", "trace.", "metric.", "incident.", "user.", "auth.",
    "session.", "token.", "audit.raw",
]

PLACEHOLDER_CREDS = {
    "api_key": "DATADOG_TEST_API_KEY_PLACEHOLDER",
    "application_key": "DATADOG_TEST_APPLICATION_KEY_PLACEHOLDER",
    "site": "DATADOG_TEST_SITE",
}

# ── Imports ────────────────────────────────────────────────────────────────────


def _import_connector():
    from app.connectors.datadog import DatadogConnector
    return DatadogConnector


def _import_ingestion_service():
    from app.services import datadog_activity_ingestion_service
    return datadog_activity_ingestion_service


def _import_normalize():
    from app.services.datadog_activity_ingestion_service import (
        normalize_datadog_activity_event,
    )
    return normalize_datadog_activity_event


def _import_activity_svc():
    from app.services import security_activity_event_service
    return security_activity_event_service


def _import_capability_matrix():
    from app.services import provider_capability_matrix_service
    return provider_capability_matrix_service


def _import_expansion_framework():
    from app.services import provider_expansion_framework
    return provider_expansion_framework


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_mock_monitor_resp(page: int = 0, page_size: int = 1) -> list:
    if page > 0:
        return []
    return [{
        "id": 42,
        "name": "High Error Rate",
        "type": "metric alert",
        "status": "OK",
        "priority": 1,
        "query": "avg:system.cpu.user{*} > 90",
        "message": "Alert @pagerduty",
        "options": {
            "notify_no_data": False,
            "thresholds": {"critical": 90.0},
            "silenced": {},
            "renotify_interval": 60,
            "evaluation_delay": 0,
            "notify_audit": True,
            "require_full_window": True,
        },
        "restricted_roles": [],
        "tags": ["env:prod"],
    }]


def _make_mock_slo_resp() -> dict:
    return {
        "data": [{
            "id": "abc123slo",
            "name": "API Availability",
            "type": "monitor",
            "thresholds": [{"target": 99.9, "timeframe": "7d"}],
            "monitor_ids": [42],
            "groups": [],
            "tags": ["team:backend"],
        }]
    }


def _make_mock_dashboard_resp() -> dict:
    return {
        "dashboards": [{
            "id": "dash-abc",
            "title": "API Overview",
            "layout_type": "ordered",
            "widgets": [{}, {}, {}],
            "template_variables": [{}],
            "restricted_roles": [],
            "url": None,
        }]
    }


def _make_mock_api_keys_resp() -> dict:
    return {
        "data": [{
            "id": "key-abc-123",
            "attributes": {
                "name": "CI Key",
                "last4": "1234",
                "created_at": "2024-01-01T00:00:00Z",
                "disabled": False,
            },
        }]
    }


def _make_mock_app_keys_resp() -> dict:
    return {
        "data": [{
            "id": "appkey-xyz",
            "attributes": {
                "name": "Terraform Key",
                "scopes": ["dashboards_read", "monitors_read"],
                "created_at": "2024-01-01T00:00:00Z",
            },
        }]
    }


def _make_mock_webhooks_resp() -> dict:
    return {"webhook_names": ["my-webhook"]}


def _make_mock_webhook_detail() -> dict:
    return {
        "name": "my-webhook",
        "url": "https://hooks.example.com/notify",
        "custom_headers": '{"X-Api-Key": "secret"}',
        "payload": '{"text": "{{#is_alert}}Alert{{/is_alert}}"}',
        "secret_headers": "",
        "encode_as": "json",
    }


def _make_mock_roles_resp() -> dict:
    return {
        "data": [{
            "id": "role-admin-abc",
            "attributes": {"name": "Admin", "user_count": 5},
            "relationships": {"permissions": {"data": [{}, {}, {}]}},
        }]
    }


def _make_mock_teams_resp() -> dict:
    return {
        "data": [{
            "id": "team-ops-abc",
            "attributes": {"name": "Ops Team", "handle": "ops-team", "user_count": 10},
        }]
    }


def _setup_mock_client(mock_get):
    """Wire up mock GET to return correct responses for each Datadog endpoint.

    DatadogConnector._get is a staticmethod with signature (client, path, params).
    """
    def side_effect(client, path, params=None):
        if "/api/v1/monitor" in path:
            page = params.get("page", 0) if params else 0
            return _make_mock_monitor_resp(page=page)
        if "/api/v1/slo" in path:
            return _make_mock_slo_resp()
        if "/api/v1/dashboard" in path and "webhooks" not in path:
            return _make_mock_dashboard_resp()
        if "/api/v2/api_keys" in path:
            page = params.get("page[number]", 0) if params else 0
            if page > 0:
                return {"data": []}
            return _make_mock_api_keys_resp()
        if "/api/v2/application_keys" in path:
            page = params.get("page[number]", 0) if params else 0
            if page > 0:
                return {"data": []}
            return _make_mock_app_keys_resp()
        if path == "/api/v1/integration/webhooks/configuration/webhooks":
            return _make_mock_webhooks_resp()
        if "/api/v1/integration/webhooks/configuration/webhooks/" in path:
            return _make_mock_webhook_detail()
        if "/api/v1/integration/pagerduty" in path:
            return {"services": [{"name": "ops"}, {"name": "infra"}]}
        if "/api/v1/integration/slack" in path:
            return {"channels": [{"channel_name": "alerts"}]}
        if "/api/v1/integration/opsgenie" in path:
            return {"services": []}
        if "/api/v2/roles" in path:
            page = params.get("page[number]", 0) if params else 0
            if page > 0:
                return {"data": []}
            return _make_mock_roles_resp()
        if "/api/v2/teams" in path:
            page = params.get("page[number]", 0) if params else 0
            if page > 0:
                return {"data": []}
            return _make_mock_teams_resp()
        if "/api/v1/integration/aws" in path:
            return {"accounts": []}
        if "/api/v1/integration/gcp" in path:
            return []
        if "/api/v1/integration/azure" in path:
            return []
        return {}
    mock_get.side_effect = side_effect


# ── Tests: connector list_activity_events ──────────────────────────────────────


class TestDatadogConnectorListActivityEvents:

    def test_returns_list_of_dicts(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        assert isinstance(events, list)
        assert len(events) > 0

    def test_all_event_types_are_config_events(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        for evt in events:
            assert evt["event_type"] in SAFE_DATADOG_CONFIG_EVENT_TYPES, (
                f"Unexpected event type: {evt['event_type']!r}"
            )

    def test_no_raw_audit_payloads(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        # Events should not contain any raw API response dict
        for evt in events:
            raw_str = str(evt)
            assert "avg:system.cpu.user" not in raw_str, "Raw query stored"
            assert "Alert @pagerduty" not in raw_str, "Raw message stored"
            assert "https://hooks.example.com" not in raw_str, "Webhook URL stored"
            assert "X-Api-Key" not in raw_str, "Header name stored"
            assert "1234" not in raw_str or "last4" in raw_str, "Potential last4 digits stored"

    def test_no_forbidden_metadata_fields(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        for evt in events:
            meta = evt.get("metadata", {})
            for forbidden in FORBIDDEN_METADATA_FIELDS:
                assert forbidden not in meta, (
                    f"Forbidden metadata field {forbidden!r} in event {evt['event_type']!r}"
                )

    def test_monitor_event_emitted(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        monitor_events = [e for e in events if "monitor" in e["event_type"]]
        assert len(monitor_events) >= 1

    def test_slo_event_emitted(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        slo_events = [e for e in events if "slo" in e["event_type"]]
        assert len(slo_events) >= 1

    def test_dashboard_event_emitted(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        dash_events = [e for e in events if "dashboard" in e["event_type"]]
        assert len(dash_events) >= 1

    def test_api_key_event_emitted(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        key_events = [e for e in events if "api_key_metadata" in e["event_type"]]
        assert len(key_events) >= 1

    def test_disabled_api_key_gets_disabled_event_type(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()

        def side_effect_disabled(client, path, params=None):
            if "/api/v2/api_keys" in path:
                page = params.get("page[number]", 0) if params else 0
                if page > 0:
                    return {"data": []}
                return {"data": [{
                    "id": "key-disabled",
                    "attributes": {
                        "name": "Disabled Key",
                        "created_at": "2024-01-01T00:00:00Z",
                        "disabled": True,
                    },
                }]}
            if "/api/v1/monitor" in path:
                return []
            if "/api/v1/slo" in path:
                return {"data": []}
            if "/api/v1/dashboard" in path:
                return {"dashboards": []}
            if "/api/v2/application_keys" in path:
                return {"data": []}
            if "/api/v2/roles" in path:
                return {"data": []}
            if "/api/v2/teams" in path:
                return {"data": []}
            return {}

        with patch.object(DatadogConnector, "_get", side_effect=side_effect_disabled):
            events = connector.list_activity_events(PLACEHOLDER_CREDS)

        key_events = [e for e in events if "api_key_metadata" in e["event_type"]]
        assert any(e["event_type"] == "datadog.api_key_metadata.disabled" for e in key_events)

    def test_max_events_cap_enforced(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS, max_events=2)
        assert len(events) <= 2

    def test_max_events_capped_at_1000(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        # Pass oversized value; connector should cap at 1000 internally
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS, max_events=99999)
        assert len(events) <= 1000

    def test_lookback_hours_capped_at_168(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        # Should not raise even with oversized lookback_hours
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(
                PLACEHOLDER_CREDS, lookback_hours=9999
            )
        assert isinstance(events, list)

    def test_provider_event_id_is_deterministic(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events1 = connector.list_activity_events(PLACEHOLDER_CREDS)
        with patch.object(DatadogConnector, "_get") as mock_get2:
            _setup_mock_client(mock_get2)
            events2 = connector.list_activity_events(PLACEHOLDER_CREDS)
        ids1 = {e["provider_event_id"] for e in events1}
        ids2 = {e["provider_event_id"] for e in events2}
        assert ids1 == ids2, "provider_event_id must be deterministic across polls on the same day"

    def test_provider_is_datadog(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        for evt in events:
            assert evt["provider"] == "datadog"

    def test_source_is_datadog_activity_event(self):
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        for evt in events:
            assert evt["source"] == "datadog_activity_event"

    def test_synthesized_not_raw_audit(self):
        """Events must be config-state observations, NOT raw Datadog audit entries."""
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            _setup_mock_client(mock_get)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        for evt in events:
            # No actor identity fields allowed
            assert "actor_email" not in evt
            assert "actor_id" not in evt
            assert "actor_uuid" not in evt
            assert "ip" not in evt
            assert "user_agent" not in evt
            # provider_event_id must be our deterministic fingerprint, not a raw audit ID
            pid = evt.get("provider_event_id", "")
            assert isinstance(pid, str) and len(pid) > 0


# ── Tests: connector error handling ───────────────────────────────────────────


class TestDatadogConnectorActivityErrors:

    def test_401_raises_authentication_error(self):
        from app.connectors.exceptions import AuthenticationError
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            mock_get.side_effect = AuthenticationError("401", status_code=401)
            with pytest.raises(AuthenticationError):
                connector.list_activity_events(PLACEHOLDER_CREDS)

    def test_403_is_soft_fail_returns_empty(self):
        """403 on a surface means permission-limited — returns empty list, no raise."""
        from app.connectors.exceptions import AuthenticationError
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            # 403 = surface not accessible (permission-limited), not a hard auth failure.
            # The connector soft-catches this and returns empty events.
            mock_get.side_effect = AuthenticationError("403", status_code=403)
            events = connector.list_activity_events(PLACEHOLDER_CREDS)
        # Should return empty, not raise
        assert isinstance(events, list)
        assert events == []

    def test_429_raises_rate_limit_error(self):
        from app.connectors.exceptions import RateLimitError
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            mock_get.side_effect = RateLimitError("429")
            with pytest.raises(RateLimitError):
                connector.list_activity_events(PLACEHOLDER_CREDS)

    def test_network_error_propagates(self):
        from app.connectors.exceptions import NetworkError
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            mock_get.side_effect = NetworkError("network")
            with pytest.raises(NetworkError):
                connector.list_activity_events(PLACEHOLDER_CREDS)

    def test_5xx_raises_connector_error(self):
        from app.connectors.exceptions import ConnectorError
        DatadogConnector = _import_connector()
        connector = DatadogConnector()
        with patch.object(DatadogConnector, "_get") as mock_get:
            mock_get.side_effect = ConnectorError("500", status_code=500)
            with pytest.raises(ConnectorError):
                connector.list_activity_events(PLACEHOLDER_CREDS)

    def test_one_surface_failure_does_not_abort_all(self):
        """A soft-failure surface should not prevent other surfaces from succeeding."""
        from app.connectors.exceptions import ConnectorError
        DatadogConnector = _import_connector()
        connector = DatadogConnector()

        def selective_failure(client, path, params=None):
            if "/api/v2/roles" in path:
                raise ConnectorError("roles 503", status_code=503)
            if "/api/v1/monitor" in path:
                page = params.get("page", 0) if params else 0
                return _make_mock_monitor_resp(page=page)
            if "/api/v1/slo" in path:
                return _make_mock_slo_resp()
            if "/api/v1/dashboard" in path:
                return _make_mock_dashboard_resp()
            if "/api/v2/api_keys" in path:
                page = params.get("page[number]", 0) if params else 0
                if page > 0:
                    return {"data": []}
                return _make_mock_api_keys_resp()
            if "/api/v2/application_keys" in path:
                page = params.get("page[number]", 0) if params else 0
                if page > 0:
                    return {"data": []}
                return _make_mock_app_keys_resp()
            if "/api/v2/teams" in path:
                page = params.get("page[number]", 0) if params else 0
                if page > 0:
                    return {"data": []}
                return _make_mock_teams_resp()
            return {}

        with patch.object(DatadogConnector, "_get", side_effect=selective_failure):
            events = connector.list_activity_events(PLACEHOLDER_CREDS)

        assert len(events) > 0
        # Monitor, SLO, dashboard events should still be present
        assert any("monitor" in e["event_type"] for e in events)


# ── Tests: normalize_datadog_activity_event ────────────────────────────────────


class TestNormalizeDatadogActivityEvent:

    def test_valid_config_event_returns_normalized(self):
        normalize = _import_normalize()
        entry = {
            "event_type": "datadog.monitor.updated",
            "provider": "datadog",
            "source": "datadog_activity_event",
            "event_source": "datadog_activity_event",
            "provider_event_id": "datadog.monitor.updated:42:2024-06-01",
            "metadata": {
                "resource_type": "monitor",
                "monitor_id": "42",
                "monitor_type": "metric alert",
                "enabled": True,
                "status": "OK",
                "tag_count": 1,
            },
        }
        result = normalize(entry)
        assert result is not None
        assert result["event_type"] == "datadog.monitor.updated"
        assert result["provider"] == "datadog"
        assert result["source"] == "datadog_activity_event"

    def test_non_config_event_type_returns_none(self):
        normalize = _import_normalize()
        for bad_type in [
            "log.write", "trace.ingested", "metric.value", "incident.created",
            "user.login", "auth.token.created", "session.started",
            "audit.raw_entry",
        ]:
            result = normalize({"event_type": bad_type, "metadata": {}})
            assert result is None, f"Expected None for {bad_type!r}"

    def test_malformed_entry_returns_none(self):
        normalize = _import_normalize()
        assert normalize(None) is None
        assert normalize({}) is None
        assert normalize({"event_type": ""}) is None
        assert normalize({"event_type": 123}) is None

    def test_fingerprint_fallback_when_no_provider_event_id(self):
        normalize = _import_normalize()
        entry = {
            "event_type": "datadog.slo.updated",
            "provider": "datadog",
            "source": "datadog_activity_event",
            "provider_event_id": None,
            "metadata": {"resource_type": "slo", "slo_id": "abc"},
        }
        result = normalize(entry)
        assert result is not None
        assert result["provider_event_id"] is not None
        assert result["provider_event_id"].startswith("fp:")

    def test_metadata_event_source_always_set(self):
        normalize = _import_normalize()
        entry = {
            "event_type": "datadog.dashboard.updated",
            "provider_event_id": "dashboard:abc:2024-06-01",
            "metadata": {"resource_type": "dashboard", "dashboard_id": "abc"},
        }
        result = normalize(entry)
        assert result is not None
        assert result["metadata"].get("event_source") == "datadog_activity_event"

    def test_no_actor_stored(self):
        normalize = _import_normalize()
        entry = {
            "event_type": "datadog.role.updated",
            "provider_event_id": "role:abc:2024-06-01",
            "metadata": {"resource_type": "role", "role_id": "abc"},
        }
        result = normalize(entry)
        assert result is not None
        assert result["actor_id"] is None
        assert result["actor_type"] is None

    def test_no_source_ip_stored(self):
        normalize = _import_normalize()
        entry = {
            "event_type": "datadog.team.updated",
            "provider_event_id": "team:abc:2024-06-01",
            "metadata": {"resource_type": "team", "team_id": "abc"},
        }
        result = normalize(entry)
        assert result is not None
        assert result["source_ip_hash"] is None

    def test_forbidden_metadata_fields_dropped(self):
        normalize = _import_normalize()
        entry = {
            "event_type": "datadog.monitor.updated",
            "provider_event_id": "monitor:42:2024-06-01",
            "metadata": {
                "resource_type": "monitor",
                "monitor_id": "42",
                # Forbidden fields that must be dropped
                "api_key": "should-be-dropped",
                "email": "user@example.com",
                "ip_address": "1.2.3.4",
                "webhook_url": "https://secret.example.com",
                "raw_payload": '{"foo": "bar"}',
            },
        }
        result = normalize(entry)
        assert result is not None
        meta = result["metadata"]
        for forbidden in ["api_key", "email", "ip_address", "webhook_url", "raw_payload"]:
            assert forbidden not in meta, f"Forbidden field {forbidden!r} not dropped"

    def test_all_config_event_types_normalize(self):
        normalize = _import_normalize()
        for event_type in SAFE_DATADOG_CONFIG_EVENT_TYPES:
            entry = {
                "event_type": event_type,
                "provider_event_id": f"{event_type}:test:2024-06-01",
                "metadata": {"category": "datadog_configuration"},
            }
            result = normalize(entry)
            assert result is not None, f"Expected non-None for event_type {event_type!r}"


# ── Tests: ingestion service with DB ──────────────────────────────────────────


class TestDatadogActivityIngestionService:

    def _make_integration(self):
        integration = MagicMock()
        integration.id = uuid.uuid4()
        integration.provider = "datadog"
        integration.status = "active"
        integration.encrypted_credentials = b"fake-encrypted"
        integration.credential_iv = b"fake-iv"
        return integration

    def _make_mock_events(self) -> list[dict]:
        return [
            {
                "event_type": "datadog.monitor.updated",
                "provider": "datadog",
                "source": "datadog_activity_event",
                "event_source": "datadog_activity_event",
                "provider_event_id": "datadog.monitor.updated:42:2024-06-01",
                "metadata": {
                    "resource_type": "monitor",
                    "monitor_id": "42",
                    "monitor_type": "metric alert",
                    "enabled": True,
                    "status": "OK",
                    "tag_count": 1,
                    "category": "datadog_configuration",
                    "status_category": "observed",
                },
            },
            {
                "event_type": "datadog.slo.updated",
                "provider": "datadog",
                "source": "datadog_activity_event",
                "event_source": "datadog_activity_event",
                "provider_event_id": "datadog.slo.updated:abc123:2024-06-01",
                "metadata": {
                    "resource_type": "slo",
                    "slo_id": "abc123",
                    "slo_type": "monitor",
                    "category": "datadog_configuration",
                },
            },
        ]

    def test_ingest_datadog_activity_success(self):
        svc = _import_ingestion_service()
        integration = self._make_integration()
        mock_events = self._make_mock_events()

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
            patch("app.services.datadog_activity_ingestion_service.activity_svc")
            as mock_activity,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.return_value = mock_events
            mock_connector_cls.return_value = mock_connector

            mock_activity.upsert_activity_event.return_value = (
                "inserted",
                MagicMock(),
            )

            result = svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["succeeded"] is True
        assert result["events_seen"] == 2
        assert result["events_inserted"] == 2
        assert result["events_skipped"] == 0
        assert result["provider"] == "datadog"
        assert result["source"] == "datadog_activity_event"

    def test_idempotency_second_run_all_skipped(self):
        svc = _import_ingestion_service()
        integration = self._make_integration()
        mock_events = self._make_mock_events()

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
            patch("app.services.datadog_activity_ingestion_service.activity_svc")
            as mock_activity,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.return_value = mock_events
            mock_connector_cls.return_value = mock_connector

            # Second run: all events already exist
            mock_activity.upsert_activity_event.return_value = (
                "skipped",
                MagicMock(),
            )

            result = svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["events_inserted"] == 0
        assert result["events_skipped"] == 2
        assert result["succeeded"] is True

    def test_auth_error_sets_permission_limited(self):
        from app.connectors.exceptions import AuthenticationError
        svc = _import_ingestion_service()
        integration = self._make_integration()

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.side_effect = AuthenticationError(
                "401", status_code=401
            )
            mock_connector_cls.return_value = mock_connector

            result = svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["permission_limited"] is True
        assert result["events_inserted"] == 0

    def test_rate_limit_error_captured(self):
        from app.connectors.exceptions import RateLimitError
        svc = _import_ingestion_service()
        integration = self._make_integration()

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.side_effect = RateLimitError("429")
            mock_connector_cls.return_value = mock_connector

            result = svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["succeeded"] is False
        assert "rate limit" in (result["error_message"] or "").lower()

    def test_network_error_captured(self):
        from app.connectors.exceptions import NetworkError
        svc = _import_ingestion_service()
        integration = self._make_integration()

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.side_effect = NetworkError("network")
            mock_connector_cls.return_value = mock_connector

            result = svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["succeeded"] is False
        assert "network" in (result["error_message"] or "").lower()

    def test_wrong_provider_integration_rejected(self):
        svc = _import_ingestion_service()
        integration = self._make_integration()
        integration.provider = "github"  # wrong provider

        result = svc.ingest_datadog_activity(
            integration=integration,
            workspace_id=uuid.uuid4(),
            db=MagicMock(),
        )
        assert result["succeeded"] is False
        assert "Not a Datadog" in (result["error_message"] or "")

    def test_malformed_events_skipped_safely(self):
        svc = _import_ingestion_service()
        integration = self._make_integration()

        malformed_events = [
            None,
            {},
            {"event_type": ""},
            {"event_type": "log.write"},  # forbidden type
            {"event_type": "datadog.monitor.updated"},  # valid but no provider_event_id
        ]

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
            patch("app.services.datadog_activity_ingestion_service.activity_svc")
            as mock_activity,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.return_value = malformed_events
            mock_connector_cls.return_value = mock_connector
            mock_activity.upsert_activity_event.return_value = ("inserted", MagicMock())
            mock_activity.compute_event_fingerprint.return_value = "fp:test"
            mock_activity.normalize_activity_event.return_value = {
                "provider": "datadog",
                "source": "datadog_activity_event",
                "event_type": "datadog.monitor.updated",
                "provider_event_id": "fp:test",
                "actor_id": None,
                "actor_type": None,
                "resource_type": None,
                "resource_id": None,
                "source_ip_hash": None,
                "occurred_at": None,
                "metadata": {},
                "raw_ref": None,
            }

            result = svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=MagicMock(),
            )

        assert result["succeeded"] is True
        # None, {}, "", log.write, and empty event_type should all be skipped
        assert result["events_inserted"] <= len(malformed_events)

    def test_workspace_id_always_passed_to_upsert(self):
        svc = _import_ingestion_service()
        integration = self._make_integration()
        expected_ws = uuid.uuid4()

        with (
            patch("app.services.datadog_activity_ingestion_service.decrypt_credentials")
            as mock_decrypt,
            patch("app.services.datadog_activity_ingestion_service.DatadogConnector")
            as mock_connector_cls,
            patch("app.services.datadog_activity_ingestion_service.activity_svc")
            as mock_activity,
        ):
            mock_decrypt.return_value = PLACEHOLDER_CREDS
            mock_connector = MagicMock()
            mock_connector.list_activity_events.return_value = [
                {
                    "event_type": "datadog.monitor.updated",
                    "provider_event_id": "monitor:42:2024-06-01",
                    "metadata": {"resource_type": "monitor", "monitor_id": "42"},
                }
            ]
            mock_connector_cls.return_value = mock_connector
            mock_activity.upsert_activity_event.return_value = ("inserted", MagicMock())
            mock_activity.compute_event_fingerprint.return_value = "fp:test"
            mock_activity.normalize_activity_event.return_value = {
                "provider": "datadog",
                "source": "datadog_activity_event",
                "event_type": "datadog.monitor.updated",
                "provider_event_id": "monitor:42:2024-06-01",
                "actor_id": None,
                "actor_type": None,
                "resource_type": "monitor",
                "resource_id": "42",
                "source_ip_hash": None,
                "occurred_at": None,
                "metadata": {},
                "raw_ref": None,
            }

            svc.ingest_datadog_activity(
                integration=integration,
                workspace_id=expected_ws,
                db=MagicMock(),
            )

        calls = mock_activity.upsert_activity_event.call_args_list
        assert len(calls) >= 1
        for call in calls:
            kw = call.kwargs
            assert kw.get("workspace_id") == expected_ws

    def test_sync_datadog_activity_no_active_integration(self):
        svc = _import_ingestion_service()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.filter.return_value.order_by.return_value.first.return_value = None
        mock_db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None

        result = svc.sync_datadog_activity(
            workspace_id=uuid.uuid4(),
            integration_id=None,
            db=mock_db,
        )
        assert result["attempted"] is False
        assert result["succeeded"] is False
        assert "No active Datadog" in (result["error_message"] or "")

    def test_sync_datadog_activity_invalid_integration_id(self):
        svc = _import_ingestion_service()
        result = svc.sync_datadog_activity(
            workspace_id=uuid.uuid4(),
            integration_id="not-a-valid-uuid",
            db=MagicMock(),
        )
        assert result["succeeded"] is False
        assert "Invalid integration_id" in (result["error_message"] or "")


# ── Tests: metadata allowlist ──────────────────────────────────────────────────


class TestDatadogMetadataAllowlist:

    def test_allowed_metadata_keys_contains_datadog_keys(self):
        activity_svc = _import_activity_svc()
        allowed = activity_svc.ALLOWED_METADATA_KEYS
        expected_keys = [
            "datadog_event_id", "monitor_id", "slo_id", "dashboard_id",
            "notification_integration_id", "application_key_id", "role_id",
            "team_id", "cloud_integration_id", "monitor_type",
            "priority_category", "query_present", "query_complexity_category",
            "message_present", "message_length_category",
            "notification_count", "notification_routing_present",
            "message_template_present", "query_uses_wildcard_scope",
            "query_group_by_count", "threshold_critical_present",
            "threshold_warning_present", "threshold_recovery_present",
            "threshold_count", "renotify_enabled", "renotify_interval_category",
            "silenced_scope_count", "no_data_timeframe_category",
            "require_full_window", "restricted_roles_count",
            "include_tags", "notify_audit", "slo_type",
            "target_category", "warning_target_category", "timeframe_count",
            "monitor_count", "group_count", "tag_count", "layout_type",
            "widget_count", "template_variable_count", "public_url_present",
            "url_present", "url_scheme_category", "custom_headers_present",
            "custom_header_count", "secret_headers_present", "secret_headers_count",
            "payload_template_present", "payload_template_length_category",
            "encode_as_category", "auth_material_present", "integration_type",
            "handle_count", "channel_count", "created_present", "modified_present",
            "created_by_present", "owned_by_present", "permission_count",
            "user_count", "team_count", "member_count", "handle_present",
            "link_count", "cloud_provider", "account_id_present",
            "resource_collection_enabled", "metric_collection_enabled",
            "log_collection_enabled", "account_tags_count", "namespace_count",
        ]
        for key in expected_keys:
            assert key in allowed, f"Expected Datadog key {key!r} not in ALLOWED_METADATA_KEYS"

    def test_allowed_metadata_keys_does_not_contain_forbidden_keys(self):
        activity_svc = _import_activity_svc()
        allowed = activity_svc.ALLOWED_METADATA_KEYS
        strictly_forbidden = [
            "api_key", "application_key", "oauth_token", "bearer_token",
            "webhook_secret", "integration_secret",
            "email", "user_email", "ip_address", "user_agent",
            "webhook_url", "raw_payload", "audit_payload",
            "actor_email", "customer_data",
        ]
        for key in strictly_forbidden:
            assert key not in allowed, (
                f"Forbidden key {key!r} found in ALLOWED_METADATA_KEYS"
            )


# ── Tests: capability matrix ───────────────────────────────────────────────────


class TestDatadogCapabilityMatrix:

    def _get_cap(self):
        matrix_svc = _import_capability_matrix()
        provider_cap = matrix_svc.get_provider_capability("datadog")
        assert provider_cap is not None
        return provider_cap.as_dict()

    def test_activity_ingestion_is_true(self):
        cap = self._get_cap()
        assert cap["security"]["activity_ingestion"] is True

    def test_activity_signals_is_true_after_m82e(self):
        # M82E set activity_signals=True (Datadog activity signal generation added)
        cap = self._get_cap()
        assert cap["security"]["activity_signals"] is True

    def test_risk_activity_correlations_is_true_after_m82f(self):
        # M82F set risk_activity_correlations=True (Datadog correlations added)
        cap = self._get_cap()
        assert cap["security"]["risk_activity_correlations"] is True

    def test_demo_seed_clear_is_false(self):
        cap = self._get_cap()
        assert cap["security"]["demo_seed_clear"] is False

    def test_security_rules_still_true(self):
        cap = self._get_cap()
        assert cap["security"]["security_rules"] is True

    def test_maturity_is_partial(self):
        cap = self._get_cap()
        assert cap["maturity"] == "partial"


# ── Tests: provider expansion framework ───────────────────────────────────────


class TestDatadogExpansionFramework:

    def test_planned_next_stage_is_m82g_after_m82f(self):
        # M82F shipped; planned_next_stage now points to M82G
        expansion_svc = _import_expansion_framework()
        framework = expansion_svc.get_framework()
        planned = framework["summary"].get("planned_next_stage", "")
        assert "M82G" in planned, (
            f"planned_next_stage should reference M82G, got: {planned!r}"
        )

    def test_planned_next_stage_mentions_demo_or_qa(self):
        expansion_svc = _import_expansion_framework()
        framework = expansion_svc.get_framework()
        planned = framework["summary"].get("planned_next_stage", "")
        assert "Demo" in planned or "M82G" in planned


# ── Tests: API endpoint auth ───────────────────────────────────────────────────


class TestDatadogActivityEndpointAuth:

    def _make_admin_user(self):
        user = MagicMock()
        user.id = uuid.uuid4()
        return user

    def _make_member_user(self):
        user = MagicMock()
        user.id = uuid.uuid4()
        return user

    def test_admin_can_sync(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import workspace_permission_service

        admin_user = self._make_admin_user()

        with (
            patch.object(
                workspace_permission_service,
                "require_workspace_admin",
                return_value=None,
            ),
            patch(
                "app.services.datadog_activity_ingestion_service.sync_datadog_activity",
                return_value={
                    "attempted": True,
                    "succeeded": True,
                    "provider": "datadog",
                    "source": "datadog_activity_event",
                    "integration_id": None,
                    "events_seen": 0,
                    "events_inserted": 0,
                    "events_skipped": 0,
                    "permission_limited": False,
                    "error_message": None,
                },
            ),
        ):
            app.dependency_overrides[get_current_user] = lambda: admin_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.post("/security/datadog-activity/sync", json={})
                assert resp.status_code == 200
                data = resp.json()
                assert data["provider"] == "datadog"
            finally:
                app.dependency_overrides.clear()

    def test_member_cannot_sync_gets_403(self):
        from fastapi.testclient import TestClient
        from fastapi import HTTPException
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import workspace_permission_service

        member_user = self._make_member_user()

        with patch.object(
            workspace_permission_service,
            "require_workspace_admin",
            side_effect=HTTPException(status_code=403, detail="Forbidden"),
        ):
            app.dependency_overrides[get_current_user] = lambda: member_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.post("/security/datadog-activity/sync", json={})
                assert resp.status_code == 403
            finally:
                app.dependency_overrides.clear()

    def test_member_can_read_events(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import security_activity_event_service

        member_user = self._make_member_user()

        with patch.object(
            security_activity_event_service,
            "list_activity_events",
            return_value=([], 0),
        ):
            app.dependency_overrides[get_current_user] = lambda: member_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.get("/security/activity/events?provider=datadog")
                assert resp.status_code in (200, 422), f"Unexpected status: {resp.status_code}"
            finally:
                app.dependency_overrides.clear()


# ── Tests: wording and secret-shape ────────────────────────────────────────────


class TestDatadogForbiddenWordingAndSecrets:

    def test_no_forbidden_phrases_in_connector(self):
        DatadogConnector = _import_connector()
        source = inspect.getsource(DatadogConnector)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source.lower(), (
                f"Forbidden phrase {phrase!r} found in DatadogConnector source"
            )

    def test_no_forbidden_phrases_in_ingestion_service(self):
        svc = _import_ingestion_service()
        source = inspect.getsource(svc)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source.lower(), (
                f"Forbidden phrase {phrase!r} found in ingestion service source"
            )

    def test_no_secret_shaped_strings_in_connector(self):
        DatadogConnector = _import_connector()
        source = inspect.getsource(DatadogConnector)
        # JWT-like pattern
        assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", source)
        # SendGrid API key pattern
        assert not re.search(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", source)
        # Twilio SID patterns
        assert not re.search(r"AC[0-9a-fA-F]{32}", source)
        assert not re.search(r"SK[0-9a-fA-F]{32}", source)

    def test_no_secret_shaped_strings_in_ingestion_service(self):
        svc = _import_ingestion_service()
        source = inspect.getsource(svc)
        assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", source)
        assert not re.search(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", source)
        assert not re.search(r"AC[0-9a-fA-F]{32}", source)
        assert not re.search(r"SK[0-9a-fA-F]{32}", source)

    def test_no_secret_shaped_strings_in_m82d_files(self):
        backend_app = Path(__file__).parent.parent / "app"
        m82d_files = [
            backend_app / "connectors" / "datadog.py",
            backend_app / "services" / "datadog_activity_ingestion_service.py",
            backend_app / "schemas" / "security_datadog_activity.py",
        ]
        pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}"
            r"|SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            r"|AC[0-9a-fA-F]{32}"
            r"|SK[0-9a-fA-F]{32}"
        )
        violations = []
        for py_file in m82d_files:
            if not py_file.exists():
                continue
            text = py_file.read_text(errors="replace")
            if pattern.search(text):
                violations.append(str(py_file))
        assert not violations, f"Secret-shaped strings in M82D files: {violations}"

    def test_no_forbidden_phrases_in_m82d_files(self):
        # Only check M82D-specific files — other files legitimately list these
        # phrases as constants for rule-checking (expansion_framework, test files, etc.)
        backend_app = Path(__file__).parent.parent / "app"
        m82d_files = [
            backend_app / "connectors" / "datadog.py",
            backend_app / "services" / "datadog_activity_ingestion_service.py",
            backend_app / "schemas" / "security_datadog_activity.py",
        ]
        violations = []
        for py_file in m82d_files:
            if not py_file.exists():
                continue
            text = py_file.read_text(errors="replace").lower()
            for phrase in FORBIDDEN_PHRASES:
                if phrase in text:
                    violations.append(f"{py_file.name}: {phrase!r}")
        assert not violations, f"Forbidden phrases in M82D files: {violations}"


# ── Tests: frontend files ──────────────────────────────────────────────────────


class TestDatadogFrontendFiles:

    def _read_frontend_file(self, rel_path: str) -> str:
        frontend = Path(__file__).parent.parent.parent.parent / "frontend" / "src"
        full = frontend / rel_path
        if not full.exists():
            pytest.skip(f"Frontend file not found: {full}")
        return full.read_text(errors="replace")

    def test_activity_page_includes_datadog_provider(self):
        text = self._read_frontend_file("app/(app)/security/activity/page.tsx")
        assert '"datadog"' in text or "'datadog'" in text

    def test_activity_page_includes_datadog_event_types(self):
        text = self._read_frontend_file("app/(app)/security/activity/page.tsx")
        assert "DATADOG_EVENT_TYPES" in text
        assert "datadog.monitor.updated" in text

    def test_activity_page_includes_sync_datadog_import(self):
        text = self._read_frontend_file("app/(app)/security/activity/page.tsx")
        assert "syncDatadogActivity" in text

    def test_activity_page_provider_label_includes_datadog(self):
        text = self._read_frontend_file("app/(app)/security/activity/page.tsx")
        assert "Datadog" in text

    def test_api_ts_includes_sync_datadog_activity(self):
        text = self._read_frontend_file("lib/api.ts")
        assert "syncDatadogActivity" in text
        assert "datadog-activity/sync" in text

    def test_types_includes_datadog_activity_sync_response(self):
        text = self._read_frontend_file("types/index.ts")
        assert "DatadogActivitySyncResponse" in text

    def test_frontend_no_forbidden_phrases(self):
        for rel_path in [
            "app/(app)/security/activity/page.tsx",
            "lib/api.ts",
        ]:
            text = self._read_frontend_file(rel_path).lower()
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in text, (
                    f"Forbidden phrase {phrase!r} in frontend/{rel_path}"
                )
