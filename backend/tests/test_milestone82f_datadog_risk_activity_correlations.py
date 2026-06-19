"""M82F — Datadog Risk × Activity Correlations.

Joins active Datadog configuration-risk findings (provider=datadog) with
Datadog activity signals (provider=datadog, from M82E) on the same resource
family within a review window.

Sections
--------
  A. Correlation rule mapping — all rule families map to expected types
  B. Correlation service — matching logic, idempotency, metadata
  C. Correlation metadata privacy — no forbidden fields
  D. API endpoint — admin-only, member cannot generate, route exists
  E. Frontend checks — provider + correlation types + generate function
  F. Capability matrix — risk_activity_correlations=True, demo=False
  G. Provider expansion framework — points to M82G
  H. Forbidden wording and secret-shape scan
  I. Regression smoke — M82A/B/C/D/E still intact
"""

from __future__ import annotations

import inspect
import re
import uuid
from datetime import datetime, timedelta, timezone
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

FORBIDDEN_CORRELATION_METADATA_FIELDS = frozenset({
    # Datadog secrets/credentials that must NEVER appear in correlation metadata
    "api_key", "application_key", "oauth_token", "bearer_token",
    "webhook_secret", "integration_secret", "secret", "token",
    "headers", "authorization",
    # Raw content that must NEVER be stored
    "request", "response", "payload", "raw", "details",
    "body", "message", "query",
    "dashboard_json", "widget_query", "notebook_content", "incident_text",
    "log", "logs", "trace", "traces", "metric", "metrics",
    "event_payload",
    # PII that must NEVER be stored
    "email", "user_email", "user_id", "user_name", "username",
    "ip_address", "device", "user_agent",
    "destination", "channel", "slack", "pagerduty",
    "webhook_url", "hostname",
    "actor", "actor_id", "actor_name", "actor_email",
    "team_member",
    "customer_data", "pii",
    "raw_payload", "raw_response", "audit_payload",
    "handle",  # handle_count/handle_present fine, but plain "handle" is not
})

EXPECTED_DATADOG_CORRELATION_TYPES = frozenset({
    "datadog_monitor_risk_activity_correlation",
    "datadog_slo_risk_activity_correlation",
    "datadog_dashboard_risk_activity_correlation",
    "datadog_webhook_risk_activity_correlation",
    "datadog_notification_integration_risk_activity_correlation",
    "datadog_api_key_risk_activity_correlation",
    "datadog_application_key_risk_activity_correlation",
    "datadog_role_risk_activity_correlation",
    "datadog_team_risk_activity_correlation",
    "datadog_cloud_integration_risk_activity_correlation",
})

# All 31 Datadog rule keys from M82B + M82C.
ALL_DATADOG_RULE_KEYS = {
    # M82B
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
    # M82C
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
    "datadog_webhook_non_https_endpoint",
    "datadog_webhook_custom_headers_without_secret_headers",
    "datadog_webhook_large_payload_template",
    "datadog_webhook_auth_material_present",
}

# Expected rule → correlation family mapping.
EXPECTED_RULE_TO_FAMILY = {
    "datadog_monitor_disabled": "datadog_monitor_risk_activity_correlation",
    "datadog_monitor_unrestricted_roles": "datadog_monitor_risk_activity_correlation",
    "datadog_monitor_no_notifications": "datadog_monitor_risk_activity_correlation",
    "datadog_monitor_query_wildcard_scope": "datadog_monitor_risk_activity_correlation",
    "datadog_slo_no_monitors": "datadog_slo_risk_activity_correlation",
    "datadog_slo_low_target": "datadog_slo_risk_activity_correlation",
    "datadog_dashboard_public_url_present": "datadog_dashboard_risk_activity_correlation",
    "datadog_dashboard_unrestricted_roles": "datadog_dashboard_risk_activity_correlation",
    "datadog_webhook_without_secret_headers": "datadog_webhook_risk_activity_correlation",
    "datadog_webhook_auth_material_present": "datadog_webhook_risk_activity_correlation",
    "datadog_notification_integration_no_channels": "datadog_notification_integration_risk_activity_correlation",
    "datadog_api_key_disabled": "datadog_api_key_risk_activity_correlation",
    "datadog_application_key_broad_scopes": "datadog_application_key_risk_activity_correlation",
    "datadog_role_high_permission_count": "datadog_role_risk_activity_correlation",
    "datadog_team_no_members": "datadog_team_risk_activity_correlation",
    "datadog_cloud_integration_broad_collection": "datadog_cloud_integration_risk_activity_correlation",
    "datadog_cloud_integration_log_collection_enabled": "datadog_cloud_integration_risk_activity_correlation",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_finding(
    rule_key: str,
    resource_id: str = "DATADOG_TEST_MONITOR_ID",
    evidence: dict | None = None,
    severity: str = "medium",
    integration_id: uuid.UUID | None = None,
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.provider = "datadog"
    f.finding_key = f"{rule_key}:{resource_id}"
    f.status = "active"
    f.severity = severity
    f.resource_id = resource_id
    f.resource_type = "monitor"
    f.integration_id = integration_id or uuid.uuid4()
    f.first_detected_at = _now() - timedelta(hours=2)
    f.last_seen_at = _now()
    f.evidence = evidence or {
        "record_id": resource_id,
        "record_type": "datadog_monitor",
        "resource_name": "Test Monitor",
        "monitor_type": "metric alert",
    }
    return f


def _make_signal(
    signal_type: str = "datadog_monitor_config_changed",
    resource_id: str = "DATADOG_TEST_MONITOR_ID",
    metadata: dict | None = None,
    integration_id: uuid.UUID | None = None,
) -> MagicMock:
    s = MagicMock()
    s.id = uuid.uuid4()
    s.provider = "datadog"
    s.signal_type = signal_type
    s.resource_id = resource_id
    s.resource_type = "monitor"
    s.integration_id = integration_id or uuid.uuid4()
    s.linked_activity_event_id = uuid.uuid4()
    s.first_seen_at = _now() - timedelta(hours=1)
    s.last_seen_at = _now()
    s.signal_metadata = metadata or {
        "resource_type": "monitor",
        "monitor_id": resource_id,
        "resource_id": resource_id,
        "resource_name": "Test Monitor",
        "event_types": "datadog.monitor.updated",
        "event_count": 1,
    }
    return s


# ── Section A: Correlation rule mapping ───────────────────────────────────────


class TestDatadogCorrelationRuleMapping:

    def test_all_expected_correlation_types_exist(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        assert set(DATADOG_CORRELATION_RULES.keys()) == EXPECTED_DATADOG_CORRELATION_TYPES

    def test_correlation_types_frozenset(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_TYPES,
        )
        assert DATADOG_CORRELATION_TYPES == EXPECTED_DATADOG_CORRELATION_TYPES

    def test_monitor_rules_covered(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        monitor_rule = DATADOG_CORRELATION_RULES["datadog_monitor_risk_activity_correlation"]
        assert "datadog_monitor_disabled" in monitor_rule["rule_keys"]
        assert "datadog_monitor_no_notifications" in monitor_rule["rule_keys"]
        assert "datadog_monitor_query_wildcard_scope" in monitor_rule["rule_keys"]

    def test_webhook_rules_covered(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        webhook_rule = DATADOG_CORRELATION_RULES["datadog_webhook_risk_activity_correlation"]
        assert "datadog_webhook_without_secret_headers" in webhook_rule["rule_keys"]
        assert "datadog_webhook_auth_material_present" in webhook_rule["rule_keys"]

    def test_cloud_integration_rules_covered(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        cloud_rule = DATADOG_CORRELATION_RULES["datadog_cloud_integration_risk_activity_correlation"]
        assert "datadog_cloud_integration_broad_collection" in cloud_rule["rule_keys"]
        assert "datadog_cloud_integration_log_collection_enabled" in cloud_rule["rule_keys"]

    def test_each_rule_has_required_fields(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        for corr_type, rule in DATADOG_CORRELATION_RULES.items():
            assert "rule_keys" in rule, f"{corr_type}: missing rule_keys"
            assert "signal_types" in rule, f"{corr_type}: missing signal_types"
            assert "id_key" in rule, f"{corr_type}: missing id_key"
            assert "signal_id_key" in rule, f"{corr_type}: missing signal_id_key"
            assert "severity" in rule, f"{corr_type}: missing severity"
            assert "title_phrase" in rule, f"{corr_type}: missing title_phrase"

    def test_webhook_correlation_severity_is_high(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        assert (
            DATADOG_CORRELATION_RULES["datadog_webhook_risk_activity_correlation"]["severity"]
            == "high"
        )

    def test_role_correlation_severity_is_high(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        assert (
            DATADOG_CORRELATION_RULES["datadog_role_risk_activity_correlation"]["severity"]
            == "high"
        )

    def test_team_correlation_severity_is_low(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        assert (
            DATADOG_CORRELATION_RULES["datadog_team_risk_activity_correlation"]["severity"]
            == "low"
        )


# ── Section B: Correlation service ────────────────────────────────────────────


class TestDatadogCorrelationService:

    def _import_svc(self):
        from app.services import datadog_risk_activity_correlation_service
        return datadog_risk_activity_correlation_service

    def _import_match_pair(self):
        from app.services.datadog_risk_activity_correlation_service import _match_pair
        return _match_pair

    def _import_build_correlation(self):
        from app.services.datadog_risk_activity_correlation_service import _build_correlation
        return _build_correlation

    def _import_in_window(self):
        from app.services.datadog_risk_activity_correlation_service import _in_window
        return _in_window

    def _get_rule(self, corr_type: str) -> dict:
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_RULES,
        )
        return DATADOG_CORRELATION_RULES[corr_type]

    # ── Match pair tests ────────────────────────────────────────────────────

    def test_exact_id_match_returns_match_reason(self):
        match_pair = self._import_match_pair()
        iid = uuid.uuid4()
        finding = _make_finding(
            "datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID",
            integration_id=iid,
        )
        signal = _make_signal(
            "datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID",
            integration_id=iid,
        )
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is not None
        match_reason, confidence = result
        assert "id_match" in match_reason or "monitor_id" in match_reason

    def test_exact_id_same_integration_gives_high_confidence(self):
        match_pair = self._import_match_pair()
        iid = uuid.uuid4()
        finding = _make_finding(
            "datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID",
            integration_id=iid,
        )
        signal = _make_signal(
            "datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID",
            integration_id=iid,
        )
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is not None
        _, confidence = result
        assert confidence == "high"

    def test_exact_id_different_integration_gives_medium_confidence(self):
        match_pair = self._import_match_pair()
        finding = _make_finding(
            "datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID",
            integration_id=uuid.uuid4(),
        )
        signal = _make_signal(
            "datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID",
            integration_id=uuid.uuid4(),
        )
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is not None
        _, confidence = result
        assert confidence == "medium"

    def test_different_resource_ids_no_match(self):
        match_pair = self._import_match_pair()
        finding = _make_finding("datadog_monitor_disabled", "monitor_A")
        signal = _make_signal("datadog_monitor_config_changed", "monitor_B",
                              metadata={"monitor_id": "monitor_B", "resource_id": "monitor_B"})
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is None

    def test_missing_signal_id_gives_family_aggregate(self):
        match_pair = self._import_match_pair()
        finding = _make_finding("datadog_monitor_disabled", "monitor_A")
        signal = _make_signal("datadog_monitor_config_changed", "monitor_A",
                              metadata={"resource_type": "monitor", "event_count": 1})
        # signal has no monitor_id in metadata
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is not None
        _, confidence = result
        assert confidence == "low"

    def test_slo_family_exact_match(self):
        match_pair = self._import_match_pair()
        finding = _make_finding("datadog_slo_no_monitors", "abc123slo",
                               evidence={"record_id": "abc123slo", "record_type": "datadog_slo"})
        signal = _make_signal("datadog_slo_config_changed", "abc123slo",
                              metadata={"slo_id": "abc123slo", "resource_id": "abc123slo"})
        rule = self._get_rule("datadog_slo_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is not None
        _, confidence = result
        assert confidence in ("high", "medium")

    def test_webhook_family_exact_match(self):
        match_pair = self._import_match_pair()
        finding = _make_finding("datadog_webhook_without_secret_headers", "my-webhook",
                               evidence={"record_id": "my-webhook", "record_type": "datadog_webhook_integration"})
        signal = _make_signal("datadog_webhook_integration_config_changed", "my-webhook",
                              metadata={"webhook_id": "my-webhook", "resource_id": "my-webhook"})
        rule = self._get_rule("datadog_webhook_risk_activity_correlation")
        result = match_pair(finding, signal, rule)
        assert result is not None

    # ── Build correlation tests ─────────────────────────────────────────────

    def test_build_correlation_produces_valid_dict(self):
        build = self._import_build_correlation()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = build(
            finding=finding,
            signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule,
            match_reason="monitor_id_id_match",
            confidence="medium",
        )
        assert result is not None
        assert result["provider"] == "datadog"
        assert result["correlation_type"] == "datadog_monitor_risk_activity_correlation"
        assert result["confidence"] == "medium"
        assert result["linked_finding_id"] == finding.id
        assert result["linked_activity_event_id"] == signal.linked_activity_event_id

    def test_correlation_key_deterministic(self):
        build = self._import_build_correlation()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        r1 = build(
            finding=finding, signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule, match_reason="monitor_id_id_match", confidence="medium",
        )
        r2 = build(
            finding=finding, signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule, match_reason="monitor_id_id_match", confidence="medium",
        )
        assert r1["correlation_key"] == r2["correlation_key"]

    def test_title_no_forbidden_wording(self):
        build = self._import_build_correlation()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = build(
            finding=finding, signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule, match_reason="monitor_id_id_match", confidence="medium",
        )
        title_lower = result["title"].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in title_lower

    def test_summary_no_forbidden_wording(self):
        build = self._import_build_correlation()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        rule = self._get_rule("datadog_monitor_risk_activity_correlation")
        result = build(
            finding=finding, signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule, match_reason="monitor_id_id_match", confidence="medium",
        )
        summary_lower = result["summary"].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in summary_lower

    # ── Time window tests ────────────────────────────────────────────────────

    def test_in_window_same_time_returns_true(self):
        in_window = self._import_in_window()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        signal.last_seen_at = _now()
        assert in_window(finding, signal) is True

    def test_out_of_window_returns_false(self):
        in_window = self._import_in_window()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        finding.first_detected_at = _now() - timedelta(days=10)
        finding.last_seen_at = _now() - timedelta(days=9)
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        signal.last_seen_at = _now()  # far outside the window
        assert in_window(finding, signal) is False

    # ── Generate correlations tests ─────────────────────────────────────────

    def test_generate_correlations_empty_db(self):
        svc = self._import_svc()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = svc.generate_datadog_correlations(
            workspace_id=uuid.uuid4(), db=mock_db
        )
        assert result["provider"] == "datadog"
        assert result["findings_scanned"] == 0
        assert result["signals_scanned"] == 0
        assert result["correlations_created"] == 0
        assert "candidate_pairs" in result

    def test_generate_correlations_scans_only_datadog(self):
        svc = self._import_svc()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        svc.generate_datadog_correlations(workspace_id=uuid.uuid4(), db=mock_db)
        # Should have queried SecurityFinding and SecurityIncidentSignal
        assert mock_db.query.called

    def test_generate_correlations_creates_on_match(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        mock_db = MagicMock()
        # First query = findings, second = signals
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.side_effect = [
            [finding], [signal]
        ]
        with patch(
            "app.services.datadog_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ):
            result = svc.generate_datadog_correlations(workspace_id=ws, db=mock_db)
        assert result["correlations_created"] >= 1

    def test_generate_correlations_idempotent(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.side_effect = [
            [finding], [signal]
        ]
        with patch(
            "app.services.datadog_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("skipped", MagicMock()),
        ):
            result = svc.generate_datadog_correlations(workspace_id=ws, db=mock_db)
        assert result["correlations_created"] == 0
        assert result["correlations_skipped"] >= 1

    def test_unrelated_resources_not_correlated(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        finding = _make_finding("datadog_monitor_disabled", "monitor_A",
                               evidence={"record_id": "monitor_A"})
        # Signal with different resource ID
        signal = _make_signal("datadog_monitor_config_changed", "monitor_B",
                              metadata={"monitor_id": "monitor_B", "resource_id": "monitor_B"})
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.side_effect = [
            [finding], [signal]
        ]
        with patch(
            "app.services.datadog_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            result = svc.generate_datadog_correlations(workspace_id=ws, db=mock_db)
        # Different IDs → no match for the specialized rule
        assert mock_upsert.call_count == 0

    def test_max_correlations_cap(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        findings = [
            _make_finding("datadog_monitor_disabled", f"monitor_{i}")
            for i in range(20)
        ]
        signals = [
            _make_signal("datadog_monitor_config_changed", f"monitor_{i}",
                         metadata={"monitor_id": f"monitor_{i}", "resource_id": f"monitor_{i}"})
            for i in range(20)
        ]
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.side_effect = [
            findings, signals
        ]
        with patch(
            "app.services.datadog_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            result = svc.generate_datadog_correlations(
                workspace_id=ws, db=mock_db, max_correlations=5
            )
        assert result["correlations_created"] <= 5
        assert mock_upsert.call_count <= 5

    def test_workspace_id_passed_to_upsert(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.side_effect = [
            [finding], [signal]
        ]
        with patch(
            "app.services.datadog_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            svc.generate_datadog_correlations(workspace_id=ws, db=mock_db)
        for call in mock_upsert.call_args_list:
            assert call.kwargs.get("workspace_id") == ws

    def test_cross_provider_not_correlated(self):
        """GitHub finding + Datadog signal must not produce a correlation."""
        svc = self._import_svc()
        ws = uuid.uuid4()
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        finding.provider = "github"  # wrong provider

        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        mock_db = MagicMock()
        # Findings query returns empty (provider=datadog filter)
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.side_effect = [
            [], [signal]
        ]
        with patch(
            "app.services.datadog_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            svc.generate_datadog_correlations(workspace_id=ws, db=mock_db)
        assert mock_upsert.call_count == 0

    def test_generic_fallback_requires_same_resource_type_and_id(self):
        from app.services.datadog_risk_activity_correlation_service import (
            _build_generic_correlation,
        )
        finding = _make_finding("datadog_monitor_disabled", "resource_XYZ",
                               evidence={"record_id": "resource_XYZ", "record_type": "datadog_monitor"})
        finding.resource_type = "datadog_monitor"
        finding.resource_id = "resource_XYZ"

        # Same resource_type + resource_id → match
        signal_match = _make_signal("datadog_monitor_config_changed", "resource_XYZ",
                                    metadata={"resource_type": "datadog_monitor", "resource_id": "resource_XYZ"})
        signal_match.resource_id = "resource_XYZ"
        signal_match.signal_metadata = {"resource_type": "datadog_monitor", "resource_id": "resource_XYZ"}
        result = _build_generic_correlation(finding=finding, signal=signal_match)
        assert result is not None
        assert result["confidence"] == "low"

        # Different resource_id → no match
        signal_no_match = _make_signal("datadog_monitor_config_changed", "resource_OTHER",
                                       metadata={"resource_type": "datadog_monitor", "resource_id": "resource_OTHER"})
        signal_no_match.resource_id = "resource_OTHER"
        result_no = _build_generic_correlation(finding=finding, signal=signal_no_match)
        assert result_no is None


# ── Section C: Correlation metadata privacy ───────────────────────────────────


class TestDatadogCorrelationMetadataPrivacy:

    def test_correlation_metadata_contains_no_forbidden_fields(self):
        from app.services.datadog_risk_activity_correlation_service import (
            _build_correlation,
            DATADOG_CORRELATION_RULES,
        )
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID",
                               evidence={
                                   "record_id": "DATADOG_TEST_MONITOR_ID",
                                   "record_type": "datadog_monitor",
                                   # Forbidden fields that must be dropped
                                   "api_key": "SHOULD_BE_DROPPED",
                                   "email": "user@example.com",
                                   "ip_address": "1.2.3.4",
                               })
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        rule = DATADOG_CORRELATION_RULES["datadog_monitor_risk_activity_correlation"]
        result = _build_correlation(
            finding=finding, signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule, match_reason="monitor_id_id_match", confidence="medium",
        )
        assert result is not None
        meta = result.get("metadata", {})
        for forbidden in FORBIDDEN_CORRELATION_METADATA_FIELDS:
            assert forbidden not in meta, (
                f"Forbidden field {forbidden!r} found in correlation metadata"
            )

    def test_allowed_metadata_keys_contains_datadog_correlation_keys(self):
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        expected_keys = [
            "monitor_id", "slo_id", "dashboard_id",
            "notification_integration_id", "application_key_id",
            "role_id", "team_id", "cloud_integration_id",
            "record_type", "signal_count", "time_delta_minutes",
            "correlation_reason", "correlation_strength",
        ]
        for key in expected_keys:
            assert key in ALLOWED_METADATA_KEYS, (
                f"Expected Datadog correlation key {key!r} not in ALLOWED_METADATA_KEYS"
            )

    def test_allowed_metadata_keys_no_forbidden_datadog_fields(self):
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        strictly_forbidden = [
            "api_key", "application_key", "oauth_token", "bearer_token",
            "webhook_secret", "integration_secret",
            "email", "user_email", "ip_address", "user_agent",
            "webhook_url", "raw_payload", "audit_payload",
        ]
        for key in strictly_forbidden:
            assert key not in ALLOWED_METADATA_KEYS, (
                f"Forbidden key {key!r} found in ALLOWED_METADATA_KEYS"
            )

    def test_no_raw_query_in_correlation_metadata(self):
        from app.services.datadog_risk_activity_correlation_service import (
            _build_correlation,
            DATADOG_CORRELATION_RULES,
        )
        finding = _make_finding("datadog_monitor_disabled", "DATADOG_TEST_MONITOR_ID")
        signal = _make_signal("datadog_monitor_config_changed", "DATADOG_TEST_MONITOR_ID")
        rule = DATADOG_CORRELATION_RULES["datadog_monitor_risk_activity_correlation"]
        result = _build_correlation(
            finding=finding, signal=signal,
            correlation_type="datadog_monitor_risk_activity_correlation",
            rule=rule, match_reason="monitor_id_id_match", confidence="medium",
        )
        meta_str = str(result.get("metadata", {}))
        assert "avg:system.cpu" not in meta_str
        assert "sum:requests" not in meta_str


# ── Section D: API endpoint ────────────────────────────────────────────────────


class TestDatadogCorrelationEndpoint:

    def _make_admin_user(self):
        user = MagicMock()
        user.id = uuid.uuid4()
        return user

    def _make_member_user(self):
        user = MagicMock()
        user.id = uuid.uuid4()
        return user

    def test_admin_can_generate_correlations(self):
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
                "app.services.datadog_risk_activity_correlation_service.generate_datadog_correlations",
                return_value={
                    "provider": "datadog",
                    "findings_scanned": 0,
                    "signals_scanned": 0,
                    "candidate_pairs": 0,
                    "correlations_created": 0,
                    "correlations_skipped": 0,
                },
            ),
        ):
            app.dependency_overrides[get_current_user] = lambda: admin_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.post("/security/datadog-correlations/generate", json={})
                assert resp.status_code == 200
                data = resp.json()
                assert data["provider"] == "datadog"
                assert "candidate_pairs" in data
            finally:
                app.dependency_overrides.clear()

    def test_member_cannot_generate_correlations(self):
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
                resp = client.post("/security/datadog-correlations/generate", json={})
                assert resp.status_code == 403
            finally:
                app.dependency_overrides.clear()

    def test_member_can_read_correlations(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import security_signal_correlation_service

        member_user = self._make_member_user()

        with patch.object(
            security_signal_correlation_service,
            "list_correlations",
            return_value=([], 0),
        ):
            app.dependency_overrides[get_current_user] = lambda: member_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.get("/security/correlations?provider=datadog")
                assert resp.status_code in (200, 422)
            finally:
                app.dependency_overrides.clear()


# ── Section E: Frontend checks ─────────────────────────────────────────────────


class TestDatadogCorrelationFrontend:

    def _read_fe(self, rel_path: str) -> str:
        frontend = Path(__file__).parent.parent.parent.parent / "frontend" / "src"
        full = frontend / rel_path
        if not full.exists():
            pytest.skip(f"Frontend file not found: {full}")
        return full.read_text(errors="replace")

    def test_correlations_page_includes_datadog_provider(self):
        text = self._read_fe("app/(app)/security/correlations/page.tsx")
        assert '"datadog"' in text or "'datadog'" in text

    def test_correlations_page_includes_datadog_correlation_types(self):
        text = self._read_fe("app/(app)/security/correlations/page.tsx")
        assert "datadog_monitor_risk_activity_correlation" in text
        assert "datadog_webhook_risk_activity_correlation" in text
        assert "datadog_role_risk_activity_correlation" in text

    def test_correlations_page_imports_generate_datadog_correlations(self):
        text = self._read_fe("app/(app)/security/correlations/page.tsx")
        assert "generateDatadogCorrelations" in text

    def test_api_ts_includes_generate_datadog_correlations(self):
        text = self._read_fe("lib/api.ts")
        assert "generateDatadogCorrelations" in text
        assert "datadog-correlations/generate" in text

    def test_types_includes_datadog_correlation_response(self):
        text = self._read_fe("types/index.ts")
        assert "DatadogCorrelationGenerateResponse" in text

    def test_correlations_page_no_forbidden_phrases(self):
        text = self._read_fe("app/(app)/security/correlations/page.tsx").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} in correlations/page.tsx"
            )

    def test_all_expected_correlation_types_in_frontend(self):
        text = self._read_fe("app/(app)/security/correlations/page.tsx")
        for ct in EXPECTED_DATADOG_CORRELATION_TYPES:
            assert ct in text, f"Correlation type {ct!r} not in correlations/page.tsx"


# ── Section F: Capability matrix ───────────────────────────────────────────────


class TestDatadogCapabilityMatrixF:

    def _get_cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("datadog")
        assert cap is not None
        return cap.as_dict()

    def test_risk_activity_correlations_is_true(self):
        cap = self._get_cap()
        assert cap["security"]["risk_activity_correlations"] is True

    def test_activity_signals_still_true(self):
        cap = self._get_cap()
        assert cap["security"]["activity_signals"] is True

    def test_activity_ingestion_still_true(self):
        cap = self._get_cap()
        assert cap["security"]["activity_ingestion"] is True

    def test_demo_seed_clear_is_true_after_m82g(self):
        # M82G set demo_seed_clear=True (Datadog demo + QA added)
        cap = self._get_cap()
        assert cap["security"]["demo_seed_clear"] is True

    def test_case_report_is_true_after_m82g(self):
        # M82G set case_report=True (Datadog demo seeds a case)
        cap = self._get_cap()
        assert cap["security"]["case_report"] is True

    def test_maturity_is_partial(self):
        cap = self._get_cap()
        assert cap["maturity"] == "partial"


# ── Section G: Provider expansion framework ────────────────────────────────────


class TestDatadogExpansionFrameworkF:

    def test_planned_next_stage_is_m83a_after_m82i(self):
        # M82I shipped; planned_next_stage now points to M83A Clerk
        from app.services.provider_expansion_framework import get_framework
        framework = get_framework()
        planned = framework["summary"].get("planned_next_stage", "")
        assert "M83A" in planned or "Clerk" in planned or "M84A" in planned or "PagerDuty" in planned, (
            f"planned_next_stage should reference M83A/Clerk or later, got: {planned!r}"
        )

    def test_planned_next_stage_is_past_m82(self):
        from app.services.provider_expansion_framework import get_framework
        framework = get_framework()
        planned = framework["summary"].get("planned_next_stage", "")
        assert "M82I" not in planned and "M82H" not in planned


# ── Section H: Forbidden wording and secret-shape scan ────────────────────────


class TestDatadogCorrelationForbiddenWordingAndSecrets:

    def test_no_forbidden_phrases_in_correlation_service(self):
        from app.services import datadog_risk_activity_correlation_service
        source = inspect.getsource(datadog_risk_activity_correlation_service)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source.lower(), (
                f"Forbidden phrase {phrase!r} in datadog_risk_activity_correlation_service"
            )

    def test_no_secret_shaped_strings_in_m82f_files(self):
        backend_app = Path(__file__).parent.parent / "app"
        m82f_files = [
            backend_app / "services" / "datadog_risk_activity_correlation_service.py",
            backend_app / "schemas" / "security_datadog_activity.py",
        ]
        pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}"
            r"|SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            r"|AC[0-9a-fA-F]{32}"
            r"|SK[0-9a-fA-F]{32}"
        )
        violations = []
        for py_file in m82f_files:
            if not py_file.exists():
                continue
            if pattern.search(py_file.read_text(errors="replace")):
                violations.append(str(py_file))
        assert not violations, f"Secret-shaped strings in M82F files: {violations}"

    def test_no_forbidden_phrases_in_m82f_files(self):
        backend_app = Path(__file__).parent.parent / "app"
        m82f_files = [
            backend_app / "services" / "datadog_risk_activity_correlation_service.py",
            backend_app / "schemas" / "security_datadog_activity.py",
        ]
        violations = []
        for py_file in m82f_files:
            if not py_file.exists():
                continue
            text = py_file.read_text(errors="replace").lower()
            for phrase in FORBIDDEN_PHRASES:
                if phrase in text:
                    violations.append(f"{py_file.name}: {phrase!r}")
        assert not violations, f"Forbidden phrases in M82F files: {violations}"


# ── Section I: Regression smoke ────────────────────────────────────────────────


class TestDatadogM82FRegression:

    def test_m82e_signal_service_still_importable(self):
        from app.services import datadog_activity_signal_service
        assert hasattr(datadog_activity_signal_service, "generate_datadog_activity_signals")

    def test_m82d_ingestion_service_still_importable(self):
        from app.services import datadog_activity_ingestion_service
        assert hasattr(datadog_activity_ingestion_service, "sync_datadog_activity")

    def test_m82c_monitor_rules_still_present(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert "datadog_monitor_silenced_scopes_present" in KNOWN_RULE_KEYS
        assert "datadog_webhook_auth_material_present" in KNOWN_RULE_KEYS

    def test_m82b_rules_still_registered(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert "datadog_monitor_disabled" in KNOWN_RULE_KEYS
        assert "datadog_cloud_integration_log_collection_enabled" in KNOWN_RULE_KEYS

    def test_m82a_connector_fetch_still_works(self):
        from app.connectors.datadog import DatadogConnector
        assert hasattr(DatadogConnector, "fetch")
        assert hasattr(DatadogConnector, "list_activity_events")

    def test_datadog_correlation_types_frozenset_complete(self):
        from app.services.datadog_risk_activity_correlation_service import (
            DATADOG_CORRELATION_TYPES,
        )
        assert len(DATADOG_CORRELATION_TYPES) == 10  # 10 specialized families
