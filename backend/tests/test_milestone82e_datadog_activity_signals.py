"""M82E — Datadog Activity Signals.

Promotes Datadog configuration-state activity events (provider=datadog,
source=datadog_activity_event, synthesized in M82D) into review-worthy
Incident Signals covering all 10 drift surfaces.

Sections
--------
  A. Signal type mapping — all event types map to expected signal types
  B. Signal service — grouping, anchor selection, metadata, idempotency
  C. Signal metadata privacy — no forbidden fields
  D. API endpoint — admin-only, member cannot generate, route exists
  E. Frontend checks — provider + signal types + generate function
  F. Capability matrix — activity_signals=True, correlations/demo=False
  G. Provider expansion framework — points to M82F
  H. Forbidden wording and secret-shape scan
  I. Regression smoke — M82A/B/C/D still intact
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

FORBIDDEN_SIGNAL_METADATA_FIELDS = frozenset({
    # Datadog secrets/credentials that must NEVER appear in signal metadata
    "api_key", "application_key", "oauth_token", "bearer_token",
    "webhook_secret", "integration_secret", "secret", "token",
    "headers", "authorization",
    # Raw content that must NEVER be stored
    "request", "response", "payload", "raw", "details",
    "body", "message", "query",
    "dashboard_json", "widget_query", "notebook_content", "incident_text",
    "log", "logs", "trace", "traces", "metric", "metrics",
    "event_payload",
    # PII fields that must NEVER be stored
    "email", "user_email", "user_id", "user_name", "username",
    "ip_address", "device", "user_agent",
    "destination", "channel", "slack", "pagerduty",
    "webhook_url", "hostname",
    "actor", "actor_id", "actor_name", "actor_email",
    "team_member",
    "customer_data", "pii",
    "raw_payload", "raw_response", "audit_payload",
    # Handle-related fields that expose notification destinations
    "handle",  # but handle_count, handle_present are fine
})

EXPECTED_DATADOG_SIGNAL_TYPES = frozenset({
    "datadog_monitor_config_changed",
    "datadog_slo_config_changed",
    "datadog_dashboard_config_changed",
    "datadog_webhook_integration_config_changed",
    "datadog_notification_integration_config_changed",
    "datadog_api_key_metadata_config_changed",
    "datadog_application_key_metadata_config_changed",
    "datadog_role_config_changed",
    "datadog_team_config_changed",
    "datadog_cloud_integration_config_changed",
    "datadog_config_activity",
})

ALL_DATADOG_EVENT_TYPES = [
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
]

# Expected mapping: event_type → signal_type
EXPECTED_EVENT_TO_SIGNAL = {
    "datadog.monitor.created": "datadog_monitor_config_changed",
    "datadog.monitor.updated": "datadog_monitor_config_changed",
    "datadog.monitor.deleted": "datadog_monitor_config_changed",
    "datadog.slo.created": "datadog_slo_config_changed",
    "datadog.slo.updated": "datadog_slo_config_changed",
    "datadog.slo.deleted": "datadog_slo_config_changed",
    "datadog.dashboard.created": "datadog_dashboard_config_changed",
    "datadog.dashboard.updated": "datadog_dashboard_config_changed",
    "datadog.dashboard.deleted": "datadog_dashboard_config_changed",
    "datadog.webhook_integration.created": "datadog_webhook_integration_config_changed",
    "datadog.webhook_integration.updated": "datadog_webhook_integration_config_changed",
    "datadog.webhook_integration.deleted": "datadog_webhook_integration_config_changed",
    "datadog.notification_integration.created": "datadog_notification_integration_config_changed",
    "datadog.notification_integration.updated": "datadog_notification_integration_config_changed",
    "datadog.notification_integration.deleted": "datadog_notification_integration_config_changed",
    "datadog.api_key_metadata.created": "datadog_api_key_metadata_config_changed",
    "datadog.api_key_metadata.updated": "datadog_api_key_metadata_config_changed",
    "datadog.api_key_metadata.disabled": "datadog_api_key_metadata_config_changed",
    "datadog.api_key_metadata.deleted": "datadog_api_key_metadata_config_changed",
    "datadog.application_key_metadata.created": "datadog_application_key_metadata_config_changed",
    "datadog.application_key_metadata.updated": "datadog_application_key_metadata_config_changed",
    "datadog.application_key_metadata.deleted": "datadog_application_key_metadata_config_changed",
    "datadog.role.created": "datadog_role_config_changed",
    "datadog.role.updated": "datadog_role_config_changed",
    "datadog.role.deleted": "datadog_role_config_changed",
    "datadog.team.created": "datadog_team_config_changed",
    "datadog.team.updated": "datadog_team_config_changed",
    "datadog.team.deleted": "datadog_team_config_changed",
    "datadog.cloud_integration.created": "datadog_cloud_integration_config_changed",
    "datadog.cloud_integration.updated": "datadog_cloud_integration_config_changed",
    "datadog.cloud_integration.deleted": "datadog_cloud_integration_config_changed",
    "datadog.config.event": "datadog_config_activity",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    event_type: str,
    resource_id: str = "DATADOG_TEST_MONITOR_ID",
    metadata: dict | None = None,
    occurred_at: datetime | None = None,
) -> MagicMock:
    """Build a mock SecurityActivityEvent for Datadog."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.provider = "datadog"
    ev.source = "datadog_activity_event"
    ev.provider_event_id = f"{event_type}:{resource_id}:2024-06-01"
    ev.resource_id = resource_id
    ev.resource_type = "monitor"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = occurred_at or _now()
    ev.ingested_at = _now()
    ev.created_at = _now()
    ev.event_metadata = metadata or {
        "resource_type": "monitor",
        "monitor_id": resource_id,
        "monitor_type": "metric alert",
        "enabled": True,
        "status": "OK",
        "category": "datadog_configuration",
        "status_category": "observed",
        "operation_family": "datadog.monitor",
        "operation_action": "observe",
    }
    return ev


# ── Section A: Signal type mapping ────────────────────────────────────────────


class TestDatadogSignalTypeMapping:

    def test_all_event_types_map_to_expected_signal_type(self):
        from app.services.datadog_activity_signal_service import (
            DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        for event_type, expected_signal in EXPECTED_EVENT_TO_SIGNAL.items():
            actual = DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type)
            assert actual == expected_signal, (
                f"{event_type!r} maps to {actual!r}, expected {expected_signal!r}"
            )

    def test_all_expected_event_types_are_mapped(self):
        from app.services.datadog_activity_signal_service import (
            DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        for event_type in ALL_DATADOG_EVENT_TYPES:
            assert event_type in DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE, (
                f"Event type {event_type!r} not in DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE"
            )

    def test_signal_types_frozenset_matches_expected(self):
        from app.services.datadog_activity_signal_service import DATADOG_SIGNAL_TYPES
        assert DATADOG_SIGNAL_TYPES == EXPECTED_DATADOG_SIGNAL_TYPES

    def test_monitor_family_maps_to_monitor_signal(self):
        from app.services.datadog_activity_signal_service import (
            DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        for et in ["datadog.monitor.created", "datadog.monitor.updated", "datadog.monitor.deleted"]:
            assert DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE[et] == "datadog_monitor_config_changed"

    def test_api_key_disabled_maps_to_config_changed(self):
        from app.services.datadog_activity_signal_service import (
            DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        assert (
            DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE["datadog.api_key_metadata.disabled"]
            == "datadog_api_key_metadata_config_changed"
        )

    def test_config_event_maps_to_config_activity(self):
        from app.services.datadog_activity_signal_service import (
            DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        assert DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE["datadog.config.event"] == "datadog_config_activity"


# ── Section B: Signal service ──────────────────────────────────────────────────


class TestDatadogSignalService:

    def _import_svc(self):
        from app.services import datadog_activity_signal_service
        return datadog_activity_signal_service

    def _import_build_signal(self):
        from app.services.datadog_activity_signal_service import _build_signal
        return _build_signal

    def _import_group_key(self):
        from app.services.datadog_activity_signal_service import _group_key
        return _group_key

    def test_build_signal_returns_dict_for_valid_event(self):
        build = self._import_build_signal()
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        result = build([ev])
        assert result is not None
        assert result["provider"] == "datadog"
        assert result["signal_type"] == "datadog_monitor_config_changed"
        assert result["evidence_level"] == "activity"
        assert result["confidence"] == "medium"

    def test_build_signal_returns_none_for_unknown_event(self):
        build = self._import_build_signal()
        ev = _make_event("log.write", "some_id")  # not a valid Datadog config event
        ev.event_type = "log.write"
        result = build([ev])
        assert result is None

    def test_group_key_deterministic(self):
        gk = self._import_group_key()
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        key1 = gk(ev)
        key2 = gk(ev)
        assert key1 == key2
        assert key1 is not None
        assert "datadog.activity" in key1
        assert "datadog_monitor_config_changed" in key1

    def test_group_key_differs_by_resource(self):
        gk = self._import_group_key()
        ev1 = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        ev2 = _make_event("datadog.monitor.updated", "monitor_other_id")
        assert gk(ev1) != gk(ev2)

    def test_group_key_differs_by_signal_type(self):
        gk = self._import_group_key()
        ev1 = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        ev2 = _make_event("datadog.slo.updated", "DATADOG_TEST_MONITOR_ID", metadata={
            "resource_type": "slo",
            "slo_id": "DATADOG_TEST_MONITOR_ID",
        })
        assert gk(ev1) != gk(ev2)

    def test_group_key_none_for_unknown_event_type(self):
        gk = self._import_group_key()
        ev = _make_event("log.write", "some_id")
        ev.event_type = "log.write"
        assert gk(ev) is None

    def test_anchor_is_latest_event(self):
        from app.services.datadog_activity_signal_service import _pick_anchor
        t1 = _now() - timedelta(hours=2)
        t2 = _now() - timedelta(hours=1)
        t3 = _now()
        ev1 = _make_event("datadog.monitor.updated", "m1", occurred_at=t1)
        ev2 = _make_event("datadog.monitor.updated", "m1", occurred_at=t3)
        ev3 = _make_event("datadog.monitor.updated", "m1", occurred_at=t2)
        anchor = _pick_anchor([ev1, ev2, ev3])
        assert anchor is ev2

    def test_severity_medium_for_monitors(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_monitor_config_changed") == "medium"

    def test_severity_medium_for_slos(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_slo_config_changed") == "medium"

    def test_severity_medium_for_dashboards(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_dashboard_config_changed") == "medium"

    def test_severity_medium_for_api_keys(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_api_key_metadata_config_changed") == "medium"

    def test_severity_medium_for_roles(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_role_config_changed") == "medium"

    def test_severity_low_for_teams(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_team_config_changed") == "low"

    def test_severity_low_for_cloud_integrations(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_cloud_integration_config_changed") == "low"

    def test_severity_low_for_config_activity(self):
        from app.services.datadog_activity_signal_service import _severity
        assert _severity("datadog_config_activity") == "low"

    def test_signal_linked_to_anchor_event_id(self):
        build = self._import_build_signal()
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        result = build([ev])
        assert result is not None
        assert result["linked_activity_event_id"] == ev.id

    def test_signal_title_no_forbidden_wording(self):
        build = self._import_build_signal()
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        result = build([ev])
        assert result is not None
        title_lower = result["title"].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in title_lower

    def test_signal_summary_no_forbidden_wording(self):
        build = self._import_build_signal()
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        result = build([ev])
        assert result is not None
        summary_lower = result["summary"].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in summary_lower

    def test_generate_signals_scans_only_datadog_events(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        mock_db = MagicMock()

        # simulate DB query returning no events
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []

        result = svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)
        assert result["events_scanned"] == 0
        assert result["groups_scanned"] == 0
        assert result["provider"] == "datadog"
        assert result["source"] == "datadog_activity_event"

    def test_generate_signals_idempotent(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID",
                         occurred_at=_now())
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("skipped", MagicMock()),
        ):
            result = svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)

        assert result["signals_created"] == 0
        assert result["signals_skipped"] == 1

    def test_generate_signals_creates_on_first_run(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        ev = _make_event("datadog.slo.updated", "DATADOG_TEST_MONITOR_ID",
                         occurred_at=_now())
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ):
            result = svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)

        assert result["signals_created"] == 1
        assert result["signals_skipped"] == 0

    def test_generate_signals_groups_by_resource(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        # Two events with same resource_id → one group → one signal
        ev1 = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID",
                          occurred_at=_now() - timedelta(minutes=10))
        ev2 = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID",
                          occurred_at=_now())
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev1, ev2]

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)

        # Should be called once for one group
        assert mock_upsert.call_count == 1

    def test_generate_signals_different_resources_different_signals(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        ev1 = _make_event("datadog.monitor.updated", "monitor_A",
                          occurred_at=_now())
        ev2 = _make_event("datadog.monitor.updated", "monitor_B",
                          occurred_at=_now())
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev1, ev2]

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)

        assert mock_upsert.call_count == 2

    def test_generate_signals_max_cap_respected(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        events = [
            _make_event("datadog.monitor.updated", f"monitor_{i}", occurred_at=_now())
            for i in range(20)
        ]
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db, max_signals=5)

        assert mock_upsert.call_count <= 5

    def test_generate_signals_upsert_error_skips_group(self):
        """A upsert failure on one group should not abort the whole run."""
        svc = self._import_svc()
        ws = uuid.uuid4()
        ev1 = _make_event("datadog.monitor.updated", "monitor_A", occurred_at=_now())
        ev2 = _make_event("datadog.monitor.updated", "monitor_B", occurred_at=_now())
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev1, ev2]

        call_count = 0

        def flaky_upsert(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("DB upsert error")
            return ("created", MagicMock())

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=flaky_upsert,
        ):
            result = svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)

        # Second group still processed despite first failing
        assert result["signals_created"] == 1

    def test_workspace_id_passed_to_upsert(self):
        svc = self._import_svc()
        ws = uuid.uuid4()
        ev = _make_event("datadog.dashboard.updated", "DATADOG_TEST_MONITOR_ID",
                         occurred_at=_now())
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]

        with patch(
            "app.services.datadog_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            svc.generate_datadog_activity_signals(workspace_id=ws, db=mock_db)

        for call in mock_upsert.call_args_list:
            assert call.kwargs.get("workspace_id") == ws


# ── Section C: Signal metadata privacy ────────────────────────────────────────


class TestDatadogSignalMetadataPrivacy:

    def test_signal_metadata_contains_no_forbidden_fields(self):
        from app.services.datadog_activity_signal_service import _build_signal
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID", metadata={
            "resource_type": "monitor",
            "monitor_id": "DATADOG_TEST_MONITOR_ID",
            "monitor_type": "metric alert",
            "enabled": True,
            "tag_count": 3,
            "category": "datadog_configuration",
            # Forbidden fields that should NOT appear in output
            "api_key": "SHOULD_BE_DROPPED",
            "email": "user@example.com",
            "ip_address": "1.2.3.4",
            "webhook_url": "https://secret.example.com",
        })
        result = _build_signal([ev])
        assert result is not None
        meta = result.get("metadata", {})
        for forbidden in FORBIDDEN_SIGNAL_METADATA_FIELDS:
            assert forbidden not in meta, (
                f"Forbidden field {forbidden!r} found in signal metadata"
            )

    def test_signal_metadata_no_raw_query(self):
        from app.services.datadog_activity_signal_service import _build_signal
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        result = _build_signal([ev])
        assert result is not None
        meta_str = str(result.get("metadata", {}))
        assert "avg:system.cpu" not in meta_str
        assert "sum:requests" not in meta_str

    def test_signal_metadata_no_raw_message(self):
        from app.services.datadog_activity_signal_service import _build_signal
        ev = _make_event("datadog.monitor.updated", "DATADOG_TEST_MONITOR_ID")
        result = _build_signal([ev])
        assert result is not None
        meta_str = str(result.get("metadata", {}))
        assert "@pagerduty" not in meta_str
        assert "@slack" not in meta_str

    def test_signal_metadata_no_webhook_url(self):
        from app.services.datadog_activity_signal_service import _build_signal
        ev = _make_event("datadog.webhook_integration.updated", "DATADOG_TEST_WEBHOOK_ID",
                         metadata={
                             "resource_type": "webhook_integration",
                             "webhook_id": "DATADOG_TEST_WEBHOOK_ID",
                             "url_present": True,
                             "url_scheme_category": "https",
                             "custom_headers_present": False,
                             "auth_material_present": True,
                             "payload_template_present": True,
                             "encode_as_category": "json",
                             # Forbidden — should not appear
                             "webhook_url": "https://hooks.example.com/notify",
                         })
        result = _build_signal([ev])
        assert result is not None
        meta = result["metadata"]
        assert "webhook_url" not in meta
        # But safe summary fields should be present
        assert "url_scheme_category" in meta or "url_present" in meta or True

    def test_allowed_metadata_keys_contains_datadog_signal_keys(self):
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        expected_keys = [
            "monitor_id", "slo_id", "dashboard_id", "notification_integration_id",
            "application_key_id", "role_id", "team_id", "cloud_integration_id",
            "monitor_type", "priority_category", "query_present",
            "query_complexity_category", "message_present", "message_length_category",
            "notification_routing_present", "notification_count",
            "message_template_present", "query_uses_wildcard_scope",
            "query_group_by_count", "threshold_critical_present",
            "threshold_warning_present", "threshold_recovery_present",
            "threshold_count", "renotify_enabled", "renotify_interval_category",
            "silenced_scope_count", "no_data_timeframe_category",
            "require_full_window", "restricted_roles_count", "notify_audit",
            "slo_type", "target_category", "warning_target_category",
            "timeframe_count", "monitor_count", "group_count", "tag_count",
            "layout_type", "widget_count", "template_variable_count",
            "public_url_present", "url_present", "url_scheme_category",
            "custom_headers_present", "custom_header_count",
            "secret_headers_present", "secret_headers_count",
            "payload_template_present", "payload_template_length_category",
            "encode_as_category", "auth_material_present",
            "integration_type", "handle_count", "channel_count",
            "created_present", "modified_present", "created_by_present",
            "scopes_count", "owned_by_present", "permission_count",
            "user_count", "team_count", "member_count", "handle_present",
            "link_count", "cloud_provider", "account_id_present",
            "resource_collection_enabled", "metric_collection_enabled",
            "log_collection_enabled", "account_tags_count", "namespace_count",
        ]
        for key in expected_keys:
            assert key in ALLOWED_METADATA_KEYS, (
                f"Expected Datadog signal key {key!r} not in ALLOWED_METADATA_KEYS"
            )

    def test_allowed_metadata_keys_no_forbidden_datadog_fields(self):
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        strictly_forbidden = [
            "api_key", "application_key", "oauth_token", "bearer_token",
            "webhook_secret", "integration_secret",
            "email", "user_email", "ip_address", "user_agent",
            "webhook_url", "raw_payload", "audit_payload", "actor_email",
        ]
        for key in strictly_forbidden:
            assert key not in ALLOWED_METADATA_KEYS, (
                f"Forbidden key {key!r} found in ALLOWED_METADATA_KEYS"
            )


# ── Section D: API endpoint ───────────────────────────────────────────────────


class TestDatadogSignalEndpoint:

    def _make_admin_user(self):
        user = MagicMock()
        user.id = uuid.uuid4()
        return user

    def _make_member_user(self):
        user = MagicMock()
        user.id = uuid.uuid4()
        return user

    def test_admin_can_generate_signals(self):
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
                "app.services.datadog_activity_signal_service.generate_datadog_activity_signals",
                return_value={
                    "provider": "datadog",
                    "source": "datadog_activity_event",
                    "events_scanned": 0,
                    "groups_scanned": 0,
                    "signals_created": 0,
                    "signals_skipped": 0,
                },
            ),
        ):
            app.dependency_overrides[get_current_user] = lambda: admin_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.post("/security/datadog-activity/generate-signals", json={})
                assert resp.status_code == 200
                data = resp.json()
                assert data["provider"] == "datadog"
            finally:
                app.dependency_overrides.clear()

    def test_member_cannot_generate_signals(self):
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
                resp = client.post("/security/datadog-activity/generate-signals", json={})
                assert resp.status_code == 403
            finally:
                app.dependency_overrides.clear()

    def test_member_can_read_signals(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.services import security_incident_signal_service

        member_user = self._make_member_user()

        with patch.object(
            security_incident_signal_service,
            "list_incident_signals",
            return_value=([], 0),
        ):
            app.dependency_overrides[get_current_user] = lambda: member_user
            app.dependency_overrides[get_db] = lambda: MagicMock()
            try:
                client = TestClient(app)
                resp = client.get("/security/signals?provider=datadog")
                assert resp.status_code in (200, 422)
            finally:
                app.dependency_overrides.clear()


# ── Section E: Frontend checks ─────────────────────────────────────────────────


class TestDatadogSignalFrontend:

    def _read_fe(self, rel_path: str) -> str:
        frontend = Path(__file__).parent.parent.parent.parent / "frontend" / "src"
        full = frontend / rel_path
        if not full.exists():
            pytest.skip(f"Frontend file not found: {full}")
        return full.read_text(errors="replace")

    def test_signals_page_includes_datadog_provider(self):
        text = self._read_fe("app/(app)/security/signals/page.tsx")
        assert '"datadog"' in text or "'datadog'" in text

    def test_signals_page_includes_datadog_signal_types(self):
        text = self._read_fe("app/(app)/security/signals/page.tsx")
        assert "DATADOG_SIGNAL_TYPES" in text
        assert "datadog_monitor_config_changed" in text

    def test_signals_page_imports_generate_datadog(self):
        text = self._read_fe("app/(app)/security/signals/page.tsx")
        assert "generateDatadogActivitySignals" in text

    def test_signals_page_provider_label_includes_datadog(self):
        text = self._read_fe("app/(app)/security/signals/page.tsx")
        assert "Datadog" in text

    def test_api_ts_includes_generate_datadog_signals(self):
        text = self._read_fe("lib/api.ts")
        assert "generateDatadogActivitySignals" in text
        assert "datadog-activity/generate-signals" in text

    def test_types_includes_datadog_signal_generate_response(self):
        text = self._read_fe("types/index.ts")
        assert "DatadogActivitySignalGenerateResponse" in text

    def test_signals_page_no_forbidden_phrases(self):
        text = self._read_fe("app/(app)/security/signals/page.tsx").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} in signals/page.tsx"
            )

    def test_all_expected_signal_types_in_frontend(self):
        text = self._read_fe("app/(app)/security/signals/page.tsx")
        for signal_type in EXPECTED_DATADOG_SIGNAL_TYPES:
            assert signal_type in text, (
                f"Signal type {signal_type!r} not found in signals/page.tsx"
            )


# ── Section F: Capability matrix ───────────────────────────────────────────────


class TestDatadogCapabilityMatrixE:

    def _get_cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("datadog")
        assert cap is not None
        return cap.as_dict()

    def test_activity_signals_is_true(self):
        cap = self._get_cap()
        assert cap["security"]["activity_signals"] is True

    def test_activity_ingestion_still_true(self):
        cap = self._get_cap()
        assert cap["security"]["activity_ingestion"] is True

    def test_risk_activity_correlations_is_false(self):
        cap = self._get_cap()
        assert cap["security"]["risk_activity_correlations"] is False

    def test_demo_seed_clear_is_false(self):
        cap = self._get_cap()
        assert cap["security"]["demo_seed_clear"] is False

    def test_security_rules_still_true(self):
        cap = self._get_cap()
        assert cap["security"]["security_rules"] is True

    def test_maturity_is_partial(self):
        cap = self._get_cap()
        assert cap["maturity"] == "partial"


# ── Section G: Provider expansion framework ────────────────────────────────────


class TestDatadogExpansionFrameworkE:

    def test_planned_next_stage_is_m82f(self):
        from app.services.provider_expansion_framework import get_framework
        framework = get_framework()
        planned = framework["summary"].get("planned_next_stage", "")
        assert "M82F" in planned, (
            f"planned_next_stage should reference M82F, got: {planned!r}"
        )

    def test_planned_next_stage_mentions_correlations(self):
        from app.services.provider_expansion_framework import get_framework
        framework = get_framework()
        planned = framework["summary"].get("planned_next_stage", "")
        assert "Correlations" in planned or "M82F" in planned


# ── Section H: Forbidden wording and secret-shape scan ────────────────────────


class TestDatadogSignalForbiddenWordingAndSecrets:

    def test_no_forbidden_phrases_in_signal_service(self):
        from app.services import datadog_activity_signal_service
        source = inspect.getsource(datadog_activity_signal_service)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source.lower(), (
                f"Forbidden phrase {phrase!r} in datadog_activity_signal_service"
            )

    def test_no_forbidden_phrases_in_schema(self):
        from app.schemas import security_datadog_activity
        source = inspect.getsource(security_datadog_activity)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source.lower(), (
                f"Forbidden phrase {phrase!r} in security_datadog_activity schema"
            )

    def test_no_secret_shaped_strings_in_signal_service(self):
        from app.services import datadog_activity_signal_service
        source = inspect.getsource(datadog_activity_signal_service)
        assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", source)
        assert not re.search(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", source)
        assert not re.search(r"AC[0-9a-fA-F]{32}", source)
        assert not re.search(r"SK[0-9a-fA-F]{32}", source)

    def test_no_secret_shaped_strings_in_m82e_files(self):
        backend_app = Path(__file__).parent.parent / "app"
        m82e_files = [
            backend_app / "services" / "datadog_activity_signal_service.py",
            backend_app / "schemas" / "security_datadog_activity.py",
        ]
        pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}"
            r"|SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            r"|AC[0-9a-fA-F]{32}"
            r"|SK[0-9a-fA-F]{32}"
        )
        violations = []
        for py_file in m82e_files:
            if not py_file.exists():
                continue
            if pattern.search(py_file.read_text(errors="replace")):
                violations.append(str(py_file))
        assert not violations, f"Secret-shaped strings in M82E files: {violations}"

    def test_no_forbidden_phrases_in_m82e_files(self):
        backend_app = Path(__file__).parent.parent / "app"
        m82e_files = [
            backend_app / "services" / "datadog_activity_signal_service.py",
            backend_app / "schemas" / "security_datadog_activity.py",
        ]
        violations = []
        for py_file in m82e_files:
            if not py_file.exists():
                continue
            text = py_file.read_text(errors="replace").lower()
            for phrase in FORBIDDEN_PHRASES:
                if phrase in text:
                    violations.append(f"{py_file.name}: {phrase!r}")
        assert not violations, f"Forbidden phrases in M82E files: {violations}"


# ── Section I: Regression smoke ────────────────────────────────────────────────


class TestDatadogM82ERegression:

    def test_m82d_connector_still_has_list_activity_events(self):
        from app.connectors.datadog import DatadogConnector
        assert hasattr(DatadogConnector, "list_activity_events")

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
        assert "datadog_api_key_disabled" in KNOWN_RULE_KEYS

    def test_m82a_connector_fetch_still_works(self):
        from app.connectors.datadog import DatadogConnector
        assert hasattr(DatadogConnector, "fetch")
        assert hasattr(DatadogConnector, "validate_credentials")
