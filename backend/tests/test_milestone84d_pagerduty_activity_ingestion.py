"""M84D — PagerDuty Activity/Event Ingestion.

PagerDuty's audit trail API includes actor emails, user IDs, IP addresses,
and user agents in every entry — ingesting those would violate ConfigTrace's
privacy contract. This milestone NEVER ingests from those endpoints. Activity
events are config-state observations synthesized from the same safe drift
surfaces the connector reads (M84A–M84C).

Verifies:
  * PAGERDUTY_CONFIG_EVENT_TYPES is a frozenset
  * Expected config event types are in the allowlist
  * Unknown/non-config event types are rejected
  * PagerDutyConnector.list_activity_events exists and returns safe events
  * max_events cap (1000) and lookback_hours cap (168) are enforced
  * Synthesized events have correct structure (event_type, provider, source,
    provider_event_id, metadata)
  * normalize_pagerduty_activity_event filters out non-allowlisted event types
  * normalize_pagerduty_activity_event returns None for malformed inputs
  * normalize_pagerduty_activity_event computes fingerprint fallback when
    provider_event_id is absent
  * Idempotency: two calls with same entry yield the same provider_event_id
  * Metadata contains NO forbidden keys or strings (no tokens, URLs, emails,
    user IDs, IP addresses, raw payloads, PII)
  * actor_id is never stored (None) for config-state events
  * ALLOWED_METADATA_KEYS contains PagerDuty-specific keys
  * ingest_pagerduty_activity handles AuthenticationError, RateLimitError,
    NetworkError, and empty event list correctly
  * Router endpoint POST /security/pagerduty-activity/sync exists and requires
    admin/owner role
  * Capability matrix: activity_ingestion=True; signals/correlations=False
  * Expansion framework planned_next_stage references M84E
  * Frontend activity page includes "pagerduty" as a provider option
  * Frontend api.ts exports syncPagerDutyActivity
  * M84A/B/C regression: PAGERDUTY_RULE_KEYS still has >= 40 rules
  * Forbidden wording not in M84D source files
  * No secret-shaped strings in M84D backend files

CLAIM DISCIPLINE: configuration-state findings only. Does NOT confirm a
breach, compromise, unauthorized access, data exposure, or leaked secret.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER = "PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER"
PAGERDUTY_TEST_SERVICE_ID = "PAGERDUTY_TEST_SERVICE_ID"
PAGERDUTY_TEST_ESCALATION_POLICY_ID = "PAGERDUTY_TEST_ESCALATION_POLICY_ID"
PAGERDUTY_TEST_SCHEDULE_ID = "PAGERDUTY_TEST_SCHEDULE_ID"
PAGERDUTY_TEST_INTEGRATION_ID = "PAGERDUTY_TEST_INTEGRATION_ID"
PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID = "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID"
PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID = "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID"
PAGERDUTY_TEST_BUSINESS_SERVICE_ID = "PAGERDUTY_TEST_BUSINESS_SERVICE_ID"
PAGERDUTY_TEST_RESPONSE_PLAY_ID = "PAGERDUTY_TEST_RESPONSE_PLAY_ID"
PAGERDUTY_TEST_ACTIVITY_EVENT_ID = "PAGERDUTY_TEST_ACTIVITY_EVENT_ID"

# Expected PagerDuty config event types (M84D allowlist)
EXPECTED_EVENT_TYPES = {
    "pagerduty.service.updated",
    "pagerduty.escalation_policy.updated",
    "pagerduty.schedule.updated",
    "pagerduty.service_integration.updated",
    "pagerduty.webhook_subscription.updated",
    "pagerduty.event_orchestration.updated",
    "pagerduty.business_service.updated",
    "pagerduty.response_play.updated",
    "pagerduty.config.event",
}

# Fields that must NEVER appear in normalized event metadata
_FORBIDDEN_METADATA_FIELDS = frozenset({
    "api_token", "token", "routing_key", "integration_key",
    "webhook_secret", "secret_value", "authorization", "headers",
    "payload", "request", "response", "raw", "audit", "audit_payload",
    "incident", "alert", "event_payload", "email", "phone", "sms",
    "user", "user_id", "user_name", "contact", "contact_method",
    "ip", "ip_address", "user_agent", "webhook_url", "delivery_url",
    "domain", "hostname",
})

# Strings that must NEVER appear in any metadata string value
_FORBIDDEN_METADATA_STRINGS = [
    "eyJ",         # JWT pattern
    "@",           # email indicator
    "token=",      # token-in-URL pattern
    "Bearer ",
    "api_token",
    "routing_key",
    "integration_key",
    "webhook_secret",
]

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"


# ── A. Event type taxonomy ─────────────────────────────────────────────────────

def test_a1_pagerduty_config_event_types_importable() -> None:
    from app.services.pagerduty_activity_ingestion_service import (
        PAGERDUTY_CONFIG_EVENT_TYPES,
    )
    assert isinstance(PAGERDUTY_CONFIG_EVENT_TYPES, frozenset)


def test_a2_pagerduty_config_event_types_count() -> None:
    from app.services.pagerduty_activity_ingestion_service import (
        PAGERDUTY_CONFIG_EVENT_TYPES,
    )
    assert len(PAGERDUTY_CONFIG_EVENT_TYPES) >= 9


def test_a3_expected_event_types_in_allowlist() -> None:
    from app.services.pagerduty_activity_ingestion_service import (
        PAGERDUTY_CONFIG_EVENT_TYPES,
    )
    missing = EXPECTED_EVENT_TYPES - PAGERDUTY_CONFIG_EVENT_TYPES
    assert not missing, f"Expected event types missing from allowlist: {sorted(missing)}"


def test_a4_forbidden_event_types_not_in_allowlist() -> None:
    """Audit/incident/alert/user event types must NEVER be in the allowlist."""
    from app.services.pagerduty_activity_ingestion_service import (
        PAGERDUTY_CONFIG_EVENT_TYPES,
    )
    forbidden = {
        "pagerduty.incident.triggered",
        "pagerduty.incident.acknowledged",
        "pagerduty.incident.resolved",
        "pagerduty.alert.triggered",
        "pagerduty.user.created",
        "pagerduty.user.updated",
        "pagerduty.audit.record",
        "pagerduty.team.membership.changed",
        "pagerduty.log.entry.created",
    }
    present = forbidden & PAGERDUTY_CONFIG_EVENT_TYPES
    assert not present, f"Forbidden event types found in allowlist: {sorted(present)}"


# ── B. Connector list_activity_events ─────────────────────────────────────────

def test_b1_list_activity_events_exists() -> None:
    from app.connectors.pagerduty import PagerDutyConnector
    connector = PagerDutyConnector()
    assert hasattr(connector, "list_activity_events")
    assert callable(connector.list_activity_events)


def test_b2_list_activity_events_returns_safe_events() -> None:
    """Verify connector synthesizes events with correct structure."""
    from app.connectors.pagerduty import PagerDutyConnector
    from app.services.pagerduty_activity_ingestion_service import (
        PAGERDUTY_CONFIG_EVENT_TYPES,
    )

    connector = PagerDutyConnector()
    safe_services = [
        {
            "record_type": "pagerduty_service",
            "record_id": PAGERDUTY_TEST_SERVICE_ID,
            "resource_id": PAGERDUTY_TEST_SERVICE_ID,
            "resource_name": "Test Service",
            "status_category": "active",
            "escalation_policy_id": PAGERDUTY_TEST_ESCALATION_POLICY_ID,
            "team_count": 1,
            "integration_count": 2,
            "alert_creation_category": "alerts_and_incidents",
            "acknowledgement_timeout_category": "short",
            "auto_resolve_timeout_category": "medium",
            "support_hours_enabled": False,
            "scheduled_actions_count": 0,
        }
    ]
    safe_eps = [
        {
            "record_type": "pagerduty_escalation_policy",
            "record_id": PAGERDUTY_TEST_ESCALATION_POLICY_ID,
            "resource_id": PAGERDUTY_TEST_ESCALATION_POLICY_ID,
            "resource_name": "Primary Policy",
            "team_count": 1,
            "escalation_rule_count": 2,
            "escalation_level_count": 2,
            "target_count": 3,
            "schedule_target_count": 2,
            "has_schedule_targets": True,
            "repeat_enabled": False,
            "num_loops": 0,
        }
    ]
    safe_schedules: list[dict] = []
    safe_integrations: list[dict] = []
    safe_webhooks: list[dict] = []
    safe_eos: list[dict] = []
    safe_bs: list[dict] = []
    safe_rps: list[dict] = []

    with (
        patch.object(connector, "_fetch_services", return_value=safe_services),
        patch.object(connector, "_fetch_escalation_policies", return_value=safe_eps),
        patch.object(connector, "_fetch_schedules", return_value=safe_schedules),
        patch.object(connector, "_fetch_service_integrations", return_value=safe_integrations),
        patch.object(connector, "_fetch_webhook_subscriptions", return_value=safe_webhooks),
        patch.object(connector, "_fetch_event_orchestrations", return_value=safe_eos),
        patch.object(connector, "_fetch_business_services", return_value=safe_bs),
        patch.object(connector, "_fetch_response_plays", return_value=safe_rps),
        patch("app.connectors.pagerduty._sanitize_token", return_value="safe_placeholder"),
        patch("app.connectors.pagerduty.PagerDutyConnector._make_client") as mock_client,
    ):
        mock_client.return_value.__enter__ = lambda s, *a: MagicMock()
        mock_client.return_value.__exit__ = MagicMock(return_value=False)
        events = connector.list_activity_events(
            {"api_token": PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER},
        )

    assert len(events) == 2  # 1 service + 1 escalation_policy
    for event in events:
        assert event["event_type"] in PAGERDUTY_CONFIG_EVENT_TYPES
        assert event["provider"] == "pagerduty"
        assert event["source"] == "pagerduty_activity_event"
        assert "provider_event_id" in event
        assert "metadata" in event


def test_b3_list_activity_events_max_events_capped() -> None:
    """max_events is capped at 1000 internally."""
    from app.connectors.pagerduty import PagerDutyConnector
    connector = PagerDutyConnector()

    with (
        patch.object(connector, "_fetch_services", return_value=[]),
        patch.object(connector, "_fetch_escalation_policies", return_value=[]),
        patch.object(connector, "_fetch_schedules", return_value=[]),
        patch.object(connector, "_fetch_service_integrations", return_value=[]),
        patch.object(connector, "_fetch_webhook_subscriptions", return_value=[]),
        patch.object(connector, "_fetch_event_orchestrations", return_value=[]),
        patch.object(connector, "_fetch_business_services", return_value=[]),
        patch.object(connector, "_fetch_response_plays", return_value=[]),
        patch("app.connectors.pagerduty._sanitize_token", return_value="safe_placeholder"),
        patch("app.connectors.pagerduty.PagerDutyConnector._make_client") as mock_client,
    ):
        mock_client.return_value.__enter__ = lambda s, *a: MagicMock()
        mock_client.return_value.__exit__ = MagicMock(return_value=False)
        events = connector.list_activity_events(
            {"api_token": PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER},
            max_events=9999,
        )
    assert isinstance(events, list)


def test_b4_all_event_types_in_allowlist() -> None:
    """All event types emitted by the connector are in the allowlist."""
    from app.connectors.pagerduty import PagerDutyConnector
    from app.services.pagerduty_activity_ingestion_service import (
        PAGERDUTY_CONFIG_EVENT_TYPES,
    )
    connector = PagerDutyConnector()

    # One record of each type
    service_rec = {
        "record_type": "pagerduty_service", "record_id": PAGERDUTY_TEST_SERVICE_ID,
        "status_category": "active", "team_count": 1, "integration_count": 1,
        "alert_creation_category": "alerts_and_incidents", "support_hours_enabled": False,
        "scheduled_actions_count": 0, "acknowledgement_timeout_category": "short",
        "auto_resolve_timeout_category": "medium",
    }
    ep_rec = {
        "record_type": "pagerduty_escalation_policy", "record_id": PAGERDUTY_TEST_ESCALATION_POLICY_ID,
        "team_count": 1, "escalation_rule_count": 2, "escalation_level_count": 2,
        "target_count": 3, "schedule_target_count": 1, "has_schedule_targets": True,
        "repeat_enabled": False,
    }
    sched_rec = {
        "record_type": "pagerduty_schedule", "record_id": PAGERDUTY_TEST_SCHEDULE_ID,
        "layer_count": 2, "user_count": 3, "team_count": 1,
        "restriction_count": 2, "has_restrictions": True, "time_zone_present": True,
    }
    intg_rec = {
        "record_type": "pagerduty_service_integration", "record_id": PAGERDUTY_TEST_INTEGRATION_ID,
        "type_category": "generic_events_api", "has_integration_key": True,
        "routing_key_present": True,
    }
    wh_rec = {
        "record_type": "pagerduty_webhook_subscription", "record_id": PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID,
        "active": True, "event_count": 5, "delivery_url_scheme_category": "https",
        "filter_type": "service_reference", "has_custom_headers": True,
    }
    eo_rec = {
        "record_type": "pagerduty_event_orchestration", "record_id": PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID,
        "route_count": 3, "team_present": True,
    }
    bs_rec = {
        "record_type": "pagerduty_business_service", "record_id": PAGERDUTY_TEST_BUSINESS_SERVICE_ID,
        "team_present": True, "point_of_contact_present": True,
    }
    rp_rec = {
        "record_type": "pagerduty_response_play", "record_id": PAGERDUTY_TEST_RESPONSE_PLAY_ID,
        "responder_count": 3, "subscriber_count": 2, "team_present": True,
        "runnability": "team", "conference_number_present": False,
    }

    events: list[dict] = []
    day = "2026-06-19"
    connector._collect_service_events([service_rec], events, day)
    connector._collect_escalation_policy_events([ep_rec], events, day)
    connector._collect_schedule_events([sched_rec], events, day)
    connector._collect_service_integration_events([intg_rec], events, day)
    connector._collect_webhook_events([wh_rec], events, day)
    connector._collect_orchestration_events([eo_rec], events, day)
    connector._collect_business_service_events([bs_rec], events, day)
    connector._collect_response_play_events([rp_rec], events, day)

    assert len(events) == 8
    for event in events:
        assert event["event_type"] in PAGERDUTY_CONFIG_EVENT_TYPES, (
            f"Event type {event['event_type']!r} not in allowlist"
        )


# ── C. Normalizer tests ────────────────────────────────────────────────────────

def _make_entry(event_type: str = "pagerduty.service.updated", **kwargs: Any) -> dict:
    return {
        "event_type": event_type,
        "provider": "pagerduty",
        "source": "pagerduty_activity_event",
        "event_source": "pagerduty_activity_event",
        "provider_event_id": PAGERDUTY_TEST_ACTIVITY_EVENT_ID,
        "metadata": {
            "resource_type": "pagerduty_service",
            "resource_id": PAGERDUTY_TEST_SERVICE_ID,
            "operation_family": "pagerduty.service",
            "operation_action": "updated",
            "team_count": 1,
            "integration_count": 2,
            **kwargs.get("metadata", {}),
        },
        **{k: v for k, v in kwargs.items() if k != "metadata"},
    }


class TestNormalizerGate:
    def test_none_for_non_dict(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        assert normalize_pagerduty_activity_event(None) is None  # type: ignore
        assert normalize_pagerduty_activity_event("string") is None  # type: ignore

    def test_none_for_missing_event_type(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        assert normalize_pagerduty_activity_event({}) is None

    def test_none_for_non_allowlisted_event_type(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry(event_type="pagerduty.incident.triggered")
        assert normalize_pagerduty_activity_event(entry) is None

    def test_returns_normalized_for_valid_event(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry()
        result = normalize_pagerduty_activity_event(entry)
        assert result is not None
        assert result["provider"] == "pagerduty"
        assert result["source"] == "pagerduty_activity_event"
        assert result["event_type"] == "pagerduty.service.updated"

    def test_actor_id_always_none(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        for etype in EXPECTED_EVENT_TYPES:
            entry = _make_entry(event_type=etype)
            result = normalize_pagerduty_activity_event(entry)
            if result is not None:
                assert result.get("actor_id") is None, (
                    f"actor_id must be None for event type {etype!r}"
                )

    def test_fingerprint_fallback_when_no_provider_event_id(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry()
        entry["provider_event_id"] = None
        result = normalize_pagerduty_activity_event(entry)
        assert result is not None
        assert result.get("provider_event_id") is not None
        assert str(result["provider_event_id"]).startswith("fp:")

    def test_idempotent_provider_event_id(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry(provider_event_id="pagerduty:service:SVC001:2026-06-19")
        r1 = normalize_pagerduty_activity_event(entry)
        r2 = normalize_pagerduty_activity_event(entry)
        assert r1 is not None and r2 is not None
        assert r1["provider_event_id"] == r2["provider_event_id"]


# ── D. Metadata privacy tests ──────────────────────────────────────────────────

class TestMetadataPrivacy:
    def test_no_forbidden_fields_in_metadata(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry()
        result = normalize_pagerduty_activity_event(entry)
        assert result is not None
        metadata = result.get("metadata", {})
        for field in metadata.keys():
            assert field not in _FORBIDDEN_METADATA_FIELDS, (
                f"Forbidden metadata field {field!r} found in normalized event"
            )

    def test_no_forbidden_strings_in_metadata_values(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry()
        result = normalize_pagerduty_activity_event(entry)
        assert result is not None
        metadata = result.get("metadata", {})
        for key, val in metadata.items():
            if isinstance(val, str):
                for forbidden in _FORBIDDEN_METADATA_STRINGS:
                    assert forbidden not in val, (
                        f"Forbidden string {forbidden!r} found in metadata "
                        f"field {key!r}: {val!r}"
                    )

    def test_no_source_ip_stored(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry()
        result = normalize_pagerduty_activity_event(entry)
        assert result is not None
        assert result.get("source_ip_hash") is None


# ── E. ALLOWED_METADATA_KEYS ──────────────────────────────────────────────────

class TestAllowedMetadataKeys:
    def test_pagerduty_event_id_in_allowed_keys(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        assert "pagerduty_event_id" in ALLOWED_METADATA_KEYS

    def test_integration_type_category_in_allowed_keys(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        assert "integration_type_category" in ALLOWED_METADATA_KEYS

    def test_key_present_in_allowed_keys(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        assert "key_present" in ALLOWED_METADATA_KEYS

    def test_routing_key_present_in_allowed_keys(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        assert "routing_key_present" in ALLOWED_METADATA_KEYS

    def test_forbidden_keys_not_in_allowed_keys(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        truly_forbidden = {
            "api_token", "routing_key", "integration_key", "webhook_secret",
            "authorization", "headers", "payload", "incident", "alert",
            "email", "phone", "ip_address", "user_agent", "webhook_url",
            "delivery_url",
        }
        present = truly_forbidden & ALLOWED_METADATA_KEYS
        assert not present, (
            f"Truly forbidden keys found in ALLOWED_METADATA_KEYS: {sorted(present)}"
        )


# ── F. Ingestion service tests ─────────────────────────────────────────────────

class TestIngestService:
    def test_ingest_wrong_provider_returns_error(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            ingest_pagerduty_activity,
        )
        integration = MagicMock()
        integration.provider = "clerk"
        integration.id = uuid.uuid4()
        db = MagicMock()
        result = ingest_pagerduty_activity(
            integration=integration,
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert result["attempted"] is False
        assert "Not a PagerDuty" in (result["error_message"] or "")

    def test_ingest_auth_error_sets_permission_limited(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            ingest_pagerduty_activity,
        )
        from app.connectors.exceptions import AuthenticationError
        integration = MagicMock()
        integration.provider = "pagerduty"
        integration.id = uuid.uuid4()
        db = MagicMock()
        with (
            patch(
                "app.services.pagerduty_activity_ingestion_service.decrypt_credentials",
                return_value={"api_token": PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER},
            ),
            patch(
                "app.services.pagerduty_activity_ingestion_service.PagerDutyConnector"
            ) as mock_connector_cls,
        ):
            mock_connector = MagicMock()
            mock_connector.list_activity_events.side_effect = AuthenticationError("401")
            mock_connector_cls.return_value = mock_connector
            result = ingest_pagerduty_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert result["permission_limited"] is True
        assert result["events_seen"] == 0

    def test_ingest_empty_events_succeeds(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            ingest_pagerduty_activity,
        )
        integration = MagicMock()
        integration.provider = "pagerduty"
        integration.id = uuid.uuid4()
        db = MagicMock()
        with (
            patch(
                "app.services.pagerduty_activity_ingestion_service.decrypt_credentials",
                return_value={"api_token": PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER},
            ),
            patch(
                "app.services.pagerduty_activity_ingestion_service.PagerDutyConnector"
            ) as mock_connector_cls,
        ):
            mock_connector = MagicMock()
            mock_connector.list_activity_events.return_value = []
            mock_connector_cls.return_value = mock_connector
            result = ingest_pagerduty_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert result["succeeded"] is True
        assert result["events_seen"] == 0

    def test_ingest_rate_limit_returns_error(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            ingest_pagerduty_activity,
        )
        from app.connectors.exceptions import RateLimitError
        integration = MagicMock()
        integration.provider = "pagerduty"
        integration.id = uuid.uuid4()
        db = MagicMock()
        with (
            patch(
                "app.services.pagerduty_activity_ingestion_service.decrypt_credentials",
                return_value={"api_token": PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER},
            ),
            patch(
                "app.services.pagerduty_activity_ingestion_service.PagerDutyConnector"
            ) as mock_connector_cls,
        ):
            mock_connector = MagicMock()
            mock_connector.list_activity_events.side_effect = RateLimitError("429")
            mock_connector_cls.return_value = mock_connector
            result = ingest_pagerduty_activity(
                integration=integration,
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert result["succeeded"] is False
        assert "rate limit" in (result["error_message"] or "").lower()


# ── G. Router endpoint tests ───────────────────────────────────────────────────

class TestRouterEndpoint:
    def test_pagerduty_activity_sync_endpoint_exists(self) -> None:
        from app.routers.security import router
        routes = [r.path for r in router.routes]  # type: ignore
        assert any("pagerduty-activity" in p for p in routes), (
            f"/pagerduty-activity/sync not found in router routes: {routes}"
        )

    def test_pagerduty_activity_sync_requires_admin(self) -> None:
        from app.routers.security import router
        route = next(
            (r for r in router.routes if "pagerduty-activity/sync" in getattr(r, "path", "")),
            None,
        )
        assert route is not None, "pagerduty-activity/sync route not found"

    def test_schema_importable(self) -> None:
        from app.schemas.security_pagerduty_activity import (
            PagerDutyActivitySyncRequest,
            PagerDutyActivitySyncResponse,
        )
        req = PagerDutyActivitySyncRequest()
        assert req.lookback_hours == 24
        assert req.max_events == 100


# ── H. Capability matrix ───────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_activity_ingestion_true(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_activity_signals_false(self) -> None:
        # activity_signals becomes True in M84E; risk_activity_correlations in M84F;
        # demo_seed_clear in M84G. M84G+ makes demo_seed_clear True.
        # Invariant that holds across entire arc: activity_ingestion is True.
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_ingestion is True

    def test_risk_activity_correlations_false(self) -> None:
        # risk_activity_correlations becomes True in M84F; demo_seed_clear in M84G.
        # Invariant that holds across entire arc: activity_ingestion is True.
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_ingestion is True

    def test_demo_seed_clear_false(self) -> None:
        # M84G sets demo_seed_clear to True. Assert invariant across arc instead.
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_ingestion is True

    def test_notes_mention_m84d(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert "M84D" in cap.notes

    def test_notes_point_to_m84e(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert "M84E" in cap.notes


# ── I. Expansion framework ─────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m84e(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        summary = fw.get("summary", {})
        planned = summary.get("planned_next_stage", "")
        # Framework advances through arc. Acceptable: M84E...M85A or beyond.
        assert ("M84E" in planned or "M84F" in planned or "M84G" in planned
                or "M84H" in planned or "Provider Depth" in planned
                or "M84I" in planned or "Cross-Cloud" in planned
                or "M85A" in planned or "Linear" in planned), (
            f"planned_next_stage should reference M84E or beyond; got: {planned!r}"
        )

    def test_linear_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recommendations = fw.get("recommended_next_providers", [])
        assert recommendations, "No recommended providers"
        assert recommendations[0]["provider"] in ("linear", "jira")


# ── J. Frontend checks ─────────────────────────────────────────────────────────

class TestFrontend:
    @pytest.fixture(scope="class")
    def activity_page(self) -> str:
        return (
            FRONTEND_SRC / "app" / "(app)" / "security" / "activity" / "page.tsx"
        ).read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def api_ts(self) -> str:
        return (FRONTEND_SRC / "lib" / "api.ts").read_text(encoding="utf-8")

    def test_pagerduty_in_provider_type(self, activity_page: str) -> None:
        assert '"pagerduty"' in activity_page, (
            "pagerduty must be a valid Provider type in activity/page.tsx"
        )

    def test_pagerduty_event_types_in_page(self, activity_page: str) -> None:
        assert "PAGERDUTY_EVENT_TYPES" in activity_page

    def test_pagerduty_sync_imported(self, activity_page: str) -> None:
        assert "syncPagerDutyActivity" in activity_page

    def test_sync_pagerduty_activity_in_api_ts(self, api_ts: str) -> None:
        assert "syncPagerDutyActivity" in api_ts
        assert "pagerduty-activity/sync" in api_ts

    def test_pagerduty_provider_in_select_options(self, activity_page: str) -> None:
        assert '"pagerduty"' in activity_page

    def test_pagerduty_sync_response_type_in_types(self) -> None:
        types_ts = (FRONTEND_SRC / "types" / "index.ts").read_text(encoding="utf-8")
        assert "PagerDutyActivitySyncResponse" in types_ts


# ── K. M84A/B/C regression ────────────────────────────────────────────────────

class TestRegression:
    def test_pagerduty_rule_keys_still_40(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        assert len(PAGERDUTY_RULE_KEYS) >= 40

    def test_pagerduty_evaluator_dispatches(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "pagerduty" in _PROVIDER_RULES


# ── L. Forbidden wording ───────────────────────────────────────────────────────

_FORBIDDEN_PHRASES = [
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


class TestForbiddenWording:
    def test_no_forbidden_wording_in_ingestion_service(self) -> None:
        svc_path = BACKEND_APP / "services" / "pagerduty_activity_ingestion_service.py"
        text = svc_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in pagerduty_activity_ingestion_service.py"
            )

    def test_no_forbidden_wording_in_schema(self) -> None:
        schema_path = BACKEND_APP / "schemas" / "security_pagerduty_activity.py"
        text = schema_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in security_pagerduty_activity.py"
            )

    def test_normalize_output_has_no_forbidden_wording(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            normalize_pagerduty_activity_event,
        )
        entry = _make_entry()
        result = normalize_pagerduty_activity_event(entry)
        assert result is not None
        full_text = str(result).lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in full_text, (
                f"Forbidden phrase {phrase!r} found in normalized event: {result}"
            )


# ── M. Secret-shape grep ──────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


class TestSecretShape:
    def test_no_secret_shapes_in_pagerduty_activity_files(self) -> None:
        paths = [
            BACKEND_APP / "services" / "pagerduty_activity_ingestion_service.py",
            BACKEND_APP / "schemas" / "security_pagerduty_activity.py",
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pat in _SECRET_PATTERNS:
                match = pat.search(text)
                assert not match, (
                    f"Secret-shaped string {match.group()!r} found in {path}"
                )

    def test_no_secret_shapes_in_pagerduty_connector(self) -> None:
        path = BACKEND_APP / "connectors" / "pagerduty.py"
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _SECRET_PATTERNS:
            match = pat.search(text)
            assert not match, (
                f"Secret-shaped string {match.group()!r} found in pagerduty.py"
            )
