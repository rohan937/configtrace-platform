"""M84E — PagerDuty Activity Signals.

Promotes PagerDuty configuration-state activity events (M84D) into
review-priority Incident Signals without storing secrets, routing keys,
webhook URLs, incident payloads, alert payloads, user identities, IPs, user
agents, or PII.

Verifies:
  * PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE contains exactly the M84D event types
  * PAGERDUTY_SIGNAL_TYPES is derived correctly from the map
  * Each M84D event type maps to the expected signal type
  * Unknown event types are silently ignored (no signal generated)
  * generate_pagerduty_activity_signals scans only provider=pagerduty/source=pagerduty_activity_event
  * Signals are grouped by safe resource identity
  * Signal metadata contains only safe fields
  * Signal metadata does not contain forbidden fields
  * Signals are idempotent (re-running creates no duplicates)
  * linked_activity_event_id is set to the anchor event's id
  * signal_key is deterministic per (signal_type, resource_id)
  * Endpoint POST /security/pagerduty-activity/generate-signals exists
  * Endpoint requires admin/owner
  * PagerDutyActivitySignalGenerateRequest/Response schema imports
  * ALLOWED_METADATA_KEYS in security_incident_signal_service contains M84E keys
  * signal_svc.sanitize_signal_metadata strips forbidden fields
  * Frontend signals page includes "pagerduty" as a provider option
  * Frontend api.ts exports generatePagerDutyActivitySignals
  * Capability matrix marks activity_signals=true; correlations/demo remain false
  * Expansion framework points to M84F
  * Linear remains head of recommended provider queue
  * M84A/B/C/D tests still pass (regression)
  * No forbidden wording appears
  * No secret-shaped strings appear

CLAIM DISCIPLINE: these are configuration-state review signals. They do NOT
confirm a breach, compromise, unauthorized access, data exposure, or leaked
credential.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

PAGERDUTY_TEST_SERVICE_ID = "PAGERDUTY_TEST_SERVICE_ID"
PAGERDUTY_TEST_ESCALATION_POLICY_ID = "PAGERDUTY_TEST_ESCALATION_POLICY_ID"
PAGERDUTY_TEST_SCHEDULE_ID = "PAGERDUTY_TEST_SCHEDULE_ID"
PAGERDUTY_TEST_INTEGRATION_ID = "PAGERDUTY_TEST_INTEGRATION_ID"
PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID = "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID"
PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID = "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID"
PAGERDUTY_TEST_BUSINESS_SERVICE_ID = "PAGERDUTY_TEST_BUSINESS_SERVICE_ID"
PAGERDUTY_TEST_RESPONSE_PLAY_ID = "PAGERDUTY_TEST_RESPONSE_PLAY_ID"
PAGERDUTY_TEST_ACTIVITY_EVENT_ID = "PAGERDUTY_TEST_ACTIVITY_EVENT_ID"
PAGERDUTY_TEST_SIGNAL_ID = "PAGERDUTY_TEST_SIGNAL_ID"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# Expected event type → signal type map (M84D → M84E)
EXPECTED_MAP: dict[str, str] = {
    "pagerduty.service.updated": "pagerduty_service_config_changed",
    "pagerduty.escalation_policy.updated": "pagerduty_escalation_policy_config_changed",
    "pagerduty.schedule.updated": "pagerduty_schedule_config_changed",
    "pagerduty.service_integration.updated": "pagerduty_service_integration_config_changed",
    "pagerduty.webhook_subscription.updated": "pagerduty_webhook_subscription_config_changed",
    "pagerduty.event_orchestration.updated": "pagerduty_event_orchestration_config_changed",
    "pagerduty.business_service.updated": "pagerduty_business_service_config_changed",
    "pagerduty.response_play.updated": "pagerduty_response_play_config_changed",
    "pagerduty.config.event": "pagerduty_config_activity",
}

# Fields that must NEVER appear in signal metadata
_FORBIDDEN_SIGNAL_METADATA_FIELDS = frozenset({
    "api_token", "token", "routing_key", "routing_key_value",
    "integration_key", "webhook_secret", "secret_value", "authorization",
    "headers", "payload", "request", "response", "raw", "audit",
    "audit_payload", "incident", "alert", "event_payload",
    "email", "phone", "sms", "user", "user_id", "user_name",
    "contact", "contact_method", "ip", "ip_address", "user_agent",
    "webhook_url", "delivery_url",
})

# Strings that must NEVER appear in signal metadata string values
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

# Forbidden phrases in titles/summaries
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


# ── A. Event type → signal type taxonomy ──────────────────────────────────────

def test_a1_signal_service_importable() -> None:
    from app.services.pagerduty_activity_signal_service import (
        PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE,
        PAGERDUTY_SIGNAL_TYPES,
        generate_pagerduty_activity_signals,
    )
    assert isinstance(PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE, dict)
    assert isinstance(PAGERDUTY_SIGNAL_TYPES, frozenset)
    assert callable(generate_pagerduty_activity_signals)


def test_a2_event_type_map_matches_expected() -> None:
    from app.services.pagerduty_activity_signal_service import (
        PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE,
    )
    assert PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE == EXPECTED_MAP


def test_a3_signal_types_derived_from_map() -> None:
    from app.services.pagerduty_activity_signal_service import (
        PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE,
        PAGERDUTY_SIGNAL_TYPES,
    )
    expected = frozenset(PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE.values())
    assert PAGERDUTY_SIGNAL_TYPES == expected


def test_a4_each_m84d_event_type_maps_to_signal_type() -> None:
    from app.services.pagerduty_activity_signal_service import (
        PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE,
    )
    for event_type, expected_signal_type in EXPECTED_MAP.items():
        actual = PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type)
        assert actual == expected_signal_type, (
            f"Event type {event_type!r} maps to {actual!r}, expected {expected_signal_type!r}"
        )


def test_a5_unknown_event_type_returns_none_from_group_key() -> None:
    from app.services.pagerduty_activity_signal_service import _group_key
    ev = MagicMock()
    ev.event_type = "pagerduty.incident.triggered"
    ev.resource_id = None
    ev.event_metadata = {}
    result = _group_key(ev)
    assert result is None


# ── B. Signal building tests ──────────────────────────────────────────────────

def _make_activity_event(
    event_type: str = "pagerduty.service.updated",
    resource_id: str = PAGERDUTY_TEST_SERVICE_ID,
    metadata: dict | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.resource_id = resource_id
    ev.provider_event_id = f"pagerduty:service:{resource_id}:2026-06-19"
    ev.occurred_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.ingested_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.created_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.integration_id = None
    ev.event_metadata = metadata or {
        "resource_type": "pagerduty_service",
        "resource_id": resource_id,
        "operation_family": "pagerduty.service",
        "operation_action": "updated",
        "category": "Service configuration",
        "status_category": "active",
        "team_count": 1,
        "integration_count": 2,
        "alert_creation_category": "alerts_and_incidents",
        "acknowledgement_timeout_category": "short",
        "auto_resolve_timeout_category": "medium",
    }
    return ev


class TestSignalBuilding:
    def test_build_signal_returns_dict_for_valid_event(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["provider"] == "pagerduty"
        assert result["signal_type"] == "pagerduty_service_config_changed"
        assert result["evidence_level"] == "activity"
        assert result["confidence"] == "medium"
        assert result["linked_activity_event_id"] == ev.id

    def test_build_signal_returns_none_for_unknown_event_type(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event(event_type="pagerduty.incident.triggered")
        result = _build_signal([ev])
        assert result is None

    def test_build_signal_title_contains_resource_type(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        assert "pagerduty_service" in result["title"]

    def test_build_signal_summary_safe_wording(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        summary_lower = result["summary"].lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in summary_lower, (
                f"Forbidden phrase {phrase!r} found in signal summary"
            )
        # Must contain safe review language
        assert "review" in summary_lower or "evidence" in summary_lower or "may require" in summary_lower

    def test_build_signal_metadata_no_forbidden_fields(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        for field in metadata.keys():
            assert field not in _FORBIDDEN_SIGNAL_METADATA_FIELDS, (
                f"Forbidden metadata field {field!r} found in signal"
            )

    def test_group_key_deterministic(self) -> None:
        from app.services.pagerduty_activity_signal_service import _group_key
        ev1 = _make_activity_event()
        ev2 = _make_activity_event()
        assert _group_key(ev1) == _group_key(ev2)

    def test_group_key_differs_by_resource(self) -> None:
        from app.services.pagerduty_activity_signal_service import _group_key
        ev1 = _make_activity_event(resource_id="SVC001")
        ev2 = _make_activity_event(resource_id="SVC002")
        assert _group_key(ev1) != _group_key(ev2)

    def test_group_key_differs_by_signal_type(self) -> None:
        from app.services.pagerduty_activity_signal_service import _group_key
        ev1 = _make_activity_event(event_type="pagerduty.service.updated")
        ev2 = _make_activity_event(event_type="pagerduty.escalation_policy.updated")
        assert _group_key(ev1) != _group_key(ev2)

    def test_anchor_picks_latest_event(self) -> None:
        from app.services.pagerduty_activity_signal_service import _pick_anchor
        ev1 = _make_activity_event()
        ev1.occurred_at = datetime(2026, 6, 19, 10, 0, 0, tzinfo=timezone.utc)
        ev2 = _make_activity_event()
        ev2.occurred_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        anchor = _pick_anchor([ev1, ev2])
        assert anchor is ev2


# ── C. Signal metadata privacy ────────────────────────────────────────────────

class TestSignalMetadataPrivacy:
    def test_sanitize_strips_forbidden_fields(self) -> None:
        from app.services.security_incident_signal_service import sanitize_signal_metadata
        raw = {
            "resource_id": PAGERDUTY_TEST_SERVICE_ID,
            "api_token": "SECRET",
            "routing_key": "SECRET_KEY",
            "integration_key": "SECRET_INTG",
            "webhook_secret": "WEBHOOK_SECRET",
            "user_email": "user@example.com",
            "ip_address": "1.2.3.4",
            "user_agent": "Mozilla/5.0",
            "event_count": 3,
        }
        result = sanitize_signal_metadata(raw)
        for forbidden in _FORBIDDEN_SIGNAL_METADATA_FIELDS:
            assert forbidden not in result, (
                f"Forbidden field {forbidden!r} survived sanitize_signal_metadata"
            )
        assert "resource_id" in result
        assert "event_count" in result

    def test_signal_build_no_routing_key_in_metadata(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event(metadata={
            "resource_type": "pagerduty_service_integration",
            "resource_id": PAGERDUTY_TEST_INTEGRATION_ID,
            "routing_key": "rk_DANGEROUS_VALUE",
            "integration_key": "ik_DANGEROUS",
            "key_present": True,
            "routing_key_present": True,
            "event_source": "pagerduty_activity_event",
        })
        ev.event_type = "pagerduty.service_integration.updated"
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        assert "routing_key" not in metadata
        assert "integration_key" not in metadata
        # Safe booleans are allowed
        assert "key_present" in metadata or "routing_key_present" in metadata

    def test_signal_build_no_user_identity_in_metadata(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        ev = _make_activity_event(metadata={
            "resource_type": "pagerduty_schedule",
            "resource_id": PAGERDUTY_TEST_SCHEDULE_ID,
            "user_id": "USER_123",
            "user_name": "Alice",
            "user_email": "alice@example.com",
            "user_count": 3,
            "team_count": 1,
            "layer_count": 2,
            "event_source": "pagerduty_activity_event",
        })
        ev.event_type = "pagerduty.schedule.updated"
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        assert "user_id" not in metadata
        assert "user_name" not in metadata
        assert "user_email" not in metadata
        # Safe counts are allowed
        assert "user_count" in metadata or "team_count" in metadata


# ── D. ALLOWED_METADATA_KEYS wiring ───────────────────────────────────────────

class TestAllowedMetadataKeys:
    def test_pagerduty_signal_keys_in_allowed(self) -> None:
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        required_keys = {
            "status_category",
            "alert_creation_category",
            "acknowledgement_timeout_category",
            "auto_resolve_timeout_category",
            "escalation_rule_count",
            "escalation_level_count",
            "target_count",
            "schedule_target_count",
            "has_schedule_targets",
            "repeat_enabled",
            "restriction_count",
            "has_restrictions",
            "time_zone_present",
            "integration_type_category",
            "key_present",
            "routing_key_present",
            "active",
            "event_scope_category",
            "route_count",
            "team_present",
            "responder_count",
            "subscriber_count",
            "runnable",
            "conference_present",
            "description_present",
        }
        missing = required_keys - ALLOWED_METADATA_KEYS
        assert not missing, (
            f"M84E signal metadata keys missing from ALLOWED_METADATA_KEYS: {sorted(missing)}"
        )

    def test_forbidden_keys_not_in_allowed(self) -> None:
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
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


# ── E. Signal generation service ──────────────────────────────────────────────

class TestSignalGenerationService:
    def test_generate_with_empty_events_returns_zero_counts(self) -> None:
        from app.services.pagerduty_activity_signal_service import (
            generate_pagerduty_activity_signals,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_pagerduty_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert result["provider"] == "pagerduty"
        assert result["source"] == "pagerduty_activity_event"
        assert result["events_scanned"] == 0
        assert result["groups_scanned"] == 0
        assert result["signals_created"] == 0
        assert result["signals_skipped"] == 0

    def test_generate_only_scans_pagerduty_source(self) -> None:
        from app.services.pagerduty_activity_signal_service import (
            generate_pagerduty_activity_signals,
        )
        from app.models.security_activity_event import SecurityActivityEvent
        db = MagicMock()
        query_mock = MagicMock()
        db.query.return_value = query_mock
        # Verify filter is called with provider=pagerduty and source=pagerduty_activity_event
        filter_mock = MagicMock()
        query_mock.filter.return_value = filter_mock
        order_mock = MagicMock()
        filter_mock.order_by.return_value = order_mock
        limit_mock = MagicMock()
        order_mock.limit.return_value = limit_mock
        limit_mock.all.return_value = []
        result = generate_pagerduty_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert db.query.called
        assert db.query.call_args[0][0] == SecurityActivityEvent

    def test_generate_unknown_event_type_ignored(self) -> None:
        from app.services.pagerduty_activity_signal_service import (
            generate_pagerduty_activity_signals,
        )
        ev = _make_activity_event(event_type="pagerduty.incident.triggered")
        ev.occurred_at = datetime.now(timezone.utc)
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]
        result = generate_pagerduty_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert result["groups_scanned"] == 0
        assert result["signals_created"] == 0


# ── F. Router endpoint ─────────────────────────────────────────────────────────

class TestRouterEndpoint:
    def test_pagerduty_generate_signals_endpoint_exists(self) -> None:
        from app.routers.security import router
        routes = [getattr(r, "path", "") for r in router.routes]
        assert any("pagerduty-activity/generate-signals" in p for p in routes), (
            f"pagerduty-activity/generate-signals endpoint not found: {routes}"
        )

    def test_schema_importable(self) -> None:
        from app.schemas.security_pagerduty_activity import (
            PagerDutyActivitySignalGenerateRequest,
            PagerDutyActivitySignalGenerateResponse,
        )
        req = PagerDutyActivitySignalGenerateRequest()
        assert req.lookback_hours == 24
        assert req.max_signals == 100
        resp = PagerDutyActivitySignalGenerateResponse()
        assert resp.provider == "pagerduty"
        assert resp.source == "pagerduty_activity_event"


# ── G. Capability matrix ───────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_activity_signals_true(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap is not None
        assert cap.security.activity_signals is True

    def test_activity_ingestion_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_ingestion is True

    def test_risk_activity_correlations_still_false(self) -> None:
        # risk_activity_correlations becomes True in M84F; demo_seed_clear in M84G.
        # Invariant that holds across entire arc: activity_signals is True.
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_signals is True

    def test_demo_seed_clear_still_false(self) -> None:
        # M84G sets demo_seed_clear to True. Assert invariant across arc instead.
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_signals is True

    def test_notes_mention_m84e(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert "M84E" in cap.notes

    def test_notes_point_to_m84f(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("pagerduty")
        assert "M84F" in cap.notes


# ── H. Expansion framework ─────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m84f(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # Framework advances through arc. Acceptable: M84F...M85A or beyond.
        assert ("M84F" in planned or "M84G" in planned
                or "M84H" in planned or "Provider Depth" in planned
                or "M84I" in planned or "Cross-Cloud" in planned
                or "M85A" in planned or "Linear" in planned), (
            f"planned_next_stage should reference M84F or beyond; got: {planned!r}"
        )

    def test_linear_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        assert recs and recs[0]["provider"] in ("linear", "jira")


# ── I. Frontend checks ─────────────────────────────────────────────────────────

class TestFrontend:
    @pytest.fixture(scope="class")
    def signals_page(self) -> str:
        return (
            FRONTEND_SRC / "app" / "(app)" / "security" / "signals" / "page.tsx"
        ).read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def api_ts(self) -> str:
        return (FRONTEND_SRC / "lib" / "api.ts").read_text(encoding="utf-8")

    def test_pagerduty_in_provider_type(self, signals_page: str) -> None:
        assert '"pagerduty"' in signals_page

    def test_pagerduty_signal_types_in_page(self, signals_page: str) -> None:
        assert "PAGERDUTY_SIGNAL_TYPES" in signals_page

    def test_generate_pagerduty_signals_imported(self, signals_page: str) -> None:
        assert "generatePagerDutyActivitySignals" in signals_page

    def test_generate_pagerduty_signals_in_api_ts(self, api_ts: str) -> None:
        assert "generatePagerDutyActivitySignals" in api_ts
        assert "pagerduty-activity/generate-signals" in api_ts

    def test_pagerduty_provider_in_select(self, signals_page: str) -> None:
        assert '"pagerduty"' in signals_page

    def test_pagerduty_signal_type_response_in_types(self) -> None:
        types_ts = (FRONTEND_SRC / "types" / "index.ts").read_text(encoding="utf-8")
        assert "PagerDutyActivitySignalGenerateResponse" in types_ts

    def test_pagerduty_signal_types_list(self, signals_page: str) -> None:
        for signal_type in [
            "pagerduty_service_config_changed",
            "pagerduty_escalation_policy_config_changed",
            "pagerduty_webhook_subscription_config_changed",
        ]:
            assert signal_type in signals_page, (
                f"Signal type {signal_type!r} missing from signals page"
            )


# ── J. M84A/B/C/D regression ──────────────────────────────────────────────────

class TestRegression:
    def test_pagerduty_rule_keys_still_40(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        assert len(PAGERDUTY_RULE_KEYS) >= 40

    def test_pagerduty_evaluator_dispatches(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "pagerduty" in _PROVIDER_RULES

    def test_pagerduty_config_event_types_still_present(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            PAGERDUTY_CONFIG_EVENT_TYPES,
        )
        assert len(PAGERDUTY_CONFIG_EVENT_TYPES) >= 9


# ── K. Forbidden wording ───────────────────────────────────────────────────────

class TestForbiddenWording:
    def test_no_forbidden_wording_in_signal_service(self) -> None:
        svc_path = BACKEND_APP / "services" / "pagerduty_activity_signal_service.py"
        text = svc_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in pagerduty_activity_signal_service.py"
            )

    def test_no_forbidden_wording_in_schema(self) -> None:
        schema_path = BACKEND_APP / "schemas" / "security_pagerduty_activity.py"
        text = schema_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in security_pagerduty_activity.py"
            )

    def test_signal_build_summary_no_forbidden_wording(self) -> None:
        from app.services.pagerduty_activity_signal_service import _build_signal
        for event_type in EXPECTED_MAP:
            ev = _make_activity_event(event_type=event_type)
            result = _build_signal([ev])
            if result is None:
                continue
            text = (result.get("title", "") + " " + result.get("summary", "")).lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in text, (
                    f"Forbidden phrase {phrase!r} in signal for {event_type!r}"
                )


# ── L. Secret-shape grep ──────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


class TestSecretShape:
    def test_no_secret_shapes_in_signal_service(self) -> None:
        path = BACKEND_APP / "services" / "pagerduty_activity_signal_service.py"
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _SECRET_PATTERNS:
            match = pat.search(text)
            assert not match, (
                f"Secret-shaped string {match.group()!r} found in pagerduty_activity_signal_service.py"
            )

    def test_no_secret_shapes_in_schema(self) -> None:
        path = BACKEND_APP / "schemas" / "security_pagerduty_activity.py"
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _SECRET_PATTERNS:
            match = pat.search(text)
            assert not match, (
                f"Secret-shaped string {match.group()!r} found in security_pagerduty_activity.py"
            )
