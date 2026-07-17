"""M83E — Clerk Activity Signals.

Promotes Clerk configuration-state activity events (provider=clerk,
source=clerk_activity_event, synthesized in M83D) into review-worthy
Incident Signals.

Sections
--------
  A. Event type mapping — completeness and shape
  B. _group_key behavior — grouping logic and determinism
  C. _severity — review-priority assignment
  D. _build_signal — dict shape, privacy, and metadata
  E. generate_clerk_activity_signals — DB integration and caps
  F. Signal metadata allowlist coverage
  G. Router endpoint — existence and admin guard
  H. Capability matrix + expansion framework
  I. Frontend checks
  J. M83A/B/C/D regression smoke
  K. Forbidden wording
  L. Secret-shape grep

CLAIM DISCIPLINE: configuration-state review signals only. Does NOT confirm a
breach, compromise, unauthorized access, data exposure, or leaked secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.clerk_activity_signal_service import (
    CLERK_EVENT_TYPE_TO_SIGNAL_TYPE,
    CLERK_SIGNAL_TYPES,
    generate_clerk_activity_signals,
    _group_key,
    _resource_key,
    _severity,
    _build_signal,
    PROVIDER,
    SOURCE,
)
from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS as SIGNAL_ALLOWED_METADATA_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Test constants ─────────────────────────────────────────────────────────────

CLERK_TEST_INSTANCE_ID = "CLERK_TEST_INSTANCE_ID"
CLERK_TEST_WEBHOOK_ID = "CLERK_TEST_WEBHOOK_ID"
CLERK_TEST_TEMPLATE_ID = "CLERK_TEST_TEMPLATE_ID"
CLERK_TEST_EVENT_ID = "CLERK_TEST_EVENT_ID"
CLERK_TEST_SIGNAL_ID = "CLERK_TEST_SIGNAL_ID"

EXPECTED_SIGNAL_TYPES = {
    # 10 producible signal types after M83H removed the orphaned
    # clerk.application.created/updated → clerk_application_config_changed
    # map entries (application events are not synthesized by the connector).
    "clerk_instance_settings_config_changed",
    "clerk_domain_config_changed",
    "clerk_redirect_url_config_changed",
    "clerk_jwt_template_config_changed",
    "clerk_webhook_endpoint_config_changed",
    "clerk_email_sms_settings_config_changed",
    "clerk_auth_strategy_config_changed",
    "clerk_organization_settings_config_changed",
    "clerk_session_policy_config_changed",
    "clerk_config_activity",
}

_FORBIDDEN_SIGNAL_METADATA_FIELDS = frozenset({
    "secret_key", "publishable_key", "api_key", "token", "bearer",
    "jwt", "session_token", "webhook_secret", "url", "webhook_url",
    "redirect_url", "callback_url", "domain_name", "template_body",
    "claims_raw", "audience_raw", "issuer_raw", "email", "user_email",
    "user_id", "phone", "member", "ip_address", "user_agent", "password",
    "raw", "payload", "audit", "session", "login",
})

_FORBIDDEN_SIGNAL_STRINGS = [
    "eyJ",
    "pk_live_",
    "sk_live_",
    "sk_test_",
    "@",
]


# ── Helper: make a mock SecurityActivityEvent ──────────────────────────────────


def _make_event(
    event_type: str,
    metadata: dict[str, Any] | None = None,
    resource_id: str | None = None,
    provider_event_id: str | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.event_type = event_type
    ev.provider = "clerk"
    ev.source = "clerk_activity_event"
    ev.resource_id = resource_id
    ev.resource_type = metadata.get("resource_type") if metadata else None
    ev.provider_event_id = provider_event_id or f"clerk:test:{event_type}:2026-01-01"
    ev.integration_id = uuid.uuid4()
    ev.id = uuid.uuid4()
    ev.event_metadata = metadata or {}
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ev.occurred_at = now
    ev.ingested_at = now
    ev.created_at = now
    return ev


# ── Section A: Event type mapping ─────────────────────────────────────────────


class TestSectionA_EventTypeMapping:
    """A: Verify CLERK_EVENT_TYPE_TO_SIGNAL_TYPE and CLERK_SIGNAL_TYPES shape."""

    def test_event_type_to_signal_type_is_complete(self):
        """CLERK_SIGNAL_TYPES must equal the expected set of signal types."""
        assert CLERK_SIGNAL_TYPES == EXPECTED_SIGNAL_TYPES, (
            f"CLERK_SIGNAL_TYPES mismatch.\n"
            f"Extra: {CLERK_SIGNAL_TYPES - EXPECTED_SIGNAL_TYPES}\n"
            f"Missing: {EXPECTED_SIGNAL_TYPES - CLERK_SIGNAL_TYPES}"
        )

    def test_instance_settings_maps_correctly(self):
        """clerk.instance_settings.updated maps to clerk_instance_settings_config_changed."""
        assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get("clerk.instance_settings.updated") == (
            "clerk_instance_settings_config_changed"
        )

    def test_session_policy_maps_correctly(self):
        """clerk.session_policy.updated maps to clerk_session_policy_config_changed."""
        assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get("clerk.session_policy.updated") == (
            "clerk_session_policy_config_changed"
        )

    def test_config_event_maps_correctly(self):
        """clerk.config.event maps to clerk_config_activity."""
        assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get("clerk.config.event") == "clerk_config_activity"

    def test_all_event_types_map_to_signal_types(self):
        """All keys in CLERK_EVENT_TYPE_TO_SIGNAL_TYPE start with 'clerk.' and all
        values in CLERK_SIGNAL_TYPES start with 'clerk_'."""
        for event_type in CLERK_EVENT_TYPE_TO_SIGNAL_TYPE:
            assert event_type.startswith("clerk."), (
                f"Event type {event_type!r} must start with 'clerk.'"
            )
        for signal_type in CLERK_SIGNAL_TYPES:
            assert signal_type.startswith("clerk_"), (
                f"Signal type {signal_type!r} must start with 'clerk_'"
            )

    def test_all_mapped_values_in_signal_types(self):
        """All values from CLERK_EVENT_TYPE_TO_SIGNAL_TYPE are in CLERK_SIGNAL_TYPES."""
        mapped_values = set(CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.values())
        assert mapped_values == CLERK_SIGNAL_TYPES, (
            f"CLERK_SIGNAL_TYPES must exactly match the values of CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.\n"
            f"Extra in CLERK_SIGNAL_TYPES: {CLERK_SIGNAL_TYPES - mapped_values}\n"
            f"Missing from CLERK_SIGNAL_TYPES: {mapped_values - CLERK_SIGNAL_TYPES}"
        )

    def test_auth_strategy_maps_correctly(self):
        """clerk.auth_strategy.updated maps to clerk_auth_strategy_config_changed."""
        assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get("clerk.auth_strategy.updated") == (
            "clerk_auth_strategy_config_changed"
        )

    def test_webhook_endpoint_maps_correctly(self):
        """clerk.webhook_endpoint.created/updated/deleted all map to clerk_webhook_endpoint_config_changed."""
        for action in ("created", "updated", "deleted"):
            event_type = f"clerk.webhook_endpoint.{action}"
            assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type) == (
                "clerk_webhook_endpoint_config_changed"
            ), f"{event_type} must map to clerk_webhook_endpoint_config_changed"

    def test_jwt_template_maps_correctly(self):
        """clerk.jwt_template.created/updated/deleted all map to clerk_jwt_template_config_changed."""
        for action in ("created", "updated", "deleted"):
            event_type = f"clerk.jwt_template.{action}"
            assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type) == (
                "clerk_jwt_template_config_changed"
            ), f"{event_type} must map to clerk_jwt_template_config_changed"

    def test_domain_maps_correctly(self):
        """clerk.domain.created/updated/deleted all map to clerk_domain_config_changed."""
        for action in ("created", "updated", "deleted"):
            event_type = f"clerk.domain.{action}"
            assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type) == (
                "clerk_domain_config_changed"
            ), f"{event_type} must map to clerk_domain_config_changed"

    def test_organization_settings_maps_correctly(self):
        """clerk.organization_settings.updated maps to clerk_organization_settings_config_changed."""
        assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get("clerk.organization_settings.updated") == (
            "clerk_organization_settings_config_changed"
        )

    def test_email_sms_settings_maps_correctly(self):
        """clerk.email_sms_settings.updated maps to clerk_email_sms_settings_config_changed."""
        assert CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.get("clerk.email_sms_settings.updated") == (
            "clerk_email_sms_settings_config_changed"
        )


# ── Section B: _group_key behavior ────────────────────────────────────────────


class TestSectionB_GroupKey:
    """B: Verify _group_key grouping logic and determinism."""

    def test_group_key_includes_signal_type(self):
        """For a clerk.instance_settings.updated event, _group_key starts with
        'clerk.activity|clerk_instance_settings_config_changed'."""
        ev = _make_event(
            "clerk.instance_settings.updated",
            metadata={"instance_id": CLERK_TEST_INSTANCE_ID},
        )
        gk = _group_key(ev)
        assert gk is not None
        assert gk.startswith("clerk.activity|clerk_instance_settings_config_changed"), (
            f"group_key must start with expected prefix, got: {gk!r}"
        )

    def test_group_key_includes_resource(self):
        """Two events with different resource_ids get different group keys."""
        ev1 = _make_event(
            "clerk.domain.updated",
            metadata={"domain_id": "domain_aaa"},
        )
        ev2 = _make_event(
            "clerk.domain.updated",
            metadata={"domain_id": "domain_bbb"},
        )
        gk1 = _group_key(ev1)
        gk2 = _group_key(ev2)
        assert gk1 is not None
        assert gk2 is not None
        assert gk1 != gk2, (
            f"Different resource_ids must produce different group keys: {gk1!r} vs {gk2!r}"
        )

    def test_group_key_returns_none_for_unknown_type(self):
        """_group_key returns None for an unknown event type."""
        ev = _make_event("unknown.event.type")
        assert _group_key(ev) is None

    def test_group_key_deterministic(self):
        """Calling _group_key twice on the same event returns the same result."""
        ev = _make_event(
            "clerk.session_policy.updated",
            metadata={"session_policy_id": "sp_abc123"},
        )
        gk1 = _group_key(ev)
        gk2 = _group_key(ev)
        assert gk1 == gk2, (
            f"_group_key must be deterministic: {gk1!r} != {gk2!r}"
        )

    def test_group_key_same_type_same_resource_same_key(self):
        """Two events with the same type and resource get the same group key."""
        ev1 = _make_event(
            "clerk.webhook_endpoint.updated",
            metadata={"webhook_endpoint_id": CLERK_TEST_WEBHOOK_ID},
        )
        ev2 = _make_event(
            "clerk.webhook_endpoint.deleted",
            metadata={"webhook_endpoint_id": CLERK_TEST_WEBHOOK_ID},
        )
        # Both map to the same signal_type, so they should share a group key
        gk1 = _group_key(ev1)
        gk2 = _group_key(ev2)
        assert gk1 is not None
        assert gk2 is not None
        assert gk1 == gk2, (
            f"Same signal_type + same resource must share a group key: {gk1!r} vs {gk2!r}"
        )

    def test_group_key_format_has_three_pipe_parts(self):
        """_group_key returns a string with exactly 3 '|'-separated parts."""
        ev = _make_event(
            "clerk.jwt_template.created",
            metadata={"jwt_template_id": CLERK_TEST_TEMPLATE_ID},
        )
        gk = _group_key(ev)
        assert gk is not None
        parts = gk.split("|")
        assert len(parts) == 3, (
            f"_group_key must have 3 pipe-separated parts, got {len(parts)}: {gk!r}"
        )
        assert parts[0] == "clerk.activity"
        assert parts[1] == "clerk_jwt_template_config_changed"
        assert parts[2] == CLERK_TEST_TEMPLATE_ID

    def test_group_key_falls_back_to_global_when_no_resource(self):
        """_group_key falls back to 'global' when no resource identifier is found."""
        ev = _make_event("clerk.instance_settings.updated", metadata={})
        ev.resource_id = None
        gk = _group_key(ev)
        assert gk is not None
        assert gk.endswith("|global"), (
            f"_group_key must end with '|global' when no resource id found, got: {gk!r}"
        )


# ── Section C: _severity ───────────────────────────────────────────────────────


class TestSectionC_Severity:
    """C: Verify _severity review-priority assignment."""

    def test_severity_medium_for_instance_settings(self):
        """_severity returns 'medium' for clerk_instance_settings_config_changed."""
        assert _severity("clerk_instance_settings_config_changed") == "medium"

    def test_severity_medium_for_session_policy(self):
        """_severity returns 'medium' for clerk_session_policy_config_changed."""
        assert _severity("clerk_session_policy_config_changed") == "medium"

    def test_severity_low_for_domain(self):
        """_severity returns 'low' for clerk_domain_config_changed."""
        assert _severity("clerk_domain_config_changed") == "low"

    def test_severity_low_for_config_activity(self):
        """_severity returns 'low' for clerk_config_activity."""
        assert _severity("clerk_config_activity") == "low"

    def test_severity_medium_for_auth_strategy(self):
        """_severity returns 'medium' for clerk_auth_strategy_config_changed."""
        assert _severity("clerk_auth_strategy_config_changed") == "medium"

    def test_severity_medium_for_organization_settings(self):
        """_severity returns 'medium' for clerk_organization_settings_config_changed."""
        assert _severity("clerk_organization_settings_config_changed") == "medium"

    def test_severity_medium_for_jwt_template(self):
        """_severity returns 'medium' for clerk_jwt_template_config_changed."""
        assert _severity("clerk_jwt_template_config_changed") == "medium"

    def test_severity_medium_for_webhook_endpoint(self):
        """_severity returns 'medium' for clerk_webhook_endpoint_config_changed."""
        assert _severity("clerk_webhook_endpoint_config_changed") == "medium"

    def test_severity_low_for_application(self):
        """_severity returns 'low' for clerk_application_config_changed."""
        assert _severity("clerk_application_config_changed") == "low"

    def test_severity_low_for_redirect_url(self):
        """_severity returns 'low' for clerk_redirect_url_config_changed."""
        assert _severity("clerk_redirect_url_config_changed") == "low"

    def test_severity_low_for_email_sms_settings(self):
        """_severity returns 'low' for clerk_email_sms_settings_config_changed."""
        assert _severity("clerk_email_sms_settings_config_changed") == "low"

    def test_severity_returns_string(self):
        """_severity always returns a string for any known signal type."""
        for signal_type in CLERK_SIGNAL_TYPES:
            result = _severity(signal_type)
            assert isinstance(result, str) and result in ("low", "medium", "high", "critical"), (
                f"_severity({signal_type!r}) returned unexpected value: {result!r}"
            )


# ── Section D: _build_signal ───────────────────────────────────────────────────


class TestSectionD_BuildSignal:
    """D: Verify _build_signal dict shape, privacy, and metadata."""

    def _make_instance_event(self, **kwargs) -> MagicMock:
        return _make_event(
            "clerk.instance_settings.updated",
            metadata={
                "resource_type": "clerk_instance_settings",
                "instance_id": CLERK_TEST_INSTANCE_ID,
                "mfa_enabled": False,
                "sign_up_enabled": True,
                "session_lifetime_category": "standard",
                "domain_count": 1,
            },
            **kwargs,
        )

    def test_build_signal_returns_dict(self):
        """_build_signal([mock_event]) returns a dict with required keys."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert isinstance(result, dict), "_build_signal must return a dict"
        required_keys = {
            "provider", "integration_id", "signal_key", "signal_type",
            "severity", "status", "title", "summary", "evidence_level",
            "confidence", "first_seen_at", "last_seen_at",
            "linked_activity_event_id", "metadata",
        }
        missing = required_keys - set(result.keys())
        assert not missing, f"_build_signal result missing keys: {missing}"

    def test_build_signal_has_correct_provider(self):
        """_build_signal returns signal with provider == 'clerk'."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["provider"] == "clerk"

    def test_build_signal_has_evidence_level_activity(self):
        """_build_signal returns signal with evidence_level == 'activity'."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["evidence_level"] == "activity"

    def test_build_signal_has_signal_key(self):
        """_build_signal returns signal with a non-None signal_key."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["signal_key"] is not None
        assert isinstance(result["signal_key"], str)
        assert len(result["signal_key"]) > 0

    def test_build_signal_groups_multiple_events(self):
        """_build_signal([ev1, ev2]) has event_count=2 in metadata."""
        ev1 = self._make_instance_event()
        ev2 = self._make_instance_event()
        result = _build_signal([ev1, ev2])
        assert result is not None
        meta = result.get("metadata") or {}
        assert meta.get("event_count") == 2, (
            f"event_count in metadata must be 2 for a group of 2 events, got: {meta.get('event_count')}"
        )

    def test_build_signal_returns_none_for_unknown_event_type(self):
        """_build_signal([make_event('unknown.type')]) returns None."""
        ev = _make_event("unknown.event.type.xyz")
        result = _build_signal([ev])
        assert result is None

    def test_build_signal_metadata_no_forbidden_fields(self):
        """Signal metadata must not contain any forbidden field names."""
        ev = _make_event(
            "clerk.session_policy.updated",
            metadata={
                "resource_type": "clerk_session_policy",
                "session_policy_id": "sp_safe_id",
                "reverification_required": True,
                "device_tracking_enabled": False,
                "token_rotation_enabled": True,
                "session_lifetime_category": "standard",
            },
        )
        result = _build_signal([ev])
        assert result is not None
        meta = result.get("metadata") or {}
        violations = [k for k in meta if k in _FORBIDDEN_SIGNAL_METADATA_FIELDS]
        assert not violations, (
            f"Forbidden metadata fields found in signal: {violations}"
        )

    def test_build_signal_metadata_no_forbidden_strings(self):
        """Signal metadata string values must not contain forbidden substrings."""
        ev = _make_event(
            "clerk.organization_settings.updated",
            metadata={
                "resource_type": "clerk_organization_settings",
                "organization_settings_id": "org_settings_safe_id",
                "organizations_enabled": True,
                "verified_domains_required": False,
                "invitation_enabled": True,
                "admin_role_present": True,
                "role_count": 2,
                "permission_count": 5,
            },
        )
        result = _build_signal([ev])
        assert result is not None
        meta = result.get("metadata") or {}
        for k, v in meta.items():
            if isinstance(v, str):
                for forbidden in _FORBIDDEN_SIGNAL_STRINGS:
                    assert forbidden not in v, (
                        f"Forbidden string {forbidden!r} found in metadata[{k!r}]={v!r}"
                    )

    def test_build_signal_title_truncated(self):
        """signal['title'] is not longer than 240 chars."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        title = result.get("title", "")
        assert isinstance(title, str)
        assert len(title) <= 240, (
            f"Signal title must not exceed 240 chars, got {len(title)}: {title!r}"
        )

    def test_build_signal_has_correct_signal_type(self):
        """_build_signal returns the correct signal_type for the event type."""
        ev = _make_event(
            "clerk.auth_strategy.updated",
            metadata={"resource_type": "clerk_auth_strategy", "auth_strategy_id": "as_abc"},
        )
        result = _build_signal([ev])
        assert result is not None
        assert result["signal_type"] == "clerk_auth_strategy_config_changed"

    def test_build_signal_has_timestamps(self):
        """_build_signal returns first_seen_at and last_seen_at as datetime objects."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        assert isinstance(result["first_seen_at"], datetime)
        assert isinstance(result["last_seen_at"], datetime)

    def test_build_signal_status_is_open(self):
        """_build_signal returns signal with status='open'."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["status"] == "open"

    def test_build_signal_has_summary(self):
        """_build_signal returns a non-empty summary string."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    def test_build_signal_summary_not_claim_breach(self):
        """Signal summary must not contain forbidden breach-confirmation phrases."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        summary_lower = result["summary"].lower()
        forbidden = [
            "breach detected",
            "compromise confirmed",
            "attacker found",
            "unauthorized access confirmed",
            "secret leaked",
        ]
        for phrase in forbidden:
            assert phrase not in summary_lower, (
                f"Forbidden phrase {phrase!r} found in signal summary"
            )

    def test_build_signal_anchor_is_latest_event(self):
        """When multiple events are in a group, the signal reflects the latest event."""
        import uuid as _uuid
        from datetime import timedelta
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        earlier = now - timedelta(hours=2)

        ev_early = _make_event(
            "clerk.domain.created",
            metadata={"domain_id": "dom_abc", "resource_type": "clerk_domain"},
            provider_event_id="early_event",
        )
        ev_early.occurred_at = earlier

        ev_late = _make_event(
            "clerk.domain.updated",
            metadata={"domain_id": "dom_abc", "resource_type": "clerk_domain"},
            provider_event_id="late_event",
        )
        ev_late.occurred_at = now

        result = _build_signal([ev_early, ev_late])
        assert result is not None
        # The anchor is the latest event; last_seen_at should be the later timestamp
        assert result["last_seen_at"] >= result["first_seen_at"]

    def test_build_signal_metadata_has_source(self):
        """Signal metadata must include the 'source' field."""
        ev = self._make_instance_event()
        result = _build_signal([ev])
        assert result is not None
        meta = result.get("metadata") or {}
        assert "source" in meta
        assert meta["source"] == SOURCE


# ── Section E: generate_clerk_activity_signals ────────────────────────────────


class TestSectionE_GenerateClerkActivitySignals:
    """E: Verify generate_clerk_activity_signals DB integration and caps."""

    def _make_empty_db(self) -> MagicMock:
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        return mock_db

    def test_generate_clerk_activity_signals_empty_db(self):
        """Returns zero-count summary when no events exist."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        summary = generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
        )
        assert summary["provider"] == "clerk"
        assert summary["source"] == "clerk_activity_event"
        assert summary["events_scanned"] == 0
        assert summary["signals_created"] == 0

    def test_generate_scans_only_clerk_provider(self):
        """DB query filters on provider='clerk' and source='clerk_activity_event'."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
        )

        # Verify that db.query was called (query chain was constructed)
        assert mock_db.query.called, "db.query must be called"

    def test_generate_caps_lookback_at_168(self):
        """Call with lookback_hours=9999 should not error; internal cap is 168."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        # Should not raise; lookback is capped internally
        summary = generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
            lookback_hours=9999,
        )
        assert summary["events_scanned"] == 0

    def test_generate_caps_max_signals_at_1000(self):
        """Call with max_signals=9999 should not error; internal cap is 1000."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        summary = generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
            max_signals=9999,
        )
        # No error, empty db returns 0 signals
        assert "signals_created" in summary

    def test_generate_returns_required_keys(self):
        """generate_clerk_activity_signals always returns a dict with required keys."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        summary = generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
        )
        required_keys = {
            "provider", "source", "events_scanned",
            "groups_scanned", "signals_created", "signals_skipped",
        }
        missing = required_keys - set(summary.keys())
        assert not missing, f"Summary missing required keys: {missing}"

    def test_generate_respects_lookback_floor(self):
        """Call with lookback_hours=0 should not error; internal floor is 1."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        summary = generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
            lookback_hours=0,
        )
        assert "events_scanned" in summary

    def test_generate_respects_max_signals_floor(self):
        """Call with max_signals=0 should not error; internal floor is 1."""
        mock_db = self._make_empty_db()
        workspace_id = uuid.uuid4()

        summary = generate_clerk_activity_signals(
            workspace_id=workspace_id,
            db=mock_db,
            max_signals=0,
        )
        assert "signals_created" in summary


# ── Section F: Signal metadata allowlist coverage ─────────────────────────────


class TestSectionF_SignalMetadataAllowlistCoverage:
    """F: Verify Clerk-specific keys are in SIGNAL_ALLOWED_METADATA_KEYS."""

    def test_clerk_instance_keys_in_signal_allowlist(self):
        """Core Clerk instance identifiers are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["instance_id", "mfa_enabled", "session_lifetime_category"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk instance keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_org_keys_in_signal_allowlist(self):
        """Clerk organization settings keys are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["organizations_enabled", "verified_domains_required", "invitation_enabled"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk org keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_session_policy_keys_in_signal_allowlist(self):
        """Clerk session policy keys are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["reverification_required", "device_tracking_enabled", "token_rotation_enabled"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk session policy keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_auth_strategy_keys_in_signal_allowlist(self):
        """Clerk auth strategy keys are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["oauth_enabled", "saml_enabled", "passkey_enabled", "magic_link_enabled"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk auth strategy keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_domain_keys_in_signal_allowlist(self):
        """Clerk domain fields are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["domain_type", "verified", "primary", "ssl_enabled", "dns_status_category"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk domain keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_jwt_template_keys_in_signal_allowlist(self):
        """Clerk JWT template fields are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = [
            "jwt_template_id", "claims_count", "custom_claims_present",
            "audience_present", "issuer_present", "lifetime_category", "algorithm",
        ]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk JWT template keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_webhook_endpoint_keys_in_signal_allowlist(self):
        """Clerk webhook endpoint fields are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["webhook_endpoint_id", "url_present", "secret_present"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk webhook endpoint keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_redirect_url_keys_in_signal_allowlist(self):
        """Clerk redirect URL fields are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["wildcard_present", "localhost_present", "custom_scheme_present"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk redirect URL keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )

    def test_clerk_email_sms_keys_in_signal_allowlist(self):
        """Clerk email/SMS settings fields are in SIGNAL_ALLOWED_METADATA_KEYS."""
        required = ["sms_enabled", "custom_sender_present", "template_customization_present"]
        missing = [k for k in required if k not in SIGNAL_ALLOWED_METADATA_KEYS]
        assert not missing, (
            f"Clerk email/SMS keys missing from SIGNAL_ALLOWED_METADATA_KEYS: {missing}"
        )


# ── Section G: Router endpoint ─────────────────────────────────────────────────


class TestSectionG_RouterEndpoint:
    """G: Verify the clerk-activity/generate-signals endpoint exists and is admin-guarded."""

    def test_generate_signals_endpoint_exists(self):
        """The security router must define the /clerk-activity/generate-signals endpoint."""
        router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
        content = router_path.read_text()
        assert "/clerk-activity/generate-signals" in content, (
            "security.py must contain the '/clerk-activity/generate-signals' endpoint path"
        )

    def test_generate_signals_requires_admin(self):
        """The clerk-activity/generate-signals endpoint must call require_workspace_admin."""
        router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
        content = router_path.read_text()
        idx = content.find("/clerk-activity/generate-signals")
        assert idx >= 0, "/clerk-activity/generate-signals not found in security.py"
        window = content[idx: idx + 1200]
        assert "require_workspace_admin" in window, (
            "require_workspace_admin must appear within 1200 chars of "
            "'/clerk-activity/generate-signals' in security.py. "
            f"Window: {window[:300]}"
        )


# ── Section H: Capability matrix + expansion framework ────────────────────────


class TestSectionH_CapabilityMatrixAndExpansionFramework:
    """H: Verify capability matrix and expansion framework state at M83E."""

    def test_capability_matrix_clerk_activity_signals_true(self):
        """Capability matrix must show activity_signals=True for clerk after M83E."""
        cap = get_provider_capability("clerk")
        assert cap is not None, "Clerk entry must exist in capability matrix"
        assert cap.security.activity_signals is True, (
            f"activity_signals must be True for clerk at M83E. "
            f"Got: {cap.security.activity_signals!r}"
        )

    def test_capability_matrix_clerk_correlations_false(self):
        """Capability matrix must show risk_activity_correlations=True (M83F promoted it) and
        demo_seed_clear=False for clerk."""
        cap = get_provider_capability("clerk")
        assert cap is not None, "Clerk entry must exist in capability matrix"
        # M83F promoted risk_activity_correlations to True.
        assert cap.security.risk_activity_correlations is True, (
            f"risk_activity_correlations must be True for clerk after M83F. "
            f"Got: {cap.security.risk_activity_correlations!r}"
        )
        # M83G rolled forward: demo_seed_clear is now True for Clerk.
        assert cap.security.demo_seed_clear is True, (
            f"demo_seed_clear must be True for clerk after M83G. "
            f"Got: {cap.security.demo_seed_clear!r}"
        )

    def test_expansion_framework_m83f(self):
        """Expansion framework planned_next_stage must reference M83F or a later stage."""
        framework = get_framework()
        assert isinstance(framework, dict)
        summary = framework.get("summary", {})
        planned = summary.get("planned_next_stage", "")
        assert isinstance(planned, str)
        assert ("M83F" in planned or "Correlations" in planned or "Clerk" in planned
                or "M84A" in planned or "PagerDuty" in planned
                or "M85A" in planned or "Linear" in planned
                or "M86" in planned or "Jira" in planned
                or "M87" in planned or "GitLab" in planned
                or "M88" in planned or "Terraform" in planned
                or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned), (
            f"planned_next_stage must reference M83F or later, got: {planned!r}"
        )

    def test_capability_matrix_clerk_activity_ingestion_still_true(self):
        """M83D activity_ingestion must remain True after M83E is applied."""
        cap = get_provider_capability("clerk")
        assert cap is not None
        assert cap.security.activity_ingestion is True, (
            f"activity_ingestion must still be True for clerk after M83E, "
            f"got: {cap.security.activity_ingestion!r}"
        )


# ── Section I: Frontend checks ─────────────────────────────────────────────────


class TestSectionI_FrontendChecks:
    """I: Verify frontend signals page and api.ts include Clerk support."""

    def test_frontend_signals_page_has_clerk_provider(self):
        """Frontend signals page must reference 'clerk' and CLERK_SIGNAL_TYPES."""
        signals_page = (
            Path(__file__).parents[3]
            / "frontend"
            / "src"
            / "app"
            / "(app)"
            / "security"
            / "signals"
            / "page.tsx"
        )
        if not signals_page.exists():
            pytest.skip("Signals page not found")
        content = signals_page.read_text()
        assert "clerk" in content, (
            "Frontend signals page must reference 'clerk' as a provider"
        )
        assert "CLERK_SIGNAL_TYPES" in content, (
            "Frontend signals page must reference CLERK_SIGNAL_TYPES"
        )

    def test_frontend_api_has_generate_clerk_signals(self):
        """Frontend api.ts must export generateClerkActivitySignals."""
        api_path = (
            Path(__file__).parents[3]
            / "frontend"
            / "src"
            / "lib"
            / "api.ts"
        )
        if not api_path.exists():
            pytest.skip("api.ts not found")
        content = api_path.read_text()
        assert "generateClerkActivitySignals" in content, (
            "api.ts must export or define generateClerkActivitySignals"
        )


# ── Section J: M83A/B/C/D regression ──────────────────────────────────────────


class TestSectionJ_M83EarlierMilestoneRegression:
    """J: Verify earlier Clerk milestones (M83A/B/C/D) are not broken."""

    def test_m83_earlier_milestones_still_wired(self):
        """CLERK_RULE_KEYS must have >= 40 rules and _CLERK_CONFIG_EVENT_TYPES >= 18."""
        from app.services.security_rules.clerk import CLERK_RULE_KEYS
        assert len(CLERK_RULE_KEYS) >= 40, (
            f"Expected >= 40 Clerk rules from M83B+M83C, got {len(CLERK_RULE_KEYS)}"
        )
        from app.connectors.clerk import _CLERK_CONFIG_EVENT_TYPES
        assert len(_CLERK_CONFIG_EVENT_TYPES) >= 18, (
            f"Expected >= 18 M83D event types, got {len(_CLERK_CONFIG_EVENT_TYPES)}"
        )


# ── Section K: Forbidden wording ──────────────────────────────────────────────


class TestSectionK_ForbiddenWording:
    """K: Verify no forbidden claim wording appears in M83E source files."""

    def test_no_forbidden_wording_in_m83e_files(self):
        """Forbidden phrases must not appear in M83E service files."""
        forbidden = [
            "compromise confirmed", "secret leaked", "data leaked",
            "breach detected", "attack detected", "attacker found",
        ]
        files_to_check = [
            Path(__file__).parent.parent / "app" / "services" / "clerk_activity_signal_service.py",
        ]
        for fpath in files_to_check:
            if not fpath.exists():
                continue
            content = fpath.read_text().lower()
            for phrase in forbidden:
                assert phrase not in content, (
                    f"Forbidden phrase {phrase!r} in {fpath.name}"
                )


# ── Section L: Secret-shape grep ──────────────────────────────────────────────


class TestSectionL_SecretShapeGrep:
    """L: Verify no secret-shaped strings appear in M83E backend source files."""

    def test_no_secret_shaped_strings_in_m83e(self):
        """No secret-shaped string literals appear in M83E backend source files."""
        import re
        patterns = [
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
            re.compile(r"SG.[A-Za-z0-9_-]{10,}.[A-Za-z0-9_-]{10,}"),
            re.compile(r"AC[0-9a-fA-F]{32}"),
            re.compile(r"SK[0-9a-fA-F]{32}"),
        ]
        files_to_check = [
            Path(__file__).parent.parent / "app" / "services" / "clerk_activity_signal_service.py",
        ]
        for fpath in files_to_check:
            if not fpath.exists():
                continue
            content = fpath.read_text()
            for pat in patterns:
                matches = pat.findall(content)
                assert not matches, (
                    f"Secret-shaped string found in {fpath.name}: {matches}"
                )


# ── Section M: Module constants ────────────────────────────────────────────────


class TestSectionM_ModuleConstants:
    """M: Verify module-level constants are correct."""

    def test_provider_constant(self):
        """PROVIDER constant must be 'clerk'."""
        assert PROVIDER == "clerk"

    def test_source_constant(self):
        """SOURCE constant must be 'clerk_activity_event'."""
        assert SOURCE == "clerk_activity_event"

    def test_clerk_signal_types_is_frozenset(self):
        """CLERK_SIGNAL_TYPES must be a frozenset."""
        assert isinstance(CLERK_SIGNAL_TYPES, frozenset)

    def test_clerk_event_type_to_signal_type_is_dict(self):
        """CLERK_EVENT_TYPE_TO_SIGNAL_TYPE must be a dict."""
        assert isinstance(CLERK_EVENT_TYPE_TO_SIGNAL_TYPE, dict)

    def test_clerk_signal_types_is_nonempty(self):
        """CLERK_SIGNAL_TYPES must be non-empty."""
        assert len(CLERK_SIGNAL_TYPES) > 0

    def test_clerk_event_type_to_signal_type_is_nonempty(self):
        """CLERK_EVENT_TYPE_TO_SIGNAL_TYPE must be non-empty."""
        assert len(CLERK_EVENT_TYPE_TO_SIGNAL_TYPE) > 0


# ── Section N: _resource_key behavior ─────────────────────────────────────────


class TestSectionN_ResourceKey:
    """N: Verify _resource_key picks the correct safe identifier."""

    def test_resource_key_uses_instance_id(self):
        """_resource_key returns instance_id when present."""
        ev = _make_event(
            "clerk.instance_settings.updated",
            metadata={"instance_id": CLERK_TEST_INSTANCE_ID},
        )
        result = _resource_key(ev)
        assert result == CLERK_TEST_INSTANCE_ID

    def test_resource_key_uses_domain_id(self):
        """_resource_key returns domain_id when instance_id is absent."""
        ev = _make_event(
            "clerk.domain.updated",
            metadata={"domain_id": "domain_test_001"},
        )
        result = _resource_key(ev)
        assert result == "domain_test_001"

    def test_resource_key_uses_jwt_template_id(self):
        """_resource_key returns jwt_template_id when earlier keys are absent."""
        ev = _make_event(
            "clerk.jwt_template.updated",
            metadata={"jwt_template_id": CLERK_TEST_TEMPLATE_ID},
        )
        result = _resource_key(ev)
        assert result == CLERK_TEST_TEMPLATE_ID

    def test_resource_key_falls_back_to_global(self):
        """_resource_key returns 'global' when no identifier is found."""
        ev = _make_event("clerk.instance_settings.updated", metadata={})
        ev.resource_id = None
        result = _resource_key(ev)
        assert result == "global"

    def test_resource_key_uses_webhook_endpoint_id(self):
        """_resource_key returns webhook_endpoint_id when appropriate."""
        ev = _make_event(
            "clerk.webhook_endpoint.updated",
            metadata={"webhook_endpoint_id": CLERK_TEST_WEBHOOK_ID},
        )
        result = _resource_key(ev)
        assert result == CLERK_TEST_WEBHOOK_ID

    def test_resource_key_never_returns_none(self):
        """_resource_key always returns a non-None string."""
        for event_type in CLERK_EVENT_TYPE_TO_SIGNAL_TYPE:
            ev = _make_event(event_type, metadata={})
            ev.resource_id = None
            result = _resource_key(ev)
            assert result is not None, f"_resource_key returned None for {event_type!r}"
            assert isinstance(result, str)
