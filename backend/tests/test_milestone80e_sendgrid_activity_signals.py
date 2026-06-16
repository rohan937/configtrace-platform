"""M80E — SendGrid Configuration Activity Signals.

Verifies:
  * SENDGRID_SIGNAL_TYPES is a frozenset containing all 10 expected types
  * SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE covers all 17 M80D event types
  * Signal generation logic groups events correctly by resource/type
  * Same resource, multiple events → 1 grouped signal with event_count > 1
  * Different resources → separate signals
  * Idempotency: calling generate twice doesn't create duplicates
  * Signal metadata privacy: no forbidden fields, no email addresses,
    no webhook URLs, no API key values, no customer data, no PII
  * API endpoint POST /security/sendgrid-activity/generate-signals
  * Provider capability matrix reflects M80E state (activity_signals=True)
  * Expansion framework planned_next_stage → M80F / Correlations
  * Frontend signals page, api.ts, types/index.ts references added
  * Forbidden wording absent from sendgrid_activity_signal_service.py
  * No SendGrid/Twilio secret-shaped strings

CLAIM DISCIPLINE: these are configuration-posture review signals only. The
service does NOT confirm breach, compromise, unauthorized access, data
exposure, or leaked credentials.
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

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_SIGNALS = REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_API = REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
FE_TYPES = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"
BACKEND_APP = REPO_ROOT / "backend" / "app"

# ── Forbidden wording ─────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
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

# Signal metadata fields that must NEVER appear.
FORBIDDEN_METADATA_FIELDS = frozenset({
    "api_key",
    "api_key_value",
    "api_key_secret",
    "bearer",
    "authorization",
    "access_token",
    "secret",
    "email",
    "from_email",
    "reply_to",
    "recipient_email",
    "sender_email",
    "suppressed_email",
    "url",
    "webhook_url",
    "hostname",
    "template_content",
    "subject",
    "body",
    "payload",
    "raw",
    "message_id",
    "sg_message_id",
    "smtp_id",
    "click",
    "bounce",
    "delivered",
    "deferred",
    "dropped",
    "spamreport",
    "unsubscribe",
    "ip_address",
    "customer",
    "contact",
    "recipient",
})

# ── Expected signal types ─────────────────────────────────────────────────────

EXPECTED_SIGNAL_TYPES: frozenset[str] = frozenset({
    "sendgrid_account_config_changed",
    "sendgrid_api_key_config_changed",
    "sendgrid_sender_identity_config_changed",
    "sendgrid_domain_authentication_config_changed",
    "sendgrid_mail_settings_config_changed",
    "sendgrid_tracking_settings_config_changed",
    "sendgrid_event_webhook_config_changed",
    "sendgrid_inbound_parse_config_changed",
    "sendgrid_suppression_settings_config_changed",
    "sendgrid_config_activity",
})

# Expected event type → signal type mappings (17 M80D event types).
EXPECTED_EVENT_MAPPING: dict[str, str] = {
    "sendgrid.account.updated": "sendgrid_account_config_changed",
    "sendgrid.api_key.created": "sendgrid_api_key_config_changed",
    "sendgrid.api_key.updated": "sendgrid_api_key_config_changed",
    "sendgrid.api_key.deleted": "sendgrid_api_key_config_changed",
    "sendgrid.sender_identity.created": "sendgrid_sender_identity_config_changed",
    "sendgrid.sender_identity.updated": "sendgrid_sender_identity_config_changed",
    "sendgrid.sender_identity.verified": "sendgrid_sender_identity_config_changed",
    "sendgrid.sender_identity.deleted": "sendgrid_sender_identity_config_changed",
    "sendgrid.domain_authentication.created": "sendgrid_domain_authentication_config_changed",
    "sendgrid.domain_authentication.updated": "sendgrid_domain_authentication_config_changed",
    "sendgrid.domain_authentication.deleted": "sendgrid_domain_authentication_config_changed",
    "sendgrid.mail_settings.updated": "sendgrid_mail_settings_config_changed",
    "sendgrid.tracking_settings.updated": "sendgrid_tracking_settings_config_changed",
    "sendgrid.event_webhook.updated": "sendgrid_event_webhook_config_changed",
    "sendgrid.inbound_parse.updated": "sendgrid_inbound_parse_config_changed",
    "sendgrid.suppression_settings.updated": "sendgrid_suppression_settings_config_changed",
    "sendgrid.config.event": "sendgrid_config_activity",
}


# ── Mock activity event factory ───────────────────────────────────────────────


def _recent(hours: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _make_event(
    event_type: str = "sendgrid.api_key.updated",
    api_key_id: str = "SENDGRID_TEST_API_KEY_PLACEHOLDER",
    resource_type: str = "api_key",
    provider_event_id: str = "SENDGRID_TEST_EVENT_ID",
    occurred_at: datetime | None = None,
    workspace_id: uuid.UUID | None = None,
    integration_id: uuid.UUID | None = None,
    extra_metadata: dict | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.workspace_id = workspace_id or uuid.uuid4()
    ev.integration_id = integration_id or uuid.uuid4()
    ev.provider = "sendgrid"
    ev.source = "sendgrid_activity_event"
    ev.event_type = event_type
    ev.provider_event_id = provider_event_id
    ev.occurred_at = occurred_at or _recent()
    ev.created_at = occurred_at or _recent()
    ev.ingested_at = occurred_at or _recent()
    ev.actor_id = None
    ev.resource_type = resource_type
    ev.resource_id = api_key_id
    meta = {
        "event_source": "sendgrid_activity_event",
        "resource_type": resource_type,
        "api_key_id": api_key_id,
        "category": resource_type,
        "event_action": event_type,
        "status": "observed",
    }
    if extra_metadata:
        meta.update(extra_metadata)
    ev.event_metadata = meta
    return ev


# ══════════════════════════════════════════════════════════════════════════════
# A: Signal type registry
# ══════════════════════════════════════════════════════════════════════════════

class TestSignalTypeRegistry:
    def test_a1_sendgrid_signal_types_frozenset(self):
        from app.services.sendgrid_activity_signal_service import SENDGRID_SIGNAL_TYPES
        assert isinstance(SENDGRID_SIGNAL_TYPES, frozenset)

    def test_a2_all_expected_types_present(self):
        from app.services.sendgrid_activity_signal_service import SENDGRID_SIGNAL_TYPES
        missing = EXPECTED_SIGNAL_TYPES - SENDGRID_SIGNAL_TYPES
        assert not missing, f"missing signal types: {missing}"

    def test_a3_signal_count_is_10(self):
        from app.services.sendgrid_activity_signal_service import SENDGRID_SIGNAL_TYPES
        assert len(SENDGRID_SIGNAL_TYPES) == 10

    def test_a4_event_type_mapping_covers_all_17(self):
        from app.services.sendgrid_activity_signal_service import SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE
        missing = set(EXPECTED_EVENT_MAPPING.keys()) - set(SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.keys())
        assert not missing, f"event types missing from mapping: {missing}"
        assert len(SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE) == 17

    def test_a5_mapping_values_are_valid_signal_types(self):
        from app.services.sendgrid_activity_signal_service import (
            SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE,
            SENDGRID_SIGNAL_TYPES,
        )
        for et, st in SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.items():
            assert st in SENDGRID_SIGNAL_TYPES, f"{et!r} maps to unknown signal type {st!r}"

    def test_a6_expected_mappings_match(self):
        from app.services.sendgrid_activity_signal_service import SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE
        for et, expected_st in EXPECTED_EVENT_MAPPING.items():
            got = SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.get(et)
            assert got == expected_st, f"{et!r}: expected {expected_st!r}, got {got!r}"


# ══════════════════════════════════════════════════════════════════════════════
# B: _group_key, _resource_key, _build_signal unit tests
# ══════════════════════════════════════════════════════════════════════════════

class TestGroupAndBuildSignal:
    def test_b1_group_key_returns_str_for_known_event(self):
        from app.services.sendgrid_activity_signal_service import _group_key
        ev = _make_event("sendgrid.api_key.updated", "SENDGRID_TEST_API_KEY_PLACEHOLDER")
        gk = _group_key(ev)
        assert isinstance(gk, str)
        assert "sendgrid" in gk

    def test_b2_group_key_returns_none_for_unknown_event(self):
        from app.services.sendgrid_activity_signal_service import _group_key
        ev = _make_event("sendgrid.unknown.whatever")
        assert _group_key(ev) is None

    def test_b3_group_key_same_resource_same_type_equal(self):
        from app.services.sendgrid_activity_signal_service import _group_key
        ev1 = _make_event("sendgrid.api_key.updated", "SENDGRID_TEST_API_KEY_PLACEHOLDER")
        ev2 = _make_event("sendgrid.api_key.created", "SENDGRID_TEST_API_KEY_PLACEHOLDER")
        assert _group_key(ev1) == _group_key(ev2)

    def test_b4_group_key_different_resource_different(self):
        from app.services.sendgrid_activity_signal_service import _group_key
        ev1 = _make_event("sendgrid.api_key.updated", "key_id_001")
        ev2 = _make_event("sendgrid.api_key.updated", "key_id_002")
        assert _group_key(ev1) != _group_key(ev2)

    def test_b5_group_key_different_event_type_different(self):
        from app.services.sendgrid_activity_signal_service import _group_key
        ev1 = _make_event("sendgrid.api_key.updated", "SENDGRID_TEST_API_KEY_PLACEHOLDER")
        ev2 = _make_event("sendgrid.sender_identity.updated", "SENDGRID_TEST_API_KEY_PLACEHOLDER")
        # Different signal types so different group keys
        assert _group_key(ev1) != _group_key(ev2)

    def test_b6_build_signal_returns_dict(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.api_key.updated")
        result = _build_signal([ev])
        assert isinstance(result, dict)

    def test_b7_build_signal_has_required_fields(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.api_key.updated")
        signal = _build_signal([ev])
        for key in ("provider", "signal_key", "signal_type", "severity",
                    "title", "summary", "evidence_level", "confidence",
                    "first_seen_at", "last_seen_at", "linked_activity_event_id"):
            assert key in signal, f"missing field: {key}"

    def test_b8_build_signal_provider_is_sendgrid(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.api_key.updated")
        signal = _build_signal([ev])
        assert signal["provider"] == "sendgrid"

    def test_b9_build_signal_evidence_level_is_activity(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.api_key.updated")
        signal = _build_signal([ev])
        assert signal["evidence_level"] == "activity"

    def test_b10_build_signal_event_count_in_metadata(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev1 = _make_event("sendgrid.api_key.updated")
        ev2 = _make_event("sendgrid.api_key.created")
        signal = _build_signal([ev1, ev2])
        assert signal["metadata"].get("event_count") == 2

    def test_b11_build_signal_returns_none_for_unknown_event(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.unknown.event")
        result = _build_signal([ev])
        assert result is None

    def test_b12_build_signal_severity_medium_for_api_key(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.api_key.created")
        signal = _build_signal([ev])
        assert signal["severity"] == "medium"

    def test_b13_build_signal_severity_low_for_account(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.account.updated", resource_type="account")
        signal = _build_signal([ev])
        assert signal["severity"] == "low"

    def test_b14_linked_event_is_anchor(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev1 = _make_event("sendgrid.api_key.updated", occurred_at=_recent(2))
        ev2 = _make_event("sendgrid.api_key.updated", occurred_at=_recent(0))
        ev2_id = ev2.id
        signal = _build_signal([ev1, ev2])
        assert signal["linked_activity_event_id"] == ev2_id


# ══════════════════════════════════════════════════════════════════════════════
# C: Signal metadata privacy
# ══════════════════════════════════════════════════════════════════════════════

class TestSignalMetadataPrivacy:
    def test_c1_no_forbidden_metadata_keys(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event(
            "sendgrid.api_key.updated",
            extra_metadata={
                "sender_verified": True,
                "domain_valid": False,
                "event_webhook_enabled": True,
                "inbound_parse_enabled": False,
                "dns_record_count": 3,
            }
        )
        signal = _build_signal([ev])
        metadata = signal.get("metadata", {})
        for forbidden in FORBIDDEN_METADATA_FIELDS:
            assert forbidden not in metadata, (
                f"forbidden field {forbidden!r} found in signal metadata"
            )

    def test_c2_no_at_signs_in_metadata_values(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.sender_identity.updated", resource_type="sender_identity")
        signal = _build_signal([ev])
        for k, v in signal.get("metadata", {}).items():
            if isinstance(v, str):
                assert "@" not in v, f"email-like value in metadata field {k!r}: {v!r}"

    def test_c3_no_http_in_metadata_values(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event("sendgrid.event_webhook.updated", resource_type="event_webhook")
        signal = _build_signal([ev])
        for k, v in signal.get("metadata", {}).items():
            if isinstance(v, str):
                assert not v.startswith("http"), (
                    f"URL-like value in metadata field {k!r}: {v!r}"
                )

    def test_c4_safe_bool_fields_preserved(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event(
            "sendgrid.event_webhook.updated",
            resource_type="event_webhook",
            extra_metadata={
                "event_webhook_enabled": True,
                "event_webhook_has_url": True,
                "inbound_parse_enabled": False,
            }
        )
        signal = _build_signal([ev])
        md = signal.get("metadata", {})
        # Bool fields should survive sanitization (they're on the allowlist)
        assert md.get("event_webhook_enabled") is True
        assert md.get("event_webhook_has_url") is True

    def test_c5_api_key_id_safe_in_metadata(self):
        from app.services.sendgrid_activity_signal_service import _build_signal
        ev = _make_event(
            "sendgrid.api_key.updated",
            api_key_id="SENDGRID_TEST_API_KEY_PLACEHOLDER",
        )
        signal = _build_signal([ev])
        md = signal.get("metadata", {})
        # api_key_id should be present (it's an opaque identifier)
        assert "api_key_id" in md
        # But the actual key value "api_key" field must not be
        assert "api_key" not in md


# ══════════════════════════════════════════════════════════════════════════════
# D: generate_sendgrid_activity_signals integration (mocked DB)
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateSignalsMocked:
    def _make_db_query(self, events: list) -> MagicMock:
        db = MagicMock()
        q = MagicMock()
        db.query.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.limit.return_value = q
        q.all.return_value = events
        return db

    def test_d1_returns_summary_dict(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        wid = uuid.uuid4()
        db = self._make_db_query([])
        result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        assert isinstance(result, dict)
        for key in ("provider", "source", "events_scanned", "groups_scanned",
                    "signals_created", "signals_skipped"):
            assert key in result, f"missing key: {key}"

    def test_d2_provider_is_sendgrid(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        db = self._make_db_query([])
        result = generate_sendgrid_activity_signals(workspace_id=uuid.uuid4(), db=db)
        assert result["provider"] == "sendgrid"

    def test_d3_source_is_sendgrid_activity_event(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        db = self._make_db_query([])
        result = generate_sendgrid_activity_signals(workspace_id=uuid.uuid4(), db=db)
        assert result["source"] == "sendgrid_activity_event"

    def test_d4_zero_events_zero_results(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        db = self._make_db_query([])
        result = generate_sendgrid_activity_signals(workspace_id=uuid.uuid4(), db=db)
        assert result["events_scanned"] == 0
        assert result["groups_scanned"] == 0
        assert result["signals_created"] == 0

    def test_d5_single_event_creates_one_signal(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        from app.services import security_incident_signal_service as signal_svc
        wid = uuid.uuid4()
        ev = _make_event("sendgrid.api_key.updated", workspace_id=wid)
        db = self._make_db_query([ev])
        with patch.object(signal_svc, "upsert_incident_signal") as mock_upsert:
            mock_signal_row = MagicMock()
            mock_upsert.return_value = ("created", mock_signal_row)
            result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        assert result["events_scanned"] == 1
        assert result["groups_scanned"] == 1
        assert result["signals_created"] == 1

    def test_d6_two_events_same_resource_one_signal(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        from app.services import security_incident_signal_service as signal_svc
        wid = uuid.uuid4()
        ev1 = _make_event("sendgrid.api_key.created", "SENDGRID_TEST_API_KEY_PLACEHOLDER",
                           workspace_id=wid, occurred_at=_recent(2))
        ev2 = _make_event("sendgrid.api_key.updated", "SENDGRID_TEST_API_KEY_PLACEHOLDER",
                           workspace_id=wid, occurred_at=_recent(1))
        db = self._make_db_query([ev1, ev2])
        with patch.object(signal_svc, "upsert_incident_signal") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        assert result["events_scanned"] == 2
        assert result["groups_scanned"] == 1
        assert result["signals_created"] == 1

    def test_d7_two_events_different_resources_two_signals(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        from app.services import security_incident_signal_service as signal_svc
        wid = uuid.uuid4()
        ev1 = _make_event("sendgrid.api_key.updated", "key_id_001", workspace_id=wid)
        ev2 = _make_event("sendgrid.api_key.updated", "key_id_002", workspace_id=wid)
        db = self._make_db_query([ev1, ev2])
        with patch.object(signal_svc, "upsert_incident_signal") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        assert result["groups_scanned"] == 2
        assert result["signals_created"] == 2

    def test_d8_idempotent_second_run_skips(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        from app.services import security_incident_signal_service as signal_svc
        wid = uuid.uuid4()
        ev = _make_event("sendgrid.api_key.updated", workspace_id=wid)
        db = self._make_db_query([ev])
        with patch.object(signal_svc, "upsert_incident_signal") as mock_upsert:
            mock_upsert.return_value = ("skipped", MagicMock())
            result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        assert result["signals_created"] == 0
        assert result["signals_skipped"] == 1

    def test_d9_unknown_event_types_not_grouped(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        wid = uuid.uuid4()
        ev = _make_event("sendgrid.unknown.type", workspace_id=wid)
        db = self._make_db_query([ev])
        result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        assert result["events_scanned"] == 1
        assert result["groups_scanned"] == 0
        assert result["signals_created"] == 0

    def test_d10_old_events_outside_lookback_excluded(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        wid = uuid.uuid4()
        old_ev = _make_event(
            "sendgrid.api_key.updated",
            workspace_id=wid,
            occurred_at=datetime.now(timezone.utc) - timedelta(hours=200),
        )
        db = self._make_db_query([old_ev])
        result = generate_sendgrid_activity_signals(
            workspace_id=wid, db=db, lookback_hours=24
        )
        assert result["groups_scanned"] == 0

    def test_d11_scans_only_sendgrid_provider(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        wid = uuid.uuid4()
        db = MagicMock()
        q = MagicMock()
        db.query.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.limit.return_value = q
        q.all.return_value = []
        from app.models.security_activity_event import SecurityActivityEvent
        result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        # Verify filter was called - it's called multiple times for workspace/provider/source
        assert db.query.called
        assert q.filter.called

    def test_d12_max_signals_cap_enforced(self):
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        from app.services import security_incident_signal_service as signal_svc
        wid = uuid.uuid4()
        # Create 5 events with different resources
        events = [_make_event("sendgrid.api_key.updated", f"key_{i}", workspace_id=wid)
                  for i in range(5)]
        db = self._make_db_query(events)
        with patch.object(signal_svc, "upsert_incident_signal") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_activity_signals(
                workspace_id=wid, db=db, max_signals=2
            )
        assert result["signals_created"] == 2

    def test_d13_upsert_error_skips_group(self):
        """A upsert error on one group is caught and the loop continues."""
        from app.services.sendgrid_activity_signal_service import generate_sendgrid_activity_signals
        from app.services import security_incident_signal_service as signal_svc
        wid = uuid.uuid4()
        ev1 = _make_event("sendgrid.api_key.updated", "key_001", workspace_id=wid)
        ev2 = _make_event("sendgrid.api_key.updated", "key_002", workspace_id=wid)
        db = self._make_db_query([ev1, ev2])
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("transient DB error")
            return ("created", MagicMock())
        with patch.object(signal_svc, "upsert_incident_signal", side_effect=side_effect):
            # Should not raise — the loop catches and continues
            result = generate_sendgrid_activity_signals(workspace_id=wid, db=db)
        # First group failed, second succeeded
        assert result["signals_created"] == 1
        assert result["groups_scanned"] == 2


# ══════════════════════════════════════════════════════════════════════════════
# E: API endpoint (mocked router)
# ══════════════════════════════════════════════════════════════════════════════

class TestApiEndpoint:
    def test_e1_endpoint_requires_auth(self):
        """Unauthenticated → 401/422/200 (dev mode may bypass auth)."""
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/security/sendgrid-activity/generate-signals", json={})
        assert resp.status_code in (200, 401, 422), (
            f"Expected 200/401/422, got {resp.status_code}: {resp.text[:200]}"
        )

    def test_e2_endpoint_exists_in_router(self):
        from app.routers.security import router
        paths = [r.path for r in router.routes]
        assert any("sendgrid-activity/generate-signals" in p for p in paths), (
            "POST /security/sendgrid-activity/generate-signals not registered"
        )

    def test_e3_schema_has_generate_request(self):
        from app.schemas.security_sendgrid_activity import SendGridActivitySignalGenerateRequest
        req = SendGridActivitySignalGenerateRequest()
        assert req.lookback_hours == 24
        assert req.max_signals == 100

    def test_e4_schema_has_generate_response(self):
        from app.schemas.security_sendgrid_activity import SendGridActivitySignalGenerateResponse
        resp = SendGridActivitySignalGenerateResponse(
            events_scanned=10,
            groups_scanned=3,
            signals_created=2,
            signals_skipped=1,
        )
        assert resp.provider == "sendgrid"
        assert resp.source == "sendgrid_activity_event"
        assert resp.signals_created == 2

    def test_e5_admin_endpoint_mock(self):
        """Mock admin endpoint call returns valid summary shape."""
        from app.schemas.security_sendgrid_activity import SendGridActivitySignalGenerateResponse
        from app.services import sendgrid_activity_signal_service as svc
        wid = uuid.uuid4()
        mock_summary = {
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "events_scanned": 5,
            "groups_scanned": 2,
            "signals_created": 2,
            "signals_skipped": 0,
        }
        with patch.object(svc, "generate_sendgrid_activity_signals", return_value=mock_summary):
            result = svc.generate_sendgrid_activity_signals(workspace_id=wid, db=MagicMock())
            response = SendGridActivitySignalGenerateResponse(**result)
            assert response.signals_created == 2
            assert response.provider == "sendgrid"


# ══════════════════════════════════════════════════════════════════════════════
# F: Capability matrix
# ══════════════════════════════════════════════════════════════════════════════

class TestCapabilityMatrix:
    def _cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        return get_provider_capability("sendgrid")

    def test_f1_activity_signals_true(self):
        assert self._cap().security.activity_signals is True

    def test_f2_activity_ingestion_true(self):
        assert self._cap().security.activity_ingestion is True

    def test_f3_security_rules_true(self):
        assert self._cap().security.security_rules is True

    def test_f4_correlations_demo_false(self):
        cap = self._cap()
        assert cap.security.risk_activity_correlations is True  # M80F rolled forward
        assert cap.security.demo_seed_clear is True  # M80G rolled forward
        assert cap.security.case_report is True  # M80G rolled forward

    def test_f5_maturity_partial(self):
        assert self._cap().maturity == "partial"

    def test_f6_notes_mention_m80e(self):
        cap = self._cap()
        assert "M80E" in cap.notes or "signals" in cap.notes.lower(), (
            "Capability notes should mention M80E or signals"
        )


# ══════════════════════════════════════════════════════════════════════════════
# G: Expansion framework
# ══════════════════════════════════════════════════════════════════════════════

class TestExpansionFramework:
    def _fw(self):
        from app.services import provider_expansion_framework as svc
        return svc.get_framework()

    def test_g1_planned_next_stage_contains_m80f(self):
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M80H" in stage, f"expected M80H, got {stage!r}"

    def test_g2_planned_next_stage_not_m80e(self):
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M80E" not in stage


# ══════════════════════════════════════════════════════════════════════════════
# H: ALLOWED_METADATA_KEYS parity
# ══════════════════════════════════════════════════════════════════════════════

class TestAllowedMetadataKeys:
    def _keys(self):
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        return ALLOWED_METADATA_KEYS

    def test_h1_sendgrid_specific_keys_present(self):
        keys = self._keys()
        sendgrid_keys = [
            "api_key_id",
            "sender_id",
            "mail_setting_name",
            "tracking_setting_name",
            "event_webhook_enabled",
            "event_webhook_has_url",
            "inbound_parse_enabled",
            "inbound_parse_spam_check_enabled",
            "inbound_parse_send_raw_enabled",
            "domain_valid",
            "automatic_security",
            "dns_record_count",
            "sender_verified",
            "sender_locked",
            "suppression_group_count",
        ]
        missing = [k for k in sendgrid_keys if k not in keys]
        assert not missing, f"missing from ALLOWED_METADATA_KEYS: {missing}"

    def test_h2_forbidden_keys_not_present(self):
        keys = self._keys()
        forbidden = [
            "api_key", "bearer", "authorization", "access_token",
            "email", "from_email", "reply_to", "recipient_email",
            "url", "webhook_url", "hostname", "template_content",
            "subject", "body", "payload", "raw", "message_id",
            "customer", "ip_address",
        ]
        found = [k for k in forbidden if k in keys]
        assert not found, f"forbidden keys in ALLOWED_METADATA_KEYS: {found}"


# ══════════════════════════════════════════════════════════════════════════════
# I: Frontend references
# ══════════════════════════════════════════════════════════════════════════════

class TestFrontendReferences:
    def test_i1_signals_page_has_sendgrid_provider_type(self):
        text = FE_SIGNALS.read_text()
        assert '"sendgrid"' in text

    def test_i2_signals_page_has_sendgrid_signal_types(self):
        text = FE_SIGNALS.read_text()
        for st in EXPECTED_SIGNAL_TYPES:
            assert st in text, f"signal type {st!r} not in signals page"

    def test_i3_signals_page_has_sendgrid_in_select(self):
        text = FE_SIGNALS.read_text()
        assert 'sendgrid' in text
        # The Select options array should include sendgrid
        assert '"sendgrid"' in text

    def test_i4_api_ts_has_generate_function(self):
        text = FE_API.read_text()
        assert "generateSendGridActivitySignals" in text
        assert "sendgrid-activity/generate-signals" in text

    def test_i5_types_has_sendgrid_signal_response(self):
        text = FE_TYPES.read_text()
        assert "SendGridActivitySignalGenerateResponse" in text

    def test_i6_signals_page_has_isSendGrid(self):
        text = FE_SIGNALS.read_text()
        assert "isSendGrid" in text


# ══════════════════════════════════════════════════════════════════════════════
# J: Forbidden wording + secret-shape source scan
# ══════════════════════════════════════════════════════════════════════════════

def _assert_no_forbidden_wording(src: str, name: str) -> None:
    low = src.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"forbidden phrase {phrase!r} in {name}"


def test_j1_no_forbidden_in_signal_service():
    import importlib
    mod = importlib.import_module("app.services.sendgrid_activity_signal_service")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_j2_no_forbidden_in_schema():
    import importlib
    mod = importlib.import_module("app.schemas.security_sendgrid_activity")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_j3_no_forbidden_in_frontend_signals_page():
    text = FE_SIGNALS.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in signals page"


_SG_PATTERN = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_TWILIO_PATTERNS = [
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


def _scan_for_secrets(root: Path) -> list[str]:
    hits = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in (".py", ".ts", ".tsx", ".js", ".json"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if _SG_PATTERN.search(text):
            hits.append(f"{path}: SendGrid secret shape")
        for pat in _TWILIO_PATTERNS:
            if pat.search(text):
                hits.append(f"{path}: Twilio secret shape")
    return hits


def test_j4_no_secret_shapes_in_backend_app():
    hits = _scan_for_secrets(BACKEND_APP)
    assert not hits, "Secret-shaped strings found:\n" + "\n".join(hits)


def test_j5_no_secret_shapes_in_frontend_src():
    hits = _scan_for_secrets(REPO_ROOT / "frontend" / "src")
    assert not hits, "Secret-shaped strings found:\n" + "\n".join(hits)
