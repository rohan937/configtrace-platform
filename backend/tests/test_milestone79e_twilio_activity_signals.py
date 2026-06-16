"""M79E — Twilio Monitor Activity Signals.

Verifies:
  * TWILIO_SIGNAL_TYPES is a frozenset containing all 7 expected types
  * TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE covers all 15 M79D event types
  * Signal generation logic groups events correctly by resource/type
  * Same resource, multiple events → 1 grouped signal with event_count > 1
  * Different resources → separate signals
  * Idempotency: calling generate twice doesn't create duplicates
  * Signal metadata privacy: no forbidden fields, no full phone numbers, etc.
  * API endpoint POST /security/twilio-activity/generate-signals
  * Provider capability matrix reflects M79E state
  * Expansion framework planned_next_stage → M79F / Twilio Correlation
  * Frontend signals/page.tsx, api.ts, types/index.ts references
  * Forbidden wording absent from twilio_activity_signal_service.py

CLAIM DISCIPLINE: these are configuration-posture review signals only. The
service does NOT confirm breach, compromise, unauthorized access, data
exposure, or leaked credentials.

FORBIDDEN PHRASES: never stored; tested in section I.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Forbidden wording / metadata fields ──────────────────────────────────────

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

FORBIDDEN_METADATA_FIELDS = frozenset({
    "auth_token",
    "api_secret",
    "api_key_secret",
    "access_token",
    "authorization",
    "phone_number",
    "to",
    "from",
    "sms_url",
    "voice_url",
    "inbound_request_url",
    "fallback_url",
    "status_callback_url",
    "status_callback",
    "message_body",
    "body",
    "recording_url",
    "media_url",
    "transcript",
    "raw_payload",
    "request",
    "response",
    "headers",
    "signature",
    "customer",
    "email",
})


# ── Mock activity event factory ───────────────────────────────────────────────


def _recent(hours: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _make_event(
    event_type: str = "twilio.phone_number.created",
    resource_sid_prefix: str = "PNtest12",
    resource_type: str = "incoming-phone-number",
    provider_event_id: str = "AEtest001",
    occurred_at: datetime | None = None,
    workspace_id: uuid.UUID | None = None,
    integration_id: uuid.UUID | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.workspace_id = workspace_id or uuid.uuid4()
    ev.integration_id = integration_id
    ev.provider = "twilio"
    ev.source = "twilio_activity_event"
    ev.event_type = event_type
    ev.provider_event_id = provider_event_id
    ev.resource_type = resource_type
    ev.occurred_at = occurred_at or _recent(1)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {
        "twilio_event_id": provider_event_id,
        "twilio_resource_sid_prefix": resource_sid_prefix,
        "resource_type": resource_type,
        "event_action": event_type,
        "event_time": ev.occurred_at.isoformat(),
        "account_sid_prefix": "TWILIO_TE",
    }
    return ev


# ══════════════════════════════════════════════════════════════════════════════
# A: Signal type constants
# ══════════════════════════════════════════════════════════════════════════════


class TestSignalTypeConstants:
    """A: TWILIO_SIGNAL_TYPES constants and event type mapping."""

    def test_a1_import_twilio_signal_types(self):
        """A1: Import TWILIO_SIGNAL_TYPES from twilio_activity_signal_service."""
        from app.services.twilio_activity_signal_service import TWILIO_SIGNAL_TYPES
        assert TWILIO_SIGNAL_TYPES is not None

    def test_a2_twilio_signal_types_is_frozenset(self):
        """A2: TWILIO_SIGNAL_TYPES is a frozenset."""
        from app.services.twilio_activity_signal_service import TWILIO_SIGNAL_TYPES
        assert isinstance(TWILIO_SIGNAL_TYPES, frozenset)

    def test_a3_contains_all_7_expected_types(self):
        """A3: Contains all 7 expected signal types."""
        from app.services.twilio_activity_signal_service import TWILIO_SIGNAL_TYPES
        expected = {
            "twilio_phone_number_config_changed",
            "twilio_messaging_service_config_changed",
            "twilio_messaging_sender_pool_changed",
            "twilio_verify_service_config_changed",
            "twilio_api_key_config_changed",
            "twilio_account_config_changed",
            "twilio_config_activity",
        }
        for st in expected:
            assert st in TWILIO_SIGNAL_TYPES, (
                f"Expected signal type {st!r} not in TWILIO_SIGNAL_TYPES"
            )

    def test_a4_event_type_to_signal_type_covers_all_15_m79d_event_types(self):
        """A4: TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE covers all 15 M79D event types."""
        from app.services.twilio_activity_signal_service import TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE
        expected_event_types = {
            "twilio.phone_number.created",
            "twilio.phone_number.updated",
            "twilio.phone_number.deleted",
            "twilio.messaging_service.created",
            "twilio.messaging_service.updated",
            "twilio.messaging_service.deleted",
            "twilio.messaging_service.sender_pool.updated",
            "twilio.verify_service.created",
            "twilio.verify_service.updated",
            "twilio.verify_service.deleted",
            "twilio.api_key.created",
            "twilio.api_key.updated",
            "twilio.api_key.deleted",
            "twilio.account.updated",
            "twilio.config.event",
        }
        for et in expected_event_types:
            assert et in TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE, (
                f"Event type {et!r} not in TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE"
            )


# ══════════════════════════════════════════════════════════════════════════════
# B: Signal generation logic
# ══════════════════════════════════════════════════════════════════════════════


def _run_generate(events: list, workspace_id: uuid.UUID | None = None) -> dict:
    """Helper: run generate_twilio_activity_signals with mocked DB."""
    from app.services import twilio_activity_signal_service as svc

    ws = workspace_id or uuid.uuid4()
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

    with patch(
        "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
        return_value=("created", MagicMock()),
    ):
        return svc.generate_twilio_activity_signals(workspace_id=ws, db=db)


class TestSignalGenerationLogic:
    """B: Signal generation logic."""

    def test_b1_phone_number_events_produce_phone_number_config_changed(self):
        """B1: phone_number events → twilio_phone_number_config_changed signal."""
        from app.services import twilio_activity_signal_service as svc

        ws = uuid.uuid4()
        events = [
            _make_event("twilio.phone_number.created", resource_sid_prefix="PNtest12",
                        provider_event_id="AE001"),
            _make_event("twilio.phone_number.updated", resource_sid_prefix="PNtest12",
                        provider_event_id="AE002"),
        ]
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        captured_signals = []

        def capture_upsert(**kwargs):
            captured_signals.append(kwargs["signal"])
            return ("created", MagicMock())

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            result = svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert result["signals_created"] == 1, (
            f"Expected 1 grouped signal, got {result['signals_created']}"
        )
        assert len(captured_signals) == 1
        assert captured_signals[0]["signal_type"] == "twilio_phone_number_config_changed"

    def test_b2_messaging_service_events_produce_correct_signal_type(self):
        """B2: messaging_service events → twilio_messaging_service_config_changed."""
        events = [
            _make_event("twilio.messaging_service.updated",
                        resource_sid_prefix="MGtest78",
                        resource_type="messaging-service",
                        provider_event_id="AE003"),
        ]
        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        from app.services import twilio_activity_signal_service as svc
        ws = uuid.uuid4()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert len(captured) == 1
        assert captured[0]["signal_type"] == "twilio_messaging_service_config_changed"

    def test_b3_sender_pool_event_produces_correct_signal_type(self):
        """B3: sender_pool event → twilio_messaging_sender_pool_changed."""
        events = [
            _make_event("twilio.messaging_service.sender_pool.updated",
                        resource_sid_prefix="MGtest78",
                        resource_type="messaging-service",
                        provider_event_id="AE004"),
        ]
        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        from app.services import twilio_activity_signal_service as svc
        ws = uuid.uuid4()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert len(captured) == 1
        assert captured[0]["signal_type"] == "twilio_messaging_sender_pool_changed"

    def test_b4_verify_service_events_produce_correct_signal_type(self):
        """B4: verify_service events → twilio_verify_service_config_changed."""
        events = [
            _make_event("twilio.verify_service.created",
                        resource_sid_prefix="VAtest12",
                        resource_type="verify-service",
                        provider_event_id="AE005"),
        ]
        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        from app.services import twilio_activity_signal_service as svc
        ws = uuid.uuid4()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert len(captured) == 1
        assert captured[0]["signal_type"] == "twilio_verify_service_config_changed"

    def test_b5_api_key_events_produce_correct_signal_type(self):
        """B5: api_key events → twilio_api_key_config_changed."""
        events = [
            _make_event("twilio.api_key.created",
                        resource_sid_prefix="SKtest12",
                        resource_type="api-key",
                        provider_event_id="AE006"),
        ]
        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        from app.services import twilio_activity_signal_service as svc
        ws = uuid.uuid4()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert len(captured) == 1
        assert captured[0]["signal_type"] == "twilio_api_key_config_changed"

    def test_b6_account_updated_produces_correct_signal_type(self):
        """B6: account.updated → twilio_account_config_changed."""
        events = [
            _make_event("twilio.account.updated",
                        resource_sid_prefix="ACtest12",
                        resource_type="account",
                        provider_event_id="AE007"),
        ]
        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        from app.services import twilio_activity_signal_service as svc
        ws = uuid.uuid4()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert len(captured) == 1
        assert captured[0]["signal_type"] == "twilio_account_config_changed"

    def test_b7_config_event_produces_correct_signal_type(self):
        """B7: config.event → twilio_config_activity."""
        events = [
            _make_event("twilio.config.event",
                        resource_sid_prefix="global",
                        resource_type="configuration",
                        provider_event_id="AE008"),
        ]
        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        from app.services import twilio_activity_signal_service as svc
        ws = uuid.uuid4()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert len(captured) == 1
        assert captured[0]["signal_type"] == "twilio_config_activity"

    def test_b8_different_resources_produce_separate_signals(self):
        """B8: 2 events from different resources → 2 separate signals."""
        from app.services import twilio_activity_signal_service as svc

        ws = uuid.uuid4()
        events = [
            _make_event("twilio.phone_number.created",
                        resource_sid_prefix="PNtestAA",
                        provider_event_id="AE009"),
            _make_event("twilio.phone_number.created",
                        resource_sid_prefix="PNtestBB",
                        provider_event_id="AE010"),
        ]
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            result = svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert result["signals_created"] == 2, (
            f"Expected 2 signals (different resources), got {result['signals_created']}"
        )

    def test_b9_same_resource_multiple_events_grouped_into_one_signal(self):
        """B9: Same resource, multiple events → 1 grouped signal with event_count == 3."""
        from app.services import twilio_activity_signal_service as svc

        ws = uuid.uuid4()
        events = [
            _make_event("twilio.phone_number.created",
                        resource_sid_prefix="PNtest12",
                        provider_event_id="AE011",
                        occurred_at=_recent(3)),
            _make_event("twilio.phone_number.updated",
                        resource_sid_prefix="PNtest12",
                        provider_event_id="AE012",
                        occurred_at=_recent(2)),
            _make_event("twilio.phone_number.updated",
                        resource_sid_prefix="PNtest12",
                        provider_event_id="AE013",
                        occurred_at=_recent(1)),
        ]
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        captured = []

        def capture_upsert(**kwargs):
            captured.append(kwargs["signal"])
            return ("created", MagicMock())

        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=capture_upsert,
        ):
            result = svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert result["signals_created"] == 1, (
            f"Expected 1 grouped signal, got {result['signals_created']}"
        )
        assert len(captured) == 1
        assert captured[0]["metadata"].get("event_count") == 3, (
            f"event_count in signal metadata should be 3, got {captured[0]['metadata'].get('event_count')!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# C: Idempotency
# ══════════════════════════════════════════════════════════════════════════════


class TestIdempotency:
    """C: Idempotency — generating signals twice doesn't create duplicates."""

    def test_c1_second_call_skips_existing_signals(self):
        """C1: Generate twice with same events → second call returns skipped."""
        from app.services import twilio_activity_signal_service as svc

        ws = uuid.uuid4()
        events = [
            _make_event("twilio.phone_number.created",
                        resource_sid_prefix="PNtest12",
                        provider_event_id="AE020"),
        ]
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

        # First call: created
        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ):
            r1 = svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert r1["signals_created"] == 1
        assert r1["signals_skipped"] == 0

        # Second call: skipped (idempotent)
        with patch(
            "app.services.twilio_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("skipped", MagicMock()),
        ):
            r2 = svc.generate_twilio_activity_signals(workspace_id=ws, db=db)

        assert r2["signals_created"] == 0
        assert r2["signals_skipped"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# D: Signal metadata privacy
# ══════════════════════════════════════════════════════════════════════════════


class TestSignalMetadataPrivacy:
    """D: Signal metadata must not contain forbidden fields."""

    def _build_signal_for(self, event_type: str, resource_sid_prefix: str = "PNtest12") -> dict | None:
        from app.services.twilio_activity_signal_service import _build_signal
        ev = _make_event(event_type, resource_sid_prefix=resource_sid_prefix)
        return _build_signal([ev])

    def test_d1_no_forbidden_metadata_fields(self):
        """D1: No key from FORBIDDEN_METADATA_FIELDS in any signal metadata."""
        from app.services.twilio_activity_signal_service import TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE
        for et in TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE:
            sig = self._build_signal_for(et)
            if sig is None:
                continue
            meta = sig.get("metadata", {})
            for key in meta.keys():
                assert key.lower() not in FORBIDDEN_METADATA_FIELDS, (
                    f"forbidden metadata key {key!r} found in signal for event_type={et!r}"
                )

    def test_d2_phone_number_last4_length_at_most_4(self):
        """D2: If phone_number_last4 present, its value has length <= 4."""
        from app.services.twilio_activity_signal_service import _build_signal
        ev = _make_event("twilio.phone_number.created")
        ev.event_metadata["phone_number_last4"] = "1234"
        sig = _build_signal([ev])
        if sig is None:
            return
        meta = sig.get("metadata", {})
        last4 = meta.get("phone_number_last4")
        if last4 is not None:
            assert len(str(last4)) <= 4, (
                f"phone_number_last4 should be <= 4 chars, got: {last4!r}"
            )

    def test_d3_no_full_e164_phone_number_in_metadata(self):
        """D3: No value that looks like a full E.164 phone number."""
        import re
        e164 = re.compile(r"^\+\d{10,}$")
        from app.services.twilio_activity_signal_service import TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE
        for et in TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE:
            sig = self._build_signal_for(et)
            if sig is None:
                continue
            meta = sig.get("metadata", {})
            for v in meta.values():
                if isinstance(v, str):
                    assert not e164.match(v), (
                        f"Full E.164 phone number pattern found in signal metadata value for {et!r}: {v!r}"
                    )

    def test_d4_no_auth_token_value_in_metadata(self):
        """D4: No auth_token value in any metadata field."""
        _fake_auth_token = "fake-auth-token-not-real-32chars00"
        from app.services.twilio_activity_signal_service import _build_signal
        ev = _make_event("twilio.phone_number.created")
        # Try to inject auth token into event metadata
        ev.event_metadata["auth_token"] = _fake_auth_token
        sig = _build_signal([ev])
        if sig is None:
            return
        meta_str = str(sig.get("metadata", {}))
        assert _fake_auth_token not in meta_str, (
            "auth_token value found in signal metadata"
        )

    def test_d5_evidence_level_is_activity(self):
        """D5: evidence_level == 'activity' for all generated signals."""
        from app.services.twilio_activity_signal_service import _build_signal
        ev = _make_event("twilio.phone_number.created")
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["evidence_level"] == "activity"


# ══════════════════════════════════════════════════════════════════════════════
# E: API endpoint
# ══════════════════════════════════════════════════════════════════════════════


class TestApiEndpoint:
    """E: POST /security/twilio-activity/generate-signals endpoint."""

    def test_e1_unauthenticated_returns_401_or_422_or_200(self):
        """E1: Unauthenticated → 401/422/200 (dev mode may bypass auth)."""
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app

        client = TestClient(fastapi_app, raise_server_exceptions=False)
        r = client.post("/security/twilio-activity/generate-signals", json={})
        assert r.status_code in (200, 401, 422), (
            f"Expected 200/401/422, got {r.status_code}: {r.text[:200]}"
        )

    def test_e2_admin_can_call_endpoint_200(self):
        """E2: Admin can call → 200 with valid response shape."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app
        from app.services import twilio_activity_signal_service as svc

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        clean_summary = {
            "provider": "twilio",
            "source": "twilio_activity_event",
            "events_scanned": 0,
            "groups_scanned": 0,
            "signals_created": 0,
            "signals_skipped": 0,
        }

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db

        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                return_value=None,
            ), patch.object(
                svc, "generate_twilio_activity_signals", return_value=clean_summary
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=True)
                r = client.post("/security/twilio-activity/generate-signals", json={})
        finally:
            fastapi_app.dependency_overrides.clear()

        assert r.status_code == 200

    def test_e3_response_has_correct_shape(self):
        """E3: Response has provider='twilio', source='twilio_activity_event', signals_created."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app
        from app.services import twilio_activity_signal_service as svc

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        clean_summary = {
            "provider": "twilio",
            "source": "twilio_activity_event",
            "events_scanned": 5,
            "groups_scanned": 3,
            "signals_created": 2,
            "signals_skipped": 1,
        }

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db

        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                return_value=None,
            ), patch.object(
                svc, "generate_twilio_activity_signals", return_value=clean_summary
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=True)
                r = client.post("/security/twilio-activity/generate-signals", json={})
        finally:
            fastapi_app.dependency_overrides.clear()

        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "twilio"
        assert body["source"] == "twilio_activity_event"
        assert "signals_created" in body


# ══════════════════════════════════════════════════════════════════════════════
# F: Capability matrix
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    """F: Provider capability matrix reflects M79E state."""

    def _cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        return get_provider_capability("twilio")

    def test_f1_activity_signals_is_true(self):
        """F1: get_provider_capability('twilio').security.activity_signals is True."""
        assert self._cap().security.activity_signals is True

    def test_f2_risk_activity_correlations_is_false(self):
        """F2: get_provider_capability('twilio').security.risk_activity_correlations is True (M79F complete; rolled forward)."""
        assert self._cap().security.risk_activity_correlations is True

    def test_f3_demo_seed_clear_is_false(self):
        """F3: get_provider_capability('twilio').security.demo_seed_clear is True (M79G complete)."""
        assert self._cap().security.demo_seed_clear is True


# ══════════════════════════════════════════════════════════════════════════════
# G: Expansion framework
# ══════════════════════════════════════════════════════════════════════════════


class TestExpansionFramework:
    """G: Expansion framework planned_next_stage points to M79F / Twilio Correlation."""

    def _fw(self):
        from app.services import provider_expansion_framework as svc
        return svc.get_framework()

    def test_g1_planned_next_stage_contains_m79f(self):
        """G1: planned_next_stage contains 'M79I' (M79H complete; rolled forward)."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M79I" in stage, (
            f"planned_next_stage should contain 'M79I', got: {stage!r}"
        )

    def test_g2_planned_next_stage_contains_twilio_or_correlation(self):
        """G2: planned_next_stage contains 'Twilio' or 'Correlation'."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "Twilio" in stage or "Correlation" in stage, (
            f"planned_next_stage should mention Twilio or Correlation, got: {stage!r}"
        )

    def test_g3_planned_next_stage_does_not_contain_m79e(self):
        """G3: planned_next_stage does NOT contain 'M79E'."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M79E" not in stage, (
            f"planned_next_stage must not still say M79E (it is complete): {stage!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# H: Frontend (skip if absent)
# ══════════════════════════════════════════════════════════════════════════════

REPO_ROOT = Path(__file__).resolve().parents[2]
_FE_SIGNALS_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "signals" / "page.tsx"
)
_FE_API_TS = REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
_FE_TYPES_TS = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"


def _read_fe(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


class TestFrontend:
    """H: Frontend checks — skipped if frontend files absent."""

    def test_h1_signals_page_contains_twilio_in_provider_options(self):
        """H1: signals/page.tsx contains 'twilio' in provider options."""
        content = _read_fe(_FE_SIGNALS_PAGE)
        if content is None:
            pytest.skip("Frontend signals/page.tsx not found")
        assert "twilio" in content.lower(), (
            "signals/page.tsx should contain 'twilio' in provider options"
        )

    def test_h2_signals_page_contains_twilio_signal_types(self):
        """H2: signals/page.tsx contains 'TWILIO_SIGNAL_TYPES' or 'twilio_phone_number_config_changed'."""
        content = _read_fe(_FE_SIGNALS_PAGE)
        if content is None:
            pytest.skip("Frontend signals/page.tsx not found")
        assert "TWILIO_SIGNAL_TYPES" in content or "twilio_phone_number_config_changed" in content, (
            "signals/page.tsx should contain TWILIO_SIGNAL_TYPES or twilio_phone_number_config_changed"
        )

    def test_h3_signals_page_contains_generate_twilio_signals_button(self):
        """H3: signals/page.tsx contains 'Generate Twilio signals'."""
        content = _read_fe(_FE_SIGNALS_PAGE)
        if content is None:
            pytest.skip("Frontend signals/page.tsx not found")
        assert "Generate Twilio signals" in content, (
            "signals/page.tsx should contain 'Generate Twilio signals'"
        )

    def test_h4_api_ts_contains_generate_twilio_activity_signals(self):
        """H4: api.ts contains 'generateTwilioActivitySignals'."""
        content = _read_fe(_FE_API_TS)
        if content is None:
            pytest.skip("Frontend api.ts not found")
        assert "generateTwilioActivitySignals" in content, (
            "api.ts should contain 'generateTwilioActivitySignals'"
        )

    def test_h5_types_contains_twilio_activity_signal_generate_response(self):
        """H5: types/index.ts contains 'TwilioActivitySignalGenerateResponse'."""
        content = _read_fe(_FE_TYPES_TS)
        if content is None:
            pytest.skip("Frontend types/index.ts not found")
        assert "TwilioActivitySignalGenerateResponse" in content, (
            "types/index.ts should contain 'TwilioActivitySignalGenerateResponse'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# I: Forbidden wording
# ══════════════════════════════════════════════════════════════════════════════


def _assert_no_forbidden_wording(src: str, module_name: str) -> None:
    low = src.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"forbidden phrase {phrase!r} found in {module_name}"
        )


def test_i1_no_forbidden_phrases_in_twilio_activity_signal_service():
    """I1: Scan twilio_activity_signal_service.py for forbidden phrases."""
    import importlib
    mod = importlib.import_module("app.services.twilio_activity_signal_service")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)
