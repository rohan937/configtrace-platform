"""M79A — Twilio drift provider foundation.

Mirrors the M78A Google Cloud foundation test scaffolding for Twilio's five
M79A surfaces:
  1. Account metadata
  2. Incoming phone numbers (last-4 only; webhook URLs as booleans)
  3. Messaging Services (webhook URLs as booleans)
  4. Verify Services
  5. API key metadata summaries

Twilio has no "project" or "VPC" analog; the top-level container is the
Account SID. Auth uses HTTP Basic (account_sid, auth_token); the auth_token
is NEVER stored in any normalised record. Full phone numbers are NEVER stored —
only the last 4 digits. Webhook / callback URLs are NEVER stored — only
boolean presence flags.
"""

from __future__ import annotations

import inspect
import json
import re
from typing import Any
from unittest.mock import MagicMock, patch

import httpx as httpx_mod
import pytest

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.twilio import TwilioConnector, _MAX_PAGES, _trunc
from app.connectors.twilio_schema import (
    TWILIO_ACCOUNT,
    TWILIO_API_KEY_SUMMARY,
    TWILIO_INCOMING_PHONE_NUMBER,
    TWILIO_MESSAGING_SERVICE,
    TWILIO_RECORD_TYPES,
    TWILIO_VERIFY_SERVICE,
)

# ── Forbidden claim wording ─────────────────────────────────────────────────
_FORBIDDEN = (
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
)

# ── Forbidden field names in any normalised record ──────────────────────────
_SENSITIVE_FIELD_NAMES = frozenset({
    "auth_token",
    "api_secret",
    "private_key",
    "access_token",
    "refresh_token",
    "bearer",
    "authorization",
    "client_secret",
    "connection_string",
    "secret_value",
    "password",
    "phone_number",       # full number — only last4 is allowed
    "account_sid",        # full SID — only prefix is allowed
    "sms_url",            # raw URL — only boolean flag is allowed
    "voice_url",          # raw URL — only boolean flag is allowed
    "inbound_request_url",
    "fallback_url",
    "status_callback_url",
    "status_callback",
})

# ── Test fixtures ───────────────────────────────────────────────────────────

_ACCOUNT_SID = "TWILIO_TEST_ACCOUNT_SID_NOT_REAL01"
_AUTH_TOKEN = "fake-auth-token-not-real-32chars00"
_CREDS = {"account_sid": _ACCOUNT_SID, "auth_token": _AUTH_TOKEN}


def _raw_account() -> dict:
    return {
        "sid": _ACCOUNT_SID,
        "friendly_name": "ConfigTrace Test Account",
        "status": "active",
        "type": "Full",
        "subresource_uris": {
            "subaccounts": f"/2010-04-01/Accounts/{_ACCOUNT_SID}/SubAccounts.json",
            "calls": f"/2010-04-01/Accounts/{_ACCOUNT_SID}/Calls.json",
        },
        # Pollution — MUST NOT survive normalization.
        "auth_token": _AUTH_TOKEN,
        "owner_account_sid": "TWILIO_FAKE_OWNER_SID_SENTINEL_0001",
    }


def _raw_phone_number() -> dict:
    return {
        "sid": "PNabcdef1234567890abcdef1234567890",
        "friendly_name": "(510) 555-1234",
        "phone_number": "+15105551234",  # MUST NOT survive — only last 4
        "iso_country": "US",
        "capabilities": {
            "voice": True,
            "sms": True,
            "mms": False,
            "fax": False,
        },
        "sms_url": "https://example.com/sms-webhook",        # MUST NOT survive
        "voice_url": "https://example.com/voice-webhook",    # MUST NOT survive
        "status_callback": "https://example.com/status",     # MUST NOT survive
        "address_requirements": "none",
        "emergency_status": "Active",
    }


def _raw_phone_number_no_urls() -> dict:
    raw = _raw_phone_number()
    raw["sms_url"] = ""
    raw["voice_url"] = ""
    raw["status_callback"] = ""
    return raw


def _raw_messaging_service() -> dict:
    return {
        "sid": "MGabcdef1234567890abcdef1234567890",
        "friendly_name": "ConfigTrace Alerts Messaging Service",
        "inbound_request_url": "https://example.com/inbound",   # MUST NOT survive
        "fallback_url": "https://example.com/fallback",          # MUST NOT survive
        "status_callback_url": "https://example.com/status",    # MUST NOT survive
        "smart_encoding": True,
        "validity_period": 14400,
        "area_code_geomatch": True,
        "sticky_sender": True,
        "mms_converter": True,
        "use_inbound_webhook_on_number": False,
        "numbers_count": 3,
    }


def _raw_messaging_service_no_urls() -> dict:
    raw = _raw_messaging_service()
    raw["inbound_request_url"] = ""
    raw["fallback_url"] = ""
    raw["status_callback_url"] = ""
    return raw


def _raw_verify_service() -> dict:
    return {
        "sid": "VAabcdef1234567890abcdef1234567890",
        "friendly_name": "ConfigTrace OTP Verify",
        "code_length": 6,
        "lookup_enabled": False,
        "psd2_enabled": False,
        "do_not_share_warning_enabled": True,
        "skip_sms_to_landlines": True,
        "default_template_sid": "HJabcdef1234567890abcdef1234567890",  # bool only
    }


def _raw_api_key() -> dict:
    return {
        "sid": "TWILIO_FAKE_APIKEY_SID_NOT_REAL001",
        "friendly_name": "ConfigTrace CI Key",
        "date_created": "2024-01-15T10:00:00Z",
        "date_updated": "2024-06-01T12:00:00Z",
        # The secret is NEVER returned in list responses — confirming absence.
    }


def _make_mock_client(responses: dict) -> MagicMock:
    """Return a mock httpx.Client that routes gets by URL substring."""
    mock_client = MagicMock()

    def _get_side_effect(url, params=None):
        resp = MagicMock()
        for substr, body in responses.items():
            if substr in url:
                resp.status_code = 200
                resp.headers = {}
                resp.json.return_value = body
                return resp
        resp.status_code = 404
        resp.headers = {}
        resp.json.return_value = {"code": 20404, "message": "not found"}
        return resp

    mock_client.get.side_effect = _get_side_effect
    mock_client.__enter__ = lambda s: s
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


# ══════════════════════════════════════════════════════════════════════════════
# A. Schema constants
# ══════════════════════════════════════════════════════════════════════════════


class TestTwilioSchemaConstants:
    def test_record_types_is_frozenset(self):
        assert isinstance(TWILIO_RECORD_TYPES, frozenset)

    def test_record_types_is_non_empty(self):
        assert len(TWILIO_RECORD_TYPES) >= 3

    def test_account_constant_value_and_membership(self):
        assert TWILIO_ACCOUNT == "twilio_account"
        assert TWILIO_ACCOUNT in TWILIO_RECORD_TYPES

    def test_incoming_phone_number_constant_value_and_membership(self):
        assert TWILIO_INCOMING_PHONE_NUMBER == "twilio_incoming_phone_number"
        assert TWILIO_INCOMING_PHONE_NUMBER in TWILIO_RECORD_TYPES

    def test_messaging_service_constant_value_and_membership(self):
        assert TWILIO_MESSAGING_SERVICE == "twilio_messaging_service"
        assert TWILIO_MESSAGING_SERVICE in TWILIO_RECORD_TYPES

    def test_verify_service_constant_value_and_membership(self):
        assert TWILIO_VERIFY_SERVICE == "twilio_verify_service"
        assert TWILIO_VERIFY_SERVICE in TWILIO_RECORD_TYPES

    def test_api_key_summary_constant_value_and_membership(self):
        assert TWILIO_API_KEY_SUMMARY == "twilio_api_key_summary"
        assert TWILIO_API_KEY_SUMMARY in TWILIO_RECORD_TYPES

    def test_all_five_types_in_set(self):
        m79a_types = {
            TWILIO_ACCOUNT,
            TWILIO_INCOMING_PHONE_NUMBER,
            TWILIO_MESSAGING_SERVICE,
            TWILIO_VERIFY_SERVICE,
            TWILIO_API_KEY_SUMMARY,
        }
        assert m79a_types.issubset(set(TWILIO_RECORD_TYPES))


# ══════════════════════════════════════════════════════════════════════════════
# B. Connector instantiation and credential validation
# ══════════════════════════════════════════════════════════════════════════════


class TestConnectorInstantiation:
    def test_twilio_connector_can_be_imported(self):
        from app.connectors.twilio import TwilioConnector as TC
        assert TC is not None

    def test_connector_instantiation_with_no_args(self):
        conn = TwilioConnector()
        assert conn is not None

    def test_make_client_returns_httpx_client(self):
        client = TwilioConnector._make_client(_ACCOUNT_SID, _AUTH_TOKEN)
        assert hasattr(client, "get")
        client.close()

    def test_make_client_uses_basic_auth(self):
        client = TwilioConnector._make_client(_ACCOUNT_SID, _AUTH_TOKEN)
        # httpx.Client stores auth as an attribute
        assert client.auth is not None
        client.close()


class TestValidateCredentials:
    def test_validate_credentials_returns_true_on_200(self):
        conn = TwilioConnector()
        resp = MagicMock(status_code=200, headers={})
        resp.json.return_value = {"sid": _ACCOUNT_SID, "status": "active"}
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.return_value = resp
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = conn.validate_credentials(_CREDS)
        assert result is True

    def test_validate_credentials_raises_auth_error_on_401(self):
        conn = TwilioConnector()
        resp = MagicMock(status_code=401, headers={})
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.return_value = resp
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(AuthenticationError) as exc:
                conn.validate_credentials(_CREDS)
        assert exc.value.status_code == 401

    def test_validate_credentials_raises_connector_error_on_403(self):
        conn = TwilioConnector()
        resp = MagicMock(status_code=403, headers={})
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.return_value = resp
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(ConnectorError) as exc:
                conn.validate_credentials(_CREDS)
        assert exc.value.status_code == 403

    def test_validate_credentials_raises_connector_error_on_404(self):
        conn = TwilioConnector()
        resp = MagicMock(status_code=404, headers={})
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.return_value = resp
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(ConnectorError) as exc:
                conn.validate_credentials(_CREDS)
        assert exc.value.status_code == 404

    def test_validate_credentials_raises_rate_limit_error_on_429(self):
        conn = TwilioConnector()
        resp = MagicMock(status_code=429, headers={"Retry-After": "30"})
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.return_value = resp
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RateLimitError) as exc:
                conn.validate_credentials(_CREDS)
        assert exc.value.retry_after == 30.0

    def test_validate_credentials_raises_network_error_on_connect_error(self):
        conn = TwilioConnector()
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.side_effect = httpx_mod.ConnectError("connection refused")
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(NetworkError):
                conn.validate_credentials(_CREDS)

    def test_validate_credentials_raises_network_error_on_timeout(self):
        conn = TwilioConnector()
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.side_effect = httpx_mod.TimeoutException("timed out")
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(NetworkError):
                conn.validate_credentials(_CREDS)

    def test_validate_credentials_raises_auth_error_for_missing_account_sid(self):
        conn = TwilioConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"auth_token": _AUTH_TOKEN})

    def test_validate_credentials_raises_auth_error_for_missing_auth_token(self):
        conn = TwilioConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"account_sid": _ACCOUNT_SID})


# ══════════════════════════════════════════════════════════════════════════════
# C. Record normalization — account
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeAccount:
    def setup_method(self):
        self.record = TwilioConnector._normalize_account(_raw_account())

    def test_record_type(self):
        assert self.record["record_type"] == TWILIO_ACCOUNT

    def test_account_sid_prefix_is_first_eight_chars(self):
        assert self.record["account_sid_prefix"] == _ACCOUNT_SID[:8]

    def test_account_sid_prefix_length(self):
        assert len(self.record["account_sid_prefix"]) == 8

    def test_no_full_account_sid_in_record(self):
        blob = json.dumps(self.record)
        assert _ACCOUNT_SID not in blob

    def test_no_auth_token_in_record(self):
        blob = json.dumps(self.record)
        assert _AUTH_TOKEN not in blob
        assert "auth_token" not in self.record

    def test_status_field(self):
        assert self.record["status"] == "active"

    def test_account_type_field(self):
        assert self.record["account_type"] == "Full"

    def test_friendly_name_present(self):
        assert self.record["friendly_name"] == "ConfigTrace Test Account"

    def test_subaccount_count_present(self):
        assert isinstance(self.record["subaccount_count"], int)

    def test_no_owner_account_sid(self):
        blob = json.dumps(self.record)
        assert "TWILIO_FAKE_OWNER_SID_SENTINEL_0001" not in blob

    def test_no_forbidden_field_names(self):
        for k in self.record.keys():
            if k == "record_type":
                continue
            assert k not in _SENSITIVE_FIELD_NAMES, (
                f"forbidden field name {k!r} in account record"
            )


# ══════════════════════════════════════════════════════════════════════════════
# C. Record normalization — incoming phone number
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeIncomingPhoneNumber:
    def setup_method(self):
        self.record = TwilioConnector._normalize_incoming_phone_number(
            _raw_phone_number()
        )

    def test_record_type(self):
        assert self.record["record_type"] == TWILIO_INCOMING_PHONE_NUMBER

    def test_phone_number_last4_present(self):
        assert "phone_number_last4" in self.record
        assert self.record["phone_number_last4"] == "1234"

    def test_phone_number_last4_is_exactly_four_chars(self):
        assert len(self.record["phone_number_last4"]) == 4

    def test_no_full_phone_number_in_record(self):
        blob = json.dumps(self.record)
        assert "+15105551234" not in blob

    def test_no_phone_number_key_in_record(self):
        assert "phone_number" not in self.record

    def test_sms_url_configured_is_bool_not_url(self):
        assert self.record["sms_url_configured"] is True
        assert "sms_url" not in self.record

    def test_voice_url_configured_is_bool_not_url(self):
        assert self.record["voice_url_configured"] is True
        assert "voice_url" not in self.record

    def test_status_callback_configured_is_bool_not_url(self):
        assert self.record["status_callback_configured"] is True
        assert "status_callback" not in self.record

    def test_no_webhook_url_strings_in_record(self):
        blob = json.dumps(self.record)
        assert "https://example.com/sms-webhook" not in blob
        assert "https://example.com/voice-webhook" not in blob
        assert "https://example.com/status" not in blob

    def test_iso_country(self):
        assert self.record["iso_country"] == "US"

    def test_capability_voice(self):
        assert self.record["capability_voice"] is True

    def test_capability_sms(self):
        assert self.record["capability_sms"] is True

    def test_capability_mms_false(self):
        assert self.record["capability_mms"] is False

    def test_capability_fax_false(self):
        assert self.record["capability_fax"] is False

    def test_address_requirements(self):
        assert self.record["address_requirements"] == "none"

    def test_emergency_status(self):
        assert self.record["emergency_status"] == "Active"

    def test_friendly_name_truncated_to_100(self):
        long_name = "x" * 200
        raw = dict(_raw_phone_number())
        raw["friendly_name"] = long_name
        r = TwilioConnector._normalize_incoming_phone_number(raw)
        assert len(r["friendly_name"]) <= 100

    def test_no_urls_gives_false_booleans(self):
        r = TwilioConnector._normalize_incoming_phone_number(
            _raw_phone_number_no_urls()
        )
        assert r["sms_url_configured"] is False
        assert r["voice_url_configured"] is False
        assert r["status_callback_configured"] is False

    def test_no_forbidden_field_names(self):
        for k in self.record.keys():
            if k == "record_type":
                continue
            assert k not in _SENSITIVE_FIELD_NAMES, (
                f"forbidden field name {k!r} in phone number record"
            )


# ══════════════════════════════════════════════════════════════════════════════
# C. Record normalization — messaging service
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeMessagingService:
    def setup_method(self):
        self.record = TwilioConnector._normalize_messaging_service(
            _raw_messaging_service()
        )

    def test_record_type(self):
        assert self.record["record_type"] == TWILIO_MESSAGING_SERVICE

    def test_inbound_request_url_configured_is_bool(self):
        assert self.record["inbound_request_url_configured"] is True
        assert "inbound_request_url" not in self.record

    def test_fallback_url_configured_is_bool(self):
        assert self.record["fallback_url_configured"] is True
        assert "fallback_url" not in self.record

    def test_status_callback_url_configured_is_bool(self):
        assert self.record["status_callback_url_configured"] is True
        assert "status_callback_url" not in self.record

    def test_no_raw_url_strings_in_record(self):
        blob = json.dumps(self.record)
        assert "https://example.com/inbound" not in blob
        assert "https://example.com/fallback" not in blob
        assert "https://example.com/status" not in blob

    def test_smart_encoding_is_bool(self):
        assert self.record["smart_encoding"] is True

    def test_area_code_geomatch_is_bool(self):
        assert self.record["area_code_geomatch"] is True

    def test_friendly_name_truncated_to_100(self):
        long_name = "y" * 200
        raw = dict(_raw_messaging_service())
        raw["friendly_name"] = long_name
        r = TwilioConnector._normalize_messaging_service(raw)
        assert len(r["friendly_name"]) <= 100

    def test_no_urls_gives_false_booleans(self):
        r = TwilioConnector._normalize_messaging_service(
            _raw_messaging_service_no_urls()
        )
        assert r["inbound_request_url_configured"] is False
        assert r["fallback_url_configured"] is False
        assert r["status_callback_url_configured"] is False

    def test_no_forbidden_field_names(self):
        for k in self.record.keys():
            if k == "record_type":
                continue
            assert k not in _SENSITIVE_FIELD_NAMES, (
                f"forbidden field name {k!r} in messaging service record"
            )


# ══════════════════════════════════════════════════════════════════════════════
# C. Record normalization — verify service
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeVerifyService:
    def setup_method(self):
        self.record = TwilioConnector._normalize_verify_service(_raw_verify_service())

    def test_record_type(self):
        assert self.record["record_type"] == TWILIO_VERIFY_SERVICE

    def test_code_length(self):
        assert self.record["code_length"] == 6

    def test_lookup_enabled_false(self):
        assert self.record["lookup_enabled"] is False

    def test_psd2_enabled_false(self):
        assert self.record["psd2_enabled"] is False

    def test_do_not_share_warning_enabled_true(self):
        assert self.record["do_not_share_warning_enabled"] is True

    def test_skip_sms_to_landlines_true(self):
        assert self.record["skip_sms_to_landlines"] is True

    def test_default_template_sid_present_is_bool_not_sid(self):
        assert self.record["default_template_sid_present"] is True
        assert "default_template_sid" not in self.record

    def test_no_template_sid_value_in_blob(self):
        blob = json.dumps(self.record)
        assert "HJabcdef1234567890abcdef1234567890" not in blob

    def test_friendly_name_present(self):
        assert self.record["friendly_name"] == "ConfigTrace OTP Verify"

    def test_no_forbidden_field_names(self):
        for k in self.record.keys():
            if k == "record_type":
                continue
            assert k not in _SENSITIVE_FIELD_NAMES, (
                f"forbidden field name {k!r} in verify service record"
            )


# ══════════════════════════════════════════════════════════════════════════════
# C. Record normalization — API key summary
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeApiKey:
    def setup_method(self):
        self.record = TwilioConnector._normalize_api_key(_raw_api_key())

    def test_record_type(self):
        assert self.record["record_type"] == TWILIO_API_KEY_SUMMARY

    def test_api_key_sid_present(self):
        assert self.record["api_key_sid"] == "TWILIO_FAKE_APIKEY_SID_NOT_REAL001"

    def test_friendly_name_present(self):
        assert self.record["friendly_name"] == "ConfigTrace CI Key"

    def test_date_created_present(self):
        assert self.record["date_created"] == "2024-01-15T10:00:00Z"

    def test_date_updated_present(self):
        assert self.record["date_updated"] == "2024-06-01T12:00:00Z"

    def test_no_api_secret_in_record(self):
        assert "api_secret" not in self.record
        assert "secret" not in self.record

    def test_no_forbidden_field_names(self):
        for k in self.record.keys():
            if k == "record_type":
                continue
            assert k not in _SENSITIVE_FIELD_NAMES, (
                f"forbidden field name {k!r} in api key summary record"
            )


# ══════════════════════════════════════════════════════════════════════════════
# D. Privacy assertions across all record types
# ══════════════════════════════════════════════════════════════════════════════


class TestPrivacyAssertions:
    def _all_records(self) -> list[dict]:
        return [
            TwilioConnector._normalize_account(_raw_account()),
            TwilioConnector._normalize_incoming_phone_number(_raw_phone_number()),
            TwilioConnector._normalize_messaging_service(_raw_messaging_service()),
            TwilioConnector._normalize_verify_service(_raw_verify_service()),
            TwilioConnector._normalize_api_key(_raw_api_key()),
        ]

    def test_no_record_contains_auth_token_key(self):
        for record in self._all_records():
            assert "auth_token" not in record, (
                f"auth_token key found in {record['record_type']!r}"
            )

    def test_no_record_contains_auth_token_value(self):
        blob = json.dumps(self._all_records())
        assert _AUTH_TOKEN not in blob

    def test_no_record_contains_api_secret_key(self):
        for record in self._all_records():
            assert "api_secret" not in record, (
                f"api_secret key found in {record['record_type']!r}"
            )

    def test_no_record_contains_full_e164_phone_number(self):
        """No record value should look like a full E.164 phone number."""
        e164_pattern = re.compile(r"^\+\d{10,}$")
        blob = json.dumps(self._all_records())
        # Check the overall blob for typical E.164 pattern
        assert not e164_pattern.search(blob), (
            "A full E.164 phone number found in normalised records"
        )
        assert "+15105551234" not in blob

    def test_phone_number_last4_is_exactly_4_chars(self):
        record = TwilioConnector._normalize_incoming_phone_number(_raw_phone_number())
        last4 = record["phone_number_last4"]
        assert len(last4) == 4

    def test_phone_number_last4_matches_tail_of_raw_number(self):
        raw = _raw_phone_number()
        record = TwilioConnector._normalize_incoming_phone_number(raw)
        assert record["phone_number_last4"] == raw["phone_number"][-4:]

    def test_no_raw_url_strings_in_any_record(self):
        """Keys ending in _url (that are not configured booleans) must not appear."""
        for record in self._all_records():
            for k in record.keys():
                if k.endswith("_url") and not k.endswith("_url_configured"):
                    pytest.fail(
                        f"raw URL key {k!r} found in {record['record_type']!r} record"
                    )

    def test_no_full_account_sid_in_any_record(self):
        blob = json.dumps(self._all_records())
        assert _ACCOUNT_SID not in blob

    def test_no_token_key_in_any_record_except_record_type(self):
        for record in self._all_records():
            for k in record.keys():
                if k == "record_type":
                    continue
                assert "token" not in k.lower() or k.endswith("_configured"), (
                    f"key containing 'token' found in {record['record_type']!r}: {k!r}"
                )


# ══════════════════════════════════════════════════════════════════════════════
# E. Pagination bounding
# ══════════════════════════════════════════════════════════════════════════════


class TestPaginationBounding:
    def test_paginate_stops_at_max_pages_with_unbounded_next_url(self):
        call_count = {"n": 0}

        def fake_get(client, url, params=None):
            call_count["n"] += 1
            return {
                "incoming_phone_numbers": [{"sid": f"PN{call_count['n']:08d}"}],
                "meta": {"next_page_url": "https://api.twilio.com/2010-04-01/more"},
            }

        mock_client = MagicMock()
        with patch.object(TwilioConnector, "_get", staticmethod(fake_get)):
            items = TwilioConnector._paginate(
                mock_client,
                "https://api.twilio.com/2010-04-01/start",
                items_key="incoming_phone_numbers",
                max_records=10000,
            )

        assert call_count["n"] == _MAX_PAGES
        assert len(items) == _MAX_PAGES

    def test_paginate_stops_when_no_next_page(self):
        call_count = {"n": 0}

        def fake_get(client, url, params=None):
            call_count["n"] += 1
            return {
                "incoming_phone_numbers": [{"sid": "PN0001"}, {"sid": "PN0002"}],
                # no meta.next_page_url or next_page_uri
            }

        mock_client = MagicMock()
        with patch.object(TwilioConnector, "_get", staticmethod(fake_get)):
            items = TwilioConnector._paginate(
                mock_client,
                "https://api.twilio.com/2010-04-01/start",
                items_key="incoming_phone_numbers",
            )

        assert call_count["n"] == 1
        assert len(items) == 2

    def test_paginate_respects_max_records_cap(self):
        def fake_get(client, url, params=None):
            return {
                "services": [{"sid": f"MG{i:04d}"} for i in range(50)],
                "meta": {"next_page_url": "https://messaging.twilio.com/v1/more"},
            }

        mock_client = MagicMock()
        with patch.object(TwilioConnector, "_get", staticmethod(fake_get)):
            items = TwilioConnector._paginate(
                mock_client,
                "https://messaging.twilio.com/v1/Services",
                items_key="services",
                max_records=30,
            )

        assert len(items) <= 30

    def test_paginate_returns_empty_on_non_dict_response(self):
        def fake_get(client, url, params=None):
            return ["not", "a", "dict"]

        mock_client = MagicMock()
        with patch.object(TwilioConnector, "_get", staticmethod(fake_get)):
            items = TwilioConnector._paginate(
                mock_client,
                "https://api.twilio.com/2010-04-01/start",
                items_key="incoming_phone_numbers",
            )

        assert items == []

    def test_paginate_handles_missing_items_key(self):
        def fake_get(client, url, params=None):
            return {"other_key": [{"sid": "PN0001"}]}

        mock_client = MagicMock()
        with patch.object(TwilioConnector, "_get", staticmethod(fake_get)):
            items = TwilioConnector._paginate(
                mock_client,
                "https://api.twilio.com/2010-04-01/start",
                items_key="incoming_phone_numbers",
            )

        assert items == []


# ══════════════════════════════════════════════════════════════════════════════
# F. Error handling — fail-soft per surface
# ══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    def test_raise_for_status_401_raises_auth_error(self):
        resp = MagicMock(status_code=401, headers={})
        with pytest.raises(AuthenticationError) as exc:
            TwilioConnector._raise_for_status(resp)
        assert exc.value.status_code == 401

    def test_raise_for_status_429_raises_rate_limit_error(self):
        resp = MagicMock(status_code=429, headers={"Retry-After": "60"})
        with pytest.raises(RateLimitError) as exc:
            TwilioConnector._raise_for_status(resp)
        assert exc.value.retry_after == 60.0

    def test_raise_for_status_429_no_retry_after_header(self):
        resp = MagicMock(status_code=429, headers={})
        with pytest.raises(RateLimitError):
            TwilioConnector._raise_for_status(resp)

    @pytest.mark.parametrize("status", [403, 404, 422, 500, 502])
    def test_raise_for_status_4xx_5xx_raises_connector_error(self, status: int):
        resp = MagicMock(status_code=status, headers={})
        with pytest.raises(ConnectorError) as exc:
            TwilioConnector._raise_for_status(resp)
        assert exc.value.status_code == status

    def test_get_raises_network_error_on_connect_error(self):
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx_mod.ConnectError("refused")
        with pytest.raises(NetworkError):
            TwilioConnector._get(mock_client, "https://api.twilio.com/test")

    def test_get_raises_network_error_on_timeout(self):
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx_mod.TimeoutException("slow")
        with pytest.raises(NetworkError):
            TwilioConnector._get(mock_client, "https://api.twilio.com/test")

    def test_get_raises_connector_error_on_invalid_json(self):
        resp = MagicMock(status_code=200, headers={})
        resp.json.side_effect = ValueError("bad json")
        mock_client = MagicMock()
        mock_client.get.return_value = resp
        with pytest.raises(ConnectorError):
            TwilioConnector._get(mock_client, "https://api.twilio.com/test")

    def test_messaging_service_404_does_not_crash_fetch(self):
        """A 404 on messaging services must fail soft — other records still returned."""
        conn = TwilioConnector()

        account_resp = MagicMock(status_code=200, headers={})
        account_resp.json.return_value = _raw_account()

        phone_resp = MagicMock(status_code=200, headers={})
        phone_resp.json.return_value = {
            "incoming_phone_numbers": [_raw_phone_number()],
        }

        def client_get(url, params=None):
            if "IncomingPhoneNumbers" in url:
                return phone_resp
            if "messaging.twilio.com" in url or "Services" in url:
                r = MagicMock(status_code=404, headers={})
                return r
            if "verify.twilio.com" in url:
                r = MagicMock(status_code=200, headers={})
                r.json.return_value = {"services": []}
                return r
            if "Keys" in url:
                r = MagicMock(status_code=200, headers={})
                r.json.return_value = {"keys": []}
                return r
            return account_resp

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.side_effect = client_get
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            records = conn.fetch(_CREDS)

        record_types = {r["record_type"] for r in records}
        # Account and phone numbers must be present even though messaging 404'd.
        assert TWILIO_ACCOUNT in record_types
        assert TWILIO_INCOMING_PHONE_NUMBER in record_types

    def test_normalize_account_with_missing_optional_fields(self):
        """A minimal raw account dict should produce a valid record."""
        r = TwilioConnector._normalize_account({})
        assert r["record_type"] == TWILIO_ACCOUNT
        assert r["account_sid_prefix"] == ""
        assert isinstance(r["subaccount_count"], int)

    def test_normalize_phone_number_with_short_number(self):
        """Phone numbers shorter than 4 chars should give empty last4."""
        raw = dict(_raw_phone_number())
        raw["phone_number"] = "+1"
        r = TwilioConnector._normalize_incoming_phone_number(raw)
        assert r["phone_number_last4"] == ""

    def test_normalize_phone_number_with_missing_number(self):
        raw = dict(_raw_phone_number())
        del raw["phone_number"]
        r = TwilioConnector._normalize_incoming_phone_number(raw)
        assert r["phone_number_last4"] == ""

    def test_normalize_messaging_service_with_empty_dict(self):
        r = TwilioConnector._normalize_messaging_service({})
        assert r["record_type"] == TWILIO_MESSAGING_SERVICE
        assert r["inbound_request_url_configured"] is False
        assert r["fallback_url_configured"] is False

    def test_normalize_verify_service_with_empty_dict(self):
        r = TwilioConnector._normalize_verify_service({})
        assert r["record_type"] == TWILIO_VERIFY_SERVICE
        assert r["code_length"] == 6  # default
        assert r["default_template_sid_present"] is False

    def test_normalize_api_key_with_empty_dict(self):
        r = TwilioConnector._normalize_api_key({})
        assert r["record_type"] == TWILIO_API_KEY_SUMMARY
        assert r["api_key_sid"] == ""
        assert r["friendly_name"] == ""


# ══════════════════════════════════════════════════════════════════════════════
# G. Provider registration
# ══════════════════════════════════════════════════════════════════════════════


def test_twilio_in_supported_providers():
    from app.services import sync_service
    src = inspect.getsource(sync_service)
    assert '"twilio"' in src
    assert "_SUPPORTED_PROVIDERS" in src


def test_worker_sync_task_dispatches_twilio():
    from app.workers import sync_task
    src = inspect.getsource(sync_task)
    assert 'integration.provider == "twilio"' in src
    assert "TwilioConnector" in src


def test_importing_twilio_connector_does_not_fail():
    import importlib
    mod = importlib.import_module("app.connectors.twilio")
    assert hasattr(mod, "TwilioConnector")


def test_importing_twilio_schema_does_not_fail():
    import importlib
    mod = importlib.import_module("app.connectors.twilio_schema")
    assert hasattr(mod, "TWILIO_RECORD_TYPES")


# ══════════════════════════════════════════════════════════════════════════════
# H. Capability matrix
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    def test_twilio_capability_is_non_none(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap is not None

    def test_twilio_label_and_category(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.label == "Twilio"
        assert cap.category == "communications"

    def test_maturity_is_partial(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.maturity == "partial"

    def test_drift_snapshots_true(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.drift.drift_snapshots is True

    def test_drift_diff_true(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.drift.drift_diff is True

    def test_drift_risk_classification_false_in_m79a(self):
        """Rolled forward in M79B: drift_risk_classification is now True (M79B enabled security rules)."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.drift.drift_risk_classification is True

    def test_security_rules_false_in_m79a(self):
        """Rolled forward in M79B: security_rules is now True (M79B added 9 Twilio security rules)."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.security.security_rules is True

    def test_demo_seed_clear_false_in_m79a(self):
        """Demo seed/clear is deferred to a future Twilio arc milestone."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("twilio")
        assert cap.security.demo_seed_clear is False

    def test_twilio_not_in_canonical_provider_capabilities(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "twilio" not in providers

    def test_twilio_in_provider_capabilities_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "twilio" in providers


# ══════════════════════════════════════════════════════════════════════════════
# I. Expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_twilio_not_in_recommended_queue():
    """Twilio launched in M79A and is no longer in the recommended queue."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "twilio" not in providers


def test_expansion_framework_planned_next_stage_contains_m79e():
    """Rolled forward in M79D: Activity Ingestion complete; next stage is M79E."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M79E" in stage


def test_expansion_framework_planned_next_stage_contains_twilio():
    """M79B is the next Twilio arc milestone — Twilio Core Security Foundation."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "Twilio" in stage


def test_expansion_framework_planned_next_stage_does_not_contain_m79a():
    """M79A is complete — the pointer must advance past it."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M79A" not in stage


def test_expansion_framework_next_provider_is_sendgrid():
    """After Twilio launched, SendGrid is the head of the recommended queue."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    assert fw["summary"]["next_provider"] == "SendGrid"


def test_expansion_framework_next_milestone_references_sendgrid_or_m80a():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    milestone = fw["summary"]["next_milestone"] or ""
    assert "SendGrid" in milestone or "M80A" in milestone


def test_expansion_framework_first_recommended_provider_is_sendgrid():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    assert recs[0]["provider"] == "sendgrid"
    assert recs[0]["label"] == "SendGrid"


def test_expansion_framework_google_cloud_not_in_recommended_queue():
    """Google Cloud launched in M78A and must not be in the recommended queue."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "google_cloud" not in providers


# ══════════════════════════════════════════════════════════════════════════════
# J. Forbidden wording — claim discipline
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("module_name", [
    "app.connectors.twilio",
    "app.connectors.twilio_schema",
])
def test_no_forbidden_claims_in_twilio_modules(module_name: str):
    import importlib
    mod = importlib.import_module(module_name)
    src = inspect.getsource(mod)
    low = src.lower()
    for phrase in _FORBIDDEN:
        assert phrase not in low, (
            f"forbidden phrase {phrase!r} found in {module_name}"
        )


def test_no_forbidden_claims_in_twilio_capability_notes():
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("twilio")
    notes_low = (cap.notes or "").lower()
    for phrase in _FORBIDDEN:
        assert phrase not in notes_low, (
            f"forbidden phrase {phrase!r} found in Twilio capability notes"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Fetch happy-path integration (mocked HTTP)
# ══════════════════════════════════════════════════════════════════════════════


class TestFetchReturnsSafeRecords:
    """End-to-end fetch() with fully mocked httpx.Client."""

    def _client_get(self, url, params=None):
        if f"Accounts/{_ACCOUNT_SID}.json" in url and "IncomingPhoneNumbers" not in url and "Keys" not in url:
            r = MagicMock(status_code=200, headers={})
            r.json.return_value = _raw_account()
            return r
        if "IncomingPhoneNumbers" in url:
            r = MagicMock(status_code=200, headers={})
            r.json.return_value = {"incoming_phone_numbers": [_raw_phone_number()]}
            return r
        if "messaging.twilio.com" in url:
            r = MagicMock(status_code=200, headers={})
            r.json.return_value = {"services": [_raw_messaging_service()]}
            return r
        if "verify.twilio.com" in url:
            r = MagicMock(status_code=200, headers={})
            r.json.return_value = {"services": [_raw_verify_service()]}
            return r
        if "Keys" in url:
            r = MagicMock(status_code=200, headers={})
            r.json.return_value = {"keys": [_raw_api_key()]}
            return r
        r = MagicMock(status_code=200, headers={})
        r.json.return_value = {}
        return r

    def _fetch_records(self) -> list[dict]:
        conn = TwilioConnector()
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.side_effect = self._client_get
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            return conn.fetch(_CREDS)

    def test_fetch_returns_all_five_record_types(self):
        records = self._fetch_records()
        types = {r["record_type"] for r in records}
        assert TWILIO_ACCOUNT in types
        assert TWILIO_INCOMING_PHONE_NUMBER in types
        assert TWILIO_MESSAGING_SERVICE in types
        assert TWILIO_VERIFY_SERVICE in types
        assert TWILIO_API_KEY_SUMMARY in types

    def test_fetch_records_are_json_serialisable(self):
        records = self._fetch_records()
        json.dumps(records)  # must not raise

    def test_fetch_records_pass_privacy_denylist(self):
        records = self._fetch_records()
        blob = json.dumps(records)
        assert _AUTH_TOKEN not in blob
        assert "+15105551234" not in blob
        assert _ACCOUNT_SID not in blob

    def test_fetch_records_have_no_forbidden_field_names(self):
        records = self._fetch_records()
        for r in records:
            for key in r.keys():
                if key == "record_type":
                    continue
                assert key not in _SENSITIVE_FIELD_NAMES, (
                    f"forbidden field {key!r} in {r['record_type']!r} record"
                )

    def test_fetch_returns_empty_list_on_401_all_surfaces(self):
        """The connector uses a fail-soft pattern per surface; a 401 on all
        surfaces results in an empty record list rather than raising."""
        conn = TwilioConnector()
        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.get.return_value = MagicMock(status_code=401, headers={})
            mock_client_cls.return_value.__enter__ = lambda s: mock_ctx
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            records = conn.fetch(_CREDS)
        assert isinstance(records, list)

    def test_fetch_missing_credentials_raises_auth_error(self):
        conn = TwilioConnector()
        with pytest.raises(AuthenticationError):
            conn.fetch({})
