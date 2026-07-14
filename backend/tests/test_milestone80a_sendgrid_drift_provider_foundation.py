"""M80A — SendGrid drift provider foundation.

Tests the privacy-safe SendGrid connector that snapshots 8 safe configuration
surfaces from the SendGrid v3 REST API:

  1. Account metadata (type, reputation)
  2. API key metadata (never the key value)
  3. Verified sender identities (email domain only)
  4. Domain authentication (domain name, validity, DNS record count)
  5. Mail settings (boolean flags only)
  6. Tracking settings (boolean flags only)
  7. Event webhook configuration (boolean flags only — never the URL)
  8. Suppression group count

Auth uses a Bearer token (api_key) in the Authorization header.
The api_key is NEVER stored in any normalised record, NEVER logged, and
NEVER included in error messages.
"""

from __future__ import annotations

import inspect
import json
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
from app.connectors.sendgrid import (
    SendGridConnector,
    _MAX_PAGES,
    _email_domain,
    _trunc,
)
from app.connectors.sendgrid_schema import (
    SENDGRID_ACCOUNT,
    SENDGRID_API_KEY,
    SENDGRID_DOMAIN_AUTHENTICATION,
    SENDGRID_MAIL_SETTINGS,
    SENDGRID_RECORD_TYPES,
    SENDGRID_SENDER_IDENTITY,
    SENDGRID_SUPPRESSION_SETTINGS,
    SENDGRID_TRACKING_SETTINGS,
    SENDGRID_WEBHOOK_SETTINGS,
)

# ── Forbidden claim wording ──────────────────────────────────────────────────
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

# ── Sensitive field names that must NEVER appear in normalised records ────────
_SENSITIVE_FIELD_NAMES = frozenset({
    # Credentials / tokens
    "api_key",
    "api_key_value",
    "api_key_secret",
    "authorization",
    "bearer",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "password",
    "signing_secret",
    "oauth_client_secret",
    # Full email addresses
    "email",
    "from_email",
    "reply_to",
    "to_email",
    "owner_email",
    # Template / email content
    "subject",
    "html_content",
    "plain_text_content",
    "body",
    "template_content",
    "dynamic_template_data",
    # Recipient / contact data
    "recipient",
    "recipients",
    "contacts",
    "suppressed_email",
    # Webhook URL
    "url",
    "webhook_url",
    "inbound_parse_url",
    # Raw API payloads
    "raw_payload",
    "request_body",
    "response_body",
    # DNS record values
    "data",
    "value",         # raw DNS record value
})

# ── Test credentials (safe placeholder values) ────────────────────────────────
_API_KEY = "SENDGRID_TEST_API_KEY_PLACEHOLDER"
_CREDS = {"api_key": _API_KEY}


# ── Raw API response fixtures ─────────────────────────────────────────────────

def _raw_account() -> dict:
    return {"type": "paid", "reputation": 99.0}


def _raw_api_key() -> dict:
    return {
        "api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID",
        "name": "ConfigTrace Test Key",
        "scopes": ["mail.send", "stats.read"],
    }


def _raw_sender_identity() -> dict:
    return {
        "id": 12345,
        "nickname": "ConfigTrace Sender",
        "from_email": "sender@example-domain.com",
        "from_name": "ConfigTrace Sender Name",
        "reply_to": "reply@example-domain.com",
        "reply_to_name": "Reply Name",
        "address": "123 Main St",
        "city": "San Francisco",
        "state": "CA",
        "country": "US",
        "zip": "94107",
        "phone": "+14155551234",
        "verified": True,
        "locked": False,
    }


def _raw_domain_auth() -> dict:
    return {
        "id": 67890,
        "domain": "mail.example-domain.com",
        "subdomain": "em",
        "username": "test-user@example-domain.com",
        "valid": True,
        "automatic_security": True,
        "default": True,
        "legacy": False,
        "dns": {
            "mail_cname": {"host": "em.example-domain.com", "type": "cname", "data": "u12345.wl.sendgrid.net"},
            "dkim1": {"host": "s1._domainkey.example-domain.com", "type": "cname", "data": "s1.domainkey.u12345.wl.sendgrid.net"},
            "dkim2": {"host": "s2._domainkey.example-domain.com", "type": "cname", "data": "s2.domainkey.u12345.wl.sendgrid.net"},
        },
    }


def _raw_mail_settings() -> dict:
    return {
        "result": [
            {"name": "bcc", "enabled": False},
            {"name": "bounce_purge", "enabled": True},
            {"name": "footer", "enabled": False},
            {"name": "forward_bounce", "enabled": True},
            {"name": "forward_spam", "enabled": False},
            {"name": "sandbox_mode", "enabled": False},
            {"name": "spam_check", "enabled": True},
        ]
    }


def _raw_tracking_settings() -> dict:
    return {
        "result": [
            {"name": "click_tracking", "enabled": True},
            {"name": "open_tracking", "enabled": True},
            {"name": "subscription_tracking", "enabled": False},
            {"name": "ganalytics", "enabled": False},
        ]
    }


def _raw_webhook_settings() -> dict:
    return {
        "enabled": True,
        "url": "https://example.com/sendgrid-webhook",
        "oauth_client_id": "",
        "bounce": True,
        "click": True,
        "deferred": False,
        "delivered": True,
        "drop": False,
        "group_resubscribe": False,
        "group_unsubscribe": False,
        "open": True,
        "processed": True,
        "spam_report": False,
        "unsubscribe": False,
    }


def _raw_suppression_groups() -> list:
    return [
        {"id": 1, "name": "Marketing", "description": "Marketing emails"},
        {"id": 2, "name": "Transactional", "description": "Transactional emails"},
    ]


def _make_mock_client(responses: dict) -> MagicMock:
    """Return a mock httpx.Client that routes GETs by URL path substring."""
    mock_client = MagicMock()

    def _get_side_effect(path: str, params=None):
        resp = MagicMock()
        for key, payload in responses.items():
            if key in path:
                if isinstance(payload, Exception):
                    raise payload
                if isinstance(payload, int):
                    resp.status_code = payload
                    resp.headers = {}
                    resp.json.side_effect = ValueError("error response")
                    return resp
                resp.status_code = 200
                resp.headers = {}
                resp.json.return_value = payload
                return resp
        # Default 404
        resp.status_code = 404
        resp.headers = {}
        resp.json.side_effect = ValueError("not found")
        return resp

    mock_client.get.side_effect = _get_side_effect
    mock_client.__enter__ = lambda s: s
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


# ══════════════════════════════════════════════════════════════════════════════
# A. Schema constants
# ══════════════════════════════════════════════════════════════════════════════

class TestSchemaConstants:
    def test_all_eight_record_type_constants_exist(self):
        assert SENDGRID_ACCOUNT == "sendgrid_account"
        assert SENDGRID_API_KEY == "sendgrid_api_key"
        assert SENDGRID_SENDER_IDENTITY == "sendgrid_sender_identity"
        assert SENDGRID_DOMAIN_AUTHENTICATION == "sendgrid_domain_authentication"
        assert SENDGRID_MAIL_SETTINGS == "sendgrid_mail_settings"
        assert SENDGRID_TRACKING_SETTINGS == "sendgrid_tracking_settings"
        assert SENDGRID_WEBHOOK_SETTINGS == "sendgrid_webhook_settings"
        assert SENDGRID_SUPPRESSION_SETTINGS == "sendgrid_suppression_settings"

    def test_record_types_frozenset_has_all_eight_types(self):
        assert len(SENDGRID_RECORD_TYPES) == 8
        expected = {
            "sendgrid_account", "sendgrid_api_key", "sendgrid_sender_identity",
            "sendgrid_domain_authentication", "sendgrid_mail_settings",
            "sendgrid_tracking_settings", "sendgrid_webhook_settings",
            "sendgrid_suppression_settings",
        }
        assert set(SENDGRID_RECORD_TYPES) == expected

    def test_all_constants_are_canonical_lowercase_with_prefix(self):
        for rt in SENDGRID_RECORD_TYPES:
            assert rt.startswith("sendgrid_"), f"{rt} must start with 'sendgrid_'"
            assert rt == rt.lower(), f"{rt} must be all-lowercase"

    def test_record_types_is_frozenset(self):
        assert isinstance(SENDGRID_RECORD_TYPES, frozenset)


# ══════════════════════════════════════════════════════════════════════════════
# B. Connector instantiation and HTTP client
# ══════════════════════════════════════════════════════════════════════════════

class TestConnectorInstantiation:
    def test_connector_can_be_instantiated_with_no_args(self):
        conn = SendGridConnector()
        assert conn is not None

    def test_connector_has_no_credential_attributes(self):
        conn = SendGridConnector()
        for attr in ("api_key", "_api_key", "auth_token", "token"):
            assert not hasattr(conn, attr), (
                f"SendGridConnector must not store credentials as '{attr}'"
            )

    def test_make_client_returns_httpx_client(self):
        client = SendGridConnector._make_client(_API_KEY)
        assert isinstance(client, httpx_mod.Client)
        client.close()

    def test_make_client_includes_authorization_header(self):
        client = SendGridConnector._make_client(_API_KEY)
        # Authorization header must be set (api_key used for Bearer auth).
        auth_header = dict(client.headers).get("authorization", "")
        assert auth_header.startswith("Bearer "), (
            "SendGrid client must set Authorization: Bearer header"
        )
        client.close()

    def test_make_client_does_not_expose_api_key_in_base_url(self):
        client = SendGridConnector._make_client(_API_KEY)
        # api_key must never appear in the URL
        assert _API_KEY not in str(client.base_url)
        client.close()

    def test_api_key_never_in_client_attributes_other_than_header(self):
        """API key must only appear in the Authorization header, not as a plain attribute."""
        client = SendGridConnector._make_client(_API_KEY)
        # Must not appear as a named attribute on the client object
        for attr in ("api_key", "key", "secret", "password"):
            val = getattr(client, attr, None)
            assert val != _API_KEY, (
                f"api_key found in client.{attr} — must be in header only"
            )
        client.close()


# ══════════════════════════════════════════════════════════════════════════════
# C. Credential validation
# ══════════════════════════════════════════════════════════════════════════════

class TestCredentialValidation:
    def test_validate_credentials_returns_true_on_200(self):
        conn = SendGridConnector()
        resp = MagicMock(status_code=200, headers={})
        resp.json.return_value = {"type": "paid", "reputation": 99.0}
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.get.return_value = resp
            mock_cls.return_value.__enter__ = lambda s: ctx
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            assert conn.validate_credentials(_CREDS) is True

    def test_validate_credentials_raises_auth_error_on_401(self):
        conn = SendGridConnector()
        resp = MagicMock(status_code=401, headers={})
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.get.return_value = resp
            mock_cls.return_value.__enter__ = lambda s: ctx
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(AuthenticationError):
                conn.validate_credentials(_CREDS)

    def test_validate_credentials_raises_connector_error_on_403(self):
        conn = SendGridConnector()
        resp = MagicMock(status_code=403, headers={})
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.get.return_value = resp
            mock_cls.return_value.__enter__ = lambda s: ctx
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(ConnectorError) as exc:
                conn.validate_credentials(_CREDS)
            assert exc.value.status_code == 403

    def test_validate_credentials_raises_rate_limit_error_on_429(self):
        conn = SendGridConnector()
        resp = MagicMock(status_code=429, headers={"Retry-After": "30"})
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.get.return_value = resp
            mock_cls.return_value.__enter__ = lambda s: ctx
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RateLimitError) as exc:
                conn.validate_credentials(_CREDS)
            assert exc.value.retry_after == 30.0

    def test_validate_credentials_raises_auth_error_on_missing_api_key(self):
        conn = SendGridConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({})

    def test_validate_credentials_raises_auth_error_on_empty_api_key(self):
        conn = SendGridConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"api_key": ""})

    def test_validate_credentials_raises_auth_error_on_non_string_key(self):
        conn = SendGridConnector()
        with pytest.raises(AuthenticationError):
            conn.validate_credentials({"api_key": 12345})

    def test_validate_credentials_raises_network_error_on_connection_failure(self):
        conn = SendGridConnector()
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.get.side_effect = httpx_mod.ConnectError("refused")
            mock_cls.return_value.__enter__ = lambda s: ctx
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(NetworkError):
                conn.validate_credentials(_CREDS)


# ══════════════════════════════════════════════════════════════════════════════
# D. Account normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestAccountNormalization:
    def test_normalizes_paid_account(self):
        rec = SendGridConnector._normalize_account(_raw_account())
        assert rec["record_type"] == SENDGRID_ACCOUNT
        assert rec["record_id"] == "sendgrid_account_main"
        assert rec["account_type"] == "paid"
        assert rec["reputation"] == 99.0

    def test_normalizes_free_account(self):
        rec = SendGridConnector._normalize_account({"type": "free", "reputation": 85.5})
        assert rec["account_type"] == "free"
        assert rec["reputation"] == 85.5

    def test_normalizes_trusted_account(self):
        rec = SendGridConnector._normalize_account({"type": "trusted", "reputation": None})
        assert rec["account_type"] == "trusted"
        assert rec["reputation"] is None

    def test_normalizes_unknown_account_type(self):
        rec = SendGridConnector._normalize_account({"type": "enterprise"})
        assert rec["account_type"] == "enterprise"

    def test_missing_type_defaults_to_unknown(self):
        rec = SendGridConnector._normalize_account({})
        assert rec["account_type"] == "unknown"
        assert rec["reputation"] is None

    def test_provider_resource_id_is_safe(self):
        rec = SendGridConnector._normalize_account(_raw_account())
        assert rec["provider_resource_id"] == "accounts/main"

    def test_no_sensitive_fields_in_account_record(self):
        rec = SendGridConnector._normalize_account(_raw_account())
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' found in account record"
            )

    def test_account_record_is_json_serializable(self):
        rec = SendGridConnector._normalize_account(_raw_account())
        json.dumps(rec)  # must not raise


# ══════════════════════════════════════════════════════════════════════════════
# E. API key normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestApiKeyNormalization:
    def test_normalizes_api_key_with_scopes(self):
        rec = SendGridConnector._normalize_api_key(_raw_api_key())
        assert rec is not None
        assert rec["record_type"] == SENDGRID_API_KEY
        assert rec["api_key_id"] == "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID"
        assert rec["name"] == "ConfigTrace Test Key"
        assert rec["scopes_count"] == 2
        assert rec["has_mail_send"] is True
        assert rec["has_full_access"] is False

    def test_normalizes_api_key_without_scopes(self):
        raw = {"api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID", "name": "No Scopes"}
        rec = SendGridConnector._normalize_api_key(raw)
        assert rec is not None
        assert rec["scopes_count"] == 0
        assert rec["has_mail_send"] is False
        assert rec["has_full_access"] is False

    def test_api_key_value_never_in_record(self):
        rec = SendGridConnector._normalize_api_key(_raw_api_key())
        assert rec is not None
        for field in ("api_key", "api_key_value", "secret", "key_value", "bearer"):
            assert field not in rec, f"Sensitive field '{field}' in API key record"

    def test_api_key_name_is_truncated(self):
        raw = {"api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID", "name": "x" * 200}
        rec = SendGridConnector._normalize_api_key(raw)
        assert rec is not None
        assert len(rec["name"]) <= 100

    def test_missing_api_key_id_returns_none(self):
        rec = SendGridConnector._normalize_api_key({"name": "No ID"})
        assert rec is None

    def test_has_full_access_detected(self):
        raw = {
            "api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID",
            "name": "Admin Key",
            "scopes": ["admin.all"],
        }
        rec = SendGridConnector._normalize_api_key(raw)
        assert rec is not None
        assert rec["has_full_access"] is True

    def test_no_sensitive_fields_in_api_key_record(self):
        rec = SendGridConnector._normalize_api_key(_raw_api_key())
        assert rec is not None
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in API key record"
            )

    def test_api_key_record_is_json_serializable(self):
        rec = SendGridConnector._normalize_api_key(_raw_api_key())
        assert rec is not None
        json.dumps(rec)


# ══════════════════════════════════════════════════════════════════════════════
# F. Sender identity normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestSenderIdentityNormalization:
    def test_normalizes_verified_sender(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        assert rec["record_type"] == SENDGRID_SENDER_IDENTITY
        assert rec["sender_id"] == "12345"
        assert rec["nickname"] == "ConfigTrace Sender"
        assert rec["verified"] is True
        assert rec["locked"] is False

    def test_from_email_domain_only_no_full_address(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        # Must contain only the domain part, never the full email.
        domain = rec["from_email_domain"]
        assert "@" not in domain, "Full email address found in from_email_domain"
        assert domain == "example-domain.com"

    def test_reply_to_domain_only_no_full_address(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        domain = rec["reply_to_domain"]
        assert "@" not in domain
        assert domain == "example-domain.com"

    def test_full_email_not_stored(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        blob = json.dumps(rec)
        # Full email addresses must not appear.
        assert "sender@example-domain.com" not in blob
        assert "reply@example-domain.com" not in blob

    def test_pii_fields_not_stored(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        blob = json.dumps(rec)
        # Postal address, phone, and name must not appear.
        assert "123 Main St" not in blob
        assert "+14155551234" not in blob
        assert "San Francisco" not in blob
        assert "Sender Name" not in blob

    def test_missing_id_returns_none(self):
        assert SendGridConnector._normalize_sender_identity({"nickname": "No ID"}) is None

    def test_empty_email_gives_empty_domain(self):
        raw = {"id": 1, "nickname": "Test", "from_email": "", "reply_to": ""}
        rec = SendGridConnector._normalize_sender_identity(raw)
        assert rec is not None
        assert rec["from_email_domain"] == ""
        assert rec["reply_to_domain"] == ""

    def test_no_sensitive_fields_in_sender_record(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in sender identity record"
            )

    def test_sender_record_is_json_serializable(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        json.dumps(rec)


# ══════════════════════════════════════════════════════════════════════════════
# G. Domain authentication normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestDomainAuthNormalization:
    def test_normalizes_valid_domain_auth(self):
        rec = SendGridConnector._normalize_domain_auth(_raw_domain_auth())
        assert rec is not None
        assert rec["record_type"] == SENDGRID_DOMAIN_AUTHENTICATION
        assert rec["domain_id"] == "67890"
        assert rec["domain"] == "mail.example-domain.com"
        assert rec["valid"] is True
        assert rec["automatic_security"] is True
        assert rec["default"] is True
        assert rec["legacy"] is False
        assert rec["dns_record_count"] == 3

    def test_raw_dns_values_never_in_record(self):
        rec = SendGridConnector._normalize_domain_auth(_raw_domain_auth())
        assert rec is not None
        blob = json.dumps(rec)
        # Raw CNAME targets and DKIM keys must not appear.
        assert "u12345.wl.sendgrid.net" not in blob
        assert "s1.domainkey.u12345.wl.sendgrid.net" not in blob

    def test_subdomain_and_username_not_stored(self):
        rec = SendGridConnector._normalize_domain_auth(_raw_domain_auth())
        assert rec is not None
        assert "subdomain" not in rec
        assert "username" not in rec
        assert "em" not in json.dumps(rec)

    def test_missing_id_returns_none(self):
        assert SendGridConnector._normalize_domain_auth({"domain": "example.com"}) is None

    def test_empty_dns_gives_zero_count(self):
        raw = {"id": 1, "domain": "example.com", "dns": {}}
        rec = SendGridConnector._normalize_domain_auth(raw)
        assert rec is not None
        assert rec["dns_record_count"] == 0

    def test_no_sensitive_fields_in_domain_auth_record(self):
        rec = SendGridConnector._normalize_domain_auth(_raw_domain_auth())
        assert rec is not None
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in domain auth record"
            )

    def test_domain_auth_record_is_json_serializable(self):
        rec = SendGridConnector._normalize_domain_auth(_raw_domain_auth())
        assert rec is not None
        json.dumps(rec)


# ══════════════════════════════════════════════════════════════════════════════
# H. Mail settings normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestMailSettingsNormalization:
    def test_normalizes_mail_settings_booleans(self):
        rec = SendGridConnector._normalize_mail_settings(_raw_mail_settings())
        assert rec["record_type"] == SENDGRID_MAIL_SETTINGS
        assert rec["record_id"] == "sendgrid_mail_settings_main"
        assert rec["bcc_enabled"] is False
        assert rec["bounce_purge_enabled"] is True
        assert rec["footer_enabled"] is False
        assert rec["spam_check_enabled"] is True

    def test_mail_settings_missing_name_skipped(self):
        raw = {"result": [{"enabled": True}, {"name": "bcc", "enabled": True}]}
        rec = SendGridConnector._normalize_mail_settings(raw)
        assert rec["bcc_enabled"] is True

    def test_empty_settings_gives_all_false(self):
        rec = SendGridConnector._normalize_mail_settings({"result": []})
        assert rec["bcc_enabled"] is False
        assert rec["spam_check_enabled"] is False

    def test_no_sensitive_fields_in_mail_settings_record(self):
        rec = SendGridConnector._normalize_mail_settings(_raw_mail_settings())
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in mail settings record"
            )

    def test_mail_settings_record_is_json_serializable(self):
        json.dumps(SendGridConnector._normalize_mail_settings(_raw_mail_settings()))


# ══════════════════════════════════════════════════════════════════════════════
# I. Tracking settings normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestTrackingSettingsNormalization:
    def test_normalizes_tracking_settings_booleans(self):
        rec = SendGridConnector._normalize_tracking_settings(_raw_tracking_settings())
        assert rec["record_type"] == SENDGRID_TRACKING_SETTINGS
        assert rec["click_tracking_enabled"] is True
        assert rec["open_tracking_enabled"] is True
        assert rec["subscription_tracking_enabled"] is False
        assert rec["ganalytics_enabled"] is False

    def test_empty_settings_gives_all_false(self):
        rec = SendGridConnector._normalize_tracking_settings({"result": []})
        assert rec["click_tracking_enabled"] is False
        assert rec["ganalytics_enabled"] is False

    def test_no_sensitive_fields_in_tracking_settings(self):
        rec = SendGridConnector._normalize_tracking_settings(_raw_tracking_settings())
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in tracking settings record"
            )

    def test_tracking_settings_record_is_json_serializable(self):
        json.dumps(
            SendGridConnector._normalize_tracking_settings(_raw_tracking_settings())
        )


# ══════════════════════════════════════════════════════════════════════════════
# J. Webhook settings normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestWebhookSettingsNormalization:
    def test_normalizes_webhook_settings_booleans(self):
        rec = SendGridConnector._normalize_webhook_settings(_raw_webhook_settings())
        assert rec["record_type"] == SENDGRID_WEBHOOK_SETTINGS
        assert rec["event_webhook_enabled"] is True
        assert rec["event_webhook_has_url"] is True  # URL present → True
        assert rec["event_webhook_signed"] is False   # no oauth_client_id

    def test_webhook_url_never_stored(self):
        rec = SendGridConnector._normalize_webhook_settings(_raw_webhook_settings())
        blob = json.dumps(rec)
        assert "https://example.com/sendgrid-webhook" not in blob
        assert "example.com" not in blob
        assert "url" not in rec

    def test_webhook_event_count(self):
        rec = SendGridConnector._normalize_webhook_settings(_raw_webhook_settings())
        # bounce, click, delivered, open, processed = 5 True events
        assert rec["event_count"] == 5

    def test_empty_webhook_settings(self):
        rec = SendGridConnector._normalize_webhook_settings({})
        assert rec["event_webhook_enabled"] is False
        assert rec["event_webhook_has_url"] is False
        assert rec["event_webhook_signed"] is False
        assert rec["event_count"] == 0

    def test_webhook_signing_detected(self):
        raw = dict(_raw_webhook_settings(), oauth_client_id="some-oauth-id")
        rec = SendGridConnector._normalize_webhook_settings(raw)
        assert rec["event_webhook_signed"] is True

    def test_no_url_in_webhook_record(self):
        rec = SendGridConnector._normalize_webhook_settings(_raw_webhook_settings())
        assert "url" not in rec
        assert "webhook_url" not in rec

    def test_no_sensitive_fields_in_webhook_record(self):
        rec = SendGridConnector._normalize_webhook_settings(_raw_webhook_settings())
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in webhook settings record"
            )

    def test_webhook_settings_record_is_json_serializable(self):
        json.dumps(SendGridConnector._normalize_webhook_settings(_raw_webhook_settings()))


# ══════════════════════════════════════════════════════════════════════════════
# K. Suppression settings normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestSuppressionSettingsNormalization:
    def test_normalizes_group_count_from_list(self):
        rec = SendGridConnector._normalize_suppression_settings(
            _raw_suppression_groups()
        )
        assert rec["record_type"] == SENDGRID_SUPPRESSION_SETTINGS
        assert rec["record_id"] == "sendgrid_suppression_settings_main"
        assert rec["suppression_group_count"] == 2

    def test_normalizes_empty_group_list(self):
        rec = SendGridConnector._normalize_suppression_settings([])
        assert rec["suppression_group_count"] == 0

    def test_no_recipient_data_in_suppression_record(self):
        rec = SendGridConnector._normalize_suppression_settings(
            _raw_suppression_groups()
        )
        blob = json.dumps(rec)
        assert "Marketing" not in blob    # group names not stored
        assert "Transactional" not in blob

    def test_no_sensitive_fields_in_suppression_record(self):
        rec = SendGridConnector._normalize_suppression_settings(
            _raw_suppression_groups()
        )
        for field in _SENSITIVE_FIELD_NAMES:
            assert field not in rec, (
                f"Sensitive field '{field}' in suppression settings record"
            )

    def test_suppression_record_is_json_serializable(self):
        json.dumps(
            SendGridConnector._normalize_suppression_settings(_raw_suppression_groups())
        )


# ══════════════════════════════════════════════════════════════════════════════
# L. Privacy assertions (cross-record)
# ══════════════════════════════════════════════════════════════════════════════

class TestPrivacyAssertions:
    def _all_records(self) -> list[dict]:
        return [
            SendGridConnector._normalize_account(_raw_account()),
            SendGridConnector._normalize_api_key(_raw_api_key()),
            SendGridConnector._normalize_sender_identity(_raw_sender_identity()),
            SendGridConnector._normalize_domain_auth(_raw_domain_auth()),
            SendGridConnector._normalize_mail_settings(_raw_mail_settings()),
            SendGridConnector._normalize_tracking_settings(_raw_tracking_settings()),
            SendGridConnector._normalize_webhook_settings(_raw_webhook_settings()),
            SendGridConnector._normalize_suppression_settings(_raw_suppression_groups()),
        ]

    def test_no_sensitive_field_names_in_any_record(self):
        for rec in self._all_records():
            if rec is None:
                continue
            for field in _SENSITIVE_FIELD_NAMES:
                assert field not in rec, (
                    f"Sensitive field '{field}' in record {rec.get('record_type')}"
                )

    def test_api_key_placeholder_not_in_any_record(self):
        for rec in self._all_records():
            if rec is None:
                continue
            blob = json.dumps(rec)
            assert "SG." not in blob, (
                f"SG.-shaped API key in {rec.get('record_type')}"
            )

    def test_no_full_email_addresses_in_any_record(self):
        for rec in self._all_records():
            if rec is None:
                continue
            blob = json.dumps(rec)
            assert "sender@" not in blob
            assert "reply@" not in blob
            assert "test-user@" not in blob

    def test_no_webhook_url_strings_in_any_record(self):
        for rec in self._all_records():
            if rec is None:
                continue
            blob = json.dumps(rec)
            assert "https://example.com/sendgrid-webhook" not in blob

    def test_no_raw_dns_values_in_any_record(self):
        for rec in self._all_records():
            if rec is None:
                continue
            blob = json.dumps(rec)
            assert "u12345.wl.sendgrid.net" not in blob

    def test_no_pii_in_sender_record(self):
        rec = SendGridConnector._normalize_sender_identity(_raw_sender_identity())
        assert rec is not None
        blob = json.dumps(rec)
        assert "123 Main St" not in blob
        assert "+14155551234" not in blob
        assert "San Francisco" not in blob

    def test_all_records_have_record_type_and_record_id(self):
        for rec in self._all_records():
            if rec is None:
                continue
            assert "record_type" in rec, f"Missing record_type in {rec}"
            assert "record_id" in rec, f"Missing record_id in {rec}"
            assert rec["record_type"] in SENDGRID_RECORD_TYPES

    def test_all_records_json_serializable(self):
        blob = json.dumps(self._all_records())
        assert blob  # non-empty


# ══════════════════════════════════════════════════════════════════════════════
# M. Pagination bounding
# ══════════════════════════════════════════════════════════════════════════════

class TestPaginationBounding:
    def test_paginate_offset_stops_at_max_pages(self):
        call_count = 0

        def fake_get(client, path, params=None):
            nonlocal call_count
            call_count += 1
            return [{"id": call_count}]  # always return a full page

        with patch.object(SendGridConnector, "_get", staticmethod(fake_get)):
            items = SendGridConnector._paginate_offset(
                MagicMock(), "/v3/test", items_key=None,
                max_records=10000, page_size=1,
            )

        assert call_count == _MAX_PAGES

    def test_paginate_offset_stops_when_batch_smaller_than_page_size(self):
        call_count = 0

        def fake_get(client, path, params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [{"id": 1}, {"id": 2}]
            return []

        with patch.object(SendGridConnector, "_get", staticmethod(fake_get)):
            items = SendGridConnector._paginate_offset(
                MagicMock(), "/v3/test", items_key=None,
                max_records=100, page_size=10,
            )

        # Should have stopped after first page (batch < page_size)
        assert len(items) == 2
        assert call_count == 1

    def test_paginate_offset_respects_max_records(self):
        def fake_get(client, path, params=None):
            return [{"id": i} for i in range(100)]

        with patch.object(SendGridConnector, "_get", staticmethod(fake_get)):
            items = SendGridConnector._paginate_offset(
                MagicMock(), "/v3/test", items_key=None,
                max_records=5, page_size=100,
            )

        assert len(items) == 5

    def test_paginate_offset_handles_empty_first_page(self):
        def fake_get(client, path, params=None):
            return []

        with patch.object(SendGridConnector, "_get", staticmethod(fake_get)):
            items = SendGridConnector._paginate_offset(
                MagicMock(), "/v3/test", items_key=None,
                max_records=100, page_size=10,
            )

        assert items == []

    def test_paginate_offset_handles_items_key(self):
        def fake_get(client, path, params=None):
            return {"result": [{"id": 1}]}

        with patch.object(SendGridConnector, "_get", staticmethod(fake_get)):
            items = SendGridConnector._paginate_offset(
                MagicMock(), "/v3/test", items_key="result",
                max_records=100, page_size=10,
            )

        assert len(items) == 1


# ══════════════════════════════════════════════════════════════════════════════
# N. Error handling
# ══════════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    def test_raise_for_status_200_does_not_raise(self):
        resp = MagicMock(status_code=200, headers={})
        SendGridConnector._raise_for_status(resp)

    def test_raise_for_status_401_raises_auth_error(self):
        resp = MagicMock(status_code=401, headers={})
        with pytest.raises(AuthenticationError) as exc:
            SendGridConnector._raise_for_status(resp)
        assert exc.value.status_code == 401

    def test_raise_for_status_429_raises_rate_limit_error(self):
        resp = MagicMock(status_code=429, headers={"Retry-After": "60"})
        with pytest.raises(RateLimitError) as exc:
            SendGridConnector._raise_for_status(resp)
        assert exc.value.retry_after == 60.0

    def test_raise_for_status_429_no_retry_after(self):
        resp = MagicMock(status_code=429, headers={})
        with pytest.raises(RateLimitError):
            SendGridConnector._raise_for_status(resp)

    @pytest.mark.parametrize("status", [403, 404, 422, 500, 503])
    def test_raise_for_status_4xx_5xx_raises_connector_error(self, status: int):
        resp = MagicMock(status_code=status, headers={})
        with pytest.raises(ConnectorError) as exc:
            SendGridConnector._raise_for_status(resp)
        assert exc.value.status_code == status

    def test_get_raises_network_error_on_connect_error(self):
        client = MagicMock()
        client.get.side_effect = httpx_mod.ConnectError("refused")
        with pytest.raises(NetworkError):
            SendGridConnector._get(client, "/v3/user/account")

    def test_get_raises_network_error_on_timeout(self):
        client = MagicMock()
        client.get.side_effect = httpx_mod.TimeoutException("slow")
        with pytest.raises(NetworkError):
            SendGridConnector._get(client, "/v3/user/account")

    def test_get_raises_connector_error_on_invalid_json(self):
        resp = MagicMock(status_code=200, headers={})
        resp.json.side_effect = ValueError("bad json")
        client = MagicMock()
        client.get.return_value = resp
        with pytest.raises(ConnectorError):
            SendGridConnector._get(client, "/v3/user/account")

    def test_api_keys_403_does_not_crash_fetch(self):
        """A 403 on /v3/api_keys must fail soft — account record still returned."""
        mock_client = _make_mock_client({
            "user/account": _raw_account(),
            "api_keys": 403,
            "verified_senders": 403,
            "whitelabel/domains": 403,
            "mail_settings": 403,
            "tracking_settings": 403,
            "webhooks": 403,
            "asm/groups": 403,
        })
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)

        types = {r["record_type"] for r in records}
        assert SENDGRID_ACCOUNT in types

    def test_optional_surface_404_does_not_crash_fetch(self):
        """A 404 on optional surfaces must fail soft."""
        mock_client = _make_mock_client({
            "user/account": _raw_account(),
            "api_keys": 404,
            "verified_senders": _raw_sender_identity(),  # This won't work because it's not in "result"
            "whitelabel/domains": 404,
            "mail_settings": {"result": []},
            "tracking_settings": {"result": []},
            "webhooks": {"enabled": False, "url": ""},
            "asm/groups": [],
        })
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)

        types = {r["record_type"] for r in records}
        assert SENDGRID_ACCOUNT in types  # required surface still returned


# ══════════════════════════════════════════════════════════════════════════════
# O. Provider registration (sync_service + sync_task)
# ══════════════════════════════════════════════════════════════════════════════

class TestProviderRegistration:
    def test_sendgrid_in_supported_providers(self):
        import importlib
        import app.services.sync_service as sync_mod
        importlib.reload(sync_mod)
        src = inspect.getsource(sync_mod)
        assert '"sendgrid"' in src or "'sendgrid'" in src, (
            "sendgrid must be listed in _SUPPORTED_PROVIDERS in sync_service.py"
        )

    def test_sendgrid_dispatch_in_sync_task(self):
        import app.workers.sync_task as task_mod
        src = inspect.getsource(task_mod)
        assert 'integration.provider == "sendgrid"' in src, (
            "sync_task.py must dispatch on 'sendgrid' provider"
        )

    def test_sendgrid_connector_import_in_sync_task(self):
        import app.workers.sync_task as task_mod
        src = inspect.getsource(task_mod)
        assert "SendGridConnector" in src, (
            "sync_task.py must import SendGridConnector"
        )

    def test_sendgrid_connector_importable(self):
        from app.connectors.sendgrid import SendGridConnector as SG
        assert SG is not None

    def test_sendgrid_schema_importable(self):
        from app.connectors.sendgrid_schema import SENDGRID_RECORD_TYPES as RT
        assert len(RT) == 8


# ══════════════════════════════════════════════════════════════════════════════
# P. Capability matrix
# ══════════════════════════════════════════════════════════════════════════════

class TestCapabilityMatrix:
    def test_sendgrid_capability_entry_exists(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        assert cap is not None

    def test_sendgrid_label_and_category(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        assert cap.label == "SendGrid"
        assert cap.category == "communications"

    def test_sendgrid_maturity_is_partial(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        assert get_provider_capability("sendgrid").maturity == "partial"

    def test_sendgrid_drift_snapshots_true(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True

    def test_sendgrid_security_flags_false_in_m80a(self):
        """After M80B, security_rules flips True. Activity surfaces remain False."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        # security_rules flipped True in M80B.
        assert cap.security.security_rules is True
        # M80D rolled activity_ingestion forward to True.
        # M80E rolled activity_signals forward to True.
        assert cap.security.activity_ingestion is True
        assert cap.security.activity_signals is True
        assert cap.security.risk_activity_correlations is True  # M80F rolled forward
        assert cap.security.demo_seed_clear is True  # M80G rolled forward

    def test_sendgrid_in_provider_capabilities_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
        )
        canonical = {p.provider for p in PROVIDER_CAPABILITIES}
        partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "sendgrid" not in canonical, (
            "sendgrid must not be in the canonical 8-provider matrix"
        )
        assert "sendgrid" in partial, (
            "sendgrid must be in PROVIDER_CAPABILITIES_PARTIAL"
        )

    def test_sendgrid_notes_mention_m80a(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        notes = (cap.notes or "")
        assert "M80A" in notes

    def test_sendgrid_notes_no_forbidden_phrases(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        low = (cap.notes or "").lower()
        for phrase in _FORBIDDEN:
            assert phrase not in low, (
                f"Forbidden phrase {phrase!r} in SendGrid capability notes"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Q. Provider expansion framework
# ══════════════════════════════════════════════════════════════════════════════

class TestExpansionFramework:
    def _fw(self) -> dict:
        from app.services.provider_expansion_framework import get_framework
        return get_framework()

    def test_planned_next_stage_is_m80b(self):
        """All SendGrid milestones complete — planned_next_stage points to M89A Kubernetes."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M89A" in stage or "Kubernetes" in stage, (
            f"planned_next_stage should reference M89A Kubernetes; got: {stage!r}"
        )

    def test_m80a_not_in_planned_next_stage(self):
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M80A" not in stage, (
            f"M80A is done; planned_next_stage must advance past it (got: {stage!r})"
        )

    def test_sendgrid_not_in_recommended_queue(self):
        """SendGrid launched in M80A — must not be in the recommended queue."""
        recs = self._fw()["recommended_next_providers"]
        providers = [r["provider"] for r in recs]
        assert "sendgrid" not in providers, (
            "SendGrid launched in M80A and should no longer be in the recommended queue"
        )

    def test_twilio_not_in_recommended_queue(self):
        recs = self._fw()["recommended_next_providers"]
        providers = [r["provider"] for r in recs]
        assert "twilio" not in providers

    def test_sendgrid_auth0_or_another_is_next_recommendation(self):
        """After SendGrid launched, Auth0 or another provider should be top of queue."""
        recs = self._fw()["recommended_next_providers"]
        assert len(recs) > 0, "recommended_next_providers must not be empty"


# ══════════════════════════════════════════════════════════════════════════════
# R. Claim discipline
# ══════════════════════════════════════════════════════════════════════════════

class TestClaimDiscipline:
    def _strip_negation_contexts(self, src: str) -> str:
        out = []
        for line in src.splitlines():
            low = line.lower()
            if any(
                tok in low
                for tok in (
                    "does not confirm", "never assert", "never claim",
                    "do not claim", "forbidden", "not confirm",
                    "claim discipline", "review-safe", "avoid",
                )
            ):
                continue
            out.append(line)
        return "\n".join(out)

    def test_sendgrid_connector_has_no_forbidden_claims(self):
        import app.connectors.sendgrid as mod
        src = inspect.getsource(mod)
        stripped = self._strip_negation_contexts(src).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in stripped, (
                f"Forbidden phrase {phrase!r} in sendgrid.py"
            )

    def test_sendgrid_schema_has_no_forbidden_claims(self):
        import app.connectors.sendgrid_schema as mod
        src = inspect.getsource(mod)
        stripped = self._strip_negation_contexts(src).lower()
        for phrase in _FORBIDDEN:
            assert phrase not in stripped, (
                f"Forbidden phrase {phrase!r} in sendgrid_schema.py"
            )

    def test_capability_matrix_sendgrid_notes_no_forbidden_claims(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("sendgrid")
        low = (cap.notes or "").lower()
        for phrase in _FORBIDDEN:
            assert phrase not in low, (
                f"Forbidden phrase {phrase!r} in SendGrid capability notes"
            )


# ══════════════════════════════════════════════════════════════════════════════
# S. Fetch happy path (mocked HTTP)
# ══════════════════════════════════════════════════════════════════════════════

class TestFetchHappyPath:
    def _build_mock_client(self) -> MagicMock:
        return _make_mock_client({
            "user/account": _raw_account(),
            "api_keys": {"result": [_raw_api_key()]},
            "verified_senders": {"results": [_raw_sender_identity()]},
            "whitelabel/domains": [_raw_domain_auth()],
            "mail_settings": _raw_mail_settings(),
            "tracking_settings": _raw_tracking_settings(),
            "webhooks/event/settings": _raw_webhook_settings(),
            "asm/groups": _raw_suppression_groups(),
        })

    def test_fetch_returns_list(self):
        mock_client = self._build_mock_client()
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)
        assert isinstance(records, list)
        assert len(records) > 0

    def test_fetch_includes_all_record_types(self):
        mock_client = self._build_mock_client()
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)
        types = {r["record_type"] for r in records}
        # All 8 record types should be present.
        assert types == SENDGRID_RECORD_TYPES, (
            f"Fetch missing record types: {SENDGRID_RECORD_TYPES - types}"
        )

    def test_fetch_records_are_json_serializable(self):
        mock_client = self._build_mock_client()
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)
        json.dumps(records)  # must not raise

    def test_fetch_records_pass_privacy_denylist(self):
        mock_client = self._build_mock_client()
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)
        blob = json.dumps(records).lower()
        # No SG.-shaped API key.
        assert "sg." not in blob
        # No full email addresses.
        assert "sender@" not in blob
        assert "reply@" not in blob
        # No webhook URL strings.
        assert "https://example.com/sendgrid-webhook" not in blob
        # No sensitive field names.
        for field in _SENSITIVE_FIELD_NAMES:
            assert f'"{field}":' not in blob, (
                f"Sensitive field '{field}' found in fetch output"
            )

    def test_fetch_raises_auth_error_on_401_account(self):
        mock_client = _make_mock_client({"user/account": 401})
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            with pytest.raises(AuthenticationError):
                conn.fetch(_CREDS)

    def test_fetch_raises_auth_error_on_missing_api_key(self):
        conn = SendGridConnector()
        with pytest.raises(AuthenticationError):
            conn.fetch({})

    def test_fetch_account_record_has_correct_type(self):
        mock_client = self._build_mock_client()
        with patch("httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__ = lambda s: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            conn = SendGridConnector()
            records = conn.fetch(_CREDS)
        account_recs = [r for r in records if r["record_type"] == SENDGRID_ACCOUNT]
        assert len(account_recs) == 1
        assert account_recs[0]["account_type"] == "paid"


# ══════════════════════════════════════════════════════════════════════════════
# T. Utility helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilityHelpers:
    def test_trunc_truncates_long_string(self):
        assert len(_trunc("x" * 200)) == 100

    def test_trunc_returns_empty_for_non_string(self):
        assert _trunc(None) == ""
        assert _trunc(123) == ""

    def test_email_domain_extracts_domain(self):
        assert _email_domain("user@example.com") == "example.com"
        assert _email_domain("USER@EXAMPLE.COM") == "example.com"

    def test_email_domain_returns_empty_for_no_at(self):
        assert _email_domain("notanemail") == ""
        assert _email_domain("") == ""
        assert _email_domain(None) == ""

    def test_email_domain_uses_last_at_sign(self):
        assert _email_domain("weird@@example.com") == "example.com"


# ══════════════════════════════════════════════════════════════════════════════
# U. Diff tracked fields (drift detection) — QA regression
# ══════════════════════════════════════════════════════════════════════════════
#
# Regression coverage for a gap where SendGrid record types had no entry in
# diff_service's per-provider tracked-fields dispatch. Without an entry,
# `_tracked_fields_for` fell through every known provider prefix to the
# Cloudflare-DNS default tuple ("record_type", "name", "content", "ttl",
# "proxied", "priority", "comment") — none of which exist on any SendGrid
# record. compute_diff would therefore NEVER detect a modified field on an
# existing SendGrid record (API key scope changes, webhook signing toggled,
# tracking settings changed, etc.) even though the connector normalizes and
# the security-rules evaluator can already classify the field correctly.
# Only added/removed records would ever surface, since those don't depend on
# tracked fields at all.


class TestSendGridDiffTrackedFields:
    def test_all_eight_record_types_have_tracked_fields_entries(self):
        from app.services.diff_service import _SENDGRID_TRACKED_FIELDS_BY_TYPE
        from app.connectors.sendgrid_schema import SENDGRID_RECORD_TYPES

        for record_type in SENDGRID_RECORD_TYPES:
            assert record_type in _SENDGRID_TRACKED_FIELDS_BY_TYPE, (
                f"{record_type!r} has no tracked-fields entry — modified-field "
                "changes for this record type will never be detected by compute_diff"
            )

    def test_tracked_fields_dispatch_uses_sendgrid_table_not_cloudflare_default(self):
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS

        for record_type in (
            "sendgrid_account",
            "sendgrid_api_key",
            "sendgrid_sender_identity",
            "sendgrid_domain_authentication",
            "sendgrid_mail_settings",
            "sendgrid_tracking_settings",
            "sendgrid_webhook_settings",
            "sendgrid_suppression_settings",
        ):
            fields = _tracked_fields_for({"record_type": record_type})
            assert fields != _TRACKED_FIELDS, (
                f"{record_type!r} is falling through to the Cloudflare DNS "
                "default tracked-fields tuple instead of its own SendGrid fields"
            )
            assert fields, f"{record_type!r} resolved to an empty tracked-fields tuple"

    def test_api_key_broad_scope_change_produces_drift_change(self):
        """has_full_access False → True must surface as a Change.

        This is the exact scenario item A (API key scope broadening) depends
        on: if this field isn't tracked, the security finding would still
        fire on next evaluation, but the Changes timeline would never show
        the drift event at all.
        """
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _api_key_record(has_full_access: bool) -> dict:
            return {
                "record_id": "SG.abc123",
                "record_type": "sendgrid_api_key",
                "provider_resource_id": "api_keys/SG.abc123",
                "api_key_id": "SG.abc123",
                "name": "prod-key",
                "scopes_count": 5,
                "has_mail_send": True,
                "has_full_access": has_full_access,
            }

        prev = _mock_snapshot([_api_key_record(False)])
        new = _mock_snapshot([_api_key_record(True)])

        changes = compute_diff(prev, new)
        scope_changes = [c for c in changes if c["field_path"] == "has_full_access"]

        assert len(scope_changes) == 1
        assert scope_changes[0]["change_type"] == "modified"
        assert scope_changes[0]["prev_value"] is False
        assert scope_changes[0]["new_value"] is True

    def test_webhook_signing_disabled_change_produces_drift_change(self):
        """event_webhook_signed True → False must surface as a Change."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _webhook_record(signed: bool) -> dict:
            return {
                "record_id": "sendgrid_webhook_settings_main",
                "record_type": "sendgrid_webhook_settings",
                "provider_resource_id": "webhooks/event/settings/main",
                "event_webhook_enabled": True,
                "event_webhook_has_url": True,
                "event_webhook_signed": signed,
                "event_count": 3,
                "inbound_parse_enabled": False,
                "inbound_parse_spam_check_enabled": True,
                "inbound_parse_send_raw_enabled": False,
            }

        prev = _mock_snapshot([_webhook_record(True)])
        new = _mock_snapshot([_webhook_record(False)])

        changes = compute_diff(prev, new)
        signed_changes = [c for c in changes if c["field_path"] == "event_webhook_signed"]

        assert len(signed_changes) == 1
        assert signed_changes[0]["prev_value"] is True
        assert signed_changes[0]["new_value"] is False

    def test_click_tracking_enabled_change_produces_drift_change(self):
        """click_tracking_enabled False → True must surface as a Change."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _tracking_record(click_enabled: bool) -> dict:
            return {
                "record_id": "sendgrid_tracking_settings_main",
                "record_type": "sendgrid_tracking_settings",
                "provider_resource_id": "tracking_settings/main",
                "click_tracking_enabled": click_enabled,
                "open_tracking_enabled": False,
                "subscription_tracking_enabled": True,
                "ganalytics_enabled": False,
            }

        prev = _mock_snapshot([_tracking_record(False)])
        new = _mock_snapshot([_tracking_record(True)])

        changes = compute_diff(prev, new)
        click_changes = [c for c in changes if c["field_path"] == "click_tracking_enabled"]

        assert len(click_changes) == 1
        assert click_changes[0]["prev_value"] is False
        assert click_changes[0]["new_value"] is True

    def test_no_spurious_change_when_records_are_identical(self):
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        record = {
            "record_id": "sendgrid_mail_settings_main",
            "record_type": "sendgrid_mail_settings",
            "provider_resource_id": "mail_settings/main",
            "bcc_enabled": False,
            "bounce_purge_enabled": True,
            "footer_enabled": False,
            "forward_bounce_enabled": False,
            "forward_spam_enabled": False,
            "sandbox_mode_enabled": False,
            "spam_check_enabled": True,
            "template_enabled": False,
        }
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []
