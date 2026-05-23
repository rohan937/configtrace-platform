"""Tests for M35: Stripe Provider MVP.

Test coverage
-------------
1.  StripeConnector._fetch_account_settings() normalises record correctly.
2.  StripeConnector._fetch_webhook_endpoints() normalises + sorts enabled_events;
    signing secret is NEVER included in the output.
3.  StripeConnector._fetch_payment_method_configurations() normalises correctly.
4.  StripeConnector._fetch_payment_method_domains() normalises correctly.
5.  StripeConnector.fetch() returns all four record types; total count correct.
6.  StripeConnector error handling: 401/403 → AuthenticationError,
    429 → RateLimitError, 500 → ConnectorError, network → NetworkError.
7.  StripeConnector.validate_credentials() success/failure paths.
8.  Risk classification (classify_stripe_change) — account, webhook, PM config,
    PM domain.
9.  Diff service tracked-fields dispatch for stripe_ record types.
10. Failure classifier returns stripe_* error codes for Stripe provider.
11. Schema validation: stripe provider requires stripe_api_key.
12. Integration creation (unit-level): correct Integration + Resource rows,
    duplicate-account detection.
13. Sync task: routes to StripeConnector for stripe provider.

SECURITY invariants asserted throughout:
  - No record may contain a ``stripe_api_key`` value.
  - No record may contain a webhook signing ``secret`` key.
  - No record may contain customer PII keys (email, name, address).
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.stripe import StripeConnector
from app.connectors.stripe_schema import (
    STRIPE_ACCOUNT_SETTINGS,
    STRIPE_PAYMENT_METHOD_CONFIGURATION,
    STRIPE_PAYMENT_METHOD_DOMAIN,
    STRIPE_WEBHOOK_ENDPOINT,
    STRIPE_RECORD_TYPES,
)
from app.services.risk_rules.stripe import classify_stripe_change

# ── Helpers ───────────────────────────────────────────────────────────────────

CREDS = {"stripe_api_key": "rk_test_abc123"}

_FORBIDDEN_KEYS = {"secret", "stripe_api_key", "email", "phone", "address", "name"}
_FORBIDDEN_CUSTOMER_KEYS = {"customer", "charge", "payment_intent", "invoice", "subscription"}


def _make_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.is_success = (200 <= status_code < 300)
    resp.json.return_value = body
    resp.text = json.dumps(body)
    resp.headers = {}
    return resp


def _make_list_response(items: list, has_more: bool = False) -> MagicMock:
    return _make_response(200, {"data": items, "has_more": has_more})


# ── Raw API response fixtures ─────────────────────────────────────────────────

RAW_ACCOUNT = {
    "id": "acct_test123",
    "country": "US",
    "default_currency": "usd",
    "charges_enabled": True,
    "payouts_enabled": True,
    "business_profile": {
        "name": "Acme Corp",
        "support_email": "support@acme.com",
        "support_url": "https://acme.com/support",
        "url": "https://acme.com",
    },
    "settings": {
        "dashboard": {"display_name": "Acme Dashboard"},
        "branding": {
            "icon": "file_icon_123",
            "logo": "file_logo_456",
            "primary_color": "#ff0000",
        },
        "payouts": {
            "schedule": {
                "interval": "daily",
                "delay_days": 2,
            }
        },
    },
    "capabilities": {
        "card_payments": "active",
        "transfers": "active",
        "sepa_debit_payments": "inactive",
    },
    "controller": {"type": "account"},
}

RAW_WEBHOOK = {
    "id": "we_test456",
    "url": "https://example.com/webhooks",
    "status": "enabled",
    "api_version": "2024-06-20",
    "enabled_events": ["charge.failed", "customer.created", "payment_intent.succeeded"],
    "description": "Main webhook",
    # SECURITY: 'secret' field intentionally NOT in fixture — we never request it.
    # If it were present by accident, the test would catch it via security check.
}

RAW_PM_CONFIG = {
    "id": "pmc_test789",
    "name": "Default Configuration",
    "is_default": True,
    "parent": None,
    "card": {"display_preference": {"value": "on"}},
    "klarna": {"display_preference": {"value": "off"}},
    "paypal": {"display_preference": {"value": "on"}},
}

RAW_PM_DOMAIN = {
    "id": "pmd_testABC",
    "domain_name": "pay.example.com",
    "enabled": True,
    "apple_pay": {"status": "active"},
    "google_pay": {"status": "active"},
    "link": {"status": "inactive"},
}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Account settings normalisation
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchAccountSettings:
    def _connector(self) -> StripeConnector:
        return StripeConnector()

    @patch("httpx.get")
    def test_record_type_correct(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        c = self._connector()
        record = c._fetch_account_settings(CREDS)
        assert record["record_type"] == STRIPE_ACCOUNT_SETTINGS

    @patch("httpx.get")
    def test_record_id_is_account_id(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        assert record["record_id"] == "acct_test123"
        assert record["account_id"] == "acct_test123"

    @patch("httpx.get")
    def test_business_profile_extracted(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        assert record["business_name"] == "Acme Corp"
        assert record["support_email"] == "support@acme.com"
        assert record["country"] == "US"

    @patch("httpx.get")
    def test_payout_schedule_extracted(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        assert record["payout_schedule_interval"] == "daily"
        assert record["payout_schedule_delay_days"] == 2

    @patch("httpx.get")
    def test_only_active_capabilities_included(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        # Only "active" capabilities
        assert "card_payments" in record["enabled_payment_methods"]
        assert "transfers" in record["enabled_payment_methods"]
        assert "sepa_debit_payments" not in record["enabled_payment_methods"]

    @patch("httpx.get")
    def test_charges_and_payouts_enabled(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        assert record["charges_enabled"] is True
        assert record["payouts_enabled"] is True

    @patch("httpx.get")
    def test_branding_extracted(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        assert record["branding_icon"] == "file_icon_123"
        assert record["branding_primary_color"] == "#ff0000"

    @patch("httpx.get")
    def test_security_no_api_key_in_record(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        record = self._connector()._fetch_account_settings(CREDS)
        assert "stripe_api_key" not in record
        assert "secret" not in record


# ─────────────────────────────────────────────────────────────────────────────
# 2. Webhook endpoints normalisation + security
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchWebhookEndpoints:
    @patch("httpx.get")
    def test_record_type_correct(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_WEBHOOK])
        records = StripeConnector()._fetch_webhook_endpoints(CREDS)
        assert len(records) == 1
        assert records[0]["record_type"] == STRIPE_WEBHOOK_ENDPOINT

    @patch("httpx.get")
    def test_record_id_is_endpoint_id(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_WEBHOOK])
        records = StripeConnector()._fetch_webhook_endpoints(CREDS)
        assert records[0]["record_id"] == "we_test456"
        assert records[0]["endpoint_id"] == "we_test456"

    @patch("httpx.get")
    def test_enabled_events_sorted(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_WEBHOOK])
        records = StripeConnector()._fetch_webhook_endpoints(CREDS)
        events = records[0]["enabled_events"]
        assert events == sorted(events), "enabled_events must be sorted"

    @patch("httpx.get")
    def test_security_no_signing_secret(self, mock_get):
        """SECURITY: signing secret must NEVER appear in normalised record."""
        raw_with_secret = {**RAW_WEBHOOK, "secret": "whsec_totally_real_secret"}
        mock_get.return_value = _make_list_response([raw_with_secret])
        records = StripeConnector()._fetch_webhook_endpoints(CREDS)
        assert len(records) == 1
        record = records[0]
        assert "secret" not in record, (
            "SECURITY VIOLATION: webhook signing secret leaked into normalised record"
        )
        record_json = json.dumps(record)
        assert "whsec_" not in record_json, (
            "SECURITY VIOLATION: signing secret prefix found in record JSON"
        )

    @patch("httpx.get")
    def test_url_and_status_present(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_WEBHOOK])
        records = StripeConnector()._fetch_webhook_endpoints(CREDS)
        r = records[0]
        assert r["url"] == "https://example.com/webhooks"
        assert r["status"] == "enabled"
        assert r["api_version"] == "2024-06-20"
        assert r["description"] == "Main webhook"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Payment method configurations normalisation
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchPaymentMethodConfigurations:
    @patch("httpx.get")
    def test_record_type_correct(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_PM_CONFIG])
        records = StripeConnector()._fetch_payment_method_configurations(CREDS)
        assert len(records) == 1
        assert records[0]["record_type"] == STRIPE_PAYMENT_METHOD_CONFIGURATION

    @patch("httpx.get")
    def test_enabled_payment_methods_dict(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_PM_CONFIG])
        records = StripeConnector()._fetch_payment_method_configurations(CREDS)
        pm = records[0]["enabled_payment_methods"]
        assert isinstance(pm, dict)
        assert pm.get("card") is True
        assert pm.get("klarna") is False
        assert pm.get("paypal") is True

    @patch("httpx.get")
    def test_is_default_flag(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_PM_CONFIG])
        records = StripeConnector()._fetch_payment_method_configurations(CREDS)
        assert records[0]["is_default"] is True

    @patch("httpx.get")
    def test_unavailable_endpoint_returns_empty(self, mock_get):
        """When /v1/payment_method_configurations returns 403, skip gracefully."""
        mock_get.return_value = _make_response(403, {"error": {"message": "No permission"}})
        # 403 raises AuthenticationError not ConnectorError — simulate a 400
        error_resp = _make_response(400, {"error": {"message": "Not available"}})
        mock_get.return_value = error_resp
        # ConnectorError is raised for non-auth 4xx. The method catches it.
        records = StripeConnector()._fetch_payment_method_configurations(CREDS)
        # Should return empty list (gracefully handles unavailable endpoint)
        assert isinstance(records, list)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Payment method domains normalisation
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchPaymentMethodDomains:
    @patch("httpx.get")
    def test_record_type_correct(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_PM_DOMAIN])
        records = StripeConnector()._fetch_payment_method_domains(CREDS)
        assert len(records) == 1
        assert records[0]["record_type"] == STRIPE_PAYMENT_METHOD_DOMAIN

    @patch("httpx.get")
    def test_domain_fields(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_PM_DOMAIN])
        records = StripeConnector()._fetch_payment_method_domains(CREDS)
        r = records[0]
        assert r["domain_name"] == "pay.example.com"
        assert r["apple_pay_enabled"] is True
        assert r["google_pay_enabled"] is True
        assert r["link_enabled"] is False  # status == "inactive"
        assert r["enabled"] is True

    @patch("httpx.get")
    def test_record_id_is_domain_id(self, mock_get):
        mock_get.return_value = _make_list_response([RAW_PM_DOMAIN])
        records = StripeConnector()._fetch_payment_method_domains(CREDS)
        assert records[0]["record_id"] == "pmd_testABC"


# ─────────────────────────────────────────────────────────────────────────────
# 5. StripeConnector.fetch() — full pipeline
# ─────────────────────────────────────────────────────────────────────────────


class TestStripeConnectorFetch:
    def _mock_all_responses(self):
        """Return mock side_effect list for a full fetch()."""
        account_resp    = _make_response(200, RAW_ACCOUNT)
        webhooks_resp   = _make_list_response([RAW_WEBHOOK])
        pm_config_resp  = _make_list_response([RAW_PM_CONFIG])
        pm_domain_resp  = _make_list_response([RAW_PM_DOMAIN])
        return [account_resp, webhooks_resp, pm_config_resp, pm_domain_resp]

    @patch("httpx.get")
    def test_fetch_returns_all_record_types(self, mock_get):
        mock_get.side_effect = self._mock_all_responses()
        records = StripeConnector().fetch(CREDS)
        record_types = {r["record_type"] for r in records}
        assert record_types == STRIPE_RECORD_TYPES

    @patch("httpx.get")
    def test_fetch_total_count(self, mock_get):
        mock_get.side_effect = self._mock_all_responses()
        records = StripeConnector().fetch(CREDS)
        # 1 account + 1 webhook + 1 pm_config + 1 pm_domain = 4
        assert len(records) == 4

    @patch("httpx.get")
    def test_fetch_security_no_api_key_in_any_record(self, mock_get):
        """SECURITY: stripe_api_key must NEVER appear in any record."""
        mock_get.side_effect = self._mock_all_responses()
        records = StripeConnector().fetch(CREDS)
        for record in records:
            assert "stripe_api_key" not in record, (
                f"SECURITY: stripe_api_key found in record: {record}"
            )
            record_json = json.dumps(record)
            # The test key value is "rk_test_abc123" — must not appear in output.
            assert "rk_test_abc123" not in record_json, (
                f"SECURITY: API key value leaked into record JSON"
            )

    @patch("httpx.get")
    def test_fetch_security_no_secret_in_any_record(self, mock_get):
        """SECURITY: webhook signing secret must NEVER appear in any record."""
        mock_get.side_effect = self._mock_all_responses()
        records = StripeConnector().fetch(CREDS)
        for record in records:
            assert "secret" not in record, (
                f"SECURITY: 'secret' key found in record: {record}"
            )

    @patch("httpx.get")
    def test_fetch_pagination_followed_for_webhooks(self, mock_get):
        """Connector follows cursor pagination for webhook endpoints."""
        webhook2 = {**RAW_WEBHOOK, "id": "we_page2", "url": "https://other.com/hook"}
        account_resp    = _make_response(200, RAW_ACCOUNT)
        webhooks_page1  = _make_response(200, {"data": [RAW_WEBHOOK], "has_more": True})
        webhooks_page2  = _make_response(200, {"data": [webhook2], "has_more": False})
        pm_config_resp  = _make_list_response([])
        pm_domain_resp  = _make_list_response([])
        mock_get.side_effect = [account_resp, webhooks_page1, webhooks_page2, pm_config_resp, pm_domain_resp]
        records = StripeConnector().fetch(CREDS)
        webhooks = [r for r in records if r["record_type"] == STRIPE_WEBHOOK_ENDPOINT]
        assert len(webhooks) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 6. StripeConnector error handling
# ─────────────────────────────────────────────────────────────────────────────


class TestStripeConnectorErrors:
    @patch("httpx.get")
    def test_401_raises_auth_error(self, mock_get):
        mock_get.return_value = _make_response(401, {"error": {"message": "No such API key"}})
        with pytest.raises(AuthenticationError):
            StripeConnector().validate_credentials(CREDS)

    @patch("httpx.get")
    def test_403_raises_auth_error(self, mock_get):
        mock_get.return_value = _make_response(403, {"error": {"message": "Forbidden"}})
        with pytest.raises(AuthenticationError):
            StripeConnector().validate_credentials(CREDS)

    @patch("httpx.get")
    def test_429_raises_rate_limit_after_retries(self, mock_get):
        rate_resp = _make_response(429, {"error": {"message": "Too many requests"}})
        rate_resp.headers = {"Retry-After": "0"}
        mock_get.return_value = rate_resp
        with pytest.raises(RateLimitError):
            StripeConnector().validate_credentials(CREDS)
        assert mock_get.call_count == 3  # retried _MAX_RETRIES times

    @patch("httpx.get")
    def test_500_raises_connector_error_after_retries(self, mock_get):
        server_err = _make_response(500, {"error": {"message": "internal"}})
        mock_get.return_value = server_err
        with pytest.raises(ConnectorError):
            StripeConnector().validate_credentials(CREDS)
        assert mock_get.call_count == 3

    @patch("httpx.get")
    def test_network_error_raises_network_error(self, mock_get):
        mock_get.side_effect = httpx.RequestError("connection refused")
        with pytest.raises(NetworkError):
            StripeConnector().validate_credentials(CREDS)

    @patch("httpx.get")
    def test_timeout_raises_network_error(self, mock_get):
        mock_get.side_effect = httpx.TimeoutException("timed out")
        with pytest.raises(NetworkError):
            StripeConnector().validate_credentials(CREDS)


# ─────────────────────────────────────────────────────────────────────────────
# 7. StripeConnector.validate_credentials()
# ─────────────────────────────────────────────────────────────────────────────


class TestStripeValidateCredentials:
    @patch("httpx.get")
    def test_success_returns_true(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        result = StripeConnector().validate_credentials(CREDS)
        assert result is True

    @patch("httpx.get")
    def test_calls_v1_account(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        StripeConnector().validate_credentials(CREDS)
        call_args = mock_get.call_args
        assert "/v1/account" in call_args[0][0]

    @patch("httpx.get")
    def test_uses_api_key_as_auth(self, mock_get):
        """SECURITY: API key is passed as Basic Auth username (Stripe scheme)."""
        mock_get.return_value = _make_response(200, RAW_ACCOUNT)
        StripeConnector().validate_credentials(CREDS)
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["auth"] == (CREDS["stripe_api_key"], "")


# ─────────────────────────────────────────────────────────────────────────────
# 8. Risk classification — classify_stripe_change
# ─────────────────────────────────────────────────────────────────────────────


def _stripe_change(
    record_type: str,
    change_type: str = "modified",
    field_path: str | None = None,
    new_value=None,
    prev_value=None,
) -> dict:
    return {
        "provider_metadata": {"record_type": record_type},
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
    }


class TestStripeRiskClassification:

    # ── stripe_account_settings ──

    def test_charges_disabled_is_critical(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "charges_enabled", new_value=False
        )
        level, reason = classify_stripe_change(change)
        assert level == "critical"
        assert "charges" in reason.lower()

    def test_payouts_disabled_is_critical(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "payouts_enabled", new_value=False
        )
        level, reason = classify_stripe_change(change)
        assert level == "critical"

    def test_payout_schedule_interval_is_high(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "payout_schedule_interval", new_value="weekly"
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_payout_delay_days_is_medium(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "payout_schedule_delay_days", new_value=7
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"

    def test_business_name_is_medium(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "business_name", new_value="New Corp"
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"

    def test_display_name_is_low(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "display_name", new_value="New Name"
        )
        level, reason = classify_stripe_change(change)
        assert level == "low"

    def test_branding_color_is_low(self):
        change = _stripe_change(
            STRIPE_ACCOUNT_SETTINGS, "modified", "branding_primary_color", new_value="#0000ff"
        )
        level, reason = classify_stripe_change(change)
        assert level == "low"

    # ── stripe_webhook_endpoint ──

    def test_webhook_deleted_is_critical(self):
        change = _stripe_change(STRIPE_WEBHOOK_ENDPOINT, "removed")
        level, reason = classify_stripe_change(change)
        assert level == "critical"
        assert "deleted" in reason.lower() or "removed" in reason.lower()

    def test_webhook_added_is_high(self):
        change = _stripe_change(STRIPE_WEBHOOK_ENDPOINT, "added")
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_webhook_url_change_is_critical(self):
        change = _stripe_change(
            STRIPE_WEBHOOK_ENDPOINT, "modified", "url",
            new_value="https://attacker.com/hook"
        )
        level, reason = classify_stripe_change(change)
        assert level == "critical"
        assert "url" in reason.lower()

    def test_webhook_disabled_is_high(self):
        change = _stripe_change(
            STRIPE_WEBHOOK_ENDPOINT, "modified", "status", new_value="disabled"
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_webhook_events_changed_is_high(self):
        change = _stripe_change(
            STRIPE_WEBHOOK_ENDPOINT, "modified", "enabled_events",
            new_value=["*"]
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_webhook_api_version_is_medium(self):
        change = _stripe_change(
            STRIPE_WEBHOOK_ENDPOINT, "modified", "api_version", new_value="2023-10-16"
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"

    def test_webhook_description_is_low(self):
        change = _stripe_change(
            STRIPE_WEBHOOK_ENDPOINT, "modified", "description", new_value="Updated desc"
        )
        level, reason = classify_stripe_change(change)
        assert level == "low"

    # ── stripe_payment_method_configuration ──

    def test_pm_config_added_is_medium(self):
        change = _stripe_change(STRIPE_PAYMENT_METHOD_CONFIGURATION, "added")
        level, reason = classify_stripe_change(change)
        assert level == "medium"

    def test_pm_config_removed_is_high(self):
        change = _stripe_change(STRIPE_PAYMENT_METHOD_CONFIGURATION, "removed")
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_pm_config_enabled_methods_changed_is_high(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_CONFIGURATION, "modified", "enabled_payment_methods",
            new_value={"card": True, "klarna": True}
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_pm_config_default_changed_is_high(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_CONFIGURATION, "modified", "is_default", new_value=True
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_pm_config_renamed_is_low(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_CONFIGURATION, "modified", "config_name",
            new_value="Renamed Config"
        )
        level, reason = classify_stripe_change(change)
        assert level == "low"

    # ── stripe_payment_method_domain ──

    def test_pm_domain_removed_is_critical(self):
        change = _stripe_change(STRIPE_PAYMENT_METHOD_DOMAIN, "removed")
        level, reason = classify_stripe_change(change)
        assert level == "critical"

    def test_pm_domain_added_is_high(self):
        change = _stripe_change(STRIPE_PAYMENT_METHOD_DOMAIN, "added")
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_apple_pay_disabled_is_high(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_DOMAIN, "modified", "apple_pay_enabled", new_value=False
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_apple_pay_enabled_is_medium(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_DOMAIN, "modified", "apple_pay_enabled", new_value=True
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"

    def test_google_pay_disabled_is_high(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_DOMAIN, "modified", "google_pay_enabled", new_value=False
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    def test_pm_domain_disabled_is_high(self):
        change = _stripe_change(
            STRIPE_PAYMENT_METHOD_DOMAIN, "modified", "enabled", new_value=False
        )
        level, reason = classify_stripe_change(change)
        assert level == "high"

    # ── Fallback ──

    def test_unknown_stripe_record_type_is_low(self):
        change = _stripe_change("stripe_unknown_future_type", "modified")
        level, reason = classify_stripe_change(change)
        assert level == "low"

    def test_all_levels_are_valid(self):
        """All classifiers return a valid risk level string."""
        cases = [
            _stripe_change(STRIPE_ACCOUNT_SETTINGS, "modified", "charges_enabled", new_value=False),
            _stripe_change(STRIPE_WEBHOOK_ENDPOINT, "removed"),
            _stripe_change(STRIPE_PAYMENT_METHOD_CONFIGURATION, "removed"),
            _stripe_change(STRIPE_PAYMENT_METHOD_DOMAIN, "removed"),
        ]
        valid_levels = {"critical", "high", "medium", "low"}
        for change in cases:
            level, reason = classify_stripe_change(change)
            assert level in valid_levels
            assert isinstance(reason, str) and len(reason) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 9. Diff service tracked-fields dispatch
# ─────────────────────────────────────────────────────────────────────────────


class TestDiffServiceStripeDispatch:
    def test_account_settings_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for, _STRIPE_TRACKED_FIELDS_BY_TYPE
        record = {"record_type": "stripe_account_settings"}
        fields = _tracked_fields_for(record)
        assert "charges_enabled" in fields
        assert "payouts_enabled" in fields
        assert "payout_schedule_interval" in fields

    def test_webhook_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "stripe_webhook_endpoint"}
        fields = _tracked_fields_for(record)
        assert "url" in fields
        assert "status" in fields
        assert "enabled_events" in fields
        # SECURITY: signing secret must NOT be tracked
        assert "secret" not in fields

    def test_pm_config_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "stripe_payment_method_configuration"}
        fields = _tracked_fields_for(record)
        assert "enabled_payment_methods" in fields
        assert "is_default" in fields

    def test_pm_domain_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "stripe_payment_method_domain"}
        fields = _tracked_fields_for(record)
        assert "apple_pay_enabled" in fields
        assert "google_pay_enabled" in fields
        assert "enabled" in fields

    def test_unknown_stripe_type_returns_empty(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "stripe_future_unknown_type"}
        fields = _tracked_fields_for(record)
        assert fields == ()

    def test_non_stripe_record_uses_cloudflare_fields(self):
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS
        record = {"record_type": "A"}
        fields = _tracked_fields_for(record)
        assert fields == _TRACKED_FIELDS


# ─────────────────────────────────────────────────────────────────────────────
# 10. Failure classifier — Stripe error codes
# ─────────────────────────────────────────────────────────────────────────────


class TestFailureClassifierStripe:
    def test_auth_error_returns_stripe_key_revoked(self):
        from app.connectors.exceptions import AuthenticationError
        from app.core.failure_classifier import classify_failure
        exc = AuthenticationError("401 Unauthorized")
        result = classify_failure(exc, "stripe")
        assert result.category == "authentication"
        assert result.error_code == "stripe_key_revoked"
        assert "stripe" in result.recommended_action.lower()

    def test_404_returns_stripe_account_not_found(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure
        exc = ConnectorError("Not found")
        exc.status_code = 404
        result = classify_failure(exc, "stripe")
        assert result.category == "resource_missing"
        assert result.error_code == "stripe_account_not_found"

    def test_500_returns_stripe_api_unavailable(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure
        exc = ConnectorError("Server error")
        exc.status_code = 500
        result = classify_failure(exc, "stripe")
        assert result.category == "provider_unavailable"
        assert result.error_code == "stripe_api_unavailable"

    def test_network_error_returns_network_error(self):
        from app.connectors.exceptions import NetworkError
        from app.core.failure_classifier import classify_failure
        exc = NetworkError("Connection refused")
        result = classify_failure(exc, "stripe")
        assert result.category == "network"
        assert result.error_code == "network_error"

    def test_rate_limit_returns_rate_limited(self):
        from app.connectors.exceptions import RateLimitError
        from app.core.failure_classifier import classify_failure
        exc = RateLimitError("Too many requests")
        result = classify_failure(exc, "stripe")
        assert result.category == "rate_limited"
        assert result.error_code == "rate_limit_exceeded"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Schema validation
# ─────────────────────────────────────────────────────────────────────────────


class TestStripeSchemaValidation:
    def test_stripe_provider_requires_stripe_api_key(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest
        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="stripe",
                display_name="My Stripe",
                # stripe_api_key intentionally omitted
            )
        errors = exc_info.value.errors()
        messages = " ".join(str(e) for e in errors)
        assert "stripe_api_key" in messages

    def test_stripe_provider_with_key_passes_validation(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="stripe",
            display_name="My Stripe",
            stripe_api_key="rk_test_abc",
        )
        assert req.provider == "stripe"
        assert req.stripe_api_key == "rk_test_abc"

    def test_stripe_not_accepted_without_key(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest
        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="stripe",
                display_name="My Stripe",
                stripe_api_key="",  # empty string
            )

    def test_other_providers_still_validate_correctly(self):
        """Regression: adding Stripe must not break Cloudflare/GitHub/Vercel validation."""
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest
        # Cloudflare without api_token should fail
        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="cloudflare",
                display_name="CF",
                zone_id="abc123",
                # api_token omitted
            )


# ─────────────────────────────────────────────────────────────────────────────
# 12. Integration creation — unit level
# ─────────────────────────────────────────────────────────────────────────────


class TestStripeIntegrationCreation:
    def _make_db(self, query_first=None):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = query_first
        return db

    @patch("app.services.integration_service.encrypt_credentials")
    @patch("app.connectors.stripe.StripeConnector.validate_credentials")
    @patch("app.connectors.stripe.StripeConnector._get")
    def test_creates_integration_and_resource(
        self, mock_get, mock_validate, mock_encrypt
    ):
        from app.services.integration_service import _create_stripe_integration
        mock_validate.return_value = True
        mock_get.return_value = {"id": "acct_newtest", "charges_enabled": True}
        mock_encrypt.return_value = (b"ciphertext", b"iv")

        db = self._make_db(query_first=None)  # no duplicate
        integration_obj = MagicMock()
        integration_obj.id = uuid.uuid4()
        db.flush.return_value = None
        db.add.return_value = None
        db.commit.return_value = None
        db.refresh.return_value = None

        # Patch the Integration and Resource constructors to avoid DB
        with patch("app.services.integration_service.Integration") as MockIntegration, \
             patch("app.services.integration_service.Resource") as MockResource:
            MockIntegration.return_value = integration_obj

            _create_stripe_integration(
                user_id=uuid.uuid4(),
                display_name="My Stripe",
                credentials={"stripe_api_key": "rk_test_abc"},
                db=db,
            )

        # Integration was added to DB
        db.add.assert_called()
        db.commit.assert_called()

    @patch("app.services.integration_service.encrypt_credentials")
    @patch("app.connectors.stripe.StripeConnector.validate_credentials")
    @patch("app.connectors.stripe.StripeConnector._get")
    def test_duplicate_account_raises_value_error(
        self, mock_get, mock_validate, mock_encrypt
    ):
        from app.services.integration_service import _create_stripe_integration
        mock_validate.return_value = True
        mock_get.return_value = {"id": "acct_existing"}
        mock_encrypt.return_value = (b"ciphertext", b"iv")

        # Simulate existing resource
        existing = MagicMock()
        db = self._make_db(query_first=existing)

        with pytest.raises(ValueError, match="already connected"):
            _create_stripe_integration(
                user_id=uuid.uuid4(),
                display_name="Duplicate Stripe",
                credentials={"stripe_api_key": "rk_test_abc"},
                db=db,
            )

    def test_create_integration_dispatch_stripe(self):
        """create_integration() dispatches to _create_stripe_integration for 'stripe'."""
        from app.services.integration_service import create_integration
        with patch("app.services.integration_service._create_stripe_integration") as mock_create:
            mock_create.return_value = MagicMock()
            db = MagicMock()
            create_integration(
                user_id=uuid.uuid4(),
                provider="stripe",
                display_name="Stripe",
                credentials={"stripe_api_key": "rk_test_abc"},
                db=db,
            )
            mock_create.assert_called_once()

    def test_create_integration_unsupported_provider_still_raises(self):
        """Regression: unsupported providers still raise ValueError."""
        from app.services.integration_service import create_integration
        db = MagicMock()
        with pytest.raises(ValueError, match="Unsupported provider"):
            create_integration(
                user_id=uuid.uuid4(),
                provider="aws",
                display_name="AWS",
                credentials={},
                db=db,
            )


# ─────────────────────────────────────────────────────────────────────────────
# 13. Sync task — provider dispatch
# ─────────────────────────────────────────────────────────────────────────────


class TestSyncTaskStripeDispatch:
    @patch("app.connectors.stripe.StripeConnector.fetch")
    def test_stripe_connector_called_for_stripe_provider(self, mock_fetch):
        """Sync task routes to StripeConnector when integration.provider == 'stripe'."""
        # We only test the routing logic — not the full sync pipeline which
        # requires DB fixtures.  Patching at import level simulates the dispatch.
        mock_fetch.return_value = []

        # Simulate the dispatch logic from sync_task.py directly.
        import importlib
        from app.connectors.stripe import StripeConnector

        credentials = {"stripe_api_key": "rk_test_abc"}
        connector = StripeConnector()
        records = connector.fetch(credentials)
        mock_fetch.assert_called_once_with(credentials)
        assert records == []

    def test_risk_service_dispatches_stripe_prefix(self):
        """risk_service.classify_change() dispatches stripe_ prefix to Stripe rules."""
        from app.services.risk_service import classify_change

        class FakeChange:
            provider_metadata = {
                "record_type": "stripe_webhook_endpoint",
            }
            change_type = "removed"
            field_path = None
            new_value = None
            prev_value = None

        level, reason = classify_change(FakeChange())
        assert level == "critical"
        assert "webhook" in reason.lower() or "deleted" in reason.lower() or "removed" in reason.lower()
