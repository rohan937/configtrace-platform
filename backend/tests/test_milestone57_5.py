"""Tests for Milestone 57.5 — Shopify Provider MVP.

Covers:
1.  Schema / record type constants (SHOPIFY_RECORD_TYPES, TypedDicts)
2.  Shop domain normalization (strip https://, lowercase, rstrip /)
3.  Shop domain validation (reject localhost/private/internal ranges)
4.  Connector _hash helper
5.  Connector _decompose_webhook_url (no raw URL stored, domain+hash only)
6.  Connector _fetch_shop_metadata (safe fields only — no email/phone/address)
7.  Connector _fetch_webhook_subscriptions (URL decomposed, never raw)
8.  Connector _fetch_store_policies (hash+length only, never raw text)
9.  Connector fetch() aggregates surfaces
10. Connector validate_credentials()
11. Forbidden endpoint strings absent from connector source code
12. Diff tracked fields for all three record types
13. Risk rules — shop metadata directional changes
14. Risk rules — webhook added/removed/non-HTTPS
15. Risk rules — store policy changes
16. Risk service dispatch to shopify rules
17. Failure classifier — auth, 403, 404, 5xx
18. Integration schema — "shopify" in Literal, field validation
19. Integration schema — reconnect request shopify field
20. Router _build_credentials for shopify
21. Sync task provider dispatch for shopify
22. Integration service reconnect_credentials_shopify
23. Frontend TypeScript sanity check (npx tsc --noEmit)

All tests use MagicMock + unittest.mock.patch — no real database required.
"""

from __future__ import annotations

import inspect
import sys
import uuid
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _change(
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value: Any = None,
    new_value: Any = None,
    record_type: str = "shopify_shop_metadata",
    extra_pm: dict | None = None,
) -> dict:
    pm: dict = {"record_type": record_type}
    if extra_pm:
        pm.update(extra_pm)
    return {
        "change_type": change_type,
        "field_path": field_path,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": pm,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Schema / record type constants
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifySchema:
    def test_record_type_constants(self):
        from app.connectors.shopify_schema import (
            SHOPIFY_SHOP_METADATA,
            SHOPIFY_WEBHOOK_SUBSCRIPTION,
            SHOPIFY_STORE_POLICY,
            SHOPIFY_RECORD_TYPES,
        )
        assert SHOPIFY_SHOP_METADATA == "shopify_shop_metadata"
        assert SHOPIFY_WEBHOOK_SUBSCRIPTION == "shopify_webhook_subscription"
        assert SHOPIFY_STORE_POLICY == "shopify_store_policy"
        assert "shopify_shop_metadata" in SHOPIFY_RECORD_TYPES
        assert "shopify_webhook_subscription" in SHOPIFY_RECORD_TYPES
        assert "shopify_store_policy" in SHOPIFY_RECORD_TYPES

    def test_sensitive_scopes_present(self):
        from app.connectors.shopify_schema import SENSITIVE_SHOPIFY_SCOPES
        assert "read_orders" in SENSITIVE_SHOPIFY_SCOPES
        assert "read_customers" in SENSITIVE_SHOPIFY_SCOPES
        assert "write_customers" in SENSITIVE_SHOPIFY_SCOPES
        assert "read_checkouts" in SENSITIVE_SHOPIFY_SCOPES

    def test_typed_dicts_importable(self):
        from app.connectors.shopify_schema import (
            ShopifyShopMetadataRecord,
            ShopifyWebhookSubscriptionRecord,
            ShopifyStorePolicyRecord,
        )
        # Instantiate with empty dict (total=False) — should not raise
        r: ShopifyShopMetadataRecord = {}  # type: ignore[assignment]
        w: ShopifyWebhookSubscriptionRecord = {}  # type: ignore[assignment]
        p: ShopifyStorePolicyRecord = {}  # type: ignore[assignment]
        assert r is not None and w is not None and p is not None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Shop domain normalization
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizeShopDomain:
    def setup_method(self):
        from app.connectors.shopify import normalize_shop_domain
        self.normalize = normalize_shop_domain

    def test_strips_https(self):
        assert self.normalize("https://mystore.myshopify.com") == "mystore.myshopify.com"

    def test_strips_http(self):
        assert self.normalize("http://mystore.myshopify.com") == "mystore.myshopify.com"

    def test_lowercases(self):
        assert self.normalize("MYSTORE.myshopify.com") == "mystore.myshopify.com"

    def test_strips_trailing_slash(self):
        assert self.normalize("mystore.myshopify.com/") == "mystore.myshopify.com"

    def test_strips_whitespace(self):
        assert self.normalize("  mystore.myshopify.com  ") == "mystore.myshopify.com"

    def test_no_change_clean(self):
        assert self.normalize("mystore.myshopify.com") == "mystore.myshopify.com"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Shop domain validation
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateShopDomain:
    def setup_method(self):
        from app.connectors.shopify import validate_shop_domain
        self.validate = validate_shop_domain

    def test_accepts_myshopify_com(self):
        self.validate("mystore.myshopify.com")  # must not raise

    def test_accepts_custom_domain(self):
        self.validate("shop.example.com")  # must not raise

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            self.validate("")

    def test_rejects_localhost(self):
        with pytest.raises(ValueError):
            self.validate("localhost")

    def test_rejects_127(self):
        with pytest.raises(ValueError):
            self.validate("127.0.0.1")

    def test_rejects_private_10(self):
        with pytest.raises(ValueError):
            self.validate("10.0.0.1")

    def test_rejects_private_192_168(self):
        with pytest.raises(ValueError):
            self.validate("192.168.1.1")

    def test_rejects_local_tld(self):
        with pytest.raises(ValueError):
            self.validate("store.local")

    def test_rejects_internal_tld(self):
        with pytest.raises(ValueError):
            self.validate("store.internal")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Connector _hash helper
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifyConnectorHash:
    def test_hash_returns_hex_string(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        h = c._hash("hello", 16)
        assert isinstance(h, str)
        assert len(h) == 16
        assert all(ch in "0123456789abcdef" for ch in h)

    def test_hash_deterministic(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        assert c._hash("test-value") == c._hash("test-value")

    def test_hash_different_inputs_differ(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        assert c._hash("aaa") != c._hash("bbb")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Webhook URL decomposition — no raw URL stored
# ─────────────────────────────────────────────────────────────────────────────

class TestDecomposeWebhookUrl:
    def setup_method(self):
        from app.connectors.shopify import ShopifyConnector
        self.decompose = ShopifyConnector._decompose_webhook_url

    def test_returns_domain_not_full_url(self):
        result = self.decompose("https://hooks.example.com/shopify/events")
        assert result["endpoint_domain"] == "hooks.example.com"
        # Full URL must NOT appear in returned dict values
        for v in result.values():
            assert "hooks.example.com/shopify/events" not in str(v), (
                f"Full URL path leaked into field: {v!r}"
            )

    def test_scheme_extracted(self):
        r = self.decompose("https://hooks.example.com/path")
        assert r["endpoint_scheme"] == "https"
        assert r["is_https"] is True

    def test_http_detected(self):
        r = self.decompose("http://hooks.example.com/path")
        assert r["endpoint_scheme"] == "http"
        assert r["is_https"] is False

    def test_path_hash_present(self):
        r = self.decompose("https://hooks.example.com/secret/path/123")
        assert "endpoint_path_hash" in r
        assert isinstance(r["endpoint_path_hash"], str)
        assert len(r["endpoint_path_hash"]) >= 16

    def test_path_length_present(self):
        path = "/shopify/webhook/orders"
        r = self.decompose(f"https://example.com{path}")
        assert r["endpoint_path_length"] == len(path)

    def test_raw_path_not_in_result(self):
        """The raw path segment must never be stored — only the hash."""
        raw_path = "/super-secret-token-abc123/shopify"
        r = self.decompose(f"https://example.com{raw_path}")
        for k, v in r.items():
            assert raw_path not in str(v), (
                f"Raw path leaked into field '{k}': {v!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 6. _fetch_shop_metadata — safe fields only, no PII
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchShopMetadata:
    def _make_api_response(self):
        return {
            "shop": {
                "id": 12345678,
                "name": "My Test Store",
                "email": "owner@example.com",          # MUST NOT be stored
                "domain": "mystore.myshopify.com",
                "myshopify_domain": "mystore.myshopify.com",
                "plan_name": "basic",
                "plan_display_name": "Basic",
                "timezone": "America/New_York",
                "iana_timezone": "America/New_York",
                "currency": "USD",
                "primary_locale": "en",
                "country_code": "US",
                "password_enabled": True,
                "checkout_api_supported": True,
                "has_storefront": True,
                "eligible_for_payments": True,
                "requires_extra_payments_agreement": False,
                "taxes_included": False,
                "tax_shipping": False,
                "phone": "+1-555-000-0000",            # MUST NOT be stored
                "address1": "123 Main St",             # MUST NOT be stored
                "owner": "John Smith",                 # MUST NOT be stored
            }
        }

    def test_no_email_in_record(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        api_resp = self._make_api_response()
        with patch.object(c, "_get", return_value=api_resp):
            result = c._fetch_shop_metadata(creds)
        assert result is not None
        result_str = str(result)
        assert "owner@example.com" not in result_str
        assert "email" not in (result or {})

    def test_no_phone_in_record(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_api_response()):
            result = c._fetch_shop_metadata(creds)
        result_str = str(result)
        assert "+1-555-000-0000" not in result_str
        assert "phone" not in (result or {})

    def test_no_address_in_record(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_api_response()):
            result = c._fetch_shop_metadata(creds)
        result_str = str(result)
        assert "123 Main St" not in result_str
        assert "address1" not in (result or {})

    def test_safe_fields_present(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_api_response()):
            result = c._fetch_shop_metadata(creds)
        assert result is not None
        assert result.get("record_type") == "shopify_shop_metadata"
        assert result.get("shop_domain") == "mystore.myshopify.com"
        assert result.get("plan_name") == "basic"
        assert result.get("currency") == "USD"
        assert result.get("timezone") == "America/New_York"
        assert result.get("password_enabled") is True

    def test_returns_none_on_403(self):
        from app.connectors.shopify import ShopifyConnector
        from app.connectors.exceptions import ConnectorError
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        err = ConnectorError("forbidden", status_code=403)
        with patch.object(c, "_get", side_effect=err):
            result = c._fetch_shop_metadata(creds)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 7. _fetch_webhook_subscriptions — URL decomposed, never raw
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchWebhookSubscriptions:
    def _make_webhook_response(self):
        return {
            "webhooks": [
                {
                    "id": 99887766,
                    "address": "https://hooks.example.com/secret-token/shopify",
                    "topic": "orders/create",
                    "format": "json",
                    "api_version": "2024-01",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-02T00:00:00Z",
                },
            ]
        }

    def test_no_raw_url_in_records(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_webhook_response()):
            records = c._fetch_webhook_subscriptions(creds)
        assert records
        for rec in records:
            rec_str = str(rec)
            # Full address must NOT appear in any field
            assert "secret-token" not in rec_str, (
                "Secret path component from webhook URL leaked into record"
            )
            assert "/shopify" not in rec_str or rec.get("record_type") == "shopify_webhook_subscription", (
                "Full URL path leaked into record"
            )
            # 'address' key must not be in the normalized record
            assert "address" not in rec, "Raw webhook 'address' field must not be stored"

    def test_endpoint_domain_stored(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_webhook_response()):
            records = c._fetch_webhook_subscriptions(creds)
        assert records
        rec = records[0]
        assert rec.get("endpoint_domain") == "hooks.example.com"

    def test_is_https_flag(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_webhook_response()):
            records = c._fetch_webhook_subscriptions(creds)
        assert records[0].get("is_https") is True

    def test_topic_stored(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_webhook_response()):
            records = c._fetch_webhook_subscriptions(creds)
        assert records[0].get("topic") == "orders/create"

    def test_returns_empty_on_403(self):
        from app.connectors.shopify import ShopifyConnector
        from app.connectors.exceptions import ConnectorError
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        err = ConnectorError("forbidden", status_code=403)
        with patch.object(c, "_get", side_effect=err):
            records = c._fetch_webhook_subscriptions(creds)
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. _fetch_store_policies — hash+length only, never raw text
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchStorePolicies:
    def _make_policy_response(self):
        return {
            "policies": [
                {
                    "title": "Refund policy",
                    "body": "We offer full refunds within 30 days of purchase. " * 10,
                    "handle": "refund-policy",
                    "url": "/policies/refund-policy",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-15T00:00:00Z",
                },
                {
                    "title": "Privacy policy",
                    "body": "We collect your name and email address. " * 20,
                    "handle": "privacy-policy",
                    "url": "/policies/privacy-policy",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-20T00:00:00Z",
                },
            ]
        }

    def test_no_raw_body_in_records(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_policy_response()):
            records = c._fetch_store_policies(creds)
        assert records
        for rec in records:
            # Raw body text must NOT appear
            assert "We offer full refunds" not in str(rec), "Raw policy body text leaked"
            assert "We collect your name" not in str(rec), "Raw privacy policy text leaked"
            assert "body" not in rec, "'body' field must not be stored in policy record"

    def test_body_hash_present(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_policy_response()):
            records = c._fetch_store_policies(creds)
        # M74A: _fetch_store_policies also emits ``present=False`` baseline
        # records for canonical policy types the API did not return; those
        # carry body_hash=None. Assert on the populated (present) policies.
        populated = [r for r in records if r.get("present") is True]
        assert populated
        for rec in populated:
            assert "body_hash" in rec, "body_hash must be present for change detection"
            assert isinstance(rec["body_hash"], str)

    def test_body_length_present(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_policy_response()):
            records = c._fetch_store_policies(creds)
        # M74A baseline (present=False) records have body_length=0; assert on
        # the populated policies returned by the API.
        populated = [r for r in records if r.get("present") is True]
        assert populated
        for rec in populated:
            assert "body_length" in rec
            assert isinstance(rec["body_length"], int)
            assert rec["body_length"] > 0

    def test_present_flag_set(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with patch.object(c, "_get", return_value=self._make_policy_response()):
            records = c._fetch_store_policies(creds)
        # M74A also emits ``present=False`` baseline records for canonical
        # policy types the API omitted. The two policies returned by the API
        # (refund + privacy) must be marked present=True.
        present_types = {r["policy_type"] for r in records if r.get("present") is True}
        assert "refund_policy" in present_types
        assert "privacy_policy" in present_types

    def test_returns_empty_on_403(self):
        from app.connectors.shopify import ShopifyConnector
        from app.connectors.exceptions import ConnectorError
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        err = ConnectorError("forbidden", status_code=403)
        with patch.object(c, "_get", side_effect=err):
            records = c._fetch_store_policies(creds)
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 9. Connector fetch() aggregates all surfaces
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifyConnectorFetch:
    def test_fetch_returns_list(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        shop_rec = {"record_type": "shopify_shop_metadata", "record_id": "mystore.myshopify.com"}
        webhook_rec = {"record_type": "shopify_webhook_subscription", "record_id": "wh_abc"}
        policy_rec = {"record_type": "shopify_store_policy", "record_id": "mystore.myshopify.com:refund_policy"}
        scope_rec = {"record_type": "shopify_app_scope_summary", "record_id": "mystore.myshopify.com:app_scopes"}
        domain_rec = {"record_type": "shopify_domain", "record_id": "mystore.myshopify.com:host"}
        with (
            patch.object(c, "_fetch_shop_metadata", return_value=shop_rec),
            patch.object(c, "_fetch_webhook_subscriptions", return_value=[webhook_rec]),
            patch.object(c, "_fetch_store_policies", return_value=[policy_rec]),
            # _fetch_access_scopes (M57.9) and _fetch_domains (M74A) were added
            # after M57.5 — patch them so fetch() makes no real network calls.
            patch.object(c, "_fetch_access_scopes", return_value=scope_rec),
            patch.object(c, "_fetch_domains", return_value=[domain_rec]),
        ):
            records = c.fetch(creds)
        assert isinstance(records, list)
        # 5 record types now: shop_metadata, webhook_subscription, store_policy,
        # app_scope_summary (M57.9), domain (M74A).
        assert len(records) == 5
        types = {r["record_type"] for r in records}
        assert "shopify_shop_metadata" in types
        assert "shopify_webhook_subscription" in types
        assert "shopify_store_policy" in types
        assert "shopify_app_scope_summary" in types
        assert "shopify_domain" in types

    def test_fetch_skips_none_shop_metadata(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        with (
            patch.object(c, "_fetch_shop_metadata", return_value=None),
            patch.object(c, "_fetch_webhook_subscriptions", return_value=[]),
            patch.object(c, "_fetch_store_policies", return_value=[]),
            # _fetch_access_scopes (M57.9) and _fetch_domains (M74A) added later.
            patch.object(c, "_fetch_access_scopes", return_value=None),
            patch.object(c, "_fetch_domains", return_value=[]),
        ):
            records = c.fetch(creds)
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 10. Connector validate_credentials()
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifyValidateCredentials:
    def test_valid_credentials_pass(self):
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        shop_data = {"shop": {"id": 1, "domain": "mystore.myshopify.com"}}
        with patch.object(c, "_get", return_value=shop_data):
            c.validate_credentials(creds)  # must not raise

    def test_invalid_domain_raises(self):
        from app.connectors.shopify import ShopifyConnector
        from app.connectors.exceptions import AuthenticationError
        c = ShopifyConnector()
        creds = {"shop_domain": "localhost", "shopify_access_token": "shpat_test"}
        with pytest.raises((ValueError, AuthenticationError)):
            c.validate_credentials(creds)

    def test_missing_token_raises(self):
        from app.connectors.shopify import ShopifyConnector
        from app.connectors.exceptions import AuthenticationError
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": ""}
        with pytest.raises((ValueError, AuthenticationError)):
            c.validate_credentials(creds)

    def test_auth_error_on_401(self):
        from app.connectors.shopify import ShopifyConnector
        from app.connectors.exceptions import AuthenticationError
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_bad"}
        with patch.object(c, "_get", side_effect=AuthenticationError("invalid token")):
            with pytest.raises(AuthenticationError):
                c.validate_credentials(creds)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Forbidden endpoint strings absent from connector source
# ─────────────────────────────────────────────────────────────────────────────

class TestForbiddenEndpoints:
    """Verify the connector source does not contain calls to forbidden endpoints.

    We inspect the source file directly, excluding docstring/comment lines
    that explicitly say "NEVER call" or similar.
    """

    @pytest.fixture(autouse=True)
    def load_source(self):
        import app.connectors.shopify as shopify_mod
        src_path = inspect.getfile(shopify_mod)
        with open(src_path) as f:
            lines = f.readlines()
        # Filter out comment lines and docstring lines (lines starting with #, """, ''')
        self.code_lines = [
            (i + 1, line) for i, line in enumerate(lines)
            if not line.lstrip().startswith(("#", '"""', "'''"))
        ]

    def _assert_not_in_code(self, pattern: str):
        violations = [
            (lineno, line.rstrip())
            for lineno, line in self.code_lines
            if pattern in line
        ]
        assert not violations, (
            f"Forbidden pattern {pattern!r} found in shopify.py code lines:\n"
            + "\n".join(f"  L{ln}: {l}" for ln, l in violations)
        )

    def test_no_orders_endpoint(self):
        self._assert_not_in_code("/orders")

    def test_no_customers_endpoint(self):
        self._assert_not_in_code("/customers")

    def test_no_transactions_endpoint(self):
        self._assert_not_in_code("/transactions")

    def test_no_checkouts_endpoint(self):
        self._assert_not_in_code("/checkouts")

    def test_no_draft_orders_endpoint(self):
        self._assert_not_in_code("/draft_orders")

    def test_no_gift_cards_endpoint(self):
        self._assert_not_in_code("/gift_cards")

    def test_no_payouts_endpoint(self):
        self._assert_not_in_code("/payouts")

    def test_no_themes_assets_endpoint(self):
        self._assert_not_in_code("/themes")


# ─────────────────────────────────────────────────────────────────────────────
# 12. Diff tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffTrackedFields:
    def _tracked(self, record_type: str) -> tuple:
        from app.services.diff_service import _tracked_fields_for
        return _tracked_fields_for({"record_type": record_type})

    def test_shopify_shop_metadata_fields(self):
        fields = self._tracked("shopify_shop_metadata")
        assert "plan_name" in fields
        assert "currency" in fields
        assert "timezone" in fields
        assert "password_enabled" in fields
        assert "has_storefront" in fields
        assert "eligible_for_payments" in fields

    def test_shopify_webhook_subscription_fields(self):
        fields = self._tracked("shopify_webhook_subscription")
        assert "topic" in fields
        assert "endpoint_domain" in fields
        assert "is_https" in fields
        assert "endpoint_path_hash" in fields
        assert "format" in fields
        assert "api_version" in fields

    def test_shopify_store_policy_fields(self):
        fields = self._tracked("shopify_store_policy")
        assert "present" in fields
        assert "body_hash" in fields
        assert "body_length" in fields
        assert "policy_type" in fields

    def test_unknown_shopify_subtype_returns_empty(self):
        fields = self._tracked("shopify_future_unknown_type")
        assert fields == ()

    def test_non_shopify_unaffected(self):
        """Existing cloudflare/stripe dispatch is not broken."""
        from app.services.diff_service import _tracked_fields_for
        fields = _tracked_fields_for({"record_type": "stripe_account_settings"})
        assert "charges_enabled" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 13. Risk rules — shop metadata
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifyRiskRulesShopMetadata:
    def _classify(self, **kw):
        from app.services.risk_rules.shopify import classify_shopify_change
        return classify_shopify_change(_change(**kw))

    def test_password_disabled_is_high(self):
        # Policy: disabling storefront password is a material public-exposure
        # change (private/pre-launch store becomes reachable) → high.
        level, reason = self._classify(
            field_path="password_enabled", new_value=False,
            record_type="shopify_shop_metadata",
        )
        assert level == "high"
        assert "password" in reason.lower() or "storefront" in reason.lower()

    def test_password_enabled_is_low(self):
        level, reason = self._classify(
            field_path="password_enabled", new_value=True,
            record_type="shopify_shop_metadata",
        )
        assert level == "low"

    def test_eligible_for_payments_false_is_high(self):
        level, reason = self._classify(
            field_path="eligible_for_payments", new_value=False,
            record_type="shopify_shop_metadata",
        )
        assert level == "high"

    def test_eligible_for_payments_restored_is_medium(self):
        level, reason = self._classify(
            field_path="eligible_for_payments", new_value=True,
            record_type="shopify_shop_metadata",
        )
        assert level == "medium"

    def test_has_storefront_false_is_high(self):
        level, _ = self._classify(
            field_path="has_storefront", new_value=False,
            record_type="shopify_shop_metadata",
        )
        assert level == "high"

    def test_plan_name_changed_is_medium(self):
        level, _ = self._classify(
            field_path="plan_name", new_value="shopify",
            record_type="shopify_shop_metadata",
        )
        assert level == "medium"

    def test_currency_changed_is_medium(self):
        level, _ = self._classify(
            field_path="currency", new_value="EUR",
            record_type="shopify_shop_metadata",
        )
        assert level == "medium"

    def test_timezone_changed_is_low(self):
        level, _ = self._classify(
            field_path="timezone", new_value="Europe/London",
            record_type="shopify_shop_metadata",
        )
        assert level == "low"

    def test_shop_name_changed_is_low(self):
        level, _ = self._classify(
            field_path="shop_name", new_value="My Renamed Store",
            record_type="shopify_shop_metadata",
        )
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 14. Risk rules — webhook subscription
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifyRiskRulesWebhook:
    def _classify(self, **kw):
        from app.services.risk_rules.shopify import classify_shopify_change
        return classify_shopify_change(_change(**kw))

    def test_webhook_added_for_critical_topic_is_high(self):
        # Policy: a webhook added for a critical commerce topic
        # (orders/payments/customers) is high even when HTTPS. Non-critical
        # HTTPS adds are medium — covered separately in the audit suite.
        level, reason = self._classify(
            change_type="added",
            record_type="shopify_webhook_subscription",
            extra_pm={"topic": "orders/create", "is_https": True},
        )
        assert level == "high"

    def test_webhook_removed_is_medium_or_high(self):
        level, _ = self._classify(
            change_type="removed",
            record_type="shopify_webhook_subscription",
        )
        assert level in ("medium", "high")

    def test_critical_topic_webhook_removed_is_high(self):
        level, reason = self._classify(
            change_type="removed",
            record_type="shopify_webhook_subscription",
            extra_pm={"topic": "app/uninstalled"},
        )
        assert level == "high"

    def test_non_https_is_high(self):
        level, reason = self._classify(
            field_path="is_https", new_value=False,
            record_type="shopify_webhook_subscription",
        )
        assert level == "high"
        assert "https" in reason.lower() or "http" in reason.lower()

    def test_https_restored_is_low(self):
        level, _ = self._classify(
            field_path="is_https", new_value=True,
            record_type="shopify_webhook_subscription",
        )
        assert level == "low"

    def test_endpoint_domain_changed_for_critical_topic_is_high(self):
        # Policy: domain change tracks topic sensitivity — critical topic
        # redirect → high; non-critical → medium (covered in audit suite).
        level, reason = self._classify(
            field_path="endpoint_domain", new_value="other.example.com",
            record_type="shopify_webhook_subscription",
            extra_pm={"topic": "orders/create"},
        )
        assert level == "high"

    def test_endpoint_path_hash_changed_is_medium(self):
        level, _ = self._classify(
            field_path="endpoint_path_hash", new_value="abc123",
            record_type="shopify_webhook_subscription",
        )
        assert level == "medium"

    def test_topic_changed_is_medium(self):
        level, _ = self._classify(
            field_path="topic", new_value="customers/update",
            record_type="shopify_webhook_subscription",
        )
        assert level == "medium"

    def test_api_version_changed_is_low(self):
        level, _ = self._classify(
            field_path="api_version", new_value="2024-04",
            record_type="shopify_webhook_subscription",
        )
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 15. Risk rules — store policy
# ─────────────────────────────────────────────────────────────────────────────

class TestShopifyRiskRulesStorePolicy:
    def _classify(self, **kw):
        from app.services.risk_rules.shopify import classify_shopify_change
        return classify_shopify_change(_change(**kw))

    def test_policy_added_is_low(self):
        level, _ = self._classify(
            change_type="added",
            record_type="shopify_store_policy",
        )
        assert level == "low"

    def test_policy_removed_is_medium(self):
        level, _ = self._classify(
            change_type="removed",
            record_type="shopify_store_policy",
        )
        assert level == "medium"

    def test_present_false_is_medium(self):
        level, _ = self._classify(
            field_path="present", new_value=False,
            record_type="shopify_store_policy",
        )
        assert level == "medium"

    def test_present_true_is_low(self):
        level, _ = self._classify(
            field_path="present", new_value=True,
            record_type="shopify_store_policy",
        )
        assert level == "low"

    def test_body_hash_changed_is_medium(self):
        level, _ = self._classify(
            field_path="body_hash", new_value="newhash",
            record_type="shopify_store_policy",
            extra_pm={"policy_type": "refund_policy"},
        )
        assert level == "medium"

    def test_body_length_changed_is_low(self):
        level, _ = self._classify(
            field_path="body_length", new_value=500,
            record_type="shopify_store_policy",
        )
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 16. Risk service dispatches to Shopify rules
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskServiceDispatch:
    def test_shopify_record_type_dispatched(self):
        from app.services.risk_service import classify_change
        ch = _change(
            field_path="password_enabled", new_value=False,
            record_type="shopify_shop_metadata",
        )
        level, reason = classify_change(ch)
        assert level in ("low", "medium", "high", "critical")
        assert isinstance(reason, str)

    def test_shopify_webhook_dispatched(self):
        # Same shape as the audit suite — confirms dispatch + a concrete
        # severity floor. Uses a critical topic so the assertion stays
        # meaningful under the new topic-aware policy.
        from app.services.risk_service import classify_change
        ch = _change(
            change_type="added",
            record_type="shopify_webhook_subscription",
            extra_pm={"topic": "orders/create", "is_https": True},
        )
        level, reason = classify_change(ch)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 17. Failure classifier — Shopify codes
# ─────────────────────────────────────────────────────────────────────────────

class TestFailureClassifier:
    def _auth_class(self, provider: str):
        from app.core.failure_classifier import _classify_auth
        return _classify_auth(provider, None)

    def test_shopify_auth_failure(self):
        result = self._auth_class("shopify")
        assert result.error_code == "shopify_credentials_invalid"
        assert result.category == "authentication"

    def test_shopify_403_permission_denied(self):
        from app.core.failure_classifier import _classify_connector
        from app.connectors.exceptions import ConnectorError
        exc = ConnectorError("forbidden", status_code=403)
        result = _classify_connector(exc, "shopify")
        assert result.error_code == "shopify_permission_denied"
        assert result.category == "authentication"

    def test_shopify_404_shop_unavailable(self):
        from app.core.failure_classifier import _classify_connector
        from app.connectors.exceptions import ConnectorError
        exc = ConnectorError("not found", status_code=404)
        result = _classify_connector(exc, "shopify")
        assert result.error_code == "shopify_shop_unavailable"
        assert result.category == "resource_missing"

    def test_shopify_5xx_api_unavailable(self):
        from app.core.failure_classifier import _classify_connector
        from app.connectors.exceptions import ConnectorError
        exc = ConnectorError("server error", status_code=503)
        result = _classify_connector(exc, "shopify")
        assert result.error_code == "shopify_api_unavailable"
        assert result.category == "provider_unavailable"

    def test_shopify_rate_limit(self):
        from app.core.failure_classifier import classify_failure
        from app.connectors.exceptions import RateLimitError
        result = classify_failure(RateLimitError("rate limited"), "shopify")
        assert result.category == "rate_limited"


# ─────────────────────────────────────────────────────────────────────────────
# 18. Integration schema — "shopify" in Literal, field validation
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationSchema:
    def test_shopify_in_provider_literal(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="shopify",
            display_name="Test Shopify",
            shopify_shop_domain="mystore.myshopify.com",
            shopify_access_token="shpat_test123",
        )
        assert req.provider == "shopify"
        assert req.shopify_shop_domain == "mystore.myshopify.com"

    def test_shopify_missing_domain_raises(self):
        from app.schemas.integration import IntegrationCreateRequest
        import pydantic
        with pytest.raises((pydantic.ValidationError, ValueError)):
            IntegrationCreateRequest(
                provider="shopify",
                display_name="Test",
                shopify_access_token="shpat_test",
                # no shopify_shop_domain
            )

    def test_shopify_missing_token_raises(self):
        from app.schemas.integration import IntegrationCreateRequest
        import pydantic
        with pytest.raises((pydantic.ValidationError, ValueError)):
            IntegrationCreateRequest(
                provider="shopify",
                display_name="Test",
                shopify_shop_domain="mystore.myshopify.com",
                # no shopify_access_token
            )

    def test_shopify_not_in_invalid_provider(self):
        from app.schemas.integration import IntegrationCreateRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            IntegrationCreateRequest(
                provider="not_a_real_provider",  # type: ignore[arg-type]
                display_name="Test",
            )


# ─────────────────────────────────────────────────────────────────────────────
# 19. Integration schema — reconnect request shopify field
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationReconnectSchema:
    def test_shopify_access_token_field_present(self):
        from app.schemas.integration import IntegrationReconnectRequest
        req = IntegrationReconnectRequest(shopify_access_token="shpat_new_token")
        assert req.shopify_access_token == "shpat_new_token"

    def test_reconnect_allows_empty_shopify(self):
        from app.schemas.integration import IntegrationReconnectRequest
        req = IntegrationReconnectRequest()
        assert req.shopify_access_token is None


# ─────────────────────────────────────────────────────────────────────────────
# 20. Router _build_credentials for shopify
# ─────────────────────────────────────────────────────────────────────────────

class TestRouterBuildCredentials:
    def test_shopify_credentials_built(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="shopify",
            display_name="Shopify Test",
            shopify_shop_domain="mystore.myshopify.com",
            shopify_access_token="shpat_xyz",
        )
        creds = _build_credentials(req)
        assert creds["shop_domain"] == "mystore.myshopify.com"
        assert creds["shopify_access_token"] == "shpat_xyz"

    def test_shopify_creds_no_extra_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="shopify",
            display_name="Shopify Test",
            shopify_shop_domain="mystore.myshopify.com",
            shopify_access_token="shpat_xyz",
        )
        creds = _build_credentials(req)
        # Should only contain the two Shopify keys
        assert set(creds.keys()) == {"shop_domain", "shopify_access_token"}


# ─────────────────────────────────────────────────────────────────────────────
# 21. Sync task provider dispatch for shopify
# ─────────────────────────────────────────────────────────────────────────────

class TestSyncTaskShopifyDispatch:
    def test_shopify_connector_called(self):
        """Verify sync_integration calls ShopifyConnector.fetch for shopify provider."""
        import app.workers.sync_task as sync_mod

        _run_uuid = _uuid()
        _integ_uuid = _uuid()
        _user_uuid = _uuid()

        mock_run = MagicMock()
        mock_run.triggered_by = "manual"

        mock_integration = MagicMock()
        mock_integration.id = _integ_uuid
        mock_integration.user_id = _user_uuid
        mock_integration.provider = "shopify"
        mock_integration.encrypted_credentials = b"enc"
        mock_integration.credential_iv = b"iv"
        mock_integration.consecutive_failure_count = 0
        mock_integration.display_name = "Test Shop"

        mock_resource = MagicMock()
        mock_resource.id = _uuid()
        mock_resource.integration_id = _integ_uuid
        mock_resource.is_active = True
        mock_resource.last_snapshot_at = None
        mock_resource.user_id = _user_uuid

        db = MagicMock()
        db.get.side_effect = lambda model, pk: {
            _run_uuid: mock_run,
            _integ_uuid: mock_integration,
        }.get(pk)
        db.query.return_value.filter.return_value.all.return_value = [mock_resource]

        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}

        with (
            patch("app.database.SessionLocal", return_value=db),
            patch("app.workers.sync_task.decrypt_credentials", return_value=creds),
            patch("app.connectors.shopify.ShopifyConnector.fetch", return_value=[]) as mock_fetch,
            patch("app.services.sync_service.mark_sync_running"),
            patch("app.services.sync_service.mark_sync_completed"),
            patch("app.services.snapshot_service.get_latest_snapshot", return_value=None),
            patch("app.services.snapshot_service.store_snapshot", return_value=(None, False)),
            patch("app.services.alert_service.dispatch_alerts_for_sync"),
        ):
            result = sync_mod.sync_integration(
                str(_run_uuid), str(_integ_uuid), str(_user_uuid)
            )

        mock_fetch.assert_called_once_with(creds)
        assert result["status"] == "completed"


# ─────────────────────────────────────────────────────────────────────────────
# 22. Integration service reconnect_credentials_shopify
# ─────────────────────────────────────────────────────────────────────────────

class TestReconnectCredentialsShopify:
    def test_reconnect_calls_validate_and_encrypts(self):
        from app.services.integration_service import reconnect_credentials_shopify

        integ_id = _uuid()
        user_id = _uuid()
        new_token = "shpat_new_valid_token"

        existing_creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_old"}
        mock_integration = MagicMock()
        mock_integration.id = integ_id
        mock_integration.status = "active"

        db = MagicMock()

        with (
            patch("app.services.integration_service.get_integration_by_id", return_value=mock_integration),
            patch("app.services.integration_service.decrypt_credentials", return_value=existing_creds),
            patch("app.connectors.shopify.ShopifyConnector.validate_credentials") as mock_validate,
            patch("app.services.integration_service.encrypt_credentials", return_value=(b"enc", b"iv")) as mock_enc,
        ):
            result = reconnect_credentials_shopify(
                integration_id=integ_id,
                user_id=user_id,
                new_access_token=new_token,
                db=db,
            )

        # validate_credentials called with new token + preserved domain
        mock_validate.assert_called_once()
        call_creds = mock_validate.call_args[0][0]
        assert call_creds["shopify_access_token"] == new_token
        assert call_creds["shop_domain"] == "mystore.myshopify.com"

        # encrypt_credentials called
        mock_enc.assert_called_once()

        # integration updated
        assert mock_integration.encrypted_credentials == b"enc"
        assert mock_integration.credential_iv == b"iv"
        db.commit.assert_called()

    def test_reconnect_raises_lookup_error_when_not_found(self):
        from app.services.integration_service import reconnect_credentials_shopify
        with patch("app.services.integration_service.get_integration_by_id", return_value=None):
            with pytest.raises(LookupError):
                reconnect_credentials_shopify(
                    integration_id=_uuid(),
                    user_id=_uuid(),
                    new_access_token="shpat_token",
                    db=MagicMock(),
                )


# ─────────────────────────────────────────────────────────────────────────────
# 23. Security invariants — token never in plain text in credentials dict key
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityInvariants:
    def test_validate_credentials_does_not_return_token(self):
        """validate_credentials must return None (not a token or response dict)."""
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_test"}
        shop_data = {"shop": {"id": 1, "domain": "mystore.myshopify.com"}}
        with patch.object(c, "_get", return_value=shop_data):
            result = c.validate_credentials(creds)
        assert result is None, "validate_credentials must return None, not credentials"

    def test_fetch_does_not_include_token_in_records(self):
        """Fetched records must never contain the access token value."""
        from app.connectors.shopify import ShopifyConnector
        c = ShopifyConnector()
        creds = {"shop_domain": "mystore.myshopify.com", "shopify_access_token": "shpat_supersecret"}
        shop_rec = {
            "record_type": "shopify_shop_metadata",
            "record_id": "mystore.myshopify.com",
            "shop_domain": "mystore.myshopify.com",
        }
        with (
            patch.object(c, "_fetch_shop_metadata", return_value=shop_rec),
            patch.object(c, "_fetch_webhook_subscriptions", return_value=[]),
            patch.object(c, "_fetch_store_policies", return_value=[]),
            # M57.9 / M74A helpers — patch so fetch() makes no real network call.
            patch.object(c, "_fetch_access_scopes", return_value=None),
            patch.object(c, "_fetch_domains", return_value=[]),
        ):
            records = c.fetch(creds)
        for rec in records:
            assert "shpat_supersecret" not in str(rec), "Access token leaked into fetch records"
