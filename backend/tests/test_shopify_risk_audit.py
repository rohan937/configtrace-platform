"""Shopify risk accuracy audit — local-only regression tests.

Builds the scenario matrix from the verification brief and asserts the
expected severity for each scenario. Designed so the file documents
ConfigTrace's Shopify risk policy: any future regression that mis-rates
one of these scenarios will fail loudly here.

Pure-mock; no DB, no network, no Shopify API.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _change(
    *,
    record_type: str,
    field_path: str | None = None,
    change_type: str = "modified",
    new_value: Any = None,
    prev_value: Any = None,
    topic: str | None = None,
    policy_type: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {"record_type": record_type}
    if topic       is not None: pm["topic"]       = topic
    if policy_type is not None: pm["policy_type"] = policy_type
    if extra_metadata:          pm.update(extra_metadata)

    c = MagicMock(name="Change")
    c.field_path        = field_path
    c.change_type       = change_type
    c.new_value         = new_value
    c.prev_value        = prev_value
    c.provider_metadata = pm
    return c


def _classify(change):
    from app.services.risk_rules.shopify import classify_shopify_change
    return classify_shopify_change(change)


# ─────────────────────────────────────────────────────────────────────────────
# A. shopify_webhook_subscription
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookSubscription:
    def test_A1_add_https_for_critical_topic_is_high(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            change_type="added",
            topic="orders/create",
            extra_metadata={"is_https": True, "endpoint_scheme": "https"},
        )
        level, _ = _classify(c)
        assert level == "high", f"orders/create HTTPS add must be high; got {level}"

    def test_A2_add_https_for_non_critical_topic_is_medium(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            change_type="added",
            topic="products/update",
            extra_metadata={"is_https": True, "endpoint_scheme": "https"},
        )
        level, _ = _classify(c)
        assert level == "medium", (
            f"non-critical HTTPS webhook add must be medium per brief; got {level}"
        )

    def test_A3_add_http_for_critical_topic_is_critical(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            change_type="added",
            topic="orders/create",
            extra_metadata={"is_https": False, "endpoint_scheme": "http"},
        )
        level, reason = _classify(c)
        assert level == "critical", (
            f"HTTP webhook for order/payment topic must be critical; got {level} ({reason})"
        )

    def test_A4_add_http_for_non_critical_topic_is_high(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            change_type="added",
            topic="products/update",
            extra_metadata={"is_https": False, "endpoint_scheme": "http"},
        )
        level, _ = _classify(c)
        assert level == "high", (
            f"HTTP webhook for any topic must be at least high; got {level}"
        )

    def test_A5_remove_critical_topic_is_high(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            change_type="removed",
            topic="orders/create",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A6_remove_non_critical_topic_is_medium(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            change_type="removed",
            topic="products/update",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A7_endpoint_domain_changed_for_critical_topic_is_high(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="endpoint_domain",
            new_value="evil.example.com",
            topic="orders/create",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A8_endpoint_domain_changed_for_non_critical_topic_is_medium(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="endpoint_domain",
            new_value="api2.example.com",
            topic="products/update",
        )
        level, _ = _classify(c)
        assert level == "medium", (
            f"domain change on non-critical topic should be medium, not high; got {level}"
        )

    def test_A9_is_https_downgrade_for_critical_topic_is_critical(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="is_https",
            new_value=False,
            topic="orders/create",
        )
        level, _ = _classify(c)
        assert level == "critical", (
            f"HTTP downgrade on order/payment webhook must be critical; got {level}"
        )

    def test_A10_is_https_downgrade_for_non_critical_topic_is_high(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="is_https",
            new_value=False,
            topic="products/update",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A11_topic_changed_is_medium(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="topic",
            new_value="orders/cancelled",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A12_api_version_changed_is_low(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="api_version",
            new_value="2024-10",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A13_format_changed_is_low(self):
        c = _change(
            record_type="shopify_webhook_subscription",
            field_path="format",
            new_value="xml",
        )
        level, _ = _classify(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# B. shopify_app_scope_summary
# ─────────────────────────────────────────────────────────────────────────────

class TestAppScopeSummary:
    def test_B1_payment_scope_newly_present_is_critical(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="payment_scope_present",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical", (
            f"newly granted payment scope must be critical per brief; got {level}"
        )

    def test_B2_customer_scope_newly_present_is_high(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="customer_scope_present",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B3_order_scope_newly_present_is_high(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="order_scope_present",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B4_sensitive_scope_count_increase_is_high(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="sensitive_scope_count",
            new_value=3,
            prev_value=1,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B5_write_scope_count_increase_is_high(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="write_scope_count",
            new_value=5,
            prev_value=2,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B6_general_scope_count_increase_is_medium(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="scope_count",
            new_value=10,
            prev_value=7,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B7_scope_count_decrease_is_medium(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            field_path="scope_count",
            new_value=5,
            prev_value=10,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B8_scope_record_removed_is_high(self):
        c = _change(
            record_type="shopify_app_scope_summary",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# C. shopify_store_policy
# ─────────────────────────────────────────────────────────────────────────────

class TestStorePolicy:
    @pytest.mark.parametrize("policy_type", [
        "privacy_policy", "refund_policy", "terms_of_service",
    ])
    def test_C1_critical_policy_removed_is_high(self, policy_type):
        c = _change(
            record_type="shopify_store_policy",
            change_type="removed",
            policy_type=policy_type,
        )
        level, _ = _classify(c)
        assert level == "high", (
            f"{policy_type} removal must be high per brief; got {level}"
        )

    @pytest.mark.parametrize("policy_type", [
        "privacy_policy", "refund_policy", "terms_of_service",
    ])
    def test_C2_critical_policy_present_false_is_high(self, policy_type):
        c = _change(
            record_type="shopify_store_policy",
            field_path="present",
            new_value=False,
            policy_type=policy_type,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C3_shipping_policy_removed_is_medium(self):
        c = _change(
            record_type="shopify_store_policy",
            change_type="removed",
            policy_type="shipping_policy",
        )
        level, _ = _classify(c)
        assert level == "medium", (
            f"shipping policy removal is operational, not legally critical; got {level}"
        )

    def test_C4_privacy_policy_body_hash_changed_is_medium(self):
        c = _change(
            record_type="shopify_store_policy",
            field_path="body_hash",
            new_value="abc123",
            policy_type="privacy_policy",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C5_policy_added_is_low(self):
        c = _change(
            record_type="shopify_store_policy",
            change_type="added",
            policy_type="refund_policy",
        )
        level, _ = _classify(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# D. shopify_shop_metadata
# ─────────────────────────────────────────────────────────────────────────────

class TestShopMetadata:
    def test_D1_password_disabled_is_high(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="password_enabled",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "high", (
            f"disabling storefront password is a material public-exposure change; "
            f"got {level}"
        )

    def test_D2_password_enabled_is_low(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="password_enabled",
            new_value=True,
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_D3_eligible_for_payments_lost_is_high(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="eligible_for_payments",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D4_requires_extra_payments_agreement_true_is_high(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="requires_extra_payments_agreement",
            new_value=True,
        )
        level, _ = _classify(c)
        assert level == "high", (
            f"new extra-payments-agreement requirement may suspend payments; got {level}"
        )

    def test_D5_storefront_disabled_is_high(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="has_storefront",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D6_checkout_api_disabled_is_medium(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="checkout_api_supported",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D7_currency_changed_is_medium(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="currency",
            new_value="EUR",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D8_plan_changed_is_medium(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="plan_name",
            new_value="basic",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D9_shop_name_changed_is_low(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="shop_name",
            new_value="New Store Name",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_D10_timezone_changed_is_low(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="iana_timezone",
            new_value="America/Los_Angeles",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_D11_taxes_included_changed_is_medium(self):
        c = _change(
            record_type="shopify_shop_metadata",
            field_path="taxes_included",
            new_value=True,
        )
        level, _ = _classify(c)
        assert level == "medium", (
            f"tax-inclusive pricing change affects checkout totals; got {level}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# E. Unknown subtype safety
# ─────────────────────────────────────────────────────────────────────────────

class TestUnknownSubtype:
    def test_E1_unknown_record_type_falls_back_safely(self):
        c = _change(record_type="shopify_some_future_thing")
        level, reason = _classify(c)
        assert level in ("low", "medium")
        assert "shopify" in reason.lower()


# ─────────────────────────────────────────────────────────────────────────────
# F. Frontend remediation copy — spot the Stripe/Shopify mix-up bug
# ─────────────────────────────────────────────────────────────────────────────

class TestFrontendCopyHygiene:
    def test_F1_shopify_webhook_playbook_does_not_say_stripe_hmac(self):
        """Catches a known copy-paste bug: the Shopify webhook-removed
        playbook referenced 'Stripe HMAC' instead of 'Shopify HMAC'."""
        import os

        here = os.path.dirname(os.path.abspath(__file__))
        front = os.path.abspath(
            os.path.join(here, "..", "..", "frontend", "src", "lib", "remediation.ts")
        )
        if not os.path.isfile(front):
            pytest.skip(f"remediation.ts not found at {front}")
        with open(front, "r", encoding="utf-8") as f:
            src = f.read()

        # Slice just the Shopify playbook section so we don't false-positive
        # on the (correct) Stripe playbook elsewhere.
        start = src.find("Playbook 8 — Shopify")
        end   = src.find("Playbook 9", start) if start != -1 else len(src)
        shopify_block = src[start:end] if start != -1 else src

        assert "Stripe HMAC" not in shopify_block, (
            "Shopify webhook playbook references 'Stripe HMAC' — copy/paste bug"
        )


# ─────────────────────────────────────────────────────────────────────────────
# G. Safety — no token logging, no auto-fix language, no provider mutations
# ─────────────────────────────────────────────────────────────────────────────

class TestSafetyInvariants:
    @pytest.mark.parametrize("change_args", [
        # critical, high, medium across all four record types
        dict(record_type="shopify_webhook_subscription", change_type="added",
             topic="orders/create",
             extra_metadata={"is_https": False, "endpoint_scheme": "http"}),
        dict(record_type="shopify_webhook_subscription", change_type="removed",
             topic="orders/create"),
        dict(record_type="shopify_app_scope_summary",
             field_path="payment_scope_present", new_value=True, prev_value=False),
        dict(record_type="shopify_store_policy", change_type="removed",
             policy_type="privacy_policy"),
        dict(record_type="shopify_shop_metadata",
             field_path="eligible_for_payments", new_value=False),
    ])
    def test_G1_risk_reasons_do_not_leak_tokens_or_full_webhook_urls(self, change_args):
        """Reasons must never contain a literal URL, secret, or token."""
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # No protocol-prefixed URL embedded in the reason
        assert "https://" not in lower and "http://" not in lower, (
            f"risk reason should not contain full URLs: {reason!r}"
        )
        # No "shpat_" / "shpca_" / "shpss_" Shopify token prefixes
        for prefix in ("shpat_", "shpca_", "shpss_"):
            assert prefix not in lower

    def test_G2_no_auto_fix_language(self):
        """Risk reasons must never claim automatic fix; everything is advisory."""
        cases = [
            dict(record_type="shopify_webhook_subscription", change_type="removed",
                 topic="orders/create"),
            dict(record_type="shopify_app_scope_summary",
                 field_path="payment_scope_present", new_value=True, prev_value=False),
            dict(record_type="shopify_store_policy", change_type="removed",
                 policy_type="privacy_policy"),
            dict(record_type="shopify_shop_metadata",
                 field_path="password_enabled", new_value=False),
        ]
        bad_phrases = ("auto-fix", "automatically fix", "guaranteed", "auto fix")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for bad in bad_phrases:
                assert bad not in lower, (
                    f"reason contains forbidden phrase {bad!r}: {reason!r}"
                )
