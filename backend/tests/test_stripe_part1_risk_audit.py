"""Stripe Part 1 — catalog (Products + Prices) + Payment Links + Checkout
configuration + Tax settings.

Coverage strategy
-----------------
* **NEW record types** (5): full scenario coverage via the new
  sub-classifiers added in M59.10.
* **Existing record types** (account / webhook / PM config / PM domain /
  billing portal): unchanged; re-verified at the dispatcher level by
  smoke calls.
* **Dispatcher / safety**: unknown subtype + malformed `provider_metadata`.
* **Secret-safety tripwires**: realistic credential-shaped fixtures must
  never appear in any risk reason.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.stripe import (
    classify_stripe_change,
    _classify_product_change,
    _classify_price_change,
    _classify_payment_link_change,
    _classify_checkout_configuration_change,
    _classify_tax_settings_change,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ch(
    *,
    record_type: str,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    pm_extra: dict | None = None,
):
    c = MagicMock(name="Change")
    c.change_type = change_type
    c.field_path = field_path
    c.prev_value = prev_value
    c.new_value = new_value
    pm = {"record_type": record_type}
    if pm_extra:
        pm.update(pm_extra)
    c.provider_metadata = pm
    return c


# ═════════════════════════════════════════════════════════════════════════════
# A. stripe_product
# ═════════════════════════════════════════════════════════════════════════════


class TestProduct:

    def test_A1_product_removed_live_is_high(self):
        c = _ch(record_type="stripe_product", change_type="removed",
                pm_extra={"record_id": "prod_001", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "high"
        assert "removed" in reason.lower() or "archived" in reason.lower()

    def test_A2_product_removed_test_mode_is_medium(self):
        c = _ch(record_type="stripe_product", change_type="removed",
                pm_extra={"record_id": "prod_002", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_A3_product_deactivated_live_is_high(self):
        c = _ch(record_type="stripe_product", field_path="active",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "prod_003", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_A4_product_reactivated_is_low(self):
        c = _ch(record_type="stripe_product", field_path="active",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "prod_004", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_A5_default_price_changed_is_medium(self):
        c = _ch(record_type="stripe_product", field_path="default_price",
                prev_value="price_old", new_value="price_new",
                pm_extra={"record_id": "prod_005", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "medium"
        assert "default_price" in reason or "default price" in reason.lower()

    def test_A6_metadata_key_count_changed_is_medium(self):
        c = _ch(record_type="stripe_product", field_path="metadata_key_count",
                prev_value=3, new_value=5,
                pm_extra={"record_id": "prod_006"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_A7_name_changed_is_low(self):
        c = _ch(record_type="stripe_product", field_path="name",
                prev_value="Old name", new_value="New name",
                pm_extra={"record_id": "prod_007"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_A8_added_is_low(self):
        c = _ch(record_type="stripe_product", change_type="added",
                pm_extra={"record_id": "prod_008"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# B. stripe_price
# ═════════════════════════════════════════════════════════════════════════════


class TestPrice:

    def test_B1_unit_amount_changed_active_live_is_critical(self):
        c = _ch(record_type="stripe_price", field_path="unit_amount",
                prev_value=1000, new_value=2000,
                pm_extra={"record_id": "price_001",
                          "active": True, "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "critical"
        assert "immutable" in reason.lower() or "replaced" in reason.lower()

    def test_B2_currency_changed_live_active_is_high(self):
        c = _ch(record_type="stripe_price", field_path="currency",
                prev_value="usd", new_value="eur",
                pm_extra={"record_id": "price_002",
                          "active": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_B3_recurring_interval_changed_live_active_is_high(self):
        c = _ch(record_type="stripe_price", field_path="recurring_interval",
                prev_value="month", new_value="year",
                pm_extra={"record_id": "price_003",
                          "active": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_B4_immutable_field_change_on_inactive_is_medium(self):
        c = _ch(record_type="stripe_price", field_path="unit_amount",
                prev_value=1000, new_value=2000,
                pm_extra={"record_id": "price_004",
                          "active": False, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B5_price_deactivated_is_high(self):
        c = _ch(record_type="stripe_price", field_path="active",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "price_005", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "high"
        assert "deactivated" in reason.lower()

    def test_B6_price_removed_active_live_is_high(self):
        c = _ch(record_type="stripe_price", change_type="removed",
                pm_extra={"record_id": "price_006",
                          "active": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_B7_tax_behavior_changed_is_medium(self):
        c = _ch(record_type="stripe_price", field_path="tax_behavior",
                prev_value="exclusive", new_value="inclusive",
                pm_extra={"record_id": "price_007"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B8_trial_period_changed_is_medium(self):
        c = _ch(record_type="stripe_price",
                field_path="recurring_trial_period_days",
                prev_value=7, new_value=30,
                pm_extra={"record_id": "price_008"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B9_lookup_key_changed_is_medium(self):
        c = _ch(record_type="stripe_price", field_path="lookup_key",
                prev_value="pro_monthly", new_value="pro_yearly",
                pm_extra={"record_id": "price_009"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B10_added_is_low(self):
        c = _ch(record_type="stripe_price", change_type="added",
                pm_extra={"record_id": "price_010"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_B11_reactivated_is_low(self):
        c = _ch(record_type="stripe_price", field_path="active",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "price_011"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. stripe_payment_link
# ═════════════════════════════════════════════════════════════════════════════


class TestPaymentLink:

    def test_C1_payment_link_disabled_live_is_high(self):
        c = _ch(record_type="stripe_payment_link", field_path="active",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "plink_001", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_C2_line_items_changed_live_is_high(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="line_item_price_ids",
                prev_value=["price_a"], new_value=["price_b"],
                pm_extra={"record_id": "plink_002", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "high"
        assert "price" in reason.lower() or "line item" in reason.lower()

    def test_C3_redirect_origin_changed_to_different_domain_is_high(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="success_url_origin",
                prev_value="https://api.example.com",
                new_value="https://attacker.example.net",
                pm_extra={"record_id": "plink_003", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "high"
        # The reason mentions the new origin (via the safe-URL helper).
        assert "attacker.example.net" in reason or "configured URL" in reason

    def test_C4_redirect_origin_changed_test_mode_is_medium(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="success_url_origin",
                prev_value="https://api.example.com",
                new_value="https://new.example.net",
                pm_extra={"record_id": "plink_004", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C5_promo_codes_toggled_is_medium(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="allow_promotion_codes",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "plink_005", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C6_automatic_tax_disabled_is_medium(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="automatic_tax_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "plink_006", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C7_transfer_destination_removed_is_high(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="transfer_destination_present",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "plink_007", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_C8_payment_link_removed_live_is_high(self):
        c = _ch(record_type="stripe_payment_link", change_type="removed",
                pm_extra={"record_id": "plink_008", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_C9_payment_link_added_is_medium(self):
        c = _ch(record_type="stripe_payment_link", change_type="added",
                pm_extra={"record_id": "plink_009", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C10_re_enabled_is_low(self):
        c = _ch(record_type="stripe_payment_link", field_path="active",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "plink_010"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_C11_application_fee_changed_is_medium(self):
        c = _ch(record_type="stripe_payment_link",
                field_path="application_fee_percent",
                prev_value=2.5, new_value=5.0,
                pm_extra={"record_id": "plink_011", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# D. stripe_checkout_configuration
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckoutConfiguration:

    def test_D1_payment_method_count_reduced_live_is_high(self):
        c = _ch(record_type="stripe_checkout_configuration",
                field_path="allowed_payment_method_types_count",
                prev_value=8, new_value=2,
                pm_extra={"record_id": "acct_001", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_D2_payment_method_count_reduced_test_is_medium(self):
        c = _ch(record_type="stripe_checkout_configuration",
                field_path="allowed_payment_method_types_count",
                prev_value=8, new_value=2,
                pm_extra={"record_id": "acct_002", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_D3_default_mode_changed_live_is_high(self):
        c = _ch(record_type="stripe_checkout_configuration",
                field_path="default_mode",
                prev_value="subscription", new_value="payment",
                pm_extra={"record_id": "acct_003", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_D4_collection_settings_changed_is_medium(self):
        for fp in ("default_customer_creation", "billing_address_collection",
                   "phone_collection_enabled",
                   "consent_collection_terms_of_service",
                   "invoice_creation_enabled"):
            c = _ch(record_type="stripe_checkout_configuration",
                    field_path=fp, prev_value="a", new_value="b",
                    pm_extra={"record_id": "acct_004", "livemode": True})
            level, _ = classify_stripe_change(c)
            assert level == "medium", f"{fp} should be medium"

    def test_D5_payment_method_count_increased_is_low(self):
        c = _ch(record_type="stripe_checkout_configuration",
                field_path="allowed_payment_method_types_count",
                prev_value=4, new_value=8,
                pm_extra={"record_id": "acct_005", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. stripe_tax_settings
# ═════════════════════════════════════════════════════════════════════════════


class TestTaxSettings:

    def test_E1_automatic_tax_disabled_live_is_high(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="automatic_tax_status",
                prev_value="active", new_value="inactive",
                pm_extra={"record_id": "acct_001", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "high"
        assert "tax" in reason.lower()

    def test_E2_automatic_tax_disabled_test_is_medium(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="automatic_tax_status",
                prev_value="active", new_value="inactive",
                pm_extra={"record_id": "acct_002", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_E3_automatic_tax_enabled_is_low(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="automatic_tax_status",
                prev_value="inactive", new_value="active",
                pm_extra={"record_id": "acct_003", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_E4_tax_registrations_reduced_live_is_high(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="tax_registrations_active_count",
                prev_value=10, new_value=3,
                pm_extra={"record_id": "acct_004", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_E5_tax_registrations_increased_is_low(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="tax_registrations_active_count",
                prev_value=3, new_value=10,
                pm_extra={"record_id": "acct_005", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_E6_default_tax_behavior_changed_is_medium(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="default_tax_behavior",
                prev_value="exclusive", new_value="inclusive",
                pm_extra={"record_id": "acct_006"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_E7_head_office_removed_is_high(self):
        c = _ch(record_type="stripe_tax_settings",
                field_path="head_office_address_present",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "acct_007"})
        level, _ = classify_stripe_change(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# F. Dispatcher + safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    @pytest.mark.parametrize(
        "fn",
        [
            _classify_product_change,
            _classify_price_change,
            _classify_payment_link_change,
            _classify_checkout_configuration_change,
            _classify_tax_settings_change,
        ],
    )
    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_F1_malformed_pm_does_not_crash(self, fn, bad_pm):
        c = MagicMock()
        c.change_type = "modified"
        c.field_path = "active"
        c.prev_value = True
        c.new_value = False
        c.provider_metadata = bad_pm
        level, _ = fn(c)
        assert level in ("critical", "high", "medium", "low")

    def test_F2_unknown_stripe_subtype_safe_default(self):
        c = _ch(record_type="stripe_does_not_exist", field_path="x",
                prev_value="a", new_value="b")
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_F3_top_level_dispatch_routes_all_new_types(self):
        for rt, expected in [
            ("stripe_product", "high"),       # removed live
            ("stripe_price", "high"),         # removed active live
            ("stripe_payment_link", "high"),  # removed live
        ]:
            c = _ch(record_type=rt, change_type="removed",
                    pm_extra={"record_id": "x_001", "livemode": True,
                              "active": True})
            level, _ = classify_stripe_change(c)
            assert level == expected, f"{rt}: expected {expected}, got {level}"

    def test_F4_top_level_dispatch_routes_checkout_and_tax(self):
        c1 = _ch(record_type="stripe_checkout_configuration",
                 field_path="default_mode",
                 prev_value="subscription", new_value="payment",
                 pm_extra={"record_id": "acct_x", "livemode": True})
        c2 = _ch(record_type="stripe_tax_settings",
                 field_path="automatic_tax_status",
                 prev_value="active", new_value="inactive",
                 pm_extra={"record_id": "acct_y", "livemode": True})
        assert classify_stripe_change(c1)[0] == "high"
        assert classify_stripe_change(c2)[0] == "high"


# ═════════════════════════════════════════════════════════════════════════════
# G. Schema registry includes new entries
# ═════════════════════════════════════════════════════════════════════════════


class TestSchemaRegistry:

    def test_G1_new_record_types_registered(self):
        from app.connectors.stripe_schema import (
            STRIPE_PRODUCT,
            STRIPE_PRICE,
            STRIPE_PAYMENT_LINK,
            STRIPE_CHECKOUT_CONFIGURATION,
            STRIPE_TAX_SETTINGS,
            STRIPE_RECORD_TYPES,
        )
        for rt in (STRIPE_PRODUCT, STRIPE_PRICE, STRIPE_PAYMENT_LINK,
                   STRIPE_CHECKOUT_CONFIGURATION, STRIPE_TAX_SETTINGS):
            assert rt in STRIPE_RECORD_TYPES


# ═════════════════════════════════════════════════════════════════════════════
# H. Existing surfaces — regression: original behaviour unchanged
# ═════════════════════════════════════════════════════════════════════════════


class TestExistingSurfacesUnchanged:

    def test_H1_account_webhook_pm_paths_still_classify(self):
        for rt in ("stripe_account_settings", "stripe_webhook_endpoint",
                   "stripe_payment_method_configuration",
                   "stripe_payment_method_domain",
                   "stripe_billing_portal_config"):
            c = _ch(record_type=rt, field_path="active",
                    prev_value=True, new_value=False,
                    pm_extra={"record_id": "x"})
            level, reason = classify_stripe_change(c)
            assert level in ("critical", "high", "medium", "low")
            assert isinstance(reason, str) and reason


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires — credential-shaped values must never leak.
# ═════════════════════════════════════════════════════════════════════════════


_SECRET_FIXTURES: dict[str, str] = {
    "stripe_sk_live": "sk_live_" + ("A" * 99),
    "stripe_sk_test": "sk_test_" + ("B" * 99),
    "stripe_whsec": "whsec_" + ("C" * 80),
    "stripe_rk": "rk_live_" + ("R" * 80),
    "aws_akia": "AKIA" + ("K" * 16),
    "bearer_jwt": "Bearer eyJhbGciOi" + ("X" * 80),
    "private_key_pem": (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("O" * 60) + "\n"
        "-----END PRIVATE KEY-----"
    ),
    "checkout_session_url_with_token": (
        "https://checkout.example.com/c/cs_live_"
        + ("Q" * 80) + "?token=" + ("Z" * 40)
    ),
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{32,}"),
    re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{32,}"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{32,}"),
    re.compile(r"\?token=[A-Za-z0-9_\-]{20,}"),
)


def _assert_safe(reason: str, secret: str) -> None:
    assert secret not in reason, f"reason leaked: {reason!r}"
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_payment_link_redirect_origin_secret_never_echoed(self, name, secret):
        """If a misconfigured/attacker-crafted redirect origin is a credential-
        shape, the classifier must redact it via _safe_url_origin."""
        c = _ch(record_type="stripe_payment_link",
                field_path="success_url_origin",
                prev_value="https://api.example.com", new_value=secret,
                pm_extra={"record_id": "plink_s1", "livemode": True})
        _, reason = classify_stripe_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_product_metadata_change_does_not_echo_secret(self, name, secret):
        c = _ch(record_type="stripe_product",
                field_path="default_price",
                prev_value="price_a", new_value=secret,
                pm_extra={"record_id": "prod_s2"})
        _, reason = classify_stripe_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S3_price_lookup_key_change_does_not_echo_secret(self, name, secret):
        c = _ch(record_type="stripe_price", field_path="lookup_key",
                prev_value="pro", new_value=secret,
                pm_extra={"record_id": "price_s3"})
        _, reason = classify_stripe_change(c)
        _assert_safe(reason, secret)

    def test_S4_no_forbidden_phrases_in_severe_reasons(self):
        bad_phrases = (
            "payments definitely broken", "revenue lost",
            "definitely broken", "guaranteed loss",
        )
        scenarios = [
            _ch(record_type="stripe_product", change_type="removed",
                pm_extra={"record_id": "x", "livemode": True}),
            _ch(record_type="stripe_price", field_path="unit_amount",
                prev_value=1000, new_value=2000,
                pm_extra={"record_id": "y", "active": True, "livemode": True}),
            _ch(record_type="stripe_payment_link", field_path="active",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "z", "livemode": True}),
            _ch(record_type="stripe_checkout_configuration",
                field_path="default_mode",
                prev_value="subscription", new_value="payment",
                pm_extra={"record_id": "a", "livemode": True}),
            _ch(record_type="stripe_tax_settings",
                field_path="automatic_tax_status",
                prev_value="active", new_value="inactive",
                pm_extra={"record_id": "b", "livemode": True}),
        ]
        for c in scenarios:
            _, reason = classify_stripe_change(c)
            r = reason.lower()
            for bad in bad_phrases:
                assert bad not in r, (
                    f"forbidden phrase {bad!r} in: {reason!r}"
                )
            # Hedged phrasing should appear in the most-severe scenarios.
            assert ("may " in r) or ("could " in r) or ("verify" in r)
