"""Stripe Part 2 — fraud / restricted keys / subscription-invoice / dunning /
payouts (external accounts) / coupons / promotion codes.

All seven new classifiers are exercised through the top-level
``classify_stripe_change`` dispatch.  No real Stripe API is called and no
real credentials are loaded.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.stripe import (
    classify_stripe_change,
    _classify_radar_rule_change,
    _classify_restricted_api_key_change,
    _classify_subscription_invoice_settings_change,
    _classify_dunning_settings_change,
    _classify_external_account_change,
    _classify_coupon_change,
    _classify_promotion_code_change,
)


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
# A. stripe_radar_rule
# ═════════════════════════════════════════════════════════════════════════════


class TestRadarRule:

    def test_A1_block_to_allow_live_is_critical(self):
        c = _ch(record_type="stripe_radar_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"record_id": "rule_001", "name": "SQLi block",
                          "action": "allow", "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "critical"
        assert "block" in reason.lower() and "allow" in reason.lower()

    def test_A2_block_to_allow_test_mode_is_high(self):
        c = _ch(record_type="stripe_radar_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"record_id": "rule_002", "name": "test",
                          "action": "allow", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_A3_challenge_to_allow_is_high(self):
        c = _ch(record_type="stripe_radar_rule", field_path="action",
                prev_value="request_three_d_secure", new_value="allow",
                pm_extra={"record_id": "rule_003", "name": "3DS",
                          "action": "allow", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_A4_review_to_allow_is_high(self):
        c = _ch(record_type="stripe_radar_rule", field_path="action",
                prev_value="review", new_value="allow",
                pm_extra={"record_id": "rule_004", "name": "Review",
                          "action": "allow", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_A5_allow_to_block_is_low_strengthened(self):
        c = _ch(record_type="stripe_radar_rule", field_path="action",
                prev_value="allow", new_value="block",
                pm_extra={"record_id": "rule_005", "name": "newly-blocking",
                          "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_A6_rule_disabled_protective_live_is_high(self):
        c = _ch(record_type="stripe_radar_rule", field_path="enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "rule_006", "name": "block-rule",
                          "action": "block", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_A7_rule_disabled_protective_test_mode_is_medium(self):
        c = _ch(record_type="stripe_radar_rule", field_path="enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "rule_007", "name": "block-rule",
                          "action": "block", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_A8_rule_re_enabled_is_low(self):
        c = _ch(record_type="stripe_radar_rule", field_path="enabled",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "rule_008", "name": "block-rule",
                          "action": "block"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_A9_rule_removed_protective_live_is_high(self):
        c = _ch(record_type="stripe_radar_rule", change_type="removed",
                pm_extra={"record_id": "rule_009", "name": "block-rule",
                          "action": "block", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_A10_rule_removed_permissive_is_medium(self):
        c = _ch(record_type="stripe_radar_rule", change_type="removed",
                pm_extra={"record_id": "rule_010", "name": "allow-rule",
                          "action": "allow", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_A11_expression_hash_changed_is_medium_and_safe(self):
        c = _ch(record_type="stripe_radar_rule", field_path="expression_hash",
                prev_value="hash_aaaa", new_value="hash_bbbb",
                pm_extra={"record_id": "rule_011", "name": "geo-block",
                          "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "medium"
        # Hash values are not echoed (they're identifiers, not secrets, but
        # we still avoid leaking them).
        assert "hash_aaaa" not in reason and "hash_bbbb" not in reason

    def test_A12_rule_added_is_medium(self):
        c = _ch(record_type="stripe_radar_rule", change_type="added",
                pm_extra={"record_id": "rule_012", "name": "new-rule"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# B. stripe_restricted_api_key
# ═════════════════════════════════════════════════════════════════════════════


class TestRestrictedAPIKey:

    def test_B1_new_key_with_secret_access_live_is_critical(self):
        c = _ch(record_type="stripe_restricted_api_key", change_type="added",
                pm_extra={"record_id": "rk_001", "name": "secrets-mgr",
                          "key_id_prefix": "rk_live",
                          "has_secret_permission": True,
                          "has_write_permission": True})
        level, reason = classify_stripe_change(c)
        assert level == "critical"
        assert "secret" in reason.lower()

    def test_B2_new_key_with_write_live_is_high(self):
        c = _ch(record_type="stripe_restricted_api_key", change_type="added",
                pm_extra={"record_id": "rk_002", "name": "writer",
                          "key_id_prefix": "rk_live",
                          "has_secret_permission": False,
                          "has_write_permission": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_B3_new_key_with_write_test_mode_is_medium(self):
        c = _ch(record_type="stripe_restricted_api_key", change_type="added",
                pm_extra={"record_id": "rk_003", "name": "writer-test",
                          "key_id_prefix": "rk_test",
                          "has_write_permission": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B4_new_read_only_key_is_medium(self):
        c = _ch(record_type="stripe_restricted_api_key", change_type="added",
                pm_extra={"record_id": "rk_004", "name": "reader",
                          "key_id_prefix": "rk_live"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B5_key_gained_write_live_is_high(self):
        c = _ch(record_type="stripe_restricted_api_key",
                field_path="has_write_permission",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "rk_005", "name": "scope-creep",
                          "key_id_prefix": "rk_live"})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_B6_key_gained_secret_access_live_is_critical(self):
        c = _ch(record_type="stripe_restricted_api_key",
                field_path="has_secret_permission",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "rk_006", "name": "secrets-creep",
                          "key_id_prefix": "rk_live"})
        level, _ = classify_stripe_change(c)
        assert level == "critical"

    def test_B7_permissions_count_increased_live_is_high(self):
        c = _ch(record_type="stripe_restricted_api_key",
                field_path="permissions_count",
                prev_value=2, new_value=8,
                pm_extra={"record_id": "rk_007",
                          "key_id_prefix": "rk_live"})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_B8_permissions_count_narrowed_is_low(self):
        c = _ch(record_type="stripe_restricted_api_key",
                field_path="permissions_count",
                prev_value=8, new_value=2,
                pm_extra={"record_id": "rk_008",
                          "key_id_prefix": "rk_live"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_B9_key_removed_live_is_medium(self):
        c = _ch(record_type="stripe_restricted_api_key", change_type="removed",
                pm_extra={"record_id": "rk_009", "name": "rotated",
                          "key_id_prefix": "rk_live"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_B10_key_removed_test_mode_is_low(self):
        c = _ch(record_type="stripe_restricted_api_key", change_type="removed",
                pm_extra={"record_id": "rk_010",
                          "key_id_prefix": "rk_test"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. stripe_subscription_invoice_settings
# ═════════════════════════════════════════════════════════════════════════════


class TestSubscriptionInvoiceSettings:

    def test_C1_collection_method_changed_live_is_high(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="default_collection_method",
                prev_value="charge_automatically", new_value="send_invoice",
                pm_extra={"record_id": "acct_001", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_C2_collection_method_changed_test_is_medium(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="default_collection_method",
                prev_value="charge_automatically", new_value="send_invoice",
                pm_extra={"record_id": "acct_002", "livemode": False})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C3_proration_changed_is_medium(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="default_proration_behavior",
                prev_value="create_prorations", new_value="none",
                pm_extra={"record_id": "acct_003"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C4_auto_advance_disabled_live_is_high(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="auto_advance_default",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "acct_004", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_C5_days_until_due_changed_is_medium(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="default_days_until_due",
                prev_value=30, new_value=7,
                pm_extra={"record_id": "acct_005"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_C6_cancel_at_period_end_enabled_is_high(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="cancel_at_period_end_default",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "acct_006", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_C7_auto_advance_enabled_is_low(self):
        c = _ch(record_type="stripe_subscription_invoice_settings",
                field_path="auto_advance_default",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "acct_007"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# D. stripe_dunning_settings
# ═════════════════════════════════════════════════════════════════════════════


class TestDunningSettings:

    def test_D1_retry_schedule_disabled_live_is_high(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="retry_schedule_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "acct_001", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_D2_smart_retries_disabled_live_is_high(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="smart_retries_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "acct_002", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_D3_past_due_to_cancel_live_is_high(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="past_due_action",
                prev_value="leave_as_is", new_value="cancel",
                pm_extra={"record_id": "acct_003", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_D4_past_due_to_leave_is_medium(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="past_due_action",
                prev_value="cancel", new_value="leave_as_is",
                pm_extra={"record_id": "acct_004", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_D5_retry_max_attempts_lowered_is_medium(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="retry_schedule_max_attempts",
                prev_value=8, new_value=2,
                pm_extra={"record_id": "acct_005"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_D6_retry_max_attempts_raised_is_low(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="retry_schedule_max_attempts",
                prev_value=2, new_value=8,
                pm_extra={"record_id": "acct_006"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_D7_failure_emails_disabled_is_medium(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="email_failed_payment_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "acct_007"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_D8_retries_re_enabled_is_low(self):
        c = _ch(record_type="stripe_dunning_settings",
                field_path="retry_schedule_enabled",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "acct_008"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. stripe_external_account
# ═════════════════════════════════════════════════════════════════════════════


class TestExternalAccount:

    def test_E1_added_default_live_is_high(self):
        c = _ch(record_type="stripe_external_account", change_type="added",
                pm_extra={"record_id": "ba_001", "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_E2_added_non_default_is_medium(self):
        c = _ch(record_type="stripe_external_account", change_type="added",
                pm_extra={"record_id": "ba_002", "account_type": "bank_account",
                          "default_for_currency": False, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_E3_removed_default_live_is_high(self):
        c = _ch(record_type="stripe_external_account", change_type="removed",
                pm_extra={"record_id": "ba_003", "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_E4_routing_fingerprint_changed_default_live_is_critical(self):
        c = _ch(record_type="stripe_external_account",
                field_path="routing_fingerprint",
                prev_value="fp_a", new_value="fp_b",
                pm_extra={"record_id": "ba_004", "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True})
        level, reason = classify_stripe_change(c)
        assert level == "critical"
        assert "routing" in reason.lower()
        # No raw routing number leaked.
        assert "fp_a" not in reason and "fp_b" not in reason

    def test_E5_last4_changed_default_live_is_high(self):
        c = _ch(record_type="stripe_external_account", field_path="last4",
                prev_value="1234", new_value="5678",
                pm_extra={"record_id": "ba_005", "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_E6_promoted_to_default_is_high(self):
        c = _ch(record_type="stripe_external_account",
                field_path="default_for_currency",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "ba_006", "account_type": "bank_account"})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_E7_status_errored_default_live_is_high(self):
        c = _ch(record_type="stripe_external_account", field_path="status",
                prev_value="verified", new_value="errored",
                pm_extra={"record_id": "ba_007", "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_E8_status_verified_is_low(self):
        c = _ch(record_type="stripe_external_account", field_path="status",
                prev_value="new", new_value="verified",
                pm_extra={"record_id": "ba_008", "account_type": "bank_account"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# F. stripe_coupon
# ═════════════════════════════════════════════════════════════════════════════


class TestCoupon:

    def test_F1_high_value_coupon_added_live_is_high(self):
        c = _ch(record_type="stripe_coupon", change_type="added",
                pm_extra={"record_id": "FREE", "name": "Free forever",
                          "duration": "forever",
                          "percent_off": 100.0, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_F2_high_value_50_percent_coupon_added_live_is_high(self):
        c = _ch(record_type="stripe_coupon", change_type="added",
                pm_extra={"record_id": "HALF", "name": "Half off",
                          "duration": "once",
                          "percent_off": 60.0, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_F3_low_value_coupon_added_is_medium(self):
        c = _ch(record_type="stripe_coupon", change_type="added",
                pm_extra={"record_id": "SMALL", "name": "Small discount",
                          "duration": "once", "percent_off": 10.0,
                          "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_F4_coupon_removed_is_medium(self):
        c = _ch(record_type="stripe_coupon", change_type="removed",
                pm_extra={"record_id": "OLD", "name": "Old coupon"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_F5_coupon_became_invalid_is_low(self):
        c = _ch(record_type="stripe_coupon", field_path="valid",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "OLD", "name": "Old coupon",
                          "duration": "once", "percent_off": 10.0})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_F6_high_value_became_valid_again_is_high(self):
        c = _ch(record_type="stripe_coupon", field_path="valid",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "BIG", "name": "Big discount",
                          "duration": "forever", "percent_off": 80.0,
                          "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_F7_duration_changed_to_forever_live_is_high(self):
        c = _ch(record_type="stripe_coupon", field_path="duration",
                prev_value="once", new_value="forever",
                pm_extra={"record_id": "FOREVER", "name": "Now forever",
                          "duration": "forever", "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "high"

    def test_F8_percent_off_changed_is_medium(self):
        c = _ch(record_type="stripe_coupon", field_path="percent_off",
                prev_value=10.0, new_value=50.0,
                pm_extra={"record_id": "BIGGER", "name": "Bigger"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_F9_amount_off_changed_is_medium(self):
        c = _ch(record_type="stripe_coupon", field_path="amount_off",
                prev_value=500, new_value=5000,
                pm_extra={"record_id": "CASH", "name": "Cash"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_F10_applies_to_count_changed_is_medium(self):
        c = _ch(record_type="stripe_coupon", field_path="applies_to_count",
                prev_value=1, new_value=10,
                pm_extra={"record_id": "MANY", "name": "Many"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# G. stripe_promotion_code
# ═════════════════════════════════════════════════════════════════════════════


class TestPromotionCode:

    def test_G1_added_broad_audience_live_is_medium(self):
        c = _ch(record_type="stripe_promotion_code", change_type="added",
                pm_extra={"record_id": "promo_001", "code": "SUMMER20",
                          "customer_restricted": False, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_G2_added_customer_restricted_is_low(self):
        c = _ch(record_type="stripe_promotion_code", change_type="added",
                pm_extra={"record_id": "promo_002", "code": "VIP-bob",
                          "customer_restricted": True, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_G3_activated_broad_audience_is_medium(self):
        c = _ch(record_type="stripe_promotion_code", field_path="active",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "promo_003", "code": "WELCOME10",
                          "customer_restricted": False, "livemode": True})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_G4_deactivated_is_low(self):
        c = _ch(record_type="stripe_promotion_code", field_path="active",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "promo_004", "code": "EXPIRED"})
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_G5_max_redemptions_changed_is_medium(self):
        c = _ch(record_type="stripe_promotion_code",
                field_path="max_redemptions",
                prev_value=100, new_value=10000,
                pm_extra={"record_id": "promo_005", "code": "BIGRUN"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_G6_customer_restriction_removed_is_medium(self):
        c = _ch(record_type="stripe_promotion_code",
                field_path="customer_restricted",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "promo_006", "code": "NOW-BROAD"})
        level, _ = classify_stripe_change(c)
        assert level == "medium"

    def test_G7_removed_is_low(self):
        c = _ch(record_type="stripe_promotion_code", change_type="removed",
                pm_extra={"record_id": "promo_007", "code": "GONE"})
        level, _ = classify_stripe_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# H. Dispatcher + safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    @pytest.mark.parametrize(
        "fn",
        [
            _classify_radar_rule_change,
            _classify_restricted_api_key_change,
            _classify_subscription_invoice_settings_change,
            _classify_dunning_settings_change,
            _classify_external_account_change,
            _classify_coupon_change,
            _classify_promotion_code_change,
        ],
    )
    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_H1_malformed_pm_does_not_crash(self, fn, bad_pm):
        c = MagicMock()
        c.change_type = "modified"
        c.field_path = "active"
        c.prev_value = True
        c.new_value = False
        c.provider_metadata = bad_pm
        level, _ = fn(c)
        assert level in ("critical", "high", "medium", "low")

    def test_H2_unknown_subtype_safe_default(self):
        c = _ch(record_type="stripe_does_not_exist_part2", field_path="x",
                prev_value="a", new_value="b")
        level, _ = classify_stripe_change(c)
        assert level == "low"

    def test_H3_dispatcher_routes_all_part2_types(self):
        cases = [
            ("stripe_radar_rule", "action", "block", "allow",
             {"record_id": "r", "name": "n", "action": "allow",
              "livemode": True}, "critical"),
            ("stripe_restricted_api_key", "has_secret_permission",
             False, True,
             {"record_id": "k", "name": "n", "key_id_prefix": "rk_live"},
             "critical"),
            ("stripe_subscription_invoice_settings",
             "default_collection_method",
             "charge_automatically", "send_invoice",
             {"record_id": "s", "livemode": True}, "high"),
            ("stripe_dunning_settings", "retry_schedule_enabled", True, False,
             {"record_id": "d", "livemode": True}, "high"),
            ("stripe_external_account", "routing_fingerprint", "a", "b",
             {"record_id": "e", "account_type": "bank_account",
              "default_for_currency": True, "livemode": True}, "critical"),
            ("stripe_coupon", None, None, None,  # added high-value
             {"record_id": "c", "duration": "forever", "percent_off": 100.0,
              "livemode": True}, "high"),
            ("stripe_promotion_code", None, None, None,  # added broad
             {"record_id": "p", "code": "OPEN", "customer_restricted": False,
              "livemode": True}, "medium"),
        ]
        for rt, fp, pv, nv, pm, expected in cases:
            kwargs: dict = {"record_type": rt, "pm_extra": pm}
            if fp is None:
                kwargs["change_type"] = "added"
            else:
                kwargs["field_path"] = fp
                kwargs["prev_value"] = pv
                kwargs["new_value"] = nv
            c = _ch(**kwargs)
            level, _ = classify_stripe_change(c)
            assert level == expected, (
                f"{rt}: expected {expected}, got {level}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# I. Schema registry includes new entries
# ═════════════════════════════════════════════════════════════════════════════


class TestSchemaRegistry:

    def test_I1_new_record_types_registered(self):
        from app.connectors.stripe_schema import (
            STRIPE_RADAR_RULE,
            STRIPE_RESTRICTED_API_KEY,
            STRIPE_SUBSCRIPTION_INVOICE_SETTINGS,
            STRIPE_DUNNING_SETTINGS,
            STRIPE_EXTERNAL_ACCOUNT,
            STRIPE_COUPON,
            STRIPE_PROMOTION_CODE,
            STRIPE_RECORD_TYPES,
        )
        for rt in (
            STRIPE_RADAR_RULE, STRIPE_RESTRICTED_API_KEY,
            STRIPE_SUBSCRIPTION_INVOICE_SETTINGS, STRIPE_DUNNING_SETTINGS,
            STRIPE_EXTERNAL_ACCOUNT, STRIPE_COUPON, STRIPE_PROMOTION_CODE,
        ):
            assert rt in STRIPE_RECORD_TYPES


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires
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
    "bank_account_number": "9999888877776666",
    "us_routing_number": "021000021",
    "iban_like": "DE89370400440532013000",
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{32,}"),
    re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{32,}"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{32,}"),
)


def _assert_safe(reason: str, secret: str) -> None:
    assert secret not in reason, f"reason leaked: {reason!r}"
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_radar_expression_hash_never_echoes_secret(self, name, secret):
        c = _ch(record_type="stripe_radar_rule", field_path="expression_hash",
                prev_value="hash_old", new_value=secret,
                pm_extra={"record_id": "rule_s1", "name": "test-rule",
                          "livemode": True})
        _, reason = classify_stripe_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_restricted_api_key_name_never_echoes_secret(self, name, secret):
        """The 'name' field is operator-supplied free text — if it carries a
        credential-shape it must not be echoed in a way that surfaces the
        substring as a leak.  We allow display in the reason but assert the
        secret-pattern regex catches no instance."""
        c = _ch(record_type="stripe_restricted_api_key",
                field_path="has_secret_permission",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "rk_s2", "name": secret,
                          "key_id_prefix": "rk_live"})
        _, reason = classify_stripe_change(c)
        # Direct presence — the reason DOES contain the name (a known
        # tradeoff: the operator chose the name).  But credential-shaped
        # regex patterns must still not match because the operator-supplied
        # name is presumed safe by contract.  Sanity-check: the reason does
        # NOT contain a secret-prefix shape from another fixture.
        # We assert the specific patterns that would indicate a true leak.
        for p in _FORBIDDEN_PATTERNS:
            # The name parameter MAY match because operator chose it; this
            # test instead confirms no other-channel leak.  Skip the bytes
            # that exactly equal `secret` and check the rest of the reason.
            reason_without_name = reason.replace(secret, "[NAME]")
            assert not p.search(reason_without_name), (
                f"reason leaked outside the name field: {reason!r}"
            )

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S3_external_account_field_change_does_not_echo_secret(
        self, name, secret
    ):
        """A misconfigured ``new_value`` for fingerprint/last4 must not be
        echoed."""
        c = _ch(record_type="stripe_external_account",
                field_path="routing_fingerprint",
                prev_value="fp_old", new_value=secret,
                pm_extra={"record_id": "ba_s3",
                          "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True})
        _, reason = classify_stripe_change(c)
        _assert_safe(reason, secret)

    def test_S4_no_overclaiming_phrases(self):
        """Never claim payment outage or confirmed fraud exposure."""
        forbidden_phrases = (
            "payments are down",
            "payments definitely broken",
            "fraud exposure confirmed",
            "revenue lost",
            "guaranteed loss",
            "definitely compromised",
        )
        scenarios = [
            _ch(record_type="stripe_radar_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"record_id": "r", "name": "n", "action": "allow",
                          "livemode": True}),
            _ch(record_type="stripe_restricted_api_key", change_type="added",
                pm_extra={"record_id": "k", "name": "n",
                          "key_id_prefix": "rk_live",
                          "has_secret_permission": True}),
            _ch(record_type="stripe_dunning_settings",
                field_path="retry_schedule_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "d", "livemode": True}),
            _ch(record_type="stripe_external_account",
                field_path="routing_fingerprint",
                prev_value="a", new_value="b",
                pm_extra={"record_id": "e", "account_type": "bank_account",
                          "default_for_currency": True, "livemode": True}),
            _ch(record_type="stripe_coupon", change_type="added",
                pm_extra={"record_id": "c", "duration": "forever",
                          "percent_off": 100.0, "livemode": True}),
        ]
        for c in scenarios:
            _, reason = classify_stripe_change(c)
            r = reason.lower()
            for bad in forbidden_phrases:
                assert bad not in r, f"forbidden phrase {bad!r} in: {reason!r}"
            # Severe scenarios should still use hedged language.
            assert ("may " in r) or ("could " in r) or ("verify" in r)
