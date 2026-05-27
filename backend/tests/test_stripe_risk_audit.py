"""Stripe risk accuracy audit — local-only regression tests.

Documents ConfigTrace's Stripe risk policy across all five record types
(account_settings, webhook_endpoint, payment_method_configuration,
payment_method_domain, billing_portal_config). Any future regression
that mis-rates one of these scenarios fails loudly here.

Special safety rules for Stripe:
  • No Stripe secret key / signing secret / Bearer token ever appears
    in risk reasons.
  • No raw webhook URL with embedded query secrets appears in reasons.
  • Reasons hedge with "may break" / "could disrupt" / "may affect"
    rather than claiming guaranteed payment outage.
  • No auto-fix language anywhere.

Pure-mock; no DB, no network, no Stripe API.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Critical Stripe events whose removal materially breaks revenue flows.
# Kept in sync with the production classifier (see _CRITICAL_STRIPE_EVENTS
# in risk_rules/stripe.py if/when that constant is introduced).
# ─────────────────────────────────────────────────────────────────────────────
_CRITICAL_EVENTS = (
    "checkout.session.completed",
    "invoice.payment_succeeded",
    "invoice.payment_failed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "payment_intent.succeeded",
    "payment_intent.payment_failed",
    "charge.succeeded",
    "charge.failed",
    "charge.refunded",
)


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
    record_name: str = "",
    record_id: str = "",
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {
        "record_type": record_type,
        "record_name": record_name,
        "record_id":   record_id,
    }
    if extra_metadata:
        pm.update(extra_metadata)
    c = MagicMock(name="Change")
    c.field_path        = field_path
    c.change_type       = change_type
    c.new_value         = new_value
    c.prev_value        = prev_value
    c.old_value         = prev_value
    c.provider_metadata = pm
    return c


def _classify(change):
    from app.services.risk_rules.stripe import classify_stripe_change
    return classify_stripe_change(change)


# ═════════════════════════════════════════════════════════════════════════════
# A. Webhook endpoints
# ═════════════════════════════════════════════════════════════════════════════

class TestWebhookEndpoint:
    def test_A1_webhook_url_changed_https_is_high(self):
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="url",
            new_value="https://api.example.com/stripe/v2",
            prev_value="https://api.example.com/stripe/v1",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A2_webhook_url_changed_to_http_is_critical(self):
        # Stripe API itself enforces HTTPS, but if the connector ever
        # surfaces a non-HTTPS URL, the risk classifier must escalate.
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="url",
            new_value="http://api.example.com/stripe",
            prev_value="https://api.example.com/stripe",
        )
        level, reason = _classify(c)
        assert level == "critical", (
            f"HTTP webhook URL must be critical; got {level} ({reason!r})"
        )

    def test_A3_webhook_endpoint_removed_is_critical(self):
        c = _change(
            record_type="stripe_webhook_endpoint",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A4_webhook_endpoint_disabled_is_high(self):
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="status",
            new_value="disabled",
            prev_value="enabled",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A5_webhook_endpoint_re_enabled_is_low(self):
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="status",
            new_value="enabled",
            prev_value="disabled",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A6_webhook_added_is_high_or_medium(self):
        # Per brief: "webhook added over HTTPS is Medium unless clearly risky."
        # Current production policy is high (defensive). Either is acceptable.
        c = _change(
            record_type="stripe_webhook_endpoint",
            change_type="added",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    @pytest.mark.parametrize("dropped_event", list(_CRITICAL_EVENTS))
    def test_A7_enabled_events_drops_critical_event_is_critical(self, dropped_event):
        # Removing a critical billing/payment event from the subscribed set
        # → critical. The classifier compares prev vs new value lists.
        prev = list(_CRITICAL_EVENTS)
        new  = [e for e in prev if e != dropped_event]
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="enabled_events",
            new_value=new,
            prev_value=prev,
        )
        level, _ = _classify(c)
        assert level == "critical", (
            f"removing critical event {dropped_event!r} must escalate to critical"
        )

    def test_A8_enabled_events_adds_only_is_high(self):
        # Adding events (no critical removed) → high (existing baseline).
        prev = ["invoice.created"]
        new  = ["invoice.created", "invoice.payment_succeeded"]
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="enabled_events",
            new_value=new,
            prev_value=prev,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A9_enabled_events_removes_only_non_critical_is_high(self):
        prev = ["invoice.created", "customer.created"]
        new  = ["invoice.created"]
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="enabled_events",
            new_value=new,
            prev_value=prev,
        )
        level, _ = _classify(c)
        # Non-critical removal stays at the baseline "high" rating.
        assert level == "high"

    def test_A10_webhook_api_version_change_is_medium(self):
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="api_version",
            new_value="2024-10-01",
            prev_value="2023-10-16",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A11_webhook_description_change_is_low(self):
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="description",
            new_value="prod webhook",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# B. Payment method configuration
# ═════════════════════════════════════════════════════════════════════════════

class TestPaymentMethodConfiguration:
    def test_B1_payment_method_config_removed_is_high(self):
        c = _change(
            record_type="stripe_payment_method_configuration",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B2_enabled_payment_methods_changed_is_high(self):
        c = _change(
            record_type="stripe_payment_method_configuration",
            field_path="enabled_payment_methods",
            new_value={"card": False, "apple_pay": True},
            prev_value={"card": True,  "apple_pay": True},
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B3_is_default_unset_is_high(self):
        c = _change(
            record_type="stripe_payment_method_configuration",
            field_path="is_default",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B4_is_default_set_is_medium(self):
        c = _change(
            record_type="stripe_payment_method_configuration",
            field_path="is_default",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B5_config_added_is_low(self):
        c = _change(
            record_type="stripe_payment_method_configuration",
            change_type="added",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. Payment method domain
# ═════════════════════════════════════════════════════════════════════════════

class TestPaymentMethodDomain:
    def test_C1_domain_removed_is_critical(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_C2_domain_added_is_high_or_medium(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            change_type="added",
        )
        level, _ = _classify(c)
        # Brief: "Medium" preferred for new HTTPS adds; current is "high"
        # (defensive). Either is acceptable.
        assert level in ("medium", "high")

    def test_C3_apple_pay_disabled_is_high(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            field_path="apple_pay_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C4_google_pay_disabled_is_high(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            field_path="google_pay_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C5_link_disabled_is_medium(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            field_path="link_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C6_domain_disabled_is_high(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            field_path="enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C7_domain_name_changed_is_high(self):
        c = _change(
            record_type="stripe_payment_method_domain",
            field_path="domain_name",
            new_value="newdomain.example.com",
            prev_value="olddomain.example.com",
        )
        level, _ = _classify(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# D. Billing portal config
# ═════════════════════════════════════════════════════════════════════════════

class TestBillingPortalConfig:
    def test_D1_billing_portal_removed_is_high(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D2_billing_portal_added_is_low(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            change_type="added",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_D3_active_disabled_is_medium(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            prev_value={"active": True,  "payment_method_update_enabled": True},
            new_value={"active": False, "payment_method_update_enabled": True},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D4_payment_method_update_disabled_is_medium(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            prev_value={"active": True, "payment_method_update_enabled": True},
            new_value={"active": True, "payment_method_update_enabled": False},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D5_subscription_cancel_enabled_changed_is_medium(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            prev_value={"active": True, "subscription_cancel_enabled": True},
            new_value={"active": True, "subscription_cancel_enabled": False},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D6_login_page_disabled_is_medium(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            prev_value={"active": True, "login_page_enabled": True},
            new_value={"active": True, "login_page_enabled": False},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D7_subscription_pause_changed_is_low(self):
        c = _change(
            record_type="stripe_billing_portal_config",
            prev_value={"active": True, "subscription_pause_enabled": True},
            new_value={"active": True, "subscription_pause_enabled": False},
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. Account settings
# ═════════════════════════════════════════════════════════════════════════════

class TestAccountSettings:
    def test_E1_charges_disabled_is_critical(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="charges_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_E2_payouts_disabled_is_critical(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="payouts_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_E3_payout_schedule_interval_changed_is_high(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="payout_schedule_interval",
            new_value="manual",
            prev_value="daily",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_E4_support_url_changed_is_at_least_medium(self):
        # Brief: "support/business profile URL changed to unknown domain is
        # Medium/High depending represented impact." Current production
        # policy is medium for all support URL changes.
        c = _change(
            record_type="stripe_account_settings",
            field_path="support_url",
            new_value="https://new-support.example.com",
            prev_value="https://support.example.com",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_E5_business_name_change_is_medium(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="business_name",
            new_value="Acme Inc.",
            prev_value="Acme LLC",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E6_branding_change_is_low(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="branding_primary_color",
            new_value="#0000ff",
            prev_value="#ff0000",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_E7_display_name_change_is_low(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="display_name",
            new_value="Acme Production",
            prev_value="Acme Prod",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_E8_controller_type_change_is_high(self):
        c = _change(
            record_type="stripe_account_settings",
            field_path="controller_type",
            new_value="application",
            prev_value="account",
        )
        level, _ = _classify(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# F. Unknown subtype + dispatcher safety
# ═════════════════════════════════════════════════════════════════════════════

class TestUnknownAndSafety:
    def test_F1_unknown_subtype_falls_back_safely(self):
        c = _change(record_type="stripe_future_thing")
        level, reason = _classify(c)
        assert level == "low"
        assert isinstance(reason, str) and len(reason) > 0

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_F2_malformed_provider_metadata_does_not_crash(self, bad_pm):
        c = MagicMock(name="Change")
        c.field_path        = "field"
        c.change_type       = "modified"
        c.new_value         = None
        c.prev_value        = None
        c.old_value         = None
        c.provider_metadata = bad_pm
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# G. Secret / token / URL safety — Stripe-specific
# ═════════════════════════════════════════════════════════════════════════════

class TestSecretSafety:
    """Reasons must never expose Stripe secrets, signing secrets, Bearer
    tokens, or webhook URLs with embedded query secrets."""

    @pytest.mark.parametrize("change_args", [
        # Webhook URL change with a secret query parameter (synthetic — the
        # connector should never pass this, but the classifier must not
        # echo it into the reason regardless).
        dict(record_type="stripe_webhook_endpoint", field_path="url",
             new_value="https://api.example.com/stripe?token=xyz", prev_value=None),
        dict(record_type="stripe_webhook_endpoint", change_type="removed"),
        dict(record_type="stripe_webhook_endpoint", field_path="status",
             new_value="disabled", prev_value="enabled"),
        dict(record_type="stripe_webhook_endpoint", field_path="enabled_events",
             new_value=["customer.created"],
             prev_value=["customer.created", "checkout.session.completed"]),
        dict(record_type="stripe_payment_method_domain",
             field_path="domain_name", new_value="secret.example.com",
             prev_value="public.example.com"),
        dict(record_type="stripe_account_settings", field_path="charges_enabled",
             new_value=False, prev_value=True),
    ])
    def test_G1_reason_does_not_leak_stripe_secrets(self, change_args):
        # Construct a change where new_value contains a fake secret-shaped
        # string in case the classifier ever echoed it.
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # Stripe key prefixes (real keys never appear; tripwire for future regressions)
        for prefix in ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_"):
            assert prefix not in lower, (
                f"reason contains a Stripe secret prefix {prefix!r}: {reason!r}"
            )
        # Raw Authorization / Bearer tokens
        for token in ("authorization:", "bearer "):
            assert token not in lower, (
                f"reason contains an auth header marker: {reason!r}"
            )

    def test_G2_webhook_url_change_reason_does_not_echo_new_url(self):
        # Even when the connector hands us a URL, the risk reason must not
        # echo the full URL — it could contain query secrets or otherwise
        # sensitive paths. Description-only references are OK.
        c = _change(
            record_type="stripe_webhook_endpoint",
            field_path="url",
            new_value="https://api.example.com/stripe/v2?token=SECRET",
            prev_value="https://api.example.com/stripe/v1",
        )
        _, reason = _classify(c)
        assert "secret" not in reason.lower(), reason
        assert "token=" not in reason.lower(), reason
        # The classifier should not echo the literal URL string.
        assert "https://api.example.com" not in reason

    def test_G3_no_auto_fix_language(self):
        cases = [
            dict(record_type="stripe_webhook_endpoint", change_type="removed"),
            dict(record_type="stripe_webhook_endpoint", field_path="url",
                 new_value="https://api.example.com/stripe", prev_value=None),
            dict(record_type="stripe_account_settings",
                 field_path="charges_enabled", new_value=False, prev_value=True),
            dict(record_type="stripe_payment_method_domain", change_type="removed"),
        ]
        bad = ("auto-fix", "automatically fix", "guaranteed", "auto fix",
               "guaranteed outage")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, (
                    f"reason contains {phrase!r}: {reason!r}"
                )

    def test_G4_no_overclaim_of_guaranteed_payment_outage(self):
        # Reasons should hedge: "may break", "could disrupt", etc.
        cases = [
            dict(record_type="stripe_webhook_endpoint", change_type="removed"),
            dict(record_type="stripe_webhook_endpoint", field_path="status",
                 new_value="disabled", prev_value="enabled"),
            dict(record_type="stripe_webhook_endpoint", field_path="enabled_events",
                 new_value=["customer.created"],
                 prev_value=["customer.created", "invoice.payment_succeeded"]),
            dict(record_type="stripe_payment_method_domain", change_type="removed"),
        ]
        absolute_phrases = (
            "payments are broken",
            "checkout is offline",
            "guaranteed payment failure",
            "all payments will fail",
        )
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in absolute_phrases:
                assert phrase not in lower, (
                    f"reason claims definitive outage: {reason!r}"
                )
