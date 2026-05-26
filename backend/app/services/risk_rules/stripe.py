"""Stripe risk classification rules — M35.

Entry point: ``classify_stripe_change(change)``

Risk levels
-----------
critical  — Webhook deleted, charges_enabled turned off, payouts_enabled
            turned off, Apple/Google Pay domain removed.
high      — Webhook URL changed (events redirected to new destination),
            webhook added, webhook disabled, enabled_events changed,
            payment method domain disabled/domain_name changed,
            payment method enabled/disabled in a config, is_default unset,
            payout schedule interval changed, controller type changed.
medium    — Account settings changed (capabilities, currency, support contact,
            business name), PM domain status changed, is_default set to True,
            payment method re-enabled, API version changed.
low       — Protection-strengthening changes (charges/payouts re-enabled,
            webhook re-enabled), cosmetic changes (branding, display name,
            descriptions), routine additions (PM config added).

Directionality
--------------
Every classification distinguishes:
  * new_value → False / "disabled" / removed  — weakening or loss of capability
  * new_value → True  / "enabled"  / added    — strengthening or new capability
Unknown / unavailable data never escalates to critical.
"""

from __future__ import annotations

from app.models.change import Change


def _get(obj: object, field: str) -> object:
    """Safely retrieve a field from a Change object or dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


# ── stripe_account_settings ───────────────────────────────────────────────────

def _classify_account_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    # Operational flags — service-impacting (directional)
    if fp == "charges_enabled":
        if new_v is False or new_v == "false":
            return (
                "critical",
                "Charges have been disabled on this Stripe account. "
                "New payments will be rejected immediately. "
                "Check the Stripe Dashboard for the reason and re-enable if this was unintended.",
            )
        # True → charges restored (positive / strengthening change)
        return (
            "medium",
            "Charges were re-enabled on this Stripe account. "
            "Payment acceptance has been restored.",
        )
    if fp == "payouts_enabled":
        if new_v is False or new_v == "false":
            return (
                "critical",
                "Payouts have been disabled on this Stripe account. "
                "Funds can no longer be transferred out. "
                "Check the Stripe Dashboard for the reason and re-enable if this was unintended.",
            )
        # True → payouts restored (positive / strengthening change)
        return (
            "medium",
            "Payouts were re-enabled on this Stripe account. "
            "Fund transfers to your bank account have been restored.",
        )

    # Payout schedule — affects cash flow
    if fp == "payout_schedule_interval":
        return (
            "high",
            "The payout schedule interval changed. "
            "This affects when funds are transferred to your bank account. "
            "Confirm the new schedule aligns with your cash-flow expectations.",
        )
    if fp == "payout_schedule_delay_days":
        return (
            "medium",
            "The payout schedule delay changed. "
            "Review the new payout timing with your finance team.",
        )

    # Enabled payment methods / capabilities
    if fp == "enabled_payment_methods":
        return (
            "medium",
            "The set of active payment method capabilities changed on this Stripe account. "
            "Verify that all payment methods you rely on are still enabled.",
        )

    # Default currency
    if fp == "default_currency":
        return (
            "medium",
            "The default currency for this Stripe account changed. "
            "Confirm pricing, checkout flows, and reporting are unaffected.",
        )

    # Business profile — contact / support info
    if fp in ("support_email", "support_url", "business_url"):
        return (
            "medium",
            f"The Stripe account {fp.replace('_', ' ')} changed. "
            "Verify the new contact details are correct.",
        )
    if fp == "business_name":
        return (
            "medium",
            "The Stripe account business name changed.",
        )

    # Branding — cosmetic
    if fp in ("branding_icon", "branding_logo"):
        return (
            "low",
            "The Stripe account branding image changed.",
        )
    if fp == "branding_primary_color":
        return (
            "low",
            "The Stripe account branding primary color changed.",
        )

    # Display name — cosmetic
    if fp == "display_name":
        return (
            "low",
            "The Stripe dashboard display name changed.",
        )

    # Controller type — platform config change
    if fp == "controller_type":
        return (
            "high",
            "The Stripe account controller type changed. "
            "This may indicate a platform ownership change. "
            "Verify the new controller configuration is expected.",
        )

    # Added / removed entire account record — shouldn't happen but handle it.
    if ct == "added":
        return ("low", "Stripe account settings baseline captured.")
    if ct == "removed":
        return ("high", "Stripe account settings record was removed — unexpected.")

    return ("low", "A Stripe account setting changed.")


# ── stripe_webhook_endpoint ───────────────────────────────────────────────────

def _classify_webhook_endpoint_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "removed":
        return (
            "critical",
            "A Stripe webhook endpoint was deleted. "
            "Events are no longer being delivered to this URL. "
            "Verify this was intentional — payment, checkout, and subscription "
            "events may stop reaching your application.",
        )
    if ct == "added":
        return (
            "high",
            "A new Stripe webhook endpoint was added. "
            "Confirm the delivery URL is under your control "
            "and the subscribed event set is correctly scoped.",
        )

    # Modified
    if fp == "url":
        return (
            "high",
            "A Stripe webhook endpoint URL changed. "
            "Stripe events will now be sent to the new URL. "
            "Verify the destination is under your control and ready to receive events.",
        )
    if fp == "status":
        if new_v in ("disabled", False, "false"):
            return (
                "high",
                "A Stripe webhook endpoint was disabled. "
                "Payment, checkout, or subscription events may stop reaching your application. "
                "Re-enable the endpoint if this was unintended.",
            )
        # Enabled — strengthening / restoration (positive change)
        return (
            "low",
            "A Stripe webhook endpoint was re-enabled. "
            "Event delivery to this URL has been restored.",
        )
    if fp == "enabled_events":
        return (
            "high",
            "The set of event types subscribed to by a Stripe webhook changed. "
            "Payment, checkout, or subscription events may have been added or removed. "
            "Verify that your application still receives the events it depends on.",
        )
    if fp == "api_version":
        return (
            "medium",
            "The API version used for Stripe webhook event payloads changed. "
            "If your handler expects the previous format, events may fail to process. "
            "Test your webhook handler against the new API version.",
        )
    if fp == "description":
        return ("low", "The Stripe webhook endpoint description changed.")

    return ("medium", "A Stripe webhook endpoint setting changed.")


# ── stripe_payment_method_configuration ──────────────────────────────────────

def _classify_payment_method_configuration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return (
            "low",
            "A new Stripe payment method configuration was added. "
            "Review the configuration to confirm its payment method availability is correct.",
        )
    if ct == "removed":
        return (
            "high",
            "A Stripe payment method configuration was removed. "
            "Check that checkout and payment flows that relied on this configuration still work.",
        )

    # Modified
    if fp == "enabled_payment_methods":
        return (
            "high",
            "The set of enabled payment methods in a Stripe configuration changed. "
            "Verify that checkout flows still offer the expected payment options.",
        )
    if fp == "is_default":
        # Directional: losing default status is more impactful than gaining it.
        if new_v is False or new_v == "false":
            return (
                "high",
                "The default Stripe payment method configuration was unset or replaced. "
                "Checkout flows may now use a different configuration's payment method availability. "
                "Verify the correct configuration is still the default.",
            )
        # True — a configuration was promoted to default (neutral/informational)
        return (
            "medium",
            "A Stripe payment method configuration was set as the new default. "
            "Checkout flows will use this configuration's payment method availability. "
            "Confirm the promoted configuration has the correct payment methods enabled.",
        )
    if fp == "config_name":
        return ("low", "A Stripe payment method configuration was renamed.")

    return ("medium", "A Stripe payment method configuration setting changed.")


# ── stripe_payment_method_domain ──────────────────────────────────────────────

def _classify_payment_method_domain_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "removed":
        return (
            "critical",
            "A Stripe payment method domain was removed. "
            "Apple Pay and Google Pay will no longer work on this domain.",
        )
    if ct == "added":
        return (
            "high",
            "A new Stripe payment method domain was added. "
            "Confirm the domain is under your control.",
        )

    # Modified
    if fp == "apple_pay_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "Apple Pay was disabled for a Stripe payment method domain. "
                "Apple Pay will no longer be available to customers on this domain.",
            )
        return (
            "medium",
            "Apple Pay was enabled for a Stripe payment method domain.",
        )
    if fp == "google_pay_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "Google Pay was disabled for a Stripe payment method domain. "
                "Google Pay will no longer be available to customers on this domain.",
            )
        return (
            "medium",
            "Google Pay was enabled for a Stripe payment method domain.",
        )
    if fp == "link_enabled":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "Link by Stripe was disabled for a payment method domain.",
            )
        return (
            "low",
            "Link by Stripe was enabled for a payment method domain.",
        )
    if fp == "enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "A Stripe payment method domain was disabled. "
                "Apple Pay and Google Pay will stop working on this domain.",
            )
        return (
            "low",
            "A Stripe payment method domain was re-enabled. "
            "Domain-based payment methods have been restored.",
        )
    if fp == "domain_name":
        return (
            "high",
            "The domain name for a Stripe payment method domain changed. "
            "Apple Pay, Google Pay, and Link may no longer work on the previous domain. "
            "Verify the new domain is correctly registered and verified with Stripe.",
        )

    return ("medium", "A Stripe payment method domain setting changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────

# ── stripe_billing_portal_config ──────────────────────────────────────────────

def _classify_billing_portal_config_change(change: Change) -> tuple[str, str]:
    """Risk rules for ``stripe_billing_portal_config`` records — M57.9.

    Priority chain (first match wins):
    1. removed → high
    2. added   → low
    3. active disabled → medium
    4. payment_method_update_enabled disabled → medium
    5. subscription_cancel_enabled changed → medium
    6. customer_update_allowed_updates changed → medium
    7. subscription_update_allowed_updates changed → medium
    8. login_page_enabled disabled → medium
    9. subscription_cancel_mode changed → low
    10. subscription_pause_enabled changed → low
    11. invoice_history_enabled changed → low
    12. is_default changed → low
    """
    change_type = (_get(change, "change_type") or "").lower()

    if change_type == "removed":
        return (
            "high",
            "A Stripe customer billing portal configuration was removed. "
            "Customers may lose access to self-service billing features.",
        )
    if change_type == "added":
        return (
            "low",
            "A new Stripe customer billing portal configuration was created.",
        )

    old = _get(change, "prev_value") or {}
    new = _get(change, "new_value") or {}
    if not isinstance(old, dict):
        old = {}
    if not isinstance(new, dict):
        new = {}

    # active disabled
    if old.get("active") is True and new.get("active") is False:
        return (
            "medium",
            "The Stripe customer billing portal configuration was deactivated. "
            "Customers may be unable to access self-service billing.",
        )

    # payment_method_update_enabled disabled
    if old.get("payment_method_update_enabled") is True and new.get("payment_method_update_enabled") is False:
        return (
            "medium",
            "Payment method updates were disabled in the Stripe billing portal. "
            "Customers may no longer be able to update their payment methods.",
        )

    # subscription_cancel_enabled changed
    if old.get("subscription_cancel_enabled") != new.get("subscription_cancel_enabled"):
        enabled_now = new.get("subscription_cancel_enabled")
        return (
            "medium",
            f"Subscription self-cancellation in the billing portal was "
            f"{'enabled' if enabled_now else 'disabled'}. "
            "Confirm this change is intentional.",
        )

    # customer_update_allowed_updates changed
    if old.get("customer_update_allowed_updates") != new.get("customer_update_allowed_updates"):
        return (
            "medium",
            "The set of customer-editable fields in the billing portal changed. "
            "Review which account details customers may now update.",
        )

    # subscription_update_allowed_updates changed
    if old.get("subscription_update_allowed_updates") != new.get("subscription_update_allowed_updates"):
        return (
            "medium",
            "Subscription update options in the billing portal changed. "
            "Verify the permitted plan changes are intentional.",
        )

    # login_page_enabled disabled
    if old.get("login_page_enabled") is True and new.get("login_page_enabled") is False:
        return (
            "medium",
            "The billing portal login page was disabled. "
            "Customers may no longer be able to sign in to the portal directly.",
        )

    # subscription_cancel_mode changed
    if old.get("subscription_cancel_mode") != new.get("subscription_cancel_mode"):
        return (
            "low",
            f"Subscription cancellation timing changed to "
            f"\"{new.get('subscription_cancel_mode')}\". "
            "Customers will experience different cancellation behaviour.",
        )

    # subscription_pause_enabled changed
    if old.get("subscription_pause_enabled") != new.get("subscription_pause_enabled"):
        return (
            "low",
            "Subscription pause capability in the billing portal changed.",
        )

    # invoice_history_enabled changed
    if old.get("invoice_history_enabled") != new.get("invoice_history_enabled"):
        return (
            "low",
            "Invoice history visibility in the billing portal changed.",
        )

    # is_default changed
    if old.get("is_default") != new.get("is_default"):
        return (
            "low",
            "The default billing portal configuration assignment changed.",
        )

    return (
        "low",
        "A Stripe billing portal configuration setting changed. "
        "Review for intended customer self-service impact.",
    )


def classify_stripe_change(change: Change) -> tuple[str, str]:
    """Return (risk_level, risk_reason) for a Stripe change.

    Dispatches to a per-record-type classifier function.  Returns
    ``("low", "…")`` as a safe fallback for unrecognised record types.
    """
    metadata = _get(change, "provider_metadata") or {}
    if isinstance(metadata, dict):
        record_type = (metadata.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "stripe_account_settings":
        return _classify_account_settings_change(change)
    if record_type == "stripe_webhook_endpoint":
        return _classify_webhook_endpoint_change(change)
    if record_type == "stripe_payment_method_configuration":
        return _classify_payment_method_configuration_change(change)
    if record_type == "stripe_payment_method_domain":
        return _classify_payment_method_domain_change(change)
    if record_type == "stripe_billing_portal_config":
        return _classify_billing_portal_config_change(change)

    return ("low", f"A Stripe configuration record changed ({record_type}).")
