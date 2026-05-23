"""Stripe risk classification rules — M35.

Entry point: ``classify_stripe_change(change)``

Risk levels
-----------
critical  — Webhook URL changed, webhook deleted, charges_enabled turned off,
            payouts_enabled turned off, Apple/Google Pay domain removed.
high      — Webhook added, enabled_events changed, webhook disabled,
            payment method domain added/removed, payout schedule changed,
            payment method enabled/disabled in a config.
medium    — Account settings changed (branding, support contact, currency,
            business name), PM domain status changed.
low       — Read-only or cosmetic changes (display name, dashboard locale,
            branding colors, description fields).
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

    # Operational flags — service-impacting
    if fp == "charges_enabled":
        if new_v is False or new_v == "false":
            return (
                "critical",
                "Charges have been disabled on this Stripe account. "
                "This will prevent accepting new payments immediately.",
            )
        return (
            "high",
            "Charges enabled status changed on this Stripe account.",
        )
    if fp == "payouts_enabled":
        if new_v is False or new_v == "false":
            return (
                "critical",
                "Payouts have been disabled on this Stripe account. "
                "Funds can no longer be transferred out.",
            )
        return (
            "high",
            "Payouts enabled status changed on this Stripe account.",
        )

    # Payout schedule — affects cash flow
    if fp == "payout_schedule_interval":
        return (
            "high",
            "The payout schedule interval changed. "
            "This affects when funds are transferred to your bank account.",
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
            "The set of enabled payment method capabilities changed on this Stripe account.",
        )

    # Default currency
    if fp == "default_currency":
        return (
            "medium",
            "The default currency for this Stripe account changed.",
        )

    # Business profile — contact / support info
    if fp in ("support_email", "support_url", "business_url"):
        return (
            "medium",
            f"The Stripe account {fp.replace('_', ' ')} changed.",
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
            "This may indicate a platform ownership change.",
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
            "Verify this was intentional and that dependent services are updated.",
        )
    if ct == "added":
        return (
            "high",
            "A new Stripe webhook endpoint was added. "
            "Confirm the delivery URL is under your control "
            "and the event set is correctly scoped.",
        )

    # Modified
    if fp == "url":
        return (
            "critical",
            "The Stripe webhook delivery URL changed. "
            "Events will now be sent to the new URL — verify it is under your control.",
        )
    if fp == "status":
        if new_v in ("disabled", False, "false"):
            return (
                "high",
                "A Stripe webhook endpoint was disabled. "
                "Events are no longer being delivered.",
            )
        return (
            "medium",
            "A Stripe webhook endpoint was re-enabled.",
        )
    if fp == "enabled_events":
        return (
            "high",
            "The event types subscribed to by a Stripe webhook changed. "
            "Verify the new event set matches what your integration expects.",
        )
    if fp == "api_version":
        return (
            "medium",
            "The API version for a Stripe webhook endpoint changed. "
            "Ensure your handler is compatible with the new version.",
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
            "medium",
            "A new Stripe payment method configuration was added.",
        )
    if ct == "removed":
        return (
            "high",
            "A Stripe payment method configuration was removed. "
            "Check that payment flows depending on this configuration still work.",
        )

    # Modified
    if fp == "enabled_payment_methods":
        return (
            "high",
            "The set of enabled payment methods in a Stripe configuration changed. "
            "Verify that checkout flows still offer the expected payment options.",
        )
    if fp == "is_default":
        return (
            "high",
            "The default Stripe payment method configuration changed. "
            "This affects which payment methods are shown at checkout by default.",
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
                "Apple Pay was disabled for a Stripe payment method domain.",
            )
        return ("medium", "Apple Pay was enabled for a Stripe payment method domain.")
    if fp == "google_pay_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "Google Pay was disabled for a Stripe payment method domain.",
            )
        return ("medium", "Google Pay was enabled for a Stripe payment method domain.")
    if fp == "link_enabled":
        return (
            "medium",
            "Link by Stripe was toggled on a payment method domain.",
        )
    if fp == "enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "A Stripe payment method domain was disabled. "
                "Apple Pay and Google Pay will stop working on this domain.",
            )
        return ("medium", "A Stripe payment method domain was re-enabled.")
    if fp == "domain_name":
        return ("medium", "The domain name for a Stripe payment method domain changed.")

    return ("medium", "A Stripe payment method domain setting changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────

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

    return ("low", f"A Stripe configuration record changed ({record_type}).")
