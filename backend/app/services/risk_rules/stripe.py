"""Stripe risk classification rules — M35.

Entry point: ``classify_stripe_change(change)``

Risk levels
-----------
critical  — Webhook deleted, webhook URL downgraded to plain HTTP,
            critical billing/payment event dropped from a webhook's
            enabled_events, charges_enabled turned off, payouts_enabled
            turned off, Apple/Google Pay domain removed.
high      — Webhook URL changed over HTTPS, webhook added, webhook
            disabled, enabled_events otherwise changed, payment method
            domain disabled/domain_name changed, payment method
            enabled/disabled in a config, is_default unset, payout
            schedule interval changed, controller type changed.
medium    — Account settings changed (capabilities, currency, support
            contact, business name), PM domain status changed,
            is_default set to True, payment method re-enabled,
            API version changed.
low       — Protection-strengthening changes (charges/payouts re-enabled,
            webhook re-enabled), cosmetic changes (branding, display name,
            descriptions), routine additions (PM config added).

Directionality
--------------
Every classification distinguishes:
  * new_value → False / "disabled" / removed  — weakening or loss of capability
  * new_value → True  / "enabled"  / added    — strengthening or new capability
Unknown / unavailable data never escalates to critical.

Secret safety
-------------
Risk reasons NEVER include:
  - Stripe secret keys (sk_live_…, sk_test_…, rk_*)
  - Webhook signing secrets (whsec_…)
  - Raw Authorization / Bearer headers
  - Full webhook URLs (could carry embedded query-string secrets)
"""

from __future__ import annotations

from app.models.change import Change


# ── Critical webhook events ────────────────────────────────────────────────────
# Events whose removal from a webhook's enabled_events list materially
# breaks revenue automation (checkout fulfilment, subscription lifecycle,
# invoice reconciliation, charge / refund handling). Used by
# `_classify_webhook_endpoint_change` to escalate enabled_events drops.
_CRITICAL_STRIPE_EVENTS: frozenset[str] = frozenset({
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "checkout.session.async_payment_failed",
    "invoice.payment_succeeded",
    "invoice.payment_failed",
    "invoice.paid",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "payment_intent.succeeded",
    "payment_intent.payment_failed",
    "charge.succeeded",
    "charge.failed",
    "charge.refunded",
    "charge.dispute.created",
})


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
        # Escalate to critical when the new URL is plain HTTP — Stripe API
        # normally enforces HTTPS, but if the connector ever surfaces a
        # non-HTTPS URL, event payloads (which carry customer + payment
        # data) would be transmitted in cleartext.
        new_url = str(new_v or "").lower()
        if new_url.startswith("http://"):
            return (
                "critical",
                "A Stripe webhook endpoint URL was changed to plain HTTP "
                "(not HTTPS). Event payloads — which include customer and "
                "payment metadata — may now be transmitted unencrypted. "
                "Restore an HTTPS endpoint immediately.",
            )
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
        # Escalate to critical if a critical billing/payment/subscription
        # event was dropped from the subscribed set — downstream
        # fulfilment, invoice reconciliation, or subscription lifecycle
        # automation may break.
        prev_v = _get(change, "prev_value")
        prev_set = set(prev_v) if isinstance(prev_v, (list, tuple, set)) else set()
        new_set  = set(new_v)  if isinstance(new_v,  (list, tuple, set)) else set()
        dropped_critical = (prev_set - new_set) & _CRITICAL_STRIPE_EVENTS
        if dropped_critical:
            # We mention how many critical events were dropped, but not
            # the event names verbatim if the list is very long — typical
            # Stripe webhooks subscribe to ≤ 30 events, so the names are
            # always safe to surface and informative for triage.
            names = ", ".join(sorted(dropped_critical))
            return (
                "critical",
                f"A Stripe webhook is no longer subscribed to critical "
                f"billing/payment events: {names}. Checkout fulfilment, "
                "invoice reconciliation, or subscription lifecycle "
                "automation may break.",
            )
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

    # ── M59.10 Part 1 expansion ─────────────────────────────────────────────
    if record_type == "stripe_product":
        return _classify_product_change(change)
    if record_type == "stripe_price":
        return _classify_price_change(change)
    if record_type == "stripe_payment_link":
        return _classify_payment_link_change(change)
    if record_type == "stripe_checkout_configuration":
        return _classify_checkout_configuration_change(change)
    if record_type == "stripe_tax_settings":
        return _classify_tax_settings_change(change)

    return ("low", f"A Stripe configuration record changed ({record_type}).")


# ═════════════════════════════════════════════════════════════════════════════
# M59.10 Part 1 — Stripe catalog / checkout / tax classifiers
# ═════════════════════════════════════════════════════════════════════════════
#
# Wording policy
# --------------
# Every reason uses hedged language: "may disrupt checkout / revenue
# operations", "could affect billing".  We never claim "payments are broken"
# or "revenue is lost" — those phrases imply outage we cannot prove from
# a configuration delta alone.
#
# Defensive metadata
# ------------------
# All five classifiers `isinstance`-guard ``provider_metadata`` exactly like
# the existing Stripe classifiers.  None of the new classifiers ever
# interpolate ``new_value`` or ``prev_value`` into a reason without going
# through a safe-shape helper — Stripe URL fields (success_url, cancel_url,
# redirect URLs) carry query-string tokens that the connector reduces to
# scheme+host before persistence.


import re as _re_stripe_part1

# Stripe URL shape allow-list — only ``https?://host[:port]`` form.  The
# connector strips paths/query strings before storage; this regex is a
# defence-in-depth check before interpolating into a reason.
_STRIPE_URL_ORIGIN_RE = _re_stripe_part1.compile(
    r"^https?://[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+"
    r"(:[0-9]{1,5})?$"
)


def _safe_url_origin(value: object) -> str:
    """Return *value* when it matches a clean URL origin (scheme+host[:port]),
    else 'the configured URL'.  Used to redact destination strings before
    they appear in risk reasons.
    """
    s = str(value or "")
    if not s or len(s) > 300:
        return "the configured URL"
    return s if _STRIPE_URL_ORIGIN_RE.match(s) else "the configured URL"


def _stripe_meta(change: Change) -> dict:
    raw = _get(change, "provider_metadata")
    return raw if isinstance(raw, dict) else {}


def _is_production_payment_link(pm: dict) -> bool:
    """Hint: a Payment Link is production if ``livemode`` is True or the
    record name looks production-y.  Conservative: defaults to True if
    livemode is missing (the safer assumption is production)."""
    if "livemode" in pm:
        return bool(pm.get("livemode"))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# A. stripe_product
# ─────────────────────────────────────────────────────────────────────────────

def _classify_product_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    pid = str(pm.get("record_id") or "unknown")
    is_live = bool(pm.get("livemode", True))

    if ct == "removed":
        sev = "high" if is_live else "medium"
        return (
            sev,
            f"Stripe product {pid} was removed/archived.  Checkout flows that "
            "referenced this product may stop functioning — verify the change "
            "is intentional.",
        )

    if ct == "added":
        return (
            "low",
            f"A new Stripe product {pid} was created.",
        )

    if fp == "active":
        if pv is True and nv is False:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe product {pid} was deactivated.  Checkout flows "
                "referencing this product may stop functioning until it is "
                "reactivated or replaced.",
            )
        if nv is True:
            return (
                "low",
                f"Stripe product {pid} was reactivated.",
            )

    if fp == "default_price":
        return (
            "medium",
            f"Stripe product {pid} default_price was changed.  Checkout flows "
            "that rely on the default may begin charging the new price — "
            "verify the change is intentional.",
        )

    if fp == "metadata_key_count":
        return (
            "medium",
            f"Stripe product {pid} metadata key count changed.  Verify any "
            "downstream consumers of product metadata still operate as "
            "expected.",
        )

    if fp in ("name", "description_present"):
        return (
            "low",
            f"Stripe product {pid} cosmetic field '{fp}' changed.",
        )

    return (
        "low",
        f"Stripe product {pid} configuration changed ({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# B. stripe_price
# ─────────────────────────────────────────────────────────────────────────────

# Tier-1 fields whose change implies a NEW price object replaced the old one.
# Stripe prices are largely immutable; we phrase the reason accordingly.
_PRICE_IMMUTABLE_FIELDS: frozenset[str] = frozenset({
    "unit_amount", "currency", "recurring_interval",
    "recurring_interval_count", "billing_scheme", "type",
})


def _classify_price_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    pid = str(pm.get("record_id") or "unknown")
    is_active = bool(pm.get("active", True))
    is_live = bool(pm.get("livemode", True))

    if ct == "removed":
        sev = "high" if (is_active and is_live) else "medium"
        return (
            sev,
            f"Stripe price record {pid} was deactivated / removed.  Checkout "
            "flows that referenced this price may stop functioning until "
            "they switch to a replacement price.",
        )

    if ct == "added":
        return (
            "low",
            f"A new Stripe price record {pid} was created.",
        )

    if fp == "active":
        if pv is True and nv is False:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe price record {pid} was deactivated.  Existing "
                "subscriptions are unaffected, but new checkouts referencing "
                "this price may fail.",
            )
        if nv is True:
            return (
                "low",
                f"Stripe price record {pid} was reactivated.",
            )

    if fp in _PRICE_IMMUTABLE_FIELDS:
        # Stripe prices are immutable for amount/currency/interval — a delta
        # means a NEW price replaced the prior one (or the snapshot was
        # cross-mapped).  Phrase carefully.
        sev = ("critical" if (is_live and is_active and fp == "unit_amount")
               else "high" if (is_live and is_active)
               else "medium")
        return (
            sev,
            f"Stripe price record {pid} field '{fp}' changed.  Stripe prices "
            "are immutable in this dimension, so this most likely indicates "
            "a NEW price record replaced the previous one.  Verify checkout "
            "flows reference the intended price — billing may be affected.",
        )

    if fp == "tax_behavior":
        return (
            "medium",
            f"Stripe price record {pid} tax_behavior changed.  Verify that "
            "the new tax behaviour is intended for the configured customers.",
        )

    if fp == "recurring_trial_period_days":
        return (
            "medium",
            f"Stripe price record {pid} trial period changed.  Customers "
            "subscribing to this price may experience a different trial "
            "than before.",
        )

    if fp == "lookup_key":
        return (
            "medium",
            f"Stripe price record {pid} lookup_key changed.  Application code "
            "that selects this price by lookup_key may now resolve to a "
            "different price — verify the integration still works.",
        )

    return (
        "low",
        f"Stripe price record {pid} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# C. stripe_payment_link
# ─────────────────────────────────────────────────────────────────────────────

def _classify_payment_link_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    plid = str(pm.get("record_id") or "unknown")
    is_live = _is_production_payment_link(pm)

    if ct == "removed":
        sev = "high" if is_live else "medium"
        return (
            sev,
            f"Stripe payment link {plid} was removed.  Any external link to "
            "this URL will stop accepting payments — verify the change is "
            "intentional.",
        )

    if ct == "added":
        return (
            "medium",
            f"A new Stripe payment link {plid} was created.  Verify the "
            "configured price, URLs, and payment method types match policy.",
        )

    if fp == "active":
        if pv is True and nv is False:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe payment link {plid} was disabled.  External links "
                "to this URL may stop accepting payments — verify the change "
                "is intentional.",
            )
        if nv is True:
            return (
                "low",
                f"Stripe payment link {plid} was re-enabled.",
            )

    if fp in ("line_item_price_ids", "line_item_count"):
        sev = "high" if is_live else "medium"
        return (
            sev,
            f"Stripe payment link {plid} line items changed.  The price or "
            "product the link sells may now be different — verify against "
            "your team's catalog policy.",
        )

    if fp in ("success_url_origin", "after_completion_redirect_origin"):
        safe_new = _safe_url_origin(nv)
        # Did the destination shift to a different (registrable) origin?
        prev_origin = str(pv or "")
        new_origin = str(nv or "")
        # The two are stored as scheme+host only by the connector, so a
        # direct comparison is meaningful.
        if prev_origin and new_origin and prev_origin != new_origin:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe payment link {plid} redirect destination changed to "
                f"{safe_new}.  Confirm the new destination is owned by your "
                "team — an unintended redirect may route customers off-site "
                "after checkout.",
            )
        return (
            "medium",
            f"Stripe payment link {plid} redirect field '{fp}' changed.",
        )

    if fp in ("allow_promotion_codes", "automatic_tax_enabled",
              "subscription_data_trial_period_days"):
        return (
            "medium",
            f"Stripe payment link {plid} field '{fp}' changed.  Verify "
            "discount, tax, and trial behaviour match policy.",
        )

    if fp == "application_fee_amount" or fp == "application_fee_percent":
        return (
            "medium",
            f"Stripe payment link {plid} application fee changed.  Verify "
            "platform revenue share against current policy.",
        )

    if fp == "transfer_destination_present":
        if pv is True and nv is False:
            return (
                "high",
                f"Stripe payment link {plid} no longer has a transfer "
                "destination configured.  Verify any expected Connect "
                "transfers will still occur.",
            )

    return (
        "low",
        f"Stripe payment link {plid} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# D. stripe_checkout_configuration
# ─────────────────────────────────────────────────────────────────────────────

def _classify_checkout_configuration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    cid = str(pm.get("record_id") or "checkout-defaults")
    is_live = bool(pm.get("livemode", True))

    if fp == "allowed_payment_method_types_count":
        try:
            prev_n = int(pv or 0)
            new_n = int(nv or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n < prev_n:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe checkout configuration {cid} allowed payment-method "
                f"count was reduced from {prev_n} to {new_n}.  Customers may "
                "be unable to pay with previously-accepted methods.",
            )
        return (
            "low",
            f"Stripe checkout configuration {cid} now allows {new_n} "
            "payment method types.",
        )

    if fp == "default_mode":
        sev = "high" if is_live else "medium"
        return (
            sev,
            f"Stripe checkout configuration {cid} default mode changed from "
            f"'{pv}' to '{nv}'.  Verify checkout flows still match the "
            "expected payment / subscription / setup intent.",
        )

    if fp in ("default_customer_creation", "billing_address_collection",
              "phone_collection_enabled", "consent_collection_terms_of_service",
              "consent_collection_promotions", "invoice_creation_enabled"):
        return (
            "medium",
            f"Stripe checkout configuration {cid} setting '{fp}' changed.  "
            "Verify customer-data collection behaviour matches policy.",
        )

    return (
        "low",
        f"Stripe checkout configuration {cid} field '{fp or 'unknown'}' "
        "changed.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# E. stripe_tax_settings
# ─────────────────────────────────────────────────────────────────────────────

def _classify_tax_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    tid = str(pm.get("record_id") or "tax-settings")
    is_live = bool(pm.get("livemode", True))

    if fp == "automatic_tax_status":
        new_s = str(nv or "").lower()
        if new_s in ("inactive", "disabled"):
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe automatic tax was disabled for {tid}.  Customers may "
                "be charged without applicable tax — this could affect "
                "compliance and revenue reporting.",
            )
        if new_s == "active":
            return (
                "low",
                f"Stripe automatic tax was enabled for {tid}.",
            )

    if fp == "tax_registrations_active_count":
        try:
            prev_n = int(pv or 0)
            new_n = int(nv or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n < prev_n:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe tax registrations active count was reduced from "
                f"{prev_n} to {new_n}.  Sales into the de-registered "
                "jurisdictions may no longer collect tax correctly.",
            )
        return (
            "low",
            f"Stripe tax registrations active count increased from "
            f"{prev_n} to {new_n}.",
        )

    if fp == "default_tax_behavior":
        return (
            "medium",
            f"Stripe default tax_behavior changed from '{pv}' to '{nv}'.  "
            "Verify product/price configuration matches the new behaviour.",
        )

    if fp == "default_tax_code":
        return (
            "medium",
            f"Stripe default tax_code changed.  Verify the new category "
            "matches the goods/services being sold.",
        )

    if fp == "head_office_address_present":
        if pv is True and nv is False:
            return (
                "high",
                f"Stripe tax settings {tid} no longer have a head-office "
                "address configured.  Tax calculation may be incomplete "
                "until the address is restored.",
            )

    return (
        "low",
        f"Stripe tax settings {tid} field '{fp or 'unknown'}' changed.",
    )
