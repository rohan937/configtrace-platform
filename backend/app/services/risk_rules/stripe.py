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

    # Modified: field_path/prev_value/new_value are the SCALAR field values
    # produced by real compute_diff() (one Change per changed field) — never
    # whole prev/new record dicts. A previous version of this function read
    # prev_value/new_value as dicts (e.g. old.get("active")), which only
    # matched hand-built test Changes that passed whole dicts; every real
    # compute_diff()-produced Change has scalar prev_value/new_value, so that
    # version's `isinstance(..., dict)` guard reset `old`/`new` to `{}` on
    # every real field change, silently collapsing the entire severity chain
    # below to the final generic "low" fallback. Fixed to dispatch on
    # field_path like every other Stripe classifier in this module.
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")

    # active disabled
    if fp == "active" and nv is False:
        return (
            "medium",
            "The Stripe customer billing portal configuration was deactivated. "
            "Customers may be unable to access self-service billing.",
        )

    # payment_method_update_enabled disabled
    if fp == "payment_method_update_enabled" and nv is False:
        return (
            "medium",
            "Payment method updates were disabled in the Stripe billing portal. "
            "Customers may no longer be able to update their payment methods.",
        )

    # subscription_cancel_enabled changed
    if fp == "subscription_cancel_enabled":
        return (
            "medium",
            f"Subscription self-cancellation in the billing portal was "
            f"{'enabled' if nv else 'disabled'}. "
            "Confirm this change is intentional.",
        )

    # customer_update_allowed_updates changed
    if fp == "customer_update_allowed_updates":
        return (
            "medium",
            "The set of customer-editable fields in the billing portal changed. "
            "Review which account details customers may now update.",
        )

    # subscription_update_allowed_updates changed
    if fp == "subscription_update_allowed_updates":
        return (
            "medium",
            "Subscription update options in the billing portal changed. "
            "Verify the permitted plan changes are intentional.",
        )

    # login_page_enabled disabled
    if fp == "login_page_enabled" and nv is False:
        return (
            "medium",
            "The billing portal login page was disabled. "
            "Customers may no longer be able to sign in to the portal directly.",
        )

    # subscription_cancel_mode changed
    if fp == "subscription_cancel_mode":
        return (
            "low",
            f"Subscription cancellation timing changed to "
            f"\"{nv}\". "
            "Customers will experience different cancellation behaviour.",
        )

    # subscription_pause_enabled changed
    if fp == "subscription_pause_enabled":
        return (
            "low",
            "Subscription pause capability in the billing portal changed.",
        )

    # invoice_history_enabled changed
    if fp == "invoice_history_enabled":
        return (
            "low",
            "Invoice history visibility in the billing portal changed.",
        )

    # is_default changed
    if fp == "is_default":
        return (
            "low",
            "The default billing portal configuration assignment changed.",
        )

    # return_url_domain changed — not in the original priority chain but a
    # real tracked field; treat as a low-severity informational change.
    if fp == "return_url_domain":
        return (
            "low",
            "The billing portal return URL domain changed.",
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

    # ── M59.11 Part 2 expansion ─────────────────────────────────────────────
    if record_type == "stripe_radar_rule":
        return _classify_radar_rule_change(change)
    if record_type == "stripe_restricted_api_key":
        return _classify_restricted_api_key_change(change)
    if record_type == "stripe_subscription_invoice_settings":
        return _classify_subscription_invoice_settings_change(change)
    if record_type == "stripe_dunning_settings":
        return _classify_dunning_settings_change(change)
    if record_type == "stripe_external_account":
        return _classify_external_account_change(change)
    if record_type == "stripe_coupon":
        return _classify_coupon_change(change)
    if record_type == "stripe_promotion_code":
        return _classify_promotion_code_change(change)

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


# ═════════════════════════════════════════════════════════════════════════════
# M59.11 Part 2 — fraud / keys / billing / payouts / coupons classifiers
# ═════════════════════════════════════════════════════════════════════════════
#
# Wording policy (shared by every classifier below)
# -------------------------------------------------
# * Hedged language: "may weaken", "could affect", "may allow", "verify".
# * Never overclaim outage: not "payments are down", not "fraud exposure
#   confirmed".  We classify CONFIGURATION DELTAS — actual fraud / payment
#   outcomes come from Stripe events, which we do not consume here.
#
# Defensive metadata
# ------------------
# All seven classifiers reuse the existing ``_stripe_meta`` helper (which
# `isinstance`-guards ``provider_metadata``), so a non-dict pm degrades
# safely.
#
# Secret safety
# -------------
# No classifier interpolates ``new_value`` for fields that can carry
# operator-supplied credential-shaped strings.  Radar rule expressions are
# referenced only by their pre-computed hash; restricted API key VALUES are
# never read or stored; bank account / routing numbers never enter
# ``provider_metadata`` (only ``last4`` + ``routing_fingerprint``).


# ─────────────────────────────────────────────────────────────────────────────
# A. stripe_radar_rule
# ─────────────────────────────────────────────────────────────────────────────

_RADAR_PROTECTIVE_ACTIONS: frozenset[str] = frozenset(
    {"block", "request_three_d_secure", "review"}
)
_RADAR_PERMISSIVE_ACTIONS: frozenset[str] = frozenset(
    {"allow"}
)


def _classify_radar_rule_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    rid = str(pm.get("record_id") or "unknown")
    name = str(pm.get("name") or rid)
    is_live = bool(pm.get("livemode", True))
    prev_action = str(pm.get("action") or "").lower()

    if ct == "removed":
        sev = "high" if is_live and prev_action in _RADAR_PROTECTIVE_ACTIONS else "medium"
        return (
            sev,
            f"Stripe Radar rule '{name}' was deleted.  Whatever fraud "
            "pattern this rule covered is no longer evaluated — verify the "
            "removal was intentional.",
        )

    if ct == "added":
        return (
            "medium",
            f"A new Stripe Radar rule '{name}' was created.  Review the "
            "rule to ensure it matches the intended traffic.",
        )

    if fp == "enabled":
        if pv is True and nv is False:
            sev = "high" if (is_live and prev_action in _RADAR_PROTECTIVE_ACTIONS) else "medium"
            return (
                sev,
                f"Stripe Radar rule '{name}' was disabled.  The fraud "
                "pattern it covered is no longer evaluated.",
            )
        if nv is True:
            return (
                "low",
                f"Stripe Radar rule '{name}' was re-enabled.",
            )

    if fp == "action":
        prev_s = str(pv or "").lower()
        new_s = str(nv or "").lower()
        if prev_s == "block" and new_s in _RADAR_PERMISSIVE_ACTIONS:
            sev = "critical" if is_live else "high"
            return (
                sev,
                f"Stripe Radar rule '{name}' action was lowered from "
                f"'block' to '{new_s}'.  Transactions previously blocked may "
                "now go through — this may weaken fraud filtering.",
            )
        if prev_s in _RADAR_PROTECTIVE_ACTIONS and new_s in _RADAR_PERMISSIVE_ACTIONS:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe Radar rule '{name}' action was lowered from "
                f"'{prev_s}' to '{new_s}'.  Verify the change is intentional.",
            )
        if prev_s in _RADAR_PERMISSIVE_ACTIONS and new_s in _RADAR_PROTECTIVE_ACTIONS:
            return (
                "low",
                f"Stripe Radar rule '{name}' action was strengthened from "
                f"'{prev_s}' to '{new_s}'.",
            )
        return (
            "medium",
            f"Stripe Radar rule '{name}' action changed from '{prev_s}' to "
            f"'{new_s}'.",
        )

    if fp == "expression_hash":
        return (
            "medium",
            f"Stripe Radar rule '{name}' expression was modified.  Review "
            "the rule in the Stripe Dashboard to confirm the new matching "
            "logic is intentional.",
        )

    return (
        "low",
        f"Stripe Radar rule '{name}' configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# B. stripe_restricted_api_key
# ─────────────────────────────────────────────────────────────────────────────

def _classify_restricted_api_key_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    kid = str(pm.get("record_id") or "unknown")
    name = str(pm.get("name") or kid)
    prefix = str(pm.get("key_id_prefix") or "").lower()
    # Derive is_live from the key-id prefix first (rk_live vs rk_test).  Only
    # fall back to the livemode flag when the prefix doesn't disambiguate.
    if prefix.endswith("live"):
        is_live = True
    elif prefix.endswith("test"):
        is_live = False
    else:
        is_live = bool(pm.get("livemode", True))
    has_write = bool(pm.get("has_write_permission", False))
    has_secret = bool(pm.get("has_secret_permission", False))

    if ct == "added":
        if has_secret and is_live:
            return (
                "critical",
                f"A new Stripe restricted API key '{name}' was created with "
                "access to Stripe-secret-management endpoints in livemode. "
                "Verify the key is owned by your team and stored securely.",
            )
        if has_write and is_live:
            return (
                "high",
                f"A new Stripe restricted API key '{name}' was created with "
                "write permission in livemode.  Verify the key is owned by "
                "your team.",
            )
        return (
            "medium",
            f"A new Stripe restricted API key '{name}' was created.",
        )

    if ct == "removed":
        sev = "medium" if is_live else "low"
        return (
            sev,
            f"Stripe restricted API key '{name}' was deleted.  Application "
            "code that referenced this key will lose access until it is "
            "rotated.",
        )

    if fp == "has_write_permission":
        if pv is False and nv is True:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe restricted API key '{name}' gained write permission. "
                "Verify the grant was approved.",
            )
        return (
            "low",
            f"Stripe restricted API key '{name}' write permission was "
            "removed.",
        )

    if fp == "has_secret_permission":
        if pv is False and nv is True:
            sev = "critical" if is_live else "high"
            return (
                sev,
                f"Stripe restricted API key '{name}' gained access to Stripe-"
                "secret-management endpoints.  Verify the grant was "
                "approved and reduce permissions if unnecessary.",
            )
        return (
            "low",
            f"Stripe restricted API key '{name}' lost access to Stripe-"
            "secret-management endpoints.",
        )

    if fp == "permissions_count":
        try:
            prev_n = int(pv or 0)
            new_n = int(nv or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n > prev_n:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe restricted API key '{name}' permission scope was "
                f"broadened from {prev_n} to {new_n} permissions.  Verify "
                "the grant was approved.",
            )
        return (
            "low",
            f"Stripe restricted API key '{name}' permission scope narrowed "
            f"from {prev_n} to {new_n}.",
        )

    if fp == "name":
        return (
            "low",
            f"Stripe restricted API key '{kid}' display name changed.",
        )

    return (
        "low",
        f"Stripe restricted API key '{name}' metadata changed "
        f"({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# C. stripe_subscription_invoice_settings
# ─────────────────────────────────────────────────────────────────────────────

def _classify_subscription_invoice_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    sid = str(pm.get("record_id") or "subscription-invoice-defaults")
    is_live = bool(pm.get("livemode", True))

    if fp == "default_collection_method":
        sev = "high" if is_live else "medium"
        return (
            sev,
            f"Stripe default collection_method changed from '{pv}' to '{nv}' "
            f"({sid}).  New subscriptions may now bill via a different "
            "mechanism — verify integration code and customer expectations.",
        )

    if fp == "default_proration_behavior":
        return (
            "medium",
            f"Stripe default proration_behavior changed from '{pv}' to "
            f"'{nv}'.  Subscription upgrades/downgrades may produce "
            "different invoice line items.",
        )

    if fp == "auto_advance_default":
        if pv is True and nv is False:
            sev = "high" if is_live else "medium"
            return (
                sev,
                "Stripe default auto_advance was disabled.  New invoices "
                "will no longer auto-finalize and may sit as drafts.",
            )
        return (
            "low",
            "Stripe default auto_advance was enabled.",
        )

    if fp == "default_days_until_due":
        return (
            "medium",
            f"Stripe default days_until_due changed from '{pv}' to '{nv}'.  "
            "Payment terms on send-invoice subscriptions are affected.",
        )

    if fp == "cancel_at_period_end_default":
        if pv is False and nv is True:
            return (
                "high",
                "Stripe default cancel_at_period_end was enabled — new "
                "subscriptions may auto-cancel at the end of their period.  "
                "Verify the change is intentional.",
            )
        return (
            "low",
            "Stripe default cancel_at_period_end was disabled.",
        )

    if fp == "customer_balance_enabled":
        return (
            "medium",
            f"Stripe customer_balance setting changed to {nv}.  Verify the "
            "billing flow for customers with non-zero balance.",
        )

    return (
        "low",
        f"Stripe subscription/invoice default '{fp or 'unknown'}' changed.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# D. stripe_dunning_settings
# ─────────────────────────────────────────────────────────────────────────────

def _classify_dunning_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    sid = str(pm.get("record_id") or "dunning-defaults")
    is_live = bool(pm.get("livemode", True))

    if fp == "retry_schedule_enabled":
        if pv is True and nv is False:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe payment retry schedule was disabled for {sid}.  "
                "Failed payments will no longer be retried automatically — "
                "this may reduce successful recovery and increase churn.",
            )
        return (
            "low",
            f"Stripe payment retry schedule was enabled for {sid}.",
        )

    if fp == "smart_retries_enabled":
        if pv is True and nv is False:
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe smart retries was disabled for {sid}.  Failed "
                "payments will fall back to the fixed retry schedule — this "
                "may reduce successful recovery.",
            )
        return (
            "low",
            f"Stripe smart retries was enabled for {sid}.",
        )

    if fp == "past_due_action":
        new_s = str(nv or "").lower()
        if new_s == "cancel":
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe past-due action changed to 'cancel'.  Subscriptions "
                "with failed payments may now be cancelled automatically — "
                "verify this matches your retention policy.",
            )
        if new_s == "leave_as_is":
            return (
                "medium",
                f"Stripe past-due action changed to 'leave_as_is'.  Failed "
                "subscriptions will continue indefinitely without "
                "auto-cancellation.",
            )
        return (
            "medium",
            f"Stripe past-due action changed from '{pv}' to '{nv}'.",
        )

    if fp == "retry_schedule_max_attempts":
        try:
            prev_n = int(pv or 0)
            new_n = int(nv or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n < prev_n:
            return (
                "medium",
                f"Stripe retry max_attempts lowered from {prev_n} to {new_n}. "
                "Fewer retries may reduce successful recovery.",
            )
        return (
            "low",
            f"Stripe retry max_attempts raised from {prev_n} to {new_n}.",
        )

    if fp == "email_failed_payment_enabled":
        if pv is True and nv is False:
            return (
                "medium",
                f"Stripe payment-failure emails disabled for {sid}.  "
                "Customers may not be notified of failed renewals.",
            )
        return (
            "low",
            f"Stripe payment-failure emails enabled for {sid}.",
        )

    return (
        "low",
        f"Stripe dunning setting '{fp or 'unknown'}' changed.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# E. stripe_external_account
# ─────────────────────────────────────────────────────────────────────────────

def _classify_external_account_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    eid = str(pm.get("record_id") or "unknown")
    acct_type = str(pm.get("account_type") or "external account")
    is_live = bool(pm.get("livemode", True))
    is_default = bool(pm.get("default_for_currency", False))

    if ct == "added":
        sev = "high" if (is_default and is_live) else "medium"
        return (
            sev,
            f"A new Stripe {acct_type} {eid} was attached to the account.  "
            "Verify the destination is owned by your team — payouts may now "
            "route to this account.",
        )

    if ct == "removed":
        sev = "high" if (is_default and is_live) else "medium"
        return (
            sev,
            f"Stripe {acct_type} {eid} was removed from the account.  If "
            "this was the default payout destination, payouts may fail "
            "until a replacement is configured.",
        )

    if fp == "routing_fingerprint":
        # The fingerprint is hash-derived; a change means the underlying
        # routing number was changed even though we never saw the raw value.
        sev = "critical" if (is_default and is_live) else "high"
        return (
            sev,
            f"Stripe {acct_type} {eid} routing fingerprint changed — the "
            "underlying bank routing target was modified.  Verify the "
            "change was authorised and that the new bank account is owned "
            "by your team.",
        )

    if fp == "last4":
        sev = "high" if (is_default and is_live) else "medium"
        return (
            sev,
            f"Stripe {acct_type} {eid} last4 changed.  Verify the new "
            "destination is owned by your team.",
        )

    if fp == "default_for_currency":
        if pv is False and nv is True:
            return (
                "high",
                f"Stripe {acct_type} {eid} was promoted to the default "
                "payout destination.  Verify the change is intentional.",
            )
        return (
            "low",
            f"Stripe {acct_type} {eid} is no longer the default payout "
            "destination.",
        )

    if fp == "status":
        new_s = str(nv or "").lower()
        if new_s == "errored":
            sev = "high" if (is_default and is_live) else "medium"
            return (
                sev,
                f"Stripe {acct_type} {eid} status changed to 'errored'.  "
                "Payouts to this destination may fail until the issue is "
                "resolved.",
            )
        if new_s in ("verified", "validated"):
            return (
                "low",
                f"Stripe {acct_type} {eid} was verified.",
            )

    return (
        "low",
        f"Stripe {acct_type} {eid} metadata changed "
        f"({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# F. stripe_coupon
# ─────────────────────────────────────────────────────────────────────────────

# Discount magnitude thresholds for severity escalation.  We treat
# 50%+ off forever / 50%+ amount_off as high-value.
_COUPON_HIGH_VALUE_PERCENT: float = 50.0
_COUPON_HIGH_VALUE_AMOUNT_USD_CENTS: int = 5000  # $50


def _classify_coupon_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    cid = str(pm.get("record_id") or "unknown")
    name = str(pm.get("name") or cid)
    duration = str(pm.get("duration") or "").lower()
    is_live = bool(pm.get("livemode", True))

    # Pre-compute discount magnitude flags.
    try:
        percent_off = float(pm.get("percent_off") or 0)
    except (TypeError, ValueError):
        percent_off = 0.0
    try:
        amount_off = int(pm.get("amount_off") or 0)
    except (TypeError, ValueError):
        amount_off = 0
    is_high_value = (
        percent_off >= _COUPON_HIGH_VALUE_PERCENT
        or amount_off >= _COUPON_HIGH_VALUE_AMOUNT_USD_CENTS
        or duration == "forever"
    )

    if ct == "added":
        sev = "high" if (is_high_value and is_live) else "medium"
        return (
            sev,
            f"A new Stripe coupon '{name}' was created (duration={duration}, "
            f"percent_off={percent_off or '-'}, amount_off={amount_off or '-'}). "
            "Verify the discount magnitude and applicability are "
            "intentional.",
        )

    if ct == "removed":
        return (
            "medium",
            f"Stripe coupon '{name}' was deleted.  Active redemptions "
            "still apply per Stripe's lifecycle, but no new customers can "
            "redeem this coupon.",
        )

    if fp == "valid":
        if pv is True and nv is False:
            return (
                "low",
                f"Stripe coupon '{name}' is no longer valid (expired or "
                "redemption limit reached).",
            )
        if nv is True:
            sev = "high" if (is_high_value and is_live) else "medium"
            return (
                sev,
                f"Stripe coupon '{name}' became valid for redemption again. "
                "Verify the change is intentional given the discount size.",
            )

    if fp in ("percent_off", "amount_off"):
        sev = "medium"
        return (
            sev,
            f"Stripe coupon '{name}' discount field '{fp}' changed.  Verify "
            "the new discount magnitude is intentional.",
        )

    if fp == "duration":
        new_s = str(nv or "").lower()
        if new_s == "forever":
            sev = "high" if is_live else "medium"
            return (
                sev,
                f"Stripe coupon '{name}' duration changed to 'forever'.  "
                "Customers who redeem will receive the discount on every "
                "billing cycle — verify the change is intentional.",
            )
        return (
            "medium",
            f"Stripe coupon '{name}' duration changed from '{pv}' to '{nv}'.",
        )

    if fp == "max_redemptions":
        return (
            "medium",
            f"Stripe coupon '{name}' max_redemptions changed from '{pv}' to "
            f"'{nv}'.",
        )

    if fp == "applies_to_count":
        return (
            "medium",
            f"Stripe coupon '{name}' product applicability changed.  "
            "Different products may now be discounted.",
        )

    return (
        "low",
        f"Stripe coupon '{name}' metadata changed "
        f"({fp or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# G. stripe_promotion_code
# ─────────────────────────────────────────────────────────────────────────────

def _classify_promotion_code_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")
    pm = _stripe_meta(change)
    pid = str(pm.get("record_id") or "unknown")
    is_live = bool(pm.get("livemode", True))
    customer_restricted = bool(pm.get("customer_restricted", False))

    if ct == "added":
        sev = "medium" if (is_live and not customer_restricted) else "low"
        return (
            sev,
            f"A new Stripe promotion code {pid} was created.  Verify the "
            "associated coupon and redemption limits are intentional.",
        )

    if ct == "removed":
        return (
            "low",
            f"Stripe promotion code {pid} was deleted.",
        )

    if fp == "active":
        if pv is False and nv is True:
            sev = "medium" if (is_live and not customer_restricted) else "low"
            return (
                sev,
                f"Stripe promotion code {pid} was activated.  Verify the "
                "associated coupon is the intended one.",
            )
        if nv is False:
            return (
                "low",
                f"Stripe promotion code {pid} was deactivated.",
            )

    if fp == "max_redemptions":
        return (
            "medium",
            f"Stripe promotion code {pid} max_redemptions changed from "
            f"'{pv}' to '{nv}'.",
        )

    if fp == "expires_at":
        return (
            "low",
            f"Stripe promotion code {pid} expiry changed.",
        )

    if fp == "customer_restricted":
        if pv is True and nv is False:
            return (
                "medium",
                f"Stripe promotion code {pid} is no longer tied to a "
                "specific customer.  Broader audience may now redeem it — "
                "verify the change is intentional.",
            )
        return (
            "low",
            f"Stripe promotion code {pid} was restricted to a specific "
            "customer.",
        )

    return (
        "low",
        f"Stripe promotion code {pid} metadata changed "
        f"({fp or 'unknown field'}).",
    )
