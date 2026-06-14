"""Stripe security / business-critical configuration rules — M60.4 / M73A.

Every rule fires only on explicit, reliable normalized fields produced by the
Stripe connector (app/connectors/stripe.py + stripe_schema.py). Evidence is
metadata-only: endpoint URLs, status strings, event-subscription counts,
configuration booleans, and Stripe object ids. No secret/restricted API key
values, webhook signing secrets, customer PII or emails, card/payment-method
data, invoices, charges, payment intents, bank-account details, tax IDs, raw
event payloads, raw API responses, OAuth tokens, or authorization headers are
ever read or stored.

CLAIM DISCIPLINE
----------------
These are configuration risks that *may affect payment/billing operations* or
*may increase webhook/payment configuration risk*. A finding is evidence for
review only. It never asserts payment fraud, that funds or card details were
exposed, that customer records were disclosed, that anyone gained access, that
access was unauthorized, or that a breach/compromise occurred.

Record types consumed
---------------------
- ``stripe_webhook_endpoint``       → plain-HTTP delivery / disabled endpoint /
                                       over-broad event subscription
- ``stripe_payment_link``           → active link with automatic tax off /
                                       promotion codes allowed
- ``stripe_billing_portal_config``  → self-serve cancellation / login page on
- ``stripe_account_settings``       → charges/payouts/onboarding not complete

Deferred Stripe rules (intentionally NOT implemented — see report)
------------------------------------------------------------------
* Insecure webhook URL as a separate ``stripe_webhook_insecure_url`` key: the
  existing ``stripe_webhook_http`` rule already fires on a plain-HTTP enabled
  endpoint, so a second key would double-flag the identical state. Not added.
* Restricted-/secret-key scope or live-mode rules: the connector deliberately
  does not (and cannot safely) enumerate other API keys' scopes, and webhook
  records carry no live/test mode field. Deferred — never invented.
* Standalone Tax-settings rule: tax posture is already reviewed per active
  payment link via ``stripe_payment_link_tax_disabled``; the account-singleton
  Stripe Tax settings surface is not fetched here. Deferred.
"""

from __future__ import annotations

from typing import Any

from app.connectors.stripe_schema import (
    STRIPE_ACCOUNT_SETTINGS,
    STRIPE_BILLING_PORTAL_CONFIG,
    STRIPE_PAYMENT_LINK,
    STRIPE_WEBHOOK_ENDPOINT,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# Existing (M60.4)
_RULE_WEBHOOK_HTTP = "stripe_webhook_http"
# M73A
_RULE_WEBHOOK_DISABLED = "stripe_webhook_disabled"
_RULE_WEBHOOK_BROAD_EVENTS = "stripe_webhook_broad_events"
_RULE_PAYMENT_LINK_TAX_DISABLED = "stripe_payment_link_tax_disabled"
_RULE_PAYMENT_LINK_PROMO_CODES = "stripe_payment_link_promo_codes_enabled"
_RULE_PORTAL_CANCEL_ENABLED = "stripe_portal_subscription_cancel_enabled"
_RULE_PORTAL_LOGIN_ENABLED = "stripe_portal_login_enabled"
_RULE_ACCOUNT_CAPABILITY_INCOMPLETE = "stripe_account_capability_incomplete"

# A webhook subscribed to this many or more event types is treated as
# over-broad (least-privilege review item). The wildcard "*" always counts.
_BROAD_EVENT_COUNT = 50


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == STRIPE_WEBHOOK_ENDPOINT:
        return _eval_webhook(record)
    if rtype == STRIPE_PAYMENT_LINK:
        return _eval_payment_link(record)
    if rtype == STRIPE_BILLING_PORTAL_CONFIG:
        return _eval_billing_portal(record)
    if rtype == STRIPE_ACCOUNT_SETTINGS:
        return _eval_account(record)
    return []


# ── Webhook endpoints ─────────────────────────────────────────────────────────


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    url = get_str(record, "url").strip()
    status = get_str(record, "status").lower()
    enabled = (not status) or status == "enabled"

    # A. Plain-HTTP delivery (existing M60.4 rule, unchanged) — only an enabled
    #    endpoint over plain HTTP is an exposure.
    if enabled and url.lower().startswith("http://"):
        out.append(
            FindingCandidate(
                provider="stripe",
                rule_key=_RULE_WEBHOOK_HTTP,
                finding_key=make_finding_key(_RULE_WEBHOOK_HTTP, record_id),
                severity="critical",
                title="Stripe webhook uses plain HTTP",
                description=(
                    "A Stripe webhook endpoint delivers events over plain HTTP. "
                    "Event payloads and signature headers may be transmitted in "
                    "cleartext, allowing interception or tampering. This is "
                    "evidence for review and does not confirm compromise, "
                    "unauthorized access, or a breach."
                ),
                evidence={"rule": _RULE_WEBHOOK_HTTP, "url": url},
                remediation={
                    "summary": "Restore HTTPS on the webhook endpoint and verify ownership.",
                    "steps": [
                        "Update the endpoint URL to https:// in the Stripe dashboard.",
                        "Verify the endpoint is owned by your team.",
                        "Confirm signature verification still succeeds after the change.",
                    ],
                },
                record_id=record_id,
            )
        )

    # B. Disabled webhook endpoint — only an explicit "disabled" status fires.
    #    A disabled endpoint stops event delivery, which may affect billing /
    #    payment operations that rely on those events.
    if status == "disabled":
        out.append(
            FindingCandidate(
                provider="stripe",
                rule_key=_RULE_WEBHOOK_DISABLED,
                finding_key=make_finding_key(_RULE_WEBHOOK_DISABLED, record_id),
                severity="medium",
                title="Stripe webhook endpoint is disabled",
                description=(
                    "A Stripe webhook endpoint is disabled and is not receiving "
                    "events. Downstream automation that depends on these events "
                    "may miss payment or subscription state changes, which may "
                    "affect billing/payment operations. This is evidence for "
                    "review and does not confirm fraud, compromise, or "
                    "unauthorized access."
                ),
                evidence={"rule": _RULE_WEBHOOK_DISABLED, "status": "disabled"},
                remediation={
                    "summary": "Confirm whether this endpoint should be enabled.",
                    "steps": [
                        "Review whether downstream systems still rely on this endpoint.",
                        "Re-enable it if needed, or remove it if it is intentionally retired.",
                    ],
                },
                record_id=record_id,
            )
        )

    # C. Over-broad event subscription — wildcard "*" or a large event count.
    #    Only an enabled endpoint is evaluated.
    if enabled:
        events = record.get("enabled_events")
        events = events if isinstance(events, list) else []
        has_wildcard = "*" in events
        count = len(events)
        if has_wildcard or count >= _BROAD_EVENT_COUNT:
            out.append(
                FindingCandidate(
                    provider="stripe",
                    rule_key=_RULE_WEBHOOK_BROAD_EVENTS,
                    finding_key=make_finding_key(_RULE_WEBHOOK_BROAD_EVENTS, record_id),
                    severity="medium",
                    title="Stripe webhook subscribes to a very broad set of events",
                    description=(
                        "A Stripe webhook endpoint subscribes to "
                        + ("all event types (\"*\")" if has_wildcard else f"{count} event types")
                        + ". Receiving more events than the integration needs "
                        "widens the configuration surface and may increase "
                        "webhook configuration risk. This is evidence for review "
                        "and does not confirm compromise or unauthorized access."
                    ),
                    evidence={
                        "rule": _RULE_WEBHOOK_BROAD_EVENTS,
                        "enabled_events_count": count,
                        "subscribes_to_all_events": has_wildcard,
                    },
                    remediation={
                        "summary": "Scope the webhook to only the events the integration needs.",
                        "steps": [
                            "Review which event types the receiving system actually handles.",
                            "Replace the wildcard / broad list with the specific events required.",
                        ],
                    },
                    record_id=record_id,
                )
            )

    return out


# ── Payment links ─────────────────────────────────────────────────────────────


def _eval_payment_link(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    # Only active payment links are evaluated; an inactive link cannot be paid.
    if record.get("active") is not True:
        return out
    record_id = get_str(record, "record_id") or None

    # D. Active payment link with automatic tax disabled.
    if record.get("automatic_tax_enabled") is False:
        out.append(
            FindingCandidate(
                provider="stripe",
                rule_key=_RULE_PAYMENT_LINK_TAX_DISABLED,
                finding_key=make_finding_key(_RULE_PAYMENT_LINK_TAX_DISABLED, record_id),
                severity="medium",
                title="Stripe payment link has automatic tax disabled",
                description=(
                    "An active Stripe payment link does not have automatic tax "
                    "enabled. Depending on where customers are, tax may not be "
                    "collected correctly, which may affect billing/payment "
                    "operations and tax compliance. This is evidence for review "
                    "and does not confirm fraud, compromise, or unauthorized "
                    "access."
                ),
                evidence={
                    "rule": _RULE_PAYMENT_LINK_TAX_DISABLED,
                    "active": True,
                    "automatic_tax_enabled": False,
                },
                remediation={
                    "summary": "Confirm whether automatic tax should be enabled for this link.",
                    "steps": [
                        "Review the payment link's tax requirements for your markets.",
                        "Enable automatic tax on the link if collection is expected.",
                    ],
                },
                record_id=record_id,
            )
        )

    # E. Active payment link that allows promotion codes.
    if record.get("allow_promotion_codes") is True:
        out.append(
            FindingCandidate(
                provider="stripe",
                rule_key=_RULE_PAYMENT_LINK_PROMO_CODES,
                finding_key=make_finding_key(_RULE_PAYMENT_LINK_PROMO_CODES, record_id),
                severity="low",
                title="Stripe payment link allows promotion codes",
                description=(
                    "An active Stripe payment link allows customers to enter "
                    "promotion codes. If unintended, this may allow unexpected "
                    "discounting and may affect billing/payment operations. This "
                    "is evidence for review and does not confirm fraud, "
                    "compromise, or unauthorized access."
                ),
                evidence={
                    "rule": _RULE_PAYMENT_LINK_PROMO_CODES,
                    "active": True,
                    "allow_promotion_codes": True,
                },
                remediation={
                    "summary": "Confirm whether promotion codes should be accepted on this link.",
                    "steps": [
                        "Review whether this payment link should accept promotion codes.",
                        "Disable promotion codes on the link if it is not intended.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Customer (billing) portal configuration ───────────────────────────────────


def _eval_billing_portal(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    # Only an active portal configuration is reviewed.
    if record.get("active") is not True:
        return out
    record_id = get_str(record, "record_id") or None

    # F. Self-serve subscription cancellation enabled.
    if record.get("subscription_cancel_enabled") is True:
        out.append(
            FindingCandidate(
                provider="stripe",
                rule_key=_RULE_PORTAL_CANCEL_ENABLED,
                finding_key=make_finding_key(_RULE_PORTAL_CANCEL_ENABLED, record_id),
                severity="low",
                title="Stripe customer portal allows self-serve cancellation",
                description=(
                    "The active Stripe customer portal configuration lets "
                    "customers cancel their own subscriptions. If unintended, "
                    "this may affect billing/payment operations and revenue "
                    "retention. This is evidence for review and does not confirm "
                    "fraud, compromise, or unauthorized access."
                ),
                evidence={
                    "rule": _RULE_PORTAL_CANCEL_ENABLED,
                    "active": True,
                    "subscription_cancel_enabled": True,
                },
                remediation={
                    "summary": "Confirm whether self-serve cancellation is intended.",
                    "steps": [
                        "Review the portal's subscription-cancel feature against your retention policy.",
                        "Disable it or add a cancellation flow if self-serve cancel is not intended.",
                    ],
                },
                record_id=record_id,
            )
        )

    # G. Portal login page enabled (any customer can request a portal link).
    if record.get("login_page_enabled") is True:
        out.append(
            FindingCandidate(
                provider="stripe",
                rule_key=_RULE_PORTAL_LOGIN_ENABLED,
                finding_key=make_finding_key(_RULE_PORTAL_LOGIN_ENABLED, record_id),
                severity="medium",
                title="Stripe customer portal login page is enabled",
                description=(
                    "The active Stripe customer portal configuration has its "
                    "hosted login page enabled, so customers can request a portal "
                    "session by email without your application creating it. If "
                    "unintended, this widens the self-serve access surface and "
                    "may increase configuration risk. This is evidence for review "
                    "and does not confirm compromise or unauthorized access."
                ),
                evidence={
                    "rule": _RULE_PORTAL_LOGIN_ENABLED,
                    "active": True,
                    "login_page_enabled": True,
                },
                remediation={
                    "summary": "Confirm whether the hosted portal login page should be enabled.",
                    "steps": [
                        "Review whether customers should reach the portal via the hosted login page.",
                        "Disable the login page if portal sessions should only be created by your app.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Account settings ──────────────────────────────────────────────────────────


def _eval_account(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or None

    # H. Charges / payouts / onboarding not complete. Each flag fires only on an
    #    explicit False; missing/unknown is skipped.
    incomplete = [
        label
        for label, key in (
            ("charges are not enabled", "charges_enabled"),
            ("payouts are not enabled", "payouts_enabled"),
            ("account details are not fully submitted", "details_submitted"),
        )
        if record.get(key) is False
    ]
    if not incomplete:
        return []

    return [
        FindingCandidate(
            provider="stripe",
            rule_key=_RULE_ACCOUNT_CAPABILITY_INCOMPLETE,
            finding_key=make_finding_key(_RULE_ACCOUNT_CAPABILITY_INCOMPLETE, record_id),
            severity="medium",
            title="Stripe account is not fully enabled for payments",
            description=(
                "This Stripe account is not fully enabled for payments: "
                + ", ".join(incomplete)
                + ". This may affect billing/payment operations (for example, "
                "accepting charges or receiving payouts). This is evidence for "
                "review and does not confirm fraud, compromise, or unauthorized "
                "access."
            ),
            evidence={
                "rule": _RULE_ACCOUNT_CAPABILITY_INCOMPLETE,
                "charges_enabled": bool(record.get("charges_enabled")),
                "payouts_enabled": bool(record.get("payouts_enabled")),
                "details_submitted": bool(record.get("details_submitted")),
            },
            remediation={
                "summary": "Complete the account's required information in the Stripe dashboard.",
                "steps": [
                    "Review the account's onboarding/requirements in the Stripe dashboard.",
                    "Submit any missing required information to enable charges and payouts.",
                ],
            },
            record_id=record_id,
        )
    ]
