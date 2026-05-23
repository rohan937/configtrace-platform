"""Stripe record type constants and TypedDicts — M35.

Record types
------------
stripe_account_settings
    Top-level Stripe account settings: business profile, email, payouts,
    dashboard locale, branding, supported payment methods, etc.
    One record per integration (the connected account).

stripe_webhook_endpoint
    Each entry under /v1/webhook_endpoints.  Captures the delivery URL,
    enabled events, and API version.  The webhook signing secret is NEVER
    fetched, stored, or included in any snapshot.

stripe_payment_method_configuration
    Each entry under /v1/payment_method_configurations.  Captures which
    payment method types are enabled in a given configuration set.

stripe_payment_method_domain
    Each entry under /v1/payment_method_domains.  Captures domain name and
    whether Apple Pay / Google Pay are enabled.

SECURITY
--------
- Signing secrets are NEVER fetched or stored.
- Customer PII (name, email, address) is NEVER fetched or stored.
- Charge / payment intent / invoice / subscription data is NEVER fetched.
- API key values are NEVER stored or logged — only the encrypted form.
"""

from __future__ import annotations

from typing import TypedDict

# ── Record type constants ──────────────────────────────────────────────────────

STRIPE_ACCOUNT_SETTINGS = "stripe_account_settings"
STRIPE_WEBHOOK_ENDPOINT = "stripe_webhook_endpoint"
STRIPE_PAYMENT_METHOD_CONFIGURATION = "stripe_payment_method_configuration"
STRIPE_PAYMENT_METHOD_DOMAIN = "stripe_payment_method_domain"

STRIPE_RECORD_TYPES: frozenset[str] = frozenset(
    {
        STRIPE_ACCOUNT_SETTINGS,
        STRIPE_WEBHOOK_ENDPOINT,
        STRIPE_PAYMENT_METHOD_CONFIGURATION,
        STRIPE_PAYMENT_METHOD_DOMAIN,
    }
)


# ── TypedDicts ─────────────────────────────────────────────────────────────────


class StripeAccountSettingsRecord(TypedDict, total=False):
    """Normalised stripe_account_settings record."""

    record_type: str          # "stripe_account_settings"
    record_id: str            # Stripe account ID, e.g. "acct_xxx"
    name: str                 # account ID — used as display identifier

    # Business profile
    account_id: str
    business_name: str | None
    support_email: str | None
    support_url: str | None
    business_url: str | None
    country: str | None

    # Operational settings
    default_currency: str | None
    payout_schedule_interval: str | None  # "daily" | "weekly" | "monthly" | "manual"
    payout_schedule_delay_days: int | None

    # Dashboard
    display_name: str | None

    # Branding
    branding_icon: str | None   # Stripe file ID (safe — not a secret)
    branding_logo: str | None   # Stripe file ID (safe — not a secret)
    branding_primary_color: str | None

    # Capabilities / payment methods (list of enabled capability names)
    enabled_payment_methods: list[str]

    # Charges enabled / payouts enabled (operational flags)
    charges_enabled: bool
    payouts_enabled: bool

    # Controller / platform info
    controller_type: str | None


class StripeWebhookEndpointRecord(TypedDict, total=False):
    """Normalised stripe_webhook_endpoint record."""

    record_type: str           # "stripe_webhook_endpoint"
    record_id: str             # Stripe webhook endpoint ID, e.g. "we_xxx"
    name: str                  # delivery URL — human-readable identifier

    endpoint_id: str
    url: str
    status: str                # "enabled" | "disabled"
    api_version: str | None
    enabled_events: list[str]  # sorted list of subscribed event types
    description: str | None
    # SECURITY: signing secret is NEVER included here.


class StripePaymentMethodConfigurationRecord(TypedDict, total=False):
    """Normalised stripe_payment_method_configuration record."""

    record_type: str           # "stripe_payment_method_configuration"
    record_id: str             # Stripe PM config ID, e.g. "pmc_xxx"
    name: str                  # human name of the config

    config_id: str
    config_name: str | None
    is_default: bool
    parent_id: str | None      # None for root config

    # Per-method enabled flags — key is payment method name, value is True/False
    enabled_payment_methods: dict[str, bool]


class StripePaymentMethodDomainRecord(TypedDict, total=False):
    """Normalised stripe_payment_method_domain record."""

    record_type: str           # "stripe_payment_method_domain"
    record_id: str             # Stripe domain ID, e.g. "pmd_xxx"
    name: str                  # domain name

    domain_id: str
    domain_name: str
    enabled: bool
    apple_pay_enabled: bool
    google_pay_enabled: bool
    link_enabled: bool
