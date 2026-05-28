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
STRIPE_BILLING_PORTAL_CONFIG = "stripe_billing_portal_config"   # M57.9

# ── M59.10 — Stripe Part 1 expansion: catalog + checkout + tax ───────────────
# One per Stripe Product.  SECURITY: customer PII / card data are never
# fetched.  Only the safe catalog fields below are persisted.
STRIPE_PRODUCT = "stripe_product"

# One per Stripe Price.  Stripe prices are typically *immutable* once
# created — a "change" usually means the price object was deactivated and a
# new one took its place.  Risk reasons phrase this as "price record changed
# / was deactivated" rather than implying in-place mutation.
STRIPE_PRICE = "stripe_price"

# One per Stripe Payment Link.  The success/cancel URLs are stored AS-IS
# only if they look like clean URLs without embedded query tokens; otherwise
# the connector should pass the scheme+host form via _safe_redirect_target
# (see the Cloudflare page-rule helper).  In the snapshot we further enforce
# this by storing a separate ``redirect_url_safe`` flag and the scheme+host
# only — see the schema docstring.
STRIPE_PAYMENT_LINK = "stripe_payment_link"

# Account-level Checkout configuration defaults.  Singleton-per-account in
# Stripe (no separate API object — connector synthesizes this from
# ``Account.controller``, the Customer Portal config, and any account-default
# Payment Method Configuration).  SECURITY: no client_secret / publishable
# key / customer info stored.
STRIPE_CHECKOUT_CONFIGURATION = "stripe_checkout_configuration"

# Stripe Tax settings (singleton per account).
STRIPE_TAX_SETTINGS = "stripe_tax_settings"

STRIPE_RECORD_TYPES: frozenset[str] = frozenset(
    {
        STRIPE_ACCOUNT_SETTINGS,
        STRIPE_WEBHOOK_ENDPOINT,
        STRIPE_PAYMENT_METHOD_CONFIGURATION,
        STRIPE_PAYMENT_METHOD_DOMAIN,
        STRIPE_BILLING_PORTAL_CONFIG,
        # M59.10 Part 1 expansion
        STRIPE_PRODUCT,
        STRIPE_PRICE,
        STRIPE_PAYMENT_LINK,
        STRIPE_CHECKOUT_CONFIGURATION,
        STRIPE_TAX_SETTINGS,
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


class StripeBillingPortalConfigRecord(TypedDict, total=False):
    """Normalised stripe_billing_portal_config record — M57.9.

    Captures Stripe Customer Portal configuration posture: which self-service
    actions the portal allows (cancel, update payment method, update
    subscription, etc.).  No customer data, subscription data, or invoice data
    is ever fetched or stored.

    SECURITY
    --------
    - business_profile URLs (privacy_policy_url, terms_of_service_url) may
      contain internal paths; only domain is extracted, never the full URL.
    - return_url domain only — full URL may contain path tokens.
    - No customer PII, no invoice data, no subscription data.
    """

    record_type: str           # "stripe_billing_portal_config"
    record_id: str             # Stripe billing portal config ID, e.g. "bpc_xxx"
    name: str                  # display: config ID or "default billing portal"

    config_id: str
    active: bool
    is_default: bool

    # Portal login page
    login_page_enabled: bool

    # Return URL — domain only (full URL may contain path tokens)
    return_url_domain: str | None

    # Customer update feature
    customer_update_enabled: bool
    customer_update_allowed_updates: list[str]   # sorted, e.g. ["address","email"]

    # Invoice history access
    invoice_history_enabled: bool

    # Payment method update
    payment_method_update_enabled: bool

    # Subscription cancel
    subscription_cancel_enabled: bool
    subscription_cancel_mode: str | None        # "immediately" | "at_period_end"
    subscription_cancel_reason_enabled: bool

    # Subscription update
    subscription_update_enabled: bool
    subscription_update_allowed_updates: list[str]  # sorted

    # Subscription pause
    subscription_pause_enabled: bool


# ── M59.10 Stripe Part 1 expansion — TypedDicts ──────────────────────────────


class StripeProductRecord(TypedDict, total=False):
    """Normalised stripe_product record.

    SECURITY: only catalog metadata is stored — no card data, customer info,
    payment-method details, or API keys.  Product images URLs and statement
    descriptors are short user-supplied strings — safe to retain.
    """

    record_type: str             # always "stripe_product"
    record_id: str               # Stripe product id, e.g. "prod_xxx"
    name: str                    # short display name (user-supplied)
    active: bool
    description_present: bool    # we store ONLY the presence flag, not the
                                  # body — descriptions can be long and may
                                  # contain customer-facing copy we do not
                                  # need to retain.
    default_price: Optional[str] # price id reference, e.g. "price_xxx"
    metadata_key_count: int      # number of metadata keys (values not stored)
    statement_descriptor: Optional[str]
    unit_label: Optional[str]
    livemode: bool
    updated: Optional[int]       # Stripe epoch timestamp


class StripePriceRecord(TypedDict, total=False):
    """Normalised stripe_price record.

    Stripe prices are typically immutable.  ``active`` toggles whether a
    price can be referenced on new checkouts; ``unit_amount`` / ``currency`` /
    ``recurring`` values are recorded but a change in any of them
    in practice means a NEW price object was attached and the old one
    deactivated — the classifier phrases this accordingly.
    """

    record_type: str             # always "stripe_price"
    record_id: str               # Stripe price id, e.g. "price_xxx"
    nickname: Optional[str]
    product_id: str
    active: bool
    currency: str
    unit_amount: Optional[int]   # in the smallest currency unit (e.g. cents)
    billing_scheme: str          # "per_unit" | "tiered"
    type: str                    # "one_time" | "recurring"
    recurring_interval: Optional[str]      # "day"|"week"|"month"|"year"|None
    recurring_interval_count: Optional[int]
    recurring_trial_period_days: Optional[int]
    tax_behavior: Optional[str]            # "inclusive"|"exclusive"|"unspecified"
    lookup_key: Optional[str]              # short safe label, user-supplied
    livemode: bool
    metadata_key_count: int
    updated: Optional[int]


class StripePaymentLinkRecord(TypedDict, total=False):
    """Normalised stripe_payment_link record.

    SECURITY: ``success_url`` / ``cancel_url`` etc. are stored ONLY as their
    scheme+host form (the connector reduces any URL to scheme+host before
    persistence).  Query strings (which may contain `?session_id={CHECKOUT_SESSION_ID}`
    or customer-supplied tokens) are never persisted.
    """

    record_type: str             # always "stripe_payment_link"
    record_id: str               # Stripe payment link id, "plink_xxx"
    active: bool
    line_item_count: int
    line_item_price_ids: list[str]
    allow_promotion_codes: bool
    automatic_tax_enabled: bool
    customer_creation: str       # "always" | "if_required"
    payment_method_collection: str  # "always" | "if_required"
    payment_method_types_count: int
    application_fee_amount: Optional[int]
    application_fee_percent: Optional[float]
    transfer_destination_present: bool
    # Scheme+host only — query strings are stripped at the connector layer.
    success_url_origin: Optional[str]   # e.g. "https://example.com"
    after_completion_type: Optional[str]  # "redirect" | "hosted_confirmation"
    after_completion_redirect_origin: Optional[str]
    subscription_data_trial_period_days: Optional[int]
    livemode: bool
    metadata_key_count: int


class StripeCheckoutConfigurationRecord(TypedDict, total=False):
    """Account-level Checkout configuration defaults.

    This is a synthesised record (Stripe does not expose a single object) —
    the connector composes it from account-default Payment Method
    Configuration + per-account Tax settings + Customer Portal default.
    """

    record_type: str             # always "stripe_checkout_configuration"
    record_id: str               # account id ("acct_xxx") since this is
                                  # account-singleton
    allowed_payment_method_types_count: int
    default_mode: str            # "payment" | "subscription" | "setup"
    default_customer_creation: str
    consent_collection_terms_of_service: Optional[str]
    consent_collection_promotions: Optional[str]
    phone_collection_enabled: bool
    billing_address_collection: str   # "auto" | "required"
    invoice_creation_enabled: bool
    livemode: bool


class StripeTaxSettingsRecord(TypedDict, total=False):
    """Stripe Tax settings (singleton per account).

    SECURITY: jurisdiction lists are stored as COUNTS only (we do not
    persist customer-region lists which may carry market-strategy data).
    """

    record_type: str             # always "stripe_tax_settings"
    record_id: str               # account id
    automatic_tax_status: str    # "active" | "pending" | "inactive"
    head_office_address_present: bool
    default_tax_behavior: str    # "inclusive" | "exclusive" | "unspecified"
    default_tax_code: Optional[str]
    tax_registrations_active_count: int
    tax_registrations_total_count: int
    livemode: bool
