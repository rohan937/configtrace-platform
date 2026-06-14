"""Shopify record type constants and TypedDicts — M57.5.

Record types
------------
shopify_shop_metadata
    GET /admin/api/{version}/shop.json — store-level configuration.
    Safe fields only: plan, timezone, currency, locale, flags.
    NEVER stored: owner email, phone, address, billing details.

shopify_webhook_subscription
    GET /admin/api/{version}/webhooks.json — all webhook subscriptions.
    Endpoint URL is decomposed into domain + path_hash to avoid storing
    raw URLs that may contain embedded secrets or tokens.
    NEVER stored: full raw URL.

shopify_store_policy
    GET /admin/api/{version}/policies.json — store policy metadata.
    Stores policy type, presence flag, and a hash of the body text.
    NEVER stored: raw policy body text (may contain PII or legal text).

SECURITY
--------
- Admin access token is NEVER logged, NEVER returned to the frontend,
  and is stored ONLY in encrypted form in the database.
- Customer PII (email, phone, address) is NEVER fetched or stored.
- Order, transaction, payment, or customer data is NEVER fetched.
- Full webhook URLs are decomposed: only domain + SHA-256 path hash stored.
- Policy body text is hashed: only hash + length stored, not raw text.
"""

from __future__ import annotations

from typing import TypedDict

# ── Record type constants ──────────────────────────────────────────────────────

SHOPIFY_SHOP_METADATA = "shopify_shop_metadata"
SHOPIFY_WEBHOOK_SUBSCRIPTION = "shopify_webhook_subscription"
SHOPIFY_STORE_POLICY = "shopify_store_policy"
SHOPIFY_APP_SCOPE_SUMMARY = "shopify_app_scope_summary"  # M57.9
# M74A — shop domain metadata (host + ssl/verified/primary flags only).
SHOPIFY_DOMAIN = "shopify_domain"

# Canonical Shopify store policy types we expect to find a "present" record
# for. The connector emits a baseline ``present=False`` record for any of
# these that the policies API does not return, so the M74A policy-missing
# rule can fire deterministically. Handles are kept underscore-canonical.
SHOPIFY_STANDARD_POLICY_TYPES: tuple[str, ...] = (
    "refund_policy",
    "privacy_policy",
    "terms_of_service",
    "shipping_policy",
)

SHOPIFY_RECORD_TYPES: frozenset[str] = frozenset(
    {
        SHOPIFY_SHOP_METADATA,
        SHOPIFY_WEBHOOK_SUBSCRIPTION,
        SHOPIFY_STORE_POLICY,
        SHOPIFY_APP_SCOPE_SUMMARY,
        SHOPIFY_DOMAIN,
    }
)

# ── Sensitive scope patterns — tracked for risk classification ─────────────────

#: Shopify access scope prefixes/names considered high-sensitivity.
#: Used by risk rules to escalate scope additions.
SENSITIVE_SHOPIFY_SCOPES: frozenset[str] = frozenset(
    {
        "read_orders",
        "write_orders",
        "read_customers",
        "write_customers",
        "read_draft_orders",
        "write_draft_orders",
        "read_checkouts",
        "write_checkouts",
        "read_gift_cards",
        "write_gift_cards",
        "read_payment_terms",
        "write_payment_terms",
        "read_financial_data",
        "write_financials",
        "read_shopify_payments_disputes",
        "read_shopify_payments_payouts",
    }
)


# ── TypedDicts ─────────────────────────────────────────────────────────────────


class ShopifyShopMetadataRecord(TypedDict, total=False):
    """Normalised shopify_shop_metadata record.

    Only safe configuration metadata is stored.  Customer PII, owner
    email, phone, address, and billing details are NEVER included.
    """

    record_type: str            # "shopify_shop_metadata"
    record_id: str              # stable: shop_id_hash or shop_domain
    name: str                   # display identifier — shop_domain

    # Shop identity (safe identifiers only)
    shop_domain: str            # e.g. "mystore.myshopify.com"
    shop_name: str | None       # merchant-facing display name

    # Plan / subscription (safe metadata)
    plan_name: str | None       # e.g. "basic", "shopify", "advanced", "plus"
    plan_display_name: str | None

    # Regional / locale settings
    timezone: str | None        # e.g. "America/New_York"
    iana_timezone: str | None
    currency: str | None        # ISO 4217, e.g. "USD"
    primary_locale: str | None  # BCP 47, e.g. "en"
    country_code: str | None    # ISO 3166-1 alpha-2

    # Store configuration flags (safe operational metadata)
    password_enabled: bool | None  # storefront password protection
    checkout_api_supported: bool | None
    has_storefront: bool | None
    eligible_for_payments: bool | None
    requires_extra_payments_agreement: bool | None
    taxes_included: bool | None
    tax_shipping: bool | None


class ShopifyWebhookSubscriptionRecord(TypedDict, total=False):
    """Normalised shopify_webhook_subscription record.

    The full delivery URL is intentionally NOT stored — it may contain
    embedded secrets, tokens, or sensitive path segments.  Instead, only
    the endpoint domain and a SHA-256 hash of the full path are stored.
    """

    record_type: str            # "shopify_webhook_subscription"
    record_id: str              # stable: webhook_id_hash
    name: str                   # display: "{topic} → {endpoint_domain}"

    # Webhook identity
    webhook_id_hash: str        # SHA-256(str(webhook_id))[:16]

    # Topic (event type)
    topic: str                  # e.g. "orders/create", "app/uninstalled"

    # Endpoint — decomposed to avoid storing raw URLs
    endpoint_domain: str        # e.g. "hooks.example.com"
    endpoint_scheme: str        # "https" or "http"
    endpoint_path_hash: str     # SHA-256(path) — non-reversible
    endpoint_path_length: int   # byte length of the path component
    is_https: bool              # True when scheme == "https"

    # Configuration
    format: str | None          # "json" or "xml"
    api_version: str | None     # e.g. "2024-01"
    created_at: str | None
    updated_at: str | None


class ShopifyStorePolicyRecord(TypedDict, total=False):
    """Normalised shopify_store_policy record.

    Raw policy body text is NEVER stored.  Only the policy type, its
    presence, and a SHA-256 hash of the body (for change detection) are
    kept.
    """

    record_type: str            # "shopify_store_policy"
    record_id: str              # stable: "{shop_domain}:{policy_type}"
    name: str                   # display: "{policy_type} policy"

    policy_type: str            # e.g. "refund_policy", "privacy_policy"
    present: bool               # True when the policy body is non-empty
    body_hash: str | None       # SHA-256(body) for change detection
    body_length: int | None     # byte length of the body text
    updated_at: str | None


class ShopifyAppScopeSummaryRecord(TypedDict, total=False):
    """Aggregate summary of the access token's OAuth scopes — M57.9.

    Fetched from GET /admin/oauth/access_scopes.json — no extra permissions
    required beyond what the token already has.  Scope names (e.g.
    "read_orders", "write_products") are infrastructure permission labels,
    not customer data.

    SECURITY
    --------
    - No customer PII, order data, or payment data is fetched.
    - Scope names are permission labels, not secret values.
    - The access token itself is NEVER stored.
    """

    record_type: str            # "shopify_app_scope_summary"
    record_id: str              # stable: "{shop_domain}:app_scopes"
    name: str                   # display: "app scopes ({shop_domain})"

    # Aggregate counts
    scope_count: int            # total number of granted scopes
    write_scope_count: int      # scopes beginning with "write_"
    sensitive_scope_count: int  # scopes matching SENSITIVE_SHOPIFY_SCOPES

    # Presence flags for high-risk scope categories
    customer_scope_present: bool   # any scope contains "customer"
    order_scope_present: bool      # any scope contains "order"
    payment_scope_present: bool    # any scope relates to payments/financials

    # Structural hash for change detection
    scope_hash: str             # SHA-256[:16] of sorted comma-joined scope handles

    # Full sorted scope list (permission labels — not secrets)
    scope_names: list[str]


class ShopifyDomainRecord(TypedDict, total=False):
    """Normalised shopify_domain record — M74A.

    Captures shop-level domain posture: hostname, ssl_enabled, primary,
    and verified flags. No customer data, billing data, or DNS record
    contents are stored.
    """

    record_type: str            # "shopify_domain"
    record_id: str              # stable: "{shop_domain}:{host}"
    name: str                   # display identifier — host

    # Identity (host is infrastructure metadata, not customer data)
    domain_id_hash: str         # SHA-256[:16] of the domain id
    host: str                   # e.g. "store.example.com"

    # Posture flags (booleans only)
    ssl_enabled: bool | None    # True when ssl is enabled
    primary: bool | None        # True when this is the shop's primary domain
    verified: bool | None       # True when verified (custom domains)
    managed_by_shopify: bool | None  # True when shopify manages the cert/DNS
