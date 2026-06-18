"""Clerk connector record type constants — M83A.

M83A scope (drift foundation)
------------------------------
Ten safe drift surfaces from the Clerk Backend API v1:

    clerk_instance_settings    — instance-level feature flags, session and
                                 restriction posture
    clerk_application          — application metadata and OAuth posture counts
    clerk_domain               — domain status and posture (never raw name)
    clerk_redirect_url_config  — redirect URL posture (never raw URL strings)
    clerk_jwt_template         — JWT template posture (never template body)
    clerk_webhook_endpoint     — webhook posture (never URL, secret, or events)
    clerk_email_sms_settings   — email/SMS channel configuration posture
    clerk_auth_strategy        — authentication strategy posture
    clerk_organization_settings — organization configuration posture
    clerk_session_policy       — session lifetime and security policy posture

Privacy contract
----------------
SECURITY: in M83A no Clerk secret key, publishable key, Frontend API URL,
session tokens, JWTs, OAuth tokens, bearer tokens, webhook secrets or URLs,
raw redirect URLs, raw callback URLs, raw allowed origins, raw template body,
JWT claims, custom claims, audience URIs, issuer strings, raw email content,
raw SMS content, sender email addresses, sender phone numbers, user emails,
user IDs, user names, phone numbers, organization member identities,
organization names (if customer-identifying), session history, login history,
password data, MFA secrets, backup codes, verification codes, IP addresses,
user agents, raw audit payloads, raw request/response payloads, customer data,
or PII is ever stored in a normalised record.

URL fields are stored as counts or posture booleans only — raw URL strings
are derived during normalisation and immediately discarded. Webhook URLs,
secrets, and signing keys are stored as presence booleans only.
"""

from __future__ import annotations

from typing import Optional, TypedDict

# ── M83A record type string constants ─────────────────────────────────────────

# Instance-level configuration posture.
# SECURITY: raw Clerk API response, instance ID strings (beyond opaque label),
# support email addresses, custom theme data, and all raw instance payload
# fields are NEVER stored.
CLERK_INSTANCE_SETTINGS = "clerk_instance_settings"

# One per Clerk application (if multiple exist; usually one per instance).
# SECURITY: client_id, OAuth client secrets, raw redirect URL lists, raw
# allowed origins, raw callback URL strings are NEVER stored.
CLERK_APPLICATION = "clerk_application"

# One per configured domain.
# SECURITY: the raw domain name string is customer-identifying and is NEVER
# stored. domain_present is always True (we only emit a record if a domain
# exists). Domain ID is an opaque Clerk identifier.
CLERK_DOMAIN = "clerk_domain"

# One per configured redirect URL entry.
# SECURITY: the raw URL string is NEVER stored. url_present is always True.
# url_scheme_category is derived from the URL scheme before discarding
# the URL itself. Wildcard and localhost posture booleans are derived then
# the URL is discarded.
CLERK_REDIRECT_URL_CONFIG = "clerk_redirect_url_config"

# One per JWT template.
# SECURITY: template body, custom claims, audience string, issuer string,
# signing key, and all raw template content are NEVER stored.
# claims_count is an integer count derived from the claims dict.
CLERK_JWT_TEMPLATE = "clerk_jwt_template"

# One per registered webhook endpoint.
# SECURITY: webhook URL, signing secret, event names (if business-sensitive),
# and all raw webhook payload are NEVER stored. url_present is a boolean.
# url_scheme_category is derived from the URL scheme before discarding
# the URL itself.
CLERK_WEBHOOK_ENDPOINT = "clerk_webhook_endpoint"

# Email and SMS delivery configuration posture.
# SECURITY: sender addresses, template content, phone numbers, and email
# content are NEVER stored.
CLERK_EMAIL_SMS_SETTINGS = "clerk_email_sms_settings"

# Authentication strategy posture for the instance.
# SECURITY: social provider secrets, SAML certificates, private keys,
# connection-level credentials, and raw strategy options are NEVER stored.
CLERK_AUTH_STRATEGY = "clerk_auth_strategy"

# Organization feature and restriction posture.
# SECURITY: organization names (customer-identifying), member emails,
# member IDs, invitation lists, and all raw organization payload are
# NEVER stored.
CLERK_ORGANIZATION_SETTINGS = "clerk_organization_settings"

# Session lifetime, rotation, and security policy posture.
# SECURITY: active session tokens, session IDs, session contents, and
# user-level session data are NEVER stored.
CLERK_SESSION_POLICY = "clerk_session_policy"

# ── Aggregate set ─────────────────────────────────────────────────────────────

CLERK_RECORD_TYPES: frozenset[str] = frozenset({
    CLERK_INSTANCE_SETTINGS,
    CLERK_APPLICATION,
    CLERK_DOMAIN,
    CLERK_REDIRECT_URL_CONFIG,
    CLERK_JWT_TEMPLATE,
    CLERK_WEBHOOK_ENDPOINT,
    CLERK_EMAIL_SMS_SETTINGS,
    CLERK_AUTH_STRATEGY,
    CLERK_ORGANIZATION_SETTINGS,
    CLERK_SESSION_POLICY,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────


class ClerkInstanceSettingsRecord(TypedDict):
    """Safe normalised record for Clerk instance settings (M83A).

    Derived from GET /v1/instance. SECURITY: raw domain names, support
    email, custom theme, raw API response, and all customer-identifying
    fields are NEVER stored.
    """

    record_type: str          # always "clerk_instance_settings"
    record_id: str            # opaque Clerk instance ID (safe internal identifier)
    provider_resource_id: str # "instance/settings"
    provider: str             # "clerk"
    environment_type: str     # "production" / "development" / "staging"
    sign_up_enabled: bool
    sign_in_enabled: bool
    email_enabled: bool
    phone_enabled: bool
    username_enabled: bool
    password_enabled: bool
    social_provider_count: int
    mfa_enabled: bool
    mfa_factor_count: int
    session_lifetime_category: str   # based on token_lifetime_minutes/hours
    allowed_redirect_count: int
    domain_count: int
    webhook_count: int
    # Restriction posture flags
    allowlist_enabled: bool
    blocklist_enabled: bool
    sign_in_mode: str         # "public" / "restricted" category label


class ClerkApplicationRecord(TypedDict):
    """Safe normalised record for a Clerk application (M83A).

    SECURITY: client_id values, OAuth client secrets, raw redirect URLs,
    raw allowed origins, and all raw application payload are NEVER stored.
    URL counts are derived from URL lists; raw URL strings are discarded.
    """

    record_type: str          # always "clerk_application"
    record_id: str            # opaque Clerk application identifier
    provider_resource_id: str # f"applications/{application_id}"
    provider: str             # "clerk"
    name: str                 # truncated to 100 chars (safe display label)
    application_type: str     # "web" / "native" / "browser-extension" etc.
    enabled: bool
    oauth_provider_count: int  # count of configured OAuth/social providers
    redirect_url_count: int   # integer count — raw URLs NEVER stored
    allowed_origin_count: int  # integer count — raw origins NEVER stored
    jwt_template_count: int
    organization_enabled: bool
    mfa_required: bool


class ClerkDomainRecord(TypedDict):
    """Safe normalised record for a Clerk domain (M83A).

    SECURITY: the raw domain name string is customer-identifying and is
    NEVER stored. domain_present is always True. domain_id is an opaque
    Clerk identifier.
    """

    record_type: str          # always "clerk_domain"
    record_id: str            # opaque Clerk domain identifier
    provider_resource_id: str # f"domains/{domain_id}"
    provider: str             # "clerk"
    domain_present: bool      # always True — raw domain string NEVER stored
    domain_type: str          # "primary" / "satellite" category label
    verified: bool
    primary: bool
    ssl_enabled: bool
    dns_status_category: str  # "verified" / "pending" / "failed" / "unknown"
    proxy_enabled: bool


class ClerkRedirectUrlConfigRecord(TypedDict):
    """Safe normalised record for a Clerk redirect URL entry (M83A).

    SECURITY: the raw URL string is NEVER stored. url_scheme_category,
    wildcard_present, and localhost_present are derived from the URL
    before it is discarded.
    """

    record_type: str          # always "clerk_redirect_url_config"
    record_id: str            # opaque Clerk redirect URL identifier
    provider_resource_id: str # f"redirect_urls/{redirect_url_id}"
    provider: str             # "clerk"
    url_present: bool         # always True
    url_scheme_category: str  # "https" / "http" / "custom" / "unknown"
    wildcard_present: bool    # derived from URL pattern — raw URL NEVER stored
    localhost_present: bool   # derived from URL — raw URL NEVER stored
    custom_scheme_present: bool  # non-http(s) scheme (deep link, custom protocol)


class ClerkJwtTemplateRecord(TypedDict):
    """Safe normalised record for a Clerk JWT template (M83A).

    SECURITY: template body, custom claims, audience URI, issuer string,
    signing key material, and all raw template content are NEVER stored.
    claims_count is an integer derived from the claims dict key count.
    """

    record_type: str          # always "clerk_jwt_template"
    record_id: str            # opaque Clerk JWT template identifier
    provider_resource_id: str # f"jwt_templates/{template_id}"
    provider: str             # "clerk"
    name: str                 # truncated to 100 chars
    enabled: bool
    claims_count: int         # number of claim keys — values/keys NEVER stored
    custom_claims_present: bool
    audience_present: bool    # audience URI presence — NEVER the URI string
    lifetime_category: str    # "short" / "standard" / "extended" based on TTL
    algorithm: str            # "RS256" / "HS256" etc. (safe label)


class ClerkWebhookEndpointRecord(TypedDict):
    """Safe normalised record for a Clerk webhook endpoint (M83A).

    SECURITY: webhook URL, signing secret, raw event names if business-
    sensitive, and all raw webhook payload are NEVER stored.
    url_scheme_category is derived before discarding the URL.
    """

    record_type: str          # always "clerk_webhook_endpoint"
    record_id: str            # opaque Clerk / Svix webhook endpoint identifier
    provider_resource_id: str # f"webhooks/{endpoint_id}"
    provider: str             # "clerk"
    enabled: bool
    url_present: bool         # always True for active endpoints
    url_scheme_category: str  # "https" / "http" / "unknown"
    event_count: int          # number of subscribed event types (count only)
    secret_present: bool      # signing secret presence — value NEVER stored
    description_present: bool # whether a description is configured


class ClerkEmailSmsSettingsRecord(TypedDict):
    """Safe normalised record for Clerk email/SMS configuration (M83A).

    SECURITY: sender email addresses, sender phone numbers, template
    content, raw SMS/email content, and all raw settings payload are
    NEVER stored.
    """

    record_type: str          # always "clerk_email_sms_settings"
    record_id: str            # always "clerk_email_sms_settings_main"
    provider_resource_id: str # "instance/email_sms"
    provider: str             # "clerk"
    email_enabled: bool
    sms_enabled: bool
    custom_sender_present: bool   # whether a custom sender domain is configured
    template_customization_present: bool


class ClerkAuthStrategyRecord(TypedDict):
    """Safe normalised record for Clerk authentication strategy posture (M83A).

    SECURITY: social provider secrets/tokens, SAML certificates, private
    keys, connection credentials, and raw strategy configuration are
    NEVER stored.
    """

    record_type: str          # always "clerk_auth_strategy"
    record_id: str            # always "clerk_auth_strategy_main"
    provider_resource_id: str # "instance/auth_strategy"
    provider: str             # "clerk"
    password_enabled: bool
    oauth_enabled: bool
    social_provider_count: int
    saml_enabled: bool
    mfa_enabled: bool
    mfa_required: bool
    passkey_enabled: bool
    magic_link_enabled: bool
    email_otp_enabled: bool
    phone_otp_enabled: bool


class ClerkOrganizationSettingsRecord(TypedDict):
    """Safe normalised record for Clerk organization configuration (M83A).

    SECURITY: organization names (customer-identifying), member emails,
    member IDs, invitation content, and all raw organization data are
    NEVER stored.
    """

    record_type: str          # always "clerk_organization_settings"
    record_id: str            # always "clerk_organization_settings_main"
    provider_resource_id: str # "instance/organization"
    provider: str             # "clerk"
    organizations_enabled: bool
    max_allowed_memberships_category: str  # "unlimited" / "limited" category
    admin_delete_enabled: bool
    domains_enabled: bool
    domains_enrollment_mode_category: str  # "automatic" / "manual" etc.


class ClerkSessionPolicyRecord(TypedDict):
    """Safe normalised record for Clerk session policy (M83A).

    SECURITY: active session tokens, session IDs, session content, and
    all user-level session data are NEVER stored.
    """

    record_type: str          # always "clerk_session_policy"
    record_id: str            # always "clerk_session_policy_main"
    provider_resource_id: str # "instance/session"
    provider: str             # "clerk"
    session_lifetime_category: str   # "short" / "standard" / "extended" / "very_long"
    inactivity_timeout_category: str # "none" / "short" / "standard" / "extended"
    single_session_mode: bool
    url_based_session_syncing: bool
    token_rotation_enabled: Optional[bool]
