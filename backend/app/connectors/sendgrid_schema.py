"""SendGrid connector record type constants — M80A.

M80A scope (drift foundation)
------------------------------
Eight safe drift surfaces ingested in the initial SendGrid connector milestone:

    sendgrid_account               — account type, reputation, and credit summary
    sendgrid_api_key               — API key metadata (SID and name only — never
                                     the key value or secret)
    sendgrid_sender_identity       — verified sender configuration (domain-part
                                     of addresses only — full email is never stored)
    sendgrid_domain_authentication — domain authentication status and DNS record
                                     count (raw DNS values never stored)
    sendgrid_mail_settings         — mail-feature boolean flags only
    sendgrid_tracking_settings     — tracking-feature boolean flags only
    sendgrid_webhook_settings      — event webhook configuration booleans (URL
                                     stored as a boolean presence flag only)
    sendgrid_suppression_settings  — suppression group count only

Privacy contract
----------------
SECURITY: in M80A no API key value, bearer token, authorization header,
email body, email subject line, recipient email address, sender personal
full email address, suppression recipient email, template HTML/plaintext/
content, marketing contact data, mail event payload, click/open event
payload, unsubscribe recipient data, raw SendGrid API response, raw
request/response payload, or customer data / PII is ever stored in a
normalised record.

Never stored:
  - API key values or secrets (api_key_id only)
  - Authorization headers or bearer tokens of any kind
  - Full email addresses — only the domain part (after @) is kept
  - Template bodies, subjects, HTML, or plaintext
  - Recipient lists, suppression lists, or email addresses in any form
  - Webhook URL strings (stored as bool: configured or not)
  - Raw DNS record values (stored as a count only)
  - Marketing contact data or campaign content
  - Mail event payloads, click/open events, or tracking data at the
    individual-recipient level
  - Raw SendGrid API responses
"""
from __future__ import annotations

from typing import Optional, TypedDict

# ── M80A record type string constants ─────────────────────────────────────────

# One per SendGrid account — top-level account posture.
# SECURITY: API key is NEVER stored. Owner email and billing PII are
# NEVER stored. Only account type and reputation metadata are kept.
SENDGRID_ACCOUNT = "sendgrid_account"

# One per API key — key metadata only.
# SECURITY: the API key value/secret is NEVER stored — only the api_key_id,
# name, and scope count.
SENDGRID_API_KEY = "sendgrid_api_key"

# One per verified sender identity — sender configuration posture.
# SECURITY: full email addresses are NEVER stored — only the domain part
# (everything after @). Sender name, postal address, city, phone, and all
# other PII fields are NEVER stored.
SENDGRID_SENDER_IDENTITY = "sendgrid_sender_identity"

# One per authenticated domain — domain authentication posture.
# SECURITY: raw DNS record values (CNAME targets, DKIM keys) are NEVER
# stored — only the count of DNS records is kept. Username fields are NEVER
# stored.
SENDGRID_DOMAIN_AUTHENTICATION = "sendgrid_domain_authentication"

# One per account — mail feature configuration booleans.
# SECURITY: BCC email addresses, footer text, and all email-content fields
# are NEVER stored — only boolean flags per mail feature.
SENDGRID_MAIL_SETTINGS = "sendgrid_mail_settings"

# One per account — tracking feature configuration booleans.
# SECURITY: unsubscribe URLs, Google Analytics parameters, and all
# recipient-level tracking data are NEVER stored — only boolean flags.
SENDGRID_TRACKING_SETTINGS = "sendgrid_tracking_settings"

# One per account — event webhook configuration booleans.
# SECURITY: webhook URL string is NEVER stored — only a boolean indicating
# whether a URL is configured. Webhook signing secrets and raw event payloads
# are NEVER stored.
SENDGRID_WEBHOOK_SETTINGS = "sendgrid_webhook_settings"

# One per account — suppression configuration summary.
# SECURITY: suppressed email addresses, recipient identities, and suppression
# list contents are NEVER stored — only the count of suppression groups.
SENDGRID_SUPPRESSION_SETTINGS = "sendgrid_suppression_settings"

# ── Aggregate set ─────────────────────────────────────────────────────────────

SENDGRID_RECORD_TYPES: frozenset[str] = frozenset({
    SENDGRID_ACCOUNT,
    SENDGRID_API_KEY,
    SENDGRID_SENDER_IDENTITY,
    SENDGRID_DOMAIN_AUTHENTICATION,
    SENDGRID_MAIL_SETTINGS,
    SENDGRID_TRACKING_SETTINGS,
    SENDGRID_WEBHOOK_SETTINGS,
    SENDGRID_SUPPRESSION_SETTINGS,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────


class SendGridAccountRecord(TypedDict):
    """Safe normalised record for a SendGrid account (M80A).

    SECURITY: API key is NEVER a field here. Owner email, billing address,
    and all PII fields are NEVER stored.
    """

    record_type: str         # always "sendgrid_account"
    record_id: str           # always "sendgrid_account_main"
    provider_resource_id: str  # always "accounts/main"
    account_type: str        # "free" | "paid" | "trusted" | "unknown"
    reputation: Optional[float]  # sender reputation score (0–100) or None


class SendGridApiKeyRecord(TypedDict):
    """Safe normalised record for a SendGrid API key (M80A).

    SECURITY: the API key value/secret is NEVER stored — only the opaque
    api_key_id identifier, the human-readable name, and a scope count.
    """

    record_type: str         # always "sendgrid_api_key"
    record_id: str           # the api_key_id (opaque identifier)
    provider_resource_id: str  # f"api_keys/{api_key_id}"
    api_key_id: str          # opaque API key identifier
    name: str                # truncated to 100 chars
    scopes_count: int        # number of scopes assigned to this key
    has_mail_send: bool      # whether "mail.send" scope is granted
    has_full_access: bool    # whether broad admin/full scopes are granted


class SendGridSenderIdentityRecord(TypedDict):
    """Safe normalised record for a SendGrid verified sender identity (M80A).

    SECURITY: full email addresses are NEVER stored — only the domain part
    (after @). Sender name, postal address, city, state, country, zip,
    and phone are NEVER stored.
    """

    record_type: str         # always "sendgrid_sender_identity"
    record_id: str           # str(sender_id)
    provider_resource_id: str  # f"verified_senders/{sender_id}"
    sender_id: str           # opaque sender identifier
    nickname: str            # truncated to 100 chars
    from_email_domain: str   # domain part only (after @) — never full address
    reply_to_domain: str     # domain part only (after @) — never full address
    verified: bool           # whether identity is verified
    locked: bool             # whether identity is locked


class SendGridDomainAuthRecord(TypedDict):
    """Safe normalised record for a SendGrid domain authentication (M80A).

    SECURITY: raw DNS record values (CNAME targets, DKIM public keys) are
    NEVER stored. The username field (usually an email address) is NEVER
    stored. Only the domain name, validity, and DNS record count are kept.
    """

    record_type: str           # always "sendgrid_domain_authentication"
    record_id: str             # str(domain_id)
    provider_resource_id: str  # f"whitelabel/domains/{domain_id}"
    domain_id: str             # opaque domain identifier
    domain: str                # the authenticated domain name (safe infrastructure label)
    valid: bool                # whether domain passes all DNS checks
    automatic_security: bool   # whether automatic DKIM rotation is enabled
    default: bool              # whether this is the default sender domain
    legacy: bool               # whether this is a legacy domain auth record
    dns_record_count: int      # number of DNS records configured for this domain


class SendGridMailSettingsRecord(TypedDict):
    """Safe normalised record for SendGrid mail settings (M80A/M80C).

    SECURITY: BCC email addresses, footer text, address-whitelist entries,
    template content, and all email-content or recipient fields are NEVER
    stored — only boolean flags per mail feature.
    """

    record_type: str           # always "sendgrid_mail_settings"
    record_id: str             # always "sendgrid_mail_settings_main"
    provider_resource_id: str  # always "mail_settings/main"
    bcc_enabled: bool
    bounce_purge_enabled: bool
    footer_enabled: bool
    forward_bounce_enabled: bool
    forward_spam_enabled: bool
    sandbox_mode_enabled: bool
    spam_check_enabled: bool
    # M80C addition — template engine feature flag (boolean only, no content stored).
    template_enabled: bool


class SendGridTrackingSettingsRecord(TypedDict):
    """Safe normalised record for SendGrid tracking settings (M80A).

    SECURITY: unsubscribe URLs, Google Analytics campaign parameters,
    and all recipient-level tracking or analytics data are NEVER stored —
    only boolean flags per tracking feature.
    """

    record_type: str           # always "sendgrid_tracking_settings"
    record_id: str             # always "sendgrid_tracking_settings_main"
    provider_resource_id: str  # always "tracking_settings/main"
    click_tracking_enabled: bool
    open_tracking_enabled: bool
    subscription_tracking_enabled: bool
    ganalytics_enabled: bool


class SendGridWebhookSettingsRecord(TypedDict):
    """Safe normalised record for SendGrid event webhook settings (M80A/M80C).

    SECURITY: the webhook URL string is NEVER stored — only a boolean
    indicating whether a URL is configured. Webhook signing secrets,
    OAuth client IDs/secrets, and raw event payloads are NEVER stored.
    Inbound parse hostnames, URLs, email bodies, and all payload content
    are NEVER stored — only safe booleans.
    """

    record_type: str             # always "sendgrid_webhook_settings"
    record_id: str               # always "sendgrid_webhook_settings_main"
    provider_resource_id: str    # always "webhooks/event/settings/main"
    event_webhook_enabled: bool  # whether event webhook delivery is active
    event_webhook_has_url: bool  # bool(url) — URL string NEVER stored
    event_webhook_signed: bool   # whether webhook signing is enabled
    event_count: int             # number of enabled webhook event types
    # M80C additions — inbound parse booleans only; hostname/URL NEVER stored.
    inbound_parse_enabled: bool          # whether any inbound parse configs exist
    inbound_parse_spam_check_enabled: bool  # spam_check flag from first config
    inbound_parse_send_raw_enabled: bool    # send_raw flag from any config


class SendGridSuppressionSettingsRecord(TypedDict):
    """Safe normalised record for SendGrid suppression settings (M80A).

    SECURITY: suppressed email addresses, recipient identities, and the
    contents of any suppression list are NEVER fetched or stored — only
    the count of suppression groups is kept.
    """

    record_type: str           # always "sendgrid_suppression_settings"
    record_id: str             # always "sendgrid_suppression_settings_main"
    provider_resource_id: str  # always "suppression_settings/main"
    suppression_group_count: int  # count of ASM suppression groups
