"""SendGrid configuration-risk security rules — M80B / M80C.

Every rule fires only on explicit, reliable normalized fields produced by the
SendGrid connector (app/connectors/sendgrid.py + sendgrid_schema.py, M80A).
Evidence is metadata-only: booleans, counts, opaque identifiers, domain names,
and sender nicknames. No API key values, bearer tokens, authorization headers,
email addresses, template content, recipient data, suppression emails, event
payloads, raw URLs, or customer data are ever read, stored, or surfaced.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review. A finding is
evidence for review only. It never asserts that a key was leaked, an email was
intercepted, a recipient list was exposed, a domain was hijacked, that
unauthorized access occurred, or that any attacker is present.

Record types consumed (M80A)
----------------------------
- ``sendgrid_api_key``           → broad-scope key detection
- ``sendgrid_sender_identity``   → verified/locked status
- ``sendgrid_domain_authentication`` → validity, automatic security, legacy
- ``sendgrid_mail_settings``     → spam check, sandbox mode, BCC
- ``sendgrid_tracking_settings`` → click/open/subscription tracking
- ``sendgrid_webhook_settings``  → event webhook presence and configuration
- ``sendgrid_suppression_settings`` → suppression group count

M80C expansion rules (mail/webhook risk expansion)
---------------------------------------------------
Eleven additional rules added in M80C:

Sender identity:
  sendgrid_sender_identity_reply_domain_mismatch — from_email_domain ≠ reply_to_domain

Domain authentication:
  sendgrid_domain_dns_records_missing            — dns_record_count == 0
  sendgrid_default_domain_authentication_invalid — default=True AND valid=False

Mail settings:
  sendgrid_footer_disabled                       — footer_enabled=False
  sendgrid_bounce_purge_disabled                 — bounce_purge_enabled=False
  sendgrid_template_engine_enabled               — template_enabled=True (M80C schema addition)

Tracking settings:
  sendgrid_google_analytics_tracking_enabled     — ganalytics_enabled=True

Webhook settings:
  sendgrid_event_webhook_broad_event_stream      — event_webhook_enabled=True AND event_count > 8
  sendgrid_inbound_parse_enabled                 — inbound_parse_enabled=True (M80C schema addition)
  sendgrid_inbound_parse_raw_email_enabled       — inbound_parse_enabled=True AND inbound_parse_send_raw_enabled=True
  sendgrid_inbound_parse_spam_check_disabled     — inbound_parse_enabled=True AND inbound_parse_spam_check_enabled=False

Rules deferred
--------------
  sendgrid_api_key_stale         — SendGrid v3 API does not expose date fields
                                   (created_at / updated_at) for API keys in
                                   either the list or individual key endpoints.
  sendgrid_api_key_full_access_scope — redundant with existing M80B rule
                                   sendgrid_api_key_broad_scopes (same
                                   has_full_access field).
  sendgrid_subscription_tracking_url_missing — requires a separate call to
                                   /v3/tracking_settings/subscription which
                                   returns URL content; deferred until the
                                   tracking endpoint is safely audited for
                                   boolean extraction without URL storage.
"""

from __future__ import annotations

from typing import Any

from app.connectors.sendgrid_schema import (
    SENDGRID_API_KEY,
    SENDGRID_DOMAIN_AUTHENTICATION,
    SENDGRID_MAIL_SETTINGS,
    SENDGRID_SENDER_IDENTITY,
    SENDGRID_SUPPRESSION_SETTINGS,
    SENDGRID_TRACKING_SETTINGS,
    SENDGRID_WEBHOOK_SETTINGS,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys — M80B ──────────────────────────────────────────────────────────

# API key
_RULE_API_KEY_BROAD_SCOPES = "sendgrid_api_key_broad_scopes"

# Sender identity
_RULE_SENDER_IDENTITY_UNVERIFIED = "sendgrid_sender_identity_unverified"
_RULE_SENDER_IDENTITY_LOCKED = "sendgrid_sender_identity_locked"

# Domain authentication
_RULE_DOMAIN_AUTH_INVALID = "sendgrid_domain_authentication_invalid"
_RULE_DOMAIN_AUTO_SECURITY_DISABLED = "sendgrid_domain_automatic_security_disabled"
_RULE_DOMAIN_AUTH_LEGACY = "sendgrid_domain_authentication_legacy"

# Mail settings
_RULE_SPAM_CHECK_DISABLED = "sendgrid_spam_check_disabled"
_RULE_SANDBOX_MODE_ENABLED = "sendgrid_sandbox_mode_enabled"
_RULE_BCC_ENABLED = "sendgrid_bcc_enabled"

# Tracking settings
_RULE_CLICK_TRACKING_ENABLED = "sendgrid_click_tracking_enabled"
_RULE_OPEN_TRACKING_ENABLED = "sendgrid_open_tracking_enabled"
_RULE_SUBSCRIPTION_TRACKING_DISABLED = "sendgrid_subscription_tracking_disabled"

# Webhook settings
_RULE_EVENT_WEBHOOK_DISABLED = "sendgrid_event_webhook_disabled"
_RULE_EVENT_WEBHOOK_URL_MISSING = "sendgrid_event_webhook_url_missing"

# Suppression settings
_RULE_SUPPRESSION_SETTINGS_EMPTY = "sendgrid_suppression_settings_empty"

# ── Rule keys — M80C ──────────────────────────────────────────────────────────

# Sender identity
_RULE_SENDER_REPLY_DOMAIN_MISMATCH = "sendgrid_sender_identity_reply_domain_mismatch"

# Domain authentication
_RULE_DOMAIN_DNS_RECORDS_MISSING = "sendgrid_domain_dns_records_missing"
_RULE_DEFAULT_DOMAIN_AUTH_INVALID = "sendgrid_default_domain_authentication_invalid"

# Mail settings
_RULE_FOOTER_DISABLED = "sendgrid_footer_disabled"
_RULE_BOUNCE_PURGE_DISABLED = "sendgrid_bounce_purge_disabled"
_RULE_TEMPLATE_ENGINE_ENABLED = "sendgrid_template_engine_enabled"

# Tracking settings
_RULE_GOOGLE_ANALYTICS_ENABLED = "sendgrid_google_analytics_tracking_enabled"

# Webhook settings
_RULE_EVENT_WEBHOOK_BROAD_STREAM = "sendgrid_event_webhook_broad_event_stream"
_RULE_INBOUND_PARSE_ENABLED = "sendgrid_inbound_parse_enabled"
_RULE_INBOUND_PARSE_RAW_EMAIL = "sendgrid_inbound_parse_raw_email_enabled"
_RULE_INBOUND_PARSE_SPAM_CHECK = "sendgrid_inbound_parse_spam_check_disabled"

# ── Rule keys — M80C QA (webhook signing posture) ─────────────────────────────

# Webhook settings
_RULE_EVENT_WEBHOOK_NOT_SIGNED = "sendgrid_event_webhook_not_signed"

# Threshold for broad event stream rule.
_BROAD_EVENT_STREAM_THRESHOLD = 8

SENDGRID_RULE_KEYS: frozenset[str] = frozenset({
    # M80B
    _RULE_API_KEY_BROAD_SCOPES,
    _RULE_SENDER_IDENTITY_UNVERIFIED,
    _RULE_SENDER_IDENTITY_LOCKED,
    _RULE_DOMAIN_AUTH_INVALID,
    _RULE_DOMAIN_AUTO_SECURITY_DISABLED,
    _RULE_DOMAIN_AUTH_LEGACY,
    _RULE_SPAM_CHECK_DISABLED,
    _RULE_SANDBOX_MODE_ENABLED,
    _RULE_BCC_ENABLED,
    _RULE_CLICK_TRACKING_ENABLED,
    _RULE_OPEN_TRACKING_ENABLED,
    _RULE_SUBSCRIPTION_TRACKING_DISABLED,
    _RULE_EVENT_WEBHOOK_DISABLED,
    _RULE_EVENT_WEBHOOK_URL_MISSING,
    _RULE_SUPPRESSION_SETTINGS_EMPTY,
    # M80C
    _RULE_SENDER_REPLY_DOMAIN_MISMATCH,
    _RULE_DOMAIN_DNS_RECORDS_MISSING,
    _RULE_DEFAULT_DOMAIN_AUTH_INVALID,
    _RULE_FOOTER_DISABLED,
    _RULE_BOUNCE_PURGE_DISABLED,
    _RULE_TEMPLATE_ENGINE_ENABLED,
    _RULE_GOOGLE_ANALYTICS_ENABLED,
    _RULE_EVENT_WEBHOOK_BROAD_STREAM,
    _RULE_INBOUND_PARSE_ENABLED,
    _RULE_INBOUND_PARSE_RAW_EMAIL,
    _RULE_INBOUND_PARSE_SPAM_CHECK,
    # M80C QA: webhook signing posture
    _RULE_EVENT_WEBHOOK_NOT_SIGNED,
})


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch one SendGrid drift record to the appropriate rule checks.

    Returns a list of FindingCandidate objects (empty if no rules fire).
    """
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == SENDGRID_API_KEY:
        return _eval_api_key(record)
    if rtype == SENDGRID_SENDER_IDENTITY:
        return _eval_sender_identity(record)
    if rtype == SENDGRID_DOMAIN_AUTHENTICATION:
        return _eval_domain_auth(record)
    if rtype == SENDGRID_MAIL_SETTINGS:
        return _eval_mail_settings(record)
    if rtype == SENDGRID_TRACKING_SETTINGS:
        return _eval_tracking_settings(record)
    if rtype == SENDGRID_WEBHOOK_SETTINGS:
        return _eval_webhook_settings(record)
    if rtype == SENDGRID_SUPPRESSION_SETTINGS:
        return _eval_suppression_settings(record)
    return []


# ── M80C dispatcher additions ─────────────────────────────────────────────────
# The existing _eval_* functions above have been extended below to include
# M80C checks via helper functions appended at the end of each section.


# ── API key ───────────────────────────────────────────────────────────────────


def _eval_api_key(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    f = _check_api_key_broad_scopes(record)
    if f:
        findings.append(f)
    return findings


def _check_api_key_broad_scopes(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when an API key is configured with broad/full-access scopes.

    SECURITY: the API key value is NEVER stored — only the api_key_id,
    name, and boolean scope summary are used.
    """
    if record.get("record_type") != SENDGRID_API_KEY:
        return None
    if record.get("has_full_access") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_API_KEY_BROAD_SCOPES,
        finding_key=make_finding_key(_RULE_API_KEY_BROAD_SCOPES, record_id),
        severity="high",
        title="SendGrid API key is configured with broad access scopes",
        description=(
            "This SendGrid API key metadata indicates it holds broad or full-access "
            "permissions. Broad-scope API keys may increase the impact of a "
            "credential compromise and may require review. This is configuration "
            "evidence for review; it does not confirm a leaked key, unauthorized "
            "access, or data exposure."
        ),
        evidence={
            "rule": _RULE_API_KEY_BROAD_SCOPES,
            "api_key_id": get_str(record, "api_key_id"),
            "name": get_str(record, "name"),
            "scopes_count": record.get("scopes_count"),
            "has_full_access": True,
        },
        remediation={
            "summary": (
                "Review whether this API key needs broad access and consider "
                "rotating it to a least-privilege key scoped only to its required operations."
            ),
            "steps": [
                "In SendGrid Console, navigate to Settings > API Keys.",
                "Identify the key and review its assigned scopes.",
                "Create a new key with only the required scopes (e.g., mail.send only).",
                "Update all integrations to use the new least-privilege key.",
                "Delete the broad-scope key once all integrations are migrated.",
            ],
        },
        record_id=record_id,
    )


# ── Sender identity ───────────────────────────────────────────────────────────


def _eval_sender_identity(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for check_fn in (
        _check_sender_identity_unverified,
        _check_sender_identity_locked,
        _check_sender_reply_domain_mismatch,  # M80C
    ):
        f = check_fn(record)
        if f:
            findings.append(f)
    return findings


def _check_sender_identity_unverified(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when a verified sender identity has not been verified."""
    if record.get("record_type") != SENDGRID_SENDER_IDENTITY:
        return None
    if record.get("verified") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SENDER_IDENTITY_UNVERIFIED,
        finding_key=make_finding_key(_RULE_SENDER_IDENTITY_UNVERIFIED, record_id),
        severity="medium",
        title="SendGrid sender identity has not been verified",
        description=(
            "This SendGrid sender identity is not verified. Unverified sender "
            "identities may not be able to send email reliably and may cause "
            "deliverability issues. Review whether verification has been completed. "
            "This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_SENDER_IDENTITY_UNVERIFIED,
            "sender_id": get_str(record, "sender_id"),
            "nickname": get_str(record, "nickname"),
            "from_email_domain": get_str(record, "from_email_domain"),
            "verified": False,
        },
        remediation={
            "summary": "Complete sender identity verification in SendGrid.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication.",
                "Locate the unverified sender identity.",
                "Follow the verification steps (e.g., click the verification link sent to the from address).",
                "Confirm the identity shows as verified before using it for sending.",
            ],
        },
        record_id=record_id,
    )


def _check_sender_identity_locked(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when a sender identity is locked (may indicate a posture issue)."""
    if record.get("record_type") != SENDGRID_SENDER_IDENTITY:
        return None
    if record.get("locked") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SENDER_IDENTITY_LOCKED,
        finding_key=make_finding_key(_RULE_SENDER_IDENTITY_LOCKED, record_id),
        severity="low",
        title="SendGrid sender identity is locked",
        description=(
            "This SendGrid sender identity is locked. Locked sender identities "
            "cannot be edited and may indicate an identity that is being actively "
            "used by a plan feature or that requires review. This is configuration "
            "evidence for review; it does not confirm any issue with email delivery "
            "or unauthorized access."
        ),
        evidence={
            "rule": _RULE_SENDER_IDENTITY_LOCKED,
            "sender_id": get_str(record, "sender_id"),
            "nickname": get_str(record, "nickname"),
            "verified": record.get("verified"),
            "locked": True,
        },
        remediation={
            "summary": "Review whether the locked sender identity is intentional.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication.",
                "Locate the locked sender identity.",
                "Review whether it is locked due to a plan feature or requires action.",
                "Contact SendGrid support if the lock status is unexpected.",
            ],
        },
        record_id=record_id,
    )


# ── Domain authentication ─────────────────────────────────────────────────────


def _eval_domain_auth(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for check_fn in (
        _check_domain_auth_invalid,
        _check_domain_auto_security_disabled,
        _check_domain_auth_legacy,
        _check_domain_dns_records_missing,          # M80C
        _check_default_domain_auth_invalid,         # M80C
    ):
        f = check_fn(record)
        if f:
            findings.append(f)
    return findings


def _check_domain_auth_invalid(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when domain authentication does not pass all DNS checks."""
    if record.get("record_type") != SENDGRID_DOMAIN_AUTHENTICATION:
        return None
    if record.get("valid") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_DOMAIN_AUTH_INVALID,
        finding_key=make_finding_key(_RULE_DOMAIN_AUTH_INVALID, record_id),
        severity="medium",
        title="SendGrid domain authentication is not passing DNS validation",
        description=(
            "This SendGrid domain authentication is marked as invalid — at least "
            "one DNS record check is not passing. Invalid domain authentication "
            "may affect email deliverability and sender reputation. This is "
            "configuration evidence for review and does not confirm email "
            "delivery failure or data exposure."
        ),
        evidence={
            "rule": _RULE_DOMAIN_AUTH_INVALID,
            "domain_id": get_str(record, "domain_id"),
            "domain": get_str(record, "domain"),
            "valid": False,
            "dns_record_count": record.get("dns_record_count"),
        },
        remediation={
            "summary": "Fix the failing DNS records for this domain authentication.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication.",
                "Select the failing domain and check which DNS records are not validated.",
                "Update your DNS provider to add or correct the required CNAME/TXT records.",
                "Wait for DNS propagation and re-verify the domain in SendGrid.",
            ],
        },
        record_id=record_id,
    )


def _check_domain_auto_security_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when automatic DKIM key rotation is disabled for a domain."""
    if record.get("record_type") != SENDGRID_DOMAIN_AUTHENTICATION:
        return None
    if record.get("automatic_security") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_DOMAIN_AUTO_SECURITY_DISABLED,
        finding_key=make_finding_key(_RULE_DOMAIN_AUTO_SECURITY_DISABLED, record_id),
        severity="medium",
        title="SendGrid domain authentication has automatic security disabled",
        description=(
            "This SendGrid domain authentication does not use automatic DKIM "
            "key rotation (automatic_security=false). Without automatic security, "
            "DKIM keys are static and not automatically rotated, which may increase "
            "long-term key-staleness risk. This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_DOMAIN_AUTO_SECURITY_DISABLED,
            "domain_id": get_str(record, "domain_id"),
            "domain": get_str(record, "domain"),
            "automatic_security": False,
            "valid": record.get("valid"),
        },
        remediation={
            "summary": "Enable automatic security on the domain authentication.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication.",
                "Select the domain and enable automatic security (DKIM rotation).",
                "Update your DNS records with the new CNAME values provided by SendGrid.",
                "Verify the domain passes validation after enabling automatic security.",
            ],
        },
        record_id=record_id,
    )


def _check_domain_auth_legacy(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when a domain uses legacy authentication format."""
    if record.get("record_type") != SENDGRID_DOMAIN_AUTHENTICATION:
        return None
    if record.get("legacy") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_DOMAIN_AUTH_LEGACY,
        finding_key=make_finding_key(_RULE_DOMAIN_AUTH_LEGACY, record_id),
        severity="low",
        title="SendGrid domain is using a legacy authentication format",
        description=(
            "This SendGrid domain authentication uses a legacy format. Legacy "
            "domain authentication may not support modern DKIM rotation and "
            "SendGrid recommends migrating to the current domain authentication "
            "format. This is a configuration posture item for review."
        ),
        evidence={
            "rule": _RULE_DOMAIN_AUTH_LEGACY,
            "domain_id": get_str(record, "domain_id"),
            "domain": get_str(record, "domain"),
            "legacy": True,
            "valid": record.get("valid"),
        },
        remediation={
            "summary": "Migrate to the current SendGrid domain authentication format.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication.",
                "Review the legacy domain and create a new domain authentication entry.",
                "Update your DNS records to use the new CNAME format.",
                "Delete the legacy entry after confirming the new authentication is valid.",
            ],
        },
        record_id=record_id,
    )


# ── Mail settings ─────────────────────────────────────────────────────────────


def _eval_mail_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for check_fn in (
        _check_spam_check_disabled,
        _check_sandbox_mode_enabled,
        _check_bcc_enabled,
        _check_footer_disabled,           # M80C
        _check_bounce_purge_disabled,     # M80C
        _check_template_engine_enabled,   # M80C
    ):
        f = check_fn(record)
        if f:
            findings.append(f)
    return findings


def _check_spam_check_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when spam check is disabled on the SendGrid account."""
    if record.get("record_type") != SENDGRID_MAIL_SETTINGS:
        return None
    if record.get("spam_check_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SPAM_CHECK_DISABLED,
        finding_key=make_finding_key(_RULE_SPAM_CHECK_DISABLED, record_id),
        severity="medium",
        title="SendGrid spam check is disabled",
        description=(
            "The SendGrid spam check mail setting is disabled. With spam check "
            "disabled, outgoing emails are not evaluated for spam-triggering "
            "content before delivery. This may reduce deliverability to spam "
            "filters. This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_SPAM_CHECK_DISABLED,
            "spam_check_enabled": False,
        },
        remediation={
            "summary": "Enable the spam check mail setting.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings.",
                "Enable the Spam Check setting.",
                "Configure the spam check threshold appropriate for your use case.",
            ],
        },
        record_id=record_id,
    )


def _check_sandbox_mode_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when sandbox mode is enabled (emails not actually delivered)."""
    if record.get("record_type") != SENDGRID_MAIL_SETTINGS:
        return None
    if record.get("sandbox_mode_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SANDBOX_MODE_ENABLED,
        finding_key=make_finding_key(_RULE_SANDBOX_MODE_ENABLED, record_id),
        severity="medium",
        title="SendGrid sandbox mode is enabled — emails are not delivered",
        description=(
            "The SendGrid sandbox mode setting is enabled. In sandbox mode, "
            "emails go through the full API processing pipeline but are not "
            "actually delivered to recipients. If sandbox mode is unintentionally "
            "left on in production, live email delivery will be silently suppressed. "
            "This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_SANDBOX_MODE_ENABLED,
            "sandbox_mode_enabled": True,
        },
        remediation={
            "summary": "Disable sandbox mode if emails should be delivered in production.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings.",
                "Disable the Sandbox Mode setting.",
                "Verify that emails are now being delivered to intended recipients.",
            ],
        },
        record_id=record_id,
    )


def _check_bcc_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when BCC (blind carbon copy) mail setting is enabled.

    SECURITY: the BCC email address is NEVER stored — only the enabled boolean.
    """
    if record.get("record_type") != SENDGRID_MAIL_SETTINGS:
        return None
    if record.get("bcc_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_BCC_ENABLED,
        finding_key=make_finding_key(_RULE_BCC_ENABLED, record_id),
        severity="medium",
        title="SendGrid BCC mail setting is enabled",
        description=(
            "The SendGrid BCC mail setting is enabled. When active, a copy of "
            "every outgoing email is sent to a configured BCC address. This "
            "behavior may affect data governance, privacy compliance, and "
            "message volume and may require review. This is configuration "
            "evidence for review and does not confirm data exposure."
        ),
        evidence={
            "rule": _RULE_BCC_ENABLED,
            "bcc_enabled": True,
            # SECURITY: BCC address is NEVER stored in evidence.
        },
        remediation={
            "summary": "Review whether the BCC setting is intentional and compliant.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings.",
                "Locate the BCC setting and review whether it is intentionally enabled.",
                "If not required, disable the BCC setting.",
                "If required, document the business justification and review compliance implications.",
            ],
        },
        record_id=record_id,
    )


# ── Tracking settings ─────────────────────────────────────────────────────────


def _eval_tracking_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for check_fn in (
        _check_click_tracking_enabled,
        _check_open_tracking_enabled,
        _check_subscription_tracking_disabled,
        _check_google_analytics_tracking_enabled,  # M80C
    ):
        f = check_fn(record)
        if f:
            findings.append(f)
    return findings


def _check_click_tracking_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when click tracking is enabled (link rewriting for tracking)."""
    if record.get("record_type") != SENDGRID_TRACKING_SETTINGS:
        return None
    if record.get("click_tracking_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_CLICK_TRACKING_ENABLED,
        finding_key=make_finding_key(_RULE_CLICK_TRACKING_ENABLED, record_id),
        severity="low",
        title="SendGrid click tracking is enabled",
        description=(
            "SendGrid click tracking is enabled. Click tracking rewrites links in "
            "outgoing emails to route through SendGrid tracking URLs before "
            "reaching the destination. This may have privacy and compliance "
            "implications depending on applicable regulations and may require "
            "review. This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_CLICK_TRACKING_ENABLED,
            "click_tracking_enabled": True,
        },
        remediation={
            "summary": "Review whether click tracking is required and compliant.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Tracking.",
                "Review whether click tracking is required for your use case.",
                "Verify that click tracking use is disclosed in your privacy policy if applicable.",
                "Disable click tracking if it is not required or permitted under applicable policies.",
            ],
        },
        record_id=record_id,
    )


def _check_open_tracking_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when open tracking is enabled (tracking pixel in emails)."""
    if record.get("record_type") != SENDGRID_TRACKING_SETTINGS:
        return None
    if record.get("open_tracking_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_OPEN_TRACKING_ENABLED,
        finding_key=make_finding_key(_RULE_OPEN_TRACKING_ENABLED, record_id),
        severity="low",
        title="SendGrid open tracking is enabled",
        description=(
            "SendGrid open tracking is enabled. Open tracking embeds a small "
            "invisible image in outgoing emails to detect when recipients open "
            "them. This may have privacy and compliance implications depending "
            "on applicable regulations (e.g., GDPR, CASL) and may require "
            "review. This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_OPEN_TRACKING_ENABLED,
            "open_tracking_enabled": True,
        },
        remediation={
            "summary": "Review whether open tracking is required and compliant.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Tracking.",
                "Review whether open tracking is required for your use case.",
                "Verify that open tracking use is disclosed in your privacy policy if applicable.",
                "Disable open tracking if it is not required or permitted under applicable policies.",
            ],
        },
        record_id=record_id,
    )


def _check_subscription_tracking_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when subscription/unsubscribe tracking is disabled."""
    if record.get("record_type") != SENDGRID_TRACKING_SETTINGS:
        return None
    if record.get("subscription_tracking_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SUBSCRIPTION_TRACKING_DISABLED,
        finding_key=make_finding_key(_RULE_SUBSCRIPTION_TRACKING_DISABLED, record_id),
        severity="medium",
        title="SendGrid subscription (unsubscribe) tracking is disabled",
        description=(
            "SendGrid subscription tracking is disabled. Subscription tracking "
            "inserts unsubscribe links into outgoing emails, helping with "
            "compliance requirements such as CAN-SPAM and GDPR. Without it, "
            "recipients may not have a clear unsubscribe path, which may "
            "require review for compliance. This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_SUBSCRIPTION_TRACKING_DISABLED,
            "subscription_tracking_enabled": False,
        },
        remediation={
            "summary": "Review whether subscription tracking should be enabled.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Tracking.",
                "Enable Subscription Tracking if you send marketing or commercial emails.",
                "Configure the unsubscribe page and landing URL.",
                "Verify unsubscribe links appear correctly in test emails.",
            ],
        },
        record_id=record_id,
    )


# ── Webhook settings ──────────────────────────────────────────────────────────


def _eval_webhook_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for check_fn in (
        _check_event_webhook_disabled,
        _check_event_webhook_url_missing,
        _check_event_webhook_not_signed,           # M80C QA
        _check_event_webhook_broad_event_stream,   # M80C
        _check_inbound_parse_enabled,              # M80C
        _check_inbound_parse_raw_email_enabled,    # M80C
        _check_inbound_parse_spam_check_disabled,  # M80C
    ):
        f = check_fn(record)
        if f:
            findings.append(f)
    return findings


def _check_event_webhook_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the SendGrid event webhook is disabled."""
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("event_webhook_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_EVENT_WEBHOOK_DISABLED,
        finding_key=make_finding_key(_RULE_EVENT_WEBHOOK_DISABLED, record_id),
        severity="medium",
        title="SendGrid event webhook is disabled",
        description=(
            "The SendGrid event webhook is disabled. Without an active event "
            "webhook, email delivery events (bounces, clicks, opens, spam reports) "
            "are not forwarded to your application. This creates an observability "
            "gap that may affect deliverability monitoring and may require review. "
            "This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_EVENT_WEBHOOK_DISABLED,
            "event_webhook_enabled": False,
        },
        remediation={
            "summary": "Enable the event webhook to restore delivery event observability.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings > Event Webhook.",
                "Enable the webhook and configure a URL that can receive POST events.",
                "Select the event types your application needs to process.",
                "Consider enabling webhook signing to verify event authenticity.",
            ],
        },
        record_id=record_id,
    )


def _check_event_webhook_url_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the event webhook is enabled but has no URL configured.

    SECURITY: webhook URL is stored as a boolean presence flag only — never
    as a string.
    """
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("event_webhook_enabled") is not True:
        return None
    if record.get("event_webhook_has_url") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_EVENT_WEBHOOK_URL_MISSING,
        finding_key=make_finding_key(_RULE_EVENT_WEBHOOK_URL_MISSING, record_id),
        severity="medium",
        title="SendGrid event webhook is enabled but has no URL configured",
        description=(
            "The SendGrid event webhook is enabled but no delivery URL is "
            "configured. Without a URL, enabled webhook events cannot be "
            "delivered to any endpoint. This may indicate an incomplete or "
            "misconfigured webhook setup and may require review. This is "
            "configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_EVENT_WEBHOOK_URL_MISSING,
            "event_webhook_enabled": True,
            "event_webhook_has_url": False,
            "event_count": record.get("event_count"),
        },
        remediation={
            "summary": "Configure a delivery URL for the event webhook.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings > Event Webhook.",
                "Set a valid HTTPS URL that can receive POST events from SendGrid.",
                "Verify the endpoint is reachable and correctly processes event payloads.",
                "Consider enabling webhook signing to verify event authenticity.",
            ],
        },
        record_id=record_id,
    )


def _check_event_webhook_not_signed(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the event webhook is active but webhook signing is not enabled.

    Webhook signing (via OAuth client credentials) lets the receiving endpoint
    verify that events originate from SendGrid. Without signing, the endpoint
    cannot authenticate the event source, which is a meaningful posture gap.

    SECURITY: webhook URL, OAuth client secret, and event payloads are NEVER
    stored — only the enabled and signed booleans are used.
    """
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("event_webhook_enabled") is not True:
        return None
    if record.get("event_webhook_has_url") is not True:
        return None
    if record.get("event_webhook_signed") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_EVENT_WEBHOOK_NOT_SIGNED,
        finding_key=make_finding_key(_RULE_EVENT_WEBHOOK_NOT_SIGNED, record_id),
        severity="medium",
        title="SendGrid event webhook is active but webhook signing is not enabled",
        description=(
            "The SendGrid event webhook is enabled and a URL is configured, but "
            "webhook signing (OAuth-based event verification) is not active. Without "
            "signing, the receiving endpoint cannot verify that delivery events "
            "originate from SendGrid. This is configuration evidence for review and "
            "does not confirm unauthorized access or data exposure."
        ),
        evidence={
            "rule": _RULE_EVENT_WEBHOOK_NOT_SIGNED,
            "event_webhook_enabled": True,
            "event_webhook_has_url": True,
            "event_webhook_signed": False,
            # SECURITY: webhook URL, OAuth secrets, and event payloads NEVER stored.
        },
        remediation={
            "summary": "Enable webhook signing to verify SendGrid event authenticity.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings > Event Webhook.",
                "Enable webhook signing (OAuth) and configure the client credentials.",
                "Update the receiving endpoint to validate the signed event signature.",
                "Verify signed events are being received and validated correctly.",
            ],
        },
        record_id=record_id,
    )


# ── Suppression settings ──────────────────────────────────────────────────────


def _eval_suppression_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    f = _check_suppression_settings_empty(record)
    if f:
        findings.append(f)
    return findings


def _check_suppression_settings_empty(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when no suppression (unsubscribe) groups are configured.

    SECURITY: suppressed email addresses and recipient data are NEVER stored —
    only the group count is used.
    """
    if record.get("record_type") != SENDGRID_SUPPRESSION_SETTINGS:
        return None
    count = record.get("suppression_group_count")
    if not isinstance(count, int):
        return None
    if count != 0:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SUPPRESSION_SETTINGS_EMPTY,
        finding_key=make_finding_key(_RULE_SUPPRESSION_SETTINGS_EMPTY, record_id),
        severity="low",
        title="SendGrid has no suppression groups configured",
        description=(
            "No SendGrid Advanced Suppression Manager (ASM) groups are configured. "
            "Suppression groups allow recipients to selectively unsubscribe from "
            "specific email categories rather than all emails. Without suppression "
            "groups, recipients have fewer unsubscribe options, which may affect "
            "compliance with applicable email regulations. This is configuration "
            "evidence for review."
        ),
        evidence={
            "rule": _RULE_SUPPRESSION_SETTINGS_EMPTY,
            "suppression_group_count": 0,
            # SECURITY: Recipient or suppression email addresses are NEVER stored.
        },
        remediation={
            "summary": "Create suppression groups for your email categories.",
            "steps": [
                "In SendGrid Console, navigate to Marketing > Suppressions > Unsubscribe Groups.",
                "Create groups matching your email categories (e.g., marketing, transactional, product updates).",
                "Update your email templates to reference appropriate unsubscribe groups.",
                "Ensure unsubscribe links are present in all commercial email.",
            ],
        },
        record_id=record_id,
    )


# ── M80C: Sender identity ─────────────────────────────────────────────────────


def _check_sender_reply_domain_mismatch(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when from_email_domain and reply_to_domain differ.

    SECURITY: full email addresses are NEVER stored — only domain parts
    (after @) are used and exposed in evidence.
    """
    if record.get("record_type") != SENDGRID_SENDER_IDENTITY:
        return None
    from_domain = get_str(record, "from_email_domain")
    reply_domain = get_str(record, "reply_to_domain")
    if not from_domain or not reply_domain:
        return None
    if from_domain == reply_domain:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_SENDER_REPLY_DOMAIN_MISMATCH,
        finding_key=make_finding_key(_RULE_SENDER_REPLY_DOMAIN_MISMATCH, record_id),
        severity="low",
        title="SendGrid sender identity reply-to domain differs from from-email domain",
        description=(
            "This SendGrid sender identity is configured with a reply-to domain "
            "that differs from the from-email domain. Mismatched sender and "
            "reply-to domains may indicate a misconfiguration or may affect "
            "deliverability and recipient trust. This is configuration evidence "
            "for review; it does not confirm unauthorized access or data exposure."
        ),
        evidence={
            "rule": _RULE_SENDER_REPLY_DOMAIN_MISMATCH,
            "sender_id": get_str(record, "sender_id"),
            "nickname": get_str(record, "nickname"),
            "from_email_domain": from_domain,
            "reply_to_domain": reply_domain,
            # SECURITY: full email addresses are NEVER stored — domain only.
        },
        remediation={
            "summary": "Review whether the reply-to domain mismatch is intentional.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication.",
                "Locate the sender identity and review the from-email and reply-to fields.",
                "Confirm whether the reply-to domain is intentionally different.",
                "Update the sender identity to align from-email and reply-to domains if needed.",
            ],
        },
        record_id=record_id,
    )


# ── M80C: Domain authentication ───────────────────────────────────────────────


def _check_domain_dns_records_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when a domain authentication has no DNS records configured.

    SECURITY: raw DNS record values are NEVER stored — only the count.
    """
    if record.get("record_type") != SENDGRID_DOMAIN_AUTHENTICATION:
        return None
    count = record.get("dns_record_count")
    if not isinstance(count, int):
        return None
    if count != 0:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_DOMAIN_DNS_RECORDS_MISSING,
        finding_key=make_finding_key(_RULE_DOMAIN_DNS_RECORDS_MISSING, record_id),
        severity="medium",
        title="SendGrid domain authentication has no DNS records configured",
        description=(
            "This SendGrid domain authentication has zero DNS records configured. "
            "Without DNS records, domain authentication cannot be validated and "
            "email deliverability may be affected. This is configuration evidence "
            "for review and does not confirm email delivery failure or data exposure."
        ),
        evidence={
            "rule": _RULE_DOMAIN_DNS_RECORDS_MISSING,
            "domain_id": get_str(record, "domain_id"),
            "domain": get_str(record, "domain"),
            "dns_record_count": 0,
            "valid": record.get("valid"),
        },
        remediation={
            "summary": "Add the required DNS records for this domain authentication.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication.",
                "Select the domain and review the required DNS records.",
                "Add the CNAME or TXT records at your DNS provider.",
                "Wait for DNS propagation and verify the domain in SendGrid.",
            ],
        },
        record_id=record_id,
    )


def _check_default_domain_auth_invalid(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the default domain authentication is invalid.

    This is a stricter variant of sendgrid_domain_authentication_invalid
    targeting only the default sender domain.
    """
    if record.get("record_type") != SENDGRID_DOMAIN_AUTHENTICATION:
        return None
    if record.get("default") is not True:
        return None
    if record.get("valid") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_DEFAULT_DOMAIN_AUTH_INVALID,
        finding_key=make_finding_key(_RULE_DEFAULT_DOMAIN_AUTH_INVALID, record_id),
        severity="high",
        title="SendGrid default domain authentication is not passing DNS validation",
        description=(
            "The default SendGrid domain authentication is marked as invalid. "
            "As the default sender domain, DNS validation failures here may "
            "affect all outgoing email deliverability and sender reputation. "
            "This is configuration evidence for review and does not confirm "
            "email delivery failure or unauthorized access."
        ),
        evidence={
            "rule": _RULE_DEFAULT_DOMAIN_AUTH_INVALID,
            "domain_id": get_str(record, "domain_id"),
            "domain": get_str(record, "domain"),
            "default": True,
            "valid": False,
            "dns_record_count": record.get("dns_record_count"),
        },
        remediation={
            "summary": "Fix the failing DNS records for the default domain authentication.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication.",
                "Select the default domain and check which DNS records are not validated.",
                "Update your DNS provider to add or correct the required CNAME/TXT records.",
                "Wait for DNS propagation and re-verify the domain in SendGrid.",
            ],
        },
        record_id=record_id,
    )


# ── M80C: Mail settings ───────────────────────────────────────────────────────


def _check_footer_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the email footer setting is disabled."""
    if record.get("record_type") != SENDGRID_MAIL_SETTINGS:
        return None
    if record.get("footer_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_FOOTER_DISABLED,
        finding_key=make_finding_key(_RULE_FOOTER_DISABLED, record_id),
        severity="low",
        title="SendGrid email footer is disabled",
        description=(
            "The SendGrid email footer setting is disabled. An email footer "
            "can include required compliance text (such as a physical mailing "
            "address for CAN-SPAM compliance) and unsubscribe information. "
            "Review whether a footer is required for your email program. "
            "This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_FOOTER_DISABLED,
            "footer_enabled": False,
            # SECURITY: footer text content is NEVER stored.
        },
        remediation={
            "summary": "Review whether the email footer should be enabled.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings.",
                "Review the Footer setting and enable it if required by your compliance program.",
                "Configure the footer with required compliance text.",
                "Verify footer appears correctly in test emails.",
            ],
        },
        record_id=record_id,
    )


def _check_bounce_purge_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the bounce purge setting is disabled."""
    if record.get("record_type") != SENDGRID_MAIL_SETTINGS:
        return None
    if record.get("bounce_purge_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_BOUNCE_PURGE_DISABLED,
        finding_key=make_finding_key(_RULE_BOUNCE_PURGE_DISABLED, record_id),
        severity="low",
        title="SendGrid bounce purge is disabled",
        description=(
            "The SendGrid bounce purge mail setting is disabled. Bounce purge "
            "automatically removes addresses from the bounce list after a "
            "configured number of days, helping maintain list hygiene. "
            "Without it, stale bounce entries may accumulate over time. "
            "This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_BOUNCE_PURGE_DISABLED,
            "bounce_purge_enabled": False,
        },
        remediation={
            "summary": "Review whether bounce purge should be enabled.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings.",
                "Enable the Bounce Purge setting and configure the soft/hard bounce thresholds.",
                "Review your current bounce list to understand its size and age.",
            ],
        },
        record_id=record_id,
    )


def _check_template_engine_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the legacy template engine mail setting is enabled.

    SECURITY: template content is NEVER stored — only the enabled boolean.
    """
    if record.get("record_type") != SENDGRID_MAIL_SETTINGS:
        return None
    if record.get("template_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_TEMPLATE_ENGINE_ENABLED,
        finding_key=make_finding_key(_RULE_TEMPLATE_ENGINE_ENABLED, record_id),
        severity="low",
        title="SendGrid legacy template engine is enabled",
        description=(
            "The SendGrid legacy template engine mail setting is enabled. "
            "The legacy template engine applies a default template to all "
            "outgoing messages. This dynamic content surface may require "
            "review to confirm the template is current and intentional. "
            "This is configuration evidence for review; template content "
            "is not stored or inspected."
        ),
        evidence={
            "rule": _RULE_TEMPLATE_ENGINE_ENABLED,
            "template_enabled": True,
            # SECURITY: template HTML/plaintext/content is NEVER stored.
        },
        remediation={
            "summary": "Review whether the legacy template engine setting is intentionally enabled.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings.",
                "Review the Template setting and confirm the template content is current.",
                "Disable the legacy template engine if it is not required.",
                "Consider migrating to SendGrid Dynamic Templates for more control.",
            ],
        },
        record_id=record_id,
    )


# ── M80C: Tracking settings ───────────────────────────────────────────────────


def _check_google_analytics_tracking_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when Google Analytics email tracking is enabled.

    SECURITY: Google Analytics campaign parameters and tracking data are
    NEVER stored — only the enabled boolean.
    """
    if record.get("record_type") != SENDGRID_TRACKING_SETTINGS:
        return None
    if record.get("ganalytics_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_GOOGLE_ANALYTICS_ENABLED,
        finding_key=make_finding_key(_RULE_GOOGLE_ANALYTICS_ENABLED, record_id),
        severity="low",
        title="SendGrid Google Analytics email tracking is enabled",
        description=(
            "SendGrid Google Analytics tracking is enabled. When active, "
            "SendGrid appends UTM tracking parameters to links in outgoing "
            "emails, enabling analytics tracking across email opens and "
            "clicks. This may have privacy and compliance implications "
            "depending on applicable regulations and privacy policies, and "
            "may require review. This is configuration evidence for review."
        ),
        evidence={
            "rule": _RULE_GOOGLE_ANALYTICS_ENABLED,
            "ganalytics_enabled": True,
            # SECURITY: GA campaign parameters and field values are NEVER stored.
        },
        remediation={
            "summary": "Review whether Google Analytics email tracking is required and compliant.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Tracking.",
                "Review whether Google Analytics tracking is required for your use case.",
                "Verify that tracking use is disclosed in your privacy policy if applicable.",
                "Disable Google Analytics tracking if not required or permitted under applicable policies.",
            ],
        },
        record_id=record_id,
    )


# ── M80C: Webhook settings ────────────────────────────────────────────────────


def _check_event_webhook_broad_event_stream(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when the event webhook is enabled with a broad set of event types.

    SECURITY: event payloads, event content, and recipient data are NEVER
    stored — only the enabled boolean and event count are used.
    """
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("event_webhook_enabled") is not True:
        return None
    event_count = record.get("event_count")
    if not isinstance(event_count, int):
        return None
    if event_count <= _BROAD_EVENT_STREAM_THRESHOLD:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_EVENT_WEBHOOK_BROAD_STREAM,
        finding_key=make_finding_key(_RULE_EVENT_WEBHOOK_BROAD_STREAM, record_id),
        severity="low",
        title="SendGrid event webhook is configured with a broad event stream",
        description=(
            f"The SendGrid event webhook is enabled and configured to deliver "
            f"{event_count} event types, which exceeds the review threshold of "
            f"{_BROAD_EVENT_STREAM_THRESHOLD}. A broad event stream may expose "
            f"delivery event metadata (bounces, clicks, opens, spam reports) to "
            f"the webhook endpoint across a wide surface. Review whether all "
            f"configured event types are required by your application. This is "
            f"configuration evidence for review; event payloads are never stored."
        ),
        evidence={
            "rule": _RULE_EVENT_WEBHOOK_BROAD_STREAM,
            "event_webhook_enabled": True,
            "event_count": event_count,
            "threshold": _BROAD_EVENT_STREAM_THRESHOLD,
            # SECURITY: event payloads, recipients, and event content NEVER stored.
        },
        remediation={
            "summary": "Review whether all configured event types are required.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Mail Settings > Event Webhook.",
                "Review the enabled event types and disable any that are not required.",
                "Scope the event stream to only the event types your application processes.",
                "Ensure the webhook endpoint handles all enabled event types securely.",
            ],
        },
        record_id=record_id,
    )


def _check_inbound_parse_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when inbound email parse is enabled.

    SECURITY: inbound parse hostnames, URLs, email bodies, sender/recipient
    addresses, and payload content are NEVER stored — only the boolean flag.
    """
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("inbound_parse_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_INBOUND_PARSE_ENABLED,
        finding_key=make_finding_key(_RULE_INBOUND_PARSE_ENABLED, record_id),
        severity="medium",
        title="SendGrid inbound email parse is enabled",
        description=(
            "SendGrid inbound email parse is enabled. Inbound parse receives "
            "emails sent to a configured hostname and delivers the email content "
            "(including sender, subject, and body) to a webhook endpoint. "
            "This inbound email processing surface may require review to confirm "
            "the configuration is intentional and the receiving endpoint is secure. "
            "This is configuration evidence for review; no hostname, URL, email "
            "content, or recipient data is stored."
        ),
        evidence={
            "rule": _RULE_INBOUND_PARSE_ENABLED,
            "inbound_parse_enabled": True,
            # SECURITY: hostname, URL, email bodies, recipients NEVER stored.
        },
        remediation={
            "summary": "Review whether inbound email parse is intentionally enabled.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Inbound Parse.",
                "Review all configured inbound parse entries.",
                "Confirm each entry is intentional and the receiving endpoint is secure.",
                "Remove any inbound parse entries that are no longer needed.",
            ],
        },
        record_id=record_id,
    )


def _check_inbound_parse_raw_email_enabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when inbound parse is enabled with raw email delivery.

    SECURITY: raw email content, sender/recipient addresses, email bodies,
    and hostnames are NEVER stored — only boolean flags.
    """
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("inbound_parse_enabled") is not True:
        return None
    if record.get("inbound_parse_send_raw_enabled") is not True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_INBOUND_PARSE_RAW_EMAIL,
        finding_key=make_finding_key(_RULE_INBOUND_PARSE_RAW_EMAIL, record_id),
        severity="medium",
        title="SendGrid inbound parse is configured to send raw email content",
        description=(
            "SendGrid inbound parse is enabled and configured to deliver raw "
            "email content (full MIME message including headers, body, and "
            "attachments) to the webhook endpoint. Raw email handling increases "
            "the data sensitivity of the inbound parse surface and may require "
            "additional review of the receiving endpoint's security posture. "
            "This is configuration evidence for review; no email content is stored."
        ),
        evidence={
            "rule": _RULE_INBOUND_PARSE_RAW_EMAIL,
            "inbound_parse_enabled": True,
            "inbound_parse_send_raw_enabled": True,
            # SECURITY: raw email content, bodies, recipients NEVER stored.
        },
        remediation={
            "summary": "Review whether raw email delivery is required for inbound parse.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Inbound Parse.",
                "For each inbound parse entry, review whether 'Send Raw' is required.",
                "Disable raw email delivery if the receiving endpoint only needs parsed fields.",
                "Ensure the webhook endpoint handling raw email content has appropriate security controls.",
            ],
        },
        record_id=record_id,
    )


def _check_inbound_parse_spam_check_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    """Fire when inbound parse is enabled but spam check is disabled."""
    if record.get("record_type") != SENDGRID_WEBHOOK_SETTINGS:
        return None
    if record.get("inbound_parse_enabled") is not True:
        return None
    if record.get("inbound_parse_spam_check_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="sendgrid",
        rule_key=_RULE_INBOUND_PARSE_SPAM_CHECK,
        finding_key=make_finding_key(_RULE_INBOUND_PARSE_SPAM_CHECK, record_id),
        severity="medium",
        title="SendGrid inbound parse spam check is disabled",
        description=(
            "SendGrid inbound parse is enabled but the spam check filter is "
            "disabled. Without spam check, all inbound emails (including "
            "unsolicited or malicious messages) are forwarded to the webhook "
            "endpoint without filtering. This may expose the receiving endpoint "
            "to spam and potentially harmful email content. This is configuration "
            "evidence for review."
        ),
        evidence={
            "rule": _RULE_INBOUND_PARSE_SPAM_CHECK,
            "inbound_parse_enabled": True,
            "inbound_parse_spam_check_enabled": False,
        },
        remediation={
            "summary": "Enable spam check for the inbound parse configuration.",
            "steps": [
                "In SendGrid Console, navigate to Settings > Inbound Parse.",
                "For each inbound parse entry, enable the Spam Check option.",
                "Confirm that the receiving endpoint handles the spam score header if needed.",
            ],
        },
        record_id=record_id,
    )
