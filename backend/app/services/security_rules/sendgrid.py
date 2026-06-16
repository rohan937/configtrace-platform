"""SendGrid configuration-risk security rules — M80B.

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

Rules deferred (insufficient M80A fields)
-----------------------------------------
  sendgrid_api_key_stale         — requires date fields (created_at/date_updated)
                                   not present in M80A sendgrid_api_key schema.
  sendgrid_inbound_parse_enabled — requires inbound_parse_enabled field not
                                   present in M80A sendgrid_webhook_settings schema.
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

SENDGRID_RULE_KEYS: frozenset[str] = frozenset({
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
