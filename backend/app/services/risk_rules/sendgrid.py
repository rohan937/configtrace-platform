"""SendGrid risk classification rules — Changes timeline drift classification.

Entry point: ``classify_sendgrid_change(change)``

Context
-------
Before this module existed, ``risk_service.classify_change`` had no dispatch
entry for ``sendgrid_*`` record types, so every SendGrid Change fell back to
``classify_dns_change`` (the Cloudflare DNS classifier). Since no SendGrid
field_path ever matches a DNS-specific field name, every SendGrid change was
silently classified ``low`` with the generic message "No specific risk
pattern matched. This change may be routine configuration maintenance." —
including changes as significant as an API key becoming full-access or event
webhook signing being disabled. This module gives SendGrid its own
classification so the Changes timeline agrees with the Security Findings
system (``app/services/security_rules/sendgrid.py``), which already
evaluates these fields correctly.

Severity conventions mirror the existing SendGrid security-finding
severities exactly where a corresponding finding exists, so a workspace
never sees a Change and a Finding disagree about how serious something is.

Risk levels
-----------
high    — API key scope broadened to full/admin access.
medium  — Event webhook signing/URL/enablement weakened, domain or sender
          authentication weakened, DKIM auto-rotation disabled, sandbox
          mode enabled, BCC enabled, spam checking disabled, subscription
          tracking disabled, inbound parse enabled/raw-email/spam-check
          weakened.
low     — Restorations/improvements (the inverse of any "medium" case
          above), click/open/Google Analytics tracking toggles either
          direction, cosmetic/identity fields, and record add/remove
          events (reversible, routine lifecycle).

Directionality
---------------
Every classification distinguishes weakening (new_value moves toward the
less-secure/less-observable state) from restoration (new_value moves back
toward the safer/more-observable state) and gives restorations a lower
severity than the corresponding weakening.

Data minimisation
------------------
Only field names and boolean/count/enum values ever appear in risk_reason
text — never API key values, full email addresses, webhook URLs, or raw DNS
values, matching the connector's own privacy contract.

Safe wording
-------------
No risk_reason in this module ever asserts breach, compromise, a leaked
secret, unauthorized access, or data exposure — only configuration evidence
that "may require review".
"""

from __future__ import annotations

from typing import Any

from app.models.change import Change


def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ── sendgrid_account ──────────────────────────────────────────────────────────


def _classify_account_change(change_type: str, field_path: str) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid account record was added or removed during sync.",
        )
    return (
        "low",
        f"SendGrid account field '{field_path}' changed. This is metadata "
        "only and does not affect access or delivery configuration.",
    )


# ── sendgrid_api_key ──────────────────────────────────────────────────────────


def _classify_api_key_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type == "added":
        new_record = new_value if isinstance(new_value, dict) else {}
        if new_record.get("has_full_access") is True:
            return (
                "high",
                "A new SendGrid API key was created with broad or full-access "
                "permissions. This may require review. Configuration evidence "
                "does not confirm compromise, unauthorized access, or data "
                "exposure.",
            )
        return (
            "low",
            "A new SendGrid API key was created.",
        )

    if change_type == "removed":
        return (
            "low",
            "A SendGrid API key was deleted. Any integration still using it "
            "will begin failing authentication.",
        )

    if change_type == "modified" and field_path == "has_full_access":
        if new_value is True:
            return (
                "high",
                "A SendGrid API key's permissions were broadened to include "
                "broad or full-access scopes. This may require review. "
                "Configuration evidence does not confirm compromise, "
                "unauthorized access, or data exposure.",
            )
        return (
            "medium",
            "A SendGrid API key's permissions were restricted away from "
            "broad/full-access scopes — a least-privilege improvement.",
        )

    if change_type == "modified" and field_path == "scopes_count":
        return (
            "low",
            "A SendGrid API key's scope count changed.",
        )

    if change_type == "modified":
        return (
            "low",
            f"SendGrid API key field '{field_path}' changed.",
        )

    return ("low", "SendGrid API key record changed; no specific risk pattern matched.")


# ── sendgrid_sender_identity ──────────────────────────────────────────────────


def _classify_sender_identity_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid sender identity was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "verified":
        if new_value is False:
            return (
                "medium",
                "A SendGrid sender identity became unverified. Mail sent from "
                "this sender may be rejected or flagged by receiving mail "
                "servers. This may require review.",
            )
        return (
            "low",
            "A SendGrid sender identity was verified — a restoration of "
            "sender authentication posture.",
        )

    if change_type == "modified" and field_path == "locked":
        return (
            "low",
            f"SendGrid sender identity lock state changed to '{new_value}'.",
        )

    if change_type == "modified" and field_path in (
        "from_email_domain",
        "reply_to_domain",
        "nickname",
    ):
        return (
            "low",
            f"SendGrid sender identity field '{field_path}' changed.",
        )

    return (
        "low",
        "SendGrid sender identity record changed; no specific risk pattern matched.",
    )


# ── sendgrid_domain_authentication ────────────────────────────────────────────


def _classify_domain_auth_change(
    change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid domain authentication record was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "valid":
        if new_value is False:
            return (
                "medium",
                "A SendGrid authenticated domain became invalid (failed DNS "
                "validation). Mail sent using this domain may fail DKIM/SPF "
                "checks at receiving servers. This may require review.",
            )
        return (
            "low",
            "A SendGrid domain authentication was restored to valid — DNS "
            "validation is passing again.",
        )

    if change_type == "modified" and field_path == "automatic_security":
        if new_value is False:
            return (
                "medium",
                "Automatic DKIM key rotation was disabled for a SendGrid "
                "authenticated domain. This may require review.",
            )
        return (
            "low",
            "Automatic DKIM key rotation was enabled for a SendGrid "
            "authenticated domain.",
        )

    if change_type == "modified" and field_path == "dns_record_count":
        try:
            decreased = prev_value is not None and new_value is not None and new_value < prev_value
        except TypeError:
            decreased = False
        if decreased:
            return (
                "medium",
                "The number of DNS records configured for a SendGrid "
                "authenticated domain decreased. Missing DNS records can "
                "cause domain authentication to fail. This may require review.",
            )
        return (
            "low",
            "The number of DNS records configured for a SendGrid "
            "authenticated domain changed.",
        )

    if change_type == "modified" and field_path in ("legacy", "default", "domain"):
        return (
            "low",
            f"SendGrid domain authentication field '{field_path}' changed.",
        )

    return (
        "low",
        "SendGrid domain authentication record changed; no specific risk "
        "pattern matched.",
    )


# ── sendgrid_mail_settings ─────────────────────────────────────────────────────


def _classify_mail_settings_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid mail settings record was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "sandbox_mode_enabled":
        if new_value is True:
            return (
                "medium",
                "SendGrid sandbox mode was enabled. Outbound mail will be "
                "accepted but NOT actually delivered until sandbox mode is "
                "turned off. This may require review.",
            )
        return (
            "low",
            "SendGrid sandbox mode was disabled — outbound mail delivery "
            "resumed.",
        )

    if change_type == "modified" and field_path == "spam_check_enabled":
        if new_value is False:
            return (
                "medium",
                "SendGrid spam checking was disabled for outbound mail. This "
                "may require review.",
            )
        return (
            "low",
            "SendGrid spam checking was enabled for outbound mail.",
        )

    if change_type == "modified" and field_path == "bcc_enabled":
        if new_value is True:
            return (
                "medium",
                "SendGrid BCC mail setting was enabled — a copy of every "
                "outbound email will now be sent to a configured address. "
                "This may require review.",
            )
        return (
            "low",
            "SendGrid BCC mail setting was disabled.",
        )

    if change_type == "modified" and field_path in (
        "footer_enabled",
        "bounce_purge_enabled",
        "forward_bounce_enabled",
        "forward_spam_enabled",
        "template_enabled",
    ):
        return (
            "low",
            f"SendGrid mail setting '{field_path}' changed to '{new_value}'.",
        )

    return (
        "low",
        "SendGrid mail settings changed; no specific risk pattern matched.",
    )


# ── sendgrid_tracking_settings ────────────────────────────────────────────────


def _classify_tracking_settings_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid tracking settings record was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "subscription_tracking_enabled":
        if new_value is False:
            return (
                "medium",
                "SendGrid subscription tracking was disabled. Outbound email "
                "will no longer include an unsubscribe link, which may affect "
                "compliance posture. This may require review.",
            )
        return (
            "low",
            "SendGrid subscription tracking was enabled — an unsubscribe "
            "link will be included in outbound mail.",
        )

    if change_type == "modified" and field_path in (
        "click_tracking_enabled",
        "open_tracking_enabled",
        "ganalytics_enabled",
    ):
        return (
            "low",
            f"SendGrid tracking setting '{field_path}' changed to "
            f"'{new_value}'. This is a configuration/privacy posture change "
            "and may require review.",
        )

    return (
        "low",
        "SendGrid tracking settings changed; no specific risk pattern matched.",
    )


# ── sendgrid_webhook_settings ──────────────────────────────────────────────────


def _classify_webhook_settings_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid event webhook settings record was added or removed "
            "during sync.",
        )

    if change_type == "modified" and field_path == "event_webhook_enabled":
        if new_value is False:
            return (
                "medium",
                "The SendGrid event webhook was disabled. Delivery events "
                "(bounces, clicks, opens, spam reports) will no longer be "
                "forwarded. This may require review.",
            )
        return (
            "low",
            "The SendGrid event webhook was re-enabled.",
        )

    if change_type == "modified" and field_path == "event_webhook_has_url":
        if new_value is False:
            return (
                "medium",
                "The SendGrid event webhook no longer has a delivery URL "
                "configured. Enabled events cannot be delivered until a URL "
                "is set. This may require review.",
            )
        return (
            "low",
            "A delivery URL was configured for the SendGrid event webhook.",
        )

    if change_type == "modified" and field_path == "event_webhook_signed":
        if new_value is False:
            return (
                "medium",
                "SendGrid event webhook signing was disabled. The receiving "
                "endpoint can no longer verify that delivery events "
                "originate from SendGrid. This may require review. "
                "Configuration evidence does not confirm unauthorized "
                "access or data exposure.",
            )
        return (
            "low",
            "SendGrid event webhook signing was enabled — event "
            "authenticity verification restored.",
        )

    if change_type == "modified" and field_path == "inbound_parse_enabled":
        if new_value is True:
            return (
                "medium",
                "SendGrid Inbound Parse was enabled, allowing inbound email "
                "to be parsed and posted to a configured endpoint. This may "
                "require review.",
            )
        return (
            "low",
            "SendGrid Inbound Parse was disabled.",
        )

    if change_type == "modified" and field_path == "inbound_parse_send_raw_enabled":
        if new_value is True:
            return (
                "medium",
                "SendGrid Inbound Parse was configured to send the raw, "
                "unparsed MIME message, which may include a broader set of "
                "email content than the parsed fields. This may require "
                "review.",
            )
        return (
            "low",
            "SendGrid Inbound Parse raw-message delivery was disabled.",
        )

    if change_type == "modified" and field_path == "inbound_parse_spam_check_enabled":
        if new_value is False:
            return (
                "medium",
                "Spam checking was disabled for SendGrid Inbound Parse. This "
                "may require review.",
            )
        return (
            "low",
            "Spam checking was enabled for SendGrid Inbound Parse.",
        )

    if change_type == "modified" and field_path == "event_count":
        return (
            "low",
            "The number of subscribed SendGrid webhook event types changed.",
        )

    return (
        "low",
        "SendGrid event webhook settings changed; no specific risk pattern "
        "matched.",
    )


# ── sendgrid_suppression_settings ─────────────────────────────────────────────


def _classify_suppression_settings_change(
    change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "SendGrid suppression settings record was added or removed "
            "during sync.",
        )

    if change_type == "modified" and field_path == "suppression_group_count":
        if new_value == 0 and (prev_value or 0) > 0:
            return (
                "low",
                "SendGrid has no suppression groups configured. Recipients "
                "who opt out may not be tracked centrally. This may require "
                "review.",
            )
        return (
            "low",
            "The number of SendGrid suppression groups changed.",
        )

    return (
        "low",
        "SendGrid suppression settings changed; no specific risk pattern "
        "matched.",
    )


# ── Dispatcher ─────────────────────────────────────────────────────────────────


def classify_sendgrid_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a SendGrid change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``sendgrid_account``               → account rules
      * ``sendgrid_api_key``                → API key scope rules
      * ``sendgrid_sender_identity``        → sender verification rules
      * ``sendgrid_domain_authentication``  → domain auth rules
      * ``sendgrid_mail_settings``          → mail settings rules
      * ``sendgrid_tracking_settings``      → tracking settings rules
      * ``sendgrid_webhook_settings``       → event webhook / inbound parse rules
      * ``sendgrid_suppression_settings``   → suppression settings rules

    Args:
        change: A ``Change`` ORM instance (or a plain dict, for testing).

    Returns:
        ``(risk_level, risk_reason)`` where risk_level is one of
        ``"high"``, ``"medium"``, ``"low"`` (SendGrid has no ``"critical"``
        classification — no modeled field can take mail delivery
        infrastructure fully offline the way, e.g., a DNS record removal can).
    """
    pm = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower() if isinstance(pm, dict) else ""

    change_type = (_get(change, "change_type") or "").lower()
    field_path = _get(change, "field_path") or ""
    prev_value = _get(change, "prev_value")
    new_value = _get(change, "new_value")

    if record_type == "sendgrid_account":
        return _classify_account_change(change_type, field_path)
    if record_type == "sendgrid_api_key":
        return _classify_api_key_change(change_type, field_path, new_value)
    if record_type == "sendgrid_sender_identity":
        return _classify_sender_identity_change(change_type, field_path, new_value)
    if record_type == "sendgrid_domain_authentication":
        return _classify_domain_auth_change(change_type, field_path, prev_value, new_value)
    if record_type == "sendgrid_mail_settings":
        return _classify_mail_settings_change(change_type, field_path, new_value)
    if record_type == "sendgrid_tracking_settings":
        return _classify_tracking_settings_change(change_type, field_path, new_value)
    if record_type == "sendgrid_webhook_settings":
        return _classify_webhook_settings_change(change_type, field_path, new_value)
    if record_type == "sendgrid_suppression_settings":
        return _classify_suppression_settings_change(
            change_type, field_path, prev_value, new_value
        )

    return (
        "low",
        "An unrecognised SendGrid configuration record changed. This may be "
        "a new record type introduced in a future update.",
    )
