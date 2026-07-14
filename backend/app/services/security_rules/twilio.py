"""Twilio security / configuration-risk rules — M79B / M79C.

Every rule fires only on explicit, reliable normalized fields produced by the
Twilio connector (app/connectors/twilio.py + twilio_schema.py). Evidence is
metadata-only: SIDs, friendly names, phone_number_last4, capability booleans,
webhook presence booleans, webhook URL *scheme* only ("http"/"https" — never
the host, path, query string, or full URL), code length, and account status
strings. No auth_token, API key secret, full phone number strings, webhook
URL/host/path/query strings, message bodies, call logs, recording data,
customer PII, or raw API responses are ever read, stored, or surfaced.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review or may
indicate a gap in webhook/verification configuration. A finding is evidence
for review only. It never asserts unauthorized access, that messages were
intercepted, that calls were compromised, that customer data was exposed,
that a breach occurred, or that any attacker is present.

Record types consumed (M79A)
----------------------------
- ``twilio_incoming_phone_number`` → SMS/voice webhook missing, status
                                       callback missing, webhook uses HTTP
- ``twilio_messaging_service``    → inbound webhook missing, fallback URL
                                       missing, status callback URL missing,
                                       webhook uses HTTP
- ``twilio_verify_service``       → short code length, lookup disabled
- ``twilio_account``              → non-active account status
- ``twilio_api_key_summary``      → stale API key (M79C)

Webhook scheme (transport posture) rule
----------------------------------------
  twilio_webhook_uses_http — fires once per webhook field (SMS/voice/status
    callback on a phone number; inbound/fallback/status callback on a
    Messaging Service) whose scheme is explicitly resolved to "http".
    Severity "high" — the one exception to this module's otherwise-medium
    ceiling, matching the equivalent GitHub webhook-HTTP convention. Never
    fires on an unknown/unparseable/missing scheme.

M79C expansion rules
--------------------
Eight additional rules added in M79C:
  twilio_api_key_stale                             — API key not updated in 180+ days
  twilio_messaging_service_observability_gap       — both fallback and status callback absent
  twilio_messaging_service_number_level_inbound_webhook — number-level inbound delegation
  twilio_messaging_service_long_validity_period    — validity period > 24 h
  twilio_phone_number_messaging_observability_gap  — SMS capable; no webhook or status callback
  twilio_phone_number_voice_observability_gap      — voice capable; no webhook or status callback
  twilio_verify_psd2_disabled                      — PSD2/SCA not enabled
  twilio_verify_sms_to_landlines_allowed           — landline SMS filtering not enabled

Deferred (M79C): twilio_api_key_update_metadata_missing — too speculative without
confirming when date_updated is systematically absent vs. just old; deferred to a
future milestone once connector metadata patterns are better understood.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.connectors.twilio_schema import (
    TWILIO_ACCOUNT,
    TWILIO_API_KEY_SUMMARY,
    TWILIO_INCOMING_PHONE_NUMBER,
    TWILIO_MESSAGING_SERVICE,
    TWILIO_VERIFY_SERVICE,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys — M79B ──────────────────────────────────────────────────────────

_RULE_PHONE_SMS_WEBHOOK_MISSING = "twilio_phone_number_sms_webhook_missing"
_RULE_PHONE_VOICE_WEBHOOK_MISSING = "twilio_phone_number_voice_webhook_missing"
_RULE_PHONE_STATUS_CALLBACK_MISSING = "twilio_phone_number_status_callback_missing"
_RULE_MSG_INBOUND_WEBHOOK_MISSING = "twilio_messaging_service_inbound_webhook_missing"
_RULE_MSG_FALLBACK_MISSING = "twilio_messaging_service_fallback_missing"
_RULE_MSG_STATUS_CALLBACK_MISSING = "twilio_messaging_service_status_callback_missing"
_RULE_VERIFY_SHORT_CODE = "twilio_verify_short_code_length"
_RULE_VERIFY_LOOKUP_DISABLED = "twilio_verify_lookup_disabled"
_RULE_ACCOUNT_SUSPENDED = "twilio_account_suspended"

# ── Rule keys — M79C ──────────────────────────────────────────────────────────

_RULE_API_KEY_STALE = "twilio_api_key_stale"
_RULE_MSG_OBSERVABILITY_GAP = "twilio_messaging_service_observability_gap"
_RULE_MSG_NUMBER_LEVEL_INBOUND = "twilio_messaging_service_number_level_inbound_webhook"
_RULE_MSG_LONG_VALIDITY = "twilio_messaging_service_long_validity_period"
_RULE_PHONE_MESSAGING_OBS_GAP = "twilio_phone_number_messaging_observability_gap"
_RULE_PHONE_VOICE_OBS_GAP = "twilio_phone_number_voice_observability_gap"
_RULE_VERIFY_PSD2_DISABLED = "twilio_verify_psd2_disabled"
_RULE_VERIFY_SMS_TO_LANDLINES = "twilio_verify_sms_to_landlines_allowed"

# ── Rule keys — webhook scheme (transport posture) ────────────────────────────

_RULE_WEBHOOK_USES_HTTP = "twilio_webhook_uses_http"

_STALE_THRESHOLD_DAYS = 180

TWILIO_RULE_KEYS: frozenset[str] = frozenset({
    # M79B
    _RULE_PHONE_SMS_WEBHOOK_MISSING,
    _RULE_PHONE_VOICE_WEBHOOK_MISSING,
    _RULE_PHONE_STATUS_CALLBACK_MISSING,
    _RULE_MSG_INBOUND_WEBHOOK_MISSING,
    _RULE_MSG_FALLBACK_MISSING,
    _RULE_MSG_STATUS_CALLBACK_MISSING,
    _RULE_VERIFY_SHORT_CODE,
    _RULE_VERIFY_LOOKUP_DISABLED,
    _RULE_ACCOUNT_SUSPENDED,
    # M79C
    _RULE_API_KEY_STALE,
    _RULE_MSG_OBSERVABILITY_GAP,
    _RULE_MSG_NUMBER_LEVEL_INBOUND,
    _RULE_MSG_LONG_VALIDITY,
    _RULE_PHONE_MESSAGING_OBS_GAP,
    _RULE_PHONE_VOICE_OBS_GAP,
    _RULE_VERIFY_PSD2_DISABLED,
    _RULE_VERIFY_SMS_TO_LANDLINES,
    # Webhook scheme
    _RULE_WEBHOOK_USES_HTTP,
})


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == TWILIO_INCOMING_PHONE_NUMBER:
        return _eval_phone_number(record)
    if rtype == TWILIO_MESSAGING_SERVICE:
        return _eval_messaging_service(record)
    if rtype == TWILIO_VERIFY_SERVICE:
        return _eval_verify_service(record)
    if rtype == TWILIO_ACCOUNT:
        return _eval_account(record)
    if rtype == TWILIO_API_KEY_SUMMARY:
        return _eval_api_key(record)
    return []


# ── Incoming phone numbers ────────────────────────────────────────────────────


def _check_phone_number_sms_webhook_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_INCOMING_PHONE_NUMBER:
        return None
    if record.get("capability_sms") is not True:
        return None
    if record.get("sms_url_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_PHONE_SMS_WEBHOOK_MISSING,
        finding_key=make_finding_key(_RULE_PHONE_SMS_WEBHOOK_MISSING, record_id),
        severity="medium",
        title="Twilio phone number has SMS capability but no SMS webhook configured",
        description=(
            "This phone number can receive SMS messages but no inbound webhook "
            "URL is configured. Inbound messages may be silently dropped. "
            "Review whether this requires a webhook endpoint. This is evidence "
            "for review and does not confirm compromise, unauthorized access, "
            "or data exposure."
        ),
        evidence={
            "rule": _RULE_PHONE_SMS_WEBHOOK_MISSING,
            "phone_number_sid": get_str(record, "phone_number_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "phone_number_last4": get_str(record, "phone_number_last4"),
            "iso_country": get_str(record, "iso_country"),
            "capability_sms": True,
        },
        remediation={
            "summary": "Configure an SMS webhook URL for this phone number.",
            "steps": [
                "In the Twilio Console, navigate to Phone Numbers > Manage > Active numbers.",
                "Select this number and set an SMS webhook URL under the Messaging section.",
                "Verify the endpoint is reachable and handles inbound messages correctly.",
            ],
        },
        record_id=record_id,
    )


def _check_phone_number_voice_webhook_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_INCOMING_PHONE_NUMBER:
        return None
    if record.get("capability_voice") is not True:
        return None
    if record.get("voice_url_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_PHONE_VOICE_WEBHOOK_MISSING,
        finding_key=make_finding_key(_RULE_PHONE_VOICE_WEBHOOK_MISSING, record_id),
        severity="medium",
        title="Twilio phone number has voice capability but no voice webhook configured",
        description=(
            "This phone number can receive voice calls but no inbound webhook "
            "URL is configured. Inbound calls may fail or use default handling. "
            "Review whether this configuration is intentional. This is evidence "
            "for review and does not confirm compromise, unauthorized access, "
            "or data exposure."
        ),
        evidence={
            "rule": _RULE_PHONE_VOICE_WEBHOOK_MISSING,
            "phone_number_sid": get_str(record, "phone_number_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "phone_number_last4": get_str(record, "phone_number_last4"),
            "iso_country": get_str(record, "iso_country"),
            "capability_voice": True,
        },
        remediation={
            "summary": "Configure a voice webhook URL for this phone number.",
            "steps": [
                "In the Twilio Console, navigate to Phone Numbers > Manage > Active numbers.",
                "Select this number and set a voice webhook URL under the Voice section.",
                "Verify the endpoint is reachable and handles inbound calls correctly.",
            ],
        },
        record_id=record_id,
    )


def _check_phone_number_status_callback_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_INCOMING_PHONE_NUMBER:
        return None
    has_sms = record.get("capability_sms")
    has_voice = record.get("capability_voice")
    if not (has_sms or has_voice):
        return None
    if record.get("status_callback_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_PHONE_STATUS_CALLBACK_MISSING,
        finding_key=make_finding_key(_RULE_PHONE_STATUS_CALLBACK_MISSING, record_id),
        severity="low",
        title="Twilio phone number has no status callback configured",
        description=(
            "This phone number has no status callback URL configured. Message "
            "and call delivery status updates may not be observable. Review "
            "whether this requires a status callback endpoint. This is evidence "
            "for review and does not confirm compromise, unauthorized access, "
            "or data exposure."
        ),
        evidence={
            "rule": _RULE_PHONE_STATUS_CALLBACK_MISSING,
            "phone_number_sid": get_str(record, "phone_number_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "phone_number_last4": get_str(record, "phone_number_last4"),
            "iso_country": get_str(record, "iso_country"),
            "capability_sms": bool(has_sms),
            "capability_voice": bool(has_voice),
        },
        remediation={
            "summary": "Configure a status callback URL for this phone number if delivery observability is required.",
            "steps": [
                "In the Twilio Console, navigate to Phone Numbers > Manage > Active numbers.",
                "Select this number and set a status callback URL.",
                "Verify the endpoint handles status update payloads.",
            ],
        },
        record_id=record_id,
    )


def _eval_phone_number(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    for check_fn in (
        _check_phone_number_sms_webhook_missing,
        _check_phone_number_voice_webhook_missing,
        _check_phone_number_status_callback_missing,
        _check_phone_number_messaging_observability_gap,
        _check_phone_number_voice_observability_gap,
    ):
        result = check_fn(record)
        if result is not None:
            out.append(result)
    out.extend(_check_phone_number_webhook_uses_http(record))
    return out


def _check_phone_number_webhook_uses_http(
    record: dict[str, Any],
) -> list[FindingCandidate]:
    """Fire once per webhook field on this phone number whose scheme is
    explicitly ``"http"``. Unknown/missing scheme (``None``, e.g. no webhook
    configured, or a scheme the connector couldn't parse) never fires — only
    an explicitly-resolved ``"http"`` does.

    SECURITY: only the scheme string ("http") is ever read or surfaced in
    evidence — never the host, path, query string, or full URL, which the
    connector never stores in the first place.
    """
    if record.get("record_type") != TWILIO_INCOMING_PHONE_NUMBER:
        return []
    record_id = get_str(record, "record_id") or None
    out: list[FindingCandidate] = []
    for field, kind in (
        ("sms_url_scheme", "SMS"),
        ("voice_url_scheme", "voice"),
        ("status_callback_scheme", "status callback"),
    ):
        if record.get(field) != "http":
            continue
        finding_key_discriminator = f"{record_id}:{field}" if record_id else field
        out.append(
            FindingCandidate(
                provider="twilio",
                rule_key=_RULE_WEBHOOK_USES_HTTP,
                finding_key=make_finding_key(_RULE_WEBHOOK_USES_HTTP, finding_key_discriminator),
                severity="high",
                title="Twilio webhook uses HTTP",
                description=(
                    f"This Twilio phone number's {kind} webhook uses plain HTTP "
                    "instead of HTTPS. Webhook transport verification is "
                    "weakened. This may require review. Configuration evidence "
                    "does not confirm compromise, unauthorized access, message "
                    "exposure, or data exposure."
                ),
                evidence={
                    "rule": _RULE_WEBHOOK_USES_HTTP,
                    "phone_number_sid": get_str(record, "phone_number_sid"),
                    "friendly_name": get_str(record, "friendly_name"),
                    "webhook_field": field,
                    "scheme": "http",
                },
                remediation={
                    "summary": "Switch this webhook to an HTTPS endpoint.",
                    "steps": [
                        "In the Twilio Console, navigate to Phone Numbers > Manage > Active numbers.",
                        "Update the webhook URL to use https:// instead of http://.",
                        "Verify the HTTPS endpoint is reachable and presents a valid certificate.",
                    ],
                },
                record_id=record_id,
            )
        )
    return out


# ── Messaging services ────────────────────────────────────────────────────────


def _check_messaging_service_inbound_webhook_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return None
    if record.get("inbound_request_url_configured") is not False:
        return None
    if record.get("use_inbound_webhook_on_number") is True:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_MSG_INBOUND_WEBHOOK_MISSING,
        finding_key=make_finding_key(_RULE_MSG_INBOUND_WEBHOOK_MISSING, record_id),
        severity="medium",
        title="Twilio Messaging Service has no inbound webhook configured",
        description=(
            "This Messaging Service has no inbound webhook URL and is not "
            "configured to use number-level webhooks. Inbound messages may not "
            "be handled. Review webhook configuration. This is evidence for "
            "review and does not confirm compromise, unauthorized access, or "
            "data exposure."
        ),
        evidence={
            "rule": _RULE_MSG_INBOUND_WEBHOOK_MISSING,
            "messaging_service_sid": get_str(record, "messaging_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "inbound_request_url_configured": False,
            "use_inbound_webhook_on_number": bool(
                record.get("use_inbound_webhook_on_number")
            ),
        },
        remediation={
            "summary": "Configure an inbound webhook URL or enable number-level webhooks for this Messaging Service.",
            "steps": [
                "In the Twilio Console, navigate to Messaging > Services.",
                "Select this service and configure an inbound webhook URL under Integration settings.",
                "Alternatively, enable 'Use inbound webhook on number' if number-level handling is preferred.",
            ],
        },
        record_id=record_id,
    )


def _check_messaging_service_fallback_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return None
    if record.get("fallback_url_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_MSG_FALLBACK_MISSING,
        finding_key=make_finding_key(_RULE_MSG_FALLBACK_MISSING, record_id),
        severity="low",
        title="Twilio Messaging Service has no fallback URL configured",
        description=(
            "This Messaging Service has no fallback URL. If the primary webhook "
            "fails, messages will not have a secondary handler. Review whether "
            "a fallback is required for reliability. This is evidence for review "
            "and does not confirm compromise, unauthorized access, or data "
            "exposure."
        ),
        evidence={
            "rule": _RULE_MSG_FALLBACK_MISSING,
            "messaging_service_sid": get_str(record, "messaging_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "fallback_url_configured": False,
        },
        remediation={
            "summary": "Configure a fallback URL for this Messaging Service if reliability is required.",
            "steps": [
                "In the Twilio Console, navigate to Messaging > Services.",
                "Select this service and configure a fallback URL under Integration settings.",
                "Verify the fallback endpoint can handle inbound message payloads.",
            ],
        },
        record_id=record_id,
    )


def _check_messaging_service_status_callback_missing(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return None
    if record.get("status_callback_url_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_MSG_STATUS_CALLBACK_MISSING,
        finding_key=make_finding_key(_RULE_MSG_STATUS_CALLBACK_MISSING, record_id),
        severity="low",
        title="Twilio Messaging Service has no status callback URL configured",
        description=(
            "This Messaging Service has no status callback URL. Message delivery "
            "status updates will not be reported. Review whether this requires "
            "status callback configuration. This is evidence for review and does "
            "not confirm compromise, unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_MSG_STATUS_CALLBACK_MISSING,
            "messaging_service_sid": get_str(record, "messaging_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "status_callback_url_configured": False,
        },
        remediation={
            "summary": "Configure a status callback URL for this Messaging Service if delivery observability is required.",
            "steps": [
                "In the Twilio Console, navigate to Messaging > Services.",
                "Select this service and configure a status callback URL under Integration settings.",
                "Verify the endpoint handles delivery status update payloads.",
            ],
        },
        record_id=record_id,
    )


def _eval_messaging_service(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    for check_fn in (
        _check_messaging_service_inbound_webhook_missing,
        _check_messaging_service_fallback_missing,
        _check_messaging_service_status_callback_missing,
        _check_messaging_service_observability_gap,
        _check_messaging_service_number_level_inbound_webhook,
        _check_messaging_service_long_validity_period,
    ):
        result = check_fn(record)
        if result is not None:
            out.append(result)
    out.extend(_check_messaging_service_webhook_uses_http(record))
    return out


def _check_messaging_service_webhook_uses_http(
    record: dict[str, Any],
) -> list[FindingCandidate]:
    """Fire once per webhook field on this Messaging Service whose scheme is
    explicitly ``"http"``. Unknown/missing scheme never fires.

    SECURITY: only the scheme string ("http") is ever read or surfaced in
    evidence — never the host, path, query string, or full URL.
    """
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return []
    record_id = get_str(record, "record_id") or None
    out: list[FindingCandidate] = []
    for field, kind in (
        ("inbound_request_url_scheme", "inbound"),
        ("fallback_url_scheme", "fallback"),
        ("status_callback_url_scheme", "status callback"),
    ):
        if record.get(field) != "http":
            continue
        finding_key_discriminator = f"{record_id}:{field}" if record_id else field
        out.append(
            FindingCandidate(
                provider="twilio",
                rule_key=_RULE_WEBHOOK_USES_HTTP,
                finding_key=make_finding_key(_RULE_WEBHOOK_USES_HTTP, finding_key_discriminator),
                severity="high",
                title="Twilio webhook uses HTTP",
                description=(
                    f"This Twilio Messaging Service's {kind} webhook uses plain "
                    "HTTP instead of HTTPS. Webhook transport verification is "
                    "weakened. This may require review. Configuration evidence "
                    "does not confirm compromise, unauthorized access, message "
                    "exposure, or data exposure."
                ),
                evidence={
                    "rule": _RULE_WEBHOOK_USES_HTTP,
                    "messaging_service_sid": get_str(record, "messaging_service_sid"),
                    "friendly_name": get_str(record, "friendly_name"),
                    "webhook_field": field,
                    "scheme": "http",
                },
                remediation={
                    "summary": "Switch this webhook to an HTTPS endpoint.",
                    "steps": [
                        "In the Twilio Console, navigate to Messaging > Services.",
                        "Update the webhook URL to use https:// instead of http://.",
                        "Verify the HTTPS endpoint is reachable and presents a valid certificate.",
                    ],
                },
                record_id=record_id,
            )
        )
    return out


# ── Verify services ───────────────────────────────────────────────────────────


def _check_verify_short_code_length(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_VERIFY_SERVICE:
        return None
    code_length = record.get("code_length")
    if not isinstance(code_length, int):
        return None
    if code_length >= 6:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_VERIFY_SHORT_CODE,
        finding_key=make_finding_key(_RULE_VERIFY_SHORT_CODE, record_id),
        severity="medium",
        title="Twilio Verify Service uses a short verification code length",
        description=(
            "This Verify Service is configured with fewer than 6 digits for "
            "verification codes. Shorter codes may be more susceptible to "
            "brute-force enumeration. Review whether the code length meets "
            "your security requirements. This is evidence for review and does "
            "not confirm compromise, unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_VERIFY_SHORT_CODE,
            "verify_service_sid": get_str(record, "verify_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "code_length": code_length,
        },
        remediation={
            "summary": "Increase the verification code length to 6 or more digits.",
            "steps": [
                "In the Twilio Console, navigate to Verify > Services.",
                "Select this service and increase the code length to at least 6 digits.",
                "Test verification flows after changing the code length.",
            ],
        },
        record_id=record_id,
    )


def _check_verify_lookup_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_VERIFY_SERVICE:
        return None
    if record.get("lookup_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_VERIFY_LOOKUP_DISABLED,
        finding_key=make_finding_key(_RULE_VERIFY_LOOKUP_DISABLED, record_id),
        severity="low",
        title="Twilio Verify Service has phone number lookup disabled",
        description=(
            "This Verify Service does not have phone number lookup enabled. "
            "Lookup can help detect invalid or non-reachable numbers before "
            "sending verification codes. Review whether this is intentional. "
            "This is evidence for review and does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_VERIFY_LOOKUP_DISABLED,
            "verify_service_sid": get_str(record, "verify_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "lookup_enabled": False,
        },
        remediation={
            "summary": "Review whether phone number lookup should be enabled for this Verify Service.",
            "steps": [
                "In the Twilio Console, navigate to Verify > Services.",
                "Select this service and review the phone number lookup setting.",
                "Enable lookup if you want to validate numbers before sending codes.",
            ],
        },
        record_id=record_id,
    )


def _eval_verify_service(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    for check_fn in (
        _check_verify_short_code_length,
        _check_verify_lookup_disabled,
        _check_verify_psd2_disabled,
        _check_verify_sms_to_landlines_allowed,
    ):
        result = check_fn(record)
        if result is not None:
            out.append(result)
    return out


# ── Account ───────────────────────────────────────────────────────────────────


def _check_account_suspended(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_ACCOUNT:
        return None
    status = get_str(record, "status").lower()
    if status in ("active", ""):
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_ACCOUNT_SUSPENDED,
        finding_key=make_finding_key(_RULE_ACCOUNT_SUSPENDED, record_id),
        severity="low",
        title="Twilio account is not in active status",
        description=(
            "This Twilio account has a non-active status. Review whether this "
            "status reflects an intended configuration or requires action. "
            "This is evidence for review and does not confirm compromise, "
            "unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_ACCOUNT_SUSPENDED,
            "account_sid_prefix": get_str(record, "account_sid_prefix"),
            "friendly_name": get_str(record, "friendly_name"),
            "status": status,
            "account_type": get_str(record, "account_type"),
        },
        remediation={
            "summary": "Review the account status in the Twilio Console and take action if needed.",
            "steps": [
                "Log in to the Twilio Console and review the account status.",
                "If the status is not intentional, contact Twilio support.",
                "Verify that all services relying on this account are functioning as expected.",
            ],
        },
        record_id=record_id,
    )


def _eval_account(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    result = _check_account_suspended(record)
    if result is not None:
        out.append(result)
    return out


# ── M79C expansion rules ──────────────────────────────────────────────────────


def _check_api_key_stale(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_API_KEY_SUMMARY:
        return None
    date_str = record.get("date_updated") or record.get("date_created")
    if not date_str:
        return None
    try:
        date_str_clean = str(date_str).replace("Z", "+00:00")
        key_date = datetime.fromisoformat(date_str_clean)
        if key_date.tzinfo is None:
            key_date = key_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - key_date).days
        if age_days < _STALE_THRESHOLD_DAYS:
            return None
    except (ValueError, TypeError):
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_API_KEY_STALE,
        finding_key=make_finding_key(_RULE_API_KEY_STALE, record_id),
        severity="medium",
        title="Twilio API key has not been updated recently",
        description=(
            f"This Twilio API key metadata indicates the key has not been updated in "
            f"over {_STALE_THRESHOLD_DAYS} days. Stale API keys may require review to "
            f"confirm they are still in use and meet current security requirements. "
            f"This is evidence for review and does not confirm compromise or "
            f"unauthorized access."
        ),
        evidence={
            "rule": _RULE_API_KEY_STALE,
            "api_key_sid": get_str(record, "api_key_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "date_created": get_str(record, "date_created"),
            "date_updated": get_str(record, "date_updated"),
        },
        remediation={
            "summary": "Review active API keys and rotate or deactivate any that are stale.",
            "steps": [
                "In the Twilio Console, navigate to Account > API keys & tokens.",
                "Identify keys that have not been updated recently and confirm they are still needed.",
                "Rotate or delete any keys that are no longer in use or no longer meet policy requirements.",
            ],
        },
        record_id=record_id,
    )


def _eval_api_key(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    result = _check_api_key_stale(record)
    if result is not None:
        out.append(result)
    return out


def _check_messaging_service_observability_gap(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return None
    if record.get("fallback_url_configured") is not False:
        return None
    if record.get("status_callback_url_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_MSG_OBSERVABILITY_GAP,
        finding_key=make_finding_key(_RULE_MSG_OBSERVABILITY_GAP, record_id),
        severity="medium",
        title="Twilio Messaging Service has neither fallback URL nor status callback configured",
        description=(
            "This Messaging Service has neither a fallback URL nor a status callback URL "
            "configured. Message delivery issues may not be detectable or recoverable. "
            "Review webhook configuration for observability. This is evidence for review "
            "and does not confirm compromise, unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_MSG_OBSERVABILITY_GAP,
            "messaging_service_sid": get_str(record, "messaging_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "fallback_url_configured": False,
            "status_callback_url_configured": False,
        },
        remediation={
            "summary": "Configure a fallback URL and/or status callback URL for this Messaging Service.",
            "steps": [
                "In the Twilio Console, navigate to Messaging > Services.",
                "Select this service and configure a fallback URL under Integration settings.",
                "Configure a status callback URL to enable delivery status observability.",
            ],
        },
        record_id=record_id,
    )


def _check_messaging_service_number_level_inbound_webhook(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return None
    if record.get("use_inbound_webhook_on_number") is not True:
        return None
    if record.get("inbound_request_url_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_MSG_NUMBER_LEVEL_INBOUND,
        finding_key=make_finding_key(_RULE_MSG_NUMBER_LEVEL_INBOUND, record_id),
        severity="low",
        title="Twilio Messaging Service delegates inbound webhook handling to individual phone numbers",
        description=(
            "This Messaging Service delegates inbound webhook handling to individual "
            "phone numbers rather than a service-level URL. Ensure all associated phone "
            "numbers have inbound webhooks configured. This is evidence for review and "
            "does not confirm compromise, unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_MSG_NUMBER_LEVEL_INBOUND,
            "messaging_service_sid": get_str(record, "messaging_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "use_inbound_webhook_on_number": True,
            "inbound_request_url_configured": False,
        },
        remediation={
            "summary": "Verify that all phone numbers in this Messaging Service have inbound webhooks configured.",
            "steps": [
                "In the Twilio Console, navigate to Messaging > Services and review this service's configuration.",
                "Check each associated phone number under Phone Numbers > Manage > Active numbers.",
                "Confirm each number has an inbound SMS webhook URL configured, or switch to a service-level inbound URL.",
            ],
        },
        record_id=record_id,
    )


def _check_messaging_service_long_validity_period(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_MESSAGING_SERVICE:
        return None
    validity_period = record.get("validity_period")
    if not isinstance(validity_period, int):
        return None
    if validity_period <= 86400:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_MSG_LONG_VALIDITY,
        finding_key=make_finding_key(_RULE_MSG_LONG_VALIDITY, record_id),
        severity="low",
        title="Twilio Messaging Service has a validity period longer than 24 hours",
        description=(
            "This Messaging Service has a validity period longer than 24 hours. "
            "Extended validity periods mean messages may be retried and delivered "
            "long after they were originally sent. Review whether this matches your "
            "operational requirements. This is evidence for review and does not "
            "confirm compromise, unauthorized access, or data exposure."
        ),
        evidence={
            "rule": _RULE_MSG_LONG_VALIDITY,
            "messaging_service_sid": get_str(record, "messaging_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "validity_period": validity_period,
        },
        remediation={
            "summary": "Review the validity period for this Messaging Service and reduce it if a shorter window is appropriate.",
            "steps": [
                "In the Twilio Console, navigate to Messaging > Services.",
                "Select this service and review the validity period setting.",
                "Reduce the validity period if messages should not be retried after a shorter window.",
            ],
        },
        record_id=record_id,
    )


def _check_phone_number_messaging_observability_gap(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_INCOMING_PHONE_NUMBER:
        return None
    if record.get("capability_sms") is not True:
        return None
    if record.get("sms_url_configured") is not False:
        return None
    if record.get("status_callback_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_PHONE_MESSAGING_OBS_GAP,
        finding_key=make_finding_key(_RULE_PHONE_MESSAGING_OBS_GAP, record_id),
        severity="medium",
        title="Twilio phone number has SMS capability but no inbound webhook or status callback configured",
        description=(
            "This phone number has SMS capability but no inbound webhook or status "
            "callback is configured. Inbound SMS messages may be silently dropped and "
            "delivery status may not be observable. Review webhook configuration. This "
            "is evidence for review and does not confirm compromise, unauthorized access, "
            "or data exposure."
        ),
        evidence={
            "rule": _RULE_PHONE_MESSAGING_OBS_GAP,
            "phone_number_sid": get_str(record, "phone_number_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "phone_number_last4": get_str(record, "phone_number_last4"),
            "iso_country": get_str(record, "iso_country"),
            "capability_sms": True,
        },
        remediation={
            "summary": "Configure an SMS webhook URL and/or a status callback URL for this phone number.",
            "steps": [
                "In the Twilio Console, navigate to Phone Numbers > Manage > Active numbers.",
                "Select this number and set an SMS webhook URL under the Messaging section.",
                "Also configure a status callback URL to enable delivery status observability.",
            ],
        },
        record_id=record_id,
    )


def _check_phone_number_voice_observability_gap(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_INCOMING_PHONE_NUMBER:
        return None
    if record.get("capability_voice") is not True:
        return None
    if record.get("voice_url_configured") is not False:
        return None
    if record.get("status_callback_configured") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_PHONE_VOICE_OBS_GAP,
        finding_key=make_finding_key(_RULE_PHONE_VOICE_OBS_GAP, record_id),
        severity="medium",
        title="Twilio phone number has voice capability but no inbound webhook or status callback configured",
        description=(
            "This phone number has voice capability but no inbound webhook or status "
            "callback is configured. Inbound calls may not be handled and call status "
            "may not be observable. Review webhook configuration. This is evidence for "
            "review and does not confirm compromise, unauthorized access, or data "
            "exposure."
        ),
        evidence={
            "rule": _RULE_PHONE_VOICE_OBS_GAP,
            "phone_number_sid": get_str(record, "phone_number_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "phone_number_last4": get_str(record, "phone_number_last4"),
            "iso_country": get_str(record, "iso_country"),
            "capability_voice": True,
        },
        remediation={
            "summary": "Configure a voice webhook URL and/or a status callback URL for this phone number.",
            "steps": [
                "In the Twilio Console, navigate to Phone Numbers > Manage > Active numbers.",
                "Select this number and set a voice webhook URL under the Voice section.",
                "Also configure a status callback URL to enable call status observability.",
            ],
        },
        record_id=record_id,
    )


def _check_verify_psd2_disabled(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_VERIFY_SERVICE:
        return None
    if record.get("psd2_enabled") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_VERIFY_PSD2_DISABLED,
        finding_key=make_finding_key(_RULE_VERIFY_PSD2_DISABLED, record_id),
        severity="low",
        title="Twilio Verify Service does not have PSD2 (Strong Customer Authentication) enabled",
        description=(
            "This Verify Service does not have PSD2 (Strong Customer Authentication) "
            "enabled. If this service is used for financial transaction verification in "
            "regulated markets, PSD2 compliance may require review. This is evidence "
            "for review and does not confirm compromise, unauthorized access, or data "
            "exposure."
        ),
        evidence={
            "rule": _RULE_VERIFY_PSD2_DISABLED,
            "verify_service_sid": get_str(record, "verify_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "psd2_enabled": False,
        },
        remediation={
            "summary": "Review whether PSD2/SCA should be enabled for this Verify Service.",
            "steps": [
                "In the Twilio Console, navigate to Verify > Services.",
                "Select this service and review the PSD2 setting.",
                "Enable PSD2 if this service is used for financial transaction verification in regulated markets.",
            ],
        },
        record_id=record_id,
    )


def _check_verify_sms_to_landlines_allowed(
    record: dict[str, Any],
) -> FindingCandidate | None:
    if record.get("record_type") != TWILIO_VERIFY_SERVICE:
        return None
    if record.get("skip_sms_to_landlines") is not False:
        return None
    record_id = get_str(record, "record_id") or None
    return FindingCandidate(
        provider="twilio",
        rule_key=_RULE_VERIFY_SMS_TO_LANDLINES,
        finding_key=make_finding_key(_RULE_VERIFY_SMS_TO_LANDLINES, record_id),
        severity="low",
        title="Twilio Verify Service is configured to send verification SMS to landlines",
        description=(
            "This Verify Service is configured to send verification SMS to landlines, "
            "which cannot receive SMS. This may result in verification failures and "
            "additional costs. Review whether landline SMS filtering should be enabled. "
            "This is evidence for review and does not confirm compromise, unauthorized "
            "access, or data exposure."
        ),
        evidence={
            "rule": _RULE_VERIFY_SMS_TO_LANDLINES,
            "verify_service_sid": get_str(record, "verify_service_sid"),
            "friendly_name": get_str(record, "friendly_name"),
            "skip_sms_to_landlines": False,
        },
        remediation={
            "summary": "Enable landline SMS filtering for this Verify Service to prevent failed deliveries to landlines.",
            "steps": [
                "In the Twilio Console, navigate to Verify > Services.",
                "Select this service and enable the 'Skip SMS to landlines' setting.",
                "Test verification flows after enabling the setting to confirm expected behaviour.",
            ],
        },
        record_id=record_id,
    )


# ── Public entry point ────────────────────────────────────────────────────────


def get_twilio_findings(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate all Twilio security rules against a single record.

    Returns a list of FindingCandidate objects (may be empty).
    """
    if not isinstance(record, dict):
        return []
    findings: list[FindingCandidate] = []
    for check_fn in [
        # M79B
        _check_phone_number_sms_webhook_missing,
        _check_phone_number_voice_webhook_missing,
        _check_phone_number_status_callback_missing,
        _check_messaging_service_inbound_webhook_missing,
        _check_messaging_service_fallback_missing,
        _check_messaging_service_status_callback_missing,
        _check_verify_short_code_length,
        _check_verify_lookup_disabled,
        _check_account_suspended,
        # M79C
        _check_api_key_stale,
        _check_messaging_service_observability_gap,
        _check_messaging_service_number_level_inbound_webhook,
        _check_messaging_service_long_validity_period,
        _check_phone_number_messaging_observability_gap,
        _check_phone_number_voice_observability_gap,
        _check_verify_psd2_disabled,
        _check_verify_sms_to_landlines_allowed,
    ]:
        result = check_fn(record)
        if result:
            findings.append(result)
    return findings
