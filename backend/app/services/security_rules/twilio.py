"""Twilio security / configuration-risk rules — M79B.

Every rule fires only on explicit, reliable normalized fields produced by the
Twilio connector (app/connectors/twilio.py + twilio_schema.py). Evidence is
metadata-only: SIDs, friendly names, phone_number_last4, capability booleans,
webhook presence booleans, code length, and account status strings. No
auth_token, API key secret, full phone number strings, webhook URL strings,
message bodies, call logs, recording data, customer PII, or raw API responses
are ever read, stored, or surfaced.

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
                                       callback missing
- ``twilio_messaging_service``    → inbound webhook missing, fallback URL
                                       missing, status callback URL missing
- ``twilio_verify_service``       → short code length, lookup disabled
- ``twilio_account``              → non-active account status
"""

from __future__ import annotations

from typing import Any

from app.connectors.twilio_schema import (
    TWILIO_ACCOUNT,
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

TWILIO_RULE_KEYS: frozenset[str] = frozenset({
    _RULE_PHONE_SMS_WEBHOOK_MISSING,
    _RULE_PHONE_VOICE_WEBHOOK_MISSING,
    _RULE_PHONE_STATUS_CALLBACK_MISSING,
    _RULE_MSG_INBOUND_WEBHOOK_MISSING,
    _RULE_MSG_FALLBACK_MISSING,
    _RULE_MSG_STATUS_CALLBACK_MISSING,
    _RULE_VERIFY_SHORT_CODE,
    _RULE_VERIFY_LOOKUP_DISABLED,
    _RULE_ACCOUNT_SUSPENDED,
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
    ):
        result = check_fn(record)
        if result is not None:
            out.append(result)
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
    ):
        result = check_fn(record)
        if result is not None:
            out.append(result)
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


# ── Public entry point ────────────────────────────────────────────────────────


def get_twilio_findings(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate all Twilio security rules against a single record.

    Returns a list of FindingCandidate objects (may be empty).
    """
    if not isinstance(record, dict):
        return []
    findings: list[FindingCandidate] = []
    for check_fn in [
        _check_phone_number_sms_webhook_missing,
        _check_phone_number_voice_webhook_missing,
        _check_phone_number_status_callback_missing,
        _check_messaging_service_inbound_webhook_missing,
        _check_messaging_service_fallback_missing,
        _check_messaging_service_status_callback_missing,
        _check_verify_short_code_length,
        _check_verify_lookup_disabled,
        _check_account_suspended,
    ]:
        result = check_fn(record)
        if result:
            findings.append(result)
    return findings
