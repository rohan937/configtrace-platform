"""Twilio risk classification rules — Changes timeline drift classification.

Entry point: ``classify_twilio_change(change)``

Context
-------
Before this module existed, ``risk_service.classify_change`` had no dispatch
entry for ``twilio_*`` record types, so every Twilio Change fell back to
``classify_dns_change`` (the Cloudflare DNS classifier). Since no Twilio
field_path ever matches a DNS-specific field name, every Twilio change was
silently classified ``low`` with the generic message "No specific risk
pattern matched. This change may be routine configuration maintenance." —
regardless of actual severity. This module gives Twilio its own
classification so the Changes timeline agrees with the Security Findings
system (``app/services/security_rules/twilio.py``), which already evaluates
these fields correctly.

Severity ceiling
-----------------
Twilio has no ``"high"`` or ``"critical"`` classification in this module,
matching every existing Twilio Security Finding (all 17 cap at ``medium``).
The connector's normalized fields never expose a scope/permission-broadening
signal (Twilio's API Key summary resource has no status/scope field at
all — only SID, friendly name, and timestamps) or a webhook URL scheme
(the connector deliberately stores webhook URLs as boolean presence flags
only, never the URL string or its scheme — see
``app/connectors/twilio_schema.py``). Without either signal, there is no
Twilio field whose weakening genuinely rises above ``medium``.

Directionality
---------------
Every classification distinguishes weakening (new_value moves toward the
less-observable/less-verified state) from restoration, and gives
restorations a lower severity than the corresponding weakening.

Data minimisation
------------------
Only field names and boolean/count/enum values ever appear in risk_reason
text — never auth tokens, full phone numbers, webhook URLs, message
content, or call/verification data, matching the connector's own privacy
contract.

Safe wording
-------------
No risk_reason in this module ever asserts breach, compromise, a leaked
secret, message interception, unauthorized access, or data exposure — only
configuration evidence that "may require review".
"""

from __future__ import annotations

from typing import Any

from app.models.change import Change


def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ── twilio_account ─────────────────────────────────────────────────────────────


def _classify_account_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "Twilio account record was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "status":
        if str(new_value).lower() not in ("active", ""):
            return (
                "medium",
                f"The Twilio account status changed to '{new_value}'. "
                "Messaging and voice services may be affected. This may "
                "require review. Configuration evidence does not confirm "
                "compromise, unauthorized access, or data exposure.",
            )
        return (
            "low",
            "The Twilio account status was restored to active.",
        )

    return (
        "low",
        f"Twilio account field '{field_path}' changed.",
    )


# ── twilio_incoming_phone_number ──────────────────────────────────────────────


def _classify_phone_number_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "Twilio incoming phone number record was added or removed during sync.",
        )

    if change_type == "modified" and field_path in (
        "sms_url_configured",
        "voice_url_configured",
    ):
        kind = "SMS" if field_path == "sms_url_configured" else "voice"
        if new_value is False:
            return (
                "medium",
                f"A Twilio phone number's {kind} webhook was removed. Inbound "
                f"{kind} events will no longer be delivered to any endpoint. "
                "This may require review.",
            )
        return (
            "low",
            f"A Twilio phone number's {kind} webhook was configured.",
        )

    if change_type == "modified" and field_path == "status_callback_configured":
        if new_value is False:
            return (
                "low",
                "A Twilio phone number's status callback was removed. "
                "Delivery status events will no longer be forwarded.",
            )
        return (
            "low",
            "A Twilio phone number's status callback was configured.",
        )

    if change_type == "modified" and field_path == "emergency_status":
        if str(new_value).lower() == "inactive":
            return (
                "medium",
                "A Twilio phone number's emergency calling status became "
                "inactive. This may require review.",
            )
        return (
            "low",
            "A Twilio phone number's emergency calling status changed.",
        )

    if change_type == "modified" and field_path in (
        "capability_voice",
        "capability_sms",
        "capability_mms",
        "capability_fax",
        "address_requirements",
        "friendly_name",
    ):
        return (
            "low",
            f"Twilio phone number field '{field_path}' changed to '{new_value}'.",
        )

    return (
        "low",
        "Twilio incoming phone number changed; no specific risk pattern matched.",
    )


# ── twilio_messaging_service ──────────────────────────────────────────────────


def _classify_messaging_service_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "Twilio Messaging Service record was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "inbound_request_url_configured":
        if new_value is False:
            return (
                "medium",
                "A Twilio Messaging Service's inbound webhook was removed. "
                "Inbound message events will no longer be delivered to any "
                "endpoint. This may require review.",
            )
        return (
            "low",
            "A Twilio Messaging Service's inbound webhook was configured.",
        )

    if change_type == "modified" and field_path in (
        "fallback_url_configured",
        "status_callback_url_configured",
    ):
        if new_value is False:
            return (
                "low",
                f"A Twilio Messaging Service's '{field_path}' was removed.",
            )
        return (
            "low",
            f"A Twilio Messaging Service's '{field_path}' was configured.",
        )

    if change_type == "modified" and field_path == "validity_period":
        try:
            long_validity = new_value is not None and int(new_value) > 86400
        except (TypeError, ValueError):
            long_validity = False
        if long_validity:
            return (
                "low",
                "A Twilio Messaging Service's message validity period was "
                "increased beyond 24 hours. Messages may be attempted for "
                "delivery long after they were sent.",
            )
        return (
            "low",
            "A Twilio Messaging Service's message validity period changed.",
        )

    if change_type == "modified" and field_path in (
        "smart_encoding",
        "area_code_geomatch",
        "sticky_sender",
        "mms_converter",
        "use_inbound_webhook_on_number",
        "number_count",
        "friendly_name",
    ):
        return (
            "low",
            f"Twilio Messaging Service field '{field_path}' changed to '{new_value}'.",
        )

    return (
        "low",
        "Twilio Messaging Service changed; no specific risk pattern matched.",
    )


# ── twilio_verify_service ──────────────────────────────────────────────────────


def _classify_verify_service_change(
    change_type: str, field_path: str, new_value: Any
) -> tuple[str, str]:
    if change_type in ("added", "removed"):
        return (
            "low",
            "Twilio Verify Service record was added or removed during sync.",
        )

    if change_type == "modified" and field_path == "code_length":
        try:
            short_code = new_value is not None and int(new_value) < 6
        except (TypeError, ValueError):
            short_code = False
        if short_code:
            return (
                "medium",
                "A Twilio Verify Service's OTP code length was reduced below "
                "6 digits. Shorter codes are easier to guess. This may "
                "require review.",
            )
        return (
            "low",
            "A Twilio Verify Service's OTP code length changed.",
        )

    if change_type == "modified" and field_path in (
        "lookup_enabled",
        "psd2_enabled",
        "skip_sms_to_landlines",
        "do_not_share_warning_enabled",
    ):
        if new_value is False:
            return (
                "low",
                f"A Twilio Verify Service setting '{field_path}' was disabled. "
                "This may require review.",
            )
        return (
            "low",
            f"A Twilio Verify Service setting '{field_path}' was enabled.",
        )

    if change_type == "modified" and field_path in (
        "default_template_sid_present",
        "friendly_name",
    ):
        return (
            "low",
            f"Twilio Verify Service field '{field_path}' changed.",
        )

    return (
        "low",
        "Twilio Verify Service changed; no specific risk pattern matched.",
    )


# ── twilio_api_key_summary ─────────────────────────────────────────────────────


def _classify_api_key_change(change_type: str, field_path: str) -> tuple[str, str]:
    if change_type == "added":
        return (
            "low",
            "A new Twilio API key was created.",
        )
    if change_type == "removed":
        return (
            "low",
            "A Twilio API key was deleted. Any integration still using it "
            "will begin failing authentication.",
        )
    return (
        "low",
        f"Twilio API key field '{field_path}' changed.",
    )


# ── Dispatcher ─────────────────────────────────────────────────────────────────


def classify_twilio_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Twilio change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``twilio_account``                 → account status rules
      * ``twilio_incoming_phone_number``   → phone number webhook/capability rules
      * ``twilio_messaging_service``       → Messaging Service webhook/config rules
      * ``twilio_verify_service``          → Verify Service posture rules
      * ``twilio_api_key_summary``         → API key lifecycle rules

    Args:
        change: A ``Change`` ORM instance (or a plain dict, for testing).

    Returns:
        ``(risk_level, risk_reason)`` where risk_level is one of ``"medium"``
        or ``"low"``. Twilio has no ``"critical"`` or ``"high"``
        classification — see the module docstring for why.
    """
    pm = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower() if isinstance(pm, dict) else ""

    change_type = (_get(change, "change_type") or "").lower()
    field_path = _get(change, "field_path") or ""
    new_value = _get(change, "new_value")

    if record_type == "twilio_account":
        return _classify_account_change(change_type, field_path, new_value)
    if record_type == "twilio_incoming_phone_number":
        return _classify_phone_number_change(change_type, field_path, new_value)
    if record_type == "twilio_messaging_service":
        return _classify_messaging_service_change(change_type, field_path, new_value)
    if record_type == "twilio_verify_service":
        return _classify_verify_service_change(change_type, field_path, new_value)
    if record_type == "twilio_api_key_summary":
        return _classify_api_key_change(change_type, field_path)

    return (
        "low",
        "An unrecognised Twilio configuration record changed. This may be "
        "a new record type introduced in a future update.",
    )
