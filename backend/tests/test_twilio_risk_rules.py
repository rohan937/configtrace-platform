"""Twilio change-classification tests — Changes timeline risk rules.

Covers ``app/services/risk_rules/twilio.py`` (added to fix the gap where
Twilio Changes fell back to the generic Cloudflare DNS classifier — every
Twilio field_path would previously match nothing in that classifier and
silently return "low / No specific risk pattern matched", even for changes
like a phone number's SMS webhook being removed entirely).

Also proves the ``risk_service.classify_change`` dispatch now routes
``twilio_*`` record types to the Twilio classifier instead of falling
through to ``classify_dns_change``.
"""

from __future__ import annotations

from app.services.risk_rules.twilio import classify_twilio_change
from app.services.risk_service import classify_change


# ── Test-change builder ───────────────────────────────────────────────────────


def _change(
    *,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    record_type: str = "twilio_incoming_phone_number",
    record_name: str = "PN123",
) -> dict:
    """Build a minimal change dict that mirrors a diff-service output."""
    return {
        "change_type": change_type,
        "field_path": field_path,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


FORBIDDEN_WORDS = (
    "breach",
    "attacker",
    "fraud",
    "message interception",
    "unauthorized access confirmed",
    "secret leaked",
    "data leaked",
    "messages exposed",
    "sms exposed",
    "phone numbers exposed",
)


def _assert_safe_wording(reason: str) -> None:
    lowered = reason.lower()
    for word in FORBIDDEN_WORDS:
        assert word not in lowered, f"Forbidden wording {word!r} found in: {reason!r}"


def _assert_never_high_or_critical(level: str) -> None:
    assert level in ("medium", "low"), (
        f"Twilio has no high/critical classification signal in its "
        f"connector data model; got {level!r}"
    )


# ── Dispatch: risk_service routes twilio_* to the Twilio classifier ─────────


def test_risk_service_dispatches_twilio_to_twilio_classifier_not_dns_fallback():
    """A Twilio change must NOT fall back to the generic DNS classifier.

    Regression test for the exact bug this module fixes: before the
    dispatch entry existed, this change would return
    ("low", "No specific risk pattern matched. This change may be routine
    configuration maintenance.") from classify_dns_change.
    """
    change = _change(
        record_type="twilio_incoming_phone_number",
        field_path="sms_url_configured",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_change(change)
    assert level == "medium"
    assert "no specific risk pattern matched" not in reason.lower()
    assert "routine configuration maintenance" not in reason.lower()


# ── D/E. Phone number webhook posture ─────────────────────────────────────────


def test_phone_number_sms_webhook_removed_is_medium():
    change = _change(field_path="sms_url_configured", prev_value=True, new_value=False)
    level, reason = classify_twilio_change(change)
    assert level == "medium"
    assert "sms webhook" in reason.lower()
    _assert_safe_wording(reason)


def test_phone_number_sms_webhook_configured_is_low_improvement():
    change = _change(field_path="sms_url_configured", prev_value=False, new_value=True)
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_phone_number_voice_webhook_removed_is_medium():
    change = _change(field_path="voice_url_configured", prev_value=True, new_value=False)
    level, reason = classify_twilio_change(change)
    assert level == "medium"
    assert "voice webhook" in reason.lower()
    _assert_safe_wording(reason)


def test_phone_number_status_callback_removed_is_low():
    change = _change(
        field_path="status_callback_configured", prev_value=True, new_value=False
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_phone_number_emergency_status_inactive_is_medium():
    change = _change(
        field_path="emergency_status", prev_value="Active", new_value="Inactive"
    )
    level, reason = classify_twilio_change(change)
    assert level == "medium"
    _assert_safe_wording(reason)


def test_phone_number_capability_toggle_is_low_not_high():
    change = _change(field_path="capability_voice", prev_value=True, new_value=False)
    level, reason = classify_twilio_change(change)
    assert level == "low"
    _assert_safe_wording(reason)


def test_phone_number_added_removed_are_low():
    for change_type in ("added", "removed"):
        change = _change(change_type=change_type, field_path=None)
        level, _ = classify_twilio_change(change)
        assert level == "low"


# ── F/G. Messaging service webhook posture ───────────────────────────────────


def test_messaging_service_inbound_webhook_removed_is_medium():
    change = _change(
        record_type="twilio_messaging_service",
        field_path="inbound_request_url_configured",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_twilio_change(change)
    assert level == "medium"
    assert "inbound webhook" in reason.lower()
    _assert_safe_wording(reason)


def test_messaging_service_inbound_webhook_configured_is_low():
    change = _change(
        record_type="twilio_messaging_service",
        field_path="inbound_request_url_configured",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_messaging_service_fallback_url_removed_is_low():
    change = _change(
        record_type="twilio_messaging_service",
        field_path="fallback_url_configured",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_messaging_service_long_validity_period_is_low():
    change = _change(
        record_type="twilio_messaging_service",
        field_path="validity_period",
        prev_value=14400,
        new_value=172800,
    )
    level, reason = classify_twilio_change(change)
    assert level == "low"
    _assert_safe_wording(reason)


def test_messaging_service_unknown_field_does_not_produce_high():
    change = _change(
        record_type="twilio_messaging_service",
        field_path="number_count",
        prev_value=2,
        new_value=5,
    )
    level, _ = classify_twilio_change(change)
    _assert_never_high_or_critical(level)


# ── H. Voice/application webhook (proxied via phone number voice_url) ───────


def test_voice_webhook_configured_is_low_improvement():
    change = _change(field_path="voice_url_configured", prev_value=False, new_value=True)
    level, reason = classify_twilio_change(change)
    assert level == "low"
    assert "voice webhook" in reason.lower()


# ── I/J. Event sink — not modeled (see report) ───────────────────────────────
# No Event Streams/Sinks record type exists in the Twilio connector; nothing
# to classify. Covered as N/A in the detection matrix, not tested here.


# ── K. Account/subaccount posture ─────────────────────────────────────────────


def test_account_status_non_active_is_medium():
    change = _change(
        record_type="twilio_account",
        field_path="status",
        prev_value="active",
        new_value="suspended",
    )
    level, reason = classify_twilio_change(change)
    assert level == "medium"
    assert "status" in reason.lower()
    _assert_safe_wording(reason)


def test_account_status_restored_to_active_is_low():
    change = _change(
        record_type="twilio_account",
        field_path="status",
        prev_value="suspended",
        new_value="active",
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


# ── L. Verify Service posture ─────────────────────────────────────────────────


def test_verify_code_length_shortened_is_medium():
    change = _change(
        record_type="twilio_verify_service",
        field_path="code_length",
        prev_value=6,
        new_value=4,
    )
    level, reason = classify_twilio_change(change)
    assert level == "medium"
    assert "code length" in reason.lower()
    _assert_safe_wording(reason)


def test_verify_code_length_restored_is_low():
    change = _change(
        record_type="twilio_verify_service",
        field_path="code_length",
        prev_value=4,
        new_value=6,
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_verify_lookup_disabled_is_low():
    change = _change(
        record_type="twilio_verify_service",
        field_path="lookup_enabled",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_verify_psd2_disabled_is_low():
    change = _change(
        record_type="twilio_verify_service",
        field_path="psd2_enabled",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


# ── M. Unknown/missing behavior ───────────────────────────────────────────────


def test_added_records_never_produce_high():
    for record_type in (
        "twilio_account",
        "twilio_incoming_phone_number",
        "twilio_messaging_service",
        "twilio_verify_service",
        "twilio_api_key_summary",
    ):
        change = _change(change_type="added", record_type=record_type, new_value={})
        level, _ = classify_twilio_change(change)
        _assert_never_high_or_critical(level)


def test_removed_records_never_produce_high():
    for record_type in (
        "twilio_account",
        "twilio_incoming_phone_number",
        "twilio_messaging_service",
        "twilio_verify_service",
        "twilio_api_key_summary",
    ):
        change = _change(change_type="removed", record_type=record_type)
        level, _ = classify_twilio_change(change)
        _assert_never_high_or_critical(level)


def test_unrecognised_record_type_falls_back_safely_to_low():
    change = _change(record_type="twilio_future_surface", field_path="whatever")
    level, reason = classify_twilio_change(change)
    assert level == "low"
    _assert_safe_wording(reason)


def test_api_key_added_is_low():
    change = _change(
        record_type="twilio_api_key_summary", change_type="added", new_value={}
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_api_key_removed_is_low():
    change = _change(record_type="twilio_api_key_summary", change_type="removed")
    level, _ = classify_twilio_change(change)
    assert level == "low"


def test_api_key_field_change_is_low_not_high():
    """Twilio API keys have no status/scope field — any change is metadata-only."""
    change = _change(
        record_type="twilio_api_key_summary",
        field_path="date_updated",
        prev_value="2024-01-01T00:00:00Z",
        new_value="2024-06-01T00:00:00Z",
    )
    level, _ = classify_twilio_change(change)
    assert level == "low"
