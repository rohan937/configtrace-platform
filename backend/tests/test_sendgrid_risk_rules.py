"""SendGrid change-classification tests — Changes timeline risk rules.

Covers ``app/services/risk_rules/sendgrid.py`` (added to fix the gap where
SendGrid Changes fell back to the generic Cloudflare DNS classifier — every
SendGrid field_path would previously match nothing in that classifier and
silently return "low / No specific risk pattern matched", even for changes
as significant as an API key becoming full-access).

Also proves the ``risk_service.classify_change`` dispatch now routes
``sendgrid_*`` record types to the SendGrid classifier instead of falling
through to ``classify_dns_change``.
"""

from __future__ import annotations

from app.services.risk_rules.sendgrid import classify_sendgrid_change
from app.services.risk_service import classify_change


# ── Test-change builder ───────────────────────────────────────────────────────


def _change(
    *,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    record_type: str = "sendgrid_api_key",
    record_name: str = "SG.abc123",
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
    "unauthorized access confirmed",
    "secret leaked",
    "data leaked",
)


def _assert_safe_wording(reason: str) -> None:
    lowered = reason.lower()
    for word in FORBIDDEN_WORDS:
        assert word not in lowered, f"Forbidden wording {word!r} found in: {reason!r}"


# ── Dispatch: risk_service routes sendgrid_* to the SendGrid classifier ──────


def test_risk_service_dispatches_sendgrid_to_sendgrid_classifier_not_dns_fallback():
    """A SendGrid change must NOT fall back to the generic DNS classifier.

    Regression test for the exact bug this module fixes: before the
    dispatch entry existed, this change would return
    ("low", "No specific risk pattern matched. This change may be routine
    configuration maintenance.") from classify_dns_change.
    """
    change = _change(
        record_type="sendgrid_api_key",
        field_path="has_full_access",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_change(change)
    assert level == "high"
    assert "no specific risk pattern matched" not in reason.lower()
    assert "routine configuration maintenance" not in reason.lower()


# ── A. API key permissions/scopes ─────────────────────────────────────────────


def test_api_key_scope_broadened_to_full_access_is_high():
    change = _change(field_path="has_full_access", prev_value=False, new_value=True)
    level, reason = classify_sendgrid_change(change)
    assert level == "high"
    assert "broadened" in reason.lower()
    _assert_safe_wording(reason)


def test_api_key_scope_restricted_is_medium_improvement():
    change = _change(field_path="has_full_access", prev_value=True, new_value=False)
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    assert "restrict" in reason.lower()
    _assert_safe_wording(reason)


def test_api_key_added_with_full_access_is_high():
    change = _change(
        change_type="added",
        new_value={"has_full_access": True, "name": "new-key"},
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "high"
    _assert_safe_wording(reason)


def test_api_key_added_without_full_access_is_low():
    change = _change(
        change_type="added",
        new_value={"has_full_access": False, "name": "new-key"},
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


def test_api_key_removed_is_low():
    change = _change(change_type="removed")
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


def test_api_key_unknown_field_does_not_produce_high():
    change = _change(field_path="scopes_count", prev_value=2, new_value=3)
    level, _ = classify_sendgrid_change(change)
    assert level != "high"


# ── B. Event webhook posture ──────────────────────────────────────────────────


def test_webhook_signing_disabled_is_medium():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="event_webhook_signed",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    assert "signing" in reason.lower()
    _assert_safe_wording(reason)


def test_webhook_signing_restored_is_low_improvement():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="event_webhook_signed",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    assert "restored" in reason.lower() or "enabled" in reason.lower()


def test_event_webhook_disabled_is_medium():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="event_webhook_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    _assert_safe_wording(reason)


def test_event_webhook_enabled_is_low():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="event_webhook_enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


def test_event_webhook_url_missing_is_medium():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="event_webhook_has_url",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "medium"


def test_inbound_parse_enabled_is_medium():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="inbound_parse_enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "medium"


def test_inbound_parse_disabled_is_low():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="inbound_parse_enabled",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


def test_webhook_unknown_field_does_not_produce_high():
    change = _change(
        record_type="sendgrid_webhook_settings",
        field_path="event_count",
        prev_value=3,
        new_value=5,
    )
    level, _ = classify_sendgrid_change(change)
    assert level != "high"


# ── C. Domain authentication ──────────────────────────────────────────────────


def test_domain_authentication_becomes_invalid_is_medium():
    change = _change(
        record_type="sendgrid_domain_authentication",
        field_path="valid",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    assert "invalid" in reason.lower()
    _assert_safe_wording(reason)


def test_domain_authentication_restored_is_low_improvement():
    change = _change(
        record_type="sendgrid_domain_authentication",
        field_path="valid",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    assert "restored" in reason.lower()


def test_domain_dns_record_count_decrease_is_medium():
    change = _change(
        record_type="sendgrid_domain_authentication",
        field_path="dns_record_count",
        prev_value=3,
        new_value=1,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "medium"


def test_domain_dns_record_count_increase_is_low():
    change = _change(
        record_type="sendgrid_domain_authentication",
        field_path="dns_record_count",
        prev_value=1,
        new_value=3,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


def test_domain_automatic_security_disabled_is_medium():
    change = _change(
        record_type="sendgrid_domain_authentication",
        field_path="automatic_security",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "medium"


# ── D. Sender authentication ──────────────────────────────────────────────────


def test_sender_identity_becomes_unverified_is_medium():
    change = _change(
        record_type="sendgrid_sender_identity",
        field_path="verified",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    assert "unverified" in reason.lower()
    _assert_safe_wording(reason)


def test_sender_identity_verified_is_low_improvement():
    change = _change(
        record_type="sendgrid_sender_identity",
        field_path="verified",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    assert "verified" in reason.lower()


def test_sender_identity_unknown_field_does_not_produce_high():
    change = _change(
        record_type="sendgrid_sender_identity",
        field_path="nickname",
        prev_value="Old",
        new_value="New",
    )
    level, _ = classify_sendgrid_change(change)
    assert level != "high"


# ── E. Link branding (proxied via domain authentication fields) ─────────────


def test_domain_legacy_flag_change_is_low():
    change = _change(
        record_type="sendgrid_domain_authentication",
        field_path="legacy",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


# ── F. Tracking settings ──────────────────────────────────────────────────────


def test_click_tracking_toggle_is_low_not_high():
    change = _change(
        record_type="sendgrid_tracking_settings",
        field_path="click_tracking_enabled",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    _assert_safe_wording(reason)


def test_open_tracking_toggle_is_low_not_high():
    change = _change(
        record_type="sendgrid_tracking_settings",
        field_path="open_tracking_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    _assert_safe_wording(reason)


def test_subscription_tracking_disabled_is_medium():
    change = _change(
        record_type="sendgrid_tracking_settings",
        field_path="subscription_tracking_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    _assert_safe_wording(reason)


def test_subscription_tracking_enabled_is_low_improvement():
    change = _change(
        record_type="sendgrid_tracking_settings",
        field_path="subscription_tracking_enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "low"


# ── G. Unknown/missing behavior ───────────────────────────────────────────────


def test_added_records_never_produce_high_except_full_access_api_key():
    for record_type in (
        "sendgrid_account",
        "sendgrid_sender_identity",
        "sendgrid_domain_authentication",
        "sendgrid_mail_settings",
        "sendgrid_tracking_settings",
        "sendgrid_webhook_settings",
        "sendgrid_suppression_settings",
    ):
        change = _change(change_type="added", record_type=record_type, new_value={})
        level, _ = classify_sendgrid_change(change)
        assert level != "high", f"{record_type} added should not be high"


def test_removed_records_are_never_high():
    for record_type in (
        "sendgrid_account",
        "sendgrid_api_key",
        "sendgrid_sender_identity",
        "sendgrid_domain_authentication",
        "sendgrid_mail_settings",
        "sendgrid_tracking_settings",
        "sendgrid_webhook_settings",
        "sendgrid_suppression_settings",
    ):
        change = _change(change_type="removed", record_type=record_type)
        level, _ = classify_sendgrid_change(change)
        assert level != "high", f"{record_type} removed should not be high"


def test_unrecognised_record_type_falls_back_safely_to_low():
    change = _change(record_type="sendgrid_future_surface", field_path="whatever")
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    _assert_safe_wording(reason)


def test_mail_settings_sandbox_mode_enabled_is_medium():
    change = _change(
        record_type="sendgrid_mail_settings",
        field_path="sandbox_mode_enabled",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "medium"
    _assert_safe_wording(reason)


def test_mail_settings_spam_check_disabled_is_medium():
    change = _change(
        record_type="sendgrid_mail_settings",
        field_path="spam_check_enabled",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_sendgrid_change(change)
    assert level == "medium"


def test_suppression_group_count_drops_to_zero_is_low_not_high():
    change = _change(
        record_type="sendgrid_suppression_settings",
        field_path="suppression_group_count",
        prev_value=2,
        new_value=0,
    )
    level, reason = classify_sendgrid_change(change)
    assert level == "low"
    _assert_safe_wording(reason)
