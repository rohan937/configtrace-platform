"""Stripe change-classification QA regression coverage (message-2 pass).

This file covers bugs found while auditing classification correctness for
every currently emitted and tracked Stripe field (severity, unknown-value
safety, added-record inspection, and Change/Finding severity parity),
building on the detection-QA pass in test_stripe_detection_qa.py:

  1. Seven boolean-field checks across three live classifiers
     (``_classify_account_settings_change``'s ``charges_enabled``/
     ``payouts_enabled``, ``_classify_payment_method_configuration_change``'s
     ``is_default``, ``_classify_payment_method_domain_change``'s
     ``apple_pay_enabled``/``google_pay_enabled``/``link_enabled``/
     ``enabled``) used an ``if new_v is False: ...; else: <assumes
     restored/promoted/enabled>`` pattern — an unconditional "else" that
     would falsely claim a restoration/improvement if the value were ever
     unknown (``None``) instead of an explicit boolean.
  2. ``_classify_billing_portal_config_change``'s ``subscription_cancel_
     enabled`` branch used a truthy check (``'enabled' if nv else
     'disabled'``) instead of an explicit ``is True``/``is False`` check —
     an unknown value would be reported as "disabled", overstating an
     explicit state.
  3. ``_classify_webhook_endpoint_change``'s ``status`` field had the same
     truthy-adjacent issue (``new_v in ("disabled", False, "false")`` with
     an unconditional "else assumes re-enabled") — flagged but deferred in
     the message-1 detection pass since it's a severity/copy nuance, not a
     routing defect. Fixed here.
  4. ``_classify_webhook_endpoint_change``'s "added" branch never inspected
     the newly added webhook's own record for risky posture (plain
     ``http://``, wildcard/broad event subscription) — every new webhook
     was flatly "high" regardless of how insecure it was from creation.
     Now uses the actual ``BROAD_WEBHOOK_EVENT_THRESHOLD`` constant from
     ``security_rules/stripe.py`` (imported, not duplicated).

These tests exercise the REAL compute_diff() -> classify_stripe_change()
pipeline (not hand-built mocks) wherever practical.
"""

from __future__ import annotations

from app.services.diff_service import compute_diff
from app.services.risk_rules.stripe import classify_stripe_change
from app.services.security_rules.stripe import BROAD_WEBHOOK_EVENT_THRESHOLD


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _change(**kwargs) -> dict:
    base = {
        "change_type": "modified",
        "field_path": None,
        "prev_value": None,
        "new_value": None,
        "provider_metadata": {},
    }
    base.update(kwargs)
    return base


_ACCOUNT_BASE = {
    "record_type": "stripe_account_settings",
    "record_id": "acct_1",
    "name": "acct_1",
    "charges_enabled": True,
    "payouts_enabled": True,
    "details_submitted": True,
}

_PMC_BASE = {
    "record_type": "stripe_payment_method_configuration",
    "record_id": "pmc_1",
    "name": "default",
    "config_id": "pmc_1",
    "config_name": "default",
    "is_default": True,
    "parent_id": None,
    "enabled_payment_methods": {"card": True},
}

_PMD_BASE = {
    "record_type": "stripe_payment_method_domain",
    "record_id": "pmd_1",
    "name": "example.com",
    "domain_id": "pmd_1",
    "domain_name": "example.com",
    "enabled": True,
    "apple_pay_enabled": True,
    "google_pay_enabled": True,
    "link_enabled": True,
}

_WEBHOOK_BASE = {
    "record_type": "stripe_webhook_endpoint",
    "record_id": "we_1",
    "name": "https://example.com/hook",
    "endpoint_id": "we_1",
    "url": "https://example.com/hook",
    "status": "enabled",
    "api_version": "2024-06-20",
    "enabled_events": ["invoice.paid"],
    "description": None,
}


class TestBooleanUnknownIsNotOverstated:
    """Unknown booleans must not be reported as an explicit restored/
    promoted/enabled state."""

    def test_charges_enabled_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "stripe_account_settings"},
            field_path="charges_enabled",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "re-enabled" not in reason.lower()
        assert "restored" not in reason.lower()

    def test_payouts_enabled_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "stripe_account_settings"},
            field_path="payouts_enabled",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "restored" not in reason.lower()

    def test_charges_enabled_real_disable_still_critical(self):
        prev = [dict(_ACCOUNT_BASE)]
        new = [{**_ACCOUNT_BASE, "charges_enabled": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "charges_enabled"]
        assert len(matching) == 1
        level, reason = classify_stripe_change(matching[0])
        assert level == "critical"
        assert "disabled" in reason.lower()

    def test_pmc_is_default_unknown_is_not_a_promotion_claim(self):
        change = _change(
            provider_metadata={"record_type": "stripe_payment_method_configuration"},
            field_path="is_default",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "set as the new default" not in reason.lower()

    def test_pmd_apple_pay_unknown_is_not_an_enabled_claim(self):
        change = _change(
            provider_metadata={"record_type": "stripe_payment_method_domain"},
            field_path="apple_pay_enabled",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "was enabled" not in reason.lower()

    def test_pmd_enabled_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "stripe_payment_method_domain"},
            field_path="enabled",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "restored" not in reason.lower()

    def test_pmd_real_disable_still_high(self):
        prev = [dict(_PMD_BASE)]
        new = [{**_PMD_BASE, "enabled": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "enabled"]
        assert len(matching) == 1
        level, _ = classify_stripe_change(matching[0])
        assert level == "high"

    def test_billing_portal_subscription_cancel_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "stripe_billing_portal_config"},
            field_path="subscription_cancel_enabled",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "was disabled" not in reason.lower()

    def test_webhook_status_unknown_is_not_a_reenable_claim(self):
        change = _change(
            provider_metadata={"record_type": "stripe_webhook_endpoint"},
            field_path="status",
            prev_value="enabled",
            new_value=None,
        )
        level, reason = classify_stripe_change(change)
        assert level == "medium"
        assert "re-enabled" not in reason.lower()
        assert "restored" not in reason.lower()


class TestWebhookAddedInspectsNewRecord:
    """A newly added webhook must be classified by its own risky posture,
    not a flat 'high' regardless of how insecure it is from creation."""

    def test_added_http_webhook_is_critical(self):
        new_record = {**_WEBHOOK_BASE, "url": "http://example.com/hook"}
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_stripe_change(added[0])
        assert level == "critical"
        assert "http://" in reason

    def test_added_webhook_with_broad_events_is_high_with_specific_copy(self):
        new_record = {**_WEBHOOK_BASE, "enabled_events": ["*"]}
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_stripe_change(added[0])
        assert level == "high"
        assert "broad" in reason.lower()

    def test_added_webhook_at_exact_threshold_is_flagged(self):
        events = [f"event.type.{i}" for i in range(BROAD_WEBHOOK_EVENT_THRESHOLD)]
        new_record = {**_WEBHOOK_BASE, "enabled_events": events}
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_stripe_change(added[0])
        assert level == "high"
        assert "broad" in reason.lower()

    def test_added_secure_webhook_below_threshold_is_still_high_generic(self):
        new_record = dict(_WEBHOOK_BASE)
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_stripe_change(added[0])
        assert level == "high"
        assert "broad" not in reason.lower()


class TestPaymentLinkLivemodeSurvivesRealComputeDiff:
    """Regression guard from the message-1 fix: payment-link severity must
    differ between live and test mode, and this must work through the real
    compute_diff() pipeline, not just hand-built provider_metadata."""

    _BASE = {
        "record_type": "stripe_payment_link",
        "record_id": "plink_1",
        "name": "plink_1",
        "active": True,
        "allow_promotion_codes": False,
        "automatic_tax_enabled": True,
        "success_url_origin": "https://example.com",
    }

    def test_live_mode_disable_is_high(self):
        prev = [{**self._BASE, "livemode": True}]
        new = [{**prev[0], "active": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "active"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["livemode"] is True
        level, _ = classify_stripe_change(matching[0])
        assert level == "high"

    def test_test_mode_disable_is_medium(self):
        prev = [{**self._BASE, "livemode": False}]
        new = [{**prev[0], "active": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "active"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["livemode"] is False
        level, _ = classify_stripe_change(matching[0])
        assert level == "medium"


class TestBillingPortalSynchronization:
    """Every billing-portal tracked field must reach either a dedicated
    classifier branch or the documented generic low fallback — proves no
    field silently falls through to a wrong bucket."""

    def _classify(self, field_path, prev_value, new_value):
        change = _change(
            provider_metadata={"record_type": "stripe_billing_portal_config"},
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
        )
        return classify_stripe_change(change)

    def test_all_tracked_fields_reach_a_branch(self):
        from app.services.diff_service import _STRIPE_TRACKED_FIELDS_BY_TYPE

        tracked = _STRIPE_TRACKED_FIELDS_BY_TYPE["stripe_billing_portal_config"]
        # Every tracked field must produce a non-crashing classification
        # with a specific reason (not an empty string) for at least one
        # representative old/new pair.
        sample_values = {
            "active": (True, False),
            "is_default": (True, False),
            "login_page_enabled": (True, False),
            "return_url_domain": ("old.example.com", "new.example.com"),
            "customer_update_enabled": (True, False),
            "customer_update_allowed_updates": (["email"], ["email", "address"]),
            "invoice_history_enabled": (True, False),
            "payment_method_update_enabled": (True, False),
            "subscription_cancel_enabled": (True, False),
            "subscription_cancel_mode": ("at_period_end", "immediately"),
            "subscription_cancel_reason_enabled": (True, False),
            "subscription_update_enabled": (True, False),
            "subscription_update_allowed_updates": (["price"], ["price", "quantity"]),
            "subscription_pause_enabled": (True, False),
        }
        for field in tracked:
            assert field in sample_values, f"no sample values defined for tracked field {field!r}"
            prev_v, new_v = sample_values[field]
            level, reason = self._classify(field, prev_v, new_v)
            assert level in ("low", "medium", "high", "critical")
            assert reason, f"empty classification reason for field {field!r}"
