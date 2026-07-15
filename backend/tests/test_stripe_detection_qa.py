"""Stripe detection-QA regression coverage (message-1 detection pass).

This file covers bugs found while auditing Stripe connector -> compute_diff
-> classify_stripe_change reachability:

  1. ``stripe_payment_link`` (M73A) is a live, connector-emitted record type
     with full classifier logic (``_classify_payment_link_change``), but had
     NO entry in ``_STRIPE_TRACKED_FIELDS_BY_TYPE`` in diff_service.py — the
     safe ``.get(rt, ())`` fallback meant compute_diff() always used an
     EMPTY tracked-fields tuple for it, so real field-level drift (a link
     disabled, promotion codes toggled, redirect changed) was silently never
     detected as a "modified" Change. (Added/removed whole-record changes
     still fired, since those don't depend on tracked fields.)
  2. ``_classify_payment_link_change`` (via ``_is_production_payment_link``)
     reads ``pm.get("livemode")`` from provider_metadata, but
     ``_build_provider_metadata()`` had no Stripe-specific stanza — only the
     generic ``record_name``/``record_content`` keys were populated. In
     production this meant "livemode" was always missing, so the
     classifier's "assume production when missing" fallback made every
     payment link (test-mode or live) always classify as production. Not an
     under-classification (the fallback is conservative), but the test/live
     distinction never actually worked.

Also documents (in the report, not fixed here — connector never emits
these): 11 of 17 schema-defined Stripe record types (stripe_product,
stripe_price, stripe_checkout_configuration, stripe_tax_settings,
stripe_radar_rule, stripe_restricted_api_key,
stripe_subscription_invoice_settings, stripe_dunning_settings,
stripe_external_account, stripe_coupon, stripe_promotion_code) have full
classifier logic in risk_rules/stripe.py but are never fetched by
``StripeConnector.fetch()`` — dead/unreachable branches, matching the
"classifier built ahead of the connector" pattern found in other providers
this session.

These tests exercise the REAL compute_diff() -> classify_stripe_change()
pipeline (not hand-built mocks), matching the established regression
pattern from this session's other detection-QA passes.
"""

from __future__ import annotations

from app.connectors.stripe import StripeConnector
from app.connectors.stripe_schema import STRIPE_RECORD_TYPES
from app.services.diff_service import compute_diff
from app.services.risk_rules.stripe import classify_stripe_change


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


_PAYMENT_LINK_BASE = {
    "record_type": "stripe_payment_link",
    "record_id": "plink_1",
    "name": "plink_1",
    "active": True,
    "allow_promotion_codes": False,
    "automatic_tax_enabled": True,
    "customer_creation": "always",
    "payment_method_collection": "always",
    "payment_method_types_count": 1,
    "application_fee_amount": None,
    "application_fee_percent": None,
    "success_url_origin": "https://example.com",
    "after_completion_type": "redirect",
    "after_completion_redirect_origin": "https://example.com",
    "livemode": True,
}


class TestPaymentLinkRealComputeDiff:
    def test_active_disabled_is_detected_and_high_for_live_mode(self):
        prev = [dict(_PAYMENT_LINK_BASE)]
        new = [{**_PAYMENT_LINK_BASE, "active": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "active"]
        assert len(matching) == 1, "payment_link 'active' change was not detected by compute_diff"
        assert matching[0]["provider_metadata"]["livemode"] is True
        level, reason = classify_stripe_change(matching[0])
        assert level == "high"
        assert "disabled" in reason.lower()

    def test_active_disabled_is_medium_for_test_mode(self):
        prev = [{**_PAYMENT_LINK_BASE, "livemode": False}]
        new = [{**prev[0], "active": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "active"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["livemode"] is False
        level, _ = classify_stripe_change(matching[0])
        assert level == "medium"

    def test_allow_promotion_codes_change_is_detected(self):
        prev = [dict(_PAYMENT_LINK_BASE)]
        new = [{**_PAYMENT_LINK_BASE, "allow_promotion_codes": True}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "allow_promotion_codes"]
        assert len(matching) == 1, "payment_link 'allow_promotion_codes' change was not detected by compute_diff"
        level, _ = classify_stripe_change(matching[0])
        assert level == "medium"

    def test_success_url_origin_change_is_detected(self):
        prev = [dict(_PAYMENT_LINK_BASE)]
        new = [{**_PAYMENT_LINK_BASE, "success_url_origin": "https://different.example.com"}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "success_url_origin"]
        assert len(matching) == 1
        level, reason = classify_stripe_change(matching[0])
        assert level == "high"
        assert "redirect destination changed" in reason.lower()

    def test_added_and_removed_still_work(self):
        added = _real_changes([], [dict(_PAYMENT_LINK_BASE)])
        assert len(added) == 1 and added[0]["change_type"] == "added"
        removed = _real_changes([dict(_PAYMENT_LINK_BASE)], [])
        assert len(removed) == 1 and removed[0]["change_type"] == "removed"


class TestUnreachableStripeRecordTypes:
    """Confirms the 11 schema-only Stripe record types remain genuinely
    unreachable — the connector never emits them, matching this pass's
    documented GAP status (not invented/fixed, per scope)."""

    _UNREACHABLE = (
        "stripe_product",
        "stripe_price",
        "stripe_checkout_configuration",
        "stripe_tax_settings",
        "stripe_radar_rule",
        "stripe_restricted_api_key",
        "stripe_subscription_invoice_settings",
        "stripe_dunning_settings",
        "stripe_external_account",
        "stripe_coupon",
        "stripe_promotion_code",
    )

    def test_unreachable_types_are_schema_defined(self):
        for rt in self._UNREACHABLE:
            assert rt in STRIPE_RECORD_TYPES

    def test_connector_source_never_references_unreachable_types(self):
        import inspect

        source = inspect.getsource(StripeConnector)
        for rt in self._UNREACHABLE:
            assert rt.upper() not in source and rt not in source, (
                f"{rt} unexpectedly referenced in StripeConnector — "
                "the detection matrix's GAP status may be stale"
            )
