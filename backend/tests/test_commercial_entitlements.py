"""Entitlement normalization tests (Commercial Infrastructure message 1).

Covers every normalized status and confirms entitlement decisions never
inspect a raw Stripe status string directly.
"""

from __future__ import annotations

import inspect

import pytest

from app.billing.entitlements import decide_entitlements, normalize_stripe_status
from app.billing.enums import BillingProvider, NormalizedSubscriptionStatus, PlanId


class TestNormalizeStripeStatus:
    @pytest.mark.parametrize(
        "stripe_status,expected",
        [
            ("trialing", NormalizedSubscriptionStatus.TRIALING),
            ("active", NormalizedSubscriptionStatus.ACTIVE),
            ("past_due", NormalizedSubscriptionStatus.PAST_DUE),
            ("canceled", NormalizedSubscriptionStatus.CANCELED),
            ("unpaid", NormalizedSubscriptionStatus.EXPIRED),
            ("incomplete", NormalizedSubscriptionStatus.INCOMPLETE),
            ("incomplete_expired", NormalizedSubscriptionStatus.EXPIRED),
            ("paused", NormalizedSubscriptionStatus.PAUSED),
        ],
    )
    def test_known_stripe_statuses_map_correctly(self, stripe_status, expected):
        assert normalize_stripe_status(stripe_status) == expected

    def test_unknown_stripe_status_maps_to_incomplete_not_active(self):
        assert normalize_stripe_status("some_future_stripe_status") == NormalizedSubscriptionStatus.INCOMPLETE


class TestEveryNormalizedStatus:
    @pytest.mark.parametrize(
        "status,expected_paid_access",
        [
            (NormalizedSubscriptionStatus.ACTIVE, True),
            (NormalizedSubscriptionStatus.TRIALING, True),
            (NormalizedSubscriptionStatus.PAST_DUE, True),
            (NormalizedSubscriptionStatus.GRACE_PERIOD, True),
            (NormalizedSubscriptionStatus.PAUSED, False),
            (NormalizedSubscriptionStatus.CANCELED, False),
            (NormalizedSubscriptionStatus.EXPIRED, False),
            (NormalizedSubscriptionStatus.INCOMPLETE, False),
        ],
    )
    def test_paid_access_by_status(self, status, expected_paid_access):
        decision = decide_entitlements(plan_id=PlanId.TEAM, status=status)
        assert decision.has_paid_access is expected_paid_access

    def test_active_team_gets_team_entitlements(self):
        decision = decide_entitlements(plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.ACTIVE)
        assert decision.plan_id == PlanId.TEAM
        assert decision.max_members == 25
        assert decision.max_integrations == 100

    def test_canceled_team_falls_back_to_free_entitlements(self):
        decision = decide_entitlements(plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.CANCELED)
        assert decision.plan_id == PlanId.FREE
        assert decision.max_members == 1
        assert decision.max_integrations == 3

    def test_past_due_still_gets_team_entitlements_during_grace(self):
        decision = decide_entitlements(plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.PAST_DUE)
        assert decision.plan_id == PlanId.TEAM
        assert decision.has_paid_access is True


class TestManagementAvailability:
    @pytest.mark.parametrize(
        "status,expected",
        [
            (NormalizedSubscriptionStatus.ACTIVE, True),
            (NormalizedSubscriptionStatus.TRIALING, True),
            (NormalizedSubscriptionStatus.PAST_DUE, True),
            (NormalizedSubscriptionStatus.GRACE_PERIOD, True),
            (NormalizedSubscriptionStatus.PAUSED, True),
            (NormalizedSubscriptionStatus.CANCELED, False),
            (NormalizedSubscriptionStatus.EXPIRED, False),
            (NormalizedSubscriptionStatus.INCOMPLETE, False),
        ],
    )
    def test_billing_management_availability(self, status, expected):
        decision = decide_entitlements(plan_id=PlanId.TEAM, status=status)
        assert decision.billing_management_available is expected


class TestFeatureGatesNeverReadRawProviderStrings:
    def test_decide_entitlements_signature_takes_normalized_status_enum(self):
        sig = inspect.signature(decide_entitlements)
        annotation = sig.parameters["status"].annotation
        assert "NormalizedSubscriptionStatus" in str(annotation)

    def test_entitlement_decision_never_stores_a_raw_provider_status_field(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM,
            status=NormalizedSubscriptionStatus.ACTIVE,
            source_provider=BillingProvider.STRIPE,
        )
        assert decision.status == NormalizedSubscriptionStatus.ACTIVE
        assert isinstance(decision.status, NormalizedSubscriptionStatus)


class TestEntitlementDecisionSerializable:
    def test_as_dict_is_json_serializable(self):
        import json
        from datetime import datetime, timezone

        decision = decide_entitlements(
            plan_id=PlanId.TEAM,
            status=NormalizedSubscriptionStatus.GRACE_PERIOD,
            grace_period_end=datetime.now(timezone.utc),
            source_provider=BillingProvider.STRIPE,
            last_synchronized_at=datetime.now(timezone.utc),
        )
        json.dumps(decision.as_dict())

    def test_source_provider_none_serializes_to_none(self):
        decision = decide_entitlements(plan_id=PlanId.FREE, status=NormalizedSubscriptionStatus.ACTIVE)
        assert decision.as_dict()["source_provider"] is None
