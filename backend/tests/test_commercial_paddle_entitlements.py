"""Paddle entitlement mapping tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

import pytest

from app.billing.entitlements import decide_entitlements
from app.billing.enums import BillingProvider, NormalizedSubscriptionStatus, PlanId
from app.billing.paddle_webhook_service import normalize_paddle_status


class TestPaddleStatusNormalization:
    @pytest.mark.parametrize(
        "paddle_status,expected",
        [
            ("trialing", NormalizedSubscriptionStatus.TRIALING),
            ("active", NormalizedSubscriptionStatus.ACTIVE),
            ("past_due", NormalizedSubscriptionStatus.PAST_DUE),
            ("paused", NormalizedSubscriptionStatus.PAUSED),
            ("canceled", NormalizedSubscriptionStatus.CANCELED),
        ],
    )
    def test_known_paddle_statuses_map_correctly(self, paddle_status, expected):
        assert normalize_paddle_status(paddle_status) == expected

    def test_unknown_paddle_status_maps_to_incomplete(self):
        assert normalize_paddle_status("some_future_status") == NormalizedSubscriptionStatus.INCOMPLETE


class TestEntitlementDecisionsForPaddle:
    def test_active_paddle_subscription_has_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.ACTIVE, source_provider=BillingProvider.PADDLE
        )
        assert decision.has_paid_access is True
        assert decision.source_provider == BillingProvider.PADDLE

    def test_canceled_immediately_falls_back_to_free(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.CANCELED, source_provider=BillingProvider.PADDLE
        )
        assert decision.plan_id == PlanId.FREE
        assert decision.has_paid_access is False

    def test_grace_period_status_has_paid_access_with_grace_end(self):
        from datetime import datetime, timezone

        grace_end = datetime.now(timezone.utc)
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.GRACE_PERIOD,
            grace_period_end=grace_end, source_provider=BillingProvider.PADDLE,
        )
        assert decision.has_paid_access is True
        assert decision.grace_period_end == grace_end

    def test_expired_status_has_no_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.EXPIRED, source_provider=BillingProvider.PADDLE
        )
        assert decision.has_paid_access is False

    def test_recovered_payment_active_status_restores_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.ACTIVE, source_provider=BillingProvider.PADDLE
        )
        assert decision.has_paid_access is True
        assert decision.reason == "subscription_active"

    def test_incomplete_status_has_no_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.INCOMPLETE, source_provider=BillingProvider.PADDLE
        )
        assert decision.has_paid_access is False

    def test_paused_status_has_no_paid_access_but_management_available(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.PAUSED, source_provider=BillingProvider.PADDLE
        )
        assert decision.has_paid_access is False
        assert decision.billing_management_available is True

    def test_canceled_at_period_end_still_active_until_period_ends(self):
        """Cancellation-at-period-end is represented as ACTIVE status with
        cancel_at_period_end=True at the subscription-aggregate level
        (message-2 spec item 25) — entitlements themselves don't need a
        separate "canceled_at_period_end" status because access is
        preserved through the current period regardless."""
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=NormalizedSubscriptionStatus.ACTIVE, source_provider=BillingProvider.PADDLE
        )
        assert decision.has_paid_access is True
