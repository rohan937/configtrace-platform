"""Dodo entitlement-decision tests (Dodo Payments message 1).

Proves Dodo's normalized statuses feed the SAME provider-neutral
``decide_entitlements`` used by Stripe and Paddle — no Dodo-specific
entitlement logic exists or is needed.
"""

from __future__ import annotations

from app.billing.dodo_webhook_service import normalize_dodo_status
from app.billing.entitlements import decide_entitlements
from app.billing.enums import BillingProvider, NormalizedSubscriptionStatus, PlanId


class TestEntitlementDecisionsForDodo:
    def test_active_dodo_subscription_has_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=normalize_dodo_status("active"), source_provider=BillingProvider.DODO,
        )
        assert decision.has_paid_access is True
        assert decision.plan_id == PlanId.TEAM

    def test_pro_active_dodo_subscription_has_paid_access_and_pro_entitlements(self):
        decision = decide_entitlements(
            plan_id=PlanId.PRO, status=normalize_dodo_status("active"), source_provider=BillingProvider.DODO,
        )
        assert decision.has_paid_access is True
        assert decision.plan_id == PlanId.PRO
        assert decision.max_integrations == 20

    def test_on_hold_still_has_paid_access_during_grace(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=normalize_dodo_status("on_hold"), source_provider=BillingProvider.DODO,
        )
        assert decision.status == NormalizedSubscriptionStatus.PAST_DUE
        assert decision.has_paid_access is True  # PAST_DUE is in _PAID_ACCESS_STATUSES

    def test_cancelled_falls_back_to_free(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=normalize_dodo_status("cancelled"), source_provider=BillingProvider.DODO,
        )
        assert decision.has_paid_access is False
        assert decision.plan_id == PlanId.FREE

    def test_expired_has_no_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=normalize_dodo_status("expired"), source_provider=BillingProvider.DODO,
        )
        assert decision.has_paid_access is False

    def test_pending_maps_to_incomplete_no_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.PRO, status=normalize_dodo_status("pending"), source_provider=BillingProvider.DODO,
        )
        assert decision.status == NormalizedSubscriptionStatus.INCOMPLETE
        assert decision.has_paid_access is False

    def test_failed_maps_to_incomplete_no_paid_access(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=normalize_dodo_status("failed"), source_provider=BillingProvider.DODO,
        )
        assert decision.status == NormalizedSubscriptionStatus.INCOMPLETE
        assert decision.has_paid_access is False

    def test_source_provider_recorded_as_dodo(self):
        decision = decide_entitlements(
            plan_id=PlanId.TEAM, status=normalize_dodo_status("active"), source_provider=BillingProvider.DODO,
        )
        assert decision.source_provider == BillingProvider.DODO
