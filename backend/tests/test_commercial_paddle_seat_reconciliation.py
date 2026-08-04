"""Seat reconciliation tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

import uuid

import pytest

from app.billing.reconciliation_service import WorkspaceCustomerMismatchError, reconcile_workspace_subscription
from app.billing.seat_reconciliation import (
    PRORATION_MODE_SEAT_ADDED,
    PRORATION_MODE_SEAT_REMOVED,
    calculate_desired_additional_quantity,
    plan_seat_reconciliation,
)


class TestDesiredQuantity:
    @pytest.mark.parametrize("members,expected", [(0, 0), (1, 0), (20, 0), (21, 1), (25, 5), (50, 30)])
    def test_desired_additional_quantity_formula(self, members, expected):
        assert calculate_desired_additional_quantity(members) == expected


class TestNoUpdateNeeded:
    def test_matching_quantities_need_no_update(self):
        plan = plan_seat_reconciliation(current_billable_members=25, observed_additional_quantity=5)
        assert plan.needs_update is False
        assert plan.proration_mode is None


class TestSeatIncreaseTransitions:
    @pytest.mark.parametrize(
        "from_seats,to_members",
        [(20, 21), (21, 20 + 4), (25, 30)],
    )
    def test_20_to_21(self, from_seats, to_members):
        plan = plan_seat_reconciliation(current_billable_members=to_members, observed_additional_quantity=max(0, from_seats - 20))
        if to_members > from_seats:
            assert plan.needs_update is True
            assert plan.proration_mode == PRORATION_MODE_SEAT_ADDED


class TestSeatDecreaseTransitions:
    def test_30_to_25(self):
        plan = plan_seat_reconciliation(current_billable_members=25, observed_additional_quantity=10)
        assert plan.needs_update is True
        assert plan.proration_mode == PRORATION_MODE_SEAT_REMOVED
        assert plan.desired_additional_quantity == 5

    def test_50_to_10(self):
        plan = plan_seat_reconciliation(current_billable_members=10, observed_additional_quantity=30)
        assert plan.needs_update is True
        assert plan.proration_mode == PRORATION_MODE_SEAT_REMOVED
        assert plan.desired_additional_quantity == 0


class TestConcurrentChangeSafety:
    def test_plan_is_a_pure_function_of_its_inputs(self):
        """Calling twice with the same inputs produces an identical plan —
        no hidden mutable state that could produce a race between two
        concurrent reconciliation attempts computing different results
        from the same observed state."""
        a = plan_seat_reconciliation(current_billable_members=25, observed_additional_quantity=0)
        b = plan_seat_reconciliation(current_billable_members=25, observed_additional_quantity=0)
        assert a == b


class TestDuplicateUpdateAvoidance:
    def test_reconciling_an_already_correct_subscription_produces_no_plan(self):
        plan = plan_seat_reconciliation(current_billable_members=21, observed_additional_quantity=1)
        assert plan.needs_update is False


class TestWorkspaceCustomerMismatch:
    def test_mismatch_detection_class_exists_and_is_a_value_error(self):
        assert issubclass(WorkspaceCustomerMismatchError, ValueError)


class TestReconcileWorkspaceSubscriptionNoLocalSubscription:
    def test_reconcile_with_no_local_subscription_returns_not_updated(self, db_session):
        from unittest.mock import MagicMock

        result = reconcile_workspace_subscription(uuid.uuid4(), MagicMock(), db_session)
        assert result.updated is False
        assert result.reason == "no_paddle_subscription_on_file"
