"""Team pricing calculation tests (Commercial Infrastructure message 1).

Covers every boundary value from the message-1 spec plus a bounded loop
over a useful range, confirming
``total == 3000 + max(0, n - 20) * 500`` for every n.
"""

from __future__ import annotations

import pytest

from app.billing.pricing import (
    TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS,
    TEAM_BASE_MONTHLY_CENTS,
    TEAM_INCLUDED_SEATS,
    NegativeMemberCountError,
    calculate_team_monthly_price,
)


def _expected_total(n: int) -> int:
    return TEAM_BASE_MONTHLY_CENTS + max(0, n - TEAM_INCLUDED_SEATS) * TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS


class TestNegativeRejected:
    def test_negative_one_raises(self):
        with pytest.raises(NegativeMemberCountError):
            calculate_team_monthly_price(-1)

    def test_large_negative_raises(self):
        with pytest.raises(NegativeMemberCountError):
            calculate_team_monthly_price(-100)


class TestZeroMembers:
    def test_zero_members_is_base_price_not_free(self):
        """Zero-member decision (message-1 spec item 10): the pricing
        function itself must never produce a free/negative Team price."""
        breakdown = calculate_team_monthly_price(0)
        assert breakdown.total_amount_cents == 3000
        assert breakdown.additional_members == 0


class TestBoundaryValues:
    @pytest.mark.parametrize(
        "count,expected_total,expected_additional",
        [
            (1, 3000, 0),
            (2, 3000, 0),
            (10, 3000, 0),
            (19, 3000, 0),
            (20, 3000, 0),
            (21, 3500, 1),
            (22, 4000, 2),
            (25, 5500, 5),
            (30, 8000, 10),
            (50, 18000, 30),
            (100, 43000, 80),
        ],
    )
    def test_boundary_value(self, count, expected_total, expected_additional):
        breakdown = calculate_team_monthly_price(count)
        assert breakdown.total_amount_cents == expected_total
        assert breakdown.additional_members == expected_additional

    def test_spec_examples_match_dollar_amounts(self):
        # From the task spec's worked examples, in dollars.
        assert calculate_team_monthly_price(1).total_amount_cents == 3000  # $30
        assert calculate_team_monthly_price(10).total_amount_cents == 3000  # $30
        assert calculate_team_monthly_price(20).total_amount_cents == 3000  # $30
        assert calculate_team_monthly_price(21).total_amount_cents == 3500  # $35
        assert calculate_team_monthly_price(25).total_amount_cents == 5500  # $55
        assert calculate_team_monthly_price(30).total_amount_cents == 8000  # $80
        assert calculate_team_monthly_price(50).total_amount_cents == 18000  # $180


class TestVeryLargeCount:
    def test_very_large_count_stays_integer_and_correct(self):
        breakdown = calculate_team_monthly_price(1_000_000)
        assert breakdown.total_amount_cents == _expected_total(1_000_000)
        assert isinstance(breakdown.total_amount_cents, int)


class TestBoundedLoopProperty:
    def test_formula_holds_for_every_n_in_range(self):
        for n in range(0, 201):
            breakdown = calculate_team_monthly_price(n)
            assert breakdown.total_amount_cents == _expected_total(n), f"mismatch at n={n}"


class TestIntegerMinorUnits:
    def test_total_is_int_never_float(self):
        for n in (0, 1, 20, 21, 50, 999):
            breakdown = calculate_team_monthly_price(n)
            assert isinstance(breakdown.total_amount_cents, int)
            assert isinstance(breakdown.base_amount_cents, int)
            assert isinstance(breakdown.additional_seat_amount_cents, int)


class TestDeterministicBreakdown:
    def test_repeated_calls_produce_identical_breakdown(self):
        a = calculate_team_monthly_price(37)
        b = calculate_team_monthly_price(37)
        assert a == b

    def test_breakdown_as_dict_is_json_serializable(self):
        import json

        breakdown = calculate_team_monthly_price(25)
        json.dumps(breakdown.as_dict())


class TestComponentQuantities:
    @pytest.mark.parametrize("count", [0, 1, 20, 21, 25, 50, 100])
    def test_base_quantity_always_one(self, count):
        breakdown = calculate_team_monthly_price(count)
        base_component = next(c for c in breakdown.components if c.component_id == "team_base_monthly")
        assert base_component.quantity == 1

    @pytest.mark.parametrize(
        "count,expected_additional_quantity",
        [(0, 0), (1, 0), (20, 0), (21, 1), (25, 5), (50, 30), (100, 80)],
    )
    def test_additional_quantity_is_max_zero_seats_minus_20(self, count, expected_additional_quantity):
        breakdown = calculate_team_monthly_price(count)
        additional_component = next(
            c for c in breakdown.components if c.component_id == "team_additional_seat_monthly"
        )
        assert additional_component.quantity == expected_additional_quantity
        assert additional_component.quantity == max(0, count - 20)


class TestCurrencyAndInterval:
    def test_currency_is_usd(self):
        assert calculate_team_monthly_price(25).currency == "USD"

    def test_interval_is_month(self):
        from app.billing.enums import BillingInterval

        assert calculate_team_monthly_price(25).interval == BillingInterval.MONTH
