"""Paddle catalog verification (Commercial Infrastructure message 2, spec item 7).

Compares LIVE Paddle price metadata against the internal expected catalog
contract. This function DOES make a real Paddle API call — it is only
ever invoked from the opt-in sandbox smoke tests
(``test_commercial_paddle_sandbox_optional.py``), never from the ordinary
offline test suite, and never automatically at import/startup time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.billing.paddle_client import PaddleAPIClient
from app.billing.pricing import TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS, TEAM_BASE_MONTHLY_CENTS, TEAM_CURRENCY


@dataclass(frozen=True)
class CatalogMismatch:
    price_id: str
    field: str
    expected: str
    observed: str


@dataclass(frozen=True)
class CatalogVerificationResult:
    verified: bool
    mismatches: tuple[CatalogMismatch, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "verified": self.verified,
            "mismatches": [
                {"price_id": m.price_id, "field": m.field, "expected": m.expected, "observed": m.observed}
                for m in self.mismatches
            ],
        }


def _check_price(client: PaddleAPIClient, price_id: str, expected_amount_cents: int, expected_recurring: bool) -> list[CatalogMismatch]:
    mismatches: list[CatalogMismatch] = []
    data = client.get_price(price_id).get("data", {})

    unit_price = data.get("unit_price", {})
    amount = unit_price.get("amount")
    currency = unit_price.get("currency_code")
    billing_cycle = data.get("billing_cycle") or {}

    if amount is not None and int(amount) != expected_amount_cents:
        mismatches.append(CatalogMismatch(price_id, "amount_cents", str(expected_amount_cents), str(amount)))
    if currency is not None and currency != TEAM_CURRENCY:
        mismatches.append(CatalogMismatch(price_id, "currency", TEAM_CURRENCY, str(currency)))
    if expected_recurring and billing_cycle.get("interval") != "month":
        mismatches.append(CatalogMismatch(price_id, "billing_interval", "month", str(billing_cycle.get("interval"))))

    return mismatches


def verify_catalog(client: PaddleAPIClient, *, base_price_id: str, additional_seat_price_id: str) -> CatalogVerificationResult:
    """Fetch both configured Paddle prices and compare against the
    internal expected Team pricing contract. Requires real credentials —
    callers must guard this behind an explicit opt-in flag."""
    mismatches: list[CatalogMismatch] = []
    mismatches.extend(_check_price(client, base_price_id, TEAM_BASE_MONTHLY_CENTS, expected_recurring=True))
    mismatches.extend(
        _check_price(client, additional_seat_price_id, TEAM_ADDITIONAL_SEAT_MONTHLY_CENTS, expected_recurring=True)
    )
    return CatalogVerificationResult(verified=not mismatches, mismatches=tuple(mismatches))
