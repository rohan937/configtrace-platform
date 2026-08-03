"""Billing-provider registry (Commercial Infrastructure message 1).

Selection is via ``settings.BILLING_PROVIDER`` (default ``"stripe"`` —
existing environments continue to default to Stripe for compatibility;
message 2 changes the deployment default to Paddle, not this code).

Paddle selection fails CLOSED if its adapter is not activated (no price
mapping configured) — it never silently falls back to Stripe
(message-1 spec item 17).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.billing.adapters.paddle import PaddleBillingAdapter, PaddleNotConfiguredError, PaddlePriceMapping
from app.billing.adapters.stripe import StripeBillingAdapter
from app.billing.enums import BillingProvider
from app.billing.provider import BillingProviderAdapter
from app.config import settings


class UnknownBillingProviderError(ValueError):
    """Raised when ``BILLING_PROVIDER`` is set to a value outside the
    bounded ``BillingProvider`` enum — never silently treated as Stripe."""


def _paddle_price_mapping() -> PaddlePriceMapping | None:
    base = settings.PADDLE_BASE_PRICE_ID
    additional = settings.PADDLE_ADDITIONAL_SEAT_PRICE_ID
    if not base and not additional:
        return None
    return PaddlePriceMapping(
        environment=settings.PADDLE_ENVIRONMENT or "sandbox",
        base_price_id=base,
        additional_seat_price_id=additional,
    )


def get_billing_provider(
    db: Session, *, provider_override: BillingProvider | None = None
) -> BillingProviderAdapter:
    """Return the configured billing-provider adapter.

    ``provider_override`` lets tests explicitly select a provider
    (message-1 spec item 17: "tests can explicitly select providers")
    without depending on process-wide settings/env vars.
    """
    raw = provider_override.value if provider_override else (settings.BILLING_PROVIDER or "stripe")
    try:
        provider = BillingProvider(raw)
    except ValueError:
        raise UnknownBillingProviderError(
            f"Unknown BILLING_PROVIDER {raw!r}; must be one of "
            f"{[p.value for p in BillingProvider]}"
        )

    if provider == BillingProvider.STRIPE:
        return StripeBillingAdapter(db)

    if provider == BillingProvider.PADDLE:
        mapping = _paddle_price_mapping()
        adapter = PaddleBillingAdapter(mapping)
        if not adapter.is_configured:
            raise PaddleNotConfiguredError(
                "BILLING_PROVIDER=paddle but no Paddle price mapping is configured "
                "(PADDLE_BASE_PRICE_ID / PADDLE_ADDITIONAL_SEAT_PRICE_ID). "
                "Refusing to silently fall back to Stripe."
            )
        return adapter

    raise UnknownBillingProviderError(f"Unhandled billing provider: {provider!r}")
