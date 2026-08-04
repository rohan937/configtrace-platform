"""Billing-provider registry (Commercial Infrastructure message 1 + 2).

Selection is via ``settings.BILLING_PROVIDER`` (default ``"stripe"`` —
existing environments continue to default to Stripe for compatibility;
message 3 changes the deployment default to Paddle, not this code).

Paddle selection fails CLOSED if its adapter is not activated (no price
mapping / API key configured) — it never silently falls back to Stripe
(message-1 spec item 17, unchanged in message 2).

This module governs NEW-checkout provider selection only — see
``app.billing.provider_routing`` for the rule that an EXISTING
subscription is always managed by the provider actually stored on it,
never reinterpreted via this global setting (message-2 spec item 31).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.billing.adapters.dodo import DodoBillingAdapter, DodoCatalogMapping, DodoNotConfiguredError
from app.billing.adapters.paddle import PaddleBillingAdapter, PaddleNotConfiguredError, PaddlePriceMapping
from app.billing.adapters.stripe import StripeBillingAdapter
from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
from app.billing.enums import BillingProvider
from app.billing.paddle_client import PaddleAPIClient, PaddleClientConfig
from app.billing.provider import BillingProviderAdapter
from app.config import settings


class UnknownBillingProviderError(ValueError):
    """Raised when ``BILLING_PROVIDER`` is set to a value outside the
    bounded ``BillingProvider`` enum — never silently treated as Stripe."""


def _paddle_price_mapping() -> PaddlePriceMapping | None:
    base = settings.effective_paddle_team_base_price_id
    additional = settings.effective_paddle_team_additional_seat_price_id
    if not base and not additional:
        return None
    env = settings.paddle_environment_normalized
    return PaddlePriceMapping(
        environment=env if env != "not_configured" else "sandbox",
        base_price_id=base,
        additional_seat_price_id=additional,
    )


def _build_paddle_adapter() -> PaddleBillingAdapter:
    mapping = _paddle_price_mapping()
    client: PaddleAPIClient | None = None
    if mapping is not None and mapping.is_configured and settings.PADDLE_API_KEY:
        env = settings.paddle_environment_normalized
        client = PaddleAPIClient(
            PaddleClientConfig(
                environment=env if env != "not_configured" else "sandbox",
                api_key=settings.PADDLE_API_KEY,
            )
        )
    return PaddleBillingAdapter(mapping, client, webhook_secret=settings.PADDLE_WEBHOOK_SECRET)


def _dodo_catalog_mapping() -> DodoCatalogMapping | None:
    pro = settings.DODO_PRO_PRODUCT_ID
    team = settings.DODO_TEAM_PRODUCT_ID
    addon = settings.DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID
    if not pro and not team and not addon:
        return None
    env = settings.dodo_environment_normalized
    return DodoCatalogMapping(
        environment=env if env != "not_configured" else "test",
        pro_product_id=pro,
        team_product_id=team,
        team_seat_addon_id=addon,
    )


def _build_dodo_adapter() -> DodoBillingAdapter:
    mapping = _dodo_catalog_mapping()
    client: DodoAPIClient | None = None
    if mapping is not None and mapping.is_configured and settings.DODO_API_KEY:
        env = settings.dodo_environment_normalized
        client = DodoAPIClient(
            DodoClientConfig(
                environment=env if env != "not_configured" else "test",
                api_key=settings.DODO_API_KEY,
            )
        )
    return DodoBillingAdapter(mapping, client, webhook_secret=settings.DODO_WEBHOOK_SECRET)


def get_billing_provider(
    db: Session, *, provider_override: BillingProvider | None = None
) -> BillingProviderAdapter:
    """Return the configured billing-provider adapter for NEW checkout /
    generic operations.

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
        adapter = _build_paddle_adapter()
        if not adapter.is_configured:
            raise PaddleNotConfiguredError(
                "BILLING_PROVIDER=paddle but Paddle is not fully configured "
                "(price mapping and/or PADDLE_API_KEY missing). "
                "Refusing to silently fall back to Stripe."
            )
        return adapter

    if provider == BillingProvider.DODO:
        adapter = _build_dodo_adapter()
        if not adapter.is_configured:
            raise DodoNotConfiguredError(
                "BILLING_PROVIDER=dodo but Dodo is not fully configured "
                "(catalog mapping and/or DODO_API_KEY missing). "
                "Refusing to silently fall back to another provider."
            )
        return adapter

    raise UnknownBillingProviderError(f"Unhandled billing provider: {provider!r}")


def get_adapter_for_provider(provider: BillingProvider, db: Session) -> BillingProviderAdapter:
    """Return the adapter for an EXPLICIT provider — used by
    ``app.billing.provider_routing`` to route an existing subscription to
    its STORED provider regardless of the current ``BILLING_PROVIDER``
    setting. Paddle still fails closed if unconfigured."""
    if provider == BillingProvider.STRIPE:
        return StripeBillingAdapter(db)
    if provider == BillingProvider.PADDLE:
        adapter = _build_paddle_adapter()
        if not adapter.is_configured:
            raise PaddleNotConfiguredError(
                "This workspace's subscription is on Paddle, but Paddle is not "
                "configured on this server — cannot manage it right now."
            )
        return adapter
    if provider == BillingProvider.DODO:
        adapter = _build_dodo_adapter()
        if not adapter.is_configured:
            raise DodoNotConfiguredError(
                "This workspace's subscription is on Dodo, but Dodo is not "
                "configured on this server — cannot manage it right now."
            )
        return adapter
    raise UnknownBillingProviderError(f"Unhandled billing provider: {provider!r}")
