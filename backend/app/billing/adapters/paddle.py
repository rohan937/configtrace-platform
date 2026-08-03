"""Paddle adapter contract (Commercial Infrastructure message 1).

NO live Paddle API implementation exists in this message — every method
returns an explicit, typed state (``ProviderOperationResult`` with
``state in {"not_configured", "unsupported_before_m2"}``) and NEVER
silently falls back to Stripe (message-1 spec item 16).

Planned Paddle subscription representation (message-1 spec item 13),
implemented starting message 2:
  * ONE Team base recurring item, quantity 1, mapped to
    ``PaddlePriceMapping.base_price_id``.
  * ONE additional-seat recurring item, quantity = max(0, seats - 20),
    mapped to ``PaddlePriceMapping.additional_seat_price_id`` — omitted or
    set to quantity 0 according to verified Paddle behavior in message 2
    (Paddle's exact handling of a zero-quantity recurring item has not
    been verified against live/sandbox Paddle yet; this message does not
    call any Paddle API, verified or otherwise).
  * NEVER one external price per team size — pricing scales via quantity,
    not via a combinatorial price catalog.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.billing.enums import BillingProvider
from app.billing.provider import (
    BillingProviderAdapter,
    BillingProviderReference,
    CancelSubscriptionRequest,
    CheckoutRequest,
    CheckoutResponse,
    NormalizedSubscriptionSnapshot,
    PortalRequest,
    PortalResponse,
    ProviderOperationResult,
    SubscriptionUpdateRequest,
)


@dataclass(frozen=True)
class PaddlePriceMapping:
    """Configuration contract for mapping internal price components to
    Paddle catalog objects (message-1 spec item 13). Populated from
    settings in message 2+ once real sandbox/live Paddle prices exist —
    all fields are ``None`` by default in message 1."""

    environment: str  # "sandbox" | "live"
    base_price_id: str | None
    additional_seat_price_id: str | None

    @property
    def is_configured(self) -> bool:
        return bool(self.base_price_id and self.additional_seat_price_id)


class PaddleNotConfiguredError(Exception):
    """Typed, explicit "not configured" state (message-1 spec item 16) —
    raised when Paddle is selected but has no price mapping configured.
    Never a silent fallback to Stripe."""


class PaddleUnsupportedBeforeM2Error(NotImplementedError):
    """Typed, explicit "unsupported before message 2" state — raised when
    Paddle IS configured (a price mapping exists) but no live Paddle API
    call is implemented yet. Never a silent fallback to Stripe."""


_NOT_CONFIGURED = ProviderOperationResult(
    state="not_configured",
    detail="Paddle is not configured on this server (no sandbox/live price mapping set).",
)
_UNSUPPORTED_BEFORE_M2 = ProviderOperationResult(
    state="unsupported_before_m2",
    detail="Paddle checkout/webhooks are not implemented until Commercial Infrastructure message 2.",
)


class PaddleBillingAdapter(BillingProviderAdapter):
    """Contract-only Paddle adapter. Every operation explicitly signals
    ``not_configured`` (mapping absent) or ``unsupported_before_m2``
    (mapping present but no live API call is implemented yet) — never a
    silent fallback to Stripe, and never a real Paddle API call. Methods
    whose interface return type can carry a state directly
    (``update_subscription``/``cancel_subscription``) return
    ``ProviderOperationResult``; methods that must return a concrete
    provider-neutral object (checkout URL, subscription snapshot, ...)
    raise one of the two typed exceptions above instead of fabricating a
    fake object.
    """

    provider = BillingProvider.PADDLE

    def __init__(self, price_mapping: PaddlePriceMapping | None):
        self._price_mapping = price_mapping

    @property
    def is_configured(self) -> bool:
        return self._price_mapping is not None and self._price_mapping.is_configured

    def _raise_typed_state(self) -> None:
        if not self.is_configured:
            raise PaddleNotConfiguredError(_NOT_CONFIGURED.detail)
        raise PaddleUnsupportedBeforeM2Error(_UNSUPPORTED_BEFORE_M2.detail)

    def _result_state(self) -> ProviderOperationResult:
        return _NOT_CONFIGURED if not self.is_configured else _UNSUPPORTED_BEFORE_M2

    def create_checkout(self, request: CheckoutRequest) -> CheckoutResponse:
        self._raise_typed_state()

    def create_portal(self, request: PortalRequest) -> PortalResponse:
        self._raise_typed_state()

    def get_customer(self, reference: BillingProviderReference) -> BillingProviderReference:
        self._raise_typed_state()

    def get_subscription(
        self, reference: BillingProviderReference
    ) -> NormalizedSubscriptionSnapshot | None:
        self._raise_typed_state()

    def update_subscription(self, request: SubscriptionUpdateRequest) -> ProviderOperationResult:
        return self._result_state()

    def cancel_subscription(self, request: CancelSubscriptionRequest) -> ProviderOperationResult:
        return self._result_state()

    def parse_webhook(self, headers: dict, body: bytes) -> dict:
        self._raise_typed_state()

    def reconcile(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None:
        self._raise_typed_state()
