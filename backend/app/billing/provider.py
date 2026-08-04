"""Provider-neutral billing adapter interface (Commercial Infrastructure message 1).

No method here may accept or return a provider-specific type (a Stripe
``Session``, ``Price``, or ``Subscription`` object). Every request/response
type below is a plain dataclass built only from primitives, enums, and
other dataclasses in this package.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from app.billing.enums import BillingInterval, BillingProvider, ObjectType, PlanId


@dataclass(frozen=True)
class BillingProviderReference:
    """A pointer to one external, provider-owned object. This is the ONLY
    place a provider-specific external ID appears in the provider-neutral
    domain — core commercial models never grow another provider-named
    column (message-1 spec item 5)."""

    provider: BillingProvider
    object_type: ObjectType
    external_id: str
    workspace_id: uuid.UUID
    metadata: dict = field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True)
class CheckoutRequest:
    workspace_id: uuid.UUID
    plan_id: PlanId
    billing_interval: BillingInterval
    billable_seat_count: int
    success_url: str
    cancel_url: str
    customer_email: str | None = None
    customer_reference: BillingProviderReference | None = None
    idempotency_reference: str | None = None
    # ConfigTrace user ID initiating checkout — additive field (Dodo
    # Payments message 1). Optional and unused by the existing Stripe/
    # Paddle adapters; Dodo's checkout metadata includes it so a webhook
    # can be traced back to the initiating user, not just the workspace.
    configtrace_user_id: uuid.UUID | None = None


@dataclass(frozen=True)
class CheckoutResponse:
    provider: BillingProvider
    checkout_url: str
    external_reference: str | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True)
class PortalRequest:
    workspace_id: uuid.UUID
    customer_reference: BillingProviderReference
    return_url: str


@dataclass(frozen=True)
class PortalResponse:
    provider: BillingProvider
    management_url: str
    expires_at: datetime | None = None
    supported_actions: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SubscriptionUpdateRequest:
    subscription_reference: BillingProviderReference
    billable_seat_count: int
    reason: str


@dataclass(frozen=True)
class CancelSubscriptionRequest:
    subscription_reference: BillingProviderReference
    cancel_at_period_end: bool = True


@dataclass(frozen=True)
class NormalizedSubscriptionSnapshot:
    """Provider-neutral snapshot of one subscription's current state, as
    returned by ``get_subscription`` / ``reconcile``. Field names
    deliberately mirror ``app.billing.models.NormalizedSubscription``
    (the persisted aggregate) so a snapshot can be applied to a row
    without a translation layer."""

    provider: BillingProvider
    subscription_reference: BillingProviderReference
    customer_reference: BillingProviderReference
    plan_id: PlanId
    billing_interval: BillingInterval
    status: str  # raw provider status string; caller normalizes
    billable_seats: int
    current_period_start: datetime | None
    current_period_end: datetime | None
    cancel_at_period_end: bool


@dataclass(frozen=True)
class ProviderOperationResult:
    """Typed, explicit result for an adapter operation that may not be
    implemented yet (message-1 spec item 16). Never a silent fallback to
    another provider — the caller must check ``state`` before trusting
    any other field."""

    state: str  # "ok" | "not_configured" | "unsupported_before_m2"
    detail: str = ""


class BillingProviderAdapter(abc.ABC):
    """Provider-neutral billing operations. Every concrete adapter
    (``adapters.stripe.StripeBillingAdapter``,
    ``adapters.paddle.PaddleBillingAdapter``) implements this exact
    surface — callers never import a concrete adapter directly; they go
    through ``app.billing.registry.get_billing_provider``."""

    provider: BillingProvider

    @abc.abstractmethod
    def create_checkout(self, request: CheckoutRequest) -> CheckoutResponse: ...

    @abc.abstractmethod
    def create_portal(self, request: PortalRequest) -> PortalResponse: ...

    @abc.abstractmethod
    def get_customer(self, reference: BillingProviderReference) -> BillingProviderReference: ...

    @abc.abstractmethod
    def get_subscription(
        self, reference: BillingProviderReference
    ) -> NormalizedSubscriptionSnapshot | None: ...

    @abc.abstractmethod
    def update_subscription(self, request: SubscriptionUpdateRequest) -> ProviderOperationResult: ...

    @abc.abstractmethod
    def cancel_subscription(self, request: CancelSubscriptionRequest) -> ProviderOperationResult: ...

    @abc.abstractmethod
    def parse_webhook(self, headers: dict, body: bytes) -> dict: ...

    @abc.abstractmethod
    def reconcile(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None: ...
