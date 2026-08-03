"""Stripe compatibility adapter (Commercial Infrastructure message 1).

Wraps the EXISTING Stripe-specific behavior in
``app.services.billing_service`` behind the provider-neutral
``BillingProviderAdapter`` interface. This is isolation, not expansion
(message-1 spec item 14) — it does not reimplement Stripe behavior, it
only translates between the provider-neutral request/response types and
the existing service functions' native (dict/string) shapes.

No Stripe SDK type (``stripe.Subscription``, etc.) crosses this
boundary — the existing service already speaks in plain dicts (it uses
raw ``httpx`` calls, not the Stripe SDK), so this adapter's job is purely
shape translation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.billing.entitlements import normalize_stripe_status
from app.billing.enums import BillingInterval, BillingProvider, ObjectType, PlanId
from app.billing.events import normalize_stripe_event
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
from app.services import billing_service


def _plan_id_for_stripe_plan(plan_name: str) -> PlanId:
    return PlanId.TEAM if plan_name == "team" else PlanId.FREE


class StripeBillingAdapter(BillingProviderAdapter):
    """Provider-neutral wrapper around the existing Stripe billing flows.

    Every method here takes/returns only provider-neutral types; internally
    it fetches the real ``WorkspaceBilling`` row and calls the existing
    ``billing_service`` functions exactly as the router already does.
    """

    provider = BillingProvider.STRIPE

    def __init__(self, db: Session):
        self._db = db

    def create_checkout(self, request: CheckoutRequest) -> CheckoutResponse:
        billing = billing_service.get_or_create_billing(request.workspace_id, self._db)
        # The existing service takes a Stripe price_id directly (already
        # validated against the server-side allowlist inside
        # create_checkout_session) — message 1 does not change that
        # contract, it only requires the caller to have resolved a price_id
        # via the existing PLAN_LIMITS/settings path before calling here.
        price_id = (
            billing_service.settings.effective_stripe_team_price_id
            if request.plan_id == PlanId.TEAM
            else billing_service.settings.effective_stripe_pro_price_id
        )
        checkout_url = billing_service.create_checkout_session(
            billing=billing,
            price_id=price_id or "",
            workspace_name="",
            owner_email=request.customer_email,
            db=self._db,
        )
        return CheckoutResponse(provider=self.provider, checkout_url=checkout_url)

    def create_portal(self, request: PortalRequest) -> PortalResponse:
        billing = billing_service.get_or_create_billing(request.workspace_id, self._db)
        portal_url = billing_service.create_portal_session(billing=billing, db=self._db)
        return PortalResponse(provider=self.provider, management_url=portal_url)

    def get_customer(self, reference: BillingProviderReference) -> BillingProviderReference:
        return reference

    def get_subscription(
        self, reference: BillingProviderReference
    ) -> NormalizedSubscriptionSnapshot | None:
        billing = (
            self._db.query(billing_service.WorkspaceBilling)
            .filter(billing_service.WorkspaceBilling.stripe_subscription_id == reference.external_id)
            .first()
        )
        if billing is None:
            return None
        return self._snapshot_from_billing(billing)

    def update_subscription(self, request: SubscriptionUpdateRequest) -> ProviderOperationResult:
        # Message 1 does not implement live seat-quantity updates against
        # Stripe — the existing flow has no per-seat pricing to update.
        # This is intentionally out of scope until Paddle cutover.
        return ProviderOperationResult(
            state="unsupported_before_m2",
            detail="Stripe seat-quantity updates are not implemented; Team pricing "
            "changes take effect via Paddle checkout in message 2+.",
        )

    def cancel_subscription(self, request: CancelSubscriptionRequest) -> ProviderOperationResult:
        # Existing product behavior: cancellation happens ONLY through the
        # Stripe-hosted Customer Portal (see billing_service.create_portal_session
        # docstring) — there is no programmatic cancel_subscription call in
        # the existing codebase to wrap. Documented, not silently invented.
        return ProviderOperationResult(
            state="unsupported_before_m2",
            detail="Cancellation is only available via the Stripe Customer Portal "
            "(create_portal) in the existing product; no programmatic cancel API "
            "is wrapped here.",
        )

    def parse_webhook(self, headers: dict, body: bytes) -> dict:
        sig_header = headers.get("stripe-signature", "")
        return billing_service.verify_stripe_signature(body, sig_header)

    def reconcile(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None:
        return self.get_subscription(reference)

    def _snapshot_from_billing(self, billing) -> NormalizedSubscriptionSnapshot:
        return NormalizedSubscriptionSnapshot(
            provider=self.provider,
            subscription_reference=BillingProviderReference(
                provider=self.provider,
                object_type=ObjectType.SUBSCRIPTION,
                external_id=billing.stripe_subscription_id or "",
                workspace_id=billing.workspace_id,
            ),
            customer_reference=BillingProviderReference(
                provider=self.provider,
                object_type=ObjectType.CUSTOMER,
                external_id=billing.stripe_customer_id or "",
                workspace_id=billing.workspace_id,
            ),
            plan_id=_plan_id_for_stripe_plan(billing.plan),
            billing_interval=BillingInterval.MONTH,
            status=billing.status,
            billable_seats=0,
            current_period_start=billing.current_period_start,
            current_period_end=billing.current_period_end,
            cancel_at_period_end=billing.cancel_at_period_end,
        )


def normalize_and_dispatch_webhook(event: dict, db: Session):
    """Convenience helper used by tests and (optionally) a future router
    update: normalize a verified Stripe event via ``app.billing.events``
    without touching the existing ``handle_webhook_event`` dispatch, which
    remains the actual processing path in message 1 (message-1 spec item
    14: isolation, not rewrite)."""
    return normalize_stripe_event(event)
