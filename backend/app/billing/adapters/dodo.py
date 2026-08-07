"""Dodo Payments billing adapter (Dodo Payments message 1, Test Mode).

Implements the existing ``BillingProviderAdapter`` contract as a fresh,
independent adapter — no Paddle-specific API assumption is reused here.
Every Dodo API path, request field, and webhook event name below was
verified against official Dodo Payments documentation during this
message's research (see the implementation report for exact source
pages); where documentation was insufficient, the behavior is implemented
behind a clearly isolated method and flagged below AND in the
implementation report as still requiring a real Test Mode verification.

Catalog model (verified, genuinely different from Stripe/Paddle)
-------------------------------------------------------------------
Dodo embeds price directly in the product — there is no separate "Price"
resource the way Stripe/Paddle have Product+Price as two objects. A
product has exactly one active price. This means the Dodo catalog mapping
below holds PRODUCT ids (``pro_product_id``, ``team_product_id``), not
price ids, plus one ADD-ON id (``team_seat_addon_id``) for the seat
add-on, which is its own separate object type in Dodo's model (verified:
"Add-ons for Subscriptions" — created as separate products, attached to a
subscription product via ``product_cart[].addons[]`` at checkout or
``change-plan``).

Post-implementation documentation audit (re-verified against current
official Dodo docs after the initial commit)
-------------------------------------------------------------------------
* CONFIRMED: removing the Team seat add-on entirely (desired quantity 0)
  is done by sending ``addons: []`` — Dodo's change-plan documentation
  states verbatim "Leaving this empty would remove any existing addons" /
  "Empty array removes all existing add-ons." This adapter's choice
  (item 2 below) is therefore confirmed correct, not merely assumed.
* CONFIRMED: the checkout ``product_cart`` shape — ``addons`` nests
  INSIDE each cart item alongside ``product_id``/``quantity`` — matches
  the documented schema exactly (verified against the official checkout
  session request schema).
* CONFIRMED: ``GET /subscriptions/{subscription_id}`` exists as the
  single-subscription retrieval path — the official Python SDK exposes
  ``client.subscriptions.retrieve(subscription_id)``, which is Dodo's
  Stainless-generated-SDK convention for ``GET /{resource}/{id}`` (the
  same pattern Stripe's own generated SDKs use).
* Still NOT explicitly confirmed by an official worked example: whether
  add-on ``quantity`` multiplies the add-on's unit price. This adapter
  still implements quantity-multiplies-price (the same behavior every
  other Dodo quantity field documents, and the only behavior consistent
  with "3 additional seats" style examples in Dodo's own add-ons page),
  but no official example shows the arithmetic explicitly.
* Still NOT documented anywhere fetched: the customer-portal URL's host
  (for a host-allowlist check analogous to Paddle's). This adapter
  therefore does NOT allowlist-validate the portal URL host (an
  intentional gap, not a guess) — see ``_validate_management_url``'s
  docstring below.

Original items, re-numbered to match the above
-------------------------------------------------------------
1. Add-on quantity multiplication — still an assumption, now more
   strongly corroborated (see above).
2. Zero-quantity add-on representation — CONFIRMED correct (see above).
3. ``GET /subscriptions/{id}`` response shape — path CONFIRMED (see
   above); the exact field-by-field response shape used by
   ``_snapshot_from_dodo_subscription`` below is still inferred from the
   subscription object's documented fields elsewhere (webhook payload,
   PATCH response), not from a dedicated GET-response example.
4. The customer-portal URL's host — still undocumented (see above).

Every one of these is repeated in the implementation report's "Behaviors
still requiring a real Dodo Test Mode verification" section.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from app.billing.dodo_client import DodoAPIClient
from app.billing.dodo_webhooks import verify_dodo_signature
from app.billing.enums import BillingInterval, BillingProvider, ObjectType, PlanId
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
from app.billing.seat_reconciliation import calculate_desired_additional_quantity

# Verified proration-mode enum (docs.dodopayments.com/api-reference/subscriptions/change-plan).
# Deliberately NOT Paddle's vocabulary — Dodo documents 4 distinct modes.
DODO_PRORATION_PRORATED_IMMEDIATELY = "prorated_immediately"
DODO_PRORATION_FULL_IMMEDIATELY = "full_immediately"
DODO_PRORATION_DIFFERENCE_IMMEDIATELY = "difference_immediately"
DODO_PRORATION_DO_NOT_BILL = "do_not_bill"

# ConfigTrace's own policy choice (not Dodo-mandated), mirroring the
# already-established Paddle asymmetric proration policy: a seat ADDED is
# charged immediately; a seat REMOVED takes effect at the next renewal
# rather than issuing a mid-cycle credit.
PRORATION_MODE_SEAT_ADDED = DODO_PRORATION_PRORATED_IMMEDIATELY
PRORATION_MODE_SEAT_REMOVED = DODO_PRORATION_DO_NOT_BILL


@dataclass(frozen=True)
class DodoCatalogMapping:
    """Configuration contract mapping internal plans to Dodo catalog
    objects. Unlike Paddle's ``PaddlePriceMapping`` (price IDs only),
    this holds PRODUCT ids for Pro/Team (Dodo has no separate Price
    resource) plus one ADD-ON id for the Team seat add-on."""

    environment: str  # "test" | "live"
    pro_product_id: str | None
    team_product_id: str | None
    team_seat_addon_id: str | None

    @property
    def is_configured(self) -> bool:
        return bool(self.pro_product_id and self.team_product_id and self.team_seat_addon_id)

    def product_id_for_plan(self, plan_id: PlanId) -> str | None:
        if plan_id == PlanId.PRO:
            return self.pro_product_id
        if plan_id == PlanId.TEAM:
            return self.team_product_id
        return None


class DodoNotConfiguredError(Exception):
    """Typed, explicit "not configured" state — raised when Dodo is
    selected but has no catalog mapping / API client configured. Never a
    silent fallback to Stripe or Paddle."""


class DodoUnsupportedPlanError(ValueError):
    """Raised for a plan Dodo has no catalog mapping for (i.e. FREE,
    which is never checked out through any provider)."""


def _validate_management_url(url: str) -> None:
    """No documented Dodo customer-portal host was found during this
    message's research (unlike Paddle's documented
    customer-portal.paddle.com), so this function deliberately does NOT
    allowlist-check a host — doing so would mean guessing a host, which
    this message's instructions explicitly forbid. It exists as a single,
    isolated call site so a host allowlist can be added later, in one
    place, once the real Test Mode portal URL is observed. See the
    implementation report's "Test Mode verification required" list.
    """
    if not url:
        raise ValueError("Dodo did not return a customer-portal URL.")


class DodoBillingAdapter(BillingProviderAdapter):
    """Real Dodo Payments adapter (Test Mode). Every method either
    performs the corresponding Dodo API call (when configured) or raises
    ``DodoNotConfiguredError`` (when not) — never a silent fallback to
    another provider, never a fabricated response."""

    provider = BillingProvider.DODO

    def __init__(
        self,
        catalog_mapping: DodoCatalogMapping | None,
        client: DodoAPIClient | None = None,
        webhook_secret: str | None = None,
    ):
        self._catalog_mapping = catalog_mapping
        self._client = client
        self._webhook_secret = webhook_secret

    @property
    def is_configured(self) -> bool:
        return (
            self._catalog_mapping is not None
            and self._catalog_mapping.is_configured
            and self._client is not None
        )

    def _require_configured(self) -> DodoAPIClient:
        if not self.is_configured:
            raise DodoNotConfiguredError(
                "Dodo is not configured on this server (missing catalog mapping or API client)."
            )
        return self._client  # type: ignore[return-value]

    # ── Checkout ──────────────────────────────────────────────────────────

    def build_product_cart(self, plan_id: PlanId, billable_seat_count: int) -> list[dict]:
        """Build the Dodo ``product_cart`` for a Pro or Team checkout.

        Pro: a single item, quantity 1, no add-ons.
        Team: a single item, quantity 1; the additional-seat add-on is
        attached ONLY when ``calculate_desired_additional_quantity() > 0``
        (documented choice — see module docstring item 2)."""
        mapping = self._catalog_mapping
        assert mapping is not None  # guarded by _require_configured before this is called

        product_id = mapping.product_id_for_plan(plan_id)
        if product_id is None:
            raise DodoUnsupportedPlanError(f"Dodo has no catalog mapping for plan {plan_id!r}.")

        item: dict = {"product_id": product_id, "quantity": 1}
        if plan_id == PlanId.TEAM:
            additional_quantity = calculate_desired_additional_quantity(billable_seat_count)
            if additional_quantity > 0:
                item["addons"] = [{"addon_id": mapping.team_seat_addon_id, "quantity": additional_quantity}]
        return [item]

    def create_checkout(self, request: CheckoutRequest) -> CheckoutResponse:
        client = self._require_configured()
        product_cart = self.build_product_cart(request.plan_id, request.billable_seat_count)

        metadata = {
            "workspace_id": str(request.workspace_id),
            "configtrace_user_id": str(request.configtrace_user_id) if request.configtrace_user_id else "",
            "plan_id": request.plan_id.value,
            "included_member_count": 20 if request.plan_id == PlanId.TEAM else 0,
            "additional_seat_count": (
                calculate_desired_additional_quantity(request.billable_seat_count)
                if request.plan_id == PlanId.TEAM else 0
            ),
            "pricing_version": 1,
            "idempotency_reference": request.idempotency_reference or str(uuid.uuid4()),
        }

        body: dict = {
            "product_cart": product_cart,
            "return_url": request.success_url,
            "cancel_url": request.cancel_url,
            "metadata": metadata,
        }
        if request.customer_reference is not None:
            body["customer"] = {"customer_id": request.customer_reference.external_id}
        elif request.customer_email:
            body["customer"] = {"email": request.customer_email}

        response = client.create_checkout_session(body=body, correlation_id=metadata["idempotency_reference"])
        return CheckoutResponse(
            provider=self.provider,
            checkout_url=response.get("checkout_url", ""),
            external_reference=response.get("session_id"),
        )

    # ── Customer / portal ────────────────────────────────────────────────

    def get_customer(self, reference: BillingProviderReference) -> BillingProviderReference:
        client = self._require_configured()
        data = client.get_customer(reference.external_id)
        return BillingProviderReference(
            provider=self.provider, object_type=ObjectType.CUSTOMER,
            external_id=data.get("customer_id", reference.external_id), workspace_id=reference.workspace_id,
            metadata={"email": data.get("email", "")},
        )

    def create_portal(self, request: PortalRequest) -> PortalResponse:
        client = self._require_configured()
        response = client.create_customer_portal_session(
            request.customer_reference.external_id, return_url=request.return_url
        )
        management_url = response.get("link", "")
        _validate_management_url(management_url)
        return PortalResponse(
            provider=self.provider,
            management_url=management_url,
            supported_actions=("view_invoices", "update_payment_method", "cancel_subscription"),
        )

    # ── Subscription reads ───────────────────────────────────────────────

    def get_subscription(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None:
        client = self._require_configured()
        data = client.get_subscription(reference.external_id)
        if not data:
            return None
        return self._snapshot_from_dodo_subscription(data, reference.workspace_id)

    def reconcile(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None:
        return self.get_subscription(reference)

    def _snapshot_from_dodo_subscription(self, data: dict, workspace_id: uuid.UUID) -> NormalizedSubscriptionSnapshot:
        product_id = data.get("product_id", "")
        mapping = self._catalog_mapping
        plan_id = PlanId.TEAM
        if mapping is not None and product_id == mapping.pro_product_id:
            plan_id = PlanId.PRO

        additional_quantity = 0
        for addon in data.get("addons", []) or []:
            if mapping is not None and addon.get("addon_id") == mapping.team_seat_addon_id:
                additional_quantity = addon.get("quantity", 0)

        billable_seats = (20 + additional_quantity) if plan_id == PlanId.TEAM else 0

        customer = data.get("customer") or {}
        return NormalizedSubscriptionSnapshot(
            provider=self.provider,
            subscription_reference=BillingProviderReference(
                provider=self.provider, object_type=ObjectType.SUBSCRIPTION,
                external_id=data.get("subscription_id", ""), workspace_id=workspace_id,
            ),
            customer_reference=BillingProviderReference(
                provider=self.provider, object_type=ObjectType.CUSTOMER,
                external_id=customer.get("customer_id", ""), workspace_id=workspace_id,
            ),
            plan_id=plan_id,
            billing_interval=BillingInterval.MONTH,
            status=data.get("status", ""),
            billable_seats=billable_seats,
            current_period_start=_parse_iso(data.get("previous_billing_date")),
            current_period_end=_parse_iso(data.get("next_billing_date")),
            cancel_at_period_end=bool(data.get("cancel_at_next_billing_date")),
        )

    # ── Team additional-seat add-on updates (seat reconciliation) ────────

    def update_subscription(self, request: SubscriptionUpdateRequest) -> ProviderOperationResult:
        """Update the Team additional-seat add-on quantity via the
        verified ``POST /subscriptions/{id}/change-plan`` endpoint —
        confirmed (not guessed) as the correct endpoint for both
        plan/product AND add-on-quantity changes.
        """
        client = self._require_configured()
        mapping = self._catalog_mapping
        assert mapping is not None

        desired_additional = calculate_desired_additional_quantity(request.billable_seat_count)

        current = client.get_subscription(request.subscription_reference.external_id)
        observed_additional = 0
        for addon in (current.get("addons", []) or []):
            if addon.get("addon_id") == mapping.team_seat_addon_id:
                observed_additional = addon.get("quantity", 0)

        proration_mode = (
            PRORATION_MODE_SEAT_ADDED if desired_additional > observed_additional else PRORATION_MODE_SEAT_REMOVED
        )

        body: dict = {
            "product_id": mapping.team_product_id,
            "quantity": 1,
            "proration_billing_mode": proration_mode,
        }
        # Documented choice (module docstring item 2): omit the add-on
        # entirely when the desired quantity is 0, rather than sending an
        # explicit quantity:0 entry.
        if desired_additional > 0:
            body["addons"] = [{"addon_id": mapping.team_seat_addon_id, "quantity": desired_additional}]
        else:
            body["addons"] = []

        client.change_plan(request.subscription_reference.external_id, body=body)
        return ProviderOperationResult(state="ok", detail=f"updated to additional_quantity={desired_additional}")

    # ── Plan change on an existing subscription (double-billing fix) ────

    def change_subscription_plan(
        self, *, subscription_reference: BillingProviderReference, target_plan_id: PlanId, billable_seat_count: int,
    ) -> ProviderOperationResult:
        """Change an EXISTING Dodo subscription's plan/product IN PLACE
        via the same verified ``POST /subscriptions/{id}/change-plan``
        endpoint ``update_subscription`` above already uses for seat
        changes — confirmed as the correct endpoint for product AND
        add-on changes, not a new/guessed capability.

        This is the fix for a confirmed production bug: a workspace
        upgrading Pro -> Team previously went through ``create_checkout``,
        which creates a brand-new, INDEPENDENT Dodo subscription while
        the original stayed active and billable — resulting in two live
        subscriptions for one customer. Calling change-plan against the
        EXISTING subscription's ID instead means Dodo mutates that same
        resource in place: the subscription ID is preserved (this is a
        POST to a path keyed by the existing ``{id}``, never a resource
        creation), and there is only ever one live subscription.

        NOT part of the ``BillingProviderAdapter`` ABC — Dodo-specific.
        The caller (``app/routers/billing.py``) only invokes this after
        confirming, from the workspace's own stored
        ``NormalizedSubscription`` row, that its existing provider is
        already Dodo; Stripe and Paddle are entirely unaffected by this
        method's existence.

        Proration mirrors the exact asymmetric policy ``update_subscription``
        above already applies to seat changes (an established, not a new,
        policy choice in this file): moving to a higher-priced plan is
        charged immediately (prorated); moving to a lower-priced plan
        takes effect without an immediate credit.
        """
        client = self._require_configured()
        mapping = self._catalog_mapping
        assert mapping is not None

        product_id = mapping.product_id_for_plan(target_plan_id)
        if product_id is None:
            raise DodoUnsupportedPlanError(f"Dodo has no catalog mapping for plan {target_plan_id!r}.")

        is_upgrade_to_team = target_plan_id == PlanId.TEAM
        proration_mode = PRORATION_MODE_SEAT_ADDED if is_upgrade_to_team else PRORATION_MODE_SEAT_REMOVED

        body: dict = {"product_id": product_id, "quantity": 1, "proration_billing_mode": proration_mode}
        if target_plan_id == PlanId.TEAM:
            additional_quantity = calculate_desired_additional_quantity(billable_seat_count)
            if additional_quantity > 0:
                body["addons"] = [{"addon_id": mapping.team_seat_addon_id, "quantity": additional_quantity}]
            else:
                body["addons"] = []
        else:
            # Pro has no add-ons — explicitly clear any Team seat add-on
            # left over from a Team -> Pro downgrade.
            body["addons"] = []

        client.change_plan(subscription_reference.external_id, body=body)
        return ProviderOperationResult(state="ok", detail=f"changed_plan_to={target_plan_id.value}")

    # ── Cancellation ─────────────────────────────────────────────────────

    def cancel_subscription(self, request: CancelSubscriptionRequest) -> ProviderOperationResult:
        """Verified (not guessed) via PATCH /subscriptions/{id}'s
        documented fields: ``cancel_at_next_billing_date: true`` for a
        deferred cancellation, or ``status: "cancelled"`` to cancel
        immediately."""
        client = self._require_configured()
        if request.cancel_at_period_end:
            body = {"cancel_at_next_billing_date": True}
        else:
            body = {"status": "cancelled"}
        client.update_subscription(request.subscription_reference.external_id, body=body)
        return ProviderOperationResult(
            state="ok",
            detail="canceled effective_from=" + ("next_billing_date" if request.cancel_at_period_end else "immediately"),
        )

    # ── Webhooks ─────────────────────────────────────────────────────────

    def parse_webhook(self, headers: dict, body: bytes) -> dict:
        if not self._webhook_secret:
            raise DodoNotConfiguredError("Dodo webhook secret is not configured.")
        return verify_dodo_signature(body, headers, self._webhook_secret)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
