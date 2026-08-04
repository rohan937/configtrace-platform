"""Real Paddle billing adapter (Commercial Infrastructure message 2).

Message 1 shipped this as a contract-only stub (every operation raised a
typed "not configured" / "unsupported before M2" state, never a live
call). Message 2 replaces the stub with a real implementation backed by
``app.billing.paddle_client.PaddleAPIClient`` — every operation now
performs (or, when unconfigured, still refuses to perform) the
corresponding Paddle API call.

Still true, unchanged from message 1: an unconfigured Paddle adapter
NEVER silently falls back to Stripe — every operation raises
``PaddleNotConfiguredError`` instead.

Planned Team subscription representation (message-1 spec item 13,
unchanged): ONE Team base recurring item, quantity 1, mapped to
``PaddlePriceMapping.base_price_id``; ONE additional-seat recurring item,
quantity ``max(0, seats - 20)``, mapped to
``PaddlePriceMapping.additional_seat_price_id`` — OMITTED from the
subscription entirely when quantity is 0 (message-2 spec item 23's
documented choice; see ``commercial_infrastructure_paddle_seat_matrix.md``
for the zero-quantity transition tests and the honest caveat that this
choice has not been verified against a live Paddle sandbox in this
message).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from app.billing.enums import BillingInterval, BillingProvider, ObjectType, PlanId
from app.billing.paddle_client import PaddleAPIClient, PaddleValidationError
from app.billing.paddle_webhooks import verify_paddle_signature
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
from app.billing.seat_reconciliation import (
    PRORATION_MODE_SEAT_ADDED,
    PRORATION_MODE_SEAT_REMOVED,
    calculate_desired_additional_quantity,
)

_ALLOWED_MANAGEMENT_URL_HOSTS = frozenset({"customer-portal.paddle.com", "sandbox-customer-portal.paddle.com"})

TEAM_BASE_COMPONENT_ID = "team_base_monthly"
TEAM_ADDITIONAL_SEAT_COMPONENT_ID = "team_additional_seat_monthly"


@dataclass(frozen=True)
class PaddlePriceMapping:
    """Configuration contract mapping internal price components to Paddle
    catalog objects (message-1 spec item 13)."""

    environment: str  # "sandbox" | "production"
    base_price_id: str | None
    additional_seat_price_id: str | None

    @property
    def is_configured(self) -> bool:
        return bool(self.base_price_id and self.additional_seat_price_id)


class PaddleNotConfiguredError(Exception):
    """Typed, explicit "not configured" state — raised when Paddle is
    selected but has no price mapping / API client configured. Never a
    silent fallback to Stripe."""


class PaddleUnsupportedBeforeM2Error(NotImplementedError):
    """Retained for backward compatibility with message-1 call sites and
    tests that reference this name; message 2 no longer raises it from
    any adapter method (every operation is implemented), but the class
    stays importable so nothing that referenced it breaks."""


class PaddleManagementUrlHostError(ValueError):
    """Raised when Paddle returns a management URL whose host is not one
    of the known Paddle customer-portal hosts — a defense-in-depth check
    against ever redirecting a user to an unexpected domain."""


class PaddleBaseItemMissingError(ValueError):
    """Raised when a subscription-item update would be attempted without
    a discoverable Team base item — refuses to guess or fabricate one."""


class PaddleDuplicateBaseItemError(ValueError):
    """Raised when a subscription unexpectedly has more than one item
    mapped to the Team base price — an unexpected/conflicting catalog
    state this adapter refuses to silently resolve."""


def _validate_management_url(url: str) -> None:
    from urllib.parse import urlparse

    host = urlparse(url).netloc
    if host not in _ALLOWED_MANAGEMENT_URL_HOSTS:
        raise PaddleManagementUrlHostError(f"Unexpected Paddle management URL host: {host!r}")


class PaddleBillingAdapter(BillingProviderAdapter):
    """Real Paddle adapter. Every method either performs the
    corresponding Paddle API call (when configured) or raises
    ``PaddleNotConfiguredError`` (when not) — never a silent Stripe
    fallback, never a fabricated response."""

    provider = BillingProvider.PADDLE

    def __init__(
        self,
        price_mapping: PaddlePriceMapping | None,
        client: PaddleAPIClient | None = None,
        webhook_secret: str | None = None,
    ):
        self._price_mapping = price_mapping
        self._client = client
        self._webhook_secret = webhook_secret

    @property
    def is_configured(self) -> bool:
        return (
            self._price_mapping is not None
            and self._price_mapping.is_configured
            and self._client is not None
        )

    def _require_configured(self) -> PaddleAPIClient:
        if not self.is_configured:
            raise PaddleNotConfiguredError(
                "Paddle is not configured on this server (missing price mapping or API client)."
            )
        return self._client  # type: ignore[return-value]

    # ── Checkout ──────────────────────────────────────────────────────────

    def build_checkout_items(self, billable_seat_count: int) -> list[dict]:
        """Build the Paddle line-item list for a Team checkout: always the
        base item (quantity 1); the additional-seat item ONLY when
        quantity > 0 (message-2 spec item 8/23's documented choice)."""
        mapping = self._price_mapping
        assert mapping is not None  # guarded by _require_configured before this is called
        items = [{"price_id": mapping.base_price_id, "quantity": 1}]
        additional_quantity = calculate_desired_additional_quantity(billable_seat_count)
        if additional_quantity > 0:
            items.append({"price_id": mapping.additional_seat_price_id, "quantity": additional_quantity})
        return items

    def create_checkout(self, request: CheckoutRequest) -> CheckoutResponse:
        client = self._require_configured()
        items = self.build_checkout_items(request.billable_seat_count)
        custom_data = {
            "workspace_id": str(request.workspace_id),
            "plan_id": request.plan_id.value,
            "billable_seat_count": request.billable_seat_count,
            "pricing_version": 1,
            "idempotency_reference": request.idempotency_reference or str(uuid.uuid4()),
        }
        response = client.create_checkout(
            items=items, custom_data=custom_data, correlation_id=custom_data["idempotency_reference"]
        )
        data = response.get("data", response)
        checkout_url = (data.get("checkout") or {}).get("url", "")
        return CheckoutResponse(
            provider=self.provider,
            checkout_url=checkout_url,
            external_reference=data.get("id"),
        )

    # ── Customer / portal ────────────────────────────────────────────────

    def get_customer(self, reference: BillingProviderReference) -> BillingProviderReference:
        client = self._require_configured()
        data = client.get_customer(reference.external_id).get("data", {})
        return BillingProviderReference(
            provider=self.provider, object_type=ObjectType.CUSTOMER,
            external_id=data.get("id", reference.external_id), workspace_id=reference.workspace_id,
            metadata={"email": data.get("email", "")},
        )

    def create_portal(self, request: PortalRequest) -> PortalResponse:
        client = self._require_configured()
        response = client.get_customer_portal_session(request.customer_reference.external_id)
        data = response.get("data", {})
        urls = data.get("urls", {})
        general = urls.get("general", {})
        management_url = general.get("overview", "")
        if management_url:
            _validate_management_url(management_url)
        return PortalResponse(
            provider=self.provider,
            management_url=management_url,
            supported_actions=("view_invoices", "update_payment_method", "cancel_subscription"),
        )

    # ── Subscription reads ───────────────────────────────────────────────

    def get_subscription(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None:
        client = self._require_configured()
        response = client.get_subscription(reference.external_id)
        data = response.get("data")
        if data is None:
            return None
        return self._snapshot_from_paddle_subscription(data, reference.workspace_id)

    def reconcile(self, reference: BillingProviderReference) -> NormalizedSubscriptionSnapshot | None:
        return self.get_subscription(reference)

    def _snapshot_from_paddle_subscription(self, data: dict, workspace_id: uuid.UUID) -> NormalizedSubscriptionSnapshot:
        items = data.get("items", [])
        additional_quantity = 0
        mapping = self._price_mapping
        if mapping is not None:
            for item in items:
                price_id = (item.get("price") or {}).get("id") or item.get("price_id")
                if price_id == mapping.additional_seat_price_id:
                    additional_quantity = item.get("quantity", 0)

        return NormalizedSubscriptionSnapshot(
            provider=self.provider,
            subscription_reference=BillingProviderReference(
                provider=self.provider, object_type=ObjectType.SUBSCRIPTION,
                external_id=data.get("id", ""), workspace_id=workspace_id,
            ),
            customer_reference=BillingProviderReference(
                provider=self.provider, object_type=ObjectType.CUSTOMER,
                external_id=data.get("customer_id", ""), workspace_id=workspace_id,
            ),
            plan_id=PlanId.TEAM,
            billing_interval=BillingInterval.MONTH,
            status=data.get("status", ""),
            billable_seats=20 + additional_quantity,
            current_period_start=_parse_iso(data.get("current_billing_period", {}).get("starts_at")),
            current_period_end=_parse_iso(data.get("current_billing_period", {}).get("ends_at")),
            cancel_at_period_end=bool(data.get("scheduled_change")),
        )

    # ── Subscription item updates (seat reconciliation) ──────────────────

    def update_subscription(self, request: SubscriptionUpdateRequest) -> ProviderOperationResult:
        client = self._require_configured()
        mapping = self._price_mapping
        assert mapping is not None

        current = client.get_subscription(request.subscription_reference.external_id).get("data", {})
        current_items = current.get("items", [])

        base_items = [
            i for i in current_items
            if ((i.get("price") or {}).get("id") or i.get("price_id")) == mapping.base_price_id
        ]
        if not base_items:
            raise PaddleBaseItemMissingError(
                f"Subscription {request.subscription_reference.external_id} has no Team base item — refusing to update."
            )
        if len(base_items) > 1:
            raise PaddleDuplicateBaseItemError(
                f"Subscription {request.subscription_reference.external_id} has multiple Team base items — refusing to update."
            )

        desired_additional = calculate_desired_additional_quantity(request.billable_seat_count)
        observed_additional = 0
        for item in current_items:
            price_id = (item.get("price") or {}).get("id") or item.get("price_id")
            if price_id == mapping.additional_seat_price_id:
                observed_additional = item.get("quantity", 0)

        new_items = [{"price_id": mapping.base_price_id, "quantity": 1}]
        if desired_additional > 0:
            new_items.append({"price_id": mapping.additional_seat_price_id, "quantity": desired_additional})
        # Preserve any unrelated recurring item unchanged (message-2 spec
        # item 22: "never accidentally remove unrelated recurring items").
        for item in current_items:
            price_id = (item.get("price") or {}).get("id") or item.get("price_id")
            if price_id not in (mapping.base_price_id, mapping.additional_seat_price_id):
                new_items.append({"price_id": price_id, "quantity": item.get("quantity", 1)})

        proration_mode = (
            PRORATION_MODE_SEAT_ADDED if desired_additional > observed_additional else PRORATION_MODE_SEAT_REMOVED
        )

        client.update_subscription_items(
            request.subscription_reference.external_id, items=new_items, proration_billing_mode=proration_mode,
        )
        return ProviderOperationResult(state="ok", detail=f"updated to additional_quantity={desired_additional}")

    # ── Cancellation ─────────────────────────────────────────────────────

    def cancel_subscription(self, request: CancelSubscriptionRequest) -> ProviderOperationResult:
        client = self._require_configured()
        effective_from = "next_billing_period" if request.cancel_at_period_end else "immediately"
        client.cancel_subscription(request.subscription_reference.external_id, effective_from=effective_from)
        return ProviderOperationResult(state="ok", detail=f"canceled effective_from={effective_from}")

    # ── Webhooks ─────────────────────────────────────────────────────────

    def parse_webhook(self, headers: dict, body: bytes) -> dict:
        if not self._webhook_secret:
            raise PaddleNotConfiguredError("Paddle webhook secret is not configured.")
        sig_header = headers.get("paddle-signature", "")
        return verify_paddle_signature(body, sig_header, self._webhook_secret)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
