"""Billing management routes — M52: Billing + Usage Limits.

Routes
------
GET  /workspaces/{workspace_id}/billing          — get billing info + usage
POST /workspaces/{workspace_id}/billing/checkout — create Stripe Checkout session
POST /workspaces/{workspace_id}/billing/portal   — create Stripe Billing Portal session

Access control
--------------
All routes require the caller to be an admin or owner of the workspace.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import UUID4, BaseModel
from sqlalchemy.orm import Session

import uuid as uuid_module

from app.billing.billable_seats import calculate_billable_member_count
from app.billing.enums import BillingInterval, BillingProvider, PlanId
from app.billing.models import NormalizedSubscription
from app.billing.pricing import calculate_team_monthly_price
from app.billing.provider import CancelSubscriptionRequest, CheckoutRequest as NeutralCheckoutRequest, PortalRequest
from app.billing.provider_routing import provider_for_checkout, provider_for_management
from app.billing.reconciliation_service import reconcile_workspace_subscription
from app.billing.registry import get_adapter_for_provider
from app.config import settings
from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.services import billing_service, workspace_service

router = APIRouter(tags=["billing"])


# ── Schemas ───────────────────────────────────────────────────────────────────


class BillingResponse(BaseModel):
    workspace_id: UUID4
    plan: str
    status: str
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    current_period_start: str | None = None
    current_period_end: str | None = None
    cancel_at_period_end: bool
    trial_end: str | None = None
    # Computed fields
    limits: dict
    usage: dict
    # Safe Stripe config status — never exposes keys, secrets, or price IDs.
    # "test" | "live" | "not_configured"
    stripe_configured: bool = False
    stripe_mode: str = "not_configured"
    stripe_events_configured: bool = False
    # Commercial Infrastructure message 2: which provider a NEW checkout
    # would use right now — "stripe" | "paddle". Never implies anything
    # about an EXISTING subscription's provider (see
    # app.billing.provider_routing for that rule).
    checkout_provider: str = "stripe"

    model_config = {"from_attributes": True}


class CheckoutRequest(BaseModel):
    price_id: str


class CheckoutResponse(BaseModel):
    checkout_url: str


class PortalResponse(BaseModel):
    portal_url: str


# ── Helper ────────────────────────────────────────────────────────────────────


def _require_admin(workspace_id: uuid.UUID, user: User, db: Session) -> None:
    """Raise 403 unless the user is an admin or owner of the workspace."""
    try:
        workspace_service.require_role(workspace_id, user.id, "admin", db)
    except LookupError:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get(
    "/workspaces/{workspace_id}/billing",
    response_model=BillingResponse,
    summary="Get workspace billing info and usage",
)
def get_billing(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BillingResponse:
    """Return the billing row, plan limits, and current usage for a workspace."""
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    billing = billing_service.get_or_create_billing(workspace_id, db)  # type: ignore[arg-type]
    db.commit()  # persist lazy-created billing row

    # Show the *enforced* limits (based on effective plan, not nominal plan).
    # This means past_due/unpaid workspaces see the free limits they're now
    # subject to, not the pro/team limits they're nominally on.
    effective_plan = billing_service._effective_plan(billing)
    limits = billing_service.get_plan_limits(effective_plan)
    usage = billing_service.get_workspace_usage(workspace_id, db)  # type: ignore[arg-type]

    return BillingResponse(
        workspace_id=billing.workspace_id,
        plan=billing.plan,
        status=billing.status,
        stripe_customer_id=billing.stripe_customer_id,
        stripe_subscription_id=billing.stripe_subscription_id,
        current_period_start=(
            billing.current_period_start.isoformat()
            if billing.current_period_start else None
        ),
        current_period_end=(
            billing.current_period_end.isoformat()
            if billing.current_period_end else None
        ),
        cancel_at_period_end=billing.cancel_at_period_end,
        trial_end=(
            billing.trial_end.isoformat() if billing.trial_end else None
        ),
        limits=limits,
        usage=usage,
        stripe_configured=settings.is_stripe_configured,
        stripe_mode=settings.stripe_mode,
        stripe_events_configured=settings.is_webhook_configured,
        checkout_provider=settings.BILLING_PROVIDER or "stripe",
    )


@router.get(
    "/workspaces/{workspace_id}/billing/pricing-preview",
    summary="Provider-neutral Team pricing preview for this workspace",
)
def get_team_pricing_preview(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the current Team pricing breakdown for this workspace's real
    billable-member count. This is the SINGLE source of truth for Team
    pricing display — the frontend must never re-implement
    ``3000 + max(0, members - 20) * 500`` itself (Commercial Infrastructure
    message-1 spec item 30)."""
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    billable_members = calculate_billable_member_count(workspace_id, db)  # type: ignore[arg-type]
    breakdown = calculate_team_monthly_price(billable_members)
    return breakdown.as_dict()


@router.post(
    "/workspaces/{workspace_id}/billing/checkout",
    response_model=CheckoutResponse,
    summary="Create a Stripe Checkout session for upgrading",
)
def create_checkout(
    workspace_id: UUID4,
    body: CheckoutRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CheckoutResponse:
    """Return a Stripe Checkout URL.

    Security: the price_id is validated against the server-side allowlist before
    being sent to Stripe — clients cannot substitute an arbitrary price.
    """
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    billing = billing_service.get_or_create_billing(workspace_id, db)  # type: ignore[arg-type]

    # Fetch workspace name and owner email for Stripe customer metadata.
    from app.models.workspace import Workspace
    workspace = db.get(Workspace, workspace_id)
    workspace_name = workspace.name if workspace else ""

    checkout_url = billing_service.create_checkout_session(
        billing=billing,
        price_id=body.price_id,
        workspace_name=workspace_name,
        owner_email=current_user.email,
        db=db,
    )
    db.commit()
    return CheckoutResponse(checkout_url=checkout_url)


@router.post(
    "/workspaces/{workspace_id}/billing/portal",
    response_model=PortalResponse,
    summary="Create a Stripe Billing Portal session",
)
def create_portal(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PortalResponse:
    """Return a Stripe Billing Portal URL for managing the subscription."""
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    billing = billing_service.get_or_create_billing(workspace_id, db)  # type: ignore[arg-type]

    portal_url = billing_service.create_portal_session(billing=billing, db=db)
    return PortalResponse(portal_url=portal_url)


# ── Provider-neutral routes (Commercial Infrastructure message 2) ──────────────
#
# These dispatch via app.billing.provider_routing / app.billing.registry —
# they never assume Stripe. A new checkout always uses the CONFIGURED
# checkout provider (settings.BILLING_PROVIDER); managing an EXISTING
# subscription always uses the provider STORED on that subscription
# (message-2 spec item 31) — never reinterpreted by the global setting.


class NeutralCheckoutResponse(BaseModel):
    provider: str
    checkout_url: str
    # Paddle transaction ID — used by the frontend to open the Paddle.js
    # overlay checkout directly (Paddle.Checkout.open({transactionId}))
    # instead of a full page redirect. None for Stripe (which uses
    # checkout_url as a redirect target, as it always has).
    external_reference: str | None = None


def _create_plan_checkout(
    plan_id: PlanId, workspace_id: uuid.UUID, db: Session, current_user: User
) -> NeutralCheckoutResponse:
    """Shared, provider-neutral checkout builder for any billing-available
    plan (Dodo Payments message 1 — generalized from the Team-only helper
    that used to live inline in ``create_team_checkout``). The client never
    supplies a price ID, plan, or seat count (message-2 spec item 10);
    success/cancel URLs are built entirely server-side from
    ``settings.effective_frontend_url``, never accepted from the client."""
    provider = provider_for_checkout(workspace_id, db)
    adapter = get_adapter_for_provider(provider, db)

    billable_seats = calculate_billable_member_count(workspace_id, db)
    frontend_url = settings.effective_frontend_url
    request = NeutralCheckoutRequest(
        workspace_id=workspace_id,
        plan_id=plan_id,
        billing_interval=BillingInterval.MONTH,
        billable_seat_count=billable_seats,
        success_url=f"{frontend_url}/settings/workspace/billing?checkout=success",
        cancel_url=f"{frontend_url}/settings/workspace/billing?checkout=canceled",
        customer_email=current_user.email,
        idempotency_reference=f"{workspace_id}:{uuid_module.uuid4()}",
        configtrace_user_id=current_user.id,
    )
    response = adapter.create_checkout(request)
    return NeutralCheckoutResponse(
        provider=response.provider.value, checkout_url=response.checkout_url,
        external_reference=response.external_reference,
    )


@router.post(
    "/workspaces/{workspace_id}/billing/checkout/team",
    response_model=NeutralCheckoutResponse,
    summary="Create a provider-neutral Team checkout (routes to the configured provider)",
)
def create_team_checkout(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NeutralCheckoutResponse:
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    return _create_plan_checkout(PlanId.TEAM, workspace_id, db, current_user)  # type: ignore[arg-type]


@router.post(
    "/workspaces/{workspace_id}/billing/checkout/pro",
    response_model=NeutralCheckoutResponse,
    summary="Create a provider-neutral Pro checkout (routes to the configured provider)",
)
def create_pro_checkout(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NeutralCheckoutResponse:
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    return _create_plan_checkout(PlanId.PRO, workspace_id, db, current_user)  # type: ignore[arg-type]


class NeutralSubscriptionResponse(BaseModel):
    provider: str | None
    plan_id: str
    status: str
    billable_seats: int
    additional_seat_quantity: int
    cancel_at_period_end: bool
    current_period_end: str | None = None
    has_paid_access: bool
    grace_period_end: str | None = None


@router.get(
    "/workspaces/{workspace_id}/billing/subscription",
    response_model=NeutralSubscriptionResponse,
    summary="Get the provider-neutral current subscription + entitlement state",
)
def get_current_subscription(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NeutralSubscriptionResponse:
    """Never exposes provider technical IDs (subscription/customer
    references) — only provider-neutral, display-safe fields."""
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]

    from app.billing.entitlements import decide_entitlements, normalize_stripe_status
    from app.billing.paddle_webhook_service import normalize_paddle_status

    sub = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id)
        .first()
    )
    if sub is None:
        return NeutralSubscriptionResponse(
            provider=None, plan_id="free", status="active", billable_seats=0,
            additional_seat_quantity=0, cancel_at_period_end=False, has_paid_access=False,
        )

    if sub.provider == "paddle":
        normalizer = normalize_paddle_status
    elif sub.provider == "dodo":
        from app.billing.dodo_webhook_service import normalize_dodo_status

        normalizer = normalize_dodo_status
    else:
        normalizer = normalize_stripe_status
    normalized_status = normalizer(sub.status)
    decision = decide_entitlements(
        plan_id=PlanId(sub.plan_id) if sub.plan_id in ("free", "pro", "team") else PlanId.FREE,
        status=normalized_status,
        grace_period_end=sub.grace_period_end,
        source_provider=BillingProvider(sub.provider),
    )
    return NeutralSubscriptionResponse(
        provider=sub.provider,
        plan_id=decision.plan_id.value,
        status=normalized_status.value,
        billable_seats=sub.billable_seats,
        additional_seat_quantity=sub.additional_seat_quantity,
        cancel_at_period_end=sub.cancel_at_period_end,
        current_period_end=sub.current_period_end.isoformat() if sub.current_period_end else None,
        has_paid_access=decision.has_paid_access,
        grace_period_end=sub.grace_period_end.isoformat() if sub.grace_period_end else None,
    )


@router.post(
    "/workspaces/{workspace_id}/billing/management",
    response_model=PortalResponse,
    summary="Get a provider-neutral billing-management URL",
)
def get_management_url(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PortalResponse:
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    provider = provider_for_management(workspace_id, db)  # type: ignore[arg-type]
    adapter = get_adapter_for_provider(provider, db)

    if provider == BillingProvider.STRIPE:
        billing = billing_service.get_or_create_billing(workspace_id, db)  # type: ignore[arg-type]
        return PortalResponse(portal_url=billing_service.create_portal_session(billing=billing, db=db))

    sub = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id)
        .first()
    )
    if sub is None or not sub.provider_customer_reference:
        raise HTTPException(status_code=400, detail="No customer found. Please subscribe first.")

    from app.billing.enums import ObjectType
    from app.billing.provider import BillingProviderReference

    response = adapter.create_portal(
        PortalRequest(
            workspace_id=workspace_id,  # type: ignore[arg-type]
            customer_reference=BillingProviderReference(
                provider=provider, object_type=ObjectType.CUSTOMER,
                external_id=sub.provider_customer_reference, workspace_id=workspace_id,  # type: ignore[arg-type]
            ),
            return_url=f"{settings.effective_frontend_url}/settings/workspace/billing",
        )
    )
    return PortalResponse(portal_url=response.management_url)


class CancelResponse(BaseModel):
    provider: str
    state: str


@router.post(
    "/workspaces/{workspace_id}/billing/cancel",
    response_model=CancelResponse,
    summary="Cancel the current subscription at period end (provider-neutral)",
)
def cancel_current_subscription(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CancelResponse:
    """Default is cancel-at-period-end (message-2 spec item 25) — access
    is preserved through the current paid period."""
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    provider = provider_for_management(workspace_id, db)  # type: ignore[arg-type]

    if provider == BillingProvider.STRIPE:
        raise HTTPException(
            status_code=400,
            detail="Stripe subscriptions are canceled via the Billing Portal, not this endpoint.",
        )

    sub = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id)
        .first()
    )
    if sub is None or not sub.provider_subscription_reference:
        raise HTTPException(status_code=400, detail="No active subscription found.")

    from app.billing.enums import ObjectType
    from app.billing.provider import BillingProviderReference

    adapter = get_adapter_for_provider(provider, db)
    result = adapter.cancel_subscription(
        CancelSubscriptionRequest(
            subscription_reference=BillingProviderReference(
                provider=provider, object_type=ObjectType.SUBSCRIPTION,
                external_id=sub.provider_subscription_reference, workspace_id=workspace_id,  # type: ignore[arg-type]
            ),
            cancel_at_period_end=True,
        )
    )
    sub.cancel_at_period_end = True
    db.commit()
    return CancelResponse(provider=provider.value, state=result.state)


class ReconcileResponse(BaseModel):
    updated: bool
    seat_update_applied: bool
    new_status: str
    reason: str


@router.post(
    "/workspaces/{workspace_id}/billing/reconcile",
    response_model=ReconcileResponse,
    summary="Manually trigger seat/subscription reconciliation against Paddle (admin only)",
)
def trigger_reconciliation(
    workspace_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReconcileResponse:
    """Manually invokable reconciliation (message-2 spec item 29) — no
    background scheduler is created; this is the operation a future
    scheduled job (or an operator) would call."""
    _require_admin(workspace_id, current_user, db)  # type: ignore[arg-type]
    provider = provider_for_management(workspace_id, db)  # type: ignore[arg-type]
    if provider != BillingProvider.PADDLE:
        raise HTTPException(status_code=400, detail="Reconciliation is only implemented for Paddle subscriptions.")

    adapter = get_adapter_for_provider(provider, db)
    result = reconcile_workspace_subscription(workspace_id, adapter, db)  # type: ignore[arg-type]
    db.commit()
    return ReconcileResponse(
        updated=result.updated, seat_update_applied=result.seat_update_applied,
        new_status=result.new_status, reason=result.reason,
    )
