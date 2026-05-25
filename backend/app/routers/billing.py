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
    )


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
