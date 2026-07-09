"""Billing service — M52: Billing + Usage Limits.

Responsibilities
----------------
* Centralise plan limits configuration.
* get_or_create_billing()  — lazy-create the free row for new workspaces.
* get_workspace_usage()    — count integrations + members for a workspace.
* assert_can_*()           — raise HTTP 402 when a plan limit would be exceeded.
* create_checkout_session()— call Stripe API to begin a subscription upgrade.
* create_portal_session()  — call Stripe API to open the billing portal.
* handle_webhook_event()   — process inbound Stripe subscription events.

Stripe API
----------
Uses raw HTTPS requests via httpx (already installed).  The Stripe Python SDK
is deliberately not added as a dependency — the existing stripe connector in
app/connectors/stripe.py follows the same pattern.

Webhook signature verification
-------------------------------
Implements Stripe's HMAC-SHA256 scheme manually:
  signed_payload = f"{timestamp}.{raw_body}"
  expected_sig = HMAC-SHA256(webhook_secret, signed_payload)
Compare with the v1 value from the Stripe-Signature header.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.models.billing import WorkspaceBilling
from app.models.integration import Integration
from app.models.workspace import WorkspaceMember

logger = logging.getLogger(__name__)

# ── Plan configuration ────────────────────────────────────────────────────────
#
# This dict is the **single source of truth** for plan pricing, limits, and
# trial length on the server. The frontend mirrors the price + trial values
# in `frontend/src/app/(app)/settings/workspace/billing/page.tsx`
# (PLAN_META); the tests in `test_milestone58_25.py` enforce that the two
# stay aligned.
#
# Pricing (M58.25 — early-access)
# -------------------------------
# free : $0 / month, no trial
# pro  : $10 / month, 14-day trial
# team : $40 / month, 14-day trial
#
# Stripe is configured with **simple monthly recurring prices**. We do NOT
# rely on Stripe product-level trial configuration — instead, the checkout
# session adds `subscription_data[trial_period_days]` for plans whose
# `trial_days` value is > 0 (see `_trial_days_for_price` and
# `create_checkout_session`).
PLAN_LIMITS: Dict[str, Dict[str, Any]] = {
    "free": {
        "max_integrations": 3,
        "max_members": 1,
        "min_sync_interval_minutes": 60,
        "history_retention_days": 30,
        "monthly_price_usd": 0,
        "trial_days": 0,
    },
    "pro": {
        "max_integrations": 20,
        "max_members": 5,
        "min_sync_interval_minutes": 15,
        "history_retention_days": 180,
        "monthly_price_usd": 10,   # M58.25 early-access price
        "trial_days": 14,          # M58.25 early-access trial
    },
    "team": {
        "max_integrations": 100,
        "max_members": 25,
        "min_sync_interval_minutes": 5,
        "history_retention_days": 365,
        "monthly_price_usd": 40,   # M58.25 early-access price
        "trial_days": 14,          # M58.25 early-access trial
    },
}

# Plans whose subscriptions confer active access (not limited to free).
_ACTIVE_STATUSES = {"active", "trialing"}

# Stripe API base URL.
_STRIPE_API = "https://api.stripe.com/v1"

# Allowlist of price IDs that may be sent by the frontend.
# Populated lazily from settings so tests can override via monkeypatch.
#
# Required env vars (read via app.config.settings):
#   STRIPE_PRICE_PRO_MONTHLY  → Stripe price ID for ConfigTrace Pro $10/mo
#   STRIPE_PRICE_TEAM_MONTHLY → Stripe price ID for ConfigTrace Team $40/mo
# Price IDs are NEVER hardcoded in this file or anywhere else in the repo.
def _allowed_price_ids() -> set[str]:
    ids = set()
    pro_id = settings.effective_stripe_pro_price_id
    team_id = settings.effective_stripe_team_price_id
    if pro_id:
        ids.add(pro_id)
    if team_id:
        ids.add(team_id)
    return ids


def _plan_for_price(price_id: str) -> str:
    """Map a Stripe price ID to our internal plan name."""
    if price_id and price_id == settings.effective_stripe_pro_price_id:
        return "pro"
    if price_id and price_id == settings.effective_stripe_team_price_id:
        return "team"
    return "free"


def _trial_days_for_price(price_id: str) -> int:
    """Return the configured trial length (days) for a given Stripe price ID.

    Used by `create_checkout_session` to inject `subscription_data
    [trial_period_days]` into the Stripe Checkout request. Returns 0 if the
    price maps to a plan with no trial (e.g. free, or an unknown price).
    """
    plan = _plan_for_price(price_id)
    return int(PLAN_LIMITS.get(plan, {}).get("trial_days", 0) or 0)


# ── Core helpers ──────────────────────────────────────────────────────────────


def get_or_create_billing(workspace_id: uuid.UUID, db: Session) -> WorkspaceBilling:
    """Return the WorkspaceBilling row, creating a free one if absent."""
    billing = (
        db.query(WorkspaceBilling)
        .filter(WorkspaceBilling.workspace_id == workspace_id)
        .first()
    )
    if billing is None:
        billing = WorkspaceBilling(
            workspace_id=workspace_id,
            plan="free",
            status="active",
        )
        db.add(billing)
        db.flush()
    return billing


def get_plan_limits(plan: str) -> Dict[str, Any]:
    """Return limit config for the given plan name."""
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])


def _effective_plan(billing: WorkspaceBilling) -> str:
    """Return the plan name that should be enforced today.

    A workspace on a paid plan with a past_due/canceled/unpaid subscription
    falls back to free limits — we don't hard-downgrade the plan field in the
    DB until the webhook fires, but we enforce free limits immediately.
    """
    if billing.status in _ACTIVE_STATUSES:
        return billing.plan
    return "free"


def get_workspace_usage(workspace_id: uuid.UUID, db: Session) -> Dict[str, int]:
    """Return current counts for limit enforcement."""
    integration_count = (
        db.query(func.count(Integration.id))
        .filter(
            Integration.workspace_id == workspace_id,
        )
        .scalar()
        or 0
    )
    member_count = (
        db.query(func.count(WorkspaceMember.id))
        .filter(WorkspaceMember.workspace_id == workspace_id)
        .scalar()
        or 0
    )
    return {
        "integrations": integration_count,
        "members": member_count,
    }


# ── Limit assertions ──────────────────────────────────────────────────────────


def assert_can_create_integration(workspace_id: uuid.UUID, db: Session) -> None:
    """Raise HTTP 402 if the workspace is at its integration limit.

    Does nothing if workspace_id is None (legacy unscoped integrations).
    """
    if workspace_id is None:
        return
    billing = get_or_create_billing(workspace_id, db)
    plan = _effective_plan(billing)
    limits = get_plan_limits(plan)
    usage = get_workspace_usage(workspace_id, db)

    if usage["integrations"] >= limits["max_integrations"]:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "integration_limit_exceeded",
                "message": (
                    f"Your {plan} plan allows {limits['max_integrations']} integration(s). "
                    "Upgrade to add more."
                ),
                "current_plan": plan,
                "limit": limits["max_integrations"],
                "current_count": usage["integrations"],
            },
        )


def assert_can_add_member(workspace_id: uuid.UUID, db: Session) -> None:
    """Raise HTTP 402 if the workspace is at its member limit."""
    billing = get_or_create_billing(workspace_id, db)
    plan = _effective_plan(billing)
    limits = get_plan_limits(plan)
    usage = get_workspace_usage(workspace_id, db)

    if usage["members"] >= limits["max_members"]:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "member_limit_exceeded",
                "message": (
                    f"Your {plan} plan allows {limits['max_members']} member(s). "
                    "Upgrade to add more."
                ),
                "current_plan": plan,
                "limit": limits["max_members"],
                "current_count": usage["members"],
            },
        )


# ── Stripe API helpers ────────────────────────────────────────────────────────


def _stripe_post(path: str, data: dict) -> dict:
    """Make an authenticated POST request to the Stripe API."""
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=503,
            detail="Stripe is not configured on this server.",
        )
    resp = httpx.post(
        f"{_STRIPE_API}{path}",
        data=data,
        auth=(settings.STRIPE_SECRET_KEY, ""),
        timeout=15.0,
    )
    if resp.status_code >= 400:
        body = resp.json()
        error_msg = body.get("error", {}).get("message", "Stripe error.")
        logger.error("Stripe API error %d: %s", resp.status_code, error_msg)
        raise HTTPException(status_code=502, detail=f"Stripe error: {error_msg}")
    return resp.json()


def _get_or_create_stripe_customer(
    billing: WorkspaceBilling,
    workspace_name: str,
    owner_email: Optional[str],
    db: Session,
) -> str:
    """Return the Stripe customer ID, creating one if needed."""
    if billing.stripe_customer_id:
        return billing.stripe_customer_id

    customer_data: dict = {"metadata[workspace_id]": str(billing.workspace_id)}
    if workspace_name:
        customer_data["name"] = workspace_name
    if owner_email:
        customer_data["email"] = owner_email

    customer = _stripe_post("/customers", customer_data)
    billing.stripe_customer_id = customer["id"]
    db.flush()
    return customer["id"]


def create_checkout_session(
    billing: WorkspaceBilling,
    price_id: str,
    workspace_name: str,
    owner_email: Optional[str],
    db: Session,
) -> str:
    """Create a Stripe Checkout Session and return the URL.

    Security: price_id is validated against the server-side allowlist before
    being sent to Stripe — the client cannot substitute an arbitrary price.
    """
    allowed = _allowed_price_ids()
    if not allowed:
        raise HTTPException(
            status_code=503,
            detail="Stripe prices are not configured on this server.",
        )
    if price_id not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid price ID.",
        )

    frontend_url = settings.effective_frontend_url
    customer_id = _get_or_create_stripe_customer(
        billing, workspace_name, owner_email, db
    )

    # M58.25: build the Checkout request, then conditionally attach the trial
    # period. We do not configure trials at the Stripe product level — the
    # server is the source of truth for `trial_days` (see PLAN_LIMITS).
    #
    # M58.26 — card-required trial policy
    # ------------------------------------
    # `payment_method_collection` is *intentionally* left unset so Stripe
    # uses its default value of "always". With `subscription_data
    # [trial_period_days]` set, that default means:
    #
    #   • Checkout requires a card on file even though today's charge is $0.
    #   • The subscription begins in `status="trialing"`.
    #   • After 14 days the saved card is charged $10 (Pro) or $40 (Team)
    #     unless the user cancels through the Stripe Customer Portal.
    #
    # We deliberately do NOT pass `payment_method_collection="if_required"`,
    # which would allow a no-card trial — that mode requires extra logic to
    # handle missing payment methods at trial-end and is out of scope.
    checkout_data: dict[str, Any] = {
        "mode": "subscription",
        "customer": customer_id,
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": (
            f"{frontend_url}/settings/workspace/billing"
            "?checkout=success&session_id={CHECKOUT_SESSION_ID}"
        ),
        "cancel_url": f"{frontend_url}/settings/workspace/billing?checkout=canceled",
        "allow_promotion_codes": "true",
        "metadata[workspace_id]": str(billing.workspace_id),
    }

    # Inject 14-day trial for Pro / Team via Stripe's nested-form syntax.
    # `subscription_data[trial_period_days]` is documented at
    # https://stripe.com/docs/api/checkout/sessions/create#create_checkout_session-subscription_data
    trial_days = _trial_days_for_price(price_id)
    if trial_days > 0:
        checkout_data["subscription_data[trial_period_days]"] = str(trial_days)

    session = _stripe_post("/checkout/sessions", checkout_data)
    return session["url"]


def create_portal_session(
    billing: WorkspaceBilling,
    db: Session,
) -> str:
    """Create a Stripe Billing Portal session and return the URL.

    M58.26 — this is the **single cancellation path**.

    The Stripe-hosted Customer Portal is the only place where ConfigTrace
    users can cancel a subscription, update a card, or download invoices.
    The app does not implement a custom "Cancel plan" UI; trialing and
    active subscribers both reach cancellation by clicking *Manage billing*
    in the app, which redirects here.

    Trialing subscribers (status="trialing") can open the portal — the
    Stripe customer ID is created at first checkout and persists for the
    lifetime of the subscription. Workspaces on the free plan that have
    never subscribed have no `stripe_customer_id`, so the route returns
    400 with a clear "Please subscribe first" message; the frontend
    interprets that as a hint to start a trial instead.

    Permissions required in the Stripe Dashboard (Settings → Billing →
    Customer portal): allow customers to cancel subscriptions, update
    payment methods, and view invoices. Return URL should be the app's
    billing page.
    """
    if not billing.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No Stripe customer found. Please subscribe first.",
        )
    frontend_url = settings.effective_frontend_url
    session = _stripe_post(
        "/billing_portal/sessions",
        {
            "customer": billing.stripe_customer_id,
            "return_url": f"{frontend_url}/settings/workspace/billing",
        },
    )
    return session["url"]


# ── Webhook processing ────────────────────────────────────────────────────────


def verify_stripe_signature(raw_body: bytes, sig_header: str) -> dict:
    """Verify the Stripe-Signature header and return the parsed event dict.

    Stripe signs webhooks using HMAC-SHA256:
      signed_payload = f"{timestamp}.{raw_body_string}"
      expected = HMAC-SHA256(webhook_secret, signed_payload)

    The Stripe-Signature header format:
      t=<unix_timestamp>,v1=<hex_signature>[,v1=<hex_signature>...]

    Raises ValueError on bad signature or stale timestamp (> 5 minutes).
    """
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise ValueError("STRIPE_WEBHOOK_SECRET is not configured.")

    # Parse header into key=value pairs.
    pairs: dict[str, str] = {}
    for part in sig_header.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            pairs.setdefault(k.strip(), v.strip())

    timestamp_str = pairs.get("t", "")
    v1_sig = pairs.get("v1", "")

    if not timestamp_str or not v1_sig:
        raise ValueError("Malformed Stripe-Signature header.")

    # Freshness check: reject events older than 5 minutes.
    try:
        ts = int(timestamp_str)
    except ValueError:
        raise ValueError("Non-integer timestamp in Stripe-Signature header.")

    if abs(time.time() - ts) > 300:
        raise ValueError(
            f"Stripe webhook timestamp too old or too far in the future: {ts}"
        )

    # Compute expected signature.
    signed_payload = f"{timestamp_str}.{raw_body.decode('utf-8')}"
    expected = hmac.new(
        settings.STRIPE_WEBHOOK_SECRET.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, v1_sig):
        raise ValueError("Stripe webhook signature mismatch.")

    return json.loads(raw_body)


def handle_webhook_event(event: dict, db: Session) -> None:
    """Update WorkspaceBilling based on a verified Stripe event.

    Handled events
    --------------
    checkout.session.completed      — subscription created; set plan + active
    customer.subscription.updated   — plan change, renewal, cancellation scheduled
    customer.subscription.deleted   — subscription ended; revert to free
    invoice.payment_failed          — mark past_due
    invoice.payment_succeeded       — mark active (clears past_due)

    M59.4 idempotency
    ------------------
    The event_id is checked against ``stripe_webhook_events`` at the start
    and a row is added at the end.  A duplicate event short-circuits to
    a safe no-op.  Concurrent races are resolved by the unique constraint
    on ``stripe_webhook_events.event_id``: the loser of the race surfaces
    ``IntegrityError`` at commit time, which the router catches and treats
    as a duplicate.
    """
    from app.models.billing import StripeWebhookEvent

    event_id = event.get("id")
    event_type = event.get("type", "")
    data_obj = event.get("data", {}).get("object", {})

    # ── Idempotency check ────────────────────────────────────────────────────
    if event_id:
        existing = (
            db.query(StripeWebhookEvent)
            .filter(StripeWebhookEvent.event_id == event_id)
            .first()
        )
        if existing is not None:
            logger.info(
                "Stripe webhook duplicate event_id=%s type=%s — skipping",
                event_id, event_type,
            )
            return

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(data_obj, db)
    elif event_type in (
        "customer.subscription.updated",
        "customer.subscription.created",
    ):
        _handle_subscription_updated(data_obj, db)
    elif event_type == "customer.subscription.deleted":
        _handle_subscription_deleted(data_obj, db)
    elif event_type == "invoice.payment_failed":
        _handle_payment_failed(data_obj, db)
    elif event_type in ("invoice.payment_succeeded", "invoice.paid"):
        _handle_payment_succeeded(data_obj, db)
    else:
        logger.debug("Unhandled Stripe event type: %s", event_type)

    # ── Record event id for future-replay dedupe (M59.4) ─────────────────────
    # Done at the END so a processing exception rolls back this row too;
    # a subsequent Stripe retry will then process the event cleanly.
    if event_id:
        db.add(StripeWebhookEvent(event_id=event_id, event_type=event_type))
        # flush surfaces unique-constraint violations now rather than at commit
        try:
            db.flush()
        except Exception:
            # Concurrent webhook for the same event_id committed first —
            # we lost the race.  Roll back our row and let the caller commit
            # any other work that succeeded (in practice this branch is rare).
            logger.info(
                "Stripe webhook race on event_id=%s — duplicate detected at flush",
                event_id,
            )
            # We must not re-raise here, otherwise the caller's outer try
            # will treat the whole webhook as failed.  Just expunge our row.
            db.rollback()


def _billing_by_customer(customer_id: str, db: Session) -> Optional[WorkspaceBilling]:
    return (
        db.query(WorkspaceBilling)
        .filter(WorkspaceBilling.stripe_customer_id == customer_id)
        .first()
    )


def _billing_by_subscription(sub_id: str, db: Session) -> Optional[WorkspaceBilling]:
    return (
        db.query(WorkspaceBilling)
        .filter(WorkspaceBilling.stripe_subscription_id == sub_id)
        .first()
    )


def _apply_subscription(billing: WorkspaceBilling, sub: dict) -> None:
    """Update billing fields from a Stripe subscription object."""
    billing.stripe_subscription_id = sub.get("id")
    billing.stripe_price_id = (
        sub.get("items", {}).get("data", [{}])[0].get("price", {}).get("id")
    )
    billing.plan = _plan_for_price(billing.stripe_price_id or "")
    billing.status = sub.get("status", "active")
    billing.cancel_at_period_end = bool(sub.get("cancel_at_period_end", False))

    period_start = sub.get("current_period_start")
    period_end = sub.get("current_period_end")
    if period_start:
        billing.current_period_start = datetime.fromtimestamp(
            period_start, tz=timezone.utc
        )
    if period_end:
        billing.current_period_end = datetime.fromtimestamp(
            period_end, tz=timezone.utc
        )
    trial_end = sub.get("trial_end")
    billing.trial_end = (
        datetime.fromtimestamp(trial_end, tz=timezone.utc) if trial_end else None
    )


def _handle_checkout_completed(obj: dict, db: Session) -> None:
    customer_id = obj.get("customer")
    if not customer_id:
        return
    billing = _billing_by_customer(customer_id, db)
    if billing is None:
        # Try to find via workspace_id in metadata.
        ws_id_str = obj.get("metadata", {}).get("workspace_id")
        if ws_id_str:
            try:
                billing = get_or_create_billing(uuid.UUID(ws_id_str), db)
                billing.stripe_customer_id = customer_id
            except Exception:
                logger.warning("checkout.session.completed: bad workspace_id %r", ws_id_str)
                return
        else:
            logger.warning("checkout.session.completed: no billing for customer %s", customer_id)
            return

    # The session has a subscription field only for subscription mode.
    sub_id = obj.get("subscription")
    if sub_id:
        billing.stripe_subscription_id = sub_id
        # We'll get full details from the customer.subscription.created event.
        # Just mark active so the user sees immediate feedback.
        billing.status = "active"
        db.flush()


def _handle_subscription_updated(sub: dict, db: Session) -> None:
    sub_id = sub.get("id")
    customer_id = sub.get("customer")
    billing = _billing_by_subscription(sub_id, db) if sub_id else None
    if billing is None and customer_id:
        billing = _billing_by_customer(customer_id, db)
    if billing is None:
        logger.warning("subscription.updated: no billing for sub %s / customer %s", sub_id, customer_id)
        return
    _apply_subscription(billing, sub)
    db.flush()


def _handle_subscription_deleted(sub: dict, db: Session) -> None:
    sub_id = sub.get("id")
    billing = _billing_by_subscription(sub_id, db) if sub_id else None
    if billing is None:
        return
    billing.plan = "free"
    billing.status = "active"  # Back to free/active
    billing.stripe_subscription_id = None
    billing.stripe_price_id = None
    billing.current_period_start = None
    billing.current_period_end = None
    billing.cancel_at_period_end = False
    billing.trial_end = None
    db.flush()


def _handle_payment_failed(obj: dict, db: Session) -> None:
    sub_id = obj.get("subscription")
    billing = _billing_by_subscription(sub_id, db) if sub_id else None
    if billing is None:
        return
    billing.status = "past_due"
    db.flush()


def _handle_payment_succeeded(obj: dict, db: Session) -> None:
    sub_id = obj.get("subscription")
    billing = _billing_by_subscription(sub_id, db) if sub_id else None
    if billing is None:
        return
    # Clears both past_due and unpaid — a successful payment restores access.
    if billing.status in ("past_due", "unpaid"):
        billing.status = "active"
        db.flush()
