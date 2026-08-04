"""Provider routing rules (Commercial Infrastructure message 2, spec item 31).

The single rule this module exists to enforce: the global
``BILLING_PROVIDER`` setting decides which provider handles a NEW
checkout — it must NEVER be used to reinterpret an EXISTING subscription
as belonging to a different provider than the one it was actually created
with. A workspace that subscribed via Stripe stays a Stripe subscription
even after the deployment default flips to Paddle; a workspace with no
subscription yet always gets the currently-configured provider.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.billing.enums import BillingProvider
from app.billing.models import NormalizedSubscription
from app.config import settings


def configured_checkout_provider() -> BillingProvider:
    """The provider new checkouts should use — read from
    ``settings.BILLING_PROVIDER`` exactly once, in exactly this function,
    so no other module re-derives it independently."""
    raw = settings.BILLING_PROVIDER or "stripe"
    return BillingProvider(raw)


def get_stored_subscription_provider(workspace_id: uuid.UUID, db: Session) -> BillingProvider | None:
    """Return the provider actually recorded for this workspace's
    subscription, or None if no ``NormalizedSubscription`` row exists yet
    (a genuinely new workspace, which should use the configured checkout
    provider instead)."""
    sub = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id)
        .first()
    )
    if sub is None:
        return None
    return BillingProvider(sub.provider)


def provider_for_checkout(workspace_id: uuid.UUID, db: Session) -> BillingProvider:
    """New-checkout routing rule (message-2 spec item 31): if the
    workspace has NO existing subscription record, use the currently
    configured checkout provider. If it DOES have one (even a canceled or
    free one, since a `NormalizedSubscription` row persists), a "new"
    checkout for that workspace still starts a fresh subscription under
    the CONFIGURED provider — the stored-provider rule exists to protect
    subscription MANAGEMENT of an existing subscription, not to freeze a
    workspace to its first-ever provider forever once it has none.
    """
    return configured_checkout_provider()


def provider_for_management(workspace_id: uuid.UUID, db: Session) -> BillingProvider:
    """Existing-subscription routing rule: an existing subscription is
    ALWAYS managed by the provider stored on it — never reinterpreted via
    the global ``BILLING_PROVIDER`` setting. Falls back to the configured
    provider only when no subscription exists yet (nothing to manage)."""
    stored = get_stored_subscription_provider(workspace_id, db)
    return stored if stored is not None else configured_checkout_provider()


def provider_for_reconciliation(workspace_id: uuid.UUID, db: Session) -> BillingProvider | None:
    """Reconciliation always targets the STORED provider — returns None
    if there is nothing to reconcile (no subscription exists yet)."""
    return get_stored_subscription_provider(workspace_id, db)
