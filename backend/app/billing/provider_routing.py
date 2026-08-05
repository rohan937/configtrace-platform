"""Provider routing rules (Commercial Infrastructure message 2, spec item 31;
Dodo Payments live-cutover preparation).

The core rule this module exists to enforce: the global
``BILLING_PROVIDER`` setting decides which provider handles a NEW
checkout — it must NEVER be used to reinterpret an EXISTING subscription
as belonging to a different provider than the one it was actually created
with. A workspace that subscribed via Stripe stays a Stripe subscription
even after the deployment default flips to Paddle; a workspace with no
subscription yet always gets the currently-configured provider.

One-workspace Dodo pilot override (live-cutover preparation)
--------------------------------------------------------------
``DODO_PILOT_WORKSPACE_ID`` (a plain workspace UUID, not a secret) lets
exactly one designated workspace's NEW checkouts route to Dodo while
``BILLING_PROVIDER`` stays "stripe" for every other workspace — see
``docs/deployment/dodo-live-cutover.md`` stage H. This override:

  * Applies ONLY inside ``provider_for_checkout`` — the "existing
    subscription" functions (``provider_for_management`` /
    ``provider_for_reconciliation``) are completely untouched, so the
    stored-provider-wins invariant remains the sole authority for any
    subscription that already exists, pilot workspace or not.
  * Fails closed: if Dodo is not fully configured
    (``settings.is_dodo_configured`` is False) the override is silently
    inert and the pilot workspace behaves exactly like every other
    workspace. A malformed or unset ``DODO_PILOT_WORKSPACE_ID`` is
    likewise inert (see ``Settings.dodo_pilot_workspace_id_parsed``).
  * Never changes ``BILLING_PROVIDER`` — removing the env var (or letting
    it expire) instantly reverts every future checkout, including the
    pilot workspace's, to the global default. Reversible with zero code
    deploy.
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


def is_dodo_pilot_workspace(workspace_id: uuid.UUID) -> bool:
    """True only when ``DODO_PILOT_WORKSPACE_ID`` is set, well-formed, and
    equal to this workspace's ID. Comparison only — no DB access, no side
    effects, safe to call from anywhere."""
    pilot_id = settings.dodo_pilot_workspace_id_parsed
    return pilot_id is not None and pilot_id == workspace_id


def dodo_pilot_override_active(workspace_id: uuid.UUID) -> bool:
    """True only when the pilot override actually changes anything for
    this workspace: it IS the designated pilot workspace, Dodo IS fully
    configured, AND the global default is NOT already "dodo" (in which
    case there is nothing to "override" — every workspace already routes
    to Dodo and this function correctly reports no override in effect)."""
    return (
        is_dodo_pilot_workspace(workspace_id)
        and settings.is_dodo_configured
        and configured_checkout_provider() != BillingProvider.DODO
    )


def provider_for_checkout(workspace_id: uuid.UUID, db: Session) -> BillingProvider:
    """New-checkout routing rule (message-2 spec item 31): if the
    workspace has NO existing subscription record, use the currently
    configured checkout provider. If it DOES have one (even a canceled or
    free one, since a `NormalizedSubscription` row persists), a "new"
    checkout for that workspace still starts a fresh subscription under
    the CONFIGURED provider — the stored-provider rule exists to protect
    subscription MANAGEMENT of an existing subscription, not to freeze a
    workspace to its first-ever provider forever once it has none.

    EXCEPTION (Dodo live-cutover preparation, additive and reversible):
    if this workspace is the designated ``DODO_PILOT_WORKSPACE_ID`` AND
    Dodo is fully configured, route to Dodo regardless of the global
    default — see this module's docstring. Every other workspace is
    completely unaffected by this setting existing.
    """
    if is_dodo_pilot_workspace(workspace_id) and settings.is_dodo_configured:
        return BillingProvider.DODO
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
