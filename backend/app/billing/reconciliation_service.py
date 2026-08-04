"""Subscription reconciliation service (Commercial Infrastructure message 2,
spec item 29).

Manually invokable operation: load the local subscription, fetch the
live Paddle subscription, validate customer/workspace correlation,
normalize state, reconcile seat quantities, update entitlements, append
an audit event. No uncontrolled background scheduler is created — this
is a plain function, callable from a test, a future admin endpoint, or a
future scheduled job, but nothing here starts a scheduler itself.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.billing.adapters.paddle import PaddleBillingAdapter
from app.billing.audit import record_audit_event
from app.billing.billable_seats import calculate_billable_member_count
from app.billing.entitlements import decide_entitlements
from app.billing.enums import BillingAuditEventType, BillingProvider, ObjectType, PlanId
from app.billing.models import NormalizedSubscription
from app.billing.paddle_webhook_service import normalize_paddle_status
from app.billing.provider import BillingProviderReference
from app.billing.seat_reconciliation import plan_seat_reconciliation


class WorkspaceCustomerMismatchError(ValueError):
    """Raised when the Paddle subscription's customer_id does not match
    the customer_id stored locally for this workspace — a potential
    misconfiguration or cross-workspace mixup that must NEVER be silently
    resolved by reassignment."""


@dataclass(frozen=True)
class ReconciliationResult:
    workspace_id: uuid.UUID
    updated: bool
    seat_update_applied: bool
    new_status: str
    reason: str


def reconcile_workspace_subscription(
    workspace_id: uuid.UUID, adapter: PaddleBillingAdapter, db: Session
) -> ReconciliationResult:
    """Reconcile one workspace's Paddle subscription against live Paddle
    state. Never mutates a Stripe subscription — the caller must only
    invoke this for a workspace whose stored provider is Paddle."""
    sub = (
        db.query(NormalizedSubscription)
        .filter(NormalizedSubscription.workspace_id == workspace_id, NormalizedSubscription.provider == "paddle")
        .first()
    )
    if sub is None or not sub.provider_subscription_reference:
        return ReconciliationResult(
            workspace_id=workspace_id, updated=False, seat_update_applied=False,
            new_status="none", reason="no_paddle_subscription_on_file",
        )

    reference = BillingProviderReference(
        provider=BillingProvider.PADDLE, object_type=ObjectType.SUBSCRIPTION,
        external_id=sub.provider_subscription_reference, workspace_id=workspace_id,
    )
    snapshot = adapter.get_subscription(reference)
    if snapshot is None:
        return ReconciliationResult(
            workspace_id=workspace_id, updated=False, seat_update_applied=False,
            new_status=sub.status, reason="paddle_subscription_not_found",
        )

    if (
        sub.provider_customer_reference
        and snapshot.customer_reference.external_id
        and sub.provider_customer_reference != snapshot.customer_reference.external_id
    ):
        raise WorkspaceCustomerMismatchError(
            f"workspace {workspace_id} stored customer reference does not match "
            "the Paddle subscription's customer_id — refusing to silently reassign."
        )

    previous_status = sub.status
    normalized_status = normalize_paddle_status(snapshot.status)
    sub.status = normalized_status.value
    sub.current_period_start = snapshot.current_period_start
    sub.current_period_end = snapshot.current_period_end
    sub.cancel_at_period_end = snapshot.cancel_at_period_end
    sub.version += 1
    db.flush()

    seat_update_applied = False
    current_members = calculate_billable_member_count(workspace_id, db)
    plan = plan_seat_reconciliation(
        current_billable_members=current_members,
        observed_additional_quantity=max(0, snapshot.billable_seats - 20),
    )
    if plan.needs_update:
        from app.billing.provider import SubscriptionUpdateRequest

        adapter.update_subscription(
            SubscriptionUpdateRequest(
                subscription_reference=reference, billable_seat_count=current_members, reason="reconciliation",
            )
        )
        seat_update_applied = True
        record_audit_event(
            workspace_id=workspace_id, event_type=BillingAuditEventType.SEAT_COUNT_CHANGED,
            provider=BillingProvider.PADDLE,
            details={"reason": "reconciliation", "billable_seats": current_members}, db=db,
        )

    record_audit_event(
        workspace_id=workspace_id, event_type=BillingAuditEventType.PROVIDER_RECONCILIATION,
        provider=BillingProvider.PADDLE,
        details={"previous_status": previous_status, "new_status": sub.status}, db=db,
    )

    return ReconciliationResult(
        workspace_id=workspace_id, updated=True, seat_update_applied=seat_update_applied,
        new_status=sub.status, reason="reconciled",
    )
