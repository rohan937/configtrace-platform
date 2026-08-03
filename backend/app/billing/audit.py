"""Append-only billing audit events (Commercial Infrastructure message 1).

Never logs credentials, secrets, or a complete provider payload — only the
small, explicitly allowlisted ``details`` dict passed in by the caller.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.billing.enums import BillingAuditEventType, BillingProvider
from app.billing.models import BillingAuditEvent

# Keys a caller may legitimately include in `details` — anything else is
# stripped before persistence as a defense-in-depth measure against an
# accidental credential/payload leak at a call site.
_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "plan_id", "billing_interval", "billable_seats", "previous_status",
        "new_status", "previous_plan_id", "new_plan_id", "reason",
        "grace_period_end", "external_event_id", "event_type",
    }
)


def record_audit_event(
    *, workspace_id: uuid.UUID, event_type: BillingAuditEventType,
    provider: BillingProvider | None, details: dict, db: Session,
) -> BillingAuditEvent:
    """Append one audit event. ``details`` is filtered to the allowlisted
    key set before persistence — never trust a call site to have already
    scrubbed it."""
    safe_details = {k: v for k, v in details.items() if k in _ALLOWED_DETAIL_KEYS}
    row = BillingAuditEvent(
        workspace_id=workspace_id,
        event_type=event_type.value,
        provider=provider.value if provider else None,
        details=safe_details,
    )
    db.add(row)
    db.flush()
    return row
