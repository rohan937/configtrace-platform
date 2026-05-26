"""Change review service — M57.2.

Public surface
--------------
:func:`get_review`               — load ChangeReview row (or None)
:func:`get_reviews_for_changes`  — bulk load review map {change_id: ChangeReview}
:func:`acknowledge_change`       — set status to "acknowledged"
:func:`mark_change_expected`     — set status to "expected"
:func:`snooze_change`            — set status to "snoozed" with expiry
:func:`reopen_change`            — reset status to "needs_review"
:func:`get_or_create_review`     — internal: upsert review row
:func:`resolve_workspace_for_change`  — derive workspace_id from change

Security / design
-----------------
* ``review_note`` and ``snooze_reason`` are plain text stored as-is.  The
  API layer should enforce length limits.  We re-check here as defence in depth.
* ``workspace_id`` is denormalised from ``Change.integration_id → Integration``
  at write time so the audit row always has a workspace scope.
* All write functions call :func:`log_audit_event` in the caller's transaction
  before committing so audit and data stay atomic.
* ``snoozed_until`` is validated to be in the future and at most 90 days out.

RBAC
----
Callers (routers) are responsible for verifying workspace membership before
calling any write function.  This service does NOT enforce RBAC internally.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.change_review import ChangeReview

logger = logging.getLogger(__name__)

# Maximum allowed snooze duration.
_MAX_SNOOZE_DAYS = 90
_NOTE_MAX_LEN = 1000


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def resolve_workspace_for_change(change: Change, db: Session) -> Optional[uuid.UUID]:
    """Derive workspace_id via Change → Integration.

    Returns None when the integration has no workspace (legacy row).
    """
    from app.models.integration import Integration
    integ = db.get(Integration, change.integration_id)
    if integ is None:
        return None
    return integ.workspace_id


# ── Read helpers ──────────────────────────────────────────────────────────────


def get_review(change_id: uuid.UUID, db: Session) -> Optional[ChangeReview]:
    """Return the ChangeReview row for *change_id*, or None if it doesn't exist."""
    return (
        db.query(ChangeReview)
        .filter(ChangeReview.change_id == change_id)
        .first()
    )


def get_reviews_for_changes(
    change_ids: list[uuid.UUID],
    db: Session,
) -> dict[uuid.UUID, ChangeReview]:
    """Bulk-load review rows for a list of change IDs.

    Returns a dict keyed by change_id.  Changes that have no review row are
    absent from the dict (callers treat that as ``needs_review``).
    """
    if not change_ids:
        return {}
    rows = (
        db.query(ChangeReview)
        .filter(ChangeReview.change_id.in_(change_ids))
        .all()
    )
    return {r.change_id: r for r in rows}


def get_or_create_review(
    change: Change,
    db: Session,
) -> ChangeReview:
    """Return the review row for *change*, inserting a default row if absent.

    Does NOT commit — callers commit when the full action is done.
    """
    row = get_review(change.id, db)
    if row is None:
        workspace_id = resolve_workspace_for_change(change, db)
        row = ChangeReview(
            change_id=change.id,
            workspace_id=workspace_id,
            review_status="needs_review",
        )
        db.add(row)
        db.flush()
    return row


# ── Write actions ─────────────────────────────────────────────────────────────


def acknowledge_change(
    change: Change,
    actor_user_id: uuid.UUID,
    db: Session,
    *,
    note: Optional[str] = None,
) -> ChangeReview:
    """Mark *change* as acknowledged.

    Sets review_status="acknowledged", reviewed_by_user_id, reviewed_at,
    and optionally review_note.  Emits an audit event.

    Returns the updated ChangeReview row (committed).
    """
    if note and len(note) > _NOTE_MAX_LEN:
        raise ValueError(f"Review note must not exceed {_NOTE_MAX_LEN} characters.")

    row = get_or_create_review(change, db)
    row.review_status = "acknowledged"
    row.reviewed_by_user_id = actor_user_id
    row.reviewed_at = _utcnow()
    row.review_note = note or None
    # Clear snooze fields if previously snoozed
    row.snoozed_until = None
    row.snooze_reason = None

    _emit_audit(change, row, "change_acknowledged", actor_user_id, db)
    db.commit()
    db.refresh(row)
    return row


def mark_change_expected(
    change: Change,
    actor_user_id: uuid.UUID,
    db: Session,
    *,
    note: Optional[str] = None,
) -> ChangeReview:
    """Mark *change* as expected / planned drift.

    Sets review_status="expected" and clears any prior snooze state.
    Emits an audit event.

    Returns the updated ChangeReview row (committed).
    """
    if note and len(note) > _NOTE_MAX_LEN:
        raise ValueError(f"Review note must not exceed {_NOTE_MAX_LEN} characters.")

    row = get_or_create_review(change, db)
    row.review_status = "expected"
    row.reviewed_by_user_id = actor_user_id
    row.reviewed_at = _utcnow()
    row.review_note = note or None
    row.snoozed_until = None
    row.snooze_reason = None

    _emit_audit(change, row, "change_marked_expected", actor_user_id, db)
    db.commit()
    db.refresh(row)
    return row


def snooze_change(
    change: Change,
    actor_user_id: uuid.UUID,
    db: Session,
    *,
    until: datetime,
    reason: Optional[str] = None,
) -> ChangeReview:
    """Snooze *change* until *until*.

    Validation:
    - ``until`` must be in the future (UTC).
    - ``until`` must be at most _MAX_SNOOZE_DAYS from now.

    Emits an audit event.  Returns the updated ChangeReview row (committed).
    """
    now = _utcnow()

    # Normalise to UTC-aware if naive
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)

    if until <= now:
        raise ValueError("Snooze 'until' must be in the future.")

    max_until = now + timedelta(days=_MAX_SNOOZE_DAYS)
    if until > max_until:
        raise ValueError(
            f"Snooze duration cannot exceed {_MAX_SNOOZE_DAYS} days."
        )

    if reason and len(reason) > _NOTE_MAX_LEN:
        raise ValueError(f"Snooze reason must not exceed {_NOTE_MAX_LEN} characters.")

    row = get_or_create_review(change, db)
    row.review_status = "snoozed"
    row.reviewed_by_user_id = actor_user_id
    row.reviewed_at = now
    row.review_note = None
    row.snoozed_until = until
    row.snooze_reason = reason or None

    _emit_audit(change, row, "change_snoozed", actor_user_id, db)
    db.commit()
    db.refresh(row)
    return row


def reopen_change(
    change: Change,
    actor_user_id: uuid.UUID,
    db: Session,
    *,
    note: Optional[str] = None,
) -> ChangeReview:
    """Reopen *change* — reset status to "needs_review".

    Clears reviewed_by, reviewed_at, review_note, snoozed_until, snooze_reason.
    Emits an audit event.  Returns the updated ChangeReview row (committed).
    """
    if note and len(note) > _NOTE_MAX_LEN:
        raise ValueError(f"Review note must not exceed {_NOTE_MAX_LEN} characters.")

    row = get_or_create_review(change, db)
    row.review_status = "needs_review"
    # Keep a note if the actor provided one (audit trail of why reopened)
    row.reviewed_by_user_id = actor_user_id
    row.reviewed_at = _utcnow()
    row.review_note = note or None
    row.snoozed_until = None
    row.snooze_reason = None

    _emit_audit(change, row, "change_reopened", actor_user_id, db)
    db.commit()
    db.refresh(row)
    return row


# ── Audit helper ──────────────────────────────────────────────────────────────


def _emit_audit(
    change: Change,
    review: ChangeReview,
    event_type: str,
    actor_user_id: uuid.UUID,
    db: Session,
) -> None:
    """Append an audit log entry for a review action.

    Safe metadata only — no raw diff values, no credentials.
    Does NOT commit; the caller commits the full transaction.
    """
    workspace_id = review.workspace_id
    if workspace_id is None:
        # Can't log without a workspace scope — skip silently.
        return

    from app.services.workspace_service import log_audit_event

    # Derive provider from Change.provider_metadata if available; otherwise
    # we'd need to join Integration — skip provider rather than add a DB call.
    record_type: Optional[str] = None
    if change.provider_metadata and isinstance(change.provider_metadata, dict):
        record_type = change.provider_metadata.get("record_type")

    metadata: dict = {
        "change_id": str(change.id),
        "risk_level": change.risk_level,
        "review_status": review.review_status,
    }
    if record_type:
        metadata["record_type"] = record_type
    if review.snoozed_until is not None:
        metadata["snoozed_until"] = review.snoozed_until.isoformat()

    log_audit_event(
        workspace_id=workspace_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        db=db,
        target_type="change",
        target_id=str(change.id),
        target_display_name=change.record_identifier,
        metadata=metadata,
    )
