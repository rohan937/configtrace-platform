"""Security finding note + activity service — M61.3.

Public surface
--------------
:func:`list_notes`     — list all notes for a finding (oldest first)
:func:`create_note`    — append a review note to a finding
:func:`build_activity` — derive a combined activity feed from a finding + notes

Security / design
-----------------
* Callers (routers) verify workspace membership (via
  ``security_finding_service.get_finding_for_user``) before calling these.
* ``body`` is stored as-is after strip + length validation (defence in depth;
  the schema validator already ran).
* Notes are append-only — no update/delete endpoint.
* A note NEVER mutates the finding's status or lifecycle fields.
* The activity feed is DERIVED at read time from existing finding lifecycle
  fields plus the notes — no separate audit table, no notifications.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy.orm import Session

from app.models.security_finding import SecurityFinding
from app.models.security_finding_note import SecurityFindingNote, _NOTE_BODY_MAX_LEN

logger = logging.getLogger(__name__)


# ── Notes ─────────────────────────────────────────────────────────────────────


def list_notes(finding_id: uuid.UUID, db: Session) -> List[SecurityFindingNote]:
    """Return all notes for *finding_id* ordered oldest-first."""
    return (
        db.query(SecurityFindingNote)
        .filter(SecurityFindingNote.finding_id == finding_id)
        .order_by(SecurityFindingNote.created_at.asc())
        .all()
    )


def create_note(
    *,
    finding_id: uuid.UUID,
    workspace_id: Optional[uuid.UUID],
    author_user_id: Optional[uuid.UUID],
    body: str,
    db: Session,
) -> SecurityFindingNote:
    """Create and persist a new SecurityFindingNote.

    Raises :exc:`ValueError` if *body* is empty or exceeds the max length
    (the schema validator should have caught this; defence in depth).
    """
    body = (body or "").strip()
    if not body:
        raise ValueError("Note body must not be empty.")
    if len(body) > _NOTE_BODY_MAX_LEN:
        raise ValueError(
            f"Note body must be {_NOTE_BODY_MAX_LEN} characters or fewer."
        )

    note = SecurityFindingNote(
        finding_id=finding_id,
        workspace_id=workspace_id,
        author_user_id=author_user_id,
        body=body,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    logger.info(
        "SecurityFindingNote created: finding=%s workspace=%s author=%s",
        finding_id,
        workspace_id,
        author_user_id,
    )
    return note


# ── Activity feed (derived) ───────────────────────────────────────────────────

# Stable ordering for items that share a timestamp (deterministic feed).
_TYPE_ORDER = {
    "exposure_opened": 0,
    "acknowledged": 1,
    "snoozed": 2,
    "accepted_risk": 3,
    "note_added": 4,
    "resolved": 5,
}


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


def build_activity(
    *,
    finding: SecurityFinding,
    notes: List[SecurityFindingNote],
) -> List[dict[str, Any]]:
    """Build a combined, deterministic activity feed for a finding.

    Items are derived from the finding's own lifecycle fields plus its review
    notes — there is no separate audit table. Careful wording is used: nothing
    is described as "fixed" unless the finding is actually resolved.

    Returned newest-first; ties broken by a stable per-type order then id.
    """
    items: List[dict[str, Any]] = []

    # Exposure opened — always present (first_detected_at is non-null).
    if finding.first_detected_at is not None:
        items.append(
            {
                "type": "exposure_opened",
                "timestamp": _iso(finding.first_detected_at),
                "actor_user_id": None,
                "title": "Exposure opened",
                "description": "ConfigTrace first detected this risky configuration state.",
                "metadata": {"severity": finding.severity},
            }
        )

    # Review actions derived from status + reviewed_at (M61.1 / M61.2).
    reviewed_at_iso = _iso(finding.reviewed_at)
    actor = str(finding.reviewed_by_user_id) if finding.reviewed_by_user_id else None

    if finding.reviewed_at is not None:
        if finding.status == "active":
            items.append(
                {
                    "type": "acknowledged",
                    "timestamp": reviewed_at_iso,
                    "actor_user_id": actor,
                    "title": "Acknowledged",
                    "description": "Reviewed by the team; the exposure remains active.",
                    "metadata": {},
                }
            )
        elif finding.status == "snoozed":
            items.append(
                {
                    "type": "snoozed",
                    "timestamp": reviewed_at_iso,
                    "actor_user_id": actor,
                    "title": "Snoozed",
                    "description": "Active attention paused temporarily; the risk is not accepted.",
                    "metadata": {"snoozed_until": _iso(finding.snoozed_until)},
                }
            )
        elif finding.status == "accepted_risk":
            items.append(
                {
                    "type": "accepted_risk",
                    "timestamp": reviewed_at_iso,
                    "actor_user_id": actor,
                    "title": "Risk accepted",
                    "description": "The team is intentionally carrying this risk until the date below.",
                    "metadata": {
                        "accepted_until": _iso(finding.accepted_until),
                        "reason": finding.acceptance_reason,
                    },
                }
            )

    # Resolved.
    if finding.resolved_at is not None:
        items.append(
            {
                "type": "resolved",
                "timestamp": _iso(finding.resolved_at),
                "actor_user_id": None,
                "title": "Resolved",
                "description": "The risky configuration state is no longer present.",
                "metadata": {},
            }
        )

    # Review notes.
    for note in notes:
        items.append(
            {
                "type": "note_added",
                "timestamp": _iso(note.created_at),
                "actor_user_id": str(note.author_user_id) if note.author_user_id else None,
                "title": "Note added",
                "description": note.body,
                "metadata": {"note_id": str(note.id)},
            }
        )

    # Deterministic newest-first ordering. Empty/None timestamps sort last.
    def _sort_key(it: dict[str, Any]) -> tuple:
        ts = it.get("timestamp") or ""
        return (ts, _TYPE_ORDER.get(it["type"], 99), it["metadata"].get("note_id", ""))

    items.sort(key=_sort_key, reverse=True)
    return items
