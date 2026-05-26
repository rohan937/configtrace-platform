"""Change note service — M58.8.

Public surface
--------------
:func:`list_notes`    — list all notes for a change (oldest first)
:func:`create_note`   — create a new note on a change

Security / design
-----------------
* Callers (routers) are responsible for verifying workspace membership via
  _get_change_and_workspace before calling any write function.
* body is stored as-is after strip + length validation (the schema validator
  already ran; we re-check here as defence in depth).
* workspace_id is denormalised from Change → Integration at write time.
* Notes are append-only for M58.8 MVP — no update/delete endpoint.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.change_note import ChangeNote, _NOTE_BODY_MAX_LEN

logger = logging.getLogger(__name__)


# ── Public API ────────────────────────────────────────────────────────────────


def list_notes(
    change_id: uuid.UUID,
    db: Session,
) -> List[ChangeNote]:
    """Return all notes for *change_id* ordered oldest-first."""
    return (
        db.query(ChangeNote)
        .filter(ChangeNote.change_id == change_id)
        .order_by(ChangeNote.created_at.asc())
        .all()
    )


def create_note(
    change_id: uuid.UUID,
    workspace_id: Optional[uuid.UUID],
    author_user_id: Optional[uuid.UUID],
    body: str,
    db: Session,
) -> ChangeNote:
    """Create and persist a new ChangeNote.

    Raises :exc:`ValueError` if *body* is empty or exceeds the maximum length.
    (Schema validators should have already caught this; this is defence in depth.)
    """
    body = body.strip()
    if not body:
        raise ValueError("Note body must not be empty.")
    if len(body) > _NOTE_BODY_MAX_LEN:
        raise ValueError(
            f"Note body must be {_NOTE_BODY_MAX_LEN} characters or fewer."
        )

    note = ChangeNote(
        change_id=change_id,
        workspace_id=workspace_id,
        author_user_id=author_user_id,
        body=body,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    logger.info(
        "ChangeNote created: change=%s workspace=%s author=%s",
        change_id,
        workspace_id,
        author_user_id,
    )
    return note
