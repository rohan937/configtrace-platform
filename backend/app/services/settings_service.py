"""User settings read/write — M34.

Provides get-or-create and upsert semantics so the GET endpoint never
returns 404 (it synthesises defaults if no row exists yet) and PATCH
creates the row on first write.

All operations are user-scoped: user_id is always taken from the
authenticated User object, never from request parameters.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.models.user_settings import UserSettings


def get_or_create_settings(user_id: uuid.UUID, db: Session) -> UserSettings:
    """Return the UserSettings row for *user_id*, creating one if absent.

    The created row uses all model defaults, which match existing hardcoded
    behavior (high_and_critical threshold, 3-failure trigger, 24h cooldown).

    Args:
        user_id: The authenticated user's UUID.
        db:      Active SQLAlchemy session.

    Returns:
        The UserSettings ORM object (possibly newly inserted).
    """
    row = (
        db.query(UserSettings)
        .filter(UserSettings.user_id == user_id)
        .first()
    )
    if row is None:
        row = UserSettings(user_id=user_id)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def update_settings(
    user_id: uuid.UUID,
    updates: dict,
    db: Session,
) -> UserSettings:
    """Apply *updates* dict to the user's settings row, creating it first if absent.

    Only keys present in *updates* are written; None values are silently skipped
    so callers can pass the Pydantic model's dict with ``exclude_none=True``.

    Args:
        user_id: The authenticated user's UUID.
        updates: Dict of field→value pairs.  Validated before calling this.
        db:      Active SQLAlchemy session.

    Returns:
        The updated UserSettings ORM object.
    """
    row = get_or_create_settings(user_id, db)
    for field, value in updates.items():
        if value is not None:
            setattr(row, field, value)
    db.commit()
    db.refresh(row)
    return row
