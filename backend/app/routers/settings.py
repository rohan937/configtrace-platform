"""Settings router — M34.

Routes
------
GET   /settings   — return the authenticated user's settings (or defaults)
PATCH /settings   — update one or more settings fields

Settings are lazily created on first access: GET /settings never returns 404.
The initial values match current hardcoded behavior (high_and_critical
alert threshold, 3-failure trigger, 24h cooldown) so existing users see
no change until they explicitly update a setting.

All fields are validated by the Pydantic request schema.  Credentials and
secrets are never included in any response.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.settings import UserSettingsResponse, UserSettingsUpdateRequest
from app.services import settings_service

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=UserSettingsResponse)
def get_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserSettingsResponse:
    """Return the authenticated user's settings, creating defaults if none exist.

    Always returns HTTP 200 — the row is created on first access using
    defaults that match existing behavior.

    Returns:
        :class:`UserSettingsResponse` with all settings fields.
    """
    row = settings_service.get_or_create_settings(current_user.id, db)
    return UserSettingsResponse.model_validate(row)


@router.patch("", response_model=UserSettingsResponse)
def update_settings(
    body: UserSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserSettingsResponse:
    """Update one or more settings fields.

    All fields are optional — only provided (non-null) fields are written.
    Invalid values return HTTP 422 with a clear error message.

    Returns:
        :class:`UserSettingsResponse` reflecting the updated state.
    """
    updates = body.model_dump(exclude_none=True)
    row = settings_service.update_settings(
        user_id=current_user.id,
        updates=updates,
        db=db,
    )
    return UserSettingsResponse.model_validate(row)
