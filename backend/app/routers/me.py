"""Authenticated-user profile routes — M59.13.

Routes
------
GET   /me/profile  → ProfileResponse — read the current user's profile
PATCH /me/profile  → ProfileResponse — update first_name / last_name

Security
--------
* Every route is gated by ``get_current_user``.
* A user can only ever read or mutate their OWN profile — there is no
  user_id path parameter, so cross-user updates are structurally impossible.
* No workspace state is touched; this is purely the user-level identity.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.profile import ProfileResponse, ProfileUpdateRequest

router = APIRouter(prefix="/me", tags=["me"])


# Display name resolved on the server so every client uses the same rule.
def _computed_display_name(user: User) -> str:
    first = (user.first_name or "").strip()
    last = (user.last_name or "").strip()
    if first or last:
        return f"{first} {last}".strip()
    if user.display_name and user.display_name != "ConfigTrace User":
        return user.display_name
    return user.email


def _to_response(user: User) -> ProfileResponse:
    return ProfileResponse(
        id=str(user.id),
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        display_name=user.display_name,
        computed_display_name=_computed_display_name(user),
    )


@router.get("/profile", response_model=ProfileResponse)
def get_my_profile(
    db: Session = Depends(get_db),  # noqa: ARG001  (session not used after the dependency)
    current_user: User = Depends(get_current_user),
) -> ProfileResponse:
    """Return the authenticated user's profile."""
    return _to_response(current_user)


@router.patch("/profile", response_model=ProfileResponse)
def update_my_profile(
    body: ProfileUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProfileResponse:
    """Update the authenticated user's ``first_name`` / ``last_name``.

    Both fields are optional.  Omitted fields are unchanged; an empty
    string (or whitespace-only) clears the field.  Names are trimmed
    and capped at 100 characters by ``ProfileUpdateRequest``.

    Returns the full refreshed profile, including the freshly-computed
    ``computed_display_name``.
    """
    fields = body.model_dump(exclude_unset=True)

    if "first_name" in fields:
        current_user.first_name = fields["first_name"]
    if "last_name" in fields:
        current_user.last_name = fields["last_name"]

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return _to_response(current_user)
