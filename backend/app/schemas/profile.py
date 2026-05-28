"""Pydantic schemas for the authenticated user's profile — M59.13.

GET   /me/profile  → ProfileResponse
PATCH /me/profile  → ProfileUpdateRequest → ProfileResponse

Field rules
-----------
* ``first_name`` and ``last_name`` are optional.  Empty/whitespace-only
  values are treated as "clear this field" and stored as ``None``.
* Both fields are trimmed of surrounding whitespace.
* Each field is capped at 100 characters after trimming.

The ``computed_display_name`` field in the response is derived server-side:

    if first_name or last_name:
        f"{first_name or ''} {last_name or ''}".strip()
    elif display_name and display_name != "ConfigTrace User":
        display_name
    else:
        email
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, field_validator

# Cap each name at this many characters AFTER trimming whitespace.  Long
# enough for the longest real human names; short enough that a buggy
# client cannot stuff a credential-shaped blob in here.
_MAX_NAME_LEN = 100


def _trim_or_none(value: object) -> Optional[str]:
    """Return *value* trimmed of whitespace, or None for blank inputs."""
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


class ProfileResponse(BaseModel):
    """Safe representation of the authenticated user's profile."""

    id: str                           # User UUID as string
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    display_name: Optional[str]       # Clerk-supplied, retained for fallback
    computed_display_name: str        # Derived per the policy in the docstring

    model_config = {"from_attributes": True}


class ProfileUpdateRequest(BaseModel):
    """Request body for PATCH /me/profile.

    Both fields are optional.  Omitted fields are unchanged; an explicit
    empty string clears the field.
    """

    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @field_validator("first_name", "last_name")
    @classmethod
    def _validate_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = _trim_or_none(value)
        if trimmed is None:
            # Explicit empty/whitespace → clear the field.
            return None
        if len(trimmed) > _MAX_NAME_LEN:
            raise ValueError(
                f"Name fields must be at most {_MAX_NAME_LEN} characters."
            )
        return trimmed
