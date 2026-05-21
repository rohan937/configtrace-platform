"""User authentication dependency.

``get_current_user`` is a FastAPI dependency that resolves the authenticated
user from the incoming request.  It is used by every protected route.

Development mode (Clerk not configured)
---------------------------------------
When ``CLERK_SECRET_KEY`` is not set (or is still the placeholder value from
``.env.example``), the dependency operates in **dev mode**:

- It automatically creates or retrieves a dev user in the database.
- The ``X-Dev-User-Email`` request header can override the default address
  ``dev@configtrace.local``, which is useful for testing multiple user contexts.
- This allows full end-to-end API testing without a real Clerk account.

Production (Clerk configured) — Milestone 12
--------------------------------------------
When ``CLERK_SECRET_KEY`` is a real Clerk secret, the dependency will validate
the ``Authorization: Bearer <token>`` JWT.  Full Clerk JWT validation is wired
in Milestone 12 when the Next.js frontend is connected.
"""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User

# Default dev-mode identity — overridable via the X-Dev-User-Email header.
_DEV_DEFAULT_EMAIL = "dev@configtrace.local"


def _is_dev_mode() -> bool:
    """Return True when Clerk is not configured (placeholder or absent key)."""
    key = settings.CLERK_SECRET_KEY
    return (
        not key
        or key.startswith("sk_test_replace")
        or key.startswith("replace-with")
    )


def _get_or_create_dev_user(email: str, db: Session) -> User:
    """Return the dev user for *email*, creating the DB row on first call."""
    # Derive a stable, deterministic clerk_id from the email so re-creating the
    # same email address across requests returns the same row.
    clerk_id = f"dev_{email.replace('@', '_at_').replace('.', '_dot_')}"
    user = db.query(User).filter(User.clerk_id == clerk_id).first()
    if user is None:
        user = User(
            clerk_id=clerk_id,
            email=email,
            display_name="Dev User",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


async def get_current_user(
    db: Session = Depends(get_db),
    x_dev_user_email: str | None = Header(default=None),
) -> User:
    """FastAPI dependency — resolve the authenticated user.

    Dev mode (Clerk not configured)
        Returns a dev user, creating the DB row on first call.
        Pass ``X-Dev-User-Email: <email>`` to simulate a different user.

    Production (Clerk configured)
        Validates the Clerk JWT from ``Authorization: Bearer <token>``.
        TODO: implement in Milestone 12.

    Raises:
        HTTPException 501: Clerk is configured but JWT validation is not yet
            implemented.
    """
    if _is_dev_mode():
        email = x_dev_user_email or _DEV_DEFAULT_EMAIL
        return _get_or_create_dev_user(email, db)

    # Production path — Milestone 12
    raise HTTPException(
        status_code=501,
        detail=(
            "Clerk JWT authentication is not yet implemented.  "
            "To enable dev mode, set CLERK_SECRET_KEY to a placeholder value."
        ),
    )
