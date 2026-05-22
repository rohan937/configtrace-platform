"""Clerk Backend API client — fetches user emails when JWT claims omit them.

Why this module exists
----------------------
Clerk's default session JWT template includes only the ``sub`` (Clerk user
ID) claim plus standard ones (``iat``, ``exp``, ``iss``, ``sid``).  The
user's primary email address is **not** in the JWT unless the dashboard's
session template has been customised to add a custom claim like:

    {
        "email": "{{user.primary_email_address}}"
    }

Without that claim, ``_get_or_create_clerk_user`` writes a placeholder
``<clerk_id>@clerk.user`` to ``users.email``, which then blocks M24 email
alert dispatch (recipient filter rejects anything ending in ``@clerk.user``).

This module fixes the problem at the source.  When the auth path sees no
email claim, it falls back to calling Clerk's Backend API to fetch the
user's primary email.  Once persisted to ``users.email``, the value is
reused on every subsequent request — Clerk is called at most once per
user (once per request only while the placeholder is still present).

Endpoint reference
------------------
``GET https://api.clerk.com/v1/users/{user_id}``
Docs:  https://clerk.com/docs/reference/backend-api/tag/Users#operation/GetUser

Response shape (only fields we read):

    {
        "id": "user_xxx",
        "primary_email_address_id": "idn_xxx",
        "email_addresses": [
            { "id": "idn_xxx", "email_address": "user@example.com", ... },
            ...
        ],
        ...
    }

Configuration
-------------
``CLERK_SECRET_KEY`` — required.  Already wired in for M21 (declared in
``app/config.py`` and set on every Render service in ``render.yaml``).
When unset, ``fetch_user_email`` returns ``None`` silently so the auth
path falls back to placeholder behaviour rather than 500-ing.

Failure semantics
-----------------
Every failure mode (no key, network error, non-200, malformed JSON, user
has no primary email) is caught and logged as a single warning.  The
function returns ``None``; the caller decides what to do (write a
placeholder, leave the existing value, etc.).  Auth must never fail
because of a Clerk Backend API outage.
"""

from __future__ import annotations

import logging
from typing import Final, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Clerk Backend API root.  Hardcoded (no per-environment differences for
# Clerk's hosted API).  Override with a monkeypatch in tests.
_CLERK_API_BASE: Final[str] = "https://api.clerk.com/v1"

# Short timeout — Clerk API is on the auth hot path.  If Clerk is slow we
# fall back to the placeholder rather than blocking the request.
_HTTP_TIMEOUT: Final[float] = 3.0


def fetch_user_email(clerk_id: str) -> Optional[str]:
    """Return *clerk_id*'s primary email from Clerk's Backend API, or ``None``.

    Returns ``None`` on any failure:
      * ``CLERK_SECRET_KEY`` is unset.
      * Network error / timeout.
      * Non-200 response (4xx/5xx, including 404 if user was deleted).
      * Response is not valid JSON.
      * Response has no ``primary_email_address_id``.
      * The matching entry in ``email_addresses`` has no ``email_address``.

    Args:
        clerk_id: The Clerk user ID (``sub`` claim, e.g. ``user_2abc...``).

    Returns:
        A real email address (string) or ``None``.  Never raises.
    """
    if not settings.CLERK_SECRET_KEY:
        logger.debug(
            "clerk_service: CLERK_SECRET_KEY not configured — skipping Backend API "
            "lookup for clerk_id=%s",
            clerk_id,
        )
        return None

    url = f"{_CLERK_API_BASE}/users/{clerk_id}"
    headers = {
        "Authorization": f"Bearer {settings.CLERK_SECRET_KEY}",
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            resp = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        # Transport-level failure (timeout, DNS, connection reset).
        logger.warning(
            "clerk_service: HTTP transport failure  clerk_id=%s  error=%r",
            clerk_id,
            exc,
        )
        return None

    if resp.status_code != 200:
        logger.warning(
            "clerk_service: non-200 response  clerk_id=%s  status=%d",
            clerk_id,
            resp.status_code,
        )
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.warning(
            "clerk_service: non-JSON response  clerk_id=%s  body=%r",
            clerk_id,
            resp.text[:200],
        )
        return None

    return _extract_primary_email(data, clerk_id=clerk_id)


def _extract_primary_email(
    user_payload: dict, *, clerk_id: str
) -> Optional[str]:
    """Pull the primary email address out of a Clerk user response.

    Returns ``None`` if any part of the structure is missing.  Kept as a
    separate function so tests can exercise the parsing logic without
    spinning up an HTTP layer.
    """
    primary_id = user_payload.get("primary_email_address_id")
    email_addresses = user_payload.get("email_addresses") or []

    if not primary_id:
        logger.info(
            "clerk_service: user has no primary_email_address_id  clerk_id=%s",
            clerk_id,
        )
        return None

    for entry in email_addresses:
        if not isinstance(entry, dict):
            continue
        if entry.get("id") == primary_id:
            email = entry.get("email_address")
            if isinstance(email, str) and email.strip():
                return email.strip()
            logger.warning(
                "clerk_service: primary entry has no email_address  clerk_id=%s",
                clerk_id,
            )
            return None

    logger.warning(
        "clerk_service: primary_email_address_id not found in email_addresses  "
        "clerk_id=%s",
        clerk_id,
    )
    return None
