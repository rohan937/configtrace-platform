"""User authentication dependency.

``get_current_user`` is a FastAPI dependency that resolves the authenticated
user from the incoming request.  It is used by every protected route.

Two modes
---------
**Dev mode** (local development convenience):
    Active only when ``ENVIRONMENT != production`` AND ``CLERK_JWKS_URL`` is
    not configured.  Auto-creates a ``dev@configtrace.local`` user, overridable
    via the ``X-Dev-User-Email`` header.  Lets you run the full stack locally
    without a Clerk account.

**Clerk JWT mode** (production and any environment with ``CLERK_JWKS_URL``):
    Validates the ``Authorization: Bearer <token>`` JWT using Clerk's JWKS
    (RS256 public keys).  Verification is performed locally — no network round
    trip to Clerk on the hot path after the JWKS is cached.

Production fail-closed guarantees
---------------------------------
1. If ``ENVIRONMENT=production`` and ``CLERK_JWKS_URL`` is missing or still a
   placeholder, every protected route returns **HTTP 503**.  The dev-mode
   branch is unreachable in production regardless of other env vars.
2. Missing / malformed / expired / signature-invalid tokens return **HTTP
   401** with a generic ``Invalid authentication credentials`` detail — never
   the raw JWT error.
3. JWKS fetch failure on cold start (no cached keys yet) returns **HTTP 503**.
   Once a JWKS is cached, transient fetch failures fall back to the stale
   cache for up to 1 hour before raising 503.

JWKS cache
----------
- TTL: 5 minutes (configurable via ``_JWKS_TTL_SECONDS``).
- A token whose ``kid`` is not in the cache triggers an immediate re-fetch
  to handle Clerk key rotation gracefully (one extra HTTP round-trip per
  rotated key, then back to local verification).
- The cache is a process-local module variable.  Multiple uvicorn workers
  each maintain their own cache — fine because Clerk's JWKS rarely changes.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import httpx
from fastapi import Depends, Header, HTTPException, status
from jose import jwt
from jose.exceptions import JWTError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User

logger = logging.getLogger(__name__)

# ── Dev mode constants ────────────────────────────────────────────────────────

_DEV_DEFAULT_EMAIL = "dev@configtrace.local"

# ── JWKS cache ────────────────────────────────────────────────────────────────
#
# Module-level cache.  Maps kid → public key dict.  ``_jwks_fetched_at`` is the
# unix timestamp of the last successful fetch.

_jwks_cache: dict[str, dict[str, Any]] = {}
_jwks_fetched_at: float = 0.0

_JWKS_TTL_SECONDS = 300            # 5 minutes — fresh cache lifetime
_JWKS_STALE_GRACE_SECONDS = 3_600  # 1 hour — emergency fallback on fetch error
_JWKS_HTTP_TIMEOUT = 5.0           # seconds


# ── Dev-mode helpers ──────────────────────────────────────────────────────────

def _is_dev_mode() -> bool:
    """True when dev-mode auth should be active.

    Two conditions, both required:
      1. ``settings.is_production`` is False.
      2. Clerk is not configured (no real CLERK_JWKS_URL).
    """
    return (not settings.is_production) and (not settings.is_clerk_configured)


def _get_or_create_dev_user(email: str, db: Session) -> User:
    """Return the dev user for *email*, creating the DB row on first call."""
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


# ── JWKS fetch + cache ────────────────────────────────────────────────────────

def _fetch_jwks(url: str) -> dict[str, dict[str, Any]]:
    """Fetch Clerk's JWKS document and return a kid → key mapping.

    Raises ``httpx.HTTPError`` on transport failure or non-200 response.
    """
    with httpx.Client(timeout=_JWKS_HTTP_TIMEOUT) as client:
        resp = client.get(url)
        resp.raise_for_status()
        document = resp.json()

    keys = document.get("keys", [])
    return {key["kid"]: key for key in keys if "kid" in key}


def _get_jwks(
    *,
    force_refresh: bool = False,
) -> dict[str, dict[str, Any]]:
    """Return the cached JWKS, refreshing if the cache is stale or empty.

    On fetch failure:
      - If we have a cached copy younger than ``_JWKS_STALE_GRACE_SECONDS``,
        return that and log a warning.
      - Otherwise raise ``HTTPException(503)`` — the caller (route handler
        path) will surface this as a service-unavailable response.
    """
    global _jwks_cache, _jwks_fetched_at

    if not settings.CLERK_JWKS_URL:
        # This is only reachable in Clerk mode — defensive check.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured.",
        )

    now = time.time()
    cache_age = now - _jwks_fetched_at
    fresh = _jwks_cache and cache_age < _JWKS_TTL_SECONDS

    if fresh and not force_refresh:
        return _jwks_cache

    try:
        new_cache = _fetch_jwks(settings.CLERK_JWKS_URL)
        _jwks_cache = new_cache
        _jwks_fetched_at = now
        return _jwks_cache
    except Exception as exc:  # httpx errors, JSON errors, etc.
        if _jwks_cache and cache_age < _JWKS_STALE_GRACE_SECONDS:
            logger.warning(
                "JWKS refresh failed; falling back to stale cache "
                "(age=%.0fs). error=%r",
                cache_age,
                exc,
            )
            return _jwks_cache
        logger.error("JWKS fetch failed and no usable cache: %r", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable.",
        ) from exc


def _key_for_kid(kid: str) -> dict[str, Any]:
    """Return the JWKS entry for *kid*, refreshing once on miss."""
    jwks = _get_jwks()
    if kid in jwks:
        return jwks[kid]
    # Possible key rotation — force one refresh before giving up.
    jwks = _get_jwks(force_refresh=True)
    if kid in jwks:
        return jwks[kid]
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials.",
    )


# ── JWT verification ──────────────────────────────────────────────────────────

def _verify_token(token: str) -> dict[str, Any]:
    """Verify a Clerk JWT and return the decoded claims.

    Raises:
        HTTPException 401: token is missing, malformed, expired, signed with
            an unknown key, or signature is invalid.
        HTTPException 503: JWKS is unavailable (propagated from ``_get_jwks``).
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
        )

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
        )

    key = _key_for_kid(kid)

    # Build jose verification options.  We always enforce signature + exp.
    # Issuer is enforced only when CLERK_ISSUER is configured — Clerk doesn't
    # require it (kid+signature is sufficient) but it's a nice defence-in-depth
    # control.
    options = {"verify_aud": False}
    decode_kwargs: dict[str, Any] = {
        "algorithms": ["RS256"],
        "options": options,
    }
    if settings.CLERK_ISSUER:
        decode_kwargs["issuer"] = settings.CLERK_ISSUER

    try:
        claims = jwt.decode(token, key, **decode_kwargs)
    except JWTError as exc:
        # Catches: ExpiredSignatureError, JWTClaimsError, signature mismatch,
        # malformed tokens, etc.  Map them all to a single generic 401.
        logger.info("JWT verification failed: %r", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
        ) from exc

    return claims


# ── User upsert from Clerk claims ─────────────────────────────────────────────

_PLACEHOLDER_EMAIL_SUFFIX = "@clerk.user"


def _resolve_email(
    clerk_id: str,
    email_claim: Optional[str],
) -> Optional[str]:
    """Return a real email for *clerk_id*, preferring the JWT claim.

    Resolution order:
        1. The ``email`` (or ``email_address``) JWT claim, if Clerk's
           session template was customised to include it.
        2. Clerk Backend API ``GET /v1/users/{clerk_id}``, which always
           returns the primary email when configured (see
           :mod:`app.services.clerk_service`).
        3. ``None`` — caller falls back to a placeholder for new users,
           or leaves the existing email untouched for upgrades.

    The Backend API call is the self-healing path that makes this work
    even when the session template has not been configured.  It costs at
    most one HTTPS request per user (and only while ``users.email`` is
    still a placeholder — once a real value lands, the caller never
    invokes this function for that user again).
    """
    if email_claim:
        return email_claim
    # Local import to avoid a module-load cycle if anything in
    # clerk_service ever needs to import from this module.
    from app.services import clerk_service

    return clerk_service.fetch_user_email(clerk_id)


def _get_or_create_clerk_user(claims: dict[str, Any], db: Session) -> User:
    """Look up or create the local ``User`` row matching the Clerk subject.

    The Clerk ``sub`` claim (always present) is stored as ``users.clerk_id``.
    Email resolution prefers the JWT ``email`` claim (when Clerk's session
    template provides it) and falls back to Clerk's Backend API for users
    whose session template doesn't include the email.  When both fail —
    e.g. ``CLERK_SECRET_KEY`` unset or Clerk Backend API down — a
    deterministic ``<clerk_id>@clerk.user`` placeholder is written and
    re-attempted on the next request.

    Email policy
        * **Real → real:**  Never overwritten by claim or Backend API.
          Once a user has a real address (or one they edited themselves),
          we never touch it from this code path.
        * **Placeholder → real:**  Upgraded automatically on any request
          that successfully resolves a real address.
        * **None of the above:**  Placeholder remains; no error.
    """
    clerk_id = claims.get("sub")
    if not clerk_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
        )

    email_claim: Optional[str] = claims.get("email") or claims.get("email_address")
    name_claim: Optional[str] = (
        claims.get("name")
        or claims.get("full_name")
        or claims.get("first_name")
    )

    user = db.query(User).filter(User.clerk_id == clerk_id).first()

    if user is None:
        # New user: try claim → Clerk Backend API → placeholder.
        resolved_email = _resolve_email(clerk_id, email_claim)
        if resolved_email:
            logger.info(
                "auth: created user with resolved email  clerk_id=%s  "
                "via=%s",
                clerk_id,
                "claim" if email_claim else "clerk_backend_api",
            )
        else:
            logger.warning(
                "auth: created user with placeholder email — JWT had no email "
                "claim AND Clerk Backend API lookup failed  clerk_id=%s",
                clerk_id,
            )
        user = User(
            clerk_id=clerk_id,
            email=resolved_email or f"{clerk_id}{_PLACEHOLDER_EMAIL_SUFFIX}",
            display_name=name_claim or "ConfigTrace User",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    # Existing user — best-effort placeholder upgrade.  We only ever
    # change ``user.email`` when the stored value is still a placeholder
    # AND we found a real address (claim or Backend API).  A real address
    # is never overwritten from this path, even if the JWT claim differs
    # (the user may have edited it manually in a future settings UI).
    dirty = False
    if user.email.endswith(_PLACEHOLDER_EMAIL_SUFFIX):
        new_email = _resolve_email(clerk_id, email_claim)
        if new_email and new_email != user.email:
            logger.info(
                "auth: upgraded placeholder email for existing user  "
                "clerk_id=%s  via=%s",
                clerk_id,
                "claim" if email_claim else "clerk_backend_api",
            )
            user.email = new_email
            dirty = True
    if (
        name_claim
        and user.display_name in (None, "", "ConfigTrace User")
        and name_claim != user.display_name
    ):
        user.display_name = name_claim
        dirty = True
    if dirty:
        db.commit()
        db.refresh(user)

    return user


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_current_user(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
    x_dev_user_email: Optional[str] = Header(default=None),
) -> User:
    """Resolve the authenticated user for the current request.

    See module docstring for the full mode matrix.

    Production behaviour:
        * 503 if ``CLERK_JWKS_URL`` is missing or a placeholder.
        * 401 if ``Authorization`` header is missing, malformed, or the
          token is invalid / expired.

    Local development:
        * If Clerk is not configured, returns a dev user (creating the row on
          first call).  The ``X-Dev-User-Email`` header overrides the default
          identity for multi-user simulation.
        * If a developer sets ``CLERK_JWKS_URL`` locally, the same JWT
          verification path used in production runs locally.
    """
    # ── Production hard guard ─────────────────────────────────────────────────
    # In production we MUST have Clerk configured; never fall back to dev mode.
    if settings.is_production and not settings.is_clerk_configured:
        logger.error(
            "Refusing to serve request: ENVIRONMENT=production but "
            "CLERK_JWKS_URL is not configured."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured on this server.",
        )

    # ── Dev mode ──────────────────────────────────────────────────────────────
    if _is_dev_mode():
        email = x_dev_user_email or _DEV_DEFAULT_EMAIL
        return _get_or_create_dev_user(email, db)

    # ── Clerk JWT verification ────────────────────────────────────────────────
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = _verify_token(token)
    return _get_or_create_clerk_user(claims, db)


# ── Test hook ─────────────────────────────────────────────────────────────────

def _reset_jwks_cache_for_tests() -> None:
    """Clear the module-level JWKS cache.  Intended for unit tests only."""
    global _jwks_cache, _jwks_fetched_at
    _jwks_cache = {}
    _jwks_fetched_at = 0.0
