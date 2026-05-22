"""Backfill placeholder user emails from Clerk's Backend API.

Why this script exists
----------------------
Before the M24-followup, every user whose Clerk session template did not
include an ``email`` claim was created in our DB with a placeholder address
``<clerk_id>@clerk.user``.  M24's alert dispatcher refuses to send to
those, so high-risk DNS change alerts silently never go out.

The auth path now self-heals on each authenticated request — but only
while the user is *actively browsing*.  Existing users who haven't signed
in since the M24-followup deployed still have placeholders, and would
continue to miss alerts until they make any authenticated request.

This script fixes them in bulk by calling Clerk's Backend API for every
placeholder user and persisting the result.

Behaviour
---------
* Iterates every ``User`` row whose ``email`` ends in ``@clerk.user``.
* For each, calls :func:`app.services.clerk_service.fetch_user_email`.
* If a real email comes back, updates the row in place.
* If Clerk returns ``None`` (no key, network failure, user no longer in
  Clerk, etc.), the row is left untouched and counted as ``failed``.
* The script is fully idempotent: re-running it on already-backfilled
  users is a no-op (they no longer match the ``%@clerk.user`` filter).

Usage
-----
Local Docker Compose:
    docker compose exec api python scripts/backfill_user_emails.py

Production (Render):
    Render dashboard → configtrace-api → Shell:
        python scripts/backfill_user_emails.py

Exit code
---------
* ``0`` — all placeholders resolved, or nothing to do.
* ``1`` — one or more placeholders could not be resolved.  Re-run after
  fixing Clerk configuration or wait for the affected users to make an
  authenticated request (which will retry the lookup automatically).

Security
--------
* No secrets are logged.  The Clerk secret comes from settings, not
  command-line args.
* No emails are mutated to placeholder; the script only *removes*
  placeholders.  A user with a real email is never touched.
"""

from __future__ import annotations

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("backfill_user_emails")


def run_backfill() -> dict:
    """Execute the backfill and return counts.

    Separated from ``main()`` so tests can call it with a real DB session
    and assert on the result without invoking ``sys.exit``.

    Returns:
        Dict with the following integer keys:
          - ``total``:    placeholder users scanned
          - ``updated``:  rows mutated to a real email
          - ``failed``:   rows where Clerk returned ``None``
    """
    from app.database import SessionLocal
    from app.models.user import User
    from app.services import clerk_service

    db = SessionLocal()
    try:
        users = (
            db.query(User)
            .filter(User.email.like("%@clerk.user"))
            .all()
        )

        total = len(users)
        if total == 0:
            logger.info("No users with placeholder emails — nothing to do.")
            return {"total": 0, "updated": 0, "failed": 0}

        logger.info("Found %d user(s) with placeholder emails.  Backfilling…", total)

        updated = 0
        failed = 0

        for user in users:
            real_email = clerk_service.fetch_user_email(user.clerk_id)
            if real_email and real_email != user.email:
                logger.info(
                    "  upgraded  user.id=%s clerk_id=%s  %s → %s",
                    user.id,
                    user.clerk_id,
                    user.email,
                    real_email,
                )
                user.email = real_email
                updated += 1
            else:
                logger.warning(
                    "  could not resolve  user.id=%s clerk_id=%s  "
                    "(Clerk Backend API returned no usable email)",
                    user.id,
                    user.clerk_id,
                )
                failed += 1

        db.commit()
        logger.info(
            "Backfill complete.  total=%d  updated=%d  failed=%d",
            total,
            updated,
            failed,
        )
        return {"total": total, "updated": updated, "failed": failed}
    finally:
        db.close()


def main() -> int:
    result = run_backfill()
    # Exit 0 when everything resolved (or nothing to do); 1 when any
    # placeholder couldn't be resolved — surfaces the partial-success
    # case to ops without obscuring it.
    return 0 if result["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
