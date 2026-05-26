"""Risk classification service — Milestone 10 + 26.

Responsibilities
----------------
* ``classify_change``      — route a single Change to the appropriate rule set
* ``update_change_risk``   — classify and persist risk for one Change row
* ``classify_changes``     — bulk-classify a list of Change rows (one flush)

Pipeline position
-----------------
    diff_service.store_changes()
        → risk_service.classify_changes()   ← this module
        → (Milestone 11) changes API

Design decisions
----------------
* Provider dispatch is via ``provider_metadata["record_type"]`` prefix:
  - Record types starting with ``"github_"`` → GitHub rule set
    (``app.services.risk_rules.github``).
  - Record types starting with ``"vercel_"`` → Vercel rule set
    (``app.services.risk_rules.vercel``).
  - All other records → Cloudflare DNS rule set
    (``app.services.risk_rules.cloudflare_dns``).
  This approach works without a DB lookup: the record type is embedded in
  ``provider_metadata`` at diff time, so no Integration join is needed.

* ``classify_changes`` does a single ``db.flush()`` after updating all rows in
  memory.  This is more efficient than flushing once per row and mirrors the
  pattern used by ``store_changes`` in the diff service.

* ``update_change_risk`` flushes and refreshes immediately after each row —
  useful for one-off classifications outside of the sync pipeline (e.g. a
  future admin endpoint or backfill script).

* Both functions leave ``db.commit()`` to the caller (``sync_integration``
  task), consistent with the transactional pattern used by snapshot_service
  and diff_service.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.change import Change
from app.services.risk_rules.cloudflare_dns import classify_dns_change

logger = logging.getLogger(__name__)


def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def classify_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for *change*.

    Dispatches to the appropriate provider rule set based on
    ``provider_metadata["record_type"]``:
    * Record types prefixed with ``"github_"`` → GitHub rule set.
    * All others → Cloudflare DNS rule set.

    Args:
        change: A ``Change`` ORM instance (or a plain dict, for testing).

    Returns:
        ``(risk_level, risk_reason)`` where *risk_level* is one of
        ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
    pm: dict = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type.startswith("github_"):
        from app.services.risk_rules.github import classify_github_change
        return classify_github_change(change)

    if record_type.startswith("vercel_"):
        from app.services.risk_rules.vercel import classify_vercel_change
        return classify_vercel_change(change)

    if record_type.startswith("stripe_"):
        from app.services.risk_rules.stripe import classify_stripe_change
        return classify_stripe_change(change)

    if record_type.startswith("aws_"):
        from app.services.risk_rules.aws import classify_aws_change
        return classify_aws_change(change)

    if record_type.startswith("firebase_"):
        from app.services.risk_rules.firebase import classify_firebase_change
        return classify_firebase_change(change)

    if record_type.startswith("supabase_"):
        from app.services.risk_rules.supabase import classify_supabase_change
        return classify_supabase_change(change)

    if record_type.startswith("shopify_"):
        from app.services.risk_rules.shopify import classify_shopify_change
        return classify_shopify_change(change)

    if record_type == "cloudflare_ruleset":
        from app.services.risk_rules.cloudflare_dns import classify_cloudflare_ruleset_change
        return classify_cloudflare_ruleset_change(change)

    return classify_dns_change(change)


def update_change_risk(change: Change, db: Session) -> Change:
    """Classify *change* and persist the result immediately.

    Calls ``db.flush()`` + ``db.refresh(change)`` so the returned object
    reflects the persisted state.  The caller is responsible for
    ``db.commit()``.

    Args:
        change: A ``Change`` ORM instance already attached to *db*.
        db:     Active SQLAlchemy session.

    Returns:
        The updated ``Change`` instance.
    """
    risk_level, risk_reason = classify_change(change)
    change.risk_level = risk_level
    change.risk_reason = risk_reason
    db.flush()
    db.refresh(change)
    logger.debug(
        "risk: classified  change_id=%s  level=%s",
        change.id,
        risk_level,
    )
    return change


def classify_changes(changes: list[Change], db: Session) -> list[Change]:
    """Classify all *changes* in memory then flush once.

    More efficient than ``update_change_risk`` in a loop because it issues a
    single ``db.flush()`` for all rows.

    Args:
        changes: List of ``Change`` ORM instances already attached to *db*.
                 An empty list is a no-op.
        db:      Active SQLAlchemy session.

    Returns:
        The same list with ``risk_level`` and ``risk_reason`` updated on every
        row.
    """
    if not changes:
        return changes

    for change in changes:
        risk_level, risk_reason = classify_change(change)
        change.risk_level = risk_level
        change.risk_reason = risk_reason

    db.flush()

    for change in changes:
        db.refresh(change)

    logger.info(
        "risk: classified %d change(s)",
        len(changes),
    )
    return changes
