"""Risk classification service — Milestone 10.

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
* All MVP changes use the Cloudflare DNS rule set from
  ``app.services.risk_rules.cloudflare_dns``.  A future ``classify_change``
  dispatch table can route by ``change.provider`` (stored on Change or
  derivable from the parent Integration) once more providers are added.

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

from sqlalchemy.orm import Session

from app.models.change import Change
from app.services.risk_rules.cloudflare_dns import classify_dns_change

logger = logging.getLogger(__name__)


def classify_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for *change*.

    MVP routing: all changes go through the Cloudflare DNS rule set.
    Future milestones can dispatch on ``change.provider`` or the parent
    integration's provider field.

    Args:
        change: A ``Change`` ORM instance (or a plain dict, for testing).

    Returns:
        ``(risk_level, risk_reason)`` where *risk_level* is one of
        ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
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
