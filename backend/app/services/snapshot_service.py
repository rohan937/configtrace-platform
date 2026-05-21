"""Snapshot service — Milestone 8.

Responsibilities
----------------
* ``compute_content_hash`` — deterministic SHA-256 hash of a config state list.
* ``get_latest_snapshot``   — fetch the most-recent Snapshot for a resource.
* ``store_snapshot``        — dedup-check then persist a new Snapshot if changed.

Design decisions
----------------
* Provider-agnostic: the service accepts ``list[dict]`` regardless of which
  connector produced the data.  The sort key (``record_id``) is standard for
  Cloudflare DNS records; future connectors should emit a ``record_id`` field
  as well, or the sort falls back to the full-dict string representation.
* Deduplication is hash-based: if the new content hash matches the latest
  snapshot's hash the write is skipped entirely and ``(existing, False)`` is
  returned.  This prevents duplicate rows when the config has not changed
  between two syncs.
* The service never touches connector code or credential encryption — those
  concerns live in the connector layer and ``core.encryption`` respectively.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.snapshot import Snapshot

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Hash computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_content_hash(state: list[dict]) -> str:
    """Return a SHA-256 hex digest of *state* in canonical form.

    Canonicalisation steps (order matters for determinism):
    1. Sort the records by their ``record_id`` field (stable across API calls).
       Records without ``record_id`` are sorted by their full JSON string
       representation as a fallback.
    2. Serialise with ``json.dumps(sort_keys=True, separators=(",", ":"))``
       — compact JSON with deterministic key order.
    3. Encode to UTF-8 and hash with SHA-256.

    Args:
        state: A list of normalised config dicts (e.g. ``CloudflareDNSRecord``).

    Returns:
        A 64-character lowercase hex string.
    """
    sorted_state = sorted(
        state,
        key=lambda r: (r.get("record_id") or json.dumps(r, sort_keys=True)),
    )
    canonical = json.dumps(
        sorted_state,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Query helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_latest_snapshot(resource_id: uuid.UUID, db: Session) -> Optional[Snapshot]:
    """Return the most-recently-created Snapshot for *resource_id*, or None.

    Ordered by ``created_at DESC`` so the first result is the newest.

    Args:
        resource_id: UUID of the resource to query.
        db:          Active SQLAlchemy session.

    Returns:
        The latest ``Snapshot`` row, or ``None`` if no snapshots exist yet.
    """
    return (
        db.query(Snapshot)
        .filter(Snapshot.resource_id == resource_id)
        .order_by(Snapshot.created_at.desc())
        .first()
    )


# ─────────────────────────────────────────────────────────────────────────────
# Store with deduplication
# ─────────────────────────────────────────────────────────────────────────────

def store_snapshot(
    *,
    resource_id: uuid.UUID,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    state: list[dict],
    triggered_by: str,
    sync_run_id: Optional[uuid.UUID] = None,
    db: Session,
) -> tuple[Snapshot, bool]:
    """Persist a new Snapshot only if the config state has changed.

    Deduplication logic:
    * Compute the SHA-256 hash of *state*.
    * Fetch the latest snapshot for *resource_id*.
    * If the hashes match → return ``(existing_snapshot, False)``.
    * If they differ (or no prior snapshot exists) → insert a new Snapshot row
      and return ``(new_snapshot, True)``.

    Args:
        resource_id:    UUID of the monitored resource.
        integration_id: UUID of the parent integration (denormalised FK).
        user_id:        UUID of the owning user (denormalised FK).
        state:          Normalised config list from the connector.
        triggered_by:   ``'manual'`` or ``'scheduled'``.
        sync_run_id:    UUID of the triggering SyncRun (nullable).
        db:             Active SQLAlchemy session.

    Returns:
        ``(snapshot, created)`` where *created* is ``True`` when a new
        Snapshot row was written and ``False`` when the existing snapshot
        was returned unchanged.
    """
    new_hash = compute_content_hash(state)
    latest = get_latest_snapshot(resource_id, db)

    if latest is not None and latest.content_hash == new_hash:
        logger.info(
            "store_snapshot: no change  resource_id=%s  hash=%s",
            resource_id,
            new_hash[:16],
        )
        return latest, False

    snapshot = Snapshot(
        resource_id=resource_id,
        integration_id=integration_id,
        user_id=user_id,
        state=state,
        content_hash=new_hash,
        triggered_by=triggered_by,
        sync_run_id=sync_run_id,
    )
    db.add(snapshot)
    db.flush()   # populate snapshot.id without closing the transaction
    db.refresh(snapshot)

    logger.info(
        "store_snapshot: new snapshot  resource_id=%s  hash=%s  snapshot_id=%s",
        resource_id,
        new_hash[:16],
        snapshot.id,
    )
    return snapshot, True
