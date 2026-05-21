"""Celery sync task — Milestone 7 placeholder.

In Milestones 8–10, this task will execute the full pipeline:
  connector.fetch() → snapshot_service.store_snapshot()
                    → diff_service.compute_diff()
                    → risk_service.classify_changes()

For Milestone 7, the task validates the end-to-end plumbing:
  - Loads the integration and SyncRun from the database.
  - Transitions the SyncRun through the ``pending → running → completed`` lifecycle.
  - Updates ``integration.last_synced_at``.
  - Does **not** call the Cloudflare connector or touch snapshots/changes.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="sync_integration", bind=True, max_retries=0)
def sync_integration(
    self,  # noqa: ANN001 — Celery task instance injected by bind=True
    sync_run_id: str,
    integration_id: str,
    user_id: str,
) -> dict:
    """Execute one manual sync for a single integration.

    Task arguments are plain strings (JSON-serialisable) and converted to
    UUIDs inside the function body.

    Args:
        sync_run_id:    UUID string of the SyncRun created by the API.
        integration_id: UUID string of the integration to sync.
        user_id:        UUID string of the owning user.

    Returns:
        ``{"status": "completed", "sync_run_id": "<uuid>"}``

    Side effects:
        - Sets ``SyncRun.status`` to ``'running'`` then ``'completed'`` or
          ``'failed'``.
        - Sets ``Integration.last_synced_at`` on success.
    """
    # Local imports: pulled in at task execution time to guarantee fresh
    # DB connections per invocation and to avoid module-load circular imports.
    from app.database import SessionLocal
    from app.models.integration import Integration
    from app.services.sync_service import (
        mark_sync_completed,
        mark_sync_failed,
        mark_sync_running,
    )

    _sync_run_uuid = uuid.UUID(sync_run_id)
    _integration_uuid = uuid.UUID(integration_id)

    db = SessionLocal()
    try:
        logger.info(
            "sync_integration started  sync_run_id=%s  integration_id=%s",
            sync_run_id,
            integration_id,
        )

        # ── Mark as running ──────────────────────────────────────────────────
        mark_sync_running(_sync_run_uuid, db)

        # ── Load integration ─────────────────────────────────────────────────
        integration = db.get(Integration, _integration_uuid)
        if integration is None:
            raise ValueError(
                f"Integration {integration_id!r} not found in the database."
            )

        logger.info(
            "sync_integration running  provider=%s  display_name=%r",
            integration.provider,
            integration.display_name,
        )

        # ── Placeholder work ─────────────────────────────────────────────────
        # TODO (Milestone 8): replace with:
        #   credentials = decrypt_credentials(
        #       integration.encrypted_credentials, integration.credential_iv
        #   )
        #   records = CloudflareConnector().fetch(credentials)
        #   snapshot, changed = snapshot_service.store_snapshot(
        #       resource_id=..., state=records, triggered_by="manual",
        #       sync_run_id=_sync_run_uuid, db=db
        #   )
        #   if changed:
        #       changes = diff_service.compute_diff(prev_snapshot, snapshot, db=db)
        #       risk_service.classify_changes(changes, db=db)
        time.sleep(2)

        # ── Update last_synced_at ────────────────────────────────────────────
        integration.last_synced_at = datetime.now(timezone.utc)
        db.commit()

        # ── Mark completed (0 counts until Milestone 8+) ────────────────────
        mark_sync_completed(
            _sync_run_uuid,
            snapshot_count=0,
            change_count=0,
            db=db,
        )

        logger.info("sync_integration completed  sync_run_id=%s", sync_run_id)
        return {"status": "completed", "sync_run_id": sync_run_id}

    except Exception as exc:
        logger.exception(
            "sync_integration failed  sync_run_id=%s  error=%r",
            sync_run_id,
            str(exc),
        )
        try:
            mark_sync_failed(_sync_run_uuid, error_message=str(exc), db=db)
        except Exception:
            logger.exception(
                "Could not mark sync_run %s as failed — DB may be unavailable",
                sync_run_id,
            )
        raise

    finally:
        db.close()
