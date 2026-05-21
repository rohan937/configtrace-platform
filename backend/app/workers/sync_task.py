"""Celery sync task — Milestone 8.

Pipeline (this milestone):
  connector.fetch() → snapshot_service.store_snapshot()

Milestones 9–10 will extend the pipeline:
  → diff_service.compute_diff()
  → risk_service.classify_changes()
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from app.connectors.cloudflare import CloudflareConnector
from app.core.encryption import decrypt_credentials
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

    Pipeline:
    1. Mark SyncRun ``running``.
    2. Load the Integration and decrypt its credentials.
    3. Look up all active Resources for the integration.
    4. For each resource, call the appropriate connector and store a Snapshot
       (skipped if the config is unchanged since the last snapshot).
    5. Update ``integration.last_synced_at`` and ``resource.last_snapshot_at``
       for resources that received new snapshots.
    6. Mark SyncRun ``completed`` with counts, or ``failed`` on any exception.

    Args:
        sync_run_id:    UUID string of the SyncRun created by the API.
        integration_id: UUID string of the integration to sync.
        user_id:        UUID string of the owning user.

    Returns:
        ``{"status": "completed", "sync_run_id": "<uuid>",
           "snapshot_count": <int>, "change_count": 0}``

    Side effects:
        - Sets ``SyncRun.status`` to ``'running'`` then ``'completed'`` or
          ``'failed'``.
        - Writes new ``Snapshot`` rows when config has changed.
        - Sets ``Integration.last_synced_at`` on success.
        - Sets ``Resource.last_snapshot_at`` when a new snapshot was stored.
    """
    # DB-related imports are local so the task module stays importable without
    # a database connection (useful for Celery worker startup and unit tests).
    # CloudflareConnector and decrypt_credentials live at module level so they
    # can be patched cleanly in tests via app.workers.sync_task.*.
    from app.database import SessionLocal
    from app.models.integration import Integration
    from app.models.resource import Resource
    from app.services.snapshot_service import store_snapshot
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

        # ── Decrypt credentials ──────────────────────────────────────────────
        credentials = decrypt_credentials(
            integration.encrypted_credentials,
            integration.credential_iv,
        )

        # ── Load active resources for this integration ───────────────────────
        resources = (
            db.query(Resource)
            .filter(
                Resource.integration_id == _integration_uuid,
                Resource.is_active.is_(True),
            )
            .all()
        )

        if not resources:
            logger.warning(
                "sync_integration: no active resources  integration_id=%s",
                integration_id,
            )

        # ── Fetch + snapshot each resource ───────────────────────────────────
        snapshot_count = 0

        for resource in resources:
            # Select the correct connector based on provider.
            # Future providers add an elif branch here.
            if integration.provider == "cloudflare":
                connector = CloudflareConnector()
                records = connector.fetch(credentials)
            else:
                logger.warning(
                    "sync_integration: unknown provider %r — skipping resource %s",
                    integration.provider,
                    resource.id,
                )
                continue

            _, created = store_snapshot(
                resource_id=resource.id,
                integration_id=_integration_uuid,
                user_id=resource.user_id,
                state=records,
                triggered_by="manual",
                sync_run_id=_sync_run_uuid,
                db=db,
            )

            if created:
                snapshot_count += 1
                resource.last_snapshot_at = datetime.now(timezone.utc)

        # ── Commit resource timestamp updates ────────────────────────────────
        # store_snapshot uses flush(); we commit all at once here.
        integration.last_synced_at = datetime.now(timezone.utc)
        db.commit()

        # ── Mark completed ───────────────────────────────────────────────────
        mark_sync_completed(
            _sync_run_uuid,
            snapshot_count=snapshot_count,
            change_count=0,          # Milestone 9 wires in real diff counts
            db=db,
        )

        logger.info(
            "sync_integration completed  sync_run_id=%s  snapshots=%d",
            sync_run_id,
            snapshot_count,
        )
        return {
            "status": "completed",
            "sync_run_id": sync_run_id,
            "snapshot_count": snapshot_count,
            "change_count": 0,
        }

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
