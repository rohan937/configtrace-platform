"""Celery sync task — Milestone 10.

Pipeline (this milestone):
  connector.fetch()
    → snapshot_service.store_snapshot()
    → diff_service.compute_diff()
    → diff_service.store_changes()
    → risk_service.classify_changes()  ← new in Milestone 10
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

    Pipeline
    --------
    1. Mark SyncRun ``running``.
    2. Load the Integration and decrypt its credentials.
    3. Look up all active Resources for the integration.
    4. For each resource:
       a. Capture the current latest snapshot as ``previous_snapshot``.
       b. Fetch fresh state from the connector.
       c. Call ``store_snapshot`` — writes only if state changed (hash dedup).
       d. If a new snapshot was written **and** ``previous_snapshot`` exists,
          run ``compute_diff`` + ``store_changes`` to persist Change rows.
       e. Update ``resource.last_snapshot_at`` for resources with new snapshots.
    5. Commit all snapshot and change writes in a single transaction.
    6. Update ``integration.last_synced_at``.
    7. Mark SyncRun ``completed`` with accurate ``snapshot_count`` and
       ``change_count``, or ``failed`` on any exception.

    Expected behaviour per sync scenario
    -------------------------------------
    First sync (baseline):
        ``snapshot_count = 1``, ``change_count = 0``
        A snapshot is stored; no previous snapshot exists so diff is skipped.

    No-change sync (identical state):
        ``snapshot_count = 0``, ``change_count = 0``
        Hash dedup skips the snapshot write; diff is never run.

    Changed sync (state differs):
        ``snapshot_count = 1``, ``change_count = N``
        New snapshot written; diff runs against the previous snapshot and
        N Change rows are stored.

    Args:
        sync_run_id:    UUID string of the SyncRun created by the API.
        integration_id: UUID string of the integration to sync.
        user_id:        UUID string of the owning user.

    Returns:
        ``{"status": "completed", "sync_run_id": str,
           "snapshot_count": int, "change_count": int}``
    """
    # DB-related imports are local so the task module stays importable without
    # a database connection (useful for Celery worker startup and unit tests).
    # CloudflareConnector and decrypt_credentials live at module level so they
    # can be patched cleanly in tests via app.workers.sync_task.*.
    from app.database import SessionLocal
    from app.models.integration import Integration
    from app.models.resource import Resource
    from app.services.alert_service import dispatch_alerts_for_sync
    from app.services.diff_service import compute_diff, store_changes
    from app.services.risk_service import classify_changes as apply_risk_classification
    from app.services.snapshot_service import get_latest_snapshot, store_snapshot
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

        # ── Defensive ownership check (Milestone 21) ─────────────────────────
        # The API route already verifies that the requesting user owns this
        # integration before enqueuing the task.  This is a belt-and-braces
        # guard against task-queue argument tampering, replays from old runs,
        # or a future code path that constructs sync_integration arguments
        # without re-checking ownership.  Refuse to sync rather than read
        # one user's data into another user's snapshots.
        _user_uuid = uuid.UUID(user_id)
        if integration.user_id != _user_uuid:
            raise ValueError(
                f"Worker user_id mismatch: integration {integration_id} is owned "
                f"by a different user than {user_id}. Refusing to sync."
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

        # ── Fetch, snapshot, and diff each resource ──────────────────────────
        snapshot_count = 0
        change_count = 0
        # Accumulate Change rows from every resource so we can dispatch one
        # digest alert email at the end of the sync (M24).  Per-resource
        # alert dispatch would split a single zone reconfiguration into
        # multiple emails — undesirable noise.
        all_changes_this_sync: list = []

        for resource in resources:
            # Select the correct connector based on provider.
            # New providers: add an elif branch here.
            if integration.provider == "cloudflare":
                connector = CloudflareConnector()
                records = connector.fetch(credentials)
            elif integration.provider == "github":
                from app.connectors.github import GitHubConnector
                connector = GitHubConnector()
                records = connector.fetch(credentials)
            else:
                logger.warning(
                    "sync_integration: unknown provider %r — skipping resource %s",
                    integration.provider,
                    resource.id,
                )
                continue

            # Capture the previous snapshot BEFORE storing the new one.
            # This is the correct "previous" snapshot to diff against.
            previous_snapshot = get_latest_snapshot(resource.id, db)

            new_snapshot, created = store_snapshot(
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

                # ── Diff against previous snapshot ───────────────────────────
                # Skip if this is the baseline snapshot (no previous exists).
                # The first sync creates the reference point; changes are only
                # meaningful when compared to a known previous state.
                if previous_snapshot is not None:
                    change_dicts = compute_diff(previous_snapshot, new_snapshot)
                    if change_dicts:
                        changes = store_changes(
                            resource_id=resource.id,
                            integration_id=_integration_uuid,
                            user_id=resource.user_id,
                            prev_snapshot_id=previous_snapshot.id,
                            new_snapshot_id=new_snapshot.id,
                            change_dicts=change_dicts,
                            db=db,
                        )
                        apply_risk_classification(changes, db)
                        change_count += len(changes)
                        all_changes_this_sync.extend(changes)
                        logger.info(
                            "sync_integration: %d change(s) detected  resource_id=%s",
                            len(changes),
                            resource.id,
                        )
                    else:
                        logger.info(
                            "sync_integration: snapshots differ by hash but "
                            "no tracked-field changes found  resource_id=%s",
                            resource.id,
                        )
                else:
                    logger.info(
                        "sync_integration: baseline snapshot stored  "
                        "resource_id=%s  (no diff run)",
                        resource.id,
                    )

        # ── Commit all snapshot + change + timestamp writes ──────────────────
        # store_snapshot and store_changes both use db.flush(); we commit
        # everything together here so the writes are atomic per sync run.
        integration.last_synced_at = datetime.now(timezone.utc)
        db.commit()

        # ── Dispatch high/critical email alerts (M24) ────────────────────────
        # Runs AFTER commit so a never-reached email path can't leave us with
        # Change rows but no Alert audit trail (and the converse: an Alert row
        # for a Change that was rolled back).
        #
        # dispatch_alerts_for_sync is hardened to never raise: provider
        # failures, missing config, and placeholder recipients are all caught
        # internally and logged.  We still wrap in try/except as a final guard
        # against future refactors that might forget that contract.
        if all_changes_this_sync:
            try:
                alert_result = dispatch_alerts_for_sync(
                    changes=all_changes_this_sync,
                    integration=integration,
                    sync_run_id=_sync_run_uuid,
                    db=db,
                )
                db.commit()
                logger.info(
                    "sync_integration: alert dispatch  sync_run_id=%s  "
                    "eligible=%d already_alerted=%d sent=%d recorded=%d failed=%d",
                    sync_run_id,
                    alert_result["eligible"],
                    alert_result["already_alerted"],
                    alert_result["sent"],
                    alert_result["recorded"],
                    alert_result["failed"],
                )
            except Exception:
                # Defence in depth: alert dispatch must never fail the sync.
                logger.exception(
                    "sync_integration: alert dispatch raised unexpectedly  "
                    "sync_run_id=%s",
                    sync_run_id,
                )
                # Roll back any partial alert writes; the DNS sync itself
                # already committed above.
                try:
                    db.rollback()
                except Exception:
                    logger.exception(
                        "sync_integration: rollback after alert failure also failed"
                    )

        # ── Mark completed ───────────────────────────────────────────────────
        mark_sync_completed(
            _sync_run_uuid,
            snapshot_count=snapshot_count,
            change_count=change_count,
            db=db,
        )

        logger.info(
            "sync_integration completed  sync_run_id=%s  "
            "snapshots=%d  changes=%d",
            sync_run_id,
            snapshot_count,
            change_count,
        )
        return {
            "status": "completed",
            "sync_run_id": sync_run_id,
            "snapshot_count": snapshot_count,
            "change_count": change_count,
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
