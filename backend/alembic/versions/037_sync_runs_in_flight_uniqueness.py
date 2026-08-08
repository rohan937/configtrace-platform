"""Second-wave production bug hunt — DB-level concurrent-sync guard.

Root cause: ``has_in_flight_sync()`` (checked before inserting a new
``SyncRun``) is a plain SELECT with no lock. Two callers running at nearly
the same time — a manual "Sync Now" racing a Celery Beat tick, a
double-click, or two Beat workers — can both see "no in-flight sync" and
both insert a ``pending`` SyncRun for the same integration. The two
resulting Celery tasks then run concurrently: each captures its own
"previous snapshot" independently and diffs against it, so the sync whose
transaction happens to commit LAST becomes ``get_latest_snapshot()``'s
answer regardless of which sync actually started first or fetched fresher
data from the provider — and duplicate Change rows can be created for a
single underlying provider-side transition.

This migration adds a partial unique index so the database itself refuses
a second ``pending``/``running`` SyncRun for the same integration, closing
the check-then-insert race. No existing column or table is changed.

Pre-existing-duplicate safety: this is the exact race the index is meant
to close, so production may already have more than one pending/running
SyncRun for the same integration_id — a bare ``CREATE UNIQUE INDEX``
would then fail outright with a duplicate-key error and block the whole
deployment. ``upgrade()`` therefore closes out every in-flight row except
the most recently started one per integration_id (marking the rest
``failed`` with an explanatory error_message, mirroring what the stale-run
reaper in sync_service.py already does for timed-out rows) before creating
the index, so the migration is safe to run against dirty existing data.

Revision ID: mig037
Revises: mig036
"""

from __future__ import annotations

from alembic import op

revision = "mig037"
down_revision = "mig036"
branch_labels = None
depends_on = None

_INDEX_NAME = "uq_sync_runs_one_in_flight_per_integration"


def upgrade() -> None:
    # Close out all but the most-recently-started in-flight SyncRun per
    # integration_id, so the unique index below cannot hit a pre-existing
    # duplicate. ``DISTINCT ON`` picks the survivor deterministically;
    # everything else in ('pending', 'running') gets marked 'failed'.
    op.execute(
        """
        UPDATE sync_runs
        SET status = 'failed',
            completed_at = now(),
            error_message = 'Closed by migration mig037: a duplicate '
                'in-flight SyncRun existed for this integration before '
                'the uniqueness guard was added. Superseded by a newer '
                'sync run for the same integration; trigger a new sync '
                'if needed.'
        WHERE status IN ('pending', 'running')
          AND id NOT IN (
              SELECT DISTINCT ON (integration_id) id
              FROM sync_runs
              WHERE status IN ('pending', 'running')
              ORDER BY integration_id, started_at DESC, id DESC
          )
        """
    )
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_INDEX_NAME}
        ON sync_runs (integration_id)
        WHERE status IN ('pending', 'running')
        """
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_INDEX_NAME}")
