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
the check-then-insert race. Purely additive — no existing column or table
is changed.

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
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_INDEX_NAME}
        ON sync_runs (integration_id)
        WHERE status IN ('pending', 'running')
        """
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_INDEX_NAME}")
