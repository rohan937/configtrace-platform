"""M61.2: Acknowledge + Snooze — add snoozed_until to security_findings.

Acknowledge reuses existing review-attribution fields (reviewed_by_user_id,
reviewed_at) with status kept ``active``. Snooze needs a dedicated expiry, so
this adds a single nullable ``snoozed_until`` column. All existing rows get
NULL (never snoozed). No backfill.

Revision ID: mig024
Revises:     mig023
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig024"
down_revision = "mig023"
branch_labels = None
depends_on = None

_TABLE = "security_findings"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column("snoozed_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "snoozed_until")
