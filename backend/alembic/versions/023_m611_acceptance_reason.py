"""M61.1: Accepted Risk workflow — add acceptance_reason to security_findings.

Adds a single nullable free-text column to capture the rationale a user gives
when intentionally marking a security finding as ``accepted_risk`` (carrying a
known exposure for a time-bound reason). All existing rows get NULL — they have
never been through the accept-risk workflow.

No backfill, no data migration. The structured accept-risk fields
(``status``, ``accepted_until``, ``reviewed_by_user_id``, ``reviewed_at``)
already exist from mig020; this only adds the human-facing reason.

Revision ID: mig023
Revises:     mig022
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig023"
down_revision = "mig022"
branch_labels = None
depends_on = None

_TABLE = "security_findings"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column("acceptance_reason", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "acceptance_reason")
