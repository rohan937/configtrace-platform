"""M62.4: rule confidence + false-positive safeguard on security_findings.

Adds three columns:
  * confidence            — Text NOT NULL default "high" (high/medium; low rules
                            are deferred and never emit findings).
  * confidence_reason     — Text nullable; why the rule reached its conclusion.
  * false_positive_guard  — Text nullable; how the rule avoids noisy cases.

Existing rows default to "high" confidence (current behavior is unchanged).
Confidence is rule-derived metadata; it is not a confirmed-exploit signal.

Revision ID: mig028
Revises:     mig027
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig028"
down_revision = "mig027"
branch_labels = None
depends_on = None

_TABLE = "security_findings"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "confidence",
            sa.Text(),
            server_default="high",
            nullable=False,
        ),
    )
    op.add_column(_TABLE, sa.Column("confidence_reason", sa.Text(), nullable=True))
    op.add_column(_TABLE, sa.Column("false_positive_guard", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column(_TABLE, "false_positive_guard")
    op.drop_column(_TABLE, "confidence_reason")
    op.drop_column(_TABLE, "confidence")
