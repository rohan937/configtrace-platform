"""M63.3 — rule pack / version traceability columns on security_findings.

Adds rule_pack_name / rule_pack_version / rule_version (all nullable). Existing
rows stay NULL and display null-safe ("unknown version"); new + refreshed
findings are stamped by the finding service.

Revision ID: mig030
Revises: mig029
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig030"
down_revision = "mig029"
branch_labels = None
depends_on = None

_TABLE = "security_findings"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("rule_pack_name", sa.Text(), nullable=True))
    op.add_column(_TABLE, sa.Column("rule_pack_version", sa.Text(), nullable=True))
    op.add_column(_TABLE, sa.Column("rule_version", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column(_TABLE, "rule_version")
    op.drop_column(_TABLE, "rule_pack_version")
    op.drop_column(_TABLE, "rule_pack_name")
