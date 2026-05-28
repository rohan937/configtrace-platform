"""M59.13: add first_name + last_name columns to users.

Adds two nullable Text columns so users can enter a profile name in
Settings → Profile.  Both default to NULL on existing rows — no data
backfill is required.

Revision ID: mig019
Revises:     mig018
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "mig019"
down_revision = "mig018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("first_name", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("last_name", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "last_name")
    op.drop_column("users", "first_name")
