"""M52: Billing + Usage Limits.

Creates:
- workspace_billing — one billing row per workspace (plan, status, Stripe IDs)

Backfill:
- Inserts a free/active billing row for every existing workspace that does not
  already have one.  Uses INSERT...SELECT so it is safe to re-run after any
  partial failure.

Design note:
- workspace_billing uses BaseMixin (id + created_at + updated_at) since the row
  is mutated whenever the workspace upgrades, downgrades, or a webhook arrives.
- unique constraint on workspace_id enforces the one-row-per-workspace invariant
  at the database level.

Revision ID: 006
Revises:     005
Create Date: 2026-05-25
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "workspace_billing",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("workspace_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("plan", sa.Text(), nullable=False, server_default="free"),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("stripe_customer_id", sa.Text(), nullable=True),
        sa.Column("stripe_subscription_id", sa.Text(), nullable=True),
        sa.Column("stripe_price_id", sa.Text(), nullable=True),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cancel_at_period_end",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("trial_end", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["workspaces.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workspace_id", name="uq_workspace_billing_workspace"),
    )
    op.create_index(
        "ix_workspace_billing_workspace_id",
        "workspace_billing",
        ["workspace_id"],
    )
    op.create_index(
        "ix_workspace_billing_stripe_customer",
        "workspace_billing",
        ["stripe_customer_id"],
    )
    op.create_index(
        "ix_workspace_billing_stripe_subscription",
        "workspace_billing",
        ["stripe_subscription_id"],
    )

    # Backfill: create a free billing row for every existing workspace.
    # ON CONFLICT DO NOTHING makes this idempotent.
    op.execute(
        """
        INSERT INTO workspace_billing (id, workspace_id, plan, status, created_at, updated_at)
        SELECT gen_random_uuid(), w.id, 'free', 'active', now(), now()
        FROM workspaces w
        WHERE NOT EXISTS (
            SELECT 1 FROM workspace_billing wb WHERE wb.workspace_id = w.id
        )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_workspace_billing_stripe_subscription", table_name="workspace_billing")
    op.drop_index("ix_workspace_billing_stripe_customer", table_name="workspace_billing")
    op.drop_index("ix_workspace_billing_workspace_id", table_name="workspace_billing")
    op.drop_table("workspace_billing")
