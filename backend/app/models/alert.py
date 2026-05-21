from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseImmutable


class Alert(BaseImmutable, Base):
    """One row per alert event dispatched by the alerting system.

    Provides an audit trail of every notification sent and is used to:
    - Show which changes have already triggered alerts in the UI
    - Prevent duplicate dispatch (check for existing alert by change_id)
    - Track retry state for failed deliveries

    Alert dispatch logic is implemented in Phase 3.  This table is a
    placeholder in the MVP schema.

    Valid channel:  'slack'  (future: 'email', 'pagerduty', 'webhook')
    Valid status:   'pending', 'delivered', 'failed'
    alert_config_id: nullable until Phase 3 adds the alert_configs table.
    """

    __tablename__ = "alerts"

    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("changes.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # nullable — alert_configs table added in Phase 3
    alert_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    channel: Mapped[str] = mapped_column(Text, nullable=False)
    # Delivery address: Slack webhook URL, email address, etc.
    # Copied from alert config at dispatch time so the audit trail is accurate
    # even if the config is later changed.
    destination: Mapped[str] = mapped_column(Text, nullable=False)
    # Full message payload sent to the destination, for debugging.
    payload: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="pending", server_default="pending"
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    delivered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} channel={self.channel!r}"
            f" status={self.status!r}>"
        )
