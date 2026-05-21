from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseImmutable


class SyncRun(BaseImmutable, Base):
    """One record per sync execution.

    Tracks trigger type, start/end times, outcome, and change count for every
    sync run.  Written by the Celery worker; status is updated throughout.

    Valid triggered_by: 'manual', 'scheduled'
    Valid status:       'pending', 'running', 'completed', 'failed'
    """

    __tablename__ = "sync_runs"

    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    triggered_by: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="pending", server_default="pending"
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Zero means the sync completed but no configuration changed.
    change_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    snapshot_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<SyncRun id={self.id} status={self.status!r}"
            f" triggered_by={self.triggered_by!r}>"
        )
