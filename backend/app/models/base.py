"""Shared declarative base and per-table mixins.

BaseMixin       — id + created_at + updated_at  (mutable entities)
BaseImmutable   — id + created_at only           (append-only / log tables)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Single shared declarative base.  Alembic reads Base.metadata."""
    pass


class BaseMixin:
    """UUID primary key + created_at + updated_at.

    Use for mutable entities (users, integrations, resources) where tracking
    the last modification time is useful.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        # DB generates the UUID when no Python value is provided (e.g. raw SQL).
        server_default=text("gen_random_uuid()"),
        # Python-side generation so the object has an id before flush/commit.
        default=uuid.uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        default=_utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )


class BaseImmutable:
    """UUID primary key + created_at only.

    Use for append-only / log tables (snapshots, changes, alerts, sync_runs)
    that are never modified after the initial INSERT.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        default=uuid.uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        default=_utcnow,
        nullable=False,
    )
