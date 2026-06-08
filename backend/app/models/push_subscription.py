"""WorkspacePushSubscription model — M58.7.

Stores Web Push API subscriptions (endpoint + encrypted keys) per browser/device.
One workspace can have many subscriptions (one per browser/device that opted in).

Security design
---------------
* endpoint URL, p256dh key, and auth secret are AES-256-GCM encrypted together
  using the same encrypt_credentials pattern.  The raw values are NEVER stored
  in plaintext and NEVER returned in API responses.
* device_label, browser_name, user_agent are safe metadata for display.
* last_error stores sanitized error strings only (no PII, no tokens).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class WorkspacePushSubscription(BaseMixin, Base):
    """A Web Push API subscription for one browser/device in a workspace."""

    __tablename__ = "workspace_push_subscriptions"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # AES-256-GCM encrypted JSON {"endpoint": "...", "p256dh": "...", "auth": "..."}.
    # NEVER return in API responses.  NEVER log.
    subscription_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    subscription_iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Safe metadata — displayed in the subscriptions list.
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    browser_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device_label: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Enabled flag — set to False when subscription expires (410 Gone).
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # Per-device minimum risk level filter.
    # "high" (default) = high + critical  |  "critical_only" = critical only
    min_risk_level: Mapped[str] = mapped_column(
        Text, nullable=False, default="high", server_default="high"
    )

    # ── M60.13 — per-device push preferences by event category ─────────────────
    # Drift critical/high push defaults ON (preserves existing behavior for
    # current subscriptions). Security exposure push is OPT-IN (default off) so
    # no device is surprised by new security notifications. Resolved-exposure
    # push is also off by default (low-noise).
    drift_push_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    security_push_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    security_resolved_push_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # Timestamps.
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Sanitized last delivery error string.  None = no error.
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<WorkspacePushSubscription workspace={self.workspace_id} "
            f"browser={self.browser_name} enabled={self.enabled}>"
        )
