"""UserSettings model — M34.

One row per user.  Lazily created on first GET /settings.
All defaults match current hardcoded behavior so existing users see no change.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseMixin

if TYPE_CHECKING:
    from app.models.user import User


class UserSettings(BaseMixin, Base):
    """Per-user settings row.

    Fields
    ------
    alert_risk_threshold
        Which risk levels trigger change-alert emails.
        Allowed: ``critical_only``, ``high_and_critical``, ``medium_and_above``.
        Default: ``high_and_critical`` — matches legacy ``_ALERTABLE_LEVELS``.

    sync_failure_alerts_enabled
        Whether to send failure-alert emails at all.
        Default: ``True``.

    sync_failure_threshold
        How many consecutive scheduled failures before a failure alert fires.
        Allowed: 2, 3, 5.  Default: 3 — matches NEEDS_ATTENTION_THRESHOLD.

    sync_failure_cooldown_hours
        Minimum hours between failure alerts for the same integration.
        Allowed: 6, 12, 24.  Default: 24 — matches FAILURE_ALERT_COOLDOWN_SECONDS / 3600.

    default_sync_enabled
        Whether scheduled sync is enabled by default for *new* integrations.
        Does NOT retroactively change existing integrations.

    default_sync_interval_minutes
        Default scheduled-sync cadence for new integrations.
        Allowed: 5, 10, 15, 30, 60.  Default: 60.

    default_change_alerts_enabled
        Whether change-alert emails are enabled by default for new integrations.

    default_timeline_range
        Default time-range filter on the Timeline page.
        Allowed: ``24h``, ``7d``, ``30d``, ``all``.  Default: ``7d``.

    default_provider_filter
        Default provider filter on the Timeline page.
        Allowed: ``all``, ``cloudflare``, ``github``, ``vercel``.  Default: ``all``.
    """

    __tablename__ = "user_settings"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_user_settings_user_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ── Alert policy ─────────────────────────────────────────────────────────
    alert_risk_threshold: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="high_and_critical",
        server_default="high_and_critical",
    )
    sync_failure_alerts_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    sync_failure_threshold: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default="3",
    )
    sync_failure_cooldown_hours: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=24,
        server_default="24",
    )

    # ── Sync defaults (new integrations only) ────────────────────────────────
    # Default is True so new users get scheduled sync out of the box.
    # Existing UserSettings rows already have False from the old server_default;
    # those users are covered by the backward-compat eligibility filter in
    # create_scheduled_syncs_for_active_integrations (interval IS NOT NULL).
    default_sync_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    default_sync_interval_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=60,
        server_default="60",
    )
    default_change_alerts_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    # ── UI preferences ───────────────────────────────────────────────────────
    default_timeline_range: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="7d",
        server_default="7d",
    )
    default_provider_filter: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="all",
        server_default="all",
    )

    # ── Relationship ─────────────────────────────────────────────────────────
    user: Mapped[User] = relationship("User")

    def __repr__(self) -> str:
        return f"<UserSettings user_id={self.user_id}>"
