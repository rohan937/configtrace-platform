"""WorkspaceNotificationSettings model — M57.1 / M58.15.

One row per workspace.  Stores encrypted Slack incoming-webhook URL and
encrypted generic-webhook URL alongside enabled flags and a risk-level filter.
M58.15 adds weekly digest scheduling columns.

Security design
---------------
* Webhook URLs are AES-256-GCM encrypted at rest using the same
  ``encrypt_credentials`` / ``decrypt_credentials`` pattern as Integration
  credentials.  The raw URL is never stored in plaintext.
* API responses return only a **masked** URL (first 12 chars + "****" + last 4)
  — the full URL is never returned after the initial PUT.
* Webhook URLs are never written to logs.  All log lines use the masked form.
* No webhook URL ever appears in audit-log metadata_json.

Lifecycle
---------
Rows are created lazily: the first GET or PUT for a workspace's notification
settings calls ``get_or_create_notification_settings`` which inserts a row
with both channels disabled and no URLs set.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, SmallInteger, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class WorkspaceNotificationSettings(BaseMixin, Base):
    """Notification channels configuration for a workspace.

    Columns
    -------
    workspace_id
        FK → workspaces.id (CASCADE delete).  Unique: one row per workspace.

    slack_enabled
        When True, a Slack incoming-webhook POST is sent on each qualifying
        change event.  Requires slack_webhook_url_encrypted to be set.

    slack_webhook_url_encrypted / slack_webhook_iv
        AES-256-GCM encrypted form of the Slack incoming-webhook URL.
        The IV is stored alongside so decryption is self-contained.
        Both are NULL until a URL is configured.

    webhook_enabled
        When True, a generic HTTPS POST is sent on each qualifying event.
        Requires webhook_url_encrypted to be set.

    webhook_url_encrypted / webhook_iv
        AES-256-GCM encrypted generic webhook URL.  NULL until configured.

    notify_on_risk_level
        Mirror of ``UserSettings.alert_risk_threshold`` but at workspace
        scope for these channels.  Valid values:
          ``critical_only``      — only CRITICAL changes
          ``high_and_critical``  — HIGH + CRITICAL (default)
          ``medium_and_above``   — MEDIUM + HIGH + CRITICAL
    """

    __tablename__ = "workspace_notification_settings"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # ── Slack incoming webhook ─────────────────────────────────────────────────
    slack_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    # AES-GCM ciphertext of the Slack webhook URL (JSON: {"url": "https://..."})
    slack_webhook_url_encrypted: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )
    # 12-byte nonce for AES-GCM decryption of the Slack URL.
    slack_webhook_iv: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )

    # ── Generic webhook ────────────────────────────────────────────────────────
    webhook_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    # AES-GCM ciphertext of the generic webhook URL (JSON: {"url": "https://..."})
    webhook_url_encrypted: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )
    # 12-byte nonce for AES-GCM decryption of the generic webhook URL.
    webhook_iv: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )

    # ── Risk-level filter ──────────────────────────────────────────────────────
    # Same vocabulary as UserSettings.alert_risk_threshold.
    notify_on_risk_level: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="high_and_critical",
        server_default="high_and_critical",
    )

    # ── Slack App installation (M58.5) ─────────────────────────────────────────
    # When True, alerts are delivered via the installed Slack App bot.
    # Takes precedence over the legacy incoming-webhook flow (slack_enabled).
    slack_app_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    # Slack workspace info — safe to return in API responses.
    slack_team_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    slack_team_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # AES-256-GCM encrypted Slack bot token.  NEVER return in API responses.
    # NEVER log in full.
    slack_bot_token_encrypted: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )
    # 12-byte nonce for AES-GCM decryption of the bot token.
    slack_bot_iv: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )
    # Slack bot user ID (e.g. UABC123) — safe to store and display.
    slack_bot_user_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Chosen Slack channel for alert delivery (the DEFAULT channel).
    slack_channel_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    slack_channel_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── M60.12 — separate Drift vs Security Slack routing ──────────────────────
    # One Slack install, multiple routes. Blank channel overrides fall back to
    # ``slack_channel_id`` (the default channel) — so existing workspaces are
    # unchanged. Security Slack delivery is OPT-IN (defaults off) so no existing
    # workspace is surprised by new security messages.
    slack_drift_channel_id: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    slack_security_channel_id: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    slack_security_alerts_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Resolved-exposure Slack messages are low-noise; off by default.
    slack_security_resolved_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # Installation audit fields.
    slack_installed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    slack_installed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    slack_app_last_test_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Last delivery error message (if any).  Safe to return to admins.
    slack_app_last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── M61.8 — separate Drift vs Security email routing ───────────────────────
    # Drift/change emails are unchanged (sent to the integration owner for
    # high/critical changes). Security exposure emails are OPT-IN (default off)
    # so no existing workspace is surprised by new security emails. Resolved
    # security emails are also off by default (low-noise).
    email_security_alerts_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    email_security_resolved_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Optional comma/newline-separated recipient list for security emails.
    # Blank → fall back to the workspace default recipient (the integration
    # owner, same as drift). Plain text, no secrets.
    email_security_recipients: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    # ── Weekly digest (M58.15) ─────────────────────────────────────────────────
    # When True, a weekly digest email is sent to workspace admins on schedule.
    weekly_digest_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    # Day of week: 0 = Monday … 6 = Sunday (ISO weekday − 1).
    weekly_digest_day: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    # Hour of day 0–23 (UTC unless weekly_digest_timezone is set).
    weekly_digest_hour: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=9,
        server_default="9",
    )
    # IANA timezone string (e.g. "America/New_York").  Null = UTC.
    weekly_digest_timezone: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Last time a digest was successfully sent for this workspace.
    weekly_digest_last_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── M59.4 — Test-notification cooldown ─────────────────────────────────────
    # Workspace-wide cooldown for the "send test" endpoints so an admin
    # cannot spam test Slack/push/webhook/digest messages.
    # Refreshed every time any of the test endpoints fires; checked at the
    # start of each one to return 429 if within ``_TEST_NOTIFICATION_COOLDOWN``.
    last_test_notification_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<WorkspaceNotificationSettings workspace={self.workspace_id} "
            f"slack_enabled={self.slack_enabled} webhook_enabled={self.webhook_enabled}>"
        )
