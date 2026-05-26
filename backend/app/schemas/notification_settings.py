"""Pydantic schemas for workspace notification settings — M57.1 + M58.5."""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Valid risk-level filter values — must match UserSettings.alert_risk_threshold.
NotifyRiskLevel = Literal["critical_only", "high_and_critical", "medium_and_above"]

_VALID_RISK_LEVELS = frozenset({"critical_only", "high_and_critical", "medium_and_above"})


class NotificationSettingsResponse(BaseModel):
    """Returned by GET and PUT /workspaces/{id}/notification-settings.

    Security: webhook URLs and bot tokens are NEVER returned in full.
    Only masked forms are exposed.
    """

    model_config = ConfigDict(from_attributes=True)

    workspace_id: UUID

    # Slack incoming webhook (legacy / fallback)
    slack_enabled: bool
    # Masked URL — None when no URL is configured.
    slack_webhook_url_masked: Optional[str] = None

    # Generic webhook
    webhook_enabled: bool
    # Masked URL — None when no URL is configured.
    webhook_url_masked: Optional[str] = None

    notify_on_risk_level: str

    # ── Slack App (M58.5) ─────────────────────────────────────────────────────
    slack_app_enabled: bool = False
    # True when a bot token is stored (i.e. installation completed).
    slack_app_installed: bool = False
    # Slack workspace name — safe to return.
    slack_team_name: Optional[str] = None
    slack_team_id: Optional[str] = None
    # Selected delivery channel.
    slack_channel_id: Optional[str] = None
    slack_channel_name: Optional[str] = None
    # Audit timestamps.
    slack_installed_at: Optional[datetime] = None
    slack_app_last_test_at: Optional[datetime] = None
    # Last delivery error (None when no error).
    slack_app_last_error: Optional[str] = None


class NotificationSettingsUpdateRequest(BaseModel):
    """Body for PUT /workspaces/{id}/notification-settings.

    All fields are optional — omitting a field leaves the current value
    unchanged.  To **clear** a webhook URL, pass an empty string ``""``.
    Passing ``null`` for a URL field is equivalent to omitting it (no-op).
    """

    slack_enabled: Optional[bool] = None

    # A non-None, non-empty string updates the Slack URL.
    # An empty string ("") clears the Slack URL and disables the channel.
    # None (default) leaves the existing URL unchanged.
    slack_webhook_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description=(
            "Slack incoming webhook URL. "
            "Must start with https://hooks.slack.com/services/. "
            "Pass an empty string to clear."
        ),
    )

    webhook_enabled: Optional[bool] = None

    # A non-None, non-empty string updates the generic webhook URL.
    # An empty string ("") clears the URL and disables the channel.
    # None (default) leaves the existing URL unchanged.
    webhook_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description=(
            "Generic HTTPS webhook URL. "
            "Must start with https://. "
            "Private/local addresses are rejected. "
            "Pass an empty string to clear."
        ),
    )

    notify_on_risk_level: Optional[str] = None

    @field_validator("notify_on_risk_level")
    @classmethod
    def validate_risk_level(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"notify_on_risk_level must be one of: {sorted(_VALID_RISK_LEVELS)}"
            )
        return v


class TestNotificationResponse(BaseModel):
    """Returned by POST /workspaces/{id}/notification-settings/test."""

    slack_sent: bool
    webhook_sent: bool
    # Human-readable error string if any channel failed, else None.
    error: Optional[str] = None


# ── Slack App schemas (M58.5) ─────────────────────────────────────────────────


class SlackInstallUrlResponse(BaseModel):
    """Returned by GET /workspaces/{id}/notifications/slack/install-url."""

    install_url: str
    state: str


class SlackChannelResponse(BaseModel):
    """A single Slack channel returned by the channels list endpoint."""

    id: str
    name: str
    is_private: bool
    is_member: bool


class SlackChannelsListResponse(BaseModel):
    """Returned by GET /workspaces/{id}/notifications/slack/channels."""

    channels: List[SlackChannelResponse]


class SlackChannelUpdateRequest(BaseModel):
    """Body for PUT /workspaces/{id}/notifications/slack/channel."""

    channel_id: str = Field(..., description="Slack channel ID (e.g. C01234567).")
    channel_name: str = Field(..., description="Display name of the channel.")
