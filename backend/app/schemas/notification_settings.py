"""Pydantic schemas for workspace notification settings — M57.1."""

from __future__ import annotations

from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Valid risk-level filter values — must match UserSettings.alert_risk_threshold.
NotifyRiskLevel = Literal["critical_only", "high_and_critical", "medium_and_above"]

_VALID_RISK_LEVELS = frozenset({"critical_only", "high_and_critical", "medium_and_above"})


class NotificationSettingsResponse(BaseModel):
    """Returned by GET and PUT /workspaces/{id}/notification-settings.

    Security: webhook URLs are NEVER returned in full.  Only a masked
    representation (first 12 chars + "****") is exposed to the caller.
    """

    model_config = ConfigDict(from_attributes=True)

    workspace_id: UUID

    # Slack
    slack_enabled: bool
    # Masked URL — None when no URL is configured.
    slack_webhook_url_masked: Optional[str] = None

    # Generic webhook
    webhook_enabled: bool
    # Masked URL — None when no URL is configured.
    webhook_url_masked: Optional[str] = None

    notify_on_risk_level: str


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
