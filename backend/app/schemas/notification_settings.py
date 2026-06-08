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
    # Selected delivery channel (default channel).
    slack_channel_id: Optional[str] = None
    slack_channel_name: Optional[str] = None
    # ── M60.12 Slack routing (Drift vs Security) ──────────────────────────────
    slack_drift_channel_id: Optional[str] = None
    slack_security_channel_id: Optional[str] = None
    slack_security_alerts_enabled: bool = False
    slack_security_resolved_enabled: bool = False
    # ── M61.8 Email routing (Drift vs Security) ───────────────────────────────
    email_security_alerts_enabled: bool = False
    email_security_resolved_enabled: bool = False
    email_security_recipients: Optional[str] = None
    # Audit timestamps.
    slack_installed_at: Optional[datetime] = None
    slack_app_last_test_at: Optional[datetime] = None
    # Last delivery error (None when no error).
    slack_app_last_error: Optional[str] = None

    # ── Web Push (M58.7) ──────────────────────────────────────────────────────
    # VAPID public key — safe to return; needed by frontend to subscribe.
    vapid_public_key: Optional[str] = None


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

    # ── M60.12 Slack routing (Drift vs Security) ──────────────────────────────
    # Channel overrides: a Slack channel ID, or "" to clear (→ default channel).
    slack_drift_channel_id: Optional[str] = Field(default=None, max_length=64)
    slack_security_channel_id: Optional[str] = Field(default=None, max_length=64)
    slack_security_alerts_enabled: Optional[bool] = None
    slack_security_resolved_enabled: Optional[bool] = None

    # ── M61.8 Email routing (Drift vs Security) ───────────────────────────────
    email_security_alerts_enabled: Optional[bool] = None
    email_security_resolved_enabled: Optional[bool] = None
    # Comma/newline-separated recipient list, or "" to clear (→ default recipient).
    email_security_recipients: Optional[str] = Field(default=None, max_length=2000)

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


# ── Web Push schemas (M58.7) ──────────────────────────────────────────────────

_VALID_PUSH_RISK_LEVELS = frozenset({"high", "critical_only"})


class PushSubscriptionKeys(BaseModel):
    """Web Push API subscription keys from the browser."""
    p256dh: str = Field(..., description="Browser's EC Diffie-Hellman public key (base64url).")
    auth: str = Field(..., description="Auth secret from the browser subscription (base64url).")


class PushSubscriptionData(BaseModel):
    """Full Web Push API PushSubscription object from the browser."""
    endpoint: str = Field(..., description="Push service endpoint URL.", max_length=2048)
    keys: PushSubscriptionKeys


class PushSubscribeRequest(BaseModel):
    """Body for POST /workspaces/{id}/notifications/push/subscriptions."""
    subscription: PushSubscriptionData
    device_label: Optional[str] = Field(
        default=None, max_length=100,
        description="Human-readable label, e.g. 'Chrome on Mac'.",
    )
    min_risk_level: str = Field(
        default="high",
        description="Minimum risk level for push: 'high' (high+critical) or 'critical_only'.",
    )
    # ── M60.13 per-device category preferences ────────────────────────────────
    drift_push_enabled: bool = Field(
        default=True, description="Receive Drift Detection critical/high push."
    )
    security_push_enabled: bool = Field(
        default=False, description="Receive Security Exposure critical/high push (opt-in)."
    )
    security_resolved_push_enabled: bool = Field(
        default=False, description="Receive resolved-exposure push (off by default)."
    )

    @field_validator("min_risk_level")
    @classmethod
    def validate_min_risk_level(cls, v: str) -> str:
        if v not in _VALID_PUSH_RISK_LEVELS:
            raise ValueError(
                f"min_risk_level must be one of: {sorted(_VALID_PUSH_RISK_LEVELS)}"
            )
        return v


class PushSubscriptionUpdateRequest(BaseModel):
    """Body for PATCH a push subscription's per-device preferences (M60.13).

    All fields optional — omitted fields are unchanged.
    """
    min_risk_level: Optional[str] = None
    drift_push_enabled: Optional[bool] = None
    security_push_enabled: Optional[bool] = None
    security_resolved_push_enabled: Optional[bool] = None

    @field_validator("min_risk_level")
    @classmethod
    def validate_min_risk_level(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _VALID_PUSH_RISK_LEVELS:
            raise ValueError(
                f"min_risk_level must be one of: {sorted(_VALID_PUSH_RISK_LEVELS)}"
            )
        return v


class PushSubscriptionResponse(BaseModel):
    """Safe subscription metadata — no endpoint, p256dh, or auth returned."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    enabled: bool
    device_label: Optional[str] = None
    browser_name: Optional[str] = None
    min_risk_level: str
    # M60.13 per-device category preferences.
    drift_push_enabled: bool = True
    security_push_enabled: bool = False
    security_resolved_push_enabled: bool = False
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    last_error: Optional[str] = None


class PushSubscriptionListResponse(BaseModel):
    """Returned by GET /workspaces/{id}/notifications/push/subscriptions."""
    subscriptions: List[PushSubscriptionResponse]


class PushPublicKeyResponse(BaseModel):
    """Returned by GET /workspaces/{id}/notifications/push/public-key."""
    vapid_public_key: Optional[str] = None
    configured: bool = False


class PushTestResponse(BaseModel):
    """Returned by POST /workspaces/{id}/notifications/push/test."""
    sent: int
    total_subscriptions: int
    error: Optional[str] = None
