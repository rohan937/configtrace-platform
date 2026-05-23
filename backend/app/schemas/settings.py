"""Pydantic schemas for settings endpoints — M34.

GET  /settings  → UserSettingsResponse
PATCH /settings → UserSettingsUpdateRequest → UserSettingsResponse

All allowed values are validated at the schema level so the router can
return clear 422 errors instead of silently storing bad values.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, field_validator

# ── Allowed value sets ────────────────────────────────────────────────────────

ALLOWED_ALERT_RISK_THRESHOLDS = frozenset(
    {"critical_only", "high_and_critical", "medium_and_above"}
)
ALLOWED_SYNC_FAILURE_THRESHOLDS = frozenset({2, 3, 5})
ALLOWED_SYNC_FAILURE_COOLDOWN_HOURS = frozenset({6, 12, 24})
ALLOWED_SYNC_INTERVAL_MINUTES = frozenset({5, 10, 15, 30, 60})
ALLOWED_TIMELINE_RANGES = frozenset({"24h", "7d", "30d", "all"})
ALLOWED_PROVIDER_FILTERS = frozenset({"all", "cloudflare", "github", "vercel", "stripe", "aws"})


# ── Response schema ───────────────────────────────────────────────────────────


class UserSettingsResponse(BaseModel):
    """Full user-settings record returned by GET /settings and PATCH /settings."""

    model_config = {"from_attributes": True}

    # Alert policy
    alert_risk_threshold: str
    sync_failure_alerts_enabled: bool
    sync_failure_threshold: int
    sync_failure_cooldown_hours: int

    # Sync defaults (new integrations only)
    default_sync_enabled: bool
    default_sync_interval_minutes: int
    default_change_alerts_enabled: bool

    # UI preferences
    default_timeline_range: str
    default_provider_filter: str


# ── Update request schema ─────────────────────────────────────────────────────


class UserSettingsUpdateRequest(BaseModel):
    """Request body for PATCH /settings.  All fields are optional.

    Only provided (non-None) fields are written; omitted fields are unchanged.
    """

    # Alert policy
    alert_risk_threshold: Optional[str] = None
    sync_failure_alerts_enabled: Optional[bool] = None
    sync_failure_threshold: Optional[int] = None
    sync_failure_cooldown_hours: Optional[int] = None

    # Sync defaults
    default_sync_enabled: Optional[bool] = None
    default_sync_interval_minutes: Optional[int] = None
    default_change_alerts_enabled: Optional[bool] = None

    # UI preferences
    default_timeline_range: Optional[str] = None
    default_provider_filter: Optional[str] = None

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("alert_risk_threshold")
    @classmethod
    def validate_alert_risk_threshold(cls, v: str) -> str:
        if v not in ALLOWED_ALERT_RISK_THRESHOLDS:
            raise ValueError(
                f"alert_risk_threshold must be one of: "
                f"{sorted(ALLOWED_ALERT_RISK_THRESHOLDS)}"
            )
        return v

    @field_validator("sync_failure_threshold")
    @classmethod
    def validate_sync_failure_threshold(cls, v: int) -> int:
        if v not in ALLOWED_SYNC_FAILURE_THRESHOLDS:
            raise ValueError(
                f"sync_failure_threshold must be one of: "
                f"{sorted(ALLOWED_SYNC_FAILURE_THRESHOLDS)}"
            )
        return v

    @field_validator("sync_failure_cooldown_hours")
    @classmethod
    def validate_sync_failure_cooldown_hours(cls, v: int) -> int:
        if v not in ALLOWED_SYNC_FAILURE_COOLDOWN_HOURS:
            raise ValueError(
                f"sync_failure_cooldown_hours must be one of: "
                f"{sorted(ALLOWED_SYNC_FAILURE_COOLDOWN_HOURS)}"
            )
        return v

    @field_validator("default_sync_interval_minutes")
    @classmethod
    def validate_default_sync_interval_minutes(cls, v: int) -> int:
        if v not in ALLOWED_SYNC_INTERVAL_MINUTES:
            raise ValueError(
                f"default_sync_interval_minutes must be one of: "
                f"{sorted(ALLOWED_SYNC_INTERVAL_MINUTES)}"
            )
        return v

    @field_validator("default_timeline_range")
    @classmethod
    def validate_default_timeline_range(cls, v: str) -> str:
        if v not in ALLOWED_TIMELINE_RANGES:
            raise ValueError(
                f"default_timeline_range must be one of: "
                f"{sorted(ALLOWED_TIMELINE_RANGES)}"
            )
        return v

    @field_validator("default_provider_filter")
    @classmethod
    def validate_default_provider_filter(cls, v: str) -> str:
        if v not in ALLOWED_PROVIDER_FILTERS:
            raise ValueError(
                f"default_provider_filter must be one of: "
                f"{sorted(ALLOWED_PROVIDER_FILTERS)}"
            )
        return v
