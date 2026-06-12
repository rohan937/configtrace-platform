"""Schemas for Cloudflare security/audit activity ingestion + signals (M68.1)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CloudflareActivitySyncRequest(BaseModel):
    """POST /security/cloudflare-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class CloudflareActivitySyncResponse(BaseModel):
    """Cloudflare audit-activity ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    source: str
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class CloudflareSignalGenerateResponse(BaseModel):
    """Cloudflare Incident Signal generation summary."""

    provider: str
    activity_events_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0


class CloudflareWafEventSyncRequest(BaseModel):
    """POST /security/cloudflare-waf-events/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class CloudflareWafEventSyncResponse(BaseModel):
    """Cloudflare WAF/security-event ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    source: str
    events_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class CloudflareWafSignalGenerateRequest(BaseModel):
    """POST /security/cloudflare-waf-events/generate-signals body (all optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_signals: Optional[int] = Field(default=None, ge=1, le=1000)
    block_threshold: Optional[int] = Field(default=None, ge=2, le=1_000_000)
    challenge_threshold: Optional[int] = Field(default=None, ge=2, le=1_000_000)
    sensitive_path_threshold: Optional[int] = Field(default=None, ge=2, le=1_000_000)
    rule_trigger_threshold: Optional[int] = Field(default=None, ge=2, le=1_000_000)
    skip_allow_threshold: Optional[int] = Field(default=None, ge=2, le=1_000_000)


class CloudflareWafSignalGenerateResponse(BaseModel):
    """Cloudflare WAF/security-event Incident Signal generation summary."""

    provider: str
    source: str
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
