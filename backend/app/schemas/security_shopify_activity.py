"""Schemas for Shopify activity/Events ingestion (M74B).

Activity ingestion only — no signals, correlations, or demo for Shopify in
this milestone. Honest about partial/limited results: ``permission_limited``
is True when the Shopify access token does not grant Events read access (the
common case for an Admin API token without the right read scope), or when
Shopify returns 401/403/404/422 for the Events endpoint. ``error_message`` is
a short, safe string — never access tokens, signing secrets, raw URLs, raw
payloads, customer / order / payment data, or staff names/emails.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ShopifyActivitySyncRequest(BaseModel):
    """POST /security/shopify-activity/sync request body (all optional)."""

    integration_id: Optional[str] = None
    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_events: Optional[int] = Field(default=None, ge=1, le=1000)


class ShopifyActivitySyncResponse(BaseModel):
    """Shopify activity/Events ingestion summary."""

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


class ShopifyActivitySignalGenerateRequest(BaseModel):
    """POST /security/shopify-activity/generate-signals body (M74C, all optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_signals: Optional[int] = Field(default=None, ge=1, le=1000)


class ShopifyActivitySignalGenerateResponse(BaseModel):
    """Shopify activity Incident Signal generation summary (M74C)."""

    provider: str
    source: str
    events_scanned: int = 0
    groups_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
