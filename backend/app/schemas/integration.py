"""Pydantic schemas for integration endpoints.

Response schemas deliberately omit every credential field:
``encrypted_credentials``, ``credential_iv``, ``api_token``, and ``zone_id``
are never present in any API response.  This is enforced at the schema level,
not by runtime filtering.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import UUID4, BaseModel, Field


class IntegrationCreateRequest(BaseModel):
    """Request body for ``POST /integrations``."""

    provider: Literal["cloudflare"] = Field(
        ...,
        description="Provider identifier.  Only 'cloudflare' is supported in the MVP.",
    )
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable label for this integration (shown in the UI).",
    )
    api_token: str = Field(
        ...,
        min_length=1,
        description=(
            "Cloudflare API token with Zone.DNS:Read permission.  "
            "Stored encrypted — never returned in API responses."
        ),
    )
    zone_id: str = Field(
        ...,
        min_length=1,
        description="Cloudflare Zone ID (32-char hex string from the dashboard).",
    )


class IntegrationResponse(BaseModel):
    """Safe representation of a single integration — no credentials."""

    id: UUID4
    provider: str
    display_name: str
    status: str
    last_synced_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class IntegrationListResponse(BaseModel):
    """Response body for ``GET /integrations``."""

    integrations: list[IntegrationResponse]
    total: int
