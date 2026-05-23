"""Pydantic schemas for integration endpoints.

Response schemas deliberately omit every credential field:
``encrypted_credentials``, ``credential_iv``, and any raw provider tokens
or IDs are never present in any API response.  This is enforced at the schema
level, not by runtime filtering.

Supported providers
-------------------
``cloudflare``
    Credentials: ``api_token`` + ``zone_id``.
``github``
    Credentials: ``github_token`` + ``repo_owner`` + ``repo_name``.

Provider-specific fields are made optional at the Pydantic level and
cross-validated by ``validate_provider_fields`` to produce clear error
messages when a required field is missing for the selected provider.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import UUID4, BaseModel, Field, model_validator


class IntegrationCreateRequest(BaseModel):
    """Request body for ``POST /integrations``.

    All credential fields are optional at the type level; the
    ``validate_provider_fields`` validator enforces that the correct subset
    is present for the chosen provider.
    """

    provider: Literal["cloudflare", "github"] = Field(
        ...,
        description=(
            "Provider identifier. "
            "Supported values: 'cloudflare', 'github'."
        ),
    )
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable label for this integration (shown in the UI).",
    )

    # ── Cloudflare fields ─────────────────────────────────────────────────────
    api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Cloudflare API token with Zone.DNS:Read permission. "
            "Required when provider='cloudflare'. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    zone_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Cloudflare Zone ID (32-char hex string from the dashboard). "
            "Required when provider='cloudflare'."
        ),
    )

    # ── GitHub fields ─────────────────────────────────────────────────────────
    github_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Fine-grained GitHub PAT with Metadata:Read, Administration:Read, "
            "Secrets:Read, and Variables:Read repository permissions. "
            "Required when provider='github'. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    repo_owner: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "GitHub username or organisation that owns the repository. "
            "Required when provider='github'."
        ),
    )
    repo_name: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Repository name (without the owner prefix). "
            "Required when provider='github'."
        ),
    )

    @model_validator(mode="after")
    def validate_provider_fields(self) -> "IntegrationCreateRequest":
        """Ensure the correct credential fields are present for the provider."""
        if self.provider == "cloudflare":
            if not self.api_token:
                raise ValueError(
                    "api_token is required for Cloudflare integrations."
                )
            if not self.zone_id:
                raise ValueError(
                    "zone_id is required for Cloudflare integrations."
                )
        elif self.provider == "github":
            if not self.github_token:
                raise ValueError(
                    "github_token is required for GitHub integrations."
                )
            if not self.repo_owner:
                raise ValueError(
                    "repo_owner is required for GitHub integrations."
                )
            if not self.repo_name:
                raise ValueError(
                    "repo_name is required for GitHub integrations."
                )
        return self


class IntegrationResponse(BaseModel):
    """Safe representation of a single integration — no credentials."""

    id: UUID4
    provider: str
    display_name: str
    status: str
    last_synced_at: Optional[datetime]
    created_at: datetime
    # Populated from the ``Integration.resource_count`` property.  The
    # ``resources`` relationship is loaded eagerly (selectin) so this incurs
    # no additional query.
    resource_count: int = 0

    model_config = {"from_attributes": True}


class IntegrationListResponse(BaseModel):
    """Response body for ``GET /integrations``."""

    integrations: list[IntegrationResponse]
    total: int
