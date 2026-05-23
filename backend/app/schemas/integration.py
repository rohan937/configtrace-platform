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
``vercel``
    Credentials: ``vercel_token`` + ``vercel_project_id``.

Provider-specific fields are made optional at the Pydantic level and
cross-validated by ``validate_provider_fields`` to produce clear error
messages when a required field is missing for the selected provider.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import UUID4, BaseModel, Field, model_validator

# Allowed per-integration sync intervals (minutes).  Must stay in sync with
# ``sync_service._ALLOWED_INTERVALS``.
_ALLOWED_SYNC_INTERVALS = frozenset({5, 10, 15, 30, 60})


class IntegrationCreateRequest(BaseModel):
    """Request body for ``POST /integrations``.

    All credential fields are optional at the type level; the
    ``validate_provider_fields`` validator enforces that the correct subset
    is present for the chosen provider.
    """

    provider: Literal["cloudflare", "github", "vercel"] = Field(
        ...,
        description=(
            "Provider identifier. "
            "Supported values: 'cloudflare', 'github', 'vercel'."
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

    # ── Vercel fields ─────────────────────────────────────────────────────────
    vercel_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Vercel personal access token with read access to the project. "
            "Generated at vercel.com → Settings → Tokens. "
            "Required when provider='vercel'. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    vercel_project_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Vercel project ID (prj_xxx) or project slug name. "
            "Found at vercel.com → <project> → Settings → General → Project ID. "
            "Required when provider='vercel'."
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
        elif self.provider == "vercel":
            if not self.vercel_token:
                raise ValueError(
                    "vercel_token is required for Vercel integrations."
                )
            if not self.vercel_project_id:
                raise ValueError(
                    "vercel_project_id is required for Vercel integrations."
                )
        return self


class IntegrationUpdateRequest(BaseModel):
    """Request body for ``PATCH /integrations/{id}``.

    All fields are optional — only the provided fields are updated.
    At least one field must be present.

    Constraints:
    - ``status`` may only be set to ``"active"`` or ``"paused"`` via this
      endpoint.  Soft-delete is performed via ``DELETE /integrations/{id}``.
    - ``sync_interval_minutes`` must be one of: 5, 10, 15, 30, 60.
    """

    display_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=200,
        description="New display name for the integration.",
    )
    sync_interval_minutes: Optional[int] = Field(
        None,
        description=(
            "Scheduled sync cadence in minutes. "
            "Allowed values: 5, 10, 15, 30, 60. "
            "Default (when null): 60."
        ),
    )
    status: Optional[Literal["active", "paused"]] = Field(
        None,
        description=(
            "Integration status. Use 'paused' to suspend scheduled syncs "
            "and block manual Sync Now requests. Use 'active' to re-enable."
        ),
    )

    @model_validator(mode="after")
    def validate_at_least_one_field(self) -> "IntegrationUpdateRequest":
        if (
            self.display_name is None
            and self.sync_interval_minutes is None
            and self.status is None
        ):
            raise ValueError(
                "At least one field (display_name, sync_interval_minutes, "
                "or status) must be provided."
            )
        if (
            self.sync_interval_minutes is not None
            and self.sync_interval_minutes not in _ALLOWED_SYNC_INTERVALS
        ):
            raise ValueError(
                f"sync_interval_minutes must be one of: "
                f"{sorted(_ALLOWED_SYNC_INTERVALS)}."
            )
        return self


class IntegrationReconnectRequest(BaseModel):
    """Request body for ``POST /integrations/{id}/reconnect``.

    Token-only reconnect — the integration's underlying resource (Cloudflare
    zone_id or GitHub owner/repo) cannot be changed via this endpoint.

    Provide ``api_token`` for Cloudflare integrations.
    Provide ``github_token`` for GitHub integrations.
    The backend uses the integration's existing provider to determine which
    field is required.  The token is validated against the live provider API
    before saving.  Tokens are never logged or returned.
    """

    api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Cloudflare API token. Required for Cloudflare integrations."
        ),
    )
    github_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New GitHub Personal Access Token. Required for GitHub integrations."
        ),
    )
    vercel_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Vercel personal access token. Required for Vercel integrations."
        ),
    )


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

    # ── M29 additions ─────────────────────────────────────────────────────────
    # ``sync_interval_minutes`` comes from the Integration column (dormant in
    # prior milestones).  ``last_sync_status`` and ``last_sync_error`` are
    # populated from the most recent SyncRun by the router helper
    # ``_build_response`` — they are not ORM attributes.
    sync_interval_minutes: Optional[int] = None
    last_sync_status: Optional[str] = None
    last_sync_error: Optional[str] = None

    # ── M31 addition ──────────────────────────────────────────────────────────
    # Derived without credential decryption — read from resource_metadata.
    # Values: "github_app" | "pat" (GitHub only) | None (non-GitHub providers).
    # This field is safe to expose — it conveys the auth method, not a secret.
    connection_method: Optional[str] = None

    # ── M32 additions ─────────────────────────────────────────────────────────
    # consecutive_failure_count: number of consecutive *scheduled* sync failures
    #   since the last success.  Reset to 0 on any successful sync.
    # needs_attention: True when consecutive_failure_count >= 3.  Populated by
    #   the router helper so the frontend can show a warning badge without
    #   knowing the threshold.
    consecutive_failure_count: int = 0
    needs_attention: bool = False

    model_config = {"from_attributes": True}


class IntegrationListResponse(BaseModel):
    """Response body for ``GET /integrations``."""

    integrations: list[IntegrationResponse]
    total: int
