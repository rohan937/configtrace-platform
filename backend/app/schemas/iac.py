"""Pydantic schemas for IaC Awareness endpoints — M58.18.

GET  /workspaces/{id}/iac/repositories              → IacRepositoryListResponse
POST /workspaces/{id}/iac/repositories              → IacRepositoryResponse
POST /workspaces/{id}/iac/repositories/{id}/scan    → IacScanResult
GET  /workspaces/{id}/iac/mappings                  → IacMappingListResponse
GET  /changes/{id}/iac-context                      → IacContextResponse

Language guidelines (permanent):
  Use:   "may be managed by Terraform", "possible IaC mapping",
         "review IaC source before making manual console changes"
  Avoid: "is definitely managed by Terraform" (unless match_confidence == "high")

The IaC context is advisory only.  It does not confirm Terraform ownership.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import UUID4, BaseModel, ConfigDict


# ── Repository schemas ────────────────────────────────────────────────────────


class IacRepositoryCreate(BaseModel):
    """Request body for POST /workspaces/{id}/iac/repositories."""

    repo_full_name: str
    """GitHub "owner/repo" string, e.g. "acme/infra"."""

    integration_id: Optional[UUID4] = None
    """Optional UUID of an existing GitHub integration to use for scanning."""

    default_branch: Optional[str] = "main"
    """Default branch to scan. Defaults to 'main'."""

    scanning_enabled: Optional[bool] = True
    """Whether automatic scanning is enabled for this repository."""


class IacRepositoryResponse(BaseModel):
    """Single IaC repository record."""

    id: UUID4
    workspace_id: UUID4
    integration_id: Optional[UUID4] = None
    provider: str
    repo_full_name: str
    default_branch: Optional[str] = None
    scanning_enabled: bool
    last_scan_status: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IacRepositoryListResponse(BaseModel):
    """Response for GET /workspaces/{id}/iac/repositories."""

    repositories: List[IacRepositoryResponse]
    total: int


# ── Scan result schema ────────────────────────────────────────────────────────


class IacScanResult(BaseModel):
    """Result of a POST .../scan request.

    ``status`` values:
    - "success"        — scan completed; ``resources_found`` indicates discoveries
    - "no_integration" — no GitHub integration linked to this repository
    - "no_access"      — GitHub API returned 403 (Contents permission required)
    - "no_tf_files"    — scan succeeded but no .tf files were found
    - "not_found"      — repository row not found
    - "error"          — unexpected error during scan
    """

    status: str
    message: str
    resources_found: int = 0
    files_scanned: int = 0


# ── Mapping schemas ───────────────────────────────────────────────────────────


class IacResourceMappingItem(BaseModel):
    """One Terraform resource mapping record.

    Safety: no file contents, no secret values, no credentials.
    Only safe metadata: file path, resource block type/name, line range,
    and safe cloud identifiers.
    """

    id: UUID4
    workspace_id: UUID4
    iac_repository_id: UUID4
    repo_full_name: str
    """Joined from the parent IacRepository for display convenience."""

    provider: str
    resource_type: str
    terraform_resource_type: Optional[str] = None
    terraform_resource_name: Optional[str] = None
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    cloud_resource_identifier: Optional[str] = None
    cloud_resource_name: Optional[str] = None
    match_confidence: str
    match_reason: str
    mapping_source: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IacMappingListResponse(BaseModel):
    """Response for GET /workspaces/{id}/iac/mappings."""

    mappings: List[IacResourceMappingItem]
    total: int


# ── Change IaC context schemas ────────────────────────────────────────────────


class IacChangeMappingCandidate(BaseModel):
    """One possible Terraform resource that may correspond to a changed cloud resource.

    Language note: "may correspond", "possible mapping" — not confirmed ownership.
    """

    mapping_id: UUID4
    iac_repository_id: UUID4
    repo_full_name: Optional[str] = None
    terraform_resource_type: Optional[str] = None
    terraform_resource_name: Optional[str] = None
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    cloud_resource_identifier: Optional[str] = None
    cloud_resource_name: Optional[str] = None
    match_confidence: str
    """'high' | 'medium' | 'low'"""
    match_reason: str
    mapping_source: str


class IacContextResponse(BaseModel):
    """IaC context for a single change — GET /changes/{id}/iac-context.

    Advisory only.  Does NOT confirm Terraform ownership of the changed resource.
    The ``available`` flag indicates whether any mapping candidates were found.
    """

    available: bool
    """True when at least one possible IaC mapping candidate exists."""

    summary: str
    """One or two sentence advisory summary using appropriate uncertainty language."""

    mappings: List[IacChangeMappingCandidate]
    """Ordered list of possible Terraform resource candidates (high confidence first)."""

    recommended_workflow: Optional[str] = None
    """Advisory steps for handling a resource that may be Terraform-managed."""

    future_fix_available: bool = False
    """Always False in M58.18; Terraform patch suggestions come in M58.19."""

    future_fix_note: Optional[str] = None
    """Note about upcoming Terraform fix suggestion capability (M58.19)."""
