"""GitHub PR create schemas — M58.21.

Request and response schemas for actually creating a GitHub draft PR from
a Terraform fix suggestion (M58.19) via the ConfigTrace GitHub App.

PERMANENT SAFETY CONSTANTS (enforced by Pydantic validators — never change):
  - executes_terraform        is ALWAYS False.  Never set True.
  - mutates_provider_resource is ALWAYS False.  Never set True.

Actual PR creation (this milestone) requires ALL of:
  - confirmation_phrase == "CREATE DRAFT PR" (exact, case-sensitive)
  - User is workspace admin or owner
  - Terraform fix preview available and not guided_only
  - Mapping confidence is "medium" or "high"
  - acknowledge_placeholders == True when fix contains <PLACEHOLDER> values
  - IacRepository.installation_id is set (GitHub App installed on repo)
  - GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY environment variables configured
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel, field_validator


# ── Request ───────────────────────────────────────────────────────────────────

class GitHubPrCreateRequest(BaseModel):
    """Request body for POST /changes/{change_id}/github-pr.

    All safety fields are required — no defaults that could allow
    accidental or automated PR creation.
    """

    confirmation_phrase: str
    """Must be exactly "CREATE DRAFT PR" (case-sensitive).
    Required to prevent accidental or automated PR creation."""

    iac_repository_id: UUID
    """UUID of the IacRepository to target.
    The repository must have a configured GitHub App installation_id."""

    target_base_branch: str
    """Branch to base the new PR off (e.g. "main"). Must not be empty."""

    acknowledge_placeholders: bool = False
    """Must be True when the Terraform fix suggestion contains <PLACEHOLDER>
    values. Confirms the user understands placeholders must be replaced
    manually before merging."""


# ── Safety flags ──────────────────────────────────────────────────────────────

class GitHubPrCreateSafetyFlags(BaseModel):
    """Safety flags confirming what this action does and permanently does not do.

    executes_terraform and mutates_provider_resource are permanently False
    and are enforced by Pydantic validators.  They must never be changed.
    """

    executes_terraform: bool = False          # Permanent — never changes
    mutates_provider_resource: bool = False    # Permanent — never changes
    creates_draft_pr: bool = True             # True — this is the actual PR creation

    @field_validator("executes_terraform")
    @classmethod
    def executes_terraform_must_be_false(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("executes_terraform must always be False.")
        return v

    @field_validator("mutates_provider_resource")
    @classmethod
    def mutates_provider_resource_must_be_false(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("mutates_provider_resource must always be False.")
        return v


# ── Response ──────────────────────────────────────────────────────────────────

class GitHubPrCreateResponse(BaseModel):
    """Full response for POST /changes/{change_id}/github-pr.

    On success: pr_url, pr_number, branch_name, base_branch, patch_file_path,
    commit_sha, and suggestion_id are populated.

    On failure: success=False and error is a human-readable explanation.
    The safety flags are always populated regardless of success/failure.

    CRITICAL: executes_terraform and mutates_provider_resource are always False.
    ConfigTrace does not execute Terraform or mutate cloud provider resources.
    """

    success: bool
    pr_url: Optional[str] = None            # e.g. "https://github.com/owner/repo/pull/42"
    pr_number: Optional[int] = None         # GitHub PR number
    branch_name: Optional[str] = None       # Created branch name
    base_branch: Optional[str] = None       # Branch the PR targets
    patch_file_path: Optional[str] = None   # Path of the created patch file
    commit_sha: Optional[str] = None        # SHA of the created commit
    safety: GitHubPrCreateSafetyFlags = GitHubPrCreateSafetyFlags()
    error: Optional[str] = None             # Human-readable error when success=False
    suggestion_id: Optional[str] = None     # UUID of the GitHubPrSuggestion audit record
