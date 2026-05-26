"""GitHub PR draft schemas — M58.20.

These schemas represent a safe, read-only PR draft proposal derived from
a Terraform fix suggestion.  No GitHub repository mutations occur in M58.20.

PERMANENT SAFETY CONSTANTS (enforced by validators — never change):
  - creates_branch   is ALWAYS False.
  - commits_code     is ALWAYS False.
  - opens_pr         is ALWAYS False.
  - executes_terraform is ALWAYS False.
  - requires_human_review is ALWAYS True.

Actual PR creation is deferred to M58.21 and requires GitHub App permissions
(repository contents write + pull requests write), explicit user opt-in, and
additional safety gates that are not present in this milestone.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, field_validator


# ── Safety flags ──────────────────────────────────────────────────────────────

class GitHubPrDraftSafetyFlags(BaseModel):
    """Hard-wired safety flags for the GitHub PR draft.

    All write-action flags are permanently False in M58.20.
    Validators enforce this invariant and will raise if any value deviates.
    """

    creates_branch: bool = False        # Never True in M58.20
    commits_code: bool = False          # Never True in M58.20
    opens_pr: bool = False              # Never True in M58.20
    executes_terraform: bool = False    # Never True in any milestone
    requires_human_review: bool = True  # Always True

    @field_validator("creates_branch")
    @classmethod
    def creates_branch_must_be_false(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("creates_branch must always be False in M58.20.")
        return v

    @field_validator("commits_code")
    @classmethod
    def commits_code_must_be_false(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("commits_code must always be False in M58.20.")
        return v

    @field_validator("opens_pr")
    @classmethod
    def opens_pr_must_be_false(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("opens_pr must always be False in M58.20.")
        return v

    @field_validator("executes_terraform")
    @classmethod
    def executes_terraform_must_be_false(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("executes_terraform must always be False.")
        return v


# ── Repo info ─────────────────────────────────────────────────────────────────

class GitHubPrDraftRepo(BaseModel):
    """The GitHub repository and file targeted by the PR draft."""

    repo_full_name: str
    default_branch: str
    file_path: str


# ── Draft PR object ───────────────────────────────────────────────────────────

class GitHubPrDraftObject(BaseModel):
    """The proposed GitHub PR — branch name, commit, title, body, and patch.

    All content is read-only.  No GitHub API calls are made in M58.20.
    ``patch_preview`` is None when the Terraform fix is guidance-only
    (low confidence mapping).
    """

    branch_name: str                    # e.g. "configtrace/aws-restrict-public-ssh"
    commit_message: str                 # Safe, non-sensational commit message
    pr_title: str                       # PR title for the proposed pull request
    pr_body: str                        # Full markdown PR body
    target_file_path: str               # File the patch would be applied to
    patch_preview: Optional[str] = None # HCL diff from M58.19; None if guided_only
    labels: List[str] = []             # Static safe labels: configtrace, security, terraform
    review_notes: List[str] = []       # Human-readable pre-merge checklist items


# ── Full response ─────────────────────────────────────────────────────────────

class GitHubPrDraftResponse(BaseModel):
    """Full response for GET /changes/{change_id}/github-pr-draft.

    ``mode`` is always "draft_preview_only" in M58.20.
    ``safety`` enforces that no repository mutations have occurred.
    ``reason`` is populated when ``available`` is False.

    CRITICAL: This endpoint never calls GitHub create-branch, create-commit,
    or create-pull-request APIs.  All content is generated locally from the
    Terraform fix preview (M58.19) and IaC mapping data (M58.18).
    """

    available: bool
    mode: str = "draft_preview_only"        # Always "draft_preview_only" in M58.20
    title: Optional[str] = None
    summary: Optional[str] = None
    repo: Optional[GitHubPrDraftRepo] = None
    draft: Optional[GitHubPrDraftObject] = None
    safety: GitHubPrDraftSafetyFlags = GitHubPrDraftSafetyFlags()
    requirements: List[str] = []
    next_step: Optional[str] = None
    reason: Optional[str] = None           # Populated when available=False
    # UUID of the IacRepository — populated in M58.21 for PR creation.
    iac_repository_id: Optional[str] = None
