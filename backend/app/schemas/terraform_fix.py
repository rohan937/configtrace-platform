"""Terraform fix suggestion preview schemas — M58.19.

PERMANENT SAFETY CONSTANTS (never change these):
  - execution_enabled is ALWAYS False. This service never applies changes.
  - pr_available is ALWAYS False. GitHub PR creation not available in M58.19.
  - safety_level is ALWAYS "requires_human_review".

These values are hard-coded in the service and validated here as
invariants — they must never be computed, toggled, or overridden.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, field_validator


class TerraformFixMappingInfo(BaseModel):
    """Summary of the IaC mapping used to derive the suggestion."""

    repo_full_name: Optional[str] = None
    file_path: str
    terraform_resource_type: Optional[str] = None
    terraform_resource_name: Optional[str] = None
    match_confidence: str  # "high" | "medium" | "low"


class TerraformFixPlaceholder(BaseModel):
    """A named placeholder inside a conceptual diff."""

    name: str         # e.g. "TRUSTED_CIDR"
    description: str  # e.g. "Your trusted IP CIDR, e.g. 10.0.0.0/8"
    example: str      # e.g. "10.0.0.0/8"


class TerraformFixSuggestion(BaseModel):
    """A single fix suggestion — either a conceptual HCL diff or guidance text.

    ``safety_level`` is always "requires_human_review".
    ``diff`` is None when ``kind == "guidance_only"``.
    """

    kind: str                        # "hcl_diff" | "guidance_only"
    title: str
    description: str
    language: str                    # "diff" | "hcl" | "text"
    diff: Optional[str] = None       # None for guidance_only
    safety_level: str = "requires_human_review"
    placeholders: List[TerraformFixPlaceholder] = []
    warnings: List[str] = []

    @field_validator("safety_level")
    @classmethod
    def safety_level_must_be_review(cls, v: str) -> str:
        """Enforce invariant: safety_level is permanently 'requires_human_review'."""
        if v != "requires_human_review":
            raise ValueError(
                "safety_level must always be 'requires_human_review' — "
                "this field is an immutable safety constraint."
            )
        return v


class TerraformFixPreviewResponse(BaseModel):
    """Full response for GET /changes/{change_id}/terraform-fix-preview.

    PERMANENT CONSTANTS:
    - pr_available: always False (GitHub PR creation not available in M58.19)
    - execution_enabled: always False (Terraform is never executed)

    These are enforced by validators and must never be changed.
    """

    available: bool
    confidence: Optional[str] = None          # "high" | "medium" | "low" | None
    title: Optional[str] = None
    summary: Optional[str] = None
    mapping: Optional[TerraformFixMappingInfo] = None
    suggestions: List[TerraformFixSuggestion] = []
    recommended_workflow: List[str] = []
    pr_available: bool = False                # Always False — permanent constraint
    execution_enabled: bool = False           # Always False — permanent constraint

    @field_validator("pr_available")
    @classmethod
    def pr_available_must_be_false(cls, v: bool) -> bool:
        """Enforce invariant: GitHub PR creation is never available."""
        if v is not False:
            raise ValueError(
                "pr_available must always be False — "
                "GitHub PR creation is not available in M58.19."
            )
        return v

    @field_validator("execution_enabled")
    @classmethod
    def execution_enabled_must_be_false(cls, v: bool) -> bool:
        """Enforce invariant: Terraform is never executed by this service."""
        if v is not False:
            raise ValueError(
                "execution_enabled must always be False — "
                "this service never applies Terraform changes."
            )
        return v
