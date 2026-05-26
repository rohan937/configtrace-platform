"""Policy engine schemas — M58.14.

All types are display-safe: no raw credential values, no customer data,
no secret values appear in any policy schema field.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ── Catalog / response types ──────────────────────────────────────────────────


class WorkspacePolicyResponse(BaseModel):
    """A built-in policy with its current enabled state for the workspace."""

    model_config = ConfigDict(from_attributes=True)

    policy_key: str
    name: str
    description: str
    provider: Optional[str]
    severity: str        # "critical" | "high" | "medium"
    category: str
    enabled: bool
    built_in: bool


class PolicyListResponse(BaseModel):
    """Full catalog for a workspace."""

    policies: list[WorkspacePolicyResponse]
    total: int


class PolicyUpdateRequest(BaseModel):
    """PUT body to enable or disable a policy."""

    enabled: bool


# ── Violation types ───────────────────────────────────────────────────────────


class PolicyViolation(BaseModel):
    """A single policy violation detected for a change.

    Language rules (enforced here and in policy_engine_service.py):
      - evidence[] contains metadata-derived facts, never raw values
      - recommended_action is static guidance, never a command
      - description never claims "confirmed", "breach", or "guaranteed"
    """

    policy_key: str
    name: str
    severity: str
    description: str
    evidence: list[str]
    recommended_action: str


class PolicyViolationsResponse(BaseModel):
    violations: list[PolicyViolation]
