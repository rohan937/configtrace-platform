"""Blast Radius schemas — M58.11.

Response shape for GET /changes/{id}/blast-radius.

Design constraints:
  - No raw prev_value / new_value content.
  - No confirmed/guaranteed language — only "may", "potentially".
  - available: false is always a valid, safe fallback.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class BlastRadiusItem(BaseModel):
    """One potential impact area identified by the blast radius analysis."""

    label: str
    """Short human-readable label, e.g. "Admin access path"."""

    description: str
    """2–3 sentence explanation using "may/potentially" language."""

    severity: str
    """Inferred severity: "critical" | "high" | "medium" | "low"."""

    confidence: str
    """How confident ConfigTrace is in this item: "high" | "medium" | "low"."""

    evidence: list[str]
    """Short evidence strings derived from metadata (never raw values)."""

    recommended_review: list[str]
    """Specific review steps for this impact area."""


class AffectedSurface(BaseModel):
    """A surface (resource class, workflow, or infra component) that may be affected."""

    type: str
    """Surface category: "resource" | "integration" | "workflow" | "infra"."""

    provider: str
    """Provider key, e.g. "aws", "github", "stripe"."""

    label: str
    """Short label shown in the UI, e.g. "Security group users"."""

    description: str
    """Explanation of the potential connection to this change."""

    count: Optional[int] = None
    """Known count of affected instances. None when count cannot be determined."""

    confidence: str
    """Confidence that this surface is affected: "high" | "medium" | "low"."""

    known: bool
    """True when inferred from actual configuration metadata; False when inferred from type only."""


class BlastRadiusResponse(BaseModel):
    """Full blast radius response for GET /changes/{id}/blast-radius."""

    available: bool
    """False when no blast radius model is applicable or the change is too low-risk."""

    confidence: str = "low"
    """Overall analysis confidence: "high" | "medium" | "low"."""

    title: str = ""
    """Short title, e.g. "Potential impact of this AWS Security Group change"."""

    summary: str = ""
    """2–3 sentence summary using "potentially/may" language."""

    impact_domains: list[str] = []
    """
    Affected blast radius domains, e.g.
    ["network_exposure", "admin_access", "data_access", "auth_flow",
     "deployment_path", "payment_flow", "commerce_operations",
     "edge_protection", "monitoring_visibility", "credential_access",
     "customer_self_service", "dns_routing"]
    """

    items: list[BlastRadiusItem] = []
    """Detailed impact items, one per affected area."""

    affected_surfaces: list[AffectedSurface] = []
    """Resource classes or workflows potentially affected."""

    limitations: list[str] = []
    """
    Honest caveats about what ConfigTrace cannot confirm without additional context.
    Always present for any meaningful blast radius result.
    """
