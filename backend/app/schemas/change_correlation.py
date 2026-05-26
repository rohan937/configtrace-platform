"""Pydantic schemas for change correlation / risk clusters — M58.10.

GET /changes/{change_id}/correlation returns one of:
  { "available": false }
  { "available": true, "primary_cluster": { ... } }

Design:
  - Clusters are computed on demand; nothing is persisted.
  - cluster_id is a stable hash derived from sorted change IDs (not a DB key).
  - related_changes never includes raw prev_value / new_value — safe metadata only.
  - confidence is one of "high" | "medium" | "low".
  - cluster_type is an internal label for UI rendering / colour coding.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import UUID4, BaseModel, ConfigDict


class CorrelationChangeItem(BaseModel):
    """Compact, safe representation of a related change in a cluster.

    Never includes prev_value / new_value — raw change data is available
    via the individual change detail endpoint.
    """

    id: UUID4
    provider: str
    risk_level: str
    record_type: Optional[str]
    title: str
    detected_at: datetime
    url: str

    model_config = ConfigDict(from_attributes=False)


class PrimaryCluster(BaseModel):
    """The most significant correlation cluster found for the primary change."""

    # Stable non-persisted hash from sorted change IDs — for client-side dedup.
    cluster_id: str
    title: str
    summary: str
    confidence: str   # "high" | "medium" | "low"
    cluster_type: str  # "deployment_routing" | "payments_commerce" | "edge_security"
                       # | "auth_access" | "data_protection" | "provider_local" | "unknown"
    time_window_minutes: int
    signals: list[str]
    recommended_review: list[str]
    related_changes: list[CorrelationChangeItem]

    model_config = ConfigDict(from_attributes=False)


class CorrelationResponse(BaseModel):
    """Response envelope for GET /changes/{change_id}/correlation."""

    available: bool
    primary_cluster: Optional[PrimaryCluster] = None

    model_config = ConfigDict(from_attributes=False)
