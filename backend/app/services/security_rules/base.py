"""Shared types/helpers for security exposure rules — M60.4."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class FindingCandidate:
    """A risky current state detected from one normalized snapshot record.

    The evaluator attaches ``resource_id`` and (best-effort) ``linked_change_id``
    at upsert time; rules do not need to know those.

    ``finding_key`` is fully-qualified and stable per risky record (base rule id
    plus a record discriminator) so multiple risky records on the SAME resource
    produce distinct findings rather than collapsing under the M60.3 active
    uniqueness key (workspace, integration, resource, finding_key).
    """

    provider: str
    rule_key: str            # base rule id, e.g. "github_webhook_http"
    finding_key: str         # fully-qualified, e.g. "github_webhook_http:123"
    severity: str            # critical | high | medium | low | info
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    # Discriminator within the resource (the normalized record_id); used to
    # match a related Change for linked_change_id.
    record_id: Optional[str] = None


def get_str(record: dict[str, Any], key: str) -> str:
    """Safely read a string field from a normalized record (never raises)."""
    val = record.get(key)
    return val if isinstance(val, str) else ""


def make_finding_key(rule_key: str, record_id: Optional[str]) -> str:
    """Build a stable, per-record finding key."""
    return f"{rule_key}:{record_id}" if record_id else rule_key
