"""Security exposure lifecycle events — M60.10.

A small, routing-agnostic event layer for Security Exposure findings. The
evaluator emits these objects on lifecycle transitions (open / re-open /
resolve); M60.11/M60.12 will route them to Slack / email / browser push.

This milestone deliberately does NOT send anything. Events are returned from the
evaluator (in its summary) and logged with the ``security_exposure_events:``
prefix so the transition is explicit and testable.

Privacy
-------
Event payloads are metadata-only: identifiers, provider, severity, title,
finding_key, status, and lifecycle timestamps. They intentionally exclude
``evidence`` and ``remediation`` blobs, secrets, tokens, payloads, raw rules,
and customer data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from app.models.security_finding import SecurityFinding

# Event type constants (boring, stable names).
EVENT_OPENED = "security_exposure_opened"
EVENT_REOPENED = "security_exposure_reopened"
EVENT_RESOLVED = "security_exposure_resolved"

# Severities that should route to alert channels (matches the default
# high_and_critical alerting convention used for drift changes).
_ALERTABLE_SEVERITIES = frozenset({"critical", "high"})


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


@dataclass(frozen=True)
class SecurityExposureEvent:
    """An alertable lifecycle event for a single security finding."""

    event_type: str
    finding_id: str
    workspace_id: str
    integration_id: str
    resource_id: Optional[str]
    provider: str
    severity: str
    title: str
    status: str
    finding_key: str
    first_detected_at: Optional[str]
    last_seen_at: Optional[str]
    resolved_at: Optional[str]
    linked_change_id: Optional[str]

    @property
    def detail_path(self) -> str:
        """Frontend path to the exposure detail page."""
        return f"/security/exposures/{self.finding_id}"

    @property
    def is_alertable(self) -> bool:
        """Whether this event should route to alert channels (critical/high)."""
        return self.severity in _ALERTABLE_SEVERITIES

    def to_payload(self) -> dict[str, Any]:
        """Metadata-only serializable payload for routing/logging."""
        return {
            "event_type": self.event_type,
            "finding_id": self.finding_id,
            "workspace_id": self.workspace_id,
            "integration_id": self.integration_id,
            "resource_id": self.resource_id,
            "provider": self.provider,
            "severity": self.severity,
            "title": self.title,
            "status": self.status,
            "finding_key": self.finding_key,
            "first_detected_at": self.first_detected_at,
            "last_seen_at": self.last_seen_at,
            "resolved_at": self.resolved_at,
            "linked_change_id": self.linked_change_id,
            "detail_path": self.detail_path,
            "alertable": self.is_alertable,
        }


def event_from_finding(
    event_type: str, finding: SecurityFinding
) -> SecurityExposureEvent:
    """Build a metadata-only event from a persisted finding."""
    return SecurityExposureEvent(
        event_type=event_type,
        finding_id=str(finding.id),
        workspace_id=str(finding.workspace_id),
        integration_id=str(finding.integration_id),
        resource_id=str(finding.resource_id) if finding.resource_id else None,
        provider=finding.provider,
        severity=finding.severity,
        title=finding.title,
        status=finding.status,
        finding_key=finding.finding_key,
        first_detected_at=_iso(finding.first_detected_at),
        last_seen_at=_iso(finding.last_seen_at),
        resolved_at=_iso(finding.resolved_at),
        linked_change_id=(
            str(finding.linked_change_id) if finding.linked_change_id else None
        ),
    )
