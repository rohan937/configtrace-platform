"""Notification routing by event category — M60.11.

A pure, config-derived routing layer that decides which notification channels an
event category is ELIGIBLE for. It does NOT send anything in M60.11 — it produces
testable routing decisions and logs them, preparing M60.12 (Slack channel
routing) and M60.13 (push preferences).

Design constraints
------------------
* Drift Detection alerts are UNCHANGED. This module does not touch the existing
  change/diff dispatch path; ``drift_change`` exists only so both products share
  one vocabulary.
* Security exposure routing respects ``event.is_alertable`` (critical/high only)
  and never re-routes a refresh (M60.10 already emits opened events once).
* No new settings columns / migrations — eligibility derives from the existing
  WorkspaceNotificationSettings flags.

Payloads are metadata-only (see SecurityExposureEvent.to_payload()).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from app.models.notification_settings import WorkspaceNotificationSettings
from app.services.security_exposure_events import (
    EVENT_OPENED,
    EVENT_REOPENED,
    EVENT_RESOLVED,
    SecurityExposureEvent,
)

logger = logging.getLogger(__name__)

# ── Event categories ─────────────────────────────────────────────────────────
CATEGORY_DRIFT = "drift_change"
CATEGORY_SECURITY = "security_exposure"
CATEGORY_SECURITY_RESOLVED = "security_exposure_resolved"

NOTIFICATION_CATEGORIES = frozenset(
    {CATEGORY_DRIFT, CATEGORY_SECURITY, CATEGORY_SECURITY_RESOLVED}
)

# Map M60.10 security event types → routing categories.
_SECURITY_EVENT_CATEGORY = {
    EVENT_OPENED: CATEGORY_SECURITY,
    EVENT_REOPENED: CATEGORY_SECURITY,
    EVENT_RESOLVED: CATEGORY_SECURITY_RESOLVED,
}


def category_for_security_event(event_type: str) -> str:
    """Return the routing category for a security exposure event type."""
    return _SECURITY_EVENT_CATEGORY.get(event_type, CATEGORY_SECURITY)


@dataclass(frozen=True)
class RoutingDecision:
    """Which channels an event is eligible for. ``dispatched`` is always False
    in M60.11 — this layer only prepares routing, it does not send."""

    category: str
    slack_eligible: bool
    email_eligible: bool
    push_eligible: bool
    dispatched: bool
    reason: str

    @property
    def any_eligible(self) -> bool:
        return self.slack_eligible or self.email_eligible or self.push_eligible


def _slack_configured(settings: Optional[WorkspaceNotificationSettings]) -> bool:
    if settings is None:
        return False
    return bool(
        getattr(settings, "slack_app_enabled", False)
        or getattr(settings, "slack_enabled", False)
    )


def route_security_event(
    *,
    event: SecurityExposureEvent,
    settings: Optional[WorkspaceNotificationSettings],
) -> RoutingDecision:
    """Compute the channel-eligibility decision for a security exposure event.

    Policy (M60.11, conservative):
    * ``security_exposure_resolved`` → not routed by default (low-noise; sending
      deferred to a later milestone).
    * ``security_exposure`` (opened/reopened):
        - only ``is_alertable`` (critical/high) events route;
        - Slack eligible when Slack is configured for the workspace;
        - email eligible (the email channel is config-gated globally, no
          per-workspace toggle exists);
        - push eligible (subscription-gated at actual send time in M60.13).
    * Nothing is dispatched in M60.11 (``dispatched`` is always False).
    """
    category = category_for_security_event(event.event_type)

    if category == CATEGORY_SECURITY_RESOLVED:
        return RoutingDecision(
            category=category,
            slack_eligible=False,
            email_eligible=False,
            push_eligible=False,
            dispatched=False,
            reason="resolved exposure events are low-noise and not routed by default",
        )

    if not event.is_alertable:
        return RoutingDecision(
            category=category,
            slack_eligible=False,
            email_eligible=False,
            push_eligible=False,
            dispatched=False,
            reason="severity is not alertable (only critical/high route)",
        )

    return RoutingDecision(
        category=category,
        slack_eligible=_slack_configured(settings),
        email_eligible=True,
        push_eligible=True,
        dispatched=False,
        reason="alertable security exposure eligible for enabled channels (not dispatched in M60.11)",
    )


def routing_payload(
    event: SecurityExposureEvent, decision: RoutingDecision
) -> dict[str, Any]:
    """Metadata-only payload combining the event with its routing decision.

    Ready for M60.12/M60.13 to consume; contains no secrets/evidence.
    """
    payload = event.to_payload()
    payload["category"] = decision.category
    payload["routing"] = {
        "slack_eligible": decision.slack_eligible,
        "email_eligible": decision.email_eligible,
        "push_eligible": decision.push_eligible,
        "dispatched": decision.dispatched,
        "reason": decision.reason,
    }
    return payload


def log_security_routing(
    event: SecurityExposureEvent, decision: RoutingDecision
) -> None:
    """Emit a routing log line (no send)."""
    logger.info(
        "notification_routing: category=%s event=%s finding_id=%s severity=%s "
        "slack=%s email=%s push=%s dispatched=%s",
        decision.category,
        event.event_type,
        event.finding_id,
        event.severity,
        decision.slack_eligible,
        decision.email_eligible,
        decision.push_eligible,
        decision.dispatched,
    )
