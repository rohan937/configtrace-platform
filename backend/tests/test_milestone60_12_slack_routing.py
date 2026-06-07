"""M60.12 — separate Slack channel routing for Drift vs Security.

Covers the routing-target resolution + send-decision policy and the
metadata-only security Slack message builder. Actual network sends are not
performed (the dispatch seam is exercised in sync regression).
"""

from __future__ import annotations

import re
import uuid

from app.models.notification_settings import WorkspaceNotificationSettings
from app.services import notification_routing_service as routing
from app.services import security_exposure_events as events
from app.services import slack_service


def _event(event_type: str, severity: str, linked: bool = False) -> events.SecurityExposureEvent:
    return events.SecurityExposureEvent(
        event_type=event_type,
        finding_id=str(uuid.uuid4()),
        workspace_id=str(uuid.uuid4()),
        integration_id=str(uuid.uuid4()),
        resource_id=str(uuid.uuid4()),
        provider="github",
        severity=severity,
        title="GitHub webhook uses plain HTTP",
        status="active" if event_type != events.EVENT_RESOLVED else "resolved",
        finding_key="github_webhook_http:1",
        first_detected_at="2026-06-01T00:00:00+00:00",
        last_seen_at="2026-06-02T00:00:00+00:00",
        resolved_at="2026-06-03T00:00:00+00:00" if event_type == events.EVENT_RESOLVED else None,
        linked_change_id=str(uuid.uuid4()) if linked else None,
    )


def _settings(**over) -> WorkspaceNotificationSettings:
    return WorkspaceNotificationSettings(
        workspace_id=uuid.uuid4(),
        slack_enabled=over.get("slack_enabled", False),
        slack_app_enabled=over.get("slack_app_enabled", True),
        webhook_enabled=False,
        notify_on_risk_level="high_and_critical",
        slack_channel_id=over.get("slack_channel_id", "C_DEFAULT"),
        slack_drift_channel_id=over.get("slack_drift_channel_id", None),
        slack_security_channel_id=over.get("slack_security_channel_id", None),
        slack_security_alerts_enabled=over.get("slack_security_alerts_enabled", False),
        slack_security_resolved_enabled=over.get("slack_security_resolved_enabled", False),
    )


# ── Channel resolution ───────────────────────────────────────────────────────


def test_security_channel_used_when_set():
    s = _settings(slack_security_channel_id="C_SEC")
    assert routing.resolve_security_slack_channel(s) == "C_SEC"


def test_security_falls_back_to_default_channel():
    s = _settings(slack_security_channel_id=None, slack_channel_id="C_DEFAULT")
    assert routing.resolve_security_slack_channel(s) == "C_DEFAULT"


def test_resolve_none_when_no_channel():
    s = _settings(slack_security_channel_id=None, slack_channel_id=None)
    assert routing.resolve_security_slack_channel(s) is None


# ── Send decision: opened/reopened ───────────────────────────────────────────


def test_opt_in_off_does_not_send():
    s = _settings(slack_security_alerts_enabled=False, slack_security_channel_id="C_SEC")
    d = routing.route_security_event(event=_event(events.EVENT_OPENED, "critical"), settings=s)
    assert d.slack_eligible is True  # configured
    assert d.slack_should_send is False  # but not opted in
    assert d.slack_channel_id is None


def test_opt_in_on_sends_to_security_channel():
    s = _settings(slack_security_alerts_enabled=True, slack_security_channel_id="C_SEC")
    d = routing.route_security_event(event=_event(events.EVENT_OPENED, "critical"), settings=s)
    assert d.slack_should_send is True
    assert d.slack_channel_id == "C_SEC"


def test_opt_in_on_falls_back_to_default_channel():
    s = _settings(slack_security_alerts_enabled=True, slack_security_channel_id=None, slack_channel_id="C_DEFAULT")
    d = routing.route_security_event(event=_event(events.EVENT_REOPENED, "high"), settings=s)
    assert d.slack_should_send is True
    assert d.slack_channel_id == "C_DEFAULT"


def test_medium_low_info_never_send():
    s = _settings(slack_security_alerts_enabled=True, slack_security_channel_id="C_SEC")
    for sev in ("medium", "low", "info"):
        d = routing.route_security_event(event=_event(events.EVENT_OPENED, sev), settings=s)
        assert d.slack_should_send is False


def test_no_send_when_slack_not_configured():
    s = _settings(slack_app_enabled=False, slack_enabled=False, slack_security_alerts_enabled=True)
    d = routing.route_security_event(event=_event(events.EVENT_OPENED, "critical"), settings=s)
    assert d.slack_should_send is False


# ── Send decision: resolved (conservative) ───────────────────────────────────


def test_resolved_not_sent_by_default():
    s = _settings(slack_security_alerts_enabled=True, slack_security_channel_id="C_SEC")
    d = routing.route_security_event(event=_event(events.EVENT_RESOLVED, "critical"), settings=s)
    assert d.slack_should_send is False  # resolved opt-in is separate and off


def test_resolved_sent_only_when_resolved_opt_in():
    s = _settings(
        slack_security_alerts_enabled=True,
        slack_security_resolved_enabled=True,
        slack_security_channel_id="C_SEC",
    )
    d = routing.route_security_event(event=_event(events.EVENT_RESOLVED, "critical"), settings=s)
    assert d.slack_should_send is True
    assert d.slack_channel_id == "C_SEC"


def test_resolved_medium_not_sent_even_when_enabled():
    s = _settings(slack_security_resolved_enabled=True, slack_security_channel_id="C_SEC")
    d = routing.route_security_event(event=_event(events.EVENT_RESOLVED, "medium"), settings=s)
    assert d.slack_should_send is False


# ── Message builder: metadata-only ───────────────────────────────────────────


def test_security_blocks_are_metadata_only():
    ev = _event(events.EVENT_OPENED, "critical", linked=True)
    blocks = slack_service.compose_security_exposure_blocks(
        event=ev, base_url="https://app.configtrace.org"
    )
    text = str(blocks)
    # Contains careful headline + detail link; never breach/attack wording.
    assert "Security exposure opened" in text
    assert f"/security/exposures/{ev.finding_id}" in text
    assert f"/changes/{ev.linked_change_id}" in text
    for banned in ("breach", "attack", "compromise"):
        assert banned.lower() not in text.lower()
    # No secret/evidence leakage.
    assert not re.search(r"secret|token|password|evidence|remediation", text, re.I)


def test_resolved_headline_wording():
    ev = _event(events.EVENT_RESOLVED, "high")
    blocks = slack_service.compose_security_exposure_blocks(
        event=ev, base_url="https://app.configtrace.org"
    )
    assert "Security exposure resolved" in str(blocks)
