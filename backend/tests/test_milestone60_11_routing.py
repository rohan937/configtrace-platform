"""M60.11 — notification routing by event category.

Tests the pure routing layer (category mapping + channel eligibility) and that
it stays metadata-only and respects the no-spam guarantee from M60.10.
"""

from __future__ import annotations

import re
import uuid

from app.models.notification_settings import WorkspaceNotificationSettings
from app.services import notification_routing_service as routing
from app.services import security_exposure_events as events


def _event(event_type: str, severity: str) -> events.SecurityExposureEvent:
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
        resolved_at=None,
        linked_change_id=None,
    )


def _settings(**over) -> WorkspaceNotificationSettings:
    return WorkspaceNotificationSettings(
        workspace_id=uuid.uuid4(),
        slack_enabled=over.get("slack_enabled", False),
        slack_app_enabled=over.get("slack_app_enabled", False),
        webhook_enabled=over.get("webhook_enabled", False),
        notify_on_risk_level="high_and_critical",
    )


# ── 1–4. Category mapping ────────────────────────────────────────────────────


def test_categories_exist():
    assert routing.CATEGORY_DRIFT == "drift_change"
    assert routing.CATEGORY_SECURITY == "security_exposure"
    assert routing.CATEGORY_SECURITY_RESOLVED == "security_exposure_resolved"


def test_opened_maps_to_security():
    assert routing.category_for_security_event(events.EVENT_OPENED) == routing.CATEGORY_SECURITY


def test_reopened_maps_to_security():
    assert routing.category_for_security_event(events.EVENT_REOPENED) == routing.CATEGORY_SECURITY


def test_resolved_maps_to_security_resolved():
    assert (
        routing.category_for_security_event(events.EVENT_RESOLVED)
        == routing.CATEGORY_SECURITY_RESOLVED
    )


# ── 5–6. Severity policy ─────────────────────────────────────────────────────


def test_critical_high_alertable_eligible_with_slack():
    s = _settings(slack_app_enabled=True)
    for sev in ("critical", "high"):
        d = routing.route_security_event(event=_event(events.EVENT_OPENED, sev), settings=s)
        assert d.category == routing.CATEGORY_SECURITY
        assert d.slack_eligible is True
        assert d.email_eligible is True
        assert d.push_eligible is True
        assert d.any_eligible is True
        assert d.dispatched is False  # M60.11 prepares only


def test_medium_low_info_not_routed():
    s = _settings(slack_app_enabled=True)
    for sev in ("medium", "low", "info"):
        d = routing.route_security_event(event=_event(events.EVENT_OPENED, sev), settings=s)
        assert d.any_eligible is False
        assert "not alertable" in d.reason


def test_slack_not_eligible_when_not_configured():
    s = _settings(slack_app_enabled=False, slack_enabled=False)
    d = routing.route_security_event(event=_event(events.EVENT_OPENED, "critical"), settings=s)
    assert d.slack_eligible is False
    # email/push still eligible for alertable events
    assert d.email_eligible is True
    assert d.push_eligible is True


def test_slack_eligible_via_legacy_flag():
    s = _settings(slack_enabled=True)
    d = routing.route_security_event(event=_event(events.EVENT_OPENED, "critical"), settings=s)
    assert d.slack_eligible is True


def test_no_settings_means_no_slack():
    d = routing.route_security_event(event=_event(events.EVENT_OPENED, "critical"), settings=None)
    assert d.slack_eligible is False
    assert d.email_eligible is True  # config-gated globally


# ── 7. Resolved policy ───────────────────────────────────────────────────────


def test_resolved_not_routed_by_default():
    s = _settings(slack_app_enabled=True)
    d = routing.route_security_event(event=_event(events.EVENT_RESOLVED, "critical"), settings=s)
    assert d.category == routing.CATEGORY_SECURITY_RESOLVED
    assert d.any_eligible is False
    assert d.dispatched is False
    assert "resolved" in d.reason


def test_reopened_routes_like_security():
    s = _settings(slack_app_enabled=True)
    d = routing.route_security_event(event=_event(events.EVENT_REOPENED, "high"), settings=s)
    assert d.category == routing.CATEGORY_SECURITY
    assert d.any_eligible is True


# ── 8. Payload privacy ───────────────────────────────────────────────────────


def test_routing_payload_metadata_only():
    s = _settings(slack_app_enabled=True)
    ev = _event(events.EVENT_OPENED, "critical")
    d = routing.route_security_event(event=ev, settings=s)
    payload = routing.routing_payload(ev, d)

    assert payload["category"] == routing.CATEGORY_SECURITY
    assert payload["routing"]["slack_eligible"] is True
    assert payload["routing"]["dispatched"] is False
    assert payload["detail_path"] == f"/security/exposures/{ev.finding_id}"

    assert "evidence" not in payload
    assert "remediation" not in payload
    secret_re = re.compile(r"secret|token|password|api_?key|private_?key", re.I)
    for k in payload.keys():
        assert not secret_re.search(k)


# ── 9. No-spam: nothing to route on refresh (DB-backed via evaluator) ────────


def test_refresh_produces_no_routable_events(test_user, db_session):
    from app.connectors.github_schema import GITHUB_WEBHOOK
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    from app.models.resource import Resource
    from app.models.security_finding import SecurityFinding
    from app.models.snapshot import Snapshot
    from app.services import security_finding_evaluator as evaluator
    from app.services import workspace_service

    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M60.11", db=db_session
    )
    ct, iv = encrypt_credentials({"credential_type": "github_app"})
    integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="github",
        display_name="gh", encrypted_credentials=ct, credential_iv=iv, status="active",
    )
    db_session.add(integ)
    db_session.commit()
    db_session.refresh(integ)
    res = Resource(
        integration_id=integ.id, user_id=test_user.id,
        provider_resource_type="github_repo", provider_resource_id="acme/widgets",
        display_name="acme/widgets", is_active=True,
    )
    db_session.add(res)
    db_session.commit()
    db_session.refresh(res)

    def _snap():
        s = Snapshot(
            resource_id=res.id, integration_id=integ.id, user_id=test_user.id,
            state=[{
                "record_id": "acme/widgets#webhook#1", "record_type": GITHUB_WEBHOOK,
                "name": "hook #1", "url": "http://example.com/h", "active": True,
            }],
            content_hash=uuid.uuid4().hex, triggered_by="manual",
        )
        db_session.add(s)
        db_session.commit()
        db_session.refresh(s)
        return s

    s1 = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=_snap()
    )
    s2 = evaluator.evaluate_security_findings_for_resource(
        db=db_session, workspace_id=ws.id, integration=integ, resource=res, snapshot=_snap()
    )
    # First pass: one opened event → routable. Second pass: refresh → none.
    assert len(s1["events"]) == 1
    assert len(s2["events"]) == 0

    settings = _settings(slack_app_enabled=True)
    routed_first = [routing.route_security_event(event=e, settings=settings) for e in s1["events"]]
    routed_second = [routing.route_security_event(event=e, settings=settings) for e in s2["events"]]
    assert sum(1 for d in routed_first if d.any_eligible) == 1
    assert routed_second == []

    db_session.query(SecurityFinding).filter(SecurityFinding.workspace_id == ws.id).delete()
    db_session.commit()
