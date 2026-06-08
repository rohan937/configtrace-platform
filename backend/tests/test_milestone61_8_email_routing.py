"""M61.8 — Drift-vs-Security email routing.

  1.  security email is OFF by default (no send)
  2.  enabled → critical/high opened & reopened send an email
  3.  medium/low/info never email (not alertable)
  4.  resolved email OFF by default
  5.  resolved email sends only when explicitly enabled
  6.  explicit recipients used; else fall back to the default recipient
  7.  email body is metadata-only and avoids forbidden wording
  8.  email not configured → no send
  9.  settings round-trip (service) persists the new fields
  10. migration columns exist on the model

Drift/change email behavior is untouched (alert_service) — covered by existing
M24 tests, not duplicated here.
"""

from __future__ import annotations

import uuid

import pytest

from app import config
from app.models.notification_settings import WorkspaceNotificationSettings
from app.services import email_service
from app.services import security_email_alert_service as svc
from app.services.security_exposure_events import (
    EVENT_OPENED,
    EVENT_REOPENED,
    EVENT_RESOLVED,
    SecurityExposureEvent,
)

BASE = "https://app.configtrace.org"


# ── helpers ───────────────────────────────────────────────────────────────────


def _enable_email(monkeypatch):
    monkeypatch.setattr(config.settings, "RESEND_API_KEY", "test_key", raising=False)
    monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.test", raising=False)


def _capture(monkeypatch):
    sent = []

    def _fake(*, to, subject, body):
        sent.append({"to": to, "subject": subject, "body": body})
        return {"id": "test"}

    monkeypatch.setattr(email_service, "send_email", _fake)
    return sent


def _settings(**over):
    base = dict(
        workspace_id=uuid.uuid4(),
        email_security_alerts_enabled=False,
        email_security_resolved_enabled=False,
        email_security_recipients=None,
    )
    base.update(over)
    return WorkspaceNotificationSettings(**base)


def _event(event_type=EVENT_OPENED, severity="critical"):
    return SecurityExposureEvent(
        event_type=event_type,
        finding_id=str(uuid.uuid4()),
        workspace_id=str(uuid.uuid4()),
        integration_id=str(uuid.uuid4()),
        resource_id=str(uuid.uuid4()),
        provider="aws",
        severity=severity,
        title="S3 bucket allows public read access",
        status="open" if event_type != EVENT_RESOLVED else "resolved",
        finding_key="aws_s3_public_acl:acme-bucket",
        first_detected_at="2026-06-01T00:00:00+00:00",
        last_seen_at="2026-06-08T00:00:00+00:00",
        resolved_at=None,
        linked_change_id=None,
    )


# ── 1. Off by default ─────────────────────────────────────────────────────────


def test_security_email_off_by_default(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(), settings=_settings(), base_url=BASE, fallback_recipient="a@b.com",
    )
    assert n == 0 and sent == []


# ── 2. Enabled sends critical/high opened & reopened ──────────────────────────


@pytest.mark.parametrize("event_type", [EVENT_OPENED, EVENT_REOPENED])
@pytest.mark.parametrize("severity", ["critical", "high"])
def test_enabled_sends_opened_reopened(monkeypatch, event_type, severity):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(event_type, severity),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    assert n == 1
    assert sent[0]["to"] == "owner@configtrace.test"
    assert "security exposure" in sent[0]["subject"].lower()


# ── 3. Non-alertable never emails ─────────────────────────────────────────────


@pytest.mark.parametrize("severity", ["medium", "low", "info"])
def test_non_alertable_no_email(monkeypatch, severity):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(EVENT_OPENED, severity),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    assert n == 0 and sent == []


# ── 4 & 5. Resolved email gating ──────────────────────────────────────────────


def test_resolved_off_by_default(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    # alerts enabled but resolved NOT enabled → resolved event must not email.
    n = svc.dispatch_security_email_for_event(
        event=_event(EVENT_RESOLVED, "critical"),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    assert n == 0 and sent == []


def test_resolved_sends_when_enabled(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(EVENT_RESOLVED, "critical"),
        settings=_settings(email_security_resolved_enabled=True),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    assert n == 1
    assert "resolved" in sent[0]["subject"].lower()


# ── 6. Explicit recipients vs fallback ────────────────────────────────────────


def test_explicit_recipients_used(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(),
        settings=_settings(
            email_security_alerts_enabled=True,
            email_security_recipients="sec1@configtrace.test, sec2@configtrace.test",
        ),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    assert n == 2
    assert {s["to"] for s in sent} == {"sec1@configtrace.test", "sec2@configtrace.test"}


def test_no_recipient_no_send(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient=None,
    )
    assert n == 0 and sent == []


def test_placeholder_recipient_filtered(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient="user_abc@clerk.user",
    )
    assert n == 0 and sent == []


# ── 7. Metadata-only, careful wording ─────────────────────────────────────────


def test_email_body_metadata_only(monkeypatch):
    _enable_email(monkeypatch)
    sent = _capture(monkeypatch)
    svc.dispatch_security_email_for_event(
        event=_event(),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    body = sent[0]["body"].lower()
    # Alarming wording must not appear.
    for forbidden in ("breach", "attack", "compromise", "incident confirmed"):
        assert forbidden not in body
    # No evidence/remediation blob leakage: the bucket name from finding_key/evidence
    # must not be embedded, and there is no JSON dump.
    assert "acme-bucket" not in body
    assert "{" not in body and "}" not in body
    assert "/security/exposures/" in sent[0]["body"]
    assert "risky configuration state" in body


# ── 8. Not configured → no send ───────────────────────────────────────────────


def test_not_configured_no_send(monkeypatch):
    monkeypatch.setattr(config.settings, "RESEND_API_KEY", "", raising=False)
    monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", "", raising=False)
    sent = _capture(monkeypatch)
    n = svc.dispatch_security_email_for_event(
        event=_event(),
        settings=_settings(email_security_alerts_enabled=True),
        base_url=BASE,
        fallback_recipient="owner@configtrace.test",
    )
    assert n == 0 and sent == []


# ── 9. Settings round-trip persists new fields ────────────────────────────────


def test_settings_roundtrip(test_user, db_session):
    from app.services import notification_service
    from app.services import workspace_service

    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M61.8", db=db_session
    )
    notification_service.update_notification_settings(
        workspace_id=ws.id,
        actor_user_id=test_user.id,
        email_security_alerts_enabled=True,
        email_security_resolved_enabled=True,
        email_security_recipients="sec@configtrace.test",
        db=db_session,
    )
    row = notification_service.get_or_create_notification_settings(ws.id, db_session)
    assert row.email_security_alerts_enabled is True
    assert row.email_security_resolved_enabled is True
    assert row.email_security_recipients == "sec@configtrace.test"
    # Clearing recipients with "" → None.
    notification_service.update_notification_settings(
        workspace_id=ws.id, actor_user_id=test_user.id,
        email_security_recipients="", db=db_session,
    )
    row2 = notification_service.get_or_create_notification_settings(ws.id, db_session)
    assert row2.email_security_recipients is None
    db_session.query(WorkspaceNotificationSettings).filter(
        WorkspaceNotificationSettings.workspace_id == ws.id
    ).delete()
    db_session.commit()


# ── 10. Migration columns exist on the model ──────────────────────────────────


def test_columns_exist(test_user, db_session):
    from app.services import notification_service
    from app.services import workspace_service

    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M61.8b", db=db_session
    )
    row = notification_service.get_or_create_notification_settings(ws.id, db_session)
    assert row.email_security_alerts_enabled is False  # default
    assert row.email_security_resolved_enabled is False
    assert row.email_security_recipients is None
    db_session.query(WorkspaceNotificationSettings).filter(
        WorkspaceNotificationSettings.workspace_id == ws.id
    ).delete()
    db_session.commit()
