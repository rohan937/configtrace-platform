"""M60.13 — per-user/device browser push preferences for Drift vs Security.

Product goal: one push subscription per device, but separate notification
preferences by event category. A device can independently enable critical Drift
Detection push and critical Security Exposure push without re-subscribing.

These tests exercise the push service gating and the PATCH preferences endpoint.
Real Web Push delivery is stubbed — ``send_push`` is monkeypatched so no network
call is made; we only assert *which* subscriptions would receive a push and that
payloads stay metadata-only.

Defaults under test (mirror the backend / M60.12 Slack opt-in convention):
  * drift_push_enabled            → True  (preserve existing drift push)
  * security_push_enabled         → False (opt-in; no surprise alerts)
  * security_resolved_push_enabled → False (low-noise)
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.services import push_notification_service as push_svc
from app.services import workspace_service
from app.services.security_exposure_events import SecurityExposureEvent


# ── Helpers ───────────────────────────────────────────────────────────────────


def _enable_web_push(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make settings.is_web_push_configured return True (non-placeholder keys)."""
    from app import config

    monkeypatch.setattr(config.settings, "WEB_PUSH_VAPID_PUBLIC_KEY", "BPubKey_test_value", raising=False)
    monkeypatch.setattr(config.settings, "WEB_PUSH_VAPID_PRIVATE_KEY", "PrivKey_test_value", raising=False)


def _capture_sends(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Replace send_push with a stub that records payloads and reports success."""
    sent: list[dict] = []

    def _fake_send_push(sub, payload, db):  # type: ignore[no-untyped-def]
        sent.append({"sub_id": sub.id, "payload": payload})
        return True

    monkeypatch.setattr(push_svc, "send_push", _fake_send_push)
    return sent


def _make_ws(test_user, db_session):
    return workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M60.13", db=db_session
    )


def _make_sub(
    ws_id,
    db_session,
    *,
    user_id=None,
    label="Chrome on Mac",
    min_risk_level="high",
    drift=True,
    security=False,
    security_resolved=False,
):
    sub = push_svc.subscribe(
        workspace_id=ws_id,
        user_id=user_id,
        endpoint=f"https://push.example.com/{uuid.uuid4().hex}",
        p256dh="p256dh-test",
        auth="auth-test",
        device_label=label,
        min_risk_level=min_risk_level,
        user_agent=None,
        browser_name="Chrome",
        db=db_session,
        drift_push_enabled=drift,
        security_push_enabled=security,
        security_resolved_push_enabled=security_resolved,
    )
    db_session.commit()
    db_session.refresh(sub)
    return sub


def _event(ws_id, *, event_type="security_exposure_opened", severity="critical"):
    return SecurityExposureEvent(
        event_type=event_type,
        finding_id=str(uuid.uuid4()),
        workspace_id=str(ws_id),
        integration_id=str(uuid.uuid4()),
        resource_id=str(uuid.uuid4()),
        provider="aws",
        severity=severity,
        title="S3 bucket allows public read access",
        status="open" if event_type != "security_exposure_resolved" else "resolved",
        finding_key="aws:s3:acme-bucket:public_read",
        first_detected_at="2026-06-01T00:00:00+00:00",
        last_seen_at="2026-06-08T00:00:00+00:00",
        resolved_at=None,
        linked_change_id=None,
    )


def _drift_change(risk_level="critical"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        risk_level=risk_level,
        record_identifier="acme/widgets#webhook#1",
        risk_reason="Webhook target changed",
    )


# ── 1. Existing drift push still works (default device) ───────────────────────


def test_existing_drift_push_still_works(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    sub = _make_sub(ws.id, db_session, user_id=test_user.id)

    integ = SimpleNamespace(provider="github")
    count = push_svc.dispatch_push_for_sync(
        workspace_id=ws.id,
        changes=[_drift_change("critical")],
        integration=integ,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    assert count == 1
    assert len(sent) == 1
    assert sent[0]["sub_id"] == sub.id


# ── 2. Drift backward-compat: opting a device out skips only that device ───────


def test_drift_opt_out_is_per_device(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    on = _make_sub(ws.id, db_session, user_id=test_user.id, label="On", drift=True)
    _make_sub(ws.id, db_session, user_id=test_user.id, label="Off", drift=False)

    count = push_svc.dispatch_push_for_sync(
        workspace_id=ws.id,
        changes=[_drift_change("critical")],
        integration=SimpleNamespace(provider="github"),
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    assert count == 1
    assert {s["sub_id"] for s in sent} == {on.id}


# ── 3. Security push is OFF by default (opt-in) ───────────────────────────────


def test_security_push_off_by_default(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    _make_sub(ws.id, db_session, user_id=test_user.id)  # defaults: security False

    count = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id, event=_event(ws.id, severity="critical"), db=db_session
    )
    assert count == 0
    assert sent == []


# ── 4 & 5. Security enabled → critical and high both delivered ────────────────


@pytest.mark.parametrize("severity", ["critical", "high"])
def test_security_enabled_allows_critical_and_high(test_user, db_session, monkeypatch, severity):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    sub = _make_sub(ws.id, db_session, user_id=test_user.id, security=True, min_risk_level="high")

    count = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id, event=_event(ws.id, severity=severity), db=db_session
    )
    assert count == 1
    assert sent[0]["sub_id"] == sub.id


# ── 6. Medium / low / info never push ─────────────────────────────────────────


@pytest.mark.parametrize("severity", ["medium", "low", "info"])
def test_security_non_alertable_never_pushes(test_user, db_session, monkeypatch, severity):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    _make_sub(ws.id, db_session, user_id=test_user.id, security=True, security_resolved=True)

    count = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id, event=_event(ws.id, severity=severity), db=db_session
    )
    assert count == 0
    assert sent == []


# ── 7. Resolved push is OFF even when security_push_enabled is on ─────────────


def test_resolved_push_off_by_default(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    # security on, but resolved still off → resolved event must not push.
    _make_sub(ws.id, db_session, user_id=test_user.id, security=True, security_resolved=False)

    count = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id,
        event=_event(ws.id, event_type="security_exposure_resolved", severity="critical"),
        db=db_session,
    )
    assert count == 0
    assert sent == []


# ── 8. Resolved push delivered only when explicitly enabled ───────────────────


def test_resolved_push_only_when_enabled(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    sub = _make_sub(
        ws.id, db_session, user_id=test_user.id, security=True, security_resolved=True
    )

    count = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id,
        event=_event(ws.id, event_type="security_exposure_resolved", severity="critical"),
        db=db_session,
    )
    assert count == 1
    assert sent[0]["sub_id"] == sub.id
    assert "resolved" in sent[0]["payload"]["title"].lower()


# ── 9. critical_only device floors out a high-severity exposure ───────────────


def test_security_min_risk_level_floor(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    _make_sub(
        ws.id, db_session, user_id=test_user.id, security=True, min_risk_level="critical_only"
    )

    high = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id, event=_event(ws.id, severity="high"), db=db_session
    )
    assert high == 0
    crit = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id, event=_event(ws.id, severity="critical"), db=db_session
    )
    assert crit == 1


# ── 10. Security push payload is metadata-only and carefully worded ───────────


def test_security_payload_is_metadata_only():
    ev = SecurityExposureEvent(
        event_type="security_exposure_opened",
        finding_id="finding-123",
        workspace_id="ws-1",
        integration_id="int-1",
        resource_id="res-1",
        provider="aws",
        severity="critical",
        title="S3 bucket allows public read access",
        status="open",
        finding_key="aws:s3:acme-bucket:public_read",
        first_detected_at=None,
        last_seen_at=None,
        resolved_at=None,
        linked_change_id=None,
    )
    payload = push_svc._build_security_push_payload(ev, "https://app.configtrace.org")

    # Careful wording — never "breach"/"attack"/"compromise".
    blob = " ".join(str(v).lower() for v in payload.values())
    for forbidden in ("breach", "attack", "compromise", "secret", "password", "token"):
        assert forbidden not in blob
    assert "security exposure" in payload["title"].lower()
    assert "opened" in payload["title"].lower()

    # Only safe metadata keys — no evidence/remediation/raw values.
    assert set(payload.keys()) == {"title", "body", "url", "tag", "risk_level", "provider"}
    assert payload["url"] == "https://app.configtrace.org/security/exposures/finding-123"
    assert payload["tag"] == "configtrace-exposure-finding-123"


# ── 11. Not-configured short-circuits to zero ─────────────────────────────────


def test_dispatch_noop_when_web_push_unconfigured(test_user, db_session, monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "WEB_PUSH_VAPID_PUBLIC_KEY", "", raising=False)
    monkeypatch.setattr(config.settings, "WEB_PUSH_VAPID_PRIVATE_KEY", "", raising=False)
    sent = _capture_sends(monkeypatch)
    ws = _make_ws(test_user, db_session)
    _make_sub(ws.id, db_session, user_id=test_user.id, security=True)

    count = push_svc.dispatch_security_push_for_event(
        workspace_id=ws.id, event=_event(ws.id, severity="critical"), db=db_session
    )
    assert count == 0
    assert sent == []


# ── 12. update_push_subscription_prefs toggles without re-subscribing ─────────


def test_update_prefs_changes_only_passed_fields(test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    ws = _make_ws(test_user, db_session)
    sub = _make_sub(ws.id, db_session, user_id=test_user.id)
    assert sub.security_push_enabled is False

    updated = push_svc.update_push_subscription_prefs(
        workspace_id=ws.id,
        subscription_id=sub.id,
        db=db_session,
        security_push_enabled=True,
    )
    assert updated is not None
    assert updated.id == sub.id  # same subscription — no re-subscribe
    assert updated.security_push_enabled is True
    # Untouched fields preserved.
    assert updated.drift_push_enabled is True
    assert updated.security_resolved_push_enabled is False
    assert updated.min_risk_level == "high"


def test_update_prefs_unknown_subscription_returns_none(test_user, db_session):
    ws = _make_ws(test_user, db_session)
    result = push_svc.update_push_subscription_prefs(
        workspace_id=ws.id,
        subscription_id=uuid.uuid4(),
        db=db_session,
        security_push_enabled=True,
    )
    assert result is None


# ── 13. PATCH endpoint round-trip (subscribe defaults → toggle → list) ────────


def test_patch_endpoint_toggles_prefs(client, test_user, db_session, monkeypatch):
    _enable_web_push(monkeypatch)
    ws = _make_ws(test_user, db_session)
    sub = _make_sub(ws.id, db_session, user_id=test_user.id)

    # Subscribe defaults: drift on, security off.
    resp = client.get(f"/workspaces/{ws.id}/notifications/push/subscriptions")
    assert resp.status_code == 200
    body = resp.json()
    target = next(s for s in body["subscriptions"] if s["id"] == str(sub.id))
    assert target["drift_push_enabled"] is True
    assert target["security_push_enabled"] is False
    assert target["security_resolved_push_enabled"] is False

    # PATCH: enable security critical push for this device.
    patch = client.patch(
        f"/workspaces/{ws.id}/notifications/push/subscriptions/{sub.id}",
        json={"security_push_enabled": True},
    )
    assert patch.status_code == 200
    patched = patch.json()
    assert patched["security_push_enabled"] is True
    assert patched["drift_push_enabled"] is True  # unchanged

    # PATCH unknown id → 404.
    missing = client.patch(
        f"/workspaces/{ws.id}/notifications/push/subscriptions/{uuid.uuid4()}",
        json={"security_push_enabled": True},
    )
    assert missing.status_code == 404


# ── 14. Migration applied — new columns are present on the model/table ────────


def test_pref_columns_exist_on_table(test_user, db_session):
    ws = _make_ws(test_user, db_session)
    sub = _make_sub(ws.id, db_session, user_id=test_user.id)
    # Round-trip the row to confirm the columns exist and persist.
    db_session.expire(sub)
    db_session.refresh(sub)
    assert hasattr(sub, "drift_push_enabled")
    assert hasattr(sub, "security_push_enabled")
    assert hasattr(sub, "security_resolved_push_enabled")
    assert sub.drift_push_enabled is True
    assert sub.security_push_enabled is False
    assert sub.security_resolved_push_enabled is False
