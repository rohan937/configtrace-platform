"""Milestone 24 tests — High-risk email alerts.

What's covered
--------------
1. ``dispatch_alerts_for_sync`` sends a digest email when a high-risk
   change is present.
2. Critical changes also trigger a digest email (and the subject says
   ``Critical`` when at least one critical change is in the batch).
3. Low-risk and medium-risk changes do **not** trigger emails or Alert
   rows — these would be noise.
4. The recipient is loaded from the integration's owner, not from any
   caller-supplied value.
5. Cross-user isolation — a high-risk change on user A's integration
   never produces an email for user B (parallel test).
6. Duplicate prevention — once an email-channel Alert row exists for a
   Change, a second dispatch invocation never sends again.
7. Provider failure path — when the email provider raises, the dispatcher
   records ``status='failed'`` Alert rows and returns normally (does not
   raise).  Combined with the worker-level guard, this means a flaky
   provider never fails the DNS sync.
8. Manual sync trigger — when ``POST /syncs`` enqueues a sync whose result
   includes high-risk changes, the alert path is reached.  Verified by
   exercising the worker task with ``triggered_by="manual"`` and a mocked
   Cloudflare connector.
9. Scheduled sync trigger — same coverage with ``triggered_by="scheduled"``.
10. Email-not-configured path — when ``RESEND_API_KEY`` /
    ``ALERTS_FROM_EMAIL`` are missing, the dispatcher logs a warning and
    skips sending, **without** recording failed Alert rows (leaving the
    door open for a future sync to retry after configuration is fixed).

What's NOT covered (intentionally)
-----------------------------------
* The Resend HTTP call.  ``email_service.send_email`` is monkeypatched —
  no real network traffic, no test API keys required.
* Existing M21 / M22 / M23 behaviour.  Those suites continue to assert
  their own contracts.

How we test
-----------
The unit-style tests in this module call ``dispatch_alerts_for_sync``
directly with Change rows we construct ourselves — much faster than
running the full sync pipeline.  The two "manual/scheduled trigger" tests
go through ``sync_integration.apply(...)`` with a mocked CloudflareConnector
so we exercise the worker wiring as written.

In every test, ``email_service.send_email`` is monkeypatched to a recorder
that captures calls; we never make a real HTTP request.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.alert import Alert
from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.models.sync_run import SyncRun
from app.models.user import User
from app.services import alert_service, email_service


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_user(
    db_session: Session,
    *,
    email_suffix: str = "@example.com",
) -> User:
    """Create a user with a unique email; caller owns cleanup."""
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"m24_clerk_{uid}",
        email=f"m24_{uid}{email_suffix}",
        display_name="M24 Test User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _cleanup_user_with_data(db_session: Session, user: User) -> None:
    """Delete *user* and everything that depends on them.

    The DB schema uses ``ondelete='RESTRICT'`` on
    ``changes.user_id``, ``snapshots.user_id``, and ``alerts.user_id`` —
    so a plain ``db.delete(user)`` raises an IntegrityError as soon as
    the user has any Change / Snapshot / Alert rows.  We therefore delete
    the leaf tables explicitly first, then rely on the CASCADE on
    ``integrations.user_id`` and ``resources.user_id`` for the rest.

    Order matters:
        alerts → changes → snapshots → user
                                      └─ CASCADE → sync_runs, resources, integrations
    """
    from sqlalchemy import delete as sa_delete

    # Drop ORM-tracked references so the unit-of-work doesn't try to
    # nullify FKs on the children we're about to delete.
    db_session.expire_all()

    db_session.execute(sa_delete(Alert).where(Alert.user_id == user.id))
    db_session.execute(sa_delete(Change).where(Change.user_id == user.id))
    db_session.execute(sa_delete(Snapshot).where(Snapshot.user_id == user.id))
    db_session.commit()

    db_session.execute(sa_delete(User).where(User.id == user.id))
    db_session.commit()


def _make_integration(
    db_session: Session,
    user: User,
    *,
    display_name: str = "M24 Integration",
) -> Integration:
    """Create a Cloudflare integration + matching resource for *user*."""
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": "zone_m24"})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=display_name,
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(integration)
    db_session.flush()

    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=f"zone_m24_{uuid.uuid4().hex[:6]}",
        display_name="Zone M24",
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    return integration


def _make_snapshot_pair(
    db_session: Session,
    integration: Integration,
) -> tuple[Snapshot, Snapshot]:
    """Create two minimal snapshots tied to the integration's resource."""
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )
    assert resource is not None

    prev = Snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=integration.user_id,
        state=[],
        content_hash="prev_" + uuid.uuid4().hex,
        triggered_by="manual",
    )
    new = Snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=integration.user_id,
        state=[],
        content_hash="new_" + uuid.uuid4().hex,
        triggered_by="manual",
    )
    db_session.add_all([prev, new])
    db_session.commit()
    db_session.refresh(prev)
    db_session.refresh(new)
    return prev, new


def _make_change(
    db_session: Session,
    integration: Integration,
    *,
    risk_level: str,
    record_identifier: str = "CNAME record: api.example.com",
    change_type: str = "modified",
    field_path: str | None = "content",
    prev_value: Any = "prod.vercel.app",
    new_value: Any = "staging.vercel.app",
    risk_reason: str | None = "Production endpoint rerouted.",
) -> Change:
    """Create a fully-formed Change row with explicit risk_level."""
    prev_snap, new_snap = _make_snapshot_pair(db_session, integration)
    resource_id = (
        db_session.query(Resource.id)
        .filter(Resource.integration_id == integration.id)
        .scalar()
    )

    change = Change(
        resource_id=resource_id,
        integration_id=integration.id,
        user_id=integration.user_id,
        prev_snapshot_id=prev_snap.id,
        new_snapshot_id=new_snap.id,
        change_type=change_type,
        record_identifier=record_identifier,
        field_path=field_path,
        prev_value=prev_value,
        new_value=new_value,
        risk_level=risk_level,
        risk_reason=risk_reason,
    )
    db_session.add(change)
    db_session.commit()
    db_session.refresh(change)
    return change


@pytest.fixture
def email_recorder(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Patch ``email_service.send_email`` so no real HTTP traffic occurs.

    Also forces ``is_email_alerting_configured`` to True so the dispatcher
    treats the environment as ready to send.  Individual tests that want to
    exercise the unconfigured path can override this via monkeypatch.
    """
    from app.config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "test_resend_key")
    monkeypatch.setattr(settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.test")

    calls: list[dict[str, Any]] = []

    def fake_send(*, to: str, subject: str, body: str) -> dict:
        calls.append({"to": to, "subject": subject, "body": body})
        return {"id": f"resend_msg_{uuid.uuid4().hex[:8]}"}

    monkeypatch.setattr(email_service, "send_email", fake_send)
    return calls


# ─────────────────────────────────────────────────────────────────────────────
# 1. High-risk change sends an email
# ─────────────────────────────────────────────────────────────────────────────


def test_high_risk_change_sends_email(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    """A single high-risk change triggers a digest email + Alert row."""
    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="high")

    result = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert result["eligible"] == 1
    assert result["sent"] == 1
    assert result["recorded"] == 1
    assert result["failed"] == 0

    assert len(email_recorder) == 1
    sent = email_recorder[0]
    assert sent["to"] == test_user.email
    assert "High-risk" in sent["subject"]
    # M28: integration display_name moved to body (subject now uses record/change details)
    assert integration.display_name in sent["body"]

    alert = (
        db_session.query(Alert)
        .filter(Alert.change_id == change.id, Alert.channel == "email")
        .one()
    )
    assert alert.status == "delivered"
    assert alert.destination == test_user.email
    assert alert.delivered_at is not None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Critical change sends an email; subject says "Critical"
# ─────────────────────────────────────────────────────────────────────────────


def test_critical_change_sends_email(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="critical")

    result = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert result["sent"] == 1
    assert email_recorder[0]["subject"].startswith("[ConfigTrace] Critical")


def test_mixed_high_and_critical_subject_says_critical(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    """When the batch contains both high and critical, subject says Critical."""
    integration = _make_integration(db_session, test_user)
    c_high = _make_change(db_session, integration, risk_level="high")
    c_crit = _make_change(db_session, integration, risk_level="critical")

    alert_service.dispatch_alerts_for_sync(
        changes=[c_high, c_crit],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert len(email_recorder) == 1
    # M28: multi-change subject uses lowercase "critical"; body uses "Change X of N" format
    assert "critical" in email_recorder[0]["subject"].lower()
    assert "Change 1 of 2" in email_recorder[0]["body"] or "Change 2 of 2" in email_recorder[0]["body"]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Low- and medium-risk changes do NOT send email or write Alert rows
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("level", ["low", "medium"])
def test_low_and_medium_changes_do_not_send_email(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
    level: str,
) -> None:
    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level=level)

    result = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert result["eligible"] == 0
    assert result["sent"] == 0
    assert result["recorded"] == 0
    assert email_recorder == []

    # And no Alert row should have been written.
    assert (
        db_session.query(Alert)
        .filter(Alert.change_id == change.id)
        .count()
        == 0
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Recipient is the integration owner
# ─────────────────────────────────────────────────────────────────────────────


def test_email_goes_to_integration_owner(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    """The 'To' is always the user that owns the integration."""
    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="high")

    alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert email_recorder[0]["to"] == test_user.email


# ─────────────────────────────────────────────────────────────────────────────
# 5. Multi-user isolation
# ─────────────────────────────────────────────────────────────────────────────


def test_multi_user_isolation_no_cross_alerts(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    """User A and user B each get only their own changes."""
    other_user = _make_user(db_session)
    try:
        int_a = _make_integration(db_session, test_user, display_name="A")
        int_b = _make_integration(db_session, other_user, display_name="B")

        change_a = _make_change(db_session, int_a, risk_level="critical")
        change_b = _make_change(db_session, int_b, risk_level="high")

        alert_service.dispatch_alerts_for_sync(
            changes=[change_a],
            integration=int_a,
            sync_run_id=uuid.uuid4(),
            db=db_session,
        )
        alert_service.dispatch_alerts_for_sync(
            changes=[change_b],
            integration=int_b,
            sync_run_id=uuid.uuid4(),
            db=db_session,
        )
        db_session.commit()

        assert len(email_recorder) == 2
        recipients = {c["to"] for c in email_recorder}
        assert recipients == {test_user.email, other_user.email}

        # Alert row recipient matches the integration owner exactly.
        alert_a = (
            db_session.query(Alert)
            .filter(Alert.change_id == change_a.id)
            .one()
        )
        alert_b = (
            db_session.query(Alert)
            .filter(Alert.change_id == change_b.id)
            .one()
        )
        assert alert_a.destination == test_user.email
        assert alert_a.user_id == test_user.id
        assert alert_b.destination == other_user.email
        assert alert_b.user_id == other_user.id
        assert alert_a.user_id != alert_b.user_id
    finally:
        _cleanup_user_with_data(db_session, other_user)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Duplicate prevention — a second dispatch never re-sends
# ─────────────────────────────────────────────────────────────────────────────


def test_duplicate_dispatch_does_not_resend(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    """A retry of the same sync's dispatch never produces a second email."""
    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="critical")

    sync_run_id = uuid.uuid4()
    first = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=sync_run_id,
        db=db_session,
    )
    db_session.commit()
    assert first["sent"] == 1

    # Simulate a worker retry of the same sync — same Change row.
    second = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=sync_run_id,
        db=db_session,
    )
    db_session.commit()

    assert second["sent"] == 0
    assert second["already_alerted"] == 1
    assert len(email_recorder) == 1
    assert (
        db_session.query(Alert)
        .filter(Alert.change_id == change.id, Alert.channel == "email")
        .count()
        == 1
    )


# ─────────────────────────────────────────────────────────────────────────────
# 7. Email provider failure path
# ─────────────────────────────────────────────────────────────────────────────


def test_email_send_failure_records_failed_alert(
    db_session: Session,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the provider raises, dispatch returns normally and records 'failed'."""
    from app.config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "test_resend_key")
    monkeypatch.setattr(settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.test")

    def boom(**_: Any) -> dict:
        raise email_service.EmailSendError("simulated provider 5xx")

    monkeypatch.setattr(email_service, "send_email", boom)

    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="critical")

    # Must not raise.
    result = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert result["sent"] == 0
    assert result["failed"] == 1
    alert = (
        db_session.query(Alert)
        .filter(Alert.change_id == change.id)
        .one()
    )
    assert alert.status == "failed"
    assert alert.error_message is not None
    assert "simulated provider" in alert.error_message
    assert alert.delivered_at is None


def test_email_send_failure_blocks_future_resends(
    db_session: Session,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed Alert row also blocks future re-sends — idempotency includes failed."""
    from app.config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "test_resend_key")
    monkeypatch.setattr(settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.test")

    sends: list[dict[str, Any]] = []

    def first_call_fails_then_succeeds(*, to: str, subject: str, body: str) -> dict:
        sends.append({"to": to})
        if len(sends) == 1:
            raise email_service.EmailSendError("first call fails")
        return {"id": "ok"}

    monkeypatch.setattr(email_service, "send_email", first_call_fails_then_succeeds)

    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="critical")

    alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()
    alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    # Only the first attempt actually invoked the provider — the second saw the
    # idempotency guard and didn't even try.  This matches the documented design:
    # the failed Alert row is enough to suppress retries.  Operators must clear
    # the row (or wait for a new Change) to retry delivery.
    assert len(sends) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 8. Manual sync trigger reaches alert dispatch
# 9. Scheduled sync trigger reaches alert dispatch
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "triggered_by",
    ["manual", "scheduled"],
    ids=["manual_sync", "scheduled_sync"],
)
@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_trigger_reaches_alert_dispatch(
    mock_connector_cls,
    triggered_by: str,
    db_session: Session,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both manual and scheduled syncs end up dispatching alerts when changes hit high/critical risk.

    We exercise the actual worker entry point ``sync_integration.apply(...)``
    with a mocked Cloudflare connector, so the test verifies the worker
    correctly calls ``dispatch_alerts_for_sync`` (not just the dispatcher
    in isolation).  An MX deletion is used because it's classified as
    ``critical`` by the risk service — see test_milestone10.
    """
    from app.config import settings
    from app.services.sync_service import create_sync_run
    from app.workers.sync_task import sync_integration

    monkeypatch.setattr(settings, "RESEND_API_KEY", "test_resend_key")
    monkeypatch.setattr(settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.test")

    sends: list[dict[str, Any]] = []
    monkeypatch.setattr(
        email_service,
        "send_email",
        lambda *, to, subject, body: (
            sends.append({"to": to, "subject": subject}) or {"id": "ok"}
        ),
    )

    integration = _make_integration(db_session, test_user)

    # Baseline: an MX record so the second sync's deletion is classified critical.
    mock_connector_cls.return_value.fetch.return_value = [
        {
            "record_id": "mx-1",
            "record_type": "MX",
            "name": "example.com",
            "content": "mail.example.com",
            "ttl": 300,
            "proxied": False,
            "priority": 10,
            "comment": None,
            "modified_on": "2026-05-21T00:00:00Z",
        },
    ]
    run1 = create_sync_run(
        user_id=test_user.id,
        integration_id=integration.id,
        db=db_session,
        triggered_by=triggered_by,
    )
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # Sync 2 — MX removed → critical change → alert.
    mock_connector_cls.return_value.fetch.return_value = []
    run2 = create_sync_run(
        user_id=test_user.id,
        integration_id=integration.id,
        db=db_session,
        triggered_by=triggered_by,
    )
    sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    db_session.expire_all()

    assert len(sends) == 1, (
        f"Expected exactly one digest email for {triggered_by} sync, "
        f"got {len(sends)}"
    )
    assert sends[0]["to"] == test_user.email
    assert "Critical" in sends[0]["subject"]

    alert_count = (
        db_session.query(Alert)
        .filter(Alert.integration_id == integration.id, Alert.channel == "email")
        .count()
    )
    assert alert_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# 10. Email-not-configured path — sync still succeeds; no Alert rows written
# ─────────────────────────────────────────────────────────────────────────────


def test_email_not_configured_skips_silently(
    db_session: Session,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When RESEND_API_KEY/ALERTS_FROM_EMAIL are missing, dispatch is a no-op.

    No email is sent and no Alert rows are written — leaving the door open
    for a future sync (after configuration is fixed) to retry the same
    changes.
    """
    from app.config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", None)
    monkeypatch.setattr(settings, "ALERTS_FROM_EMAIL", None)

    # send_email should never be called in this path, but patch it to a
    # raise so we'd notice if it were.
    monkeypatch.setattr(
        email_service,
        "send_email",
        lambda **_: (_ for _ in ()).throw(AssertionError("must not call send_email")),
    )

    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="critical")

    result = alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    assert result["sent"] == 0
    assert result["recorded"] == 0
    assert result["failed"] == 0

    assert (
        db_session.query(Alert)
        .filter(Alert.change_id == change.id)
        .count()
        == 0
    )


# ─────────────────────────────────────────────────────────────────────────────
# Recipient resolution — placeholder email is filtered out
# ─────────────────────────────────────────────────────────────────────────────


def test_placeholder_clerk_user_email_is_skipped(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An owner whose email ends in @clerk.user is not sent to."""
    from app.config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "test_resend_key")
    monkeypatch.setattr(settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.test")

    placeholder_user = User(
        clerk_id=f"m24_clerk_ph_{uuid.uuid4().hex[:6]}",
        email=f"user_{uuid.uuid4().hex[:8]}@clerk.user",
        display_name="Placeholder",
    )
    db_session.add(placeholder_user)
    db_session.commit()
    db_session.refresh(placeholder_user)

    try:
        monkeypatch.setattr(
            email_service,
            "send_email",
            lambda **_: (_ for _ in ()).throw(AssertionError("must not send")),
        )

        integration = _make_integration(db_session, placeholder_user)
        change = _make_change(db_session, integration, risk_level="critical")

        result = alert_service.dispatch_alerts_for_sync(
            changes=[change],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db_session,
        )
        db_session.commit()

        assert result["sent"] == 0
        # And no Alert rows — so a future sync (after the email is fixed)
        # can retry.
        assert (
            db_session.query(Alert)
            .filter(Alert.change_id == change.id)
            .count()
            == 0
        )
    finally:
        _cleanup_user_with_data(db_session, placeholder_user)


# ─────────────────────────────────────────────────────────────────────────────
# Body content sanity — link to /changes/<id> and key fields present
# ─────────────────────────────────────────────────────────────────────────────


def test_email_body_includes_change_deep_link(
    db_session: Session,
    test_user: User,
    email_recorder: list[dict[str, Any]],
) -> None:
    """Body contains the /changes/<id> URL using APP_BASE_URL."""
    from app.config import settings

    integration = _make_integration(db_session, test_user)
    change = _make_change(db_session, integration, risk_level="high")

    alert_service.dispatch_alerts_for_sync(
        changes=[change],
        integration=integration,
        sync_run_id=uuid.uuid4(),
        db=db_session,
    )
    db_session.commit()

    body = email_recorder[0]["body"]
    expected_link = f"{settings.APP_BASE_URL.rstrip('/')}/changes/{change.id}"
    assert expected_link in body
    assert integration.display_name in body
    assert change.record_identifier in body
    assert "Cloudflare DNS" in body
