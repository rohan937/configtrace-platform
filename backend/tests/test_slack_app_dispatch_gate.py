"""Regression tests for the Slack App real-alert dispatch gate.

The bug fixed by these tests:

    A workspace that installed the Slack App (`slack_app_enabled=True`)
    but never set up the legacy incoming-webhook (`slack_enabled=False`)
    was being early-returned by `dispatch_notifications_for_sync` before
    the Slack App branch could fire — producing
    `slack_sent=0 webhook_sent=0` in worker logs even though push and
    email worked.

These tests assert that:

  (1) The dispatcher reaches the Slack App branch when only Slack App is
      configured (no legacy webhook, no generic webhook).
  (2) `dispatch_alert_message` is called with the decrypted bot token and
      the configured channel ID.
  (3) `result["slack_sent"] == 1` after a successful dispatch.
  (4) Push dispatch still fires (no regression to the push path).
  (5) The function returns the push-only branch only when ALL of
      slack_app, legacy slack webhook, and generic webhook are inactive.

All tests are DB-free — `WorkspaceNotificationSettings` rows, sessions,
and provider-side calls are mocked.
"""

from __future__ import annotations

import uuid
from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest


# ── Fakes ────────────────────────────────────────────────────────────────────

class _FakeChange:
    """Stand-in for a Change ORM row. Carries every attribute the
    notification dispatcher reads (see notification_service.py)."""
    def __init__(
        self,
        change_id: uuid.UUID | None = None,
        risk_level: str = "high",
        integration_id: uuid.UUID | None = None,
    ):
        self.id                 = change_id or uuid.uuid4()
        self.risk_level         = risk_level
        self.integration_id     = integration_id or uuid.uuid4()
        self.change_type        = "modified"
        self.record_identifier  = "api.example.com (CNAME)"
        self.field_path         = "value"
        self.risk_reason        = "DNS record rerouted to a new destination."


def _fake_integration(workspace_id: uuid.UUID | None = None) -> MagicMock:
    i = MagicMock(name="Integration")
    i.workspace_id   = workspace_id or uuid.uuid4()
    i.display_name   = "Production Cloudflare"
    i.provider       = "cloudflare"
    return i


def _fake_settings_row(
    *,
    slack_app_enabled: bool,
    slack_bot_token_encrypted: bytes | None,
    slack_bot_iv: bytes | None,
    slack_channel_id: str | None,
    slack_enabled: bool = False,
    slack_webhook_url_encrypted: bytes | None = None,
    slack_webhook_iv: bytes | None = None,
    webhook_enabled: bool = False,
    webhook_url_encrypted: bytes | None = None,
    webhook_iv: bytes | None = None,
    notify_on_risk_level: str = "high_and_critical",
) -> MagicMock:
    row = MagicMock(name="WorkspaceNotificationSettings")
    row.slack_app_enabled            = slack_app_enabled
    row.slack_bot_token_encrypted    = slack_bot_token_encrypted
    row.slack_bot_iv                 = slack_bot_iv
    row.slack_channel_id             = slack_channel_id
    row.slack_enabled                = slack_enabled
    row.slack_webhook_url_encrypted  = slack_webhook_url_encrypted
    row.slack_webhook_iv             = slack_webhook_iv
    row.webhook_enabled              = webhook_enabled
    row.webhook_url_encrypted        = webhook_url_encrypted
    row.webhook_iv                   = webhook_iv
    row.notify_on_risk_level         = notify_on_risk_level
    row.slack_app_last_error         = None
    return row


def _mock_db_with_settings(settings_row: MagicMock | None) -> MagicMock:
    """Build a MagicMock SQLAlchemy session whose `.query(...).filter(...).first()`
    yields the given settings_row."""
    chain = MagicMock()
    chain.first.return_value = settings_row
    query = MagicMock()
    query.filter.return_value = chain
    db = MagicMock(name="Session")
    db.query.return_value = query
    db.flush  = MagicMock(return_value=None)
    db.commit = MagicMock(return_value=None)
    db.add    = MagicMock(return_value=None)
    return db


@pytest.fixture
def fake_settings_env(monkeypatch: pytest.MonkeyPatch):
    """app.config.settings needs APP_BASE_URL during dispatch."""
    from app import config
    monkeypatch.setattr(config.settings, "APP_BASE_URL", "https://app.example.test")
    yield


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — Slack App-only workspace reaches the Slack App branch
# ─────────────────────────────────────────────────────────────────────────────

def test_slack_app_only_workspace_dispatches_via_app(fake_settings_env):
    """The regression fix: when only `slack_app_enabled=True` (no legacy
    slack webhook, no generic webhook), the dispatcher must still send via
    the Slack App and report `slack_sent=1`."""
    from app.services import notification_service

    integration   = _fake_integration()
    settings_row  = _fake_settings_row(
        slack_app_enabled         = True,
        slack_bot_token_encrypted = b"\x01" * 32,  # opaque ciphertext bytes
        slack_bot_iv              = b"\x02" * 12,
        slack_channel_id          = "C0DEADBEEF",
        slack_enabled             = False,   # legacy webhook OFF
        webhook_enabled           = False,   # generic webhook OFF
    )
    db      = _mock_db_with_settings(settings_row)
    changes = [_FakeChange(risk_level="critical")]

    with patch(
        "app.services.slack_service._decrypt_token",
        return_value="xoxb-test-token-DO-NOT-LOG",
    ) as mock_decrypt, patch(
        "app.services.slack_service.dispatch_alert_message"
    ) as mock_dispatch, patch(
        "app.services.push_notification_service.dispatch_push_for_sync",
        return_value=0,
    ):
        result = notification_service.dispatch_notifications_for_sync(
            changes=changes,
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )

    # The Slack App branch must have been reached and dispatched.
    assert mock_dispatch.call_count == 1, (
        "dispatch_alert_message must be called exactly once when slack_app "
        "is the only configured channel; the early-return gate was bypassed."
    )
    kwargs = mock_dispatch.call_args.kwargs
    assert kwargs["channel_id"]  == "C0DEADBEEF"
    assert kwargs["bot_token"]   == "xoxb-test-token-DO-NOT-LOG"
    assert kwargs["provider"]    == "cloudflare"

    # And the result counter must reflect it.
    assert result["slack_sent"] == 1, (
        f"slack_sent must be 1 after a successful Slack App dispatch; got {result}"
    )
    assert result["failed"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — Push dispatch still runs alongside the Slack App branch
# ─────────────────────────────────────────────────────────────────────────────

def test_push_dispatch_still_runs_when_slack_app_only(fake_settings_env):
    """No push regression: even when only Slack App is configured, the
    main-branch push dispatch at the end of the function still fires."""
    from app.services import notification_service

    integration  = _fake_integration()
    settings_row = _fake_settings_row(
        slack_app_enabled         = True,
        slack_bot_token_encrypted = b"\x01" * 32,
        slack_bot_iv              = b"\x02" * 12,
        slack_channel_id          = "C0PUSHTEST",
    )
    db      = _mock_db_with_settings(settings_row)
    changes = [_FakeChange(risk_level="critical")]

    with patch(
        "app.services.slack_service._decrypt_token", return_value="xoxb-test"
    ), patch(
        "app.services.slack_service.dispatch_alert_message"
    ), patch(
        "app.services.push_notification_service.dispatch_push_for_sync",
        return_value=3,
    ) as mock_push:
        result = notification_service.dispatch_notifications_for_sync(
            changes=changes,
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )

    assert mock_push.call_count == 1, "Push dispatch must still run."
    assert result["push_sent"] == 3
    assert result["slack_sent"] == 1   # both succeeded


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — Slack App branch is skipped if its token is missing
# ─────────────────────────────────────────────────────────────────────────────

def test_slack_app_enabled_but_missing_token_does_not_attempt_dispatch(fake_settings_env):
    """Defence in depth: `slack_app_enabled=True` with no bot token is a
    half-configured state. The dispatcher must not blow up — it should
    fall through to the push-only branch."""
    from app.services import notification_service

    integration  = _fake_integration()
    settings_row = _fake_settings_row(
        slack_app_enabled         = True,
        slack_bot_token_encrypted = None,   # half-configured
        slack_bot_iv              = None,
        slack_channel_id          = None,
    )
    db      = _mock_db_with_settings(settings_row)
    changes = [_FakeChange(risk_level="critical")]

    with patch(
        "app.services.slack_service.dispatch_alert_message"
    ) as mock_dispatch, patch(
        "app.services.push_notification_service.dispatch_push_for_sync",
        return_value=1,
    ) as mock_push:
        result = notification_service.dispatch_notifications_for_sync(
            changes=changes,
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )

    assert mock_dispatch.call_count == 0
    assert result["slack_sent"] == 0
    # Push-only branch should still attempt push:
    assert mock_push.call_count == 1
    assert result["push_sent"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Push-only branch fires when NO non-push channel is configured
# ─────────────────────────────────────────────────────────────────────────────

def test_push_only_branch_when_no_channels_configured(fake_settings_env):
    """When all three of legacy slack, generic webhook, and Slack App are
    inactive, the dispatcher must take the push-only early-return branch
    (no Slack call attempted)."""
    from app.services import notification_service

    integration  = _fake_integration()
    settings_row = _fake_settings_row(
        slack_app_enabled         = False,
        slack_bot_token_encrypted = None,
        slack_bot_iv              = None,
        slack_channel_id          = None,
        slack_enabled             = False,
        webhook_enabled           = False,
    )
    db      = _mock_db_with_settings(settings_row)
    changes = [_FakeChange(risk_level="critical")]

    with patch(
        "app.services.slack_service.dispatch_alert_message"
    ) as mock_dispatch, patch(
        "app.services.push_notification_service.dispatch_push_for_sync",
        return_value=2,
    ) as mock_push:
        result = notification_service.dispatch_notifications_for_sync(
            changes=changes,
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )

    assert mock_dispatch.call_count == 0, "Slack App must not be called."
    assert result["slack_sent"] == 0
    # Push still fires in the push-only branch:
    assert mock_push.call_count == 1
    assert result["push_sent"] == 2


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — Legacy webhook fallback still works
# ─────────────────────────────────────────────────────────────────────────────

def test_legacy_slack_webhook_still_works_when_slack_app_off(fake_settings_env):
    """Backwards-compatibility: a workspace that uses the legacy incoming
    webhook (and never installed the Slack App) must continue to receive
    alerts."""
    from app.services import notification_service

    integration  = _fake_integration()
    settings_row = _fake_settings_row(
        slack_app_enabled            = False,
        slack_bot_token_encrypted    = None,
        slack_bot_iv                 = None,
        slack_channel_id             = None,
        slack_enabled                = True,
        slack_webhook_url_encrypted  = b"\xAA" * 32,
        slack_webhook_iv             = b"\xBB" * 12,
    )
    db      = _mock_db_with_settings(settings_row)
    changes = [_FakeChange(risk_level="critical")]

    with patch(
        "app.services.notification_service._decrypt_url",
        return_value="https://hooks.slack.test/services/legacy",
    ), patch(
        "app.services.notification_service._post_json"
    ) as mock_post, patch(
        "app.services.slack_service.dispatch_alert_message"
    ) as mock_app_dispatch, patch(
        "app.services.push_notification_service.dispatch_push_for_sync",
        return_value=0,
    ):
        result = notification_service.dispatch_notifications_for_sync(
            changes=changes,
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )

    # Legacy webhook path must have fired, Slack App path must not have.
    assert mock_post.call_count == 1
    assert mock_app_dispatch.call_count == 0
    assert result["slack_sent"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — No bot token / channel ID / URL gets logged
# ─────────────────────────────────────────────────────────────────────────────

def test_log_messages_do_not_contain_bot_token(fake_settings_env, caplog):
    """Diagnostic logs must NOT contain the decrypted bot token. We allow
    the channel ID (a public Slack identifier) but never the token."""
    import logging

    from app.services import notification_service

    integration  = _fake_integration()
    settings_row = _fake_settings_row(
        slack_app_enabled         = True,
        slack_bot_token_encrypted = b"\x01" * 32,
        slack_bot_iv              = b"\x02" * 12,
        slack_channel_id          = "C0DEADBEEF",
    )
    db      = _mock_db_with_settings(settings_row)
    changes = [_FakeChange(risk_level="critical")]

    secret_token = "xoxb-SECRET-NEVER-LOG-ME-1234567890"
    with patch(
        "app.services.slack_service._decrypt_token", return_value=secret_token
    ), patch(
        "app.services.slack_service.dispatch_alert_message"
    ), patch(
        "app.services.push_notification_service.dispatch_push_for_sync",
        return_value=0,
    ):
        with caplog.at_level(logging.DEBUG, logger="app.services.notification_service"):
            notification_service.dispatch_notifications_for_sync(
                changes=changes,
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )

    combined_logs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert secret_token not in combined_logs, (
        "The decrypted bot token must NEVER appear in log output."
    )
    # And no raw token-shaped string should leak:
    assert "xoxb-" not in combined_logs, (
        "Strings starting with 'xoxb-' (Slack bot token prefix) must not appear in logs."
    )
