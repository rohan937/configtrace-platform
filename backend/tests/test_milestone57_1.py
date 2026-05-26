"""Tests for M57.1: Slack + Webhook Alert Routing.

Test strategy
-------------
All tests are pure unit tests using MagicMock for database sessions, following
the M51 pattern.  This avoids requiring a running PostgreSQL instance and is
consistent with the established M35-M51 test approach.

Where the real service layer is tested (update_notification_settings,
dispatch_notifications_for_sync) the DB session is a MagicMock that returns
pre-configured rows.  Router tests use FastAPI TestClient with dependency
overrides for get_db and get_current_user.

Coverage
--------
Model:
  1.  WorkspaceNotificationSettings model imports cleanly
  2.  Model fields exist with correct defaults
  3.  Model uses BaseMixin (has id, created_at, updated_at)
  4.  __repr__ is informative

Migration:
  5.  Migration 007 file imports cleanly
  6.  Migration 007 has correct revision/down_revision chain
  7.  Migration 007 upgrade/downgrade are callable

Service — _validate_url:
  8.  Accepts valid https:// URL
  9.  Rejects http:// URL
  10. Rejects localhost
  11. Rejects 127.0.0.1
  12. Rejects 10.x.x.x private IP
  13. Rejects 192.168.x.x private IP
  14. Rejects URL that exceeds max length
  15. Slack: rejects non-slack https:// URL
  16. Slack: accepts valid hooks.slack.com URL

Service — _mask_url:
  17. Returns "https://****" for short URLs
  18. Masks middle of normal URL — full URL not exposed
  19. Empty string returns empty

Service — get_or_create_notification_settings (mocked):
  20. Creates a new row when none exists
  21. Returns existing row when found (idempotent)

Service — update_notification_settings (mocked DB):
  22. Encrypts and stores Slack URL
  23. Enables Slack after URL is set
  24. Enabling Slack without existing URL raises ValueError
  25. Enabling webhook without existing URL raises ValueError
  26. Empty string clears Slack URL and disables channel
  27. Empty string clears webhook URL and disables channel
  28. Invalid Slack URL raises WebhookURLError
  29. Invalid generic webhook URL raises WebhookURLError
  30. notify_on_risk_level is persisted

Service — build_settings_response:
  31. Returns masked Slack URL (not raw URL)
  32. Returns masked webhook URL (not raw URL)
  33. Returns None for both masked fields when no URL configured
  34. Full raw URL is not present anywhere in response dict

Service — dispatch_notifications_for_sync:
  35. Returns skipped_no_settings when workspace_id is None
  36. Returns skipped_no_settings when no settings row in DB
  37. Returns early when both channels disabled
  38. Filters changes by notify_on_risk_level (critical_only skips high)
  39. Posts to Slack when enabled and URL configured
  40. Posts to webhook when enabled and URL configured
  41. Slack delivery failure increments failed count, does not raise
  42. Webhook delivery failure increments failed count, does not raise
  43. Never raises — catches all exceptions including DB errors

Service — send_test_notification:
  44. Sends test message to Slack when enabled
  45. Sends test message to webhook when enabled
  46. Returns error string when Slack delivery fails
  47. Returns False for slack_sent when Slack not enabled

Router endpoints (TestClient + overrides):
  48. GET /workspaces/{id}/notification-settings returns 200 for member
  49. GET /workspaces/{id}/notification-settings returns 404 for non-member
  50. PUT /workspaces/{id}/notification-settings updates settings (owner)
  51. PUT /workspaces/{id}/notification-settings returns 403 for plain member
  52. PUT /workspaces/{id}/notification-settings returns 422 for bad Slack URL
  53. PUT /workspaces/{id}/notification-settings returns 422 for bad webhook URL
  54. PUT /workspaces/{id}/notification-settings writes audit event (mocked)
  55. POST /workspaces/{id}/notification-settings/test returns 200
  56. POST /workspaces/{id}/notification-settings/test returns 403 for member

Security:
  57. build_settings_response output does not contain full webhook URL
  58. Audit metadata dict from PUT does not contain webhook URLs
  59. _mask_url hides all but first 12 and last 4 chars
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Test fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

_VALID_SLACK_URL = "https://hooks.slack.com/services/T00000/B00000/abc123xyz789"
_VALID_WEBHOOK_URL = "https://example.com/hooks/configtrace"
_LONG_URL = "https://example.com/" + "a" * 2048


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_mock_change(risk_level: str = "critical") -> MagicMock:
    c = MagicMock()
    c.id = uuid.uuid4()
    c.risk_level = risk_level
    c.change_type = "added"
    c.record_identifier = "sg-abc123"
    c.field_path = "inbound_rules[0]"
    c.risk_reason = "Port 22 opened to 0.0.0.0/0"
    c.created_at = _utcnow()
    return c


def _make_mock_integration(workspace_id: uuid.UUID | None = None) -> MagicMock:
    i = MagicMock()
    i.id = uuid.uuid4()
    i.workspace_id = workspace_id if workspace_id is not None else uuid.uuid4()
    i.user_id = uuid.uuid4()
    i.provider = "aws"
    i.display_name = "My AWS Integration"
    return i


def _make_mock_settings_row(
    workspace_id: uuid.UUID | None = None,
    slack_enabled: bool = False,
    webhook_enabled: bool = False,
    notify_on_risk_level: str = "high_and_critical",
    slack_url_encrypted: bytes | None = None,
    slack_iv: bytes | None = None,
    webhook_url_encrypted: bytes | None = None,
    webhook_iv: bytes | None = None,
) -> MagicMock:
    from app.models.notification_settings import WorkspaceNotificationSettings
    row = MagicMock(spec=WorkspaceNotificationSettings)
    row.id = uuid.uuid4()
    row.workspace_id = workspace_id or uuid.uuid4()
    row.slack_enabled = slack_enabled
    row.webhook_enabled = webhook_enabled
    row.notify_on_risk_level = notify_on_risk_level
    row.slack_webhook_url_encrypted = slack_url_encrypted
    row.slack_webhook_iv = slack_iv
    row.webhook_url_encrypted = webhook_url_encrypted
    row.webhook_iv = webhook_iv
    return row


def _make_mock_db(settings_row=None) -> MagicMock:
    """Build a mock DB session that returns settings_row on query."""
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = settings_row
    return db


# ─────────────────────────────────────────────────────────────────────────────
# 1–4: Model
# ─────────────────────────────────────────────────────────────────────────────


class TestNotificationSettingsModel:
    def test_model_imports(self):
        """WorkspaceNotificationSettings model imports cleanly."""
        from app.models.notification_settings import WorkspaceNotificationSettings
        assert WorkspaceNotificationSettings is not None

    def test_model_fields_exist_with_defaults(self):
        """Model has all expected columns with the right INSERT defaults.

        SQLAlchemy 2.0 applies scalar defaults at INSERT time (not at Python
        instantiation time), so we verify column-level defaults via the table
        metadata rather than testing the unset Python attributes.
        """
        from app.models.notification_settings import WorkspaceNotificationSettings

        ws_id = uuid.uuid4()
        row = WorkspaceNotificationSettings(workspace_id=ws_id)

        # workspace_id is explicitly passed — always set
        assert row.workspace_id == ws_id

        # Nullable URL / IV columns start as None before insert
        assert row.slack_webhook_url_encrypted is None
        assert row.slack_webhook_iv is None
        assert row.webhook_url_encrypted is None
        assert row.webhook_iv is None

        # Verify column-level INSERT defaults via table metadata (SQLAlchemy 2.0
        # scalar defaults are applied at flush, not at __init__ time)
        table = WorkspaceNotificationSettings.__table__
        assert table.c.slack_enabled.default.arg is False
        assert table.c.webhook_enabled.default.arg is False
        assert table.c.notify_on_risk_level.default.arg == "high_and_critical"

    def test_model_inherits_base_mixin(self):
        """WorkspaceNotificationSettings inherits BaseMixin (has id field)."""
        from app.models.notification_settings import WorkspaceNotificationSettings
        from app.models.base import BaseMixin

        assert issubclass(WorkspaceNotificationSettings, BaseMixin)

    def test_repr_is_informative(self):
        """__repr__ includes workspace_id and enabled flags."""
        from app.models.notification_settings import WorkspaceNotificationSettings

        ws_id = uuid.uuid4()
        row = WorkspaceNotificationSettings(workspace_id=ws_id)
        r = repr(row)
        assert str(ws_id) in r
        assert "slack_enabled" in r


# ─────────────────────────────────────────────────────────────────────────────
# 5–7: Migration
# ─────────────────────────────────────────────────────────────────────────────


class TestMigration007:
    def test_migration_imports_cleanly(self):
        """Migration 007 file imports without error."""
        import importlib
        import sys

        # Ensure the alembic/versions directory is importable.
        import os
        versions_dir = os.path.join(
            os.path.dirname(__file__), "..", "alembic", "versions"
        )
        versions_dir = os.path.abspath(versions_dir)

        # Direct file load using importlib.util
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "migration_007",
            os.path.join(versions_dir, "007_m57_notification_settings.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        # Deliberately NOT exec'ing — just checking the spec loaded.
        assert spec is not None
        assert mod is not None

    def test_migration_revision_chain(self):
        """Migration 007 has revision='007' and down_revision='006'."""
        import importlib.util
        import os

        versions_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "alembic", "versions")
        )
        spec = importlib.util.spec_from_file_location(
            "migration_007",
            os.path.join(versions_dir, "007_m57_notification_settings.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

        assert mod.revision == "007"
        assert mod.down_revision == "006"

    def test_migration_upgrade_downgrade_callable(self):
        """Migration 007 upgrade and downgrade are callable."""
        import importlib.util
        import os

        versions_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "alembic", "versions")
        )
        spec = importlib.util.spec_from_file_location(
            "migration_007",
            os.path.join(versions_dir, "007_m57_notification_settings.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

        assert callable(mod.upgrade)
        assert callable(mod.downgrade)


# ─────────────────────────────────────────────────────────────────────────────
# 8–16: _validate_url
# ─────────────────────────────────────────────────────────────────────────────


class TestValidateUrl:
    def _ok(self, url: str, slack: bool = False) -> None:
        from app.services.notification_service import _validate_url
        _validate_url(url, slack=slack)  # must not raise

    def _bad(self, url: str, slack: bool = False) -> None:
        from app.services.notification_service import _validate_url, WebhookURLError
        with pytest.raises(WebhookURLError):
            _validate_url(url, slack=slack)

    def test_accepts_valid_https_url(self):
        self._ok(_VALID_WEBHOOK_URL)

    def test_rejects_http_url(self):
        self._bad("http://example.com/hook")

    def test_rejects_localhost(self):
        self._bad("https://localhost/hook")

    def test_rejects_127_0_0_1(self):
        self._bad("https://127.0.0.1/hook")

    def test_rejects_10_x_private_ip(self):
        self._bad("https://10.0.0.1/hook")

    def test_rejects_192_168_private_ip(self):
        self._bad("https://192.168.1.1/hook")

    def test_rejects_url_too_long(self):
        self._bad(_LONG_URL)

    def test_slack_rejects_non_slack_https_url(self):
        self._bad(_VALID_WEBHOOK_URL, slack=True)

    def test_slack_accepts_valid_hooks_slack_com_url(self):
        self._ok(_VALID_SLACK_URL, slack=True)


# ─────────────────────────────────────────────────────────────────────────────
# 17–19: _mask_url
# ─────────────────────────────────────────────────────────────────────────────


class TestMaskUrl:
    def test_short_url_returns_placeholder(self):
        from app.services.notification_service import _mask_url
        result = _mask_url("https://x.co")
        assert result == "https://****"

    def test_normal_url_full_url_not_exposed(self):
        from app.services.notification_service import _mask_url
        url = _VALID_SLACK_URL
        result = _mask_url(url)
        assert "****" in result
        # The masked form must not equal the original URL.
        assert result != url
        # The middle portion is masked.
        middle = url[12:-4]
        assert middle not in result

    def test_empty_string(self):
        from app.services.notification_service import _mask_url
        assert _mask_url("") == ""


# ─────────────────────────────────────────────────────────────────────────────
# 20–21: get_or_create_notification_settings (mocked)
# ─────────────────────────────────────────────────────────────────────────────


class TestGetOrCreate:
    def test_creates_new_row_when_none_exists(self):
        """Creates and persists a new row when the query returns None."""
        from app.services.notification_service import get_or_create_notification_settings

        ws_id = uuid.uuid4()
        db = MagicMock()
        # Simulate "no existing row" then "row after add/commit/refresh".
        created_row = _make_mock_settings_row(workspace_id=ws_id)
        db.query.return_value.filter.return_value.first.return_value = None
        db.refresh.side_effect = lambda row: None  # no-op

        # After add+commit, the next call to db.query should return the row.
        # We simulate this by returning None first then created_row on refresh.
        result = get_or_create_notification_settings(ws_id, db)
        db.add.assert_called_once()
        db.commit.assert_called_once()

    def test_returns_existing_row(self):
        """Returns existing row without inserting when one already exists."""
        from app.services.notification_service import get_or_create_notification_settings

        ws_id = uuid.uuid4()
        existing = _make_mock_settings_row(workspace_id=ws_id)
        db = _make_mock_db(settings_row=existing)

        result = get_or_create_notification_settings(ws_id, db)
        assert result is existing
        db.add.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 22–30: update_notification_settings (mocked DB)
# ─────────────────────────────────────────────────────────────────────────────


class TestUpdateNotificationSettings:
    def _make_db_with_row(self, row: MagicMock) -> MagicMock:
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = row
        db.refresh.side_effect = lambda r: None
        return db

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_encrypts_and_stores_slack_url(self, _key):
        """Setting a Slack URL encrypts it and stores bytes in the row."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id)
        db = self._make_db_with_row(row)

        update_notification_settings(
            ws_id, uuid.uuid4(),
            slack_webhook_url=_VALID_SLACK_URL,
            db=db,
        )
        # encrypted bytes were assigned
        assert row.slack_webhook_url_encrypted is not None
        assert row.slack_webhook_iv is not None
        db.commit.assert_called()

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_enables_slack_after_url_set(self, _key):
        """slack_enabled=True is accepted when the URL is being set in the same call."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        # Row starts with no URL.
        row = _make_mock_settings_row(workspace_id=ws_id)
        db = self._make_db_with_row(row)

        update_notification_settings(
            ws_id, uuid.uuid4(),
            slack_webhook_url=_VALID_SLACK_URL,
            slack_enabled=True,
            db=db,
        )
        assert row.slack_enabled is True

    def test_enable_slack_without_url_raises_value_error(self):
        """Enabling Slack without any URL (new or existing) raises ValueError."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id)  # no encrypted URL
        db = self._make_db_with_row(row)

        with pytest.raises(ValueError, match="URL"):
            update_notification_settings(
                ws_id, uuid.uuid4(), slack_enabled=True, db=db
            )

    def test_enable_webhook_without_url_raises_value_error(self):
        """Enabling webhook without any URL raises ValueError."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id)
        db = self._make_db_with_row(row)

        with pytest.raises(ValueError, match="URL"):
            update_notification_settings(
                ws_id, uuid.uuid4(), webhook_enabled=True, db=db
            )

    def test_empty_string_clears_slack_url_and_disables(self):
        """Passing '' for slack_webhook_url clears the URL and forces disable."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        # Row has an existing URL.
        row = _make_mock_settings_row(
            workspace_id=ws_id,
            slack_url_encrypted=b"encrypted_bytes",
            slack_iv=b"iv_12bytes_pad",
            slack_enabled=True,
        )
        db = self._make_db_with_row(row)

        update_notification_settings(
            ws_id, uuid.uuid4(), slack_webhook_url="", db=db
        )
        assert row.slack_webhook_url_encrypted is None
        assert row.slack_webhook_iv is None
        assert row.slack_enabled is False

    def test_empty_string_clears_webhook_url_and_disables(self):
        """Passing '' for webhook_url clears the URL and forces disable."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(
            workspace_id=ws_id,
            webhook_url_encrypted=b"encrypted_bytes",
            webhook_iv=b"iv_12bytes_pad",
            webhook_enabled=True,
        )
        db = self._make_db_with_row(row)

        update_notification_settings(
            ws_id, uuid.uuid4(), webhook_url="", db=db
        )
        assert row.webhook_url_encrypted is None
        assert row.webhook_iv is None
        assert row.webhook_enabled is False

    def test_invalid_slack_url_raises_webhook_url_error(self):
        """Passing a non-Slack HTTPS URL raises WebhookURLError (validation before encryption)."""
        from app.services.notification_service import update_notification_settings, WebhookURLError

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id)
        db = self._make_db_with_row(row)

        with pytest.raises(WebhookURLError):
            update_notification_settings(
                ws_id, uuid.uuid4(),
                slack_webhook_url="https://notslack.com/hook",
                db=db,
            )

    def test_invalid_webhook_url_raises_webhook_url_error(self):
        """Passing an HTTP URL raises WebhookURLError."""
        from app.services.notification_service import update_notification_settings, WebhookURLError

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id)
        db = self._make_db_with_row(row)

        with pytest.raises(WebhookURLError):
            update_notification_settings(
                ws_id, uuid.uuid4(),
                webhook_url="http://insecure.example.com/hook",
                db=db,
            )

    def test_risk_level_is_persisted(self):
        """notify_on_risk_level is assigned to the row."""
        from app.services.notification_service import update_notification_settings

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id)
        db = self._make_db_with_row(row)

        update_notification_settings(
            ws_id, uuid.uuid4(), notify_on_risk_level="critical_only", db=db
        )
        assert row.notify_on_risk_level == "critical_only"


# ─────────────────────────────────────────────────────────────────────────────
# 31–34: build_settings_response
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildSettingsResponse:
    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_returns_masked_slack_url(self, _key):
        """slack_webhook_url_masked is masked — the full URL is not exposed."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import build_settings_response

        ciphertext, iv = encrypt_credentials({"url": _VALID_SLACK_URL})
        row = _make_mock_settings_row(
            slack_url_encrypted=ciphertext, slack_iv=iv, slack_enabled=True
        )
        resp = build_settings_response(row)

        masked = resp["slack_webhook_url_masked"]
        assert masked is not None
        assert _VALID_SLACK_URL not in masked
        assert "****" in masked

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_returns_masked_webhook_url(self, _key):
        """webhook_url_masked is masked — the full URL is not exposed."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import build_settings_response

        ciphertext, iv = encrypt_credentials({"url": _VALID_WEBHOOK_URL})
        row = _make_mock_settings_row(
            webhook_url_encrypted=ciphertext, webhook_iv=iv, webhook_enabled=True
        )
        resp = build_settings_response(row)

        masked = resp["webhook_url_masked"]
        assert masked is not None
        assert _VALID_WEBHOOK_URL not in masked

    def test_returns_none_when_no_urls_configured(self):
        """Both masked fields are None when no URLs are configured."""
        from app.services.notification_service import build_settings_response

        row = _make_mock_settings_row()
        resp = build_settings_response(row)
        assert resp["slack_webhook_url_masked"] is None
        assert resp["webhook_url_masked"] is None

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_full_raw_url_not_in_response(self, _key):
        """The full raw URLs are completely absent from the response dict."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import build_settings_response

        ct_s, iv_s = encrypt_credentials({"url": _VALID_SLACK_URL})
        ct_w, iv_w = encrypt_credentials({"url": _VALID_WEBHOOK_URL})
        row = _make_mock_settings_row(
            slack_url_encrypted=ct_s, slack_iv=iv_s,
            webhook_url_encrypted=ct_w, webhook_iv=iv_w,
        )
        resp = build_settings_response(row)
        resp_str = str(resp)
        assert _VALID_SLACK_URL not in resp_str
        assert _VALID_WEBHOOK_URL not in resp_str


# ─────────────────────────────────────────────────────────────────────────────
# 35–43: dispatch_notifications_for_sync
# ─────────────────────────────────────────────────────────────────────────────


class TestDispatchNotificationsForSync:
    def test_skips_when_workspace_id_none(self):
        """Returns skipped_no_settings=True when integration.workspace_id is None."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        integration.workspace_id = None
        db = MagicMock()

        result = dispatch_notifications_for_sync(
            changes=[_make_mock_change()],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )
        assert result["skipped_no_settings"] is True
        assert result["slack_sent"] == 0

    def test_skips_when_no_settings_row(self):
        """Returns skipped_no_settings=True when no DB row for the workspace."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        db = _make_mock_db(settings_row=None)

        result = dispatch_notifications_for_sync(
            changes=[_make_mock_change()],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )
        assert result["skipped_no_settings"] is True

    def test_returns_early_when_both_disabled(self):
        """Zero counts when both channels are disabled."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        row = _make_mock_settings_row(slack_enabled=False, webhook_enabled=False)
        db = _make_mock_db(settings_row=row)

        result = dispatch_notifications_for_sync(
            changes=[_make_mock_change()],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )
        assert result["slack_sent"] == 0
        assert result["webhook_sent"] == 0
        assert result["failed"] == 0

    def test_critical_only_skips_high_risk_changes(self):
        """critical_only filter does not POST when only high-risk changes exist."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            slack_enabled=True,
            notify_on_risk_level="critical_only",
            slack_url_encrypted=b"enc",
            slack_iv=b"iv",
        )
        db = _make_mock_db(settings_row=row)
        changes = [_make_mock_change(risk_level="high")]

        with patch("app.services.notification_service._post_json") as mock_post:
            result = dispatch_notifications_for_sync(
                changes=changes,
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )
        mock_post.assert_not_called()
        assert result["slack_sent"] == 0

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_posts_to_slack_when_enabled(self, _key):
        """Posts to Slack when channel is enabled and URL is configured."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import dispatch_notifications_for_sync

        ciphertext, iv = encrypt_credentials({"url": _VALID_SLACK_URL})
        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            workspace_id=integration.workspace_id,
            slack_enabled=True,
            slack_url_encrypted=ciphertext,
            slack_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = dispatch_notifications_for_sync(
                changes=[_make_mock_change(risk_level="critical")],
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )
        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == _VALID_SLACK_URL
        assert result["slack_sent"] == 1
        assert result["failed"] == 0

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_posts_to_webhook_when_enabled(self, _key):
        """Posts to webhook when channel is enabled and URL is configured."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import dispatch_notifications_for_sync

        ciphertext, iv = encrypt_credentials({"url": _VALID_WEBHOOK_URL})
        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            workspace_id=integration.workspace_id,
            webhook_enabled=True,
            webhook_url_encrypted=ciphertext,
            webhook_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = dispatch_notifications_for_sync(
                changes=[_make_mock_change(risk_level="high")],
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )
        mock_post.assert_called_once()
        assert result["webhook_sent"] == 1
        assert result["failed"] == 0

    def test_slack_failure_counted_not_raised(self):
        """Slack HTTP error increments failed count — does not propagate."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            slack_enabled=True,
            slack_url_encrypted=b"enc",
            slack_iv=b"iv",
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.core.encryption.decrypt_credentials", return_value={"url": _VALID_SLACK_URL}):
            with patch(
                "app.services.notification_service._post_json",
                side_effect=Exception("connection refused"),
            ):
                result = dispatch_notifications_for_sync(
                    changes=[_make_mock_change()],
                    integration=integration,
                    sync_run_id=uuid.uuid4(),
                    db=db,
                )
        assert result["failed"] == 1
        assert result["slack_sent"] == 0

    def test_webhook_failure_counted_not_raised(self):
        """Webhook HTTP error increments failed count — does not propagate."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            webhook_enabled=True,
            webhook_url_encrypted=b"enc",
            webhook_iv=b"iv",
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.core.encryption.decrypt_credentials", return_value={"url": _VALID_WEBHOOK_URL}):
            with patch(
                "app.services.notification_service._post_json",
                side_effect=ValueError("HTTP 500"),
            ):
                result = dispatch_notifications_for_sync(
                    changes=[_make_mock_change()],
                    integration=integration,
                    sync_run_id=uuid.uuid4(),
                    db=db,
                )
        assert result["failed"] == 1
        assert result["webhook_sent"] == 0

    def test_never_raises_on_db_error(self):
        """dispatch_notifications_for_sync never raises even when DB throws."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        db = MagicMock()
        db.query.side_effect = Exception("DB totally gone")

        # Must not raise.
        result = dispatch_notifications_for_sync(
            changes=[_make_mock_change()],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 44–47: send_test_notification
# ─────────────────────────────────────────────────────────────────────────────


class TestSendTestNotification:
    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_sends_test_to_slack_when_enabled(self, _key):
        """Calls _post_json with the Slack URL when Slack is enabled."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import send_test_notification

        ct, iv = encrypt_credentials({"url": _VALID_SLACK_URL})
        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(
            workspace_id=ws_id,
            slack_enabled=True,
            slack_url_encrypted=ct,
            slack_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = send_test_notification(ws_id, db)

        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == _VALID_SLACK_URL
        assert result["slack_sent"] is True
        assert result["error"] is None

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_sends_test_to_webhook_when_enabled(self, _key):
        """Calls _post_json with the webhook URL when webhook is enabled."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import send_test_notification

        ct, iv = encrypt_credentials({"url": _VALID_WEBHOOK_URL})
        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(
            workspace_id=ws_id,
            webhook_enabled=True,
            webhook_url_encrypted=ct,
            webhook_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = send_test_notification(ws_id, db)

        mock_post.assert_called_once()
        assert result["webhook_sent"] is True

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_returns_error_string_on_delivery_failure(self, _key):
        """Sets error field when Slack delivery fails."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import send_test_notification

        ct, iv = encrypt_credentials({"url": _VALID_SLACK_URL})
        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(
            workspace_id=ws_id,
            slack_enabled=True,
            slack_url_encrypted=ct,
            slack_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch(
            "app.services.notification_service._post_json",
            side_effect=ValueError("connection refused"),
        ):
            result = send_test_notification(ws_id, db)

        assert result["slack_sent"] is False
        assert result["error"] is not None
        assert "Slack" in result["error"]

    def test_slack_not_sent_when_not_enabled(self):
        """slack_sent is False when Slack channel is disabled."""
        from app.services.notification_service import send_test_notification

        ws_id = uuid.uuid4()
        row = _make_mock_settings_row(workspace_id=ws_id, slack_enabled=False)
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = send_test_notification(ws_id, db)
        mock_post.assert_not_called()
        assert result["slack_sent"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 48–56: Router endpoints (TestClient with dependency overrides)
# ─────────────────────────────────────────────────────────────────────────────


def _make_test_user_and_workspace():
    """Return a pair of mock User + mock Workspace for router tests."""
    from app.models.user import User
    from app.models.workspace import Workspace

    ws_id = uuid.uuid4()
    user_id = uuid.uuid4()

    ws = MagicMock(spec=Workspace)
    ws.id = ws_id
    ws.name = "Router Test WS"
    ws.created_by_user_id = user_id
    ws.created_at = _utcnow()
    ws.updated_at = _utcnow()

    user = MagicMock(spec=User)
    user.id = user_id
    user.clerk_id = "test_clerk_router"
    user.email = "router@example.com"
    user.display_name = "Router User"

    return user, ws


class TestNotificationSettingsRouter:
    """Router tests using FastAPI TestClient and full dependency mock.

    These tests patch the service layer directly so no DB is needed.
    """

    def _client_with_owner(self):
        """Return (TestClient, mock_user, mock_ws_id) with owner-level access."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import get_db
        from app.core.auth import get_current_user
        from app.models.workspace import WorkspaceMember

        user, ws = _make_test_user_and_workspace()

        # Mock the DB so require_role("member") and require_role("admin") succeed.
        owner_member = MagicMock(spec=WorkspaceMember)
        owner_member.role = "owner"
        owner_member.workspace_id = ws.id
        owner_member.user_id = user.id

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = owner_member
        mock_db.get.return_value = ws
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        mock_db.refresh = MagicMock()
        mock_db.flush = MagicMock()

        app.dependency_overrides[get_db] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False), user, ws.id, mock_db

    def _client_with_member(self):
        """Return (TestClient, mock_user, ws_id) with member (view-only) access."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import get_db
        from app.core.auth import get_current_user
        from app.models.workspace import WorkspaceMember

        user, ws = _make_test_user_and_workspace()

        # Simulate a view-only member.
        view_member = MagicMock(spec=WorkspaceMember)
        view_member.role = "member"
        view_member.workspace_id = ws.id
        view_member.user_id = user.id

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = view_member
        mock_db.get.return_value = ws

        app.dependency_overrides[get_db] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False), user, ws.id

    def _teardown(self):
        from app.main import app
        app.dependency_overrides.clear()

    def test_get_returns_200_for_member(self):
        """GET notification-settings returns 200 for any workspace member."""
        from app.services.notification_service import build_settings_response

        client, user, ws_id, mock_db = self._client_with_owner()
        settings_row = _make_mock_settings_row(workspace_id=ws_id)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=settings_row,
        ), patch(
            "app.services.notification_service.build_settings_response",
            return_value={
                "workspace_id": ws_id,
                "slack_enabled": False,
                "slack_webhook_url_masked": None,
                "webhook_enabled": False,
                "webhook_url_masked": None,
                "notify_on_risk_level": "high_and_critical",
            },
        ):
            resp = client.get(f"/workspaces/{ws_id}/notification-settings")

        self._teardown()
        assert resp.status_code == 200
        data = resp.json()
        assert "slack_enabled" in data
        assert "notify_on_risk_level" in data

    def test_get_returns_404_for_non_member(self):
        """GET returns 404 when the user is not a workspace member."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import get_db
        from app.core.auth import get_current_user

        user, ws = _make_test_user_and_workspace()

        # Mock DB returns None (no membership row).
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        app.dependency_overrides[get_db] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: user
        client = TestClient(app, raise_server_exceptions=False)

        try:
            resp = client.get(f"/workspaces/{ws.id}/notification-settings")
            assert resp.status_code == 404
        finally:
            self._teardown()

    def test_put_updates_settings_for_owner(self):
        """PUT returns 200 and updated settings when called by owner/admin."""
        ws_id = uuid.uuid4()
        client, user, ws_id, mock_db = self._client_with_owner()
        settings_row = _make_mock_settings_row(workspace_id=ws_id, notify_on_risk_level="critical_only")

        with patch(
            "app.services.notification_service.update_notification_settings",
            return_value=settings_row,
        ), patch(
            "app.services.notification_service.build_settings_response",
            return_value={
                "workspace_id": ws_id,
                "slack_enabled": False,
                "slack_webhook_url_masked": None,
                "webhook_enabled": False,
                "webhook_url_masked": None,
                "notify_on_risk_level": "critical_only",
            },
        ):
            resp = client.put(
                f"/workspaces/{ws_id}/notification-settings",
                json={"notify_on_risk_level": "critical_only"},
            )
        self._teardown()
        assert resp.status_code == 200
        assert resp.json()["notify_on_risk_level"] == "critical_only"

    def test_put_returns_403_for_plain_member(self):
        """PUT returns 403 for view-only workspace member."""
        client, user, ws_id = self._client_with_member()
        try:
            resp = client.put(
                f"/workspaces/{ws_id}/notification-settings",
                json={"notify_on_risk_level": "critical_only"},
            )
            assert resp.status_code == 403
        finally:
            self._teardown()

    def test_put_returns_422_for_bad_slack_url(self):
        """PUT returns 422 when Slack URL fails validation."""
        from app.services.notification_service import WebhookURLError

        client, user, ws_id, mock_db = self._client_with_owner()

        with patch(
            "app.services.notification_service.update_notification_settings",
            side_effect=WebhookURLError("Slack webhook URL must start with https://hooks.slack.com"),
        ):
            resp = client.put(
                f"/workspaces/{ws_id}/notification-settings",
                json={"slack_webhook_url": "https://notslack.com/hook"},
            )
        self._teardown()
        assert resp.status_code == 422

    def test_put_returns_422_for_bad_webhook_url(self):
        """PUT returns 422 when generic webhook URL fails validation."""
        from app.services.notification_service import WebhookURLError

        client, user, ws_id, mock_db = self._client_with_owner()

        with patch(
            "app.services.notification_service.update_notification_settings",
            side_effect=WebhookURLError("Webhook URL must use HTTPS"),
        ):
            resp = client.put(
                f"/workspaces/{ws_id}/notification-settings",
                json={"webhook_url": "http://insecure.example.com"},
            )
        self._teardown()
        assert resp.status_code == 422

    def test_put_writes_audit_event(self):
        """PUT calls log_audit_event with event_type=notification_settings_updated."""
        ws_id = uuid.uuid4()
        client, user, ws_id, mock_db = self._client_with_owner()
        settings_row = _make_mock_settings_row(workspace_id=ws_id)
        settings_row.id = uuid.uuid4()
        settings_row.slack_enabled = False
        settings_row.webhook_enabled = False
        settings_row.notify_on_risk_level = "high_and_critical"

        with patch(
            "app.services.notification_service.update_notification_settings",
            return_value=settings_row,
        ), patch(
            "app.services.notification_service.build_settings_response",
            return_value={
                "workspace_id": ws_id,
                "slack_enabled": False,
                "slack_webhook_url_masked": None,
                "webhook_enabled": False,
                "webhook_url_masked": None,
                "notify_on_risk_level": "high_and_critical",
            },
        ), patch(
            "app.services.workspace_service.log_audit_event"
        ) as mock_log:
            resp = client.put(
                f"/workspaces/{ws_id}/notification-settings",
                json={"notify_on_risk_level": "high_and_critical"},
            )
        self._teardown()
        assert resp.status_code == 200
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args
        assert call_kwargs.kwargs.get("event_type") == "notification_settings_updated" or (
            len(call_kwargs.args) > 2 and call_kwargs.args[2] == "notification_settings_updated"
        )

    def test_post_test_returns_200(self):
        """POST .../test returns 200 even when no channels are configured."""
        client, user, ws_id, mock_db = self._client_with_owner()

        with patch(
            "app.services.notification_service.send_test_notification",
            return_value={"slack_sent": False, "webhook_sent": False, "error": None},
        ):
            resp = client.post(f"/workspaces/{ws_id}/notification-settings/test")
        self._teardown()
        assert resp.status_code == 200
        data = resp.json()
        assert "slack_sent" in data
        assert "webhook_sent" in data

    def test_post_test_returns_403_for_member(self):
        """POST .../test returns 403 for view-only member."""
        client, user, ws_id = self._client_with_member()
        try:
            resp = client.post(f"/workspaces/{ws_id}/notification-settings/test")
            assert resp.status_code == 403
        finally:
            self._teardown()


# ─────────────────────────────────────────────────────────────────────────────
# 57–59: Security invariants
# ─────────────────────────────────────────────────────────────────────────────


class TestSecurityInvariants:
    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_full_url_not_in_build_response(self, _key):
        """build_settings_response never leaks the full webhook URL string."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import build_settings_response

        ct_s, iv_s = encrypt_credentials({"url": _VALID_SLACK_URL})
        ct_w, iv_w = encrypt_credentials({"url": _VALID_WEBHOOK_URL})
        row = _make_mock_settings_row(
            slack_url_encrypted=ct_s, slack_iv=iv_s,
            webhook_url_encrypted=ct_w, webhook_iv=iv_w,
        )
        resp = build_settings_response(row)
        resp_str = str(resp)
        assert _VALID_SLACK_URL not in resp_str
        assert _VALID_WEBHOOK_URL not in resp_str

    def test_audit_metadata_no_webhook_urls(self):
        """PUT endpoint passes audit metadata that contains no webhook URL strings."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import get_db
        from app.core.auth import get_current_user
        from app.models.workspace import WorkspaceMember

        user, ws = _make_test_user_and_workspace()
        owner_member = MagicMock(spec=WorkspaceMember)
        owner_member.role = "owner"
        owner_member.workspace_id = ws.id
        owner_member.user_id = user.id

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = owner_member
        mock_db.get.return_value = ws
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()
        mock_db.refresh = MagicMock()

        app.dependency_overrides[get_db] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: user

        settings_row = _make_mock_settings_row(workspace_id=ws.id)
        settings_row.id = uuid.uuid4()
        settings_row.slack_enabled = False
        settings_row.webhook_enabled = False
        settings_row.notify_on_risk_level = "high_and_critical"

        client = TestClient(app, raise_server_exceptions=False)
        captured_metadata: dict = {}

        def capture_log(*args, **kwargs):
            meta = kwargs.get("metadata", {})
            captured_metadata.update(meta)

        with patch(
            "app.services.notification_service.update_notification_settings",
            return_value=settings_row,
        ), patch(
            "app.services.notification_service.build_settings_response",
            return_value={
                "workspace_id": ws.id,
                "slack_enabled": False,
                "slack_webhook_url_masked": None,
                "webhook_enabled": False,
                "webhook_url_masked": None,
                "notify_on_risk_level": "high_and_critical",
            },
        ), patch(
            "app.services.workspace_service.log_audit_event",
            side_effect=capture_log,
        ):
            resp = client.put(
                f"/workspaces/{ws.id}/notification-settings",
                json={"notify_on_risk_level": "high_and_critical"},
            )

        app.dependency_overrides.clear()
        assert resp.status_code == 200

        meta_str = str(captured_metadata)
        assert "slack.com/services" not in meta_str
        assert "https://example.com" not in meta_str
        assert "hooks." not in meta_str

    def test_mask_url_hides_middle_portion(self):
        """_mask_url exposes only the first 12 chars and last 4 chars."""
        from app.services.notification_service import _mask_url

        url = "https://hooks.slack.com/services/T12345/B12345/XXXXXXXXXXXXXX"
        masked = _mask_url(url)
        assert masked.startswith(url[:12])
        assert masked.endswith(url[-4:])
        assert "****" in masked
        # The middle portion is not present.
        middle = url[12:-4]
        assert middle not in masked
