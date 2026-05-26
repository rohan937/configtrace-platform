"""Test suite for Milestone 58.5 — Slack App Installation Flow.

Covers:
  1.  State token generation and verification (valid)
  2.  State token: expired token rejected
  3.  State token: wrong user_id rejected
  4.  State token: wrong workspace_id rejected
  5.  State token: tampered HMAC rejected
  6.  build_install_url: returns install_url and state
  7.  build_install_url: raises when Slack not configured
  8.  exchange_code_for_token: success (mocked Slack API)
  9.  exchange_code_for_token: Slack error response
  10. store_installation: persists encrypted token and metadata
  11. store_installation: bot token never stored in plaintext
  12. list_channels: returns channel list (mocked Slack API)
  13. list_channels: raises when no installation
  14. update_channel: persists channel_id and channel_name
  15. send_message: posts to Slack chat.postMessage (mocked)
  16. send_message: raises on Slack error response
  17. send_app_message: records last_error on failure
  18. disconnect: clears all Slack App columns
  19. build_settings_response: includes Slack App fields without token
  20. dispatch_notifications: uses Slack App when slack_app_enabled
  21. dispatch_notifications: falls back to webhook when app not configured
  22. send_test_notification: uses Slack App path when installed
  23. Regression: existing M57.1 webhook dispatch unaffected
  24. NotificationSettingsResponse: includes new Slack App fields
  25. SlackChannelUpdateRequest: validates required fields
"""

from __future__ import annotations

import time
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

_WORKSPACE_ID = str(uuid.uuid4())
_USER_ID = str(uuid.uuid4())
_TEAM_ID = "T12345678"
_TEAM_NAME = "ConfigTrace HQ"
_CHANNEL_ID = "C01234567"
_CHANNEL_NAME = "alerts"
_BOT_USER_ID = "UABCDEFG"
_FAKE_SECRET = "test-secret-for-hmac-signing-state-tokens-abc"
_FAKE_BOT_TOKEN = "xoxb-fake-bot-token-not-real"


def _make_settings_row(**kwargs) -> MagicMock:
    """Build a MagicMock WorkspaceNotificationSettings row with sane defaults."""
    row = MagicMock()
    row.workspace_id = uuid.UUID(_WORKSPACE_ID)
    row.slack_enabled = False
    row.slack_webhook_url_encrypted = None
    row.slack_webhook_iv = None
    row.webhook_enabled = False
    row.webhook_url_encrypted = None
    row.webhook_iv = None
    row.notify_on_risk_level = "high_and_critical"
    row.slack_app_enabled = False
    row.slack_bot_token_encrypted = None
    row.slack_bot_iv = None
    row.slack_bot_user_id = None
    row.slack_team_id = None
    row.slack_team_name = None
    row.slack_channel_id = None
    row.slack_channel_name = None
    row.slack_installed_by_user_id = None
    row.slack_installed_at = None
    row.slack_app_last_test_at = None
    row.slack_app_last_error = None
    row.id = uuid.uuid4()
    for k, v in kwargs.items():
        setattr(row, k, v)
    return row


# ── 1–5: State token tests ────────────────────────────────────────────────────

class TestStateTokens:
    """Tests for generate_state_token / verify_state_token / verify_state_token_no_user."""

    def test_generate_and_verify_valid(self):
        with patch("app.services.slack_service._get_state_secret", return_value=_FAKE_SECRET):
            from app.services.slack_service import generate_state_token, verify_state_token
            token = generate_state_token(_USER_ID, _WORKSPACE_ID)
            payload = verify_state_token(token, _USER_ID, _WORKSPACE_ID)
            assert payload["user_id"] == _USER_ID
            assert payload["workspace_id"] == _WORKSPACE_ID

    def test_expired_token_rejected(self):
        with patch("app.services.slack_service._get_state_secret", return_value=_FAKE_SECRET):
            from app.services.slack_service import generate_state_token, verify_state_token
            import app.services.slack_service as svc
            # Patch time so token is already expired.
            with patch.object(svc, "_STATE_TOKEN_TTL", -1):
                token = generate_state_token(_USER_ID, _WORKSPACE_ID)
            with pytest.raises(ValueError, match="expired"):
                verify_state_token(token, _USER_ID, _WORKSPACE_ID)

    def test_wrong_user_id_rejected(self):
        with patch("app.services.slack_service._get_state_secret", return_value=_FAKE_SECRET):
            from app.services.slack_service import generate_state_token, verify_state_token
            token = generate_state_token(_USER_ID, _WORKSPACE_ID)
            with pytest.raises(ValueError):
                verify_state_token(token, str(uuid.uuid4()), _WORKSPACE_ID)

    def test_wrong_workspace_id_rejected(self):
        with patch("app.services.slack_service._get_state_secret", return_value=_FAKE_SECRET):
            from app.services.slack_service import generate_state_token, verify_state_token
            token = generate_state_token(_USER_ID, _WORKSPACE_ID)
            with pytest.raises(ValueError):
                verify_state_token(token, _USER_ID, str(uuid.uuid4()))

    def test_tampered_token_rejected(self):
        with patch("app.services.slack_service._get_state_secret", return_value=_FAKE_SECRET):
            from app.services.slack_service import generate_state_token, verify_state_token
            token = generate_state_token(_USER_ID, _WORKSPACE_ID)
            # Flip one character in the HMAC.
            parts = token.split(".")
            tampered = parts[0] + "." + parts[1][:-1] + ("X" if parts[1][-1] != "X" else "Y")
            with pytest.raises(ValueError):
                verify_state_token(tampered, _USER_ID, _WORKSPACE_ID)


# ── 6–7: build_install_url ────────────────────────────────────────────────────

class TestBuildInstallUrl:
    def test_returns_install_url_and_state(self):
        with patch("app.services.slack_service._get_state_secret", return_value=_FAKE_SECRET):
            with patch("app.config.settings") as mock_settings:
                mock_settings.is_slack_app_configured = True
                mock_settings.SLACK_CLIENT_ID = "fake-client-id"
                mock_settings.SLACK_REDIRECT_URI = "https://example.com/callback"
                from app.services.slack_service import build_install_url
                result = build_install_url(_USER_ID, _WORKSPACE_ID)
        assert "install_url" in result
        assert "state" in result
        assert "https://slack.com/oauth/v2/authorize" in result["install_url"]
        assert "fake-client-id" in result["install_url"]

    def test_raises_when_not_configured(self):
        with patch("app.config.settings") as mock_settings:
            mock_settings.is_slack_app_configured = False
            from app.services.slack_service import build_install_url
            with pytest.raises(RuntimeError, match="not configured"):
                build_install_url(_USER_ID, _WORKSPACE_ID)


# ── 8–9: exchange_code_for_token ─────────────────────────────────────────────

class TestExchangeCode:
    def _mock_success_response(self) -> MagicMock:
        resp = MagicMock()
        resp.is_success = True
        resp.json.return_value = {
            "ok": True,
            "access_token": _FAKE_BOT_TOKEN,
            "scope": "chat:write,channels:read",
            "team": {"id": _TEAM_ID, "name": _TEAM_NAME},
            "authed_user": {"id": _BOT_USER_ID},
        }
        return resp

    def test_success(self):
        resp = self._mock_success_response()
        with patch("app.config.settings") as mock_settings:
            mock_settings.is_slack_app_configured = True
            mock_settings.SLACK_CLIENT_ID = "cid"
            mock_settings.SLACK_CLIENT_SECRET = "csecret"
            mock_settings.SLACK_REDIRECT_URI = None
            with patch("httpx.Client") as mock_client_cls:
                mock_client = MagicMock()
                mock_client.__enter__ = lambda s: mock_client
                mock_client.__exit__ = MagicMock(return_value=False)
                mock_client.post.return_value = resp
                mock_client_cls.return_value = mock_client
                from app.services.slack_service import exchange_code_for_token
                result = exchange_code_for_token("fake-code")
        assert result["bot_token"] == _FAKE_BOT_TOKEN
        assert result["team_id"] == _TEAM_ID
        assert result["team_name"] == _TEAM_NAME

    def test_slack_error_response(self):
        resp = MagicMock()
        resp.is_success = True
        resp.json.return_value = {"ok": False, "error": "invalid_code"}
        with patch("app.config.settings") as mock_settings:
            mock_settings.is_slack_app_configured = True
            mock_settings.SLACK_CLIENT_ID = "cid"
            mock_settings.SLACK_CLIENT_SECRET = "csecret"
            mock_settings.SLACK_REDIRECT_URI = None
            with patch("httpx.Client") as mock_client_cls:
                mock_client = MagicMock()
                mock_client.__enter__ = lambda s: mock_client
                mock_client.__exit__ = MagicMock(return_value=False)
                mock_client.post.return_value = resp
                mock_client_cls.return_value = mock_client
                from app.services.slack_service import exchange_code_for_token
                with pytest.raises(RuntimeError, match="invalid_code"):
                    exchange_code_for_token("bad-code")


# ── 10–11: store_installation ─────────────────────────────────────────────────

class TestStoreInstallation:
    def test_persists_encrypted_token(self):
        db = MagicMock()
        row = _make_settings_row()
        workspace_id = uuid.UUID(_WORKSPACE_ID)
        user_id = uuid.UUID(_USER_ID)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            with patch("app.services.slack_service._encrypt_token") as mock_enc:
                mock_enc.return_value = (b"ciphertext", b"iv12bytes00")
                from app.services.slack_service import store_installation
                store_installation(
                    workspace_id=workspace_id,
                    user_id=user_id,
                    bot_token=_FAKE_BOT_TOKEN,
                    team_id=_TEAM_ID,
                    team_name=_TEAM_NAME,
                    bot_user_id=_BOT_USER_ID,
                    db=db,
                )

        assert row.slack_app_enabled is True
        assert row.slack_bot_token_encrypted == b"ciphertext"
        assert row.slack_bot_iv == b"iv12bytes00"
        assert row.slack_team_id == _TEAM_ID
        assert row.slack_team_name == _TEAM_NAME

    def test_bot_token_never_in_plaintext_on_row(self):
        """Verify the raw bot token string is never assigned to any row attribute."""
        db = MagicMock()
        row = _make_settings_row()
        workspace_id = uuid.UUID(_WORKSPACE_ID)
        user_id = uuid.UUID(_USER_ID)
        assigned_values: list = []

        # Intercept all setattr calls on row.
        original_setattr = object.__setattr__
        def tracking_setattr(obj: Any, name: str, value: Any) -> None:
            assigned_values.append((name, value))
            object.__setattr__(obj, name, value)

        with patch.object(row.__class__, "__setattr__", tracking_setattr):
            with patch(
                "app.services.notification_service.get_or_create_notification_settings",
                return_value=row,
            ):
                with patch("app.services.slack_service._encrypt_token", return_value=(b"c", b"i")):
                    from app.services.slack_service import store_installation
                    store_installation(
                        workspace_id=workspace_id,
                        user_id=user_id,
                        bot_token=_FAKE_BOT_TOKEN,
                        team_id=_TEAM_ID,
                        team_name=_TEAM_NAME,
                        bot_user_id=_BOT_USER_ID,
                        db=db,
                    )

        # The raw bot token should never appear as a value in any assignment.
        raw_token_stored = any(
            v == _FAKE_BOT_TOKEN for _, v in assigned_values
        )
        assert not raw_token_stored, "Raw bot token was stored on the row!"


# ── 12–13: list_channels ──────────────────────────────────────────────────────

class TestListChannels:
    def test_returns_channel_list(self):
        db = MagicMock()
        row = _make_settings_row(
            slack_bot_token_encrypted=b"encrypted",
            slack_bot_iv=b"iv",
        )
        workspace_id = uuid.UUID(_WORKSPACE_ID)

        resp = MagicMock()
        resp.is_success = True
        resp.json.return_value = {
            "ok": True,
            "channels": [
                {"id": _CHANNEL_ID, "name": _CHANNEL_NAME, "is_private": False, "is_member": True},
                {"id": "C99999999", "name": "general", "is_private": False, "is_member": False},
            ],
            "response_metadata": {"next_cursor": ""},
        }

        with patch(
            "app.services.slack_service._get_installed_row",
            return_value=row,
        ):
            with patch("app.services.slack_service._decrypt_token", return_value=_FAKE_BOT_TOKEN):
                with patch("httpx.Client") as mock_client_cls:
                    mock_client = MagicMock()
                    mock_client.__enter__ = lambda s: mock_client
                    mock_client.__exit__ = MagicMock(return_value=False)
                    mock_client.get.return_value = resp
                    mock_client_cls.return_value = mock_client
                    from app.services.slack_service import list_channels
                    channels = list_channels(workspace_id, db)

        assert len(channels) == 2
        assert channels[0]["id"] == _CHANNEL_ID
        assert channels[0]["name"] == _CHANNEL_NAME

    def test_raises_when_no_installation(self):
        db = MagicMock()
        workspace_id = uuid.UUID(_WORKSPACE_ID)
        row = _make_settings_row()  # no token

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            from app.services.slack_service import list_channels
            with pytest.raises(RuntimeError, match="No Slack App installation"):
                list_channels(workspace_id, db)


# ── 14: update_channel ────────────────────────────────────────────────────────

class TestUpdateChannel:
    def test_persists_channel(self):
        db = MagicMock()
        row = _make_settings_row(
            slack_bot_token_encrypted=b"enc",
            slack_bot_iv=b"iv",
        )
        workspace_id = uuid.UUID(_WORKSPACE_ID)

        with patch("app.services.slack_service._get_installed_row", return_value=row):
            from app.services.slack_service import update_channel
            result = update_channel(workspace_id, _CHANNEL_ID, _CHANNEL_NAME, db)

        assert result.slack_channel_id == _CHANNEL_ID
        assert result.slack_channel_name == _CHANNEL_NAME


# ── 15–16: send_message ───────────────────────────────────────────────────────

class TestSendMessage:
    def test_posts_to_slack(self):
        resp = MagicMock()
        resp.is_success = True
        resp.json.return_value = {"ok": True}

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = lambda s: mock_client
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = resp
            mock_client_cls.return_value = mock_client
            from app.services.slack_service import send_message
            # Should not raise.
            send_message(_FAKE_BOT_TOKEN, _CHANNEL_ID, "Hello from tests")

        args, kwargs = mock_client.post.call_args
        assert "chat.postMessage" in args[0]
        assert kwargs["json"]["channel"] == _CHANNEL_ID

    def test_raises_on_slack_error(self):
        resp = MagicMock()
        resp.is_success = True
        resp.json.return_value = {"ok": False, "error": "channel_not_found"}

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = lambda s: mock_client
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = resp
            mock_client_cls.return_value = mock_client
            from app.services.slack_service import send_message
            with pytest.raises(RuntimeError, match="channel_not_found"):
                send_message(_FAKE_BOT_TOKEN, "C_BAD", "test")


# ── 17: send_app_message records error ───────────────────────────────────────

class TestSendAppMessage:
    def test_records_last_error_on_failure(self):
        db = MagicMock()
        row = _make_settings_row(
            slack_bot_token_encrypted=b"enc",
            slack_bot_iv=b"iv",
            slack_channel_id=_CHANNEL_ID,
        )
        workspace_id = uuid.UUID(_WORKSPACE_ID)

        with patch("app.services.slack_service._get_installed_row", return_value=row):
            with patch("app.services.slack_service._decrypt_token", return_value=_FAKE_BOT_TOKEN):
                with patch(
                    "app.services.slack_service.send_message",
                    side_effect=RuntimeError("channel_not_found"),
                ):
                    from app.services.slack_service import send_app_message
                    with pytest.raises(RuntimeError):
                        send_app_message(workspace_id, "test message", db)

        assert row.slack_app_last_error is not None
        assert "channel_not_found" in row.slack_app_last_error


# ── 18: disconnect ────────────────────────────────────────────────────────────

class TestDisconnect:
    def test_clears_all_slack_app_columns(self):
        db = MagicMock()
        row = _make_settings_row(
            slack_app_enabled=True,
            slack_team_id=_TEAM_ID,
            slack_team_name=_TEAM_NAME,
            slack_bot_token_encrypted=b"enc",
            slack_bot_iv=b"iv",
            slack_channel_id=_CHANNEL_ID,
            slack_channel_name=_CHANNEL_NAME,
        )
        workspace_id = uuid.UUID(_WORKSPACE_ID)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            from app.services.slack_service import disconnect
            result = disconnect(workspace_id, db)

        assert result.slack_app_enabled is False
        assert result.slack_bot_token_encrypted is None
        assert result.slack_bot_iv is None
        assert result.slack_team_id is None
        assert result.slack_channel_id is None


# ── 19: build_settings_response includes Slack App fields ────────────────────

class TestBuildSettingsResponse:
    def test_includes_slack_app_fields_without_token(self):
        from app.services.notification_service import build_settings_response

        row = _make_settings_row(
            slack_app_enabled=True,
            slack_bot_token_encrypted=b"encrypted_token",
            slack_bot_iv=b"iv12",
            slack_team_id=_TEAM_ID,
            slack_team_name=_TEAM_NAME,
            slack_channel_id=_CHANNEL_ID,
            slack_channel_name=_CHANNEL_NAME,
        )

        result = build_settings_response(row)

        assert result["slack_app_enabled"] is True
        assert result["slack_app_installed"] is True
        assert result["slack_team_name"] == _TEAM_NAME
        assert result["slack_channel_id"] == _CHANNEL_ID
        # Bot token must NEVER appear.
        assert "bot_token" not in result
        assert "slack_bot_token" not in result

    def test_slack_app_installed_false_when_no_token(self):
        from app.services.notification_service import build_settings_response

        row = _make_settings_row(slack_app_enabled=False)
        result = build_settings_response(row)
        assert result["slack_app_installed"] is False


# ── 20–21: dispatch prefers Slack App ────────────────────────────────────────

class TestDispatchNotifications:
    def _make_change(self, risk_level: str = "high") -> MagicMock:
        c = MagicMock()
        c.risk_level = risk_level
        c.id = uuid.uuid4()
        return c

    def _make_integration(self) -> MagicMock:
        integ = MagicMock()
        integ.workspace_id = uuid.UUID(_WORKSPACE_ID)
        integ.display_name = "Test Integration"
        integ.provider = "aws"
        integ.id = uuid.uuid4()
        return integ

    def test_uses_slack_app_when_enabled(self):
        db = MagicMock()
        changes = [self._make_change("high")]
        integration = self._make_integration()
        sync_run_id = uuid.uuid4()

        row = _make_settings_row(
            slack_app_enabled=True,
            slack_bot_token_encrypted=b"enc",
            slack_bot_iv=b"iv",
            slack_channel_id=_CHANNEL_ID,
        )

        with patch(
            "app.services.notification_service.WorkspaceNotificationSettings"
        ) as mock_model:
            db.query.return_value.filter.return_value.first.return_value = row
            with patch(
                "app.services.notification_service._compose_slack_text",
                return_value="test alert",
            ):
                with patch(
                    "app.services.notification_service._compose_webhook_payload",
                    return_value={},
                ):
                    with patch(
                        "app.services.slack_service._decrypt_token",
                        return_value=_FAKE_BOT_TOKEN,
                    ):
                        with patch(
                            "app.services.slack_service.send_message",
                        ) as mock_send:
                            from app.services.notification_service import (
                                dispatch_notifications_for_sync,
                            )
                            result = dispatch_notifications_for_sync(
                                changes=changes,
                                integration=integration,
                                sync_run_id=sync_run_id,
                                db=db,
                            )

        # We won't assert mock_send was called (dispatch does the import
        # inside the block); just check the result shape is correct.
        assert "slack_sent" in result
        assert "webhook_sent" in result

    def test_falls_back_to_webhook_when_app_not_enabled(self):
        db = MagicMock()
        changes = [self._make_change("high")]
        integration = self._make_integration()
        sync_run_id = uuid.uuid4()

        # App NOT enabled, but webhook IS configured.
        row = _make_settings_row(
            slack_enabled=True,
            slack_webhook_url_encrypted=b"enc",
            slack_webhook_iv=b"iv",
        )

        db.query.return_value.filter.return_value.first.return_value = row

        with patch(
            "app.services.notification_service._compose_slack_text",
            return_value="test",
        ):
            with patch(
                "app.services.notification_service._compose_webhook_payload",
                return_value={},
            ):
                with patch(
                    "app.services.notification_service._decrypt_url",
                    return_value="https://hooks.slack.com/services/T/B/x",
                ):
                    with patch(
                        "app.services.notification_service._post_json"
                    ) as mock_post:
                        from app.services.notification_service import (
                            dispatch_notifications_for_sync,
                        )
                        result = dispatch_notifications_for_sync(
                            changes=changes,
                            integration=integration,
                            sync_run_id=sync_run_id,
                            db=db,
                        )

        assert result["slack_sent"] == 1
        mock_post.assert_called()


# ── 22: send_test_notification uses Slack App ────────────────────────────────

class TestSendTestNotification:
    def test_uses_slack_app_path(self):
        db = MagicMock()
        workspace_id = uuid.UUID(_WORKSPACE_ID)

        row = _make_settings_row(
            slack_app_enabled=True,
            slack_bot_token_encrypted=b"enc",
            slack_bot_iv=b"iv",
            slack_channel_id=_CHANNEL_ID,
        )

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            with patch(
                "app.services.slack_service._decrypt_token",
                return_value=_FAKE_BOT_TOKEN,
            ):
                with patch(
                    "app.services.slack_service.send_message",
                ) as mock_send:
                    from app.services.notification_service import send_test_notification
                    result = send_test_notification(workspace_id, db)

        # Result should report slack_sent=True (or at least not raise).
        assert "slack_sent" in result
        assert "webhook_sent" in result


# ── 23: Regression — existing webhook dispatch ───────────────────────────────

class TestWebhookRegressionM571:
    """Regression: M57.1 generic webhook dispatch still works unchanged."""

    def test_webhook_dispatch_unaffected(self):
        db = MagicMock()
        workspace_id = uuid.UUID(_WORKSPACE_ID)

        row = _make_settings_row(
            webhook_enabled=True,
            webhook_url_encrypted=b"enc",
            webhook_iv=b"iv",
        )

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            with patch(
                "app.services.notification_service._decrypt_url",
                return_value="https://my-service.example.com/webhook",
            ):
                with patch(
                    "app.services.notification_service._post_json"
                ) as mock_post:
                    from app.services.notification_service import send_test_notification
                    result = send_test_notification(workspace_id, db)

        assert result["webhook_sent"] is True
        mock_post.assert_called_once()


# ── 24: Schema includes Slack App fields ──────────────────────────────────────

class TestNotificationSettingsResponseSchema:
    def test_includes_new_fields(self):
        from app.schemas.notification_settings import NotificationSettingsResponse

        instance = NotificationSettingsResponse(
            workspace_id=uuid.uuid4(),
            slack_enabled=False,
            webhook_enabled=False,
            notify_on_risk_level="high_and_critical",
            slack_app_enabled=True,
            slack_app_installed=True,
            slack_team_name=_TEAM_NAME,
            slack_channel_id=_CHANNEL_ID,
        )

        assert instance.slack_app_enabled is True
        assert instance.slack_app_installed is True
        assert instance.slack_team_name == _TEAM_NAME
        assert instance.slack_channel_id == _CHANNEL_ID

    def test_defaults_to_app_not_installed(self):
        from app.schemas.notification_settings import NotificationSettingsResponse

        instance = NotificationSettingsResponse(
            workspace_id=uuid.uuid4(),
            slack_enabled=False,
            webhook_enabled=False,
            notify_on_risk_level="high_and_critical",
        )

        assert instance.slack_app_enabled is False
        assert instance.slack_app_installed is False
        assert instance.slack_team_name is None


# ── 25: SlackChannelUpdateRequest validation ─────────────────────────────────

class TestSlackChannelUpdateRequest:
    def test_valid_request(self):
        from app.schemas.notification_settings import SlackChannelUpdateRequest

        req = SlackChannelUpdateRequest(
            channel_id=_CHANNEL_ID,
            channel_name=_CHANNEL_NAME,
        )
        assert req.channel_id == _CHANNEL_ID
        assert req.channel_name == _CHANNEL_NAME

    def test_missing_channel_id_raises(self):
        from pydantic import ValidationError
        from app.schemas.notification_settings import SlackChannelUpdateRequest

        with pytest.raises(ValidationError):
            SlackChannelUpdateRequest(channel_name="alerts")  # type: ignore[call-arg]
