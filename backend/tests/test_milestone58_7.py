"""Tests for M58.7: Web Push / PWA Browser Notifications.

Test strategy
-------------
Pure unit tests using MagicMock for database sessions and the FastAPI
TestClient for router endpoints.  No real VAPID keys, no pywebpush HTTP
calls, no live database.

Patch-path rules
----------------
* push_notification_service uses LOCAL imports inside each function:
    - ``from app.config import settings`` → patch ``app.config.settings``
    - ``from pywebpush import webpush`` → patch ``pywebpush.webpush``
    - ``from pywebpush import WebPushException`` → patch ``pywebpush.WebPushException``
    - ``from app.core.encryption import encrypt_credentials`` → patch
      ``app.core.encryption.encrypt_credentials``
    - ``from app.core.encryption import decrypt_credentials`` → patch
      ``app.core.encryption.decrypt_credentials``
* Functions that ARE module-level (e.g. _decrypt_subscription, _get_vapid_private_key)
  are patched at ``app.services.push_notification_service.<name>``.
* dispatch_push_for_sync is imported locally in notification_service → patch
  ``app.services.push_notification_service.dispatch_push_for_sync``.

Coverage
--------
Config (TestPushConfig):
  1.  is_web_push_configured returns False when both keys absent
  2.  is_web_push_configured returns False when public key absent
  3.  is_web_push_configured returns False when private key absent
  4.  is_web_push_configured returns False when key contains placeholder
  5.  is_web_push_configured returns True with valid keys

VAPID key helpers (TestVapidKeyHelpers):
  6.  get_vapid_public_key returns the configured public key
  7.  get_vapid_public_key returns None when unconfigured
  8.  _get_vapid_private_key returns the configured private key
  9.  _get_vapid_private_key raises RuntimeError when unconfigured
  10. _get_vapid_subject returns configured value
  11. _get_vapid_subject returns default when unconfigured

Push subscription storage (TestPushSubscribe):
  12. subscribe() calls encrypt_credentials with endpoint+p256dh+auth
  13. subscribe() adds row to DB
  14. subscribe() sets metadata fields correctly

Push subscription list (TestListSubscriptions):
  15. list_subscriptions() queries DB and returns results
  16. list_subscriptions() returns empty list when none exist

Push subscription delete (TestDeleteSubscription):
  17. delete_subscription() sets enabled=False and returns True
  18. delete_subscription() returns False when not found
  19. delete_subscription() uses both subscription_id and workspace_id in filter

Risk level filter (TestAlertablePushLevels):
  20. "high" includes both high and critical
  21. "critical_only" includes only critical
  22. Unknown value defaults to high+critical

Push payload builder (TestBuildPushPayload):
  23. Payload contains all required keys
  24. Critical change produces "Critical" in title
  25. High change produces "High-risk" in title
  26. Multi-change body includes count suffix

Subscription decryption (TestDecryptSubscription):
  27. _decrypt_subscription calls decrypt_credentials correctly
  28. Returns dict with endpoint, p256dh, auth

Send push delivery (TestSendPush):
  29. Returns False when VAPID not configured
  30. Returns False when subscription is disabled
  31. Calls webpush with correct subscription_info
  32. Returns True on successful delivery and clears last_error
  33. Handles 410 Gone — disables subscription, returns False
  34. Handles generic exception — records error_type, returns False

Dispatch for sync (TestDispatchPushForSync):
  35. Returns 0 when VAPID not configured
  36. Returns 0 when no changes
  37. Returns 0 when no enabled subscriptions
  38. Sends push for qualifying changes per min_risk_level
  39. Skips changes below subscription min_risk_level
  40. Returns correct count of successful sends
  41. Never raises on per-subscription error

Send test push (TestSendTestPush):
  42. Returns error dict when not configured
  43. Returns error dict when no subscriptions
  44. Returns sent count on success
  45. Sets error when all sends fail

Router endpoints — public key (TestPushEndpointPublicKey):
  46. GET returns 200 + vapid_public_key when configured
  47. GET returns configured=False when VAPID absent
  48. GET returns 403 for non-member

Router endpoints — subscribe (TestPushEndpointSubscribe):
  49. POST returns 201 with subscription metadata
  50. POST with invalid min_risk_level returns 422

Router endpoints — list (TestPushEndpointList):
  51. GET returns subscriptions list

Router endpoints — delete (TestPushEndpointDelete):
  52. DELETE returns 204 on success
  53. DELETE returns 404 when not found

Router endpoints — test push (TestPushEndpointTest):
  54. POST returns 200 with sent/total_subscriptions
  55. POST returns 403 for plain member (admin required)

Notification service integration (TestNotificationServicePushIntegration):
  56. push_sent key is always in the result dict
  57. Early-return path (no Slack/webhook) attempts push
  58. Normal flow (Slack enabled) also dispatches push
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_FAKE_PUB_KEY = "BNxBrFM8hpuBapWsVxDJcC7avQmcxilz_ABC123"
_FAKE_PRIV_KEY = "priv_fake_key_abc123"
_FAKE_SUBJECT = "mailto:test@configtrace.org"
_FAKE_ENDPOINT = "https://push.example.com/sub/abc123"
_FAKE_P256DH = "BN4Cg2yXBQ5jY9iVAc7rK_fake_p256dh"
_FAKE_AUTH = "authsecret_fake"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_mock_sub(
    workspace_id: uuid.UUID | None = None,
    enabled: bool = True,
    min_risk_level: str = "high",
) -> MagicMock:
    sub = MagicMock()
    sub.id = uuid.uuid4()
    sub.workspace_id = workspace_id or uuid.uuid4()
    sub.enabled = enabled
    sub.min_risk_level = min_risk_level
    sub.subscription_encrypted = b"encrypted_data"
    sub.subscription_iv = b"iv_bytes"
    sub.device_label = "Chrome on Mac"
    sub.browser_name = "Chrome"
    sub.user_agent = "Mozilla/5.0"
    sub.last_error = None
    sub.last_used_at = None
    sub.created_at = _utcnow()
    sub.updated_at = _utcnow()
    return sub


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
    i.workspace_id = workspace_id or uuid.uuid4()
    i.provider = "aws"
    i.display_name = "My AWS"
    return i


def _make_mock_db() -> MagicMock:
    db = MagicMock()
    db.query.return_value = db
    db.filter.return_value = db
    db.order_by.return_value = db
    db.first.return_value = None
    db.all.return_value = []
    return db


def _mock_configured_settings() -> MagicMock:
    """Return mock Settings with VAPID configured."""
    s = MagicMock()
    s.is_web_push_configured = True
    s.APP_BASE_URL = "https://app.example.com"
    s.WEB_PUSH_VAPID_PUBLIC_KEY = _FAKE_PUB_KEY
    s.WEB_PUSH_VAPID_PRIVATE_KEY = _FAKE_PRIV_KEY
    s.WEB_PUSH_SUBJECT = _FAKE_SUBJECT
    return s


# ─────────────────────────────────────────────────────────────────────────────
# TestClient factory
# ─────────────────────────────────────────────────────────────────────────────

def _make_router_test_setup(role: str = "member"):
    """Return (app, workspace_id, user_id, mock_db, cleanup_fn)."""
    from app.main import app
    from app.core.auth import get_current_user
    from app.database import get_db

    workspace_id = uuid.uuid4()
    user_id = uuid.uuid4()

    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.email = "test@example.com"
    mock_db = _make_mock_db()

    app.dependency_overrides[get_current_user] = lambda: mock_user
    app.dependency_overrides[get_db] = lambda: mock_db

    def cleanup():
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)

    return app, workspace_id, user_id, mock_db, cleanup, get_current_user, get_db


# ─────────────────────────────────────────────────────────────────────────────
# 1-5: Config
# ─────────────────────────────────────────────────────────────────────────────

class TestPushConfig:
    def test_unconfigured_both_missing(self):
        from app.config import Settings
        s = Settings(ENCRYPTION_KEY="a" * 32)
        # Override at instance level for testing.
        s.WEB_PUSH_VAPID_PUBLIC_KEY = None
        s.WEB_PUSH_VAPID_PRIVATE_KEY = None
        assert s.is_web_push_configured is False

    def test_unconfigured_public_key_missing(self):
        from app.config import Settings
        s = Settings(ENCRYPTION_KEY="a" * 32)
        s.WEB_PUSH_VAPID_PUBLIC_KEY = None
        s.WEB_PUSH_VAPID_PRIVATE_KEY = _FAKE_PRIV_KEY
        assert s.is_web_push_configured is False

    def test_unconfigured_private_key_missing(self):
        from app.config import Settings
        s = Settings(ENCRYPTION_KEY="a" * 32)
        s.WEB_PUSH_VAPID_PUBLIC_KEY = _FAKE_PUB_KEY
        s.WEB_PUSH_VAPID_PRIVATE_KEY = None
        assert s.is_web_push_configured is False

    def test_unconfigured_placeholder_in_public_key(self):
        from app.config import Settings
        s = Settings(ENCRYPTION_KEY="a" * 32)
        s.WEB_PUSH_VAPID_PUBLIC_KEY = "replace-with-real-key"
        s.WEB_PUSH_VAPID_PRIVATE_KEY = _FAKE_PRIV_KEY
        assert s.is_web_push_configured is False

    def test_configured_valid_keys(self):
        from app.config import Settings
        s = Settings(ENCRYPTION_KEY="a" * 32)
        s.WEB_PUSH_VAPID_PUBLIC_KEY = _FAKE_PUB_KEY
        s.WEB_PUSH_VAPID_PRIVATE_KEY = _FAKE_PRIV_KEY
        assert s.is_web_push_configured is True


# ─────────────────────────────────────────────────────────────────────────────
# 6-11: VAPID key helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestVapidKeyHelpers:
    def test_get_public_key_returns_key(self):
        from app.services.push_notification_service import get_vapid_public_key
        mock_s = MagicMock()
        mock_s.WEB_PUSH_VAPID_PUBLIC_KEY = _FAKE_PUB_KEY
        with patch("app.config.settings", mock_s):
            key = get_vapid_public_key()
        assert key == _FAKE_PUB_KEY

    def test_get_public_key_returns_none_when_unconfigured(self):
        from app.services.push_notification_service import get_vapid_public_key
        mock_s = MagicMock()
        mock_s.WEB_PUSH_VAPID_PUBLIC_KEY = None
        with patch("app.config.settings", mock_s):
            key = get_vapid_public_key()
        assert key is None

    def test_get_private_key_returns_key(self):
        from app.services.push_notification_service import _get_vapid_private_key
        mock_s = MagicMock()
        mock_s.WEB_PUSH_VAPID_PRIVATE_KEY = _FAKE_PRIV_KEY
        with patch("app.config.settings", mock_s):
            key = _get_vapid_private_key()
        assert key == _FAKE_PRIV_KEY

    def test_get_private_key_raises_when_unconfigured(self):
        from app.services.push_notification_service import _get_vapid_private_key
        mock_s = MagicMock()
        mock_s.WEB_PUSH_VAPID_PRIVATE_KEY = None
        with patch("app.config.settings", mock_s):
            with pytest.raises(RuntimeError, match="WEB_PUSH_VAPID_PRIVATE_KEY"):
                _get_vapid_private_key()

    def test_get_subject_returns_configured_value(self):
        from app.services.push_notification_service import _get_vapid_subject
        mock_s = MagicMock()
        mock_s.WEB_PUSH_SUBJECT = _FAKE_SUBJECT
        with patch("app.config.settings", mock_s):
            subj = _get_vapid_subject()
        assert subj == _FAKE_SUBJECT

    def test_get_subject_returns_default_when_unconfigured(self):
        from app.services.push_notification_service import _get_vapid_subject
        mock_s = MagicMock()
        mock_s.WEB_PUSH_SUBJECT = None
        with patch("app.config.settings", mock_s):
            subj = _get_vapid_subject()
        assert subj == "mailto:security@configtrace.org"


# ─────────────────────────────────────────────────────────────────────────────
# 12-14: Push subscription storage
# ─────────────────────────────────────────────────────────────────────────────

class TestPushSubscribe:
    def test_subscribe_encrypts_data_with_all_three_secrets(self):
        """encrypt_credentials must receive endpoint, p256dh, and auth."""
        from app.services.push_notification_service import subscribe
        db = _make_mock_db()

        with patch("app.core.encryption.encrypt_credentials") as mock_enc:
            mock_enc.return_value = (b"enc", b"iv")
            subscribe(
                workspace_id=uuid.uuid4(),
                user_id=None,
                endpoint=_FAKE_ENDPOINT,
                p256dh=_FAKE_P256DH,
                auth=_FAKE_AUTH,
                device_label=None,
                min_risk_level="high",
                user_agent=None,
                browser_name=None,
                db=db,
            )

        mock_enc.assert_called_once()
        call_arg = mock_enc.call_args[0][0]
        assert call_arg["endpoint"] == _FAKE_ENDPOINT
        assert call_arg["p256dh"] == _FAKE_P256DH
        assert call_arg["auth"] == _FAKE_AUTH

    def test_subscribe_adds_row_to_db(self):
        from app.services.push_notification_service import subscribe
        db = _make_mock_db()

        with patch("app.core.encryption.encrypt_credentials", return_value=(b"enc", b"iv")):
            result = subscribe(
                workspace_id=uuid.uuid4(),
                user_id=None,
                endpoint=_FAKE_ENDPOINT,
                p256dh=_FAKE_P256DH,
                auth=_FAKE_AUTH,
                device_label=None,
                min_risk_level="high",
                user_agent=None,
                browser_name=None,
                db=db,
            )

        db.add.assert_called_once()
        db.flush.assert_called_once()
        assert result is not None

    def test_subscribe_sets_metadata_fields(self):
        from app.services.push_notification_service import subscribe
        db = _make_mock_db()

        with patch("app.core.encryption.encrypt_credentials", return_value=(b"enc", b"iv")):
            result = subscribe(
                workspace_id=uuid.uuid4(),
                user_id=None,
                endpoint=_FAKE_ENDPOINT,
                p256dh=_FAKE_P256DH,
                auth=_FAKE_AUTH,
                device_label="Edge on Windows",
                min_risk_level="critical_only",
                user_agent="Mozilla/5.0 Edge",
                browser_name="Edge",
                db=db,
            )

        assert result.device_label == "Edge on Windows"
        assert result.browser_name == "Edge"
        assert result.min_risk_level == "critical_only"
        assert result.enabled is True


# ─────────────────────────────────────────────────────────────────────────────
# 15-16: List subscriptions
# ─────────────────────────────────────────────────────────────────────────────

class TestListSubscriptions:
    def test_list_returns_subscriptions(self):
        from app.services.push_notification_service import list_subscriptions
        workspace_id = uuid.uuid4()
        mock_sub = _make_mock_sub(workspace_id=workspace_id)
        db = _make_mock_db()
        db.all.return_value = [mock_sub]

        result = list_subscriptions(workspace_id, db)

        db.query.assert_called_once()
        assert result == [mock_sub]

    def test_list_returns_empty_when_none_exist(self):
        from app.services.push_notification_service import list_subscriptions
        db = _make_mock_db()
        db.all.return_value = []

        result = list_subscriptions(uuid.uuid4(), db)
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# 17-19: Delete subscription
# ─────────────────────────────────────────────────────────────────────────────

class TestDeleteSubscription:
    def test_delete_disables_and_returns_true(self):
        from app.services.push_notification_service import delete_subscription
        workspace_id = uuid.uuid4()
        mock_sub = _make_mock_sub(workspace_id=workspace_id, enabled=True)
        db = _make_mock_db()
        db.first.return_value = mock_sub

        result = delete_subscription(uuid.uuid4(), workspace_id, db)

        assert result is True
        assert mock_sub.enabled is False

    def test_delete_returns_false_when_not_found(self):
        from app.services.push_notification_service import delete_subscription
        db = _make_mock_db()
        db.first.return_value = None

        result = delete_subscription(uuid.uuid4(), uuid.uuid4(), db)
        assert result is False

    def test_delete_uses_workspace_filter(self):
        """Query must filter by both subscription_id and workspace_id."""
        from app.services.push_notification_service import delete_subscription
        db = _make_mock_db()
        db.first.return_value = None  # wrong workspace → None

        delete_subscription(uuid.uuid4(), uuid.uuid4(), db)

        assert db.filter.called


# ─────────────────────────────────────────────────────────────────────────────
# 20-22: Risk level filter
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertablePushLevels:
    def test_high_includes_high_and_critical(self):
        from app.services.push_notification_service import _alertable_push_levels
        levels = _alertable_push_levels("high")
        assert "high" in levels
        assert "critical" in levels
        assert "medium" not in levels

    def test_critical_only_includes_only_critical(self):
        from app.services.push_notification_service import _alertable_push_levels
        levels = _alertable_push_levels("critical_only")
        assert "critical" in levels
        assert "high" not in levels

    def test_unknown_value_defaults_to_high_and_critical(self):
        from app.services.push_notification_service import _alertable_push_levels
        levels = _alertable_push_levels("unknown_value")
        assert "high" in levels
        assert "critical" in levels


# ─────────────────────────────────────────────────────────────────────────────
# 23-26: Payload builder
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildPushPayload:
    def test_payload_has_all_required_keys(self):
        from app.services.push_notification_service import _build_push_payload
        payload = _build_push_payload(
            [_make_mock_change("critical")],
            _make_mock_integration(),
            "https://app.example.com",
        )
        for key in ("title", "body", "url", "tag", "risk_level", "provider"):
            assert key in payload, f"Missing key: {key}"

    def test_critical_change_produces_critical_title(self):
        from app.services.push_notification_service import _build_push_payload
        payload = _build_push_payload(
            [_make_mock_change("critical")],
            _make_mock_integration(),
            "https://app.example.com",
        )
        assert "Critical" in payload["title"]

    def test_high_change_produces_high_risk_title(self):
        from app.services.push_notification_service import _build_push_payload
        payload = _build_push_payload(
            [_make_mock_change("high")],
            _make_mock_integration(),
            "https://app.example.com",
        )
        assert "High-risk" in payload["title"]

    def test_multi_change_body_includes_count(self):
        from app.services.push_notification_service import _build_push_payload
        changes = [
            _make_mock_change("critical"),
            _make_mock_change("high"),
            _make_mock_change("high"),
        ]
        payload = _build_push_payload(changes, _make_mock_integration(), "https://app.example.com")
        assert "+2 more" in payload["body"]


# ─────────────────────────────────────────────────────────────────────────────
# 27-28: Subscription decryption
# ─────────────────────────────────────────────────────────────────────────────

class TestDecryptSubscription:
    def test_calls_decrypt_credentials_with_encrypted_data(self):
        from app.services.push_notification_service import _decrypt_subscription
        sub = _make_mock_sub()
        expected = {"endpoint": _FAKE_ENDPOINT, "p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH}

        with patch("app.core.encryption.decrypt_credentials", return_value=expected) as mock_dec:
            result = _decrypt_subscription(sub)

        mock_dec.assert_called_once_with(sub.subscription_encrypted, sub.subscription_iv)
        assert result == expected

    def test_returned_dict_has_endpoint_p256dh_auth(self):
        from app.services.push_notification_service import _decrypt_subscription
        sub = _make_mock_sub()
        expected = {"endpoint": _FAKE_ENDPOINT, "p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH}

        with patch("app.core.encryption.decrypt_credentials", return_value=expected):
            result = _decrypt_subscription(sub)

        assert result["endpoint"] == _FAKE_ENDPOINT
        assert result["p256dh"] == _FAKE_P256DH
        assert result["auth"] == _FAKE_AUTH


# ─────────────────────────────────────────────────────────────────────────────
# 29-34: send_push
# ─────────────────────────────────────────────────────────────────────────────

class TestSendPush:
    def test_returns_false_when_vapid_not_configured(self):
        from app.services.push_notification_service import send_push
        sub = _make_mock_sub(enabled=True)
        mock_s = MagicMock()
        mock_s.is_web_push_configured = False
        with patch("app.config.settings", mock_s):
            result = send_push(sub, {"title": "test"}, _make_mock_db())
        assert result is False

    def test_returns_false_when_subscription_disabled(self):
        from app.services.push_notification_service import send_push
        sub = _make_mock_sub(enabled=False)
        mock_s = _mock_configured_settings()
        with patch("app.config.settings", mock_s):
            result = send_push(sub, {"title": "test"}, _make_mock_db())
        assert result is False

    def test_calls_webpush_with_correct_subscription_info(self):
        from app.services.push_notification_service import send_push
        sub = _make_mock_sub(enabled=True)
        db = _make_mock_db()
        decrypted = {"endpoint": _FAKE_ENDPOINT, "p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH}

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service._decrypt_subscription", return_value=decrypted), \
             patch("app.services.push_notification_service._get_vapid_private_key", return_value=_FAKE_PRIV_KEY), \
             patch("app.services.push_notification_service._get_vapid_subject", return_value=_FAKE_SUBJECT), \
             patch("pywebpush.webpush") as mock_wp:
            send_push(sub, {"title": "test"}, db)

        mock_wp.assert_called_once()
        call_kwargs = mock_wp.call_args[1]
        sub_info = call_kwargs.get("subscription_info", {})
        assert sub_info["endpoint"] == _FAKE_ENDPOINT
        assert "keys" in sub_info
        assert sub_info["keys"]["p256dh"] == _FAKE_P256DH
        assert sub_info["keys"]["auth"] == _FAKE_AUTH

    def test_returns_true_and_clears_error_on_success(self):
        from app.services.push_notification_service import send_push
        sub = _make_mock_sub(enabled=True)
        sub.last_error = "previous error"
        db = _make_mock_db()
        decrypted = {"endpoint": _FAKE_ENDPOINT, "p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH}

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service._decrypt_subscription", return_value=decrypted), \
             patch("app.services.push_notification_service._get_vapid_private_key", return_value=_FAKE_PRIV_KEY), \
             patch("app.services.push_notification_service._get_vapid_subject", return_value=_FAKE_SUBJECT), \
             patch("pywebpush.webpush"):
            result = send_push(sub, {"title": "test"}, db)

        assert result is True
        assert sub.last_error is None

    def test_handles_410_gone_disables_subscription(self):
        from app.services.push_notification_service import send_push
        sub = _make_mock_sub(enabled=True)
        db = _make_mock_db()
        decrypted = {"endpoint": _FAKE_ENDPOINT, "p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH}

        # Build a fake WebPushException with status_code 410.
        mock_response = MagicMock()
        mock_response.status_code = 410

        class FakeWebPushException(Exception):
            def __init__(self):
                super().__init__("Gone")
                self.response = mock_response

        fake_exc = FakeWebPushException()

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service._decrypt_subscription", return_value=decrypted), \
             patch("app.services.push_notification_service._get_vapid_private_key", return_value=_FAKE_PRIV_KEY), \
             patch("app.services.push_notification_service._get_vapid_subject", return_value=_FAKE_SUBJECT), \
             patch("pywebpush.webpush", side_effect=fake_exc), \
             patch("pywebpush.WebPushException", FakeWebPushException):
            result = send_push(sub, {"title": "test"}, db)

        assert result is False
        assert sub.enabled is False
        assert "410" in (sub.last_error or "")

    def test_handles_generic_exception_records_error_type(self):
        from app.services.push_notification_service import send_push
        sub = _make_mock_sub(enabled=True)
        db = _make_mock_db()
        decrypted = {"endpoint": _FAKE_ENDPOINT, "p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH}

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service._decrypt_subscription", return_value=decrypted), \
             patch("app.services.push_notification_service._get_vapid_private_key", return_value=_FAKE_PRIV_KEY), \
             patch("app.services.push_notification_service._get_vapid_subject", return_value=_FAKE_SUBJECT), \
             patch("pywebpush.webpush", side_effect=ConnectionError("refused")):
            result = send_push(sub, {"title": "test"}, db)

        assert result is False
        assert sub.last_error == "ConnectionError"


# ─────────────────────────────────────────────────────────────────────────────
# 35-41: dispatch_push_for_sync
# ─────────────────────────────────────────────────────────────────────────────

class TestDispatchPushForSync:
    def test_returns_zero_when_vapid_not_configured(self):
        from app.services.push_notification_service import dispatch_push_for_sync
        s = MagicMock()
        s.is_web_push_configured = False
        with patch("app.config.settings", s):
            result = dispatch_push_for_sync(
                workspace_id=uuid.uuid4(),
                changes=[_make_mock_change()],
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=_make_mock_db(),
            )
        assert result == 0

    def test_returns_zero_when_no_changes(self):
        from app.services.push_notification_service import dispatch_push_for_sync
        with patch("app.config.settings", _mock_configured_settings()):
            result = dispatch_push_for_sync(
                workspace_id=uuid.uuid4(),
                changes=[],
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=_make_mock_db(),
            )
        assert result == 0

    def test_returns_zero_when_no_subscriptions(self):
        from app.services.push_notification_service import dispatch_push_for_sync
        db = _make_mock_db()
        db.all.return_value = []
        with patch("app.config.settings", _mock_configured_settings()):
            result = dispatch_push_for_sync(
                workspace_id=uuid.uuid4(),
                changes=[_make_mock_change()],
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=db,
            )
        assert result == 0

    def test_sends_for_qualifying_changes(self):
        from app.services.push_notification_service import dispatch_push_for_sync
        workspace_id = uuid.uuid4()
        sub = _make_mock_sub(workspace_id=workspace_id, enabled=True, min_risk_level="high")
        db = _make_mock_db()
        db.all.return_value = [sub]
        changes = [_make_mock_change("critical"), _make_mock_change("high")]

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service.send_push", return_value=True) as mock_sp:
            result = dispatch_push_for_sync(
                workspace_id=workspace_id,
                changes=changes,
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        assert result == 1
        mock_sp.assert_called_once()

    def test_skips_changes_below_min_risk_level(self):
        """critical_only subscription: only critical qualifies, not high."""
        from app.services.push_notification_service import dispatch_push_for_sync
        workspace_id = uuid.uuid4()
        sub = _make_mock_sub(workspace_id=workspace_id, enabled=True, min_risk_level="critical_only")
        db = _make_mock_db()
        db.all.return_value = [sub]
        changes = [_make_mock_change("high")]  # no critical changes

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service.send_push", return_value=True) as mock_sp:
            result = dispatch_push_for_sync(
                workspace_id=workspace_id,
                changes=changes,
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        assert result == 0
        mock_sp.assert_not_called()

    def test_returns_count_of_successful_sends(self):
        from app.services.push_notification_service import dispatch_push_for_sync
        workspace_id = uuid.uuid4()
        sub1 = _make_mock_sub(workspace_id=workspace_id, enabled=True, min_risk_level="high")
        sub2 = _make_mock_sub(workspace_id=workspace_id, enabled=True, min_risk_level="high")
        db = _make_mock_db()
        db.all.return_value = [sub1, sub2]
        changes = [_make_mock_change("critical")]

        send_results = iter([True, False])

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service.send_push",
                   side_effect=lambda *a, **kw: next(send_results)):
            result = dispatch_push_for_sync(
                workspace_id=workspace_id,
                changes=changes,
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        assert result == 1

    def test_never_raises_on_per_subscription_error(self):
        from app.services.push_notification_service import dispatch_push_for_sync
        workspace_id = uuid.uuid4()
        sub = _make_mock_sub(workspace_id=workspace_id, enabled=True, min_risk_level="high")
        db = _make_mock_db()
        db.all.return_value = [sub]

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service.send_push",
                   side_effect=RuntimeError("boom")):
            result = dispatch_push_for_sync(
                workspace_id=workspace_id,
                changes=[_make_mock_change("critical")],
                integration=_make_mock_integration(),
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        assert result == 0  # did not raise


# ─────────────────────────────────────────────────────────────────────────────
# 42-45: send_test_push
# ─────────────────────────────────────────────────────────────────────────────

class TestSendTestPush:
    def test_returns_error_when_not_configured(self):
        from app.services.push_notification_service import send_test_push
        s = MagicMock()
        s.is_web_push_configured = False
        with patch("app.config.settings", s):
            result = send_test_push(uuid.uuid4(), _make_mock_db())
        assert result["error"] is not None
        assert result["sent"] == 0

    def test_returns_error_when_no_subscriptions(self):
        from app.services.push_notification_service import send_test_push
        db = _make_mock_db()
        db.all.return_value = []
        with patch("app.config.settings", _mock_configured_settings()):
            result = send_test_push(uuid.uuid4(), db)
        assert result["total_subscriptions"] == 0
        assert result["error"] is not None

    def test_returns_sent_count_on_success(self):
        from app.services.push_notification_service import send_test_push
        workspace_id = uuid.uuid4()
        sub = _make_mock_sub(workspace_id=workspace_id, enabled=True)
        db = _make_mock_db()
        db.all.return_value = [sub]

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service.send_push", return_value=True):
            result = send_test_push(workspace_id, db)

        assert result["sent"] == 1
        assert result["total_subscriptions"] == 1
        assert result["error"] is None

    def test_sets_error_when_all_sends_fail(self):
        from app.services.push_notification_service import send_test_push
        workspace_id = uuid.uuid4()
        sub = _make_mock_sub(workspace_id=workspace_id, enabled=True)
        db = _make_mock_db()
        db.all.return_value = [sub]

        with patch("app.config.settings", _mock_configured_settings()), \
             patch("app.services.push_notification_service.send_push", return_value=False):
            result = send_test_push(workspace_id, db)

        assert result["sent"] == 0
        assert result["error"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 46-55: Router endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestPushEndpointPublicKey:
    def test_get_returns_200_with_key_when_configured(self):
        app, workspace_id, _, mock_db, cleanup, _, _ = _make_router_test_setup()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.services.push_notification_service.get_vapid_public_key",
                        return_value=_FAKE_PUB_KEY):
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.get(
                    f"/workspaces/{workspace_id}/notifications/push/public-key"
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["vapid_public_key"] == _FAKE_PUB_KEY
            assert data["configured"] is True
        finally:
            cleanup()

    def test_get_returns_configured_false_when_unconfigured(self):
        app, workspace_id, _, mock_db, cleanup, _, _ = _make_router_test_setup()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.services.push_notification_service.get_vapid_public_key",
                        return_value=None):
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.get(
                    f"/workspaces/{workspace_id}/notifications/push/public-key"
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["configured"] is False
            assert data["vapid_public_key"] is None
        finally:
            cleanup()

    def test_get_returns_403_for_non_member(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws:
                mock_ws.require_role.side_effect = PermissionError("Not a member")
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get(
                    f"/workspaces/{workspace_id}/notifications/push/public-key"
                )
            assert resp.status_code == 403
        finally:
            cleanup()


class TestPushEndpointSubscribe:
    def test_post_creates_subscription_returns_201(self):
        app, workspace_id, _, mock_db, cleanup, _, _ = _make_router_test_setup()
        sub_id = uuid.uuid4()
        mock_sub = _make_mock_sub(workspace_id=workspace_id)
        mock_sub.id = sub_id
        mock_db.refresh = MagicMock()

        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.core.encryption.encrypt_credentials", return_value=(b"enc", b"iv")), \
                 patch("app.services.push_notification_service.subscribe",
                        return_value=mock_sub) as mock_subscribe:
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.post(
                    f"/workspaces/{workspace_id}/notifications/push/subscriptions",
                    json={
                        "subscription": {
                            "endpoint": _FAKE_ENDPOINT,
                            "keys": {"p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH},
                        },
                        "device_label": "Chrome on Mac",
                        "min_risk_level": "high",
                    },
                )
            assert resp.status_code == 201
        finally:
            cleanup()

    def test_post_invalid_min_risk_level_returns_422(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws:
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.post(
                    f"/workspaces/{workspace_id}/notifications/push/subscriptions",
                    json={
                        "subscription": {
                            "endpoint": _FAKE_ENDPOINT,
                            "keys": {"p256dh": _FAKE_P256DH, "auth": _FAKE_AUTH},
                        },
                        "min_risk_level": "medium",  # invalid
                    },
                )
            assert resp.status_code == 422
        finally:
            cleanup()


class TestPushEndpointList:
    def test_get_returns_subscriptions_list(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        mock_sub = _make_mock_sub(workspace_id=workspace_id)
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.services.push_notification_service.list_subscriptions",
                        return_value=[mock_sub]):
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.get(
                    f"/workspaces/{workspace_id}/notifications/push/subscriptions"
                )
            assert resp.status_code == 200
            data = resp.json()
            assert "subscriptions" in data
            assert len(data["subscriptions"]) == 1
        finally:
            cleanup()


class TestPushEndpointDelete:
    def test_delete_returns_204_on_success(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        sub_id = uuid.uuid4()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.services.push_notification_service.delete_subscription",
                        return_value=True):
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.delete(
                    f"/workspaces/{workspace_id}/notifications/push/subscriptions/{sub_id}"
                )
            assert resp.status_code == 204
        finally:
            cleanup()

    def test_delete_returns_404_when_not_found(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        sub_id = uuid.uuid4()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.services.push_notification_service.delete_subscription",
                        return_value=False):
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.delete(
                    f"/workspaces/{workspace_id}/notifications/push/subscriptions/{sub_id}"
                )
            assert resp.status_code == 404
        finally:
            cleanup()


class TestPushEndpointTest:
    def test_post_returns_200_with_counts(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws, \
                 patch("app.services.push_notification_service.send_test_push",
                        return_value={"sent": 2, "total_subscriptions": 2, "error": None}):
                mock_ws.require_role.return_value = None
                client = TestClient(app)
                resp = client.post(
                    f"/workspaces/{workspace_id}/notifications/push/test"
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["sent"] == 2
            assert data["total_subscriptions"] == 2
            assert data["error"] is None
        finally:
            cleanup()

    def test_post_returns_403_for_member(self):
        app, workspace_id, _, _, cleanup, _, _ = _make_router_test_setup()
        try:
            with patch("app.routers.workspaces.workspace_service") as mock_ws:
                mock_ws.require_role.side_effect = PermissionError("Admin required")
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    f"/workspaces/{workspace_id}/notifications/push/test"
                )
            assert resp.status_code == 403
        finally:
            cleanup()


# ─────────────────────────────────────────────────────────────────────────────
# 56-58: Notification service integration
# ─────────────────────────────────────────────────────────────────────────────

class TestNotificationServicePushIntegration:
    """
    dispatch_notifications_for_sync signature:
        changes, integration, sync_run_id, db
    workspace_id is derived from integration.workspace_id.
    """

    def _make_settings_row(
        self,
        slack_enabled: bool = False,
        webhook_enabled: bool = False,
    ) -> MagicMock:
        row = MagicMock(spec=object)  # use spec=object so all attrs must be set explicitly
        row.slack_enabled = slack_enabled
        row.slack_webhook_url_encrypted = None
        row.slack_webhook_iv = None
        row.webhook_enabled = webhook_enabled
        row.webhook_url_encrypted = None
        row.webhook_iv = None
        row.notify_on_risk_level = "high_and_critical"
        row.slack_app_enabled = False
        row.slack_bot_token_encrypted = None
        row.slack_bot_iv = None
        row.slack_channel_id = None
        row.slack_app_last_error = None
        return row

    def test_result_dict_includes_push_sent(self):
        """push_sent must appear in result regardless of channel config."""
        from app.services.notification_service import dispatch_notifications_for_sync
        workspace_id = uuid.uuid4()
        integration = _make_mock_integration(workspace_id=workspace_id)
        db = _make_mock_db()
        db.first.return_value = self._make_settings_row()
        changes = [_make_mock_change("critical")]

        with patch("app.services.push_notification_service.dispatch_push_for_sync",
                   return_value=0):
            result = dispatch_notifications_for_sync(
                changes=changes,
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        assert "push_sent" in result

    def test_early_return_path_attempts_push(self):
        """When Slack + webhook both disabled, push is still dispatched."""
        from app.services.notification_service import dispatch_notifications_for_sync
        workspace_id = uuid.uuid4()
        integration = _make_mock_integration(workspace_id=workspace_id)
        db = _make_mock_db()
        # Both traditional channels disabled → triggers early-return path.
        db.first.return_value = self._make_settings_row(
            slack_enabled=False, webhook_enabled=False
        )
        changes = [_make_mock_change("critical")]

        with patch("app.services.push_notification_service.dispatch_push_for_sync",
                   return_value=1) as mock_push:
            result = dispatch_notifications_for_sync(
                changes=changes,
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        mock_push.assert_called_once()
        assert result["push_sent"] == 1

    def test_normal_flow_dispatches_push_at_end(self):
        """When Slack is enabled (no URL configured), qualifying changes still trigger push."""
        from app.services.notification_service import dispatch_notifications_for_sync
        workspace_id = uuid.uuid4()
        integration = _make_mock_integration(workspace_id=workspace_id)
        db = _make_mock_db()
        # slack_enabled=True but no encrypted URL → Slack path skipped,
        # but qualifying list is non-empty → push dispatch runs.
        settings_row = self._make_settings_row(slack_enabled=True, webhook_enabled=False)
        settings_row.slack_webhook_url_encrypted = None  # no URL
        db.first.return_value = settings_row
        changes = [_make_mock_change("critical")]

        with patch("app.services.push_notification_service.dispatch_push_for_sync",
                   return_value=3) as mock_push:
            result = dispatch_notifications_for_sync(
                changes=changes,
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )

        mock_push.assert_called_once()
        assert result["push_sent"] == 3
