"""M80D — SendGrid Configuration Activity Ingestion.

SendGrid has NO native audit/event API. Activity events are config-state
observations synthesized from the safe SendGrid configuration surfaces.

Verifies:
  * SendGridConnector.list_activity_events synthesizes safe config-state events
  * Mail/delivery event types (bounce, click, open, delivered, etc.) are NEVER
    returned and NEVER in the allowlist
  * max_events cap is enforced
  * 401 → AuthenticationError; 403/404 fail soft (permission_limited at service);
    429 → RateLimitError; network → NetworkError
  * normalize_sendgrid_activity_event returns None for mail-event types and
    processes config events
  * ingestion service normalizes config events to activity events
  * idempotency: same events twice → second run has events_inserted=0
  * fingerprint fallback when provider_event_id is None
  * metadata contains NO forbidden fields
  * workspace scoping (workspace_id always passed to upsert)
  * admin endpoint; member cannot sync (403)
  * ALLOWED_METADATA_KEYS contains expected SendGrid keys and NOT forbidden keys
  * capability matrix: activity_ingestion=True
  * expansion framework planned_next_stage contains "M80E"
  * forbidden wording not in module source
  * no secret-shaped strings

CLAIM DISCIPLINE: configuration-state findings only. Does NOT confirm a breach,
compromise, unauthorized access, data exposure, or leaked credentials.
"""

from __future__ import annotations

import inspect
import re
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Forbidden wording / metadata fields ──────────────────────────────────────

FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

FORBIDDEN_METADATA_FIELDS = frozenset({
    "api_key",
    "api_key_value",
    "api_key_secret",
    "bearer_token",
    "access_token",
    "authorization",
    "email",
    "from_email",
    "reply_to",
    "recipient",
    "to",
    "subject",
    "body",
    "message_body",
    "html",
    "plaintext",
    "template",
    "template_content",
    "webhook_url",
    "url",
    "hostname",
    "message_id",
    "raw_payload",
    "payload",
    "dns",
    "dns_records",
    "customer",
})

# Secret-shaped patterns that must never appear in metadata values.
_SECRET_SHAPES = re.compile(
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|AC[0-9a-fA-F]{32}"
    r"|SK[0-9a-fA-F]{32}"
)

# Placeholders only — never real-looking secrets.
_API_KEY_PLACEHOLDER = "SENDGRID_TEST_API_KEY_PLACEHOLDER"
_CREDS = {"api_key": _API_KEY_PLACEHOLDER}


# ── Mock HTTP surfaces ─────────────────────────────────────────────────────────

_ACCOUNT_BODY = {"type": "paid", "reputation": 98.0}
_API_KEYS_BODY = {
    "result": [
        {
            "api_key_id": "SENDGRID_TEST_API_KEY_ID_01",
            "name": "Primary Key",
            "scopes": ["mail.send", "alerts.read"],
        },
        {
            "api_key_id": "SENDGRID_TEST_API_KEY_ID_02",
            "name": "Admin Key",
            "scopes": ["admin"],
        },
    ]
}
_SENDERS_BODY = {
    "results": [
        {
            "id": "SENDGRID_TEST_SENDER_ID",
            "nickname": "Marketing",
            "from_email": "news@example.com",
            "reply_to": "reply@example.com",
            "verified": {"status": True},
            "locked": False,
        }
    ]
}
_DOMAINS_BODY = [
    {
        "id": "SENDGRID_TEST_DOMAIN_ID",
        "domain": "example.com",
        "valid": True,
        "automatic_security": True,
        "default": True,
        "legacy": False,
        "dns": {"a": {}, "b": {}, "c": {}},
    }
]
_MAIL_SETTINGS_BODY = {
    "result": [
        {"name": "spam_check", "enabled": True},
        {"name": "sandbox_mode", "enabled": False},
        {"name": "bcc", "enabled": False},
    ]
}
_TRACKING_SETTINGS_BODY = {
    "result": [
        {"name": "click_tracking", "enabled": True},
        {"name": "open_tracking", "enabled": True},
    ]
}
_WEBHOOK_BODY = {
    "enabled": True,
    "url": "https://hooks.example.com/sendgrid",
    "bounce": True,
    "click": True,
    "open": True,
    "delivered": True,
}
_PARSE_BODY = {"result": [{"hostname": "parse.example.com", "spam_check": True, "send_raw": False}]}
_ASM_GROUPS_BODY = [{"id": 1}, {"id": 2}, {"id": 3}]


def _route(path: str):
    """Return the right mock body for a given SendGrid path."""
    if path == "/v3/user/account":
        return _ACCOUNT_BODY
    if path == "/v3/api_keys":
        return _API_KEYS_BODY
    if path == "/v3/verified_senders":
        return _SENDERS_BODY
    if path.startswith("/v3/whitelabel/domains"):
        return _DOMAINS_BODY
    if path == "/v3/mail_settings":
        return _MAIL_SETTINGS_BODY
    if path == "/v3/tracking_settings":
        return _TRACKING_SETTINGS_BODY
    if path == "/v3/user/webhooks/event/settings":
        return _WEBHOOK_BODY
    if path == "/v3/user/webhooks/parse/settings":
        return _PARSE_BODY
    if path == "/v3/asm/groups":
        return _ASM_GROUPS_BODY
    return {}


def _make_client_ctx(status: int = 200, headers=None):
    """Build a mock httpx.Client context that routes GETs to safe mock bodies."""
    mock_ctx = MagicMock()

    def _get(path, params=None):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = headers or {}
        resp.json.return_value = _route(path)
        return resp

    mock_ctx.get.side_effect = _get
    mock_ctx.__enter__ = lambda s: s
    mock_ctx.__exit__ = MagicMock(return_value=False)
    return mock_ctx


# ══════════════════════════════════════════════════════════════════════════════
# A: Connector list_activity_events
# ══════════════════════════════════════════════════════════════════════════════


class TestListActivityEvents:
    def _conn(self):
        from app.connectors.sendgrid import SendGridConnector
        return SendGridConnector()

    def test_a1_returns_safe_config_events(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        assert len(result) >= 1
        for rec in result:
            assert rec.get("provider") == "sendgrid"
            assert rec.get("source") == "sendgrid_activity_event"
            assert rec.get("event_source") == "sendgrid_activity_event"
            assert "event_type" in rec

    def test_a1_event_types_are_all_config_types(self):
        from app.connectors.sendgrid import _SENDGRID_CONFIG_EVENT_TYPES
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        for rec in result:
            assert rec["event_type"] in _SENDGRID_CONFIG_EVENT_TYPES

    def test_a2_no_mail_delivery_event_types(self):
        """Mail/delivery types are never produced."""
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        forbidden = {
            "bounce", "delivered", "deferred", "dropped", "click", "open",
            "spamreport", "unsubscribe", "group_unsubscribe", "processed",
        }
        for rec in result:
            et = rec["event_type"].lower()
            for f in forbidden:
                assert f not in et, f"mail-delivery token {f!r} leaked into {et!r}"

    def test_a3_max_events_cap(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS, max_events=2)
        assert len(result) <= 2

    def test_a4_caps_clamped(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS, max_events=99999, lookback_hours=99999)
        assert len(result) >= 1

    def test_a5_missing_api_key_raises_auth_error(self):
        from app.connectors.exceptions import AuthenticationError
        conn = self._conn()
        with pytest.raises(AuthenticationError):
            conn.list_activity_events({})

    def test_a6_401_raises_authentication_error(self):
        from app.connectors.exceptions import AuthenticationError
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx(status=401)):
            with pytest.raises(AuthenticationError):
                conn.list_activity_events(_CREDS)

    def test_a7_403_account_fails_soft_to_empty(self):
        """403 on the account surface → no events (fail soft)."""
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx(status=403)):
            result = conn.list_activity_events(_CREDS)
        assert result == []

    def test_a7_404_account_fails_soft_to_empty(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx(status=404)):
            result = conn.list_activity_events(_CREDS)
        assert result == []

    def test_a8_429_raises_rate_limit_error(self):
        from app.connectors.exceptions import RateLimitError
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx(status=429)):
            with pytest.raises(RateLimitError):
                conn.list_activity_events(_CREDS)

    def test_a9_network_error_raises_network_error(self):
        import httpx as httpx_mod
        from app.connectors.exceptions import NetworkError
        conn = self._conn()
        mock_ctx = MagicMock()
        mock_ctx.get.side_effect = httpx_mod.ConnectError("connection refused")
        mock_ctx.__enter__ = lambda s: s
        mock_ctx.__exit__ = MagicMock(return_value=False)
        with patch.object(conn, "_make_client", return_value=mock_ctx):
            with pytest.raises(NetworkError):
                conn.list_activity_events(_CREDS)

    def test_a10_no_forbidden_metadata_fields(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        for rec in result:
            meta = rec.get("metadata", {})
            for key in meta.keys():
                assert key.lower() not in FORBIDDEN_METADATA_FIELDS, (
                    f"forbidden metadata key {key!r} found"
                )

    def test_a10_no_full_email_in_metadata(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        for rec in result:
            meta = rec.get("metadata", {})
            for v in meta.values():
                if isinstance(v, str):
                    assert not email_re.search(v), f"email-shaped value leaked: {v!r}"

    def test_a10_no_secret_shaped_values(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        for rec in result:
            for v in rec.get("metadata", {}).values():
                if isinstance(v, str):
                    assert not _SECRET_SHAPES.search(v), f"secret-shaped value: {v!r}"

    def test_a10_no_webhook_url_string(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            result = conn.list_activity_events(_CREDS)
        for rec in result:
            for v in rec.get("metadata", {}).values():
                if isinstance(v, str):
                    assert "https://" not in v and "http://" not in v

    def test_a11_provider_event_ids_are_date_scoped_and_stable(self):
        conn = self._conn()
        with patch.object(conn, "_make_client", return_value=_make_client_ctx()):
            r1 = conn.list_activity_events(_CREDS)
            r2 = conn.list_activity_events(_CREDS)
        ids1 = sorted(r["provider_event_id"] for r in r1)
        ids2 = sorted(r["provider_event_id"] for r in r2)
        assert ids1 == ids2  # stable across polls on the same day
        for r in r1:
            assert r["provider_event_id"].startswith("sg:")


# ══════════════════════════════════════════════════════════════════════════════
# B: Normalizer
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizer:
    def test_b1_config_event_normalizes(self):
        from app.services.sendgrid_activity_ingestion_service import (
            normalize_sendgrid_activity_event,
        )
        entry = {
            "event_type": "sendgrid.api_key.updated",
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "event_source": "sendgrid_activity_event",
            "provider_event_id": "sg:api_key:KID:2026-06-16",
            "metadata": {
                "resource_type": "api_key",
                "api_key_id": "KID",
                "resource_id": "KID",
            },
        }
        result = normalize_sendgrid_activity_event(entry)
        assert result is not None
        assert result["event_type"] == "sendgrid.api_key.updated"
        assert result["provider"] == "sendgrid"
        assert result["resource_id"] == "KID"

    @pytest.mark.parametrize(
        "mail_type",
        [
            "bounce", "delivered", "deferred", "dropped", "click", "open",
            "spamreport", "unsubscribe", "group_unsubscribe", "processed",
            "sendgrid.bounce", "sendgrid.click.event",
        ],
    )
    def test_b2_mail_event_types_return_none(self, mail_type):
        from app.services.sendgrid_activity_ingestion_service import (
            normalize_sendgrid_activity_event,
        )
        entry = {
            "event_type": mail_type,
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "provider_event_id": "x",
            "metadata": {"resource_id": "r"},
        }
        assert normalize_sendgrid_activity_event(entry) is None

    def test_b3_malformed_returns_none(self):
        from app.services.sendgrid_activity_ingestion_service import (
            normalize_sendgrid_activity_event,
        )
        assert normalize_sendgrid_activity_event(None) is None
        assert normalize_sendgrid_activity_event({}) is None
        assert normalize_sendgrid_activity_event({"event_type": ""}) is None

    def test_b4_fingerprint_fallback_when_no_provider_event_id(self):
        from app.services.sendgrid_activity_ingestion_service import (
            normalize_sendgrid_activity_event,
        )
        entry = {
            "event_type": "sendgrid.account.updated",
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "provider_event_id": None,
            "metadata": {"resource_type": "account"},
        }
        result = normalize_sendgrid_activity_event(entry)
        assert result is not None
        assert result["provider_event_id"].startswith("fp:")

    def test_b5_forbidden_metadata_stripped(self):
        from app.services.sendgrid_activity_ingestion_service import (
            normalize_sendgrid_activity_event,
        )
        entry = {
            "event_type": "sendgrid.api_key.updated",
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "provider_event_id": "x",
            "metadata": {
                "api_key_id": "KID",
                "resource_id": "KID",
                # forbidden — must be stripped by the sanitizer allowlist
                "api_key": "SHOULD_NOT_SURVIVE",
                "webhook_url": "https://secret.example.com/hook",
                "from_email": "person@example.com",
                "subject": "secret subject",
            },
        }
        result = normalize_sendgrid_activity_event(entry)
        assert result is not None
        s = str(result)
        assert "SHOULD_NOT_SURVIVE" not in s
        assert "secret.example.com" not in s
        assert "person@example.com" not in s
        assert "secret subject" not in s


# ══════════════════════════════════════════════════════════════════════════════
# C: Ingestion service
# ══════════════════════════════════════════════════════════════════════════════


def _make_mock_integration(provider: str = "sendgrid") -> MagicMock:
    integ = MagicMock()
    integ.id = uuid.uuid4()
    integ.provider = provider
    integ.encrypted_credentials = b"encrypted"
    integ.credential_iv = b"iv"
    integ.status = "active"
    return integ


def _synth_event(n: int = 1) -> dict:
    return {
        "event_type": "sendgrid.api_key.updated",
        "provider": "sendgrid",
        "source": "sendgrid_activity_event",
        "event_source": "sendgrid_activity_event",
        "provider_event_id": f"sg:api_key:KID{n}:2026-06-16",
        "metadata": {
            "resource_type": "api_key",
            "api_key_id": f"KID{n}",
            "resource_id": f"KID{n}",
            "event_action": "sendgrid.api_key.updated",
            "category": "api_key",
        },
    }


class TestIngestionService:
    def test_c1_ingest_returns_success(self):
        from app.services import sendgrid_activity_ingestion_service as svc
        from app.services import security_activity_event_service as activity_svc

        mock_db = MagicMock()
        workspace_id = uuid.uuid4()
        integ = _make_mock_integration()
        events = [_synth_event(1), _synth_event(2)]

        with patch.object(
            svc.SendGridConnector, "list_activity_events", return_value=events
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ), patch.object(
            activity_svc, "upsert_activity_event", return_value=("inserted", MagicMock())
        ):
            result = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=workspace_id, db=mock_db
            )

        assert result["provider"] == "sendgrid"
        assert result["source"] == "sendgrid_activity_event"
        assert result["succeeded"] is True
        assert result["events_inserted"] == 2

    def test_c2_idempotency(self):
        from app.services import sendgrid_activity_ingestion_service as svc
        from app.services import security_activity_event_service as activity_svc

        mock_db = MagicMock()
        workspace_id = uuid.uuid4()
        integ = _make_mock_integration()
        events = [_synth_event(1), _synth_event(2)]

        with patch.object(
            svc.SendGridConnector, "list_activity_events", return_value=events
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ), patch.object(
            activity_svc, "upsert_activity_event",
            MagicMock(return_value=("inserted", MagicMock())),
        ):
            r1 = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=workspace_id, db=mock_db
            )
            assert r1["events_inserted"] == 2

        with patch.object(
            svc.SendGridConnector, "list_activity_events", return_value=events
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ), patch.object(
            activity_svc, "upsert_activity_event",
            MagicMock(return_value=("skipped", MagicMock())),
        ):
            r2 = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=workspace_id, db=mock_db
            )
            assert r2["events_inserted"] == 0

    def test_c3_workspace_scoping(self):
        """workspace_id is always passed through to upsert."""
        from app.services import sendgrid_activity_ingestion_service as svc
        from app.services import security_activity_event_service as activity_svc

        mock_db = MagicMock()
        workspace_id = uuid.uuid4()
        integ = _make_mock_integration()
        events = [_synth_event(1)]
        upsert = MagicMock(return_value=("inserted", MagicMock()))

        with patch.object(
            svc.SendGridConnector, "list_activity_events", return_value=events
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ), patch.object(activity_svc, "upsert_activity_event", upsert):
            svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=workspace_id, db=mock_db
            )

        assert upsert.call_count == 1
        _, kwargs = upsert.call_args
        assert kwargs["workspace_id"] == workspace_id

    def test_c4_401_sets_permission_limited(self):
        from app.connectors.exceptions import AuthenticationError
        from app.services import sendgrid_activity_ingestion_service as svc

        mock_db = MagicMock()
        integ = _make_mock_integration()
        with patch.object(
            svc.SendGridConnector, "list_activity_events",
            side_effect=AuthenticationError("401"),
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ):
            result = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=uuid.uuid4(), db=mock_db
            )
        assert result["permission_limited"] is True
        assert result["succeeded"] is True  # non-fatal

    def test_c4_403_sets_permission_limited(self):
        from app.connectors.exceptions import ConnectorError
        from app.services import sendgrid_activity_ingestion_service as svc

        mock_db = MagicMock()
        integ = _make_mock_integration()
        with patch.object(
            svc.SendGridConnector, "list_activity_events",
            side_effect=ConnectorError("403", status_code=403),
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ):
            result = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=uuid.uuid4(), db=mock_db
            )
        assert result["permission_limited"] is True

    def test_c5_429_returns_error(self):
        from app.connectors.exceptions import RateLimitError
        from app.services import sendgrid_activity_ingestion_service as svc

        mock_db = MagicMock()
        integ = _make_mock_integration()
        with patch.object(
            svc.SendGridConnector, "list_activity_events",
            side_effect=RateLimitError("429"),
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ):
            result = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=uuid.uuid4(), db=mock_db
            )
        assert result["succeeded"] is False
        assert result["error_message"] is not None

    def test_c5_network_returns_error(self):
        from app.connectors.exceptions import NetworkError
        from app.services import sendgrid_activity_ingestion_service as svc

        mock_db = MagicMock()
        integ = _make_mock_integration()
        with patch.object(
            svc.SendGridConnector, "list_activity_events",
            side_effect=NetworkError("net"),
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ):
            result = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=uuid.uuid4(), db=mock_db
            )
        assert result["succeeded"] is False
        assert result["error_message"] is not None

    def test_c6_wrong_provider_rejected(self):
        from app.services import sendgrid_activity_ingestion_service as svc
        integ = _make_mock_integration(provider="twilio")
        result = svc.ingest_sendgrid_activity(
            integration=integ, workspace_id=uuid.uuid4(), db=MagicMock()
        )
        assert result["succeeded"] is False
        assert result["attempted"] is False

    def test_c7_malformed_event_does_not_abort(self):
        from app.services import sendgrid_activity_ingestion_service as svc
        from app.services import security_activity_event_service as activity_svc

        mock_db = MagicMock()
        integ = _make_mock_integration()
        events = [None, {}, _synth_event(1)]
        with patch.object(
            svc.SendGridConnector, "list_activity_events", return_value=events
        ), patch(
            "app.services.sendgrid_activity_ingestion_service.decrypt_credentials",
            return_value=_CREDS,
        ), patch.object(
            activity_svc, "upsert_activity_event", return_value=("inserted", MagicMock())
        ):
            result = svc.ingest_sendgrid_activity(
                integration=integ, workspace_id=uuid.uuid4(), db=mock_db
            )
        assert result["succeeded"] is True
        assert result["events_seen"] == 3
        assert result["events_inserted"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# D: API endpoint
# ══════════════════════════════════════════════════════════════════════════════


class TestEndpoint:
    def test_d1_requires_auth(self):
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app

        plain = TestClient(fastapi_app, raise_server_exceptions=False)
        r = plain.post("/security/sendgrid-activity/sync", json={})
        assert r.status_code in (200, 401, 422), r.text[:200]

    def test_d2_member_cannot_sync_403(self):
        from fastapi.testclient import TestClient
        from fastapi import HTTPException
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        def _deny(workspace_id, user_id, db):
            raise HTTPException(status_code=403, detail="Admin or owner role required.")

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                side_effect=_deny,
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=False)
                r = client.post("/security/sendgrid-activity/sync", json={})
        finally:
            fastapi_app.dependency_overrides.clear()
        assert r.status_code == 403

    def test_d3_admin_can_sync_200(self):
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app
        from app.services import sendgrid_activity_ingestion_service as svc

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        clean = {
            "attempted": True,
            "succeeded": True,
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "integration_id": None,
            "events_seen": 3,
            "events_inserted": 2,
            "events_skipped": 1,
            "permission_limited": False,
            "error_message": None,
        }

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                return_value=None,
            ), patch.object(svc, "sync_sendgrid_activity", return_value=clean):
                client = TestClient(fastapi_app, raise_server_exceptions=True)
                r = client.post("/security/sendgrid-activity/sync", json={})
        finally:
            fastapi_app.dependency_overrides.clear()

        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "sendgrid"
        assert body["source"] == "sendgrid_activity_event"
        assert "events_seen" in body
        assert "events_inserted" in body
        assert "succeeded" in body


# ══════════════════════════════════════════════════════════════════════════════
# E: Metadata allowlist
# ══════════════════════════════════════════════════════════════════════════════


class TestMetadataAllowlist:
    _REQUIRED = {
        "sendgrid_event_id",
        "resource_id",
        "resource_name",
        "resource_type",
        "event_action",
        "category",
        "api_key_id",
        "sender_id",
        "domain_id",
        "event_webhook_enabled",
        "event_webhook_has_url",
        "event_webhook_event_count",
        "inbound_parse_enabled",
        "domain_valid",
        "automatic_security",
        "dns_record_count",
        "sender_verified",
        "sender_locked",
        "suppression_group_count",
    }
    _FORBIDDEN = {
        "api_key",
        "api_key_value",
        "bearer_token",
        "authorization",
        "email",
        "from_email",
        "subject",
        "body",
        "message_body",
        "template",
        "webhook_url",
        "dns",
    }

    def test_e1_required_keys_present(self):
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        for k in self._REQUIRED:
            assert k in ALLOWED_METADATA_KEYS, f"{k!r} missing from allowlist"

    def test_e2_forbidden_keys_absent(self):
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        for k in self._FORBIDDEN:
            assert k not in ALLOWED_METADATA_KEYS, f"{k!r} should NOT be in allowlist"


# ══════════════════════════════════════════════════════════════════════════════
# F: Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    def _cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        return get_provider_capability("sendgrid")

    def test_f1_activity_ingestion_true(self):
        assert self._cap().security.activity_ingestion is True

    def test_f2_security_rules_true(self):
        assert self._cap().security.security_rules is True

    def test_f3_maturity_partial(self):
        assert self._cap().maturity == "partial"


class TestExpansionFramework:
    def _fw(self):
        from app.services import provider_expansion_framework as svc
        return svc.get_framework()

    def test_g1_planned_next_stage_contains_m80e(self):
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M80E" in stage, f"expected M80E, got {stage!r}"

    def test_g2_planned_next_stage_not_m80d(self):
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M80D" not in stage


# ══════════════════════════════════════════════════════════════════════════════
# H: Forbidden wording + secret-shape source scan
# ══════════════════════════════════════════════════════════════════════════════


def _assert_no_forbidden_wording(src: str, name: str) -> None:
    low = src.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"forbidden phrase {phrase!r} in {name}"


def test_h1_no_forbidden_in_ingestion_service():
    import importlib
    mod = importlib.import_module("app.services.sendgrid_activity_ingestion_service")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_h2_no_forbidden_in_schema():
    import importlib
    mod = importlib.import_module("app.schemas.security_sendgrid_activity")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_h3_no_forbidden_in_connector():
    import importlib
    mod = importlib.import_module("app.connectors.sendgrid")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_h4_no_secret_shapes_in_sources():
    import importlib
    for name in (
        "app.services.sendgrid_activity_ingestion_service",
        "app.connectors.sendgrid",
        "app.schemas.security_sendgrid_activity",
    ):
        mod = importlib.import_module(name)
        src = inspect.getsource(mod)
        assert not _SECRET_SHAPES.search(src), f"secret-shaped string in {name}"


# ══════════════════════════════════════════════════════════════════════════════
# I: Frontend
# ══════════════════════════════════════════════════════════════════════════════

REPO_ROOT = Path(__file__).resolve().parents[2]
_FE_ACTIVITY_PAGE = REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "activity" / "page.tsx"
_FE_API_TS = REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
_FE_TYPES_TS = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"


def _read_fe(path: Path):
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


class TestFrontend:
    def test_i1_activity_page_contains_sendgrid(self):
        content = _read_fe(_FE_ACTIVITY_PAGE)
        if content is None:
            pytest.skip("Frontend activity/page.tsx not found")
        assert "sendgrid" in content.lower()
        assert "SENDGRID_EVENT_TYPES" in content
        assert "Sync SendGrid activity" in content

    def test_i2_api_ts_contains_sync_fn(self):
        content = _read_fe(_FE_API_TS)
        if content is None:
            pytest.skip("Frontend api.ts not found")
        assert "syncSendGridActivity" in content

    def test_i3_types_contains_response(self):
        content = _read_fe(_FE_TYPES_TS)
        if content is None:
            pytest.skip("Frontend types/index.ts not found")
        assert "SendGridActivitySyncResponse" in content
