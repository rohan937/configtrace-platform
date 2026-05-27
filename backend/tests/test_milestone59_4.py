"""M59.4 — Abuse protection, rate limits, and edge hardening.

Verifies the four protections added in M59.4:
  A. Manual sync dedupe via ``has_in_flight_sync``.
  B. Test-notification cooldown via ``assert_test_notification_cooldown``.
  C. Stripe webhook event-id dedupe via ``StripeWebhookEvent``.
  D. DNS-rebinding protection in ``_validate_url``.

Strategy
--------
All tests run without PostgreSQL by mocking the SQLAlchemy session at the
service boundary.  The DNS-rebinding tests use the autouse
``deterministic_dns_stub`` fixture from ``conftest.py``, mutating
``_TEST_PRIVATE_HOSTS`` to flip a hostname's resolved IP per-case.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import _TEST_PRIVATE_HOSTS


# ═════════════════════════════════════════════════════════════════════════════
# A. Manual sync dedupe — POST /syncs returns 409 when has_in_flight_sync
# ═════════════════════════════════════════════════════════════════════════════


class TestManualSyncDedupe:

    def test_A1_router_calls_has_in_flight_sync(self):
        """Static check: the router imports and invokes the helper."""
        from pathlib import Path
        src = Path("app/routers/syncs.py").read_text()
        assert "sync_service.has_in_flight_sync(" in src

    def test_A2_409_returned_when_sync_already_running(self):
        """End-to-end behaviour via the router function: when
        ``has_in_flight_sync`` returns True, FastAPI raises 409."""
        from fastapi import HTTPException
        from app.routers.syncs import create_sync
        from app.schemas.sync import SyncCreateRequest

        # Build a SyncCreateRequest that points at a fake integration_id.
        body = SyncCreateRequest(integration_id=uuid.uuid4())
        db = MagicMock()

        # Mock integration ownership lookup → succeeds (active integration).
        integ = MagicMock()
        integ.status = "active"
        integ.id = body.integration_id

        with patch(
            "app.services.integration_service.get_integration_by_id",
            return_value=integ,
        ), patch(
            "app.services.sync_service.has_in_flight_sync",
            return_value=True,
        ):
            with pytest.raises(HTTPException) as exc:
                create_sync(
                    body=body,
                    db=db,
                    current_user=MagicMock(id=uuid.uuid4()),
                )
            assert exc.value.status_code == 409
            assert "in progress" in exc.value.detail.lower()

    def test_A3_first_manual_sync_proceeds_when_no_in_flight(self):
        from app.routers.syncs import create_sync
        from app.schemas.sync import SyncCreateRequest

        body = SyncCreateRequest(integration_id=uuid.uuid4())
        db = MagicMock()
        integ = MagicMock()
        integ.status = "active"
        integ.id = body.integration_id

        sync_run = MagicMock(id=uuid.uuid4(), integration_id=body.integration_id,
                             status="pending", started_at=datetime.now(timezone.utc))
        with patch(
            "app.services.integration_service.get_integration_by_id",
            return_value=integ,
        ), patch(
            "app.services.sync_service.has_in_flight_sync",
            return_value=False,
        ), patch(
            "app.services.sync_service.create_sync_run",
            return_value=sync_run,
        ), patch("app.workers.sync_task.sync_integration") as mock_task:
            mock_task.delay = MagicMock()
            result = create_sync(
                body=body,
                db=db,
                current_user=MagicMock(id=uuid.uuid4()),
            )
            assert result is sync_run
            mock_task.delay.assert_called_once()

    def test_A4_paused_integration_blocked_before_in_flight_check(self):
        """Order: paused check fires first so paused integrations get a clear
        409 message even when no sync is currently running."""
        from fastapi import HTTPException
        from app.routers.syncs import create_sync
        from app.schemas.sync import SyncCreateRequest

        body = SyncCreateRequest(integration_id=uuid.uuid4())
        db = MagicMock()
        integ = MagicMock()
        integ.status = "paused"
        with patch(
            "app.services.integration_service.get_integration_by_id",
            return_value=integ,
        ):
            with pytest.raises(HTTPException) as exc:
                create_sync(
                    body=body,
                    db=db,
                    current_user=MagicMock(id=uuid.uuid4()),
                )
            assert exc.value.status_code == 409
            assert "paused" in exc.value.detail.lower()

    def test_A5_unauthorized_integration_still_404(self):
        """Cross-workspace / unowned integration still 404s (not 409) — the
        ownership check runs before the dedupe gate."""
        from fastapi import HTTPException
        from app.routers.syncs import create_sync
        from app.schemas.sync import SyncCreateRequest

        body = SyncCreateRequest(integration_id=uuid.uuid4())
        db = MagicMock()
        with patch(
            "app.services.integration_service.get_integration_by_id",
            return_value=None,  # not owned or deleted
        ):
            with pytest.raises(HTTPException) as exc:
                create_sync(
                    body=body,
                    db=db,
                    current_user=MagicMock(id=uuid.uuid4()),
                )
            assert exc.value.status_code == 404


# ═════════════════════════════════════════════════════════════════════════════
# B. Test-notification cooldown
# ═════════════════════════════════════════════════════════════════════════════


class TestTestNotificationCooldown:

    def _row(self, last_test_at):
        row = MagicMock()
        row.workspace_id = uuid.uuid4()
        row.last_test_notification_at = last_test_at
        return row

    def test_B1_no_row_means_no_cooldown(self):
        from app.services.notification_service import (
            assert_test_notification_cooldown,
        )

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        # Should not raise.
        assert_test_notification_cooldown(uuid.uuid4(), db)

    def test_B2_recent_test_triggers_cooldown(self):
        from app.services.notification_service import (
            TestNotificationCooldownError,
            assert_test_notification_cooldown,
        )

        row = self._row(datetime.now(timezone.utc) - timedelta(seconds=5))
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = row
        with pytest.raises(TestNotificationCooldownError) as exc:
            assert_test_notification_cooldown(uuid.uuid4(), db)
        # retry_after is approx (60 - 5) = 55 seconds.
        assert 40 <= exc.value.retry_after <= 60

    def test_B3_old_test_does_not_trigger_cooldown(self):
        from app.services.notification_service import (
            assert_test_notification_cooldown,
        )

        row = self._row(datetime.now(timezone.utc) - timedelta(minutes=5))
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = row
        # 5 minutes >> 60 second window → no raise.
        assert_test_notification_cooldown(uuid.uuid4(), db)

    def test_B4_mark_creates_row_if_missing(self):
        from app.services.notification_service import (
            mark_test_notification_sent,
        )

        ws = uuid.uuid4()
        db = MagicMock()
        # No existing row.
        db.query.return_value.filter.return_value.first.return_value = None
        mark_test_notification_sent(ws, db)
        # A new WorkspaceNotificationSettings row was added.
        added = db.add.call_args[0][0]
        assert added.workspace_id == ws
        assert added.last_test_notification_at is not None

    def test_B5_mark_updates_existing_row(self):
        from app.services.notification_service import (
            mark_test_notification_sent,
        )

        row = self._row(None)
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = row
        mark_test_notification_sent(uuid.uuid4(), db)
        assert row.last_test_notification_at is not None
        # Did NOT add a new row.
        db.add.assert_not_called()

    @pytest.mark.parametrize(
        "endpoint_func",
        ["test_notification", "test_slack_app",
         "test_push_notification", "test_weekly_digest"],
    )
    def test_B6_all_four_test_endpoints_call_cooldown(self, endpoint_func):
        """Static: every router endpoint that sends a test message calls
        the cooldown helper before doing work, and the mark helper after."""
        from pathlib import Path
        src = Path("app/routers/workspaces.py").read_text()
        block = src.split(f"def {endpoint_func}(")[1].split("@router.")[0]
        assert "assert_test_notification_cooldown(" in block, (
            f"{endpoint_func} missing cooldown guard"
        )
        assert "mark_test_notification_sent(" in block, (
            f"{endpoint_func} missing mark-sent call"
        )

    def test_B7_cooldown_returns_429_with_retry_after(self):
        """The router converts TestNotificationCooldownError to 429 + Retry-After."""
        from pathlib import Path
        src = Path("app/routers/workspaces.py").read_text()
        # All four router blocks return 429 with Retry-After header.
        assert src.count("status_code=429") >= 4
        assert "Retry-After" in src


# ═════════════════════════════════════════════════════════════════════════════
# C. Stripe webhook event-id dedupe
# ═════════════════════════════════════════════════════════════════════════════


class TestStripeEventIdDedupe:

    def test_C1_model_exists_with_unique_event_id(self):
        from app.models.billing import StripeWebhookEvent

        # SQLAlchemy table reflection — confirm columns + uniqueness.
        cols = {c.name for c in StripeWebhookEvent.__table__.columns}
        assert {"id", "event_id", "event_type", "processed_at"} <= cols
        # event_id column is unique.
        event_col = StripeWebhookEvent.__table__.columns["event_id"]
        assert event_col.unique is True

    def test_C2_migration_creates_table_and_unique_index(self):
        from pathlib import Path
        text = Path("alembic/versions/018_m594_abuse_protection.py").read_text()
        assert 'create_table(\n        "stripe_webhook_events"' in text
        assert "ix_stripe_webhook_events_event_id" in text
        assert "unique=True" in text

    def test_C3_duplicate_event_id_short_circuits(self):
        """When the event_id is already in stripe_webhook_events, the handler
        returns early without dispatching to any per-type branch."""
        from app.services.billing_service import handle_webhook_event

        existing = MagicMock()
        existing.event_id = "evt_dup"
        db = MagicMock()
        # First query (StripeWebhookEvent lookup) returns existing.
        db.query.return_value.filter.return_value.first.return_value = existing

        # If the function tried to dispatch, it would call _billing_by_customer
        # (which would call db.query again).  Patch that to assert it never runs.
        with patch(
            "app.services.billing_service._handle_subscription_updated"
        ) as h_updated:
            handle_webhook_event(
                {"id": "evt_dup", "type": "customer.subscription.updated",
                 "data": {"object": {"id": "sub_x", "customer": "cus_x"}}},
                db,
            )
            h_updated.assert_not_called()

    def test_C4_new_event_id_processed_and_recorded(self):
        from app.services.billing_service import handle_webhook_event
        from app.models.billing import StripeWebhookEvent

        db = MagicMock()
        # No existing dedupe row.
        db.query.return_value.filter.return_value.first.return_value = None

        with patch(
            "app.services.billing_service._handle_subscription_updated"
        ) as h_updated:
            handle_webhook_event(
                {"id": "evt_new", "type": "customer.subscription.updated",
                 "data": {"object": {"id": "sub_x", "customer": "cus_x"}}},
                db,
            )
            h_updated.assert_called_once()

        # A StripeWebhookEvent row was added.
        added = [c.args[0] for c in db.add.call_args_list
                 if isinstance(c.args[0], StripeWebhookEvent)]
        assert len(added) == 1
        assert added[0].event_id == "evt_new"
        assert added[0].event_type == "customer.subscription.updated"

    def test_C5_event_without_id_still_processed_no_dedupe_row(self):
        """Test events from Stripe sometimes lack an id (older API).  The
        handler still processes them; no dedupe row is added."""
        from app.services.billing_service import handle_webhook_event
        from app.models.billing import StripeWebhookEvent

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch(
            "app.services.billing_service._handle_subscription_updated"
        ) as h_updated:
            handle_webhook_event(
                {"type": "customer.subscription.updated",
                 "data": {"object": {"id": "sub_x", "customer": "cus_x"}}},
                db,
            )
            h_updated.assert_called_once()
        # No StripeWebhookEvent rows added because event_id is missing.
        added = [c.args[0] for c in db.add.call_args_list
                 if isinstance(c.args[0], StripeWebhookEvent)]
        assert added == []

    def test_C6_dedupe_check_uses_event_id_field(self):
        """Static: the dedupe lookup filters on StripeWebhookEvent.event_id."""
        import inspect
        from app.services import billing_service
        src = inspect.getsource(billing_service.handle_webhook_event)
        assert "StripeWebhookEvent.event_id == event_id" in src


# ═════════════════════════════════════════════════════════════════════════════
# D. DNS-rebinding protection in _validate_url
# ═════════════════════════════════════════════════════════════════════════════


class TestDNSRebindingProtection:

    def test_D1_helper_exists(self):
        from app.services.notification_service import (
            _assert_hostname_resolves_public,
        )
        assert callable(_assert_hostname_resolves_public)

    def test_D2_hostname_resolving_to_public_ip_accepted(self):
        """Default stub returns 93.184.216.34 (public) for any host."""
        from app.services.notification_service import _validate_url

        _validate_url("https://hooks.example.com/intake", slack=False)

    @pytest.mark.parametrize(
        "private_ip",
        [
            "127.0.0.1",
            "10.0.0.5",
            "10.255.255.255",
            "172.16.0.10",
            "192.168.1.1",
            "169.254.169.254",  # AWS metadata
            "0.0.0.0",
        ],
    )
    def test_D3_hostname_resolving_to_private_ipv4_rejected(self, private_ip):
        from app.services.notification_service import _validate_url, WebhookURLError

        host = "evil.example.com"
        _TEST_PRIVATE_HOSTS[host] = private_ip
        try:
            with pytest.raises(WebhookURLError):
                _validate_url(f"https://{host}/hook", slack=False)
        finally:
            _TEST_PRIVATE_HOSTS.pop(host, None)

    def test_D4_dns_failure_fails_closed(self, monkeypatch):
        from app.services.notification_service import _validate_url, WebhookURLError
        import socket

        def _gaierror(*_a, **_kw):
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", _gaierror)
        with pytest.raises(WebhookURLError, match="could not be resolved"):
            _validate_url("https://unknown.example.com/hook", slack=False)

    def test_D5_empty_result_set_rejected(self, monkeypatch):
        from app.services.notification_service import _validate_url, WebhookURLError
        import socket

        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [])
        with pytest.raises(WebhookURLError, match="did not resolve"):
            _validate_url("https://empty.example.com/hook", slack=False)

    def test_D6_slack_url_skips_dns_resolution(self, monkeypatch):
        """Slack URLs go through the prefix check; we trust the hostname.
        Even if the resolver would return a private IP, the Slack path
        must still succeed (otherwise CI without network breaks)."""
        from app.services.notification_service import _validate_url
        import socket

        # Simulate a hostile resolver — Slack path should not call it.
        def _boom(*_a, **_kw):
            raise AssertionError(
                "getaddrinfo should not be called for slack=True URLs"
            )

        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        # No exception expected.
        _validate_url("https://hooks.slack.com/services/T/B/abc", slack=True)

    def test_D7_literal_ip_still_uses_existing_check(self):
        """Literal IPs short-circuit via _PRIVATE_NETWORKS without DNS."""
        from app.services.notification_service import _validate_url, WebhookURLError

        # Existing M59.3 protection: literal 127.0.0.1 rejected.
        with pytest.raises(WebhookURLError):
            _validate_url("https://127.0.0.1/hook", slack=False)


# ═════════════════════════════════════════════════════════════════════════════
# E. Notification service module-level surface (regression sanity)
# ═════════════════════════════════════════════════════════════════════════════


class TestNotificationServiceSurface:

    def test_E1_cooldown_helpers_exported_at_module_level(self):
        from app.services import notification_service

        assert hasattr(notification_service, "assert_test_notification_cooldown")
        assert hasattr(notification_service, "mark_test_notification_sent")
        assert hasattr(notification_service, "TestNotificationCooldownError")

    def test_E2_cooldown_error_carries_retry_after(self):
        from app.services.notification_service import TestNotificationCooldownError

        err = TestNotificationCooldownError(retry_after=42)
        assert err.retry_after == 42
        assert "42s" in str(err)

    def test_E3_cooldown_constant_is_at_most_5_minutes(self):
        """Sanity: cooldown is short enough to be operator-friendly."""
        from app.services.notification_service import _TEST_NOTIFICATION_COOLDOWN
        assert 30 <= _TEST_NOTIFICATION_COOLDOWN <= 300
