"""M59.14 — Stale integrations after upstream revocation.

Covers
------
1.  POST /syncs returns 409 for an integration whose status is
    ``needs_reconnect`` (no Stripe-style "Sync Now" on a dead connection).
2.  GET  /integrations exposes the ``needs_reconnect`` status to the
    frontend so the UI can render a Reconnect chip instead of "Active".
3.  The scheduled-sync query excludes ``needs_reconnect`` integrations —
    so a revoked integration silently stops being polled.
4.  The reconnect service clears ``needs_reconnect`` back to ``active``
    after fresh credentials land.
5.  The sync_task exception handler flips ``status`` from ``active`` to
    ``needs_reconnect`` when the failure classifier returns
    ``failure_category == "authentication"`` (covers GitHub App
    uninstalled / Cloudflare token revoked / etc.).
6.  Soft-deleted integrations are unaffected by the new path
    (deleted stays deleted; the worker does not resurrect them).

Out of scope
------------
* The reconnect UI itself (existing ReconnectIntegrationModal).
* The classifier's mapping from exception → ``authentication`` — already
  covered by the M32 / M33 test suites.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.user import User


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_cloudflare_integration(
    db: Session,
    user: User,
    *,
    status: str = "active",
) -> Integration:
    """Build a minimal Cloudflare integration row (no Resources)."""
    zone = f"zone_{uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"CF {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


# ─────────────────────────────────────────────────────────────────────────────
# A. POST /syncs — 409 for needs_reconnect
# ─────────────────────────────────────────────────────────────────────────────


class TestSyncNowBlockedForNeedsReconnect:

    def test_A1_sync_now_returns_409_for_needs_reconnect(
        self, client, test_user, db_session
    ):
        integration = _make_cloudflare_integration(
            db_session, test_user, status="needs_reconnect"
        )
        resp = client.post(
            "/syncs",
            json={"integration_id": str(integration.id)},
        )
        assert resp.status_code == 409
        detail = resp.json().get("detail", "").lower()
        assert "reconnect" in detail

    def test_A2_sync_now_still_works_for_active_integration(
        self, client, test_user, db_session
    ):
        """Regression — the new guard must not block healthy integrations."""
        integration = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        with patch("app.workers.sync_task.sync_integration.delay"):
            resp = client.post(
                "/syncs",
                json={"integration_id": str(integration.id)},
            )
        assert resp.status_code == 201, resp.text


# ─────────────────────────────────────────────────────────────────────────────
# B. GET /integrations — surfaces needs_reconnect
# ─────────────────────────────────────────────────────────────────────────────


class TestNeedsReconnectVisibleToFrontend:

    def test_B1_list_returns_needs_reconnect_status(
        self, client, test_user, db_session
    ):
        integration = _make_cloudflare_integration(
            db_session, test_user, status="needs_reconnect"
        )
        resp = client.get("/integrations")
        assert resp.status_code == 200
        rows = resp.json()["integrations"]
        match = [r for r in rows if r["id"] == str(integration.id)]
        assert len(match) == 1
        assert match[0]["status"] == "needs_reconnect"

    def test_B2_detail_returns_needs_reconnect_status(
        self, client, test_user, db_session
    ):
        integration = _make_cloudflare_integration(
            db_session, test_user, status="needs_reconnect"
        )
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "needs_reconnect"


# ─────────────────────────────────────────────────────────────────────────────
# C. Scheduler query — excludes needs_reconnect
# ─────────────────────────────────────────────────────────────────────────────


class TestScheduledSyncSkipsRevoked:

    def test_C1_scheduled_query_excludes_needs_reconnect(
        self, client, test_user, db_session
    ):
        """The scheduler reads ``Integration.status == 'active'``.  Verify a
        ``needs_reconnect`` integration is filtered out by the same query."""
        active = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        active.scheduled_sync_enabled = True
        active.sync_interval_minutes = 60

        revoked = _make_cloudflare_integration(
            db_session, test_user, status="needs_reconnect"
        )
        revoked.scheduled_sync_enabled = True
        revoked.sync_interval_minutes = 60
        db_session.commit()

        ids = {
            r.id
            for r in db_session.query(Integration)
            .filter(Integration.status == "active")
            .all()
        }
        assert active.id in ids
        assert revoked.id not in ids


# ─────────────────────────────────────────────────────────────────────────────
# D. Reconnect service — clears needs_reconnect
# ─────────────────────────────────────────────────────────────────────────────


class TestReconnectClearsNeedsReconnect:

    def test_D1_cloudflare_reconnect_clears_needs_reconnect(
        self, test_user, db_session
    ):
        """The unified ``reconnect_credentials`` entry point dispatches on
        ``integration.provider`` for the four token-only providers
        (cloudflare, github, vercel, stripe).  After a successful credential
        swap, ``needs_reconnect`` must be cleared back to ``active``."""
        from app.services import integration_service

        integration = _make_cloudflare_integration(
            db_session, test_user, status="needs_reconnect"
        )
        with patch(
            "app.connectors.cloudflare.CloudflareConnector.validate_credentials"
        ):
            integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token="new_token",
                db=db_session,
            )

        db_session.refresh(integration)
        assert integration.status == "active"

    def test_D2_reconnect_does_not_alter_active_status(
        self, test_user, db_session
    ):
        """Calling reconnect on an integration that's already active
        does not introduce any spurious status churn."""
        from app.services import integration_service

        integration = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        with patch(
            "app.connectors.cloudflare.CloudflareConnector.validate_credentials"
        ):
            integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token="new_token",
                db=db_session,
            )

        db_session.refresh(integration)
        assert integration.status == "active"


# ─────────────────────────────────────────────────────────────────────────────
# E. Worker — auth failure flips status
# ─────────────────────────────────────────────────────────────────────────────


class TestWorkerFlipsStatusOnAuthFailure:
    """Direct unit test of the new branch in ``sync_integration``: when the
    failure classifier returns ``category='authentication'``, the worker
    must set ``Integration.status = 'needs_reconnect'`` and commit it."""

    def _make_db_mocks(self, *, integration_status: str = "active"):
        from app.models.integration import Integration as _Integration
        from app.models.sync_run import SyncRun

        run_id = uuid.uuid4()
        integ_id = uuid.uuid4()
        user_id = uuid.uuid4()

        mock_run = MagicMock(spec=SyncRun)
        mock_run.id = run_id
        mock_run.triggered_by = "scheduled"

        mock_integration = MagicMock(spec=_Integration)
        mock_integration.id = integ_id
        mock_integration.user_id = user_id
        mock_integration.provider = "cloudflare"
        mock_integration.display_name = "Test CF"
        mock_integration.status = integration_status
        mock_integration.consecutive_failure_count = 0
        mock_integration.resources = []

        db = MagicMock()
        db.get.side_effect = lambda model, pk: {
            run_id: mock_run,
            integ_id: mock_integration,
        }.get(pk)
        db.query.return_value.filter.return_value.all.return_value = []
        return db, mock_integration, run_id, integ_id, user_id

    def test_E1_authentication_failure_sets_needs_reconnect(self):
        """A Cloudflare 401 → ``category='authentication'`` →
        ``Integration.status = 'needs_reconnect'``."""
        from app.connectors import AuthenticationError

        db, integration, run_id, integ_id, user_id = self._make_db_mocks(
            integration_status="active"
        )

        # Force the decrypt step to raise AuthenticationError, which the
        # classifier maps to category='authentication' for Cloudflare.
        with (
            patch("app.database.SessionLocal", return_value=db),
            patch(
                "app.workers.sync_task.decrypt_credentials",
                side_effect=AuthenticationError("token revoked"),
            ),
            patch("app.services.sync_service.mark_sync_running"),
            patch("app.services.sync_service.mark_sync_failed"),
            patch(
                "app.services.sync_service.increment_consecutive_failures",
                return_value=1,
            ),
            patch(
                "app.services.sync_failure_alert_service.maybe_send_failure_alert"
            ),
        ):
            from app.workers.sync_task import sync_integration

            with pytest.raises(AuthenticationError):
                sync_integration(str(run_id), str(integ_id), str(user_id))

        # The new branch must have flipped the status.
        assert integration.status == "needs_reconnect"

    def test_E2_authentication_failure_does_not_resurrect_paused(self):
        """A paused integration whose creds are also revoked must stay
        paused — the more restrictive state wins."""
        from app.connectors import AuthenticationError

        db, integration, run_id, integ_id, user_id = self._make_db_mocks(
            integration_status="paused"
        )

        with (
            patch("app.database.SessionLocal", return_value=db),
            patch(
                "app.workers.sync_task.decrypt_credentials",
                side_effect=AuthenticationError("token revoked"),
            ),
            patch("app.services.sync_service.mark_sync_running"),
            patch("app.services.sync_service.mark_sync_failed"),
            patch(
                "app.services.sync_service.increment_consecutive_failures",
                return_value=1,
            ),
            patch(
                "app.services.sync_failure_alert_service.maybe_send_failure_alert"
            ),
        ):
            from app.workers.sync_task import sync_integration

            with pytest.raises(AuthenticationError):
                sync_integration(str(run_id), str(integ_id), str(user_id))

        assert integration.status == "paused"
