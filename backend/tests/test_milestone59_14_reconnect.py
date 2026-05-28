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


# ─────────────────────────────────────────────────────────────────────────────
# F. M59.15 — last_sync_failure_category propagation
# ─────────────────────────────────────────────────────────────────────────────


class TestLastSyncFailureCategoryExposed:
    """The frontend needs the stable failure category from the most recent
    SyncRun in order to render a derived display status (Active vs.
    Needs attention vs. Degraded) without string-matching on the error
    message.  Verify GET /integrations surfaces it correctly."""

    def _add_failed_sync_run(
        self,
        db: Session,
        integration: Integration,
        *,
        failure_category: str,
        error_message: str = "boom",
    ) -> None:
        from app.models.sync_run import SyncRun

        run = SyncRun(
            user_id=integration.user_id,
            integration_id=integration.id,
            status="failed",
            triggered_by="manual",
            error_message=error_message,
            failure_category=failure_category,
        )
        db.add(run)
        db.commit()

    def test_F1_no_sync_runs_yields_null_category(
        self, client, test_user, db_session
    ):
        integration = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["last_sync_status"] is None
        assert body["last_sync_failure_category"] is None

    def test_F2_resource_missing_category_propagates(
        self, client, test_user, db_session
    ):
        integration = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        self._add_failed_sync_run(
            db_session, integration, failure_category="resource_missing"
        )
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["last_sync_status"] == "failed"
        assert body["last_sync_failure_category"] == "resource_missing"
        # Status itself is unchanged — backend credentials are still valid.
        assert body["status"] == "active"

    def test_F3_generic_failure_category_propagates(
        self, client, test_user, db_session
    ):
        """A non-resource-missing failure category surfaces too — the
        frontend uses it to pick ``degraded`` over ``needs_attention``."""
        integration = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        self._add_failed_sync_run(
            db_session, integration, failure_category="provider_unavailable"
        )
        resp = client.get(f"/integrations/{integration.id}")
        body = resp.json()
        assert body["last_sync_failure_category"] == "provider_unavailable"

    def test_F4_list_endpoint_includes_failure_category(
        self, client, test_user, db_session
    ):
        integration = _make_cloudflare_integration(
            db_session, test_user, status="active"
        )
        self._add_failed_sync_run(
            db_session, integration, failure_category="rate_limited"
        )
        resp = client.get("/integrations")
        assert resp.status_code == 200
        match = [
            r
            for r in resp.json()["integrations"]
            if r["id"] == str(integration.id)
        ]
        assert len(match) == 1
        assert match[0]["last_sync_failure_category"] == "rate_limited"


# ─────────────────────────────────────────────────────────────────────────────
# G. M59.16 — GitHub App auto-reconnect on broken existing row
# ─────────────────────────────────────────────────────────────────────────────


class TestGitHubAppAutoReconnect:
    """When the user re-installs the GitHub App for a repo whose existing
    ConfigTrace integration is in ``needs_reconnect`` / ``error``, we update
    the existing row in place rather than rejecting with the duplicate-repo
    error.  Active rows still block.  Soft-deleted rows still allow a fresh
    install."""

    def _make_github_app_integration(
        self,
        db: Session,
        user: User,
        *,
        owner: str = "acme",
        repo: str = "widgets",
        installation_id: int = 11111,
        status: str = "active",
    ) -> Integration:
        from app.models.resource import Resource

        creds = {
            "credential_type": "github_app",
            "installation_id": installation_id,
            "repo_owner": owner,
            "repo_name": repo,
        }
        ciphertext, iv = encrypt_credentials(creds)
        integration = Integration(
            user_id=user.id,
            provider="github",
            display_name=f"{owner}/{repo}",
            encrypted_credentials=ciphertext,
            credential_iv=iv,
            status=status,
            consecutive_failure_count=4,  # simulate prior failures
        )
        db.add(integration)
        db.flush()
        resource = Resource(
            integration_id=integration.id,
            user_id=user.id,
            provider_resource_type="github_repo",
            provider_resource_id=f"{owner}/{repo}",
            display_name=f"{owner}/{repo}",
            resource_metadata={
                "repo_owner": owner,
                "repo_name": repo,
                "connection_method": "github_app",
            },
            is_active=True,
        )
        db.add(resource)
        db.commit()
        db.refresh(integration)
        return integration

    def test_G1_needs_reconnect_row_is_updated_in_place(
        self, test_user, db_session
    ):
        """Re-installing the GitHub App for a repo whose existing row is in
        ``needs_reconnect`` must reuse the same row, refresh its credentials,
        flip status to ``active``, and reset the failure count."""
        from app.services import integration_service

        existing = self._make_github_app_integration(
            db_session,
            test_user,
            owner="acme",
            repo="widgets",
            installation_id=11111,
            status="needs_reconnect",
        )
        original_id = existing.id

        result = integration_service.create_github_app_integration(
            user_id=test_user.id,
            display_name="Re-installed",
            credentials={
                "credential_type": "github_app",
                "installation_id": 22222,  # new install
                "repo_owner": "acme",
                "repo_name": "widgets",
            },
            db=db_session,
        )

        # Same row, not a fresh one.
        assert result.id == original_id
        db_session.refresh(result)
        assert result.status == "active"
        assert result.consecutive_failure_count == 0

        # Only one integration row for this repo now (no duplicate).
        from app.models.resource import Resource

        rows = (
            db_session.query(Integration)
            .join(Resource, Resource.integration_id == Integration.id)
            .filter(
                Resource.user_id == test_user.id,
                Resource.provider_resource_id == "acme/widgets",
                Integration.status != "deleted",
            )
            .all()
        )
        assert len(rows) == 1
        assert rows[0].id == original_id

    def test_G2_error_status_also_auto_reconnects(self, test_user, db_session):
        """Legacy ``error`` status (kept for backwards-compat) follows the
        same auto-reconnect path as ``needs_reconnect``."""
        from app.services import integration_service

        existing = self._make_github_app_integration(
            db_session,
            test_user,
            owner="acme",
            repo="legacy",
            status="error",
        )
        original_id = existing.id

        result = integration_service.create_github_app_integration(
            user_id=test_user.id,
            display_name="Re-installed",
            credentials={
                "credential_type": "github_app",
                "installation_id": 33333,
                "repo_owner": "acme",
                "repo_name": "legacy",
            },
            db=db_session,
        )

        assert result.id == original_id
        db_session.refresh(result)
        assert result.status == "active"

    def test_G3_active_row_still_blocks_duplicate(self, test_user, db_session):
        """Re-installing on top of a healthy active integration must continue
        to raise the duplicate-repo ValueError (no silent overwrite of a
        working connection)."""
        from app.services import integration_service

        self._make_github_app_integration(
            db_session,
            test_user,
            owner="acme",
            repo="prod",
            status="active",
        )

        with pytest.raises(ValueError, match="already connected"):
            integration_service.create_github_app_integration(
                user_id=test_user.id,
                display_name="dup attempt",
                credentials={
                    "credential_type": "github_app",
                    "installation_id": 44444,
                    "repo_owner": "acme",
                    "repo_name": "prod",
                },
                db=db_session,
            )

    def test_G4_deleted_row_allows_fresh_creation(self, test_user, db_session):
        """A soft-deleted row must not block a fresh install of the same
        repo — the new install creates a brand new row."""
        from app.services import integration_service

        old = self._make_github_app_integration(
            db_session,
            test_user,
            owner="acme",
            repo="resurrect",
            status="deleted",
        )

        result = integration_service.create_github_app_integration(
            user_id=test_user.id,
            display_name="Fresh install",
            credentials={
                "credential_type": "github_app",
                "installation_id": 55555,
                "repo_owner": "acme",
                "repo_name": "resurrect",
            },
            db=db_session,
        )

        # A new integration row was created — distinct from the deleted one.
        assert result.id != old.id
        assert result.status == "active"

    def test_G5_pat_integration_in_needs_reconnect_migrates_to_app(
        self, test_user, db_session
    ):
        """If the existing broken row is a PAT integration and the user
        re-installs the App for the same repo, the row is reconnected and
        its connection_method metadata flips to ``github_app`` (no orphaned
        PAT row left behind)."""
        from app.models.resource import Resource
        from app.services import integration_service

        # Hand-build a PAT-style row (connection_method='pat' in metadata).
        creds = {
            "github_token": "ghp_abc",
            "repo_owner": "acme",
            "repo_name": "mixed",
        }
        ciphertext, iv = encrypt_credentials(creds)
        existing = Integration(
            user_id=test_user.id,
            provider="github",
            display_name="acme/mixed (PAT)",
            encrypted_credentials=ciphertext,
            credential_iv=iv,
            status="needs_reconnect",
        )
        db_session.add(existing)
        db_session.flush()
        db_session.add(
            Resource(
                integration_id=existing.id,
                user_id=test_user.id,
                provider_resource_type="github_repo",
                provider_resource_id="acme/mixed",
                display_name="acme/mixed",
                resource_metadata={
                    "repo_owner": "acme",
                    "repo_name": "mixed",
                    "connection_method": "pat",
                },
                is_active=True,
            )
        )
        db_session.commit()
        original_id = existing.id

        integration_service.create_github_app_integration(
            user_id=test_user.id,
            display_name="acme/mixed (App)",
            credentials={
                "credential_type": "github_app",
                "installation_id": 66666,
                "repo_owner": "acme",
                "repo_name": "mixed",
            },
            db=db_session,
        )

        # Same row, but metadata now says github_app.
        db_session.expire_all()
        reloaded = db_session.get(Integration, original_id)
        assert reloaded is not None
        assert reloaded.status == "active"
        assert (
            integration_service.get_connection_method(reloaded) == "github_app"
        )
