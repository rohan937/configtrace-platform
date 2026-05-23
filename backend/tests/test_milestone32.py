"""Milestone 32 tests — Sync Reliability, Failure Classification, Paginated
Sync History, and Failure Alerts.

Coverage areas
--------------
1. Failure classifier: maps exception types to categories/codes/actions.
2. ``mark_sync_failed`` with classification fields.
3. ``increment_consecutive_failures`` and ``reset_consecutive_failures``.
4. Paginated ``get_recent_sync_runs`` with status/trigger filters.
5. ``GET /integrations/{id}/sync-runs`` pagination and filter query params.
6. ``IntegrationResponse`` includes ``consecutive_failure_count`` and
   ``needs_attention``.
7. Failure alert policy: threshold, cooldown, scheduled-only.
8. ``sync_integration`` task: classification written to SyncRun on failure.
9. ``sync_integration`` task: consecutive counter reset on success.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.failure_classifier import (
    FAILURE_ALERT_COOLDOWN_SECONDS,
    NEEDS_ATTENTION_THRESHOLD,
    FailureClassification,
    classify_failure,
)
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.sync_run import SyncRun
from app.models.user import User
from app.core.encryption import encrypt_credentials
from app.services.sync_service import (
    increment_consecutive_failures,
    mark_sync_failed,
    reset_consecutive_failures,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_cloudflare_integration(db: Session, user: User) -> Integration:
    zone = f"zone_{uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"CF {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db.add(integration)
    db.flush()
    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=zone,
        display_name=f"CF {zone} (DNS Zone)",
        resource_metadata={"zone_id": zone},
        is_active=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(integration)
    return integration


def _make_sync_run(
    db: Session,
    integration: Integration,
    *,
    triggered_by: str = "scheduled",
    status: str = "pending",
) -> SyncRun:
    run = SyncRun(
        integration_id=integration.id,
        user_id=integration.user_id,
        triggered_by=triggered_by,
        status=status,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _cleanup(db: Session, user: User) -> None:
    try:
        db.delete(user)
        db.commit()
    except Exception:
        db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# Module-level fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def test_integration(db_session: Session, test_user: User) -> Integration:
    """A live Cloudflare integration owned by test_user, cleaned up automatically."""
    return _make_cloudflare_integration(db_session, test_user)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Failure classifier
# ─────────────────────────────────────────────────────────────────────────────


class TestFailureClassifier:
    """Unit tests for app.core.failure_classifier.classify_failure."""

    def _cf(self, exc, provider="cloudflare", cred_type=None) -> FailureClassification:
        return classify_failure(exc, provider, cred_type)

    # ── AuthenticationError ───────────────────────────────────────────────────

    def test_auth_error_github_pat(self):
        from app.connectors.exceptions import AuthenticationError

        result = self._cf(AuthenticationError("bad token"), "github", "pat")
        assert result.category == "authentication"
        assert result.error_code == "github_token_revoked"
        assert "Personal Access Token" in result.recommended_action

    def test_auth_error_github_app(self):
        from app.connectors.exceptions import AuthenticationError

        result = self._cf(AuthenticationError("app uninstalled"), "github", "github_app")
        assert result.category == "authentication"
        assert result.error_code == "github_app_uninstalled"
        assert "GitHub App" in result.recommended_action

    def test_auth_error_github_no_cred_type(self):
        from app.connectors.exceptions import AuthenticationError

        result = self._cf(AuthenticationError("bad"), "github", None)
        assert result.category == "authentication"
        assert result.error_code == "github_token_revoked"

    def test_auth_error_cloudflare(self):
        from app.connectors.exceptions import AuthenticationError

        result = self._cf(AuthenticationError("bad token"), "cloudflare")
        assert result.category == "authentication"
        assert result.error_code == "cloudflare_token_revoked"

    # ── RateLimitError ────────────────────────────────────────────────────────

    def test_rate_limit_error(self):
        from app.connectors.exceptions import RateLimitError

        result = self._cf(RateLimitError("429"), "github")
        assert result.category == "rate_limited"
        assert result.error_code == "rate_limit_exceeded"

    # ── ConnectorError 404 ────────────────────────────────────────────────────

    def test_connector_404_github(self):
        from app.connectors.exceptions import ConnectorError

        exc = ConnectorError("Not found", status_code=404)
        result = self._cf(exc, "github")
        assert result.category == "resource_missing"
        assert result.error_code == "github_repo_not_found"

    def test_connector_404_cloudflare(self):
        from app.connectors.exceptions import ConnectorError

        exc = ConnectorError("Not found", status_code=404)
        result = self._cf(exc, "cloudflare")
        assert result.category == "resource_missing"
        assert result.error_code == "cloudflare_zone_not_found"

    # ── ConnectorError 5xx ────────────────────────────────────────────────────

    def test_connector_502_github(self):
        from app.connectors.exceptions import ConnectorError

        exc = ConnectorError("Server error", status_code=502)
        result = self._cf(exc, "github")
        assert result.category == "provider_unavailable"
        assert result.error_code == "github_api_unavailable"

    def test_connector_503_cloudflare(self):
        from app.connectors.exceptions import ConnectorError

        exc = ConnectorError("Service unavailable", status_code=503)
        result = self._cf(exc, "cloudflare")
        assert result.category == "provider_unavailable"
        assert result.error_code == "cloudflare_api_unavailable"

    # ── NetworkError ──────────────────────────────────────────────────────────

    def test_network_error(self):
        from app.connectors.exceptions import NetworkError

        result = self._cf(NetworkError("connection refused"), "github")
        assert result.category == "network"
        assert result.error_code == "network_error"

    # ── ValueError (config) ───────────────────────────────────────────────────

    def test_value_error_config(self):
        result = self._cf(ValueError("GitHub App private key could not be parsed"), "github")
        assert result.category == "config_error"
        assert result.error_code == "config_error"

    # ── RuntimeError (App JWT/token minting) ──────────────────────────────────

    def test_runtime_error_auth_hint(self):
        result = self._cf(
            RuntimeError("GitHub App authentication failed (HTTP 401)"),
            "github",
            "github_app",
        )
        assert result.category == "authentication"

    def test_runtime_error_generic(self):
        result = self._cf(RuntimeError("unexpected error"), "github")
        assert result.category == "provider_unavailable"
        assert result.error_code == "github_api_unavailable"

    # ── Unknown exception ─────────────────────────────────────────────────────

    def test_unknown_exception(self):
        result = self._cf(Exception("something weird"), "github")
        assert result.category == "unknown"
        assert result.error_code == "unknown"

    # ── Constants ─────────────────────────────────────────────────────────────

    def test_needs_attention_threshold(self):
        assert NEEDS_ATTENTION_THRESHOLD == 3

    def test_cooldown_is_24h(self):
        assert FAILURE_ALERT_COOLDOWN_SECONDS == 86_400


# ─────────────────────────────────────────────────────────────────────────────
# 2. mark_sync_failed with classification fields
# ─────────────────────────────────────────────────────────────────────────────


class TestMarkSyncFailed:
    def test_stores_classification_fields(self, db_session, test_integration):
        run = _make_sync_run(db_session, test_integration)

        mark_sync_failed(
            run.id,
            error_message="Connection refused",
            failure_category="network",
            error_code="network_error",
            recommended_action="Check connectivity.",
            db=db_session,
        )

        db_session.refresh(run)
        assert run.status == "failed"
        assert run.failure_category == "network"
        assert run.error_code == "network_error"
        assert run.recommended_action == "Check connectivity."
        assert run.error_message == "Connection refused"

    def test_omitting_classification_leaves_nulls(self, db_session, test_integration):
        run = _make_sync_run(db_session, test_integration)

        mark_sync_failed(run.id, error_message="error", db=db_session)

        db_session.refresh(run)
        assert run.status == "failed"
        assert run.failure_category is None
        assert run.error_code is None
        assert run.recommended_action is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Consecutive failure tracking
# ─────────────────────────────────────────────────────────────────────────────


class TestConsecutiveFailures:
    def test_increment_returns_new_count(self, db_session, test_integration):
        assert test_integration.consecutive_failure_count == 0
        count = increment_consecutive_failures(test_integration.id, db_session)
        assert count == 1
        db_session.refresh(test_integration)
        assert test_integration.consecutive_failure_count == 1

    def test_increment_accumulates(self, db_session, test_integration):
        increment_consecutive_failures(test_integration.id, db_session)
        increment_consecutive_failures(test_integration.id, db_session)
        count = increment_consecutive_failures(test_integration.id, db_session)
        assert count == 3
        db_session.refresh(test_integration)
        assert test_integration.consecutive_failure_count == 3

    def test_increment_sets_last_failure_at(self, db_session, test_integration):
        before = datetime.now(timezone.utc)
        increment_consecutive_failures(test_integration.id, db_session)
        db_session.refresh(test_integration)
        assert test_integration.last_failure_at is not None
        assert test_integration.last_failure_at >= before

    def test_reset_clears_count(self, db_session, test_integration):
        increment_consecutive_failures(test_integration.id, db_session)
        increment_consecutive_failures(test_integration.id, db_session)
        reset_consecutive_failures(test_integration.id, db_session)
        db_session.refresh(test_integration)
        assert test_integration.consecutive_failure_count == 0

    def test_reset_on_zero_is_noop(self, db_session, test_integration):
        """Resetting when already 0 does not raise."""
        reset_consecutive_failures(test_integration.id, db_session)
        db_session.refresh(test_integration)
        assert test_integration.consecutive_failure_count == 0

    def test_increment_missing_integration_returns_zero(self, db_session):
        count = increment_consecutive_failures(uuid.uuid4(), db_session)
        assert count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4 + 5. Paginated sync runs — service and router
# ─────────────────────────────────────────────────────────────────────────────


class TestPaginatedSyncRuns:
    """Tests for get_recent_sync_runs (service) and GET /integrations/{id}/sync-runs."""

    def _create_runs(
        self,
        db: Session,
        integration: Integration,
        *,
        count: int,
        triggered_by: str = "manual",
        status: str = "completed",
    ):
        for _ in range(count):
            _make_sync_run(db, integration, triggered_by=triggered_by, status=status)

    # ── Service layer ─────────────────────────────────────────────────────────

    def test_pagination_basic(self, db_session, test_integration):
        from app.services.integration_service import get_recent_sync_runs

        self._create_runs(db_session, test_integration, count=15)
        runs, total = get_recent_sync_runs(
            integration_id=test_integration.id,
            user_id=test_integration.user_id,
            page=1,
            page_size=10,
            db=db_session,
        )
        assert total == 15
        assert len(runs) == 10

    def test_pagination_page2(self, db_session, test_integration):
        from app.services.integration_service import get_recent_sync_runs

        self._create_runs(db_session, test_integration, count=15)
        runs, total = get_recent_sync_runs(
            integration_id=test_integration.id,
            user_id=test_integration.user_id,
            page=2,
            page_size=10,
            db=db_session,
        )
        assert total == 15
        assert len(runs) == 5

    def test_status_filter(self, db_session, test_integration):
        from app.services.integration_service import get_recent_sync_runs

        self._create_runs(db_session, test_integration, count=5, status="completed")
        self._create_runs(db_session, test_integration, count=3, status="failed")

        runs, total = get_recent_sync_runs(
            integration_id=test_integration.id,
            user_id=test_integration.user_id,
            status_filter="failed",
            db=db_session,
        )
        assert total == 3
        assert all(r.status == "failed" for r in runs)

    def test_trigger_filter(self, db_session, test_integration):
        from app.services.integration_service import get_recent_sync_runs

        self._create_runs(db_session, test_integration, count=4, triggered_by="manual")
        self._create_runs(db_session, test_integration, count=6, triggered_by="scheduled")

        runs, total = get_recent_sync_runs(
            integration_id=test_integration.id,
            user_id=test_integration.user_id,
            trigger_filter="scheduled",
            db=db_session,
        )
        assert total == 6
        assert all(r.triggered_by == "scheduled" for r in runs)

    def test_legacy_limit_arg(self, db_session, test_integration):
        from app.services.integration_service import get_recent_sync_runs

        self._create_runs(db_session, test_integration, count=20)
        runs, total = get_recent_sync_runs(
            integration_id=test_integration.id,
            user_id=test_integration.user_id,
            limit=5,
            db=db_session,
        )
        assert total == 20
        assert len(runs) == 5

    # ── Router layer (API) ───────────────────────────────────────────────────

    def test_api_pagination_defaults(self, client, test_integration, db_session):
        self._create_runs(db_session, test_integration, count=5)
        resp = client.get(f"/integrations/{test_integration.id}/sync-runs")
        assert resp.status_code == 200
        body = resp.json()
        assert "sync_runs" in body
        assert "total" in body
        assert "page" in body
        assert "page_size" in body
        assert "total_pages" in body
        assert body["page"] == 1
        assert body["page_size"] == 25

    def test_api_page_size_param(self, client, test_integration, db_session):
        self._create_runs(db_session, test_integration, count=10)
        resp = client.get(
            f"/integrations/{test_integration.id}/sync-runs",
            params={"page_size": 3, "page": 1},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["sync_runs"]) == 3
        assert body["total"] == 10
        assert body["total_pages"] == 4  # ceil(10/3)

    def test_api_status_filter(self, client, test_integration, db_session):
        self._create_runs(db_session, test_integration, count=3, status="completed")
        self._create_runs(db_session, test_integration, count=2, status="failed")
        resp = client.get(
            f"/integrations/{test_integration.id}/sync-runs",
            params={"status": "failed"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert all(r["status"] == "failed" for r in body["sync_runs"])

    def test_api_trigger_filter(self, client, test_integration, db_session):
        self._create_runs(db_session, test_integration, count=4, triggered_by="manual")
        self._create_runs(db_session, test_integration, count=2, triggered_by="scheduled")
        resp = client.get(
            f"/integrations/{test_integration.id}/sync-runs",
            params={"trigger": "scheduled"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2

    def test_api_invalid_status_returns_400(self, client, test_integration):
        resp = client.get(
            f"/integrations/{test_integration.id}/sync-runs",
            params={"status": "not_a_status"},
        )
        assert resp.status_code == 400

    def test_api_invalid_trigger_returns_400(self, client, test_integration):
        resp = client.get(
            f"/integrations/{test_integration.id}/sync-runs",
            params={"trigger": "cron"},
        )
        assert resp.status_code == 400

    def test_api_failure_fields_in_response(self, client, test_integration, db_session):
        run = _make_sync_run(db_session, test_integration)
        mark_sync_failed(
            run.id,
            error_message="Connection timed out",
            failure_category="network",
            error_code="network_error",
            recommended_action="Check server connectivity.",
            db=db_session,
        )
        resp = client.get(f"/integrations/{test_integration.id}/sync-runs")
        assert resp.status_code == 200
        runs = resp.json()["sync_runs"]
        failed = next((r for r in runs if r["id"] == str(run.id)), None)
        assert failed is not None
        assert failed["failure_category"] == "network"
        assert failed["error_code"] == "network_error"
        assert failed["recommended_action"] == "Check server connectivity."

    def test_api_page2_returns_correct_slice(self, client, test_integration, db_session):
        self._create_runs(db_session, test_integration, count=8)
        resp = client.get(
            f"/integrations/{test_integration.id}/sync-runs",
            params={"page": 2, "page_size": 5},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["sync_runs"]) == 3   # 8 - 5 = 3
        assert body["page"] == 2
        assert body["total_pages"] == 2


# ─────────────────────────────────────────────────────────────────────────────
# 6. IntegrationResponse health fields
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegrationHealthFields:
    def test_consecutive_failure_count_zero_by_default(self, client, test_integration):
        resp = client.get(f"/integrations/{test_integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["consecutive_failure_count"] == 0
        assert body["needs_attention"] is False

    def test_needs_attention_true_at_threshold(self, db_session, client, test_integration):
        for _ in range(NEEDS_ATTENTION_THRESHOLD):
            increment_consecutive_failures(test_integration.id, db_session)

        resp = client.get(f"/integrations/{test_integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["consecutive_failure_count"] == NEEDS_ATTENTION_THRESHOLD
        assert body["needs_attention"] is True

    def test_needs_attention_false_below_threshold(self, db_session, client, test_integration):
        for _ in range(NEEDS_ATTENTION_THRESHOLD - 1):
            increment_consecutive_failures(test_integration.id, db_session)

        resp = client.get(f"/integrations/{test_integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["needs_attention"] is False

    def test_needs_attention_clears_after_reset(self, db_session, client, test_integration):
        for _ in range(NEEDS_ATTENTION_THRESHOLD):
            increment_consecutive_failures(test_integration.id, db_session)
        reset_consecutive_failures(test_integration.id, db_session)

        resp = client.get(f"/integrations/{test_integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["consecutive_failure_count"] == 0
        assert body["needs_attention"] is False

    def test_list_endpoint_includes_health_fields(self, client):
        resp = client.get("/integrations")
        assert resp.status_code == 200
        for integration in resp.json()["integrations"]:
            assert "consecutive_failure_count" in integration
            assert "needs_attention" in integration


# ─────────────────────────────────────────────────────────────────────────────
# 7. Failure alert policy
# ─────────────────────────────────────────────────────────────────────────────


class TestFailureAlertPolicy:
    """Tests for sync_failure_alert_service.maybe_send_failure_alert."""

    def _make_failed_run(self, db: Session, integration: Integration) -> SyncRun:
        run = _make_sync_run(db, integration, triggered_by="scheduled")
        mark_sync_failed(
            run.id,
            error_message="Some error",
            failure_category="network",
            error_code="network_error",
            recommended_action="Check connectivity.",
            db=db,
        )
        db.refresh(run)
        return run

    def _svc(self):
        from app.services.sync_failure_alert_service import maybe_send_failure_alert
        return maybe_send_failure_alert

    def test_no_email_below_threshold(self, db_session, test_integration):
        run = self._make_failed_run(db_session, test_integration)
        with patch("app.services.sync_failure_alert_service.email_service") as mock_email:
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD - 1,
                db=db_session,
            )
        assert result is False
        mock_email.send_email.assert_not_called()

    def test_sends_email_at_threshold(self, db_session, test_integration, monkeypatch):
        run = self._make_failed_run(db_session, test_integration)

        from app import config
        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_fake_key")
        monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", "alerts@example.com")
        monkeypatch.setattr(config.settings, "APP_BASE_URL", "https://app.configtrace.org")

        with patch("app.services.sync_failure_alert_service.email_service") as mock_email:
            mock_email.send_email.return_value = {"id": "msg-123"}
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD,
                db=db_session,
            )
        assert result is True
        mock_email.send_email.assert_called_once()
        db_session.refresh(test_integration)
        assert test_integration.last_failure_alert_sent_at is not None

    def test_cooldown_suppresses_second_alert(self, db_session, test_integration, monkeypatch):
        run = self._make_failed_run(db_session, test_integration)

        from app import config
        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_fake_key")
        monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", "alerts@example.com")
        monkeypatch.setattr(config.settings, "APP_BASE_URL", "https://app.configtrace.org")

        # Simulate cooldown already active (sent < 24h ago)
        test_integration.last_failure_alert_sent_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        )
        db_session.commit()

        with patch("app.services.sync_failure_alert_service.email_service") as mock_email:
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD + 5,
                db=db_session,
            )
        assert result is False
        mock_email.send_email.assert_not_called()

    def test_alert_sent_after_cooldown_expires(self, db_session, test_integration, monkeypatch):
        run = self._make_failed_run(db_session, test_integration)

        from app import config
        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_fake_key")
        monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", "alerts@example.com")
        monkeypatch.setattr(config.settings, "APP_BASE_URL", "https://app.configtrace.org")

        # Cooldown has expired (sent > 24h ago)
        test_integration.last_failure_alert_sent_at = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        )
        db_session.commit()

        with patch("app.services.sync_failure_alert_service.email_service") as mock_email:
            mock_email.send_email.return_value = {"id": "msg-456"}
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD + 2,
                db=db_session,
            )
        assert result is True
        mock_email.send_email.assert_called_once()

    def test_no_alert_when_email_not_configured(self, db_session, test_integration, monkeypatch):
        run = self._make_failed_run(db_session, test_integration)

        from app import config
        monkeypatch.setattr(config.settings, "RESEND_API_KEY", None)
        monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", None)

        with patch("app.services.sync_failure_alert_service.email_service") as mock_email:
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD,
                db=db_session,
            )
        assert result is False
        mock_email.send_email.assert_not_called()

    def test_no_alert_for_placeholder_email(
        self, db_session, test_integration, test_user, monkeypatch
    ):
        run = self._make_failed_run(db_session, test_integration)

        # Make the user's email a Clerk placeholder
        real_email = test_user.email
        test_user.email = f"user_{test_user.id}@clerk.user"
        db_session.commit()

        from app import config
        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_fake_key")
        monkeypatch.setattr(config.settings, "ALERTS_FROM_EMAIL", "alerts@example.com")
        monkeypatch.setattr(config.settings, "APP_BASE_URL", "https://app.configtrace.org")

        with patch("app.services.sync_failure_alert_service.email_service") as mock_email:
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD,
                db=db_session,
            )
        assert result is False
        mock_email.send_email.assert_not_called()

        # Restore email
        test_user.email = real_email
        db_session.commit()

    def test_never_raises_on_exception(self, db_session, test_integration):
        """maybe_send_failure_alert must never raise."""
        run = self._make_failed_run(db_session, test_integration)

        with patch(
            "app.services.sync_failure_alert_service._attempt_alert",
            side_effect=RuntimeError("Boom"),
        ):
            result = self._svc()(
                integration=test_integration,
                sync_run=run,
                consecutive_count=NEEDS_ATTENTION_THRESHOLD,
                db=db_session,
            )
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# 8 + 9. sync_integration task — classification and counter reset
# ─────────────────────────────────────────────────────────────────────────────


class TestSyncIntegrationTask:
    """Integration tests for the Celery task with M32 additions.

    Strategy
    --------
    We call ``sync_integration.apply(args=(...))`` which runs the task
    synchronously in the current process (Celery's eager mode), allowing
    monkeypatching of module-level names.  The task uses its own real
    ``SessionLocal`` session so it can commit and close without affecting the
    test's ``db_session``.

    After the task completes we call ``db_session.expire_all()`` to clear
    SQLAlchemy's identity-map cache, then re-fetch objects from the DB to
    verify the committed state.
    """

    def _create_resource(self, db: Session, integration: Integration) -> Resource:
        res = Resource(
            integration_id=integration.id,
            user_id=integration.user_id,
            provider_resource_type="cloudflare_dns_zone",
            provider_resource_id=f"zone-{uuid.uuid4().hex[:8]}",
            display_name="zone",
            is_active=True,
        )
        db.add(res)
        db.commit()
        return res

    # ── Classification written on failure ─────────────────────────────────────

    def test_auth_error_writes_classification(self, db_session, test_integration, monkeypatch):
        from app.connectors.exceptions import AuthenticationError
        from app.models.sync_run import SyncRun as _SyncRun
        from app.workers.sync_task import sync_integration

        run = _make_sync_run(db_session, test_integration)
        self._create_resource(db_session, test_integration)

        monkeypatch.setattr(
            "app.workers.sync_task.CloudflareConnector",
            lambda: MagicMock(
                fetch=MagicMock(side_effect=AuthenticationError("bad token"))
            ),
        )
        monkeypatch.setattr(
            "app.workers.sync_task.decrypt_credentials",
            lambda *a: {"api_token": "x", "zone_id": "z"},
        )

        result = sync_integration.apply(
            args=(str(run.id), str(test_integration.id), str(test_integration.user_id))
        )
        assert result.failed(), "Task should have failed with AuthenticationError"
        assert isinstance(result.result, AuthenticationError)

        db_session.expire_all()
        refreshed = db_session.get(_SyncRun, run.id)
        assert refreshed is not None
        assert refreshed.status == "failed"
        assert refreshed.failure_category == "authentication"
        assert refreshed.error_code == "cloudflare_token_revoked"

    # ── Consecutive counter incremented on scheduled failure ──────────────────

    def test_scheduled_failure_increments_counter(
        self, db_session, test_integration, monkeypatch
    ):
        from app.connectors.exceptions import NetworkError
        from app.models.integration import Integration as _Integration
        from app.workers.sync_task import sync_integration

        run = _make_sync_run(db_session, test_integration, triggered_by="scheduled")
        self._create_resource(db_session, test_integration)

        monkeypatch.setattr(
            "app.workers.sync_task.CloudflareConnector",
            lambda: MagicMock(fetch=MagicMock(side_effect=NetworkError("timeout"))),
        )
        monkeypatch.setattr(
            "app.workers.sync_task.decrypt_credentials",
            lambda *a: {"api_token": "x", "zone_id": "z"},
        )

        result = sync_integration.apply(
            args=(str(run.id), str(test_integration.id), str(test_integration.user_id))
        )
        assert result.failed(), "Task should have failed with NetworkError"

        db_session.expire_all()
        refreshed = db_session.get(_Integration, test_integration.id)
        assert refreshed is not None
        assert refreshed.consecutive_failure_count == 1

    # ── Manual failure does NOT increment counter ─────────────────────────────

    def test_manual_failure_does_not_increment_counter(
        self, db_session, test_integration, monkeypatch
    ):
        from app.connectors.exceptions import NetworkError
        from app.models.integration import Integration as _Integration
        from app.workers.sync_task import sync_integration

        run = _make_sync_run(db_session, test_integration, triggered_by="manual")
        self._create_resource(db_session, test_integration)

        monkeypatch.setattr(
            "app.workers.sync_task.CloudflareConnector",
            lambda: MagicMock(fetch=MagicMock(side_effect=NetworkError("timeout"))),
        )
        monkeypatch.setattr(
            "app.workers.sync_task.decrypt_credentials",
            lambda *a: {"api_token": "x", "zone_id": "z"},
        )

        result = sync_integration.apply(
            args=(str(run.id), str(test_integration.id), str(test_integration.user_id))
        )
        assert result.failed(), "Task should have failed with NetworkError"

        db_session.expire_all()
        refreshed = db_session.get(_Integration, test_integration.id)
        assert refreshed is not None
        assert refreshed.consecutive_failure_count == 0

    # ── Successful sync resets consecutive counter ────────────────────────────

    def test_successful_sync_resets_counter(
        self, db_session, test_integration, monkeypatch
    ):
        """After a successful sync the consecutive failure count is reset to 0."""
        from app.models.integration import Integration as _Integration
        from app.workers.sync_task import sync_integration

        # Pre-set the counter to simulate prior failures
        test_integration.consecutive_failure_count = 3
        db_session.commit()

        run = _make_sync_run(db_session, test_integration, triggered_by="scheduled")
        self._create_resource(db_session, test_integration)

        # Mock module-level imports in sync_task (CloudflareConnector, decrypt_credentials)
        monkeypatch.setattr(
            "app.workers.sync_task.CloudflareConnector",
            lambda: MagicMock(fetch=MagicMock(return_value={})),
        )
        monkeypatch.setattr(
            "app.workers.sync_task.decrypt_credentials",
            lambda *a: {"api_token": "x", "zone_id": "z"},
        )

        # dispatch_alerts_for_sync, get_latest_snapshot, and store_snapshot are
        # imported INSIDE the task function body (local imports), so they must
        # be patched at their canonical source module, not at sync_task.
        monkeypatch.setattr(
            "app.services.alert_service.dispatch_alerts_for_sync",
            lambda **kw: {"eligible": 0, "already_alerted": 0, "sent": 0, "recorded": 0, "failed": 0},
        )
        monkeypatch.setattr(
            "app.services.snapshot_service.get_latest_snapshot",
            lambda *a, **kw: None,
        )

        # store_snapshot returns (snap, False) → created=False skips the entire
        # diff block, so we can return a lightweight mock without a DB write.
        def fake_store(**kw):
            snap = MagicMock()
            snap.id = uuid.uuid4()
            return snap, False  # not created → no diff runs

        monkeypatch.setattr("app.services.snapshot_service.store_snapshot", fake_store)

        result = sync_integration.apply(
            args=(str(run.id), str(test_integration.id), str(test_integration.user_id))
        )
        assert result.successful(), f"Task should have succeeded, got: {result.result}"

        db_session.expire_all()
        refreshed = db_session.get(_Integration, test_integration.id)
        assert refreshed is not None
        assert refreshed.consecutive_failure_count == 0
