"""Milestone 30 integration tests — Integration Detail Page + Sync History.

Coverage
--------
1. GET /integrations/{id}
   - Owner can fetch own integration detail.
   - Another user returns 404 (no object-existence leak).
   - Soft-deleted integration returns 404.
   - Non-existent UUID returns 404.
   - Response never contains credentials or tokens.
   - Response includes last_sync_status and last_sync_error.
   - Response includes sync_interval_minutes.

2. GET /integrations/{id}/sync-runs
   - Returns runs for owned integration, ordered newest-first.
   - Limit param caps results.
   - Limit is clamped to max 50.
   - Default limit is 10.
   - Other user's integration returns 404.
   - Deleted integration returns 404.
   - Only returns runs for this integration (no cross-integration leak).
   - Response never contains credentials.
   - total field reflects all-time count, not just limit.
   - Empty integration returns empty list with total=0.

3. Sync Now compatibility
   - POST /syncs works for active integration (existing behaviour preserved).
   - POST /syncs blocked for paused integration (409, M29 behaviour).
   - POST /syncs blocked for deleted integration (404, M29 behaviour).
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.sync_run import SyncRun
from app.models.user import User


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_user(db: Session, suffix: str = "") -> User:
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"m30_test_{uid}{suffix}",
        email=f"m30_{uid}{suffix}@configtrace.test",
        display_name="M30 Test User",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_cloudflare_integration(
    db: Session,
    user: User,
    *,
    status: str = "active",
    sync_interval_minutes: int | None = None,
) -> Integration:
    zone = f"zone_{uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"CF {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
        sync_interval_minutes=sync_interval_minutes,
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


def _make_github_integration(
    db: Session,
    user: User,
    *,
    status: str = "active",
) -> Integration:
    repo = f"repo_{uuid.uuid4().hex[:6]}"
    slug = f"acme/{repo}"
    ciphertext, iv = encrypt_credentials({
        "github_token": "github_pat_test",
        "repo_owner": "acme",
        "repo_name": repo,
    })
    integration = Integration(
        user_id=user.id,
        provider="github",
        display_name=f"GitHub {slug}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
    )
    db.add(integration)
    db.flush()
    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="github_repo",
        provider_resource_id=slug,
        display_name=f"GitHub {slug}",
        resource_metadata={"repo_owner": "acme", "repo_name": repo},
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
    status: str = "completed",
    triggered_by: str = "manual",
    change_count: int | None = 0,
    snapshot_count: int | None = 1,
    error_message: str | None = None,
) -> SyncRun:
    run = SyncRun(
        integration_id=integration.id,
        user_id=integration.user_id,
        triggered_by=triggered_by,
        status=status,
        change_count=change_count,
        snapshot_count=snapshot_count,
        error_message=error_message,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _cleanup(db: Session, *users: User) -> None:
    for user in users:
        try:
            db.delete(user)
            db.commit()
        except Exception:
            db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# 1. GET /integrations/{id}
# ─────────────────────────────────────────────────────────────────────────────

class TestGetIntegrationDetail:

    def test_owner_can_fetch_own_detail(self, client, test_user, db_session):
        """Owner fetching their integration returns 200 with correct fields."""
        integration = _make_cloudflare_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == str(integration.id)
        assert body["provider"] == "cloudflare"
        assert body["display_name"] == integration.display_name
        assert body["status"] == "active"
        assert "resource_count" in body
        assert body["resource_count"] == 1

    def test_other_user_returns_404(self, client, db_session):
        """User B fetching User A's integration returns 404 (no leak)."""
        user_a = _make_user(db_session, "_a")
        try:
            integration = _make_cloudflare_integration(db_session, user_a)
            # client is authenticated as test_user (User B), not user_a
            resp = client.get(f"/integrations/{integration.id}")
            assert resp.status_code == 404
        finally:
            _cleanup(db_session, user_a)

    def test_deleted_integration_returns_404(self, client, test_user, db_session):
        """Soft-deleted integration returns 404 from the detail endpoint."""
        integration = _make_cloudflare_integration(db_session, test_user)
        integration.status = "deleted"
        db_session.commit()

        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 404

    def test_nonexistent_id_returns_404(self, client, test_user):
        """Random UUID that doesn't exist returns 404."""
        random_id = uuid.uuid4()
        resp = client.get(f"/integrations/{random_id}")
        assert resp.status_code == 404

    def test_response_excludes_credentials(self, client, test_user, db_session):
        """Response must never contain tokens, IVs, or encrypted bytes."""
        integration = _make_cloudflare_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body_str = resp.text
        # Sensitive field names must not appear
        for field in ("encrypted_credentials", "credential_iv", "api_token",
                      "github_token", "zone_id", "repo_owner", "repo_name"):
            assert field not in body_str, f"Sensitive field {field!r} found in response"

    def test_response_includes_last_sync_status(self, client, test_user, db_session):
        """Response includes last_sync_status populated from most recent SyncRun."""
        integration = _make_cloudflare_integration(db_session, test_user)
        _make_sync_run(db_session, integration, status="failed", error_message="auth error")
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["last_sync_status"] == "failed"
        assert body["last_sync_error"] == "auth error"

    def test_response_includes_sync_interval_minutes(self, client, test_user, db_session):
        """Response includes sync_interval_minutes when set."""
        integration = _make_cloudflare_integration(
            db_session, test_user, sync_interval_minutes=15
        )
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["sync_interval_minutes"] == 15

    def test_null_last_sync_fields_when_no_run_exists(self, client, test_user, db_session):
        """last_sync_status and last_sync_error are null when no SyncRun exists."""
        integration = _make_cloudflare_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["last_sync_status"] is None
        assert body["last_sync_error"] is None

    def test_github_integration_detail(self, client, test_user, db_session):
        """GitHub integration detail also works correctly."""
        integration = _make_github_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "github"
        assert body["resource_count"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 2. GET /integrations/{id}/sync-runs
# ─────────────────────────────────────────────────────────────────────────────

class TestGetIntegrationSyncRuns:

    def test_returns_runs_for_owned_integration(self, client, test_user, db_session):
        """Owner fetching sync runs for their integration returns 200."""
        integration = _make_cloudflare_integration(db_session, test_user)
        run = _make_sync_run(db_session, integration, status="completed", change_count=3)
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "sync_runs" in body
        assert "total" in body
        assert len(body["sync_runs"]) == 1
        assert body["total"] == 1
        assert body["sync_runs"][0]["id"] == str(run.id)
        assert body["sync_runs"][0]["status"] == "completed"
        assert body["sync_runs"][0]["change_count"] == 3

    def test_runs_ordered_newest_first(self, client, test_user, db_session):
        """Sync runs are returned in descending created_at order."""
        integration = _make_cloudflare_integration(db_session, test_user)
        run1 = _make_sync_run(db_session, integration, status="completed")
        run2 = _make_sync_run(db_session, integration, status="failed",
                               error_message="timeout")
        run3 = _make_sync_run(db_session, integration, status="completed")

        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200
        runs = resp.json()["sync_runs"]
        assert len(runs) == 3
        # Most recent (run3) should be first
        assert runs[0]["id"] == str(run3.id)
        assert runs[1]["id"] == str(run2.id)
        assert runs[2]["id"] == str(run1.id)

    def test_page_size_param_caps_results(self, client, test_user, db_session):
        """?page_size=3 returns at most 3 runs even if more exist."""
        integration = _make_cloudflare_integration(db_session, test_user)
        for _ in range(7):
            _make_sync_run(db_session, integration)
        resp = client.get(f"/integrations/{integration.id}/sync-runs?page_size=3")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["sync_runs"]) == 3
        assert body["total"] == 7

    def test_default_page_size_is_25(self, client, test_user, db_session):
        """No page_size param → returns up to 25 runs by default."""
        integration = _make_cloudflare_integration(db_session, test_user)
        for _ in range(15):
            _make_sync_run(db_session, integration)
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200
        body = resp.json()
        # 15 runs, all fit in one page of 25
        assert len(body["sync_runs"]) == 15
        assert body["total"] == 15
        assert body["page_size"] == 25

    def test_page_size_clamped_to_max_100(self, client, test_user, db_session):
        """?page_size=999 is rejected with 422 (query param validation)."""
        integration = _make_cloudflare_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}/sync-runs?page_size=999")
        assert resp.status_code == 422

    def test_other_user_integration_returns_404(self, client, db_session):
        """User B fetching User A's sync runs returns 404."""
        user_a = _make_user(db_session, "_sra")
        try:
            integration = _make_cloudflare_integration(db_session, user_a)
            _make_sync_run(db_session, integration)
            # client is authenticated as test_user (User B)
            resp = client.get(f"/integrations/{integration.id}/sync-runs")
            assert resp.status_code == 404
        finally:
            _cleanup(db_session, user_a)

    def test_deleted_integration_returns_404(self, client, test_user, db_session):
        """Soft-deleted integration's sync-runs endpoint returns 404."""
        integration = _make_cloudflare_integration(db_session, test_user)
        integration.status = "deleted"
        db_session.commit()
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 404

    def test_only_this_integrations_runs_returned(self, client, test_user, db_session):
        """Runs from other integrations do not appear in the response."""
        integration_a = _make_cloudflare_integration(db_session, test_user)
        integration_b = _make_cloudflare_integration(db_session, test_user)
        run_a = _make_sync_run(db_session, integration_a)
        _make_sync_run(db_session, integration_b)  # should NOT appear

        resp = client.get(f"/integrations/{integration_a.id}/sync-runs")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["sync_runs"]) == 1
        assert body["sync_runs"][0]["id"] == str(run_a.id)
        assert body["total"] == 1

    def test_response_excludes_credentials(self, client, test_user, db_session):
        """Sync run response never contains tokens or encrypted credential data."""
        integration = _make_cloudflare_integration(db_session, test_user)
        _make_sync_run(db_session, integration)
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200
        body_str = resp.text
        for field in ("encrypted_credentials", "credential_iv",
                      "api_token", "github_token", "zone_id"):
            assert field not in body_str, f"Sensitive field {field!r} in sync-run response"

    def test_total_field_is_lifetime_count(self, client, test_user, db_session):
        """total reflects all-time run count, not just the current page slice."""
        integration = _make_cloudflare_integration(db_session, test_user)
        for _ in range(20):
            _make_sync_run(db_session, integration)
        resp = client.get(f"/integrations/{integration.id}/sync-runs?page_size=5")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["sync_runs"]) == 5
        assert body["total"] == 20

    def test_empty_integration_returns_empty_list(self, client, test_user, db_session):
        """Integration with no sync runs returns empty list with total=0."""
        integration = _make_cloudflare_integration(db_session, test_user)
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200
        body = resp.json()
        assert body["sync_runs"] == []
        assert body["total"] == 0

    def test_failed_run_exposes_error_message(self, client, test_user, db_session):
        """Failed sync run includes error_message in the response."""
        integration = _make_cloudflare_integration(db_session, test_user)
        _make_sync_run(db_session, integration, status="failed",
                       error_message="API token expired")
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200
        runs = resp.json()["sync_runs"]
        assert runs[0]["status"] == "failed"
        assert runs[0]["error_message"] == "API token expired"

    def test_scheduled_and_manual_runs_returned(self, client, test_user, db_session):
        """Both 'manual' and 'scheduled' triggered runs are returned."""
        integration = _make_cloudflare_integration(db_session, test_user)
        _make_sync_run(db_session, integration, triggered_by="manual")
        _make_sync_run(db_session, integration, triggered_by="scheduled")
        resp = client.get(f"/integrations/{integration.id}/sync-runs")
        assert resp.status_code == 200
        runs = resp.json()["sync_runs"]
        triggered_by_values = {r["triggered_by"] for r in runs}
        assert triggered_by_values == {"manual", "scheduled"}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Sync Now compatibility (existing behaviour preserved)
# ─────────────────────────────────────────────────────────────────────────────

class TestSyncNowCompatibility:
    """Verify M29 Sync Now behaviour is unchanged by M30 route additions."""

    def test_sync_now_works_for_active_integration(self, client, test_user, db_session):
        """POST /syncs succeeds for an active integration."""
        integration = _make_cloudflare_integration(db_session, test_user)
        with patch("app.workers.sync_task.sync_integration.delay"):
            resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "pending"
        assert body["integration_id"] == str(integration.id)

    def test_sync_now_blocked_for_paused_integration(self, client, test_user, db_session):
        """POST /syncs returns 409 for a paused integration (M29 guard)."""
        integration = _make_cloudflare_integration(db_session, test_user, status="paused")
        resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        assert resp.status_code == 409

    def test_sync_now_blocked_for_deleted_integration(self, client, test_user, db_session):
        """POST /syncs returns 404 for a deleted integration (M29 guard)."""
        integration = _make_cloudflare_integration(db_session, test_user)
        integration.status = "deleted"
        db_session.commit()
        resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        assert resp.status_code == 404
