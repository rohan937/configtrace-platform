"""Milestone 34 tests — Dashboard Command Center + Settings.

Coverage areas
--------------
1. Settings defaults: GET /settings returns defaults for new users.
2. Settings persistence: PATCH /settings writes and returns updated values.
3. Settings user-scoping: settings rows are isolated per user.
4. Settings validation: invalid values return HTTP 422.
5. Settings secrets: no credential fields in any response.
6. Dashboard summary: GET /dashboard/summary returns correct structure.
7. Dashboard user-scoping: counts are scoped to the authenticated user.
8. Dashboard integration health: counts by status / attention state.
9. Dashboard resource counts: total and active.
10. Dashboard change activity: totals across time windows.
11. Dashboard risk distribution: counts per level.
12. Dashboard provider distribution: per-provider stats.
13. Dashboard recent changes: only high/critical, max 10.
14. Dashboard recent failed syncs: only integrations with recent failures.
15. Dashboard: last_updated_at is a valid ISO 8601 string.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.encryption import encrypt_credentials
from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.models.sync_run import SyncRun
from app.models.user import User
from app.models.user_settings import UserSettings
from app.services.settings_service import get_or_create_settings, update_settings


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_integration(
    db: Session,
    user: User,
    provider: str = "cloudflare",
    status: str = "active",
    consecutive_failures: int = 0,
    last_failure_at: datetime | None = None,
) -> Integration:
    ciphertext, iv = encrypt_credentials({"api_token": "tok", "zone_id": "z"})
    integ = Integration(
        user_id=user.id,
        provider=provider,
        display_name=f"{provider} {uuid.uuid4().hex[:6]}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
        consecutive_failure_count=consecutive_failures,
        last_failure_at=last_failure_at,
    )
    db.add(integ)
    db.flush()
    res = Resource(
        integration_id=integ.id,
        user_id=user.id,
        provider_resource_type=f"{provider}_dns_zone" if provider == "cloudflare" else f"{provider}_repo",
        provider_resource_id=f"rid_{uuid.uuid4().hex[:8]}",
        display_name=f"{provider} resource",
        resource_metadata={},
        is_active=True,
    )
    db.add(res)
    db.commit()
    db.refresh(integ)
    return integ


def _make_change(
    db: Session,
    user: User,
    integration: Integration,
    resource: Resource,
    risk_level: str = "medium",
    created_at: datetime | None = None,
) -> Change:
    """Insert a minimal Change row (no real snapshots — uses placeholder UUIDs)."""
    snap_id = uuid.uuid4()
    snap = Snapshot(
        id=snap_id,
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
        state=[],
    )
    db.add(snap)
    db.flush()

    snap2_id = uuid.uuid4()
    snap2 = Snapshot(
        id=snap2_id,
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
        state=[],
    )
    db.add(snap2)
    db.flush()

    now = created_at or datetime.now(timezone.utc)
    change = Change(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        prev_snapshot_id=snap_id,
        new_snapshot_id=snap2_id,
        change_type="modified",
        record_identifier="test.example.com",
        field_path="ttl",
        prev_value=300,
        new_value=600,
        risk_level=risk_level,
        risk_reason=f"Test {risk_level} change.",
        provider_metadata={"record_type": "A", "record_name": "test"},
    )
    db.add(change)
    db.commit()
    db.refresh(change)
    # Force the created_at if specified (bypass server default)
    if created_at is not None:
        db.execute(
            __import__("sqlalchemy").text(
                "UPDATE changes SET created_at = :ts WHERE id = :id"
            ),
            {"ts": created_at, "id": change.id},
        )
        db.commit()
        db.refresh(change)
    return change


def _make_sync_run(
    db: Session,
    user: User,
    integration: Integration,
    status: str = "completed",
    started_at: datetime | None = None,
    failure_category: str | None = None,
    error_code: str | None = None,
    recommended_action: str | None = None,
) -> SyncRun:
    now = started_at or datetime.now(timezone.utc)
    run = SyncRun(
        integration_id=integration.id,
        user_id=user.id,
        triggered_by="manual",
        status=status,
        started_at=now,
        failure_category=failure_category,
        error_code=error_code,
        recommended_action=recommended_action,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


# ─────────────────────────────────────────────────────────────────────────────
# Settings — defaults
# ─────────────────────────────────────────────────────────────────────────────


class TestSettingsDefaults:
    def test_get_settings_returns_200_for_new_user(self, client: TestClient) -> None:
        resp = client.get("/settings")
        assert resp.status_code == 200

    def test_get_settings_returns_correct_defaults(self, client: TestClient) -> None:
        data = client.get("/settings").json()
        # Alert policy defaults
        assert data["alert_risk_threshold"] == "high_and_critical"
        assert data["sync_failure_alerts_enabled"] is True
        assert data["sync_failure_threshold"] == 3
        assert data["sync_failure_cooldown_hours"] == 24
        # Sync defaults
        assert data["default_sync_enabled"] is False
        assert data["default_sync_interval_minutes"] == 60
        assert data["default_change_alerts_enabled"] is True
        # UI prefs
        assert data["default_timeline_range"] == "7d"
        assert data["default_provider_filter"] == "all"

    def test_get_settings_idempotent(self, client: TestClient) -> None:
        """Calling GET /settings twice should return the same data and not create duplicate rows."""
        r1 = client.get("/settings").json()
        r2 = client.get("/settings").json()
        assert r1 == r2

    def test_settings_no_credential_fields(self, client: TestClient) -> None:
        data = client.get("/settings").json()
        forbidden = {"api_token", "github_token", "vercel_token", "encrypted_credentials", "password"}
        assert not forbidden.intersection(set(data.keys()))


# ─────────────────────────────────────────────────────────────────────────────
# Settings — PATCH
# ─────────────────────────────────────────────────────────────────────────────


class TestSettingsPatch:
    def test_patch_alert_risk_threshold(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"alert_risk_threshold": "critical_only"})
        assert resp.status_code == 200
        assert resp.json()["alert_risk_threshold"] == "critical_only"

    def test_patch_medium_and_above_threshold(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"alert_risk_threshold": "medium_and_above"})
        assert resp.status_code == 200
        assert resp.json()["alert_risk_threshold"] == "medium_and_above"

    def test_patch_sync_failure_threshold(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_threshold": 5})
        assert resp.status_code == 200
        assert resp.json()["sync_failure_threshold"] == 5

    def test_patch_sync_failure_threshold_2(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_threshold": 2})
        assert resp.status_code == 200
        assert resp.json()["sync_failure_threshold"] == 2

    def test_patch_cooldown_hours(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_cooldown_hours": 6})
        assert resp.status_code == 200
        assert resp.json()["sync_failure_cooldown_hours"] == 6

    def test_patch_cooldown_hours_12(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_cooldown_hours": 12})
        assert resp.status_code == 200
        assert resp.json()["sync_failure_cooldown_hours"] == 12

    def test_patch_sync_failure_alerts_disabled(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_alerts_enabled": False})
        assert resp.status_code == 200
        assert resp.json()["sync_failure_alerts_enabled"] is False

    def test_patch_default_sync_enabled(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_sync_enabled": True})
        assert resp.status_code == 200
        assert resp.json()["default_sync_enabled"] is True

    def test_patch_default_sync_interval(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_sync_interval_minutes": 15})
        assert resp.status_code == 200
        assert resp.json()["default_sync_interval_minutes"] == 15

    def test_patch_default_timeline_range(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_timeline_range": "24h"})
        assert resp.status_code == 200
        assert resp.json()["default_timeline_range"] == "24h"

    def test_patch_default_provider_filter_vercel(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_provider_filter": "vercel"})
        assert resp.status_code == 200
        assert resp.json()["default_provider_filter"] == "vercel"

    def test_patch_default_provider_filter_github(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_provider_filter": "github"})
        assert resp.status_code == 200
        assert resp.json()["default_provider_filter"] == "github"

    def test_patch_partial_update_preserves_other_fields(self, client: TestClient) -> None:
        """Patching one field must not reset unmentioned fields."""
        client.patch("/settings", json={"sync_failure_threshold": 5})
        resp = client.patch("/settings", json={"alert_risk_threshold": "critical_only"})
        data = resp.json()
        assert data["sync_failure_threshold"] == 5       # preserved
        assert data["alert_risk_threshold"] == "critical_only"  # updated

    def test_patch_multiple_fields(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={
            "alert_risk_threshold": "critical_only",
            "sync_failure_threshold": 2,
            "default_timeline_range": "30d",
        })
        data = resp.json()
        assert data["alert_risk_threshold"] == "critical_only"
        assert data["sync_failure_threshold"] == 2
        assert data["default_timeline_range"] == "30d"

    def test_patch_creates_row_on_first_write(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        """PATCH on a user with no settings row should create one."""
        existing = (
            db_session.query(UserSettings)
            .filter(UserSettings.user_id == test_user.id)
            .first()
        )
        assert existing is None
        resp = client.patch("/settings", json={"sync_failure_threshold": 2})
        assert resp.status_code == 200
        # Row should now exist
        row = (
            db_session.query(UserSettings)
            .filter(UserSettings.user_id == test_user.id)
            .first()
        )
        assert row is not None
        assert row.sync_failure_threshold == 2


# ─────────────────────────────────────────────────────────────────────────────
# Settings — Validation (422 errors)
# ─────────────────────────────────────────────────────────────────────────────


class TestSettingsValidation:
    def test_invalid_alert_risk_threshold_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"alert_risk_threshold": "all"})
        assert resp.status_code == 422

    def test_invalid_sync_failure_threshold_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_threshold": 10})
        assert resp.status_code == 422

    def test_invalid_sync_failure_threshold_zero_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_threshold": 0})
        assert resp.status_code == 422

    def test_invalid_cooldown_hours_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"sync_failure_cooldown_hours": 48})
        assert resp.status_code == 422

    def test_invalid_sync_interval_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_sync_interval_minutes": 45})
        assert resp.status_code == 422

    def test_invalid_timeline_range_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_timeline_range": "1h"})
        assert resp.status_code == 422

    def test_invalid_provider_filter_rejected(self, client: TestClient) -> None:
        # "gcp" is not a valid provider — should be rejected.
        # Note: "stripe" was added as a valid provider filter in M35,
        # and "aws" was added as a valid provider filter in M36.
        resp = client.patch("/settings", json={"default_provider_filter": "gcp"})
        assert resp.status_code == 422

    def test_stripe_provider_filter_accepted(self, client: TestClient) -> None:
        """M35: 'stripe' is now a valid provider filter value."""
        resp = client.patch("/settings", json={"default_provider_filter": "stripe"})
        assert resp.status_code == 200
        assert resp.json()["default_provider_filter"] == "stripe"

    def test_invalid_interval_120_rejected(self, client: TestClient) -> None:
        resp = client.patch("/settings", json={"default_sync_interval_minutes": 120})
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Settings — User isolation
# ─────────────────────────────────────────────────────────────────────────────


class TestSettingsUserIsolation:
    def test_settings_are_user_scoped(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Two users must have independent settings rows."""
        import sqlalchemy as sa

        uid2 = uuid.uuid4().hex[:12]
        user2 = User(
            clerk_id=f"test_clerk_{uid2}",
            email=f"test2_{uid2}@configtrace.test",
        )
        db_session.add(user2)
        db_session.commit()
        user2_id = user2.id

        try:
            # Set settings via client (user1)
            client.patch("/settings", json={"sync_failure_threshold": 5})

            # Create user2 settings directly
            row2 = UserSettings(user_id=user2_id, sync_failure_threshold=2)
            db_session.add(row2)
            db_session.commit()

            # user1 should still see 5
            data = client.get("/settings").json()
            assert data["sync_failure_threshold"] == 5

            # user2 should have 2
            row2_check = (
                db_session.query(UserSettings)
                .filter(UserSettings.user_id == user2_id)
                .first()
            )
            assert row2_check is not None
            assert row2_check.sync_failure_threshold == 2
        finally:
            db_session.execute(
                sa.text("DELETE FROM users WHERE id = :uid"), {"uid": user2_id}
            )
            db_session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Settings — service layer
# ─────────────────────────────────────────────────────────────────────────────


class TestSettingsService:
    def test_get_or_create_returns_defaults(
        self, test_user: User, db_session: Session
    ) -> None:
        row = get_or_create_settings(test_user.id, db_session)
        assert row.alert_risk_threshold == "high_and_critical"
        assert row.sync_failure_alerts_enabled is True
        assert row.sync_failure_threshold == 3
        assert row.sync_failure_cooldown_hours == 24
        assert row.default_sync_enabled is False
        assert row.default_sync_interval_minutes == 60
        assert row.default_change_alerts_enabled is True
        assert row.default_timeline_range == "7d"
        assert row.default_provider_filter == "all"

    def test_get_or_create_idempotent(
        self, test_user: User, db_session: Session
    ) -> None:
        row1 = get_or_create_settings(test_user.id, db_session)
        row2 = get_or_create_settings(test_user.id, db_session)
        assert row1.id == row2.id

    def test_update_settings_writes_fields(
        self, test_user: User, db_session: Session
    ) -> None:
        row = update_settings(
            test_user.id,
            {"alert_risk_threshold": "critical_only", "sync_failure_threshold": 2},
            db_session,
        )
        assert row.alert_risk_threshold == "critical_only"
        assert row.sync_failure_threshold == 2

    def test_update_settings_preserves_unmentioned_fields(
        self, test_user: User, db_session: Session
    ) -> None:
        update_settings(test_user.id, {"sync_failure_threshold": 5}, db_session)
        row = update_settings(
            test_user.id, {"alert_risk_threshold": "critical_only"}, db_session
        )
        # sync_failure_threshold must still be 5
        assert row.sync_failure_threshold == 5


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — structure
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardSummaryStructure:
    def test_summary_returns_200(self, client: TestClient) -> None:
        resp = client.get("/dashboard/summary")
        assert resp.status_code == 200

    def test_summary_has_all_top_level_keys(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        expected_keys = {
            "integration_health",
            "resource_counts",
            "change_activity",
            "risk_distribution",
            "provider_distribution",
            "recent_high_critical_changes",
            "recent_failed_syncs",
            "last_updated_at",
        }
        assert expected_keys == set(data.keys())

    def test_integration_health_keys(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        ih = data["integration_health"]
        assert set(ih.keys()) == {
            "total", "active", "paused", "needs_attention",
            "failed_last_24h", "with_consecutive_failures",
        }

    def test_resource_counts_keys(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        assert set(data["resource_counts"].keys()) == {"total", "active"}

    def test_change_activity_keys(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        assert set(data["change_activity"].keys()) == {
            "total", "last_24h", "last_7d", "high_critical_last_7d", "last_change_at",
        }

    def test_risk_distribution_keys(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        assert set(data["risk_distribution"].keys()) == {
            "critical", "high", "medium", "low",
        }

    def test_last_updated_at_is_iso8601(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        ts = data["last_updated_at"]
        # Must parse without raising
        from datetime import datetime
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt is not None

    def test_empty_dashboard_for_new_user(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        ih = data["integration_health"]
        assert ih["total"] == 0
        assert ih["active"] == 0
        assert data["resource_counts"]["total"] == 0
        assert data["change_activity"]["total"] == 0
        assert data["risk_distribution"]["critical"] == 0
        assert data["provider_distribution"] == []
        assert data["recent_high_critical_changes"] == []
        assert data["recent_failed_syncs"] == []
        assert data["change_activity"]["last_change_at"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — integration health counts
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardIntegrationHealth:
    def test_counts_active_and_paused(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user, status="active")
        _make_integration(db_session, test_user, status="active")
        _make_integration(db_session, test_user, status="paused")

        data = client.get("/dashboard/summary").json()
        ih = data["integration_health"]
        assert ih["total"] == 3
        assert ih["active"] == 2
        assert ih["paused"] == 1

    def test_needs_attention_count(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        from app.core.failure_classifier import NEEDS_ATTENTION_THRESHOLD
        _make_integration(db_session, test_user, consecutive_failures=NEEDS_ATTENTION_THRESHOLD)
        _make_integration(db_session, test_user, consecutive_failures=0)

        data = client.get("/dashboard/summary").json()
        assert data["integration_health"]["needs_attention"] == 1

    def test_with_consecutive_failures_count(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user, consecutive_failures=1)
        _make_integration(db_session, test_user, consecutive_failures=0)

        data = client.get("/dashboard/summary").json()
        assert data["integration_health"]["with_consecutive_failures"] == 1

    def test_deleted_integrations_excluded(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user, status="deleted")
        data = client.get("/dashboard/summary").json()
        assert data["integration_health"]["total"] == 0

    def test_failed_last_24h(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        # Recent failed sync run
        _make_sync_run(
            db_session, test_user, integ,
            status="failed",
            started_at=datetime.now(timezone.utc) - timedelta(hours=6),
        )
        data = client.get("/dashboard/summary").json()
        assert data["integration_health"]["failed_last_24h"] == 1

    def test_failed_outside_24h_not_counted(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        _make_sync_run(
            db_session, test_user, integ,
            status="failed",
            started_at=datetime.now(timezone.utc) - timedelta(hours=36),
        )
        data = client.get("/dashboard/summary").json()
        assert data["integration_health"]["failed_last_24h"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — resource counts
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardResourceCounts:
    def test_counts_active_resources(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user)
        _make_integration(db_session, test_user)
        data = client.get("/dashboard/summary").json()
        rc = data["resource_counts"]
        assert rc["total"] == 2
        assert rc["active"] == 2

    def test_inactive_resources_counted_in_total(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        # Mark the resource inactive
        integ.resources[0].is_active = False
        db_session.commit()

        data = client.get("/dashboard/summary").json()
        rc = data["resource_counts"]
        assert rc["total"] == 1
        assert rc["active"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — change activity
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardChangeActivity:
    def test_total_changes(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource, risk_level="medium")
        _make_change(db_session, test_user, integ, resource, risk_level="high")

        data = client.get("/dashboard/summary").json()
        assert data["change_activity"]["total"] == 2

    def test_changes_24h(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        _make_change(
            db_session, test_user, integ, resource,
            created_at=datetime.now(timezone.utc) - timedelta(hours=12),
        )
        _make_change(
            db_session, test_user, integ, resource,
            created_at=datetime.now(timezone.utc) - timedelta(hours=36),
        )
        data = client.get("/dashboard/summary").json()
        assert data["change_activity"]["last_24h"] == 1

    def test_high_critical_last_7d(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource, risk_level="critical")
        _make_change(db_session, test_user, integ, resource, risk_level="high")
        _make_change(db_session, test_user, integ, resource, risk_level="medium")
        _make_change(db_session, test_user, integ, resource, risk_level="low")

        data = client.get("/dashboard/summary").json()
        assert data["change_activity"]["high_critical_last_7d"] == 2

    def test_last_change_at_is_set(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource)

        data = client.get("/dashboard/summary").json()
        assert data["change_activity"]["last_change_at"] is not None

    def test_last_change_at_null_when_no_changes(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        assert data["change_activity"]["last_change_at"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — risk distribution
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardRiskDistribution:
    def test_risk_distribution_counts(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        for level in ["critical", "critical", "high", "medium", "low", "low", "low"]:
            _make_change(db_session, test_user, integ, resource, risk_level=level)

        data = client.get("/dashboard/summary").json()
        rd = data["risk_distribution"]
        assert rd["critical"] == 2
        assert rd["high"] == 1
        assert rd["medium"] == 1
        assert rd["low"] == 3

    def test_risk_distribution_zeros_for_no_changes(self, client: TestClient) -> None:
        data = client.get("/dashboard/summary").json()
        rd = data["risk_distribution"]
        assert rd["critical"] == rd["high"] == rd["medium"] == rd["low"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — provider distribution
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardProviderDistribution:
    def test_provider_distribution_cloudflare(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user, provider="cloudflare")
        data = client.get("/dashboard/summary").json()
        providers = {p["provider"]: p for p in data["provider_distribution"]}
        assert "cloudflare" in providers
        assert providers["cloudflare"]["integration_count"] == 1
        assert providers["cloudflare"]["resource_count"] == 1

    def test_provider_distribution_includes_vercel(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user, provider="vercel")
        data = client.get("/dashboard/summary").json()
        providers = {p["provider"]: p for p in data["provider_distribution"]}
        assert "vercel" in providers

    def test_provider_distribution_multiple_providers(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        _make_integration(db_session, test_user, provider="cloudflare")
        _make_integration(db_session, test_user, provider="github")
        _make_integration(db_session, test_user, provider="vercel")
        data = client.get("/dashboard/summary").json()
        providers = {p["provider"]: p for p in data["provider_distribution"]}
        assert set(providers.keys()) == {"cloudflare", "github", "vercel"}

    def test_provider_change_count_7d(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user, provider="cloudflare")
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource, risk_level="high")

        data = client.get("/dashboard/summary").json()
        providers = {p["provider"]: p for p in data["provider_distribution"]}
        assert providers["cloudflare"]["change_count_7d"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — recent high/critical changes
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardRecentHighCritical:
    def test_only_high_critical_returned(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource, risk_level="critical")
        _make_change(db_session, test_user, integ, resource, risk_level="high")
        _make_change(db_session, test_user, integ, resource, risk_level="medium")
        _make_change(db_session, test_user, integ, resource, risk_level="low")

        data = client.get("/dashboard/summary").json()
        changes = data["recent_high_critical_changes"]
        assert len(changes) == 2
        levels = {c["risk_level"] for c in changes}
        assert levels <= {"high", "critical"}

    def test_max_10_recent_changes(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        for _ in range(15):
            _make_change(db_session, test_user, integ, resource, risk_level="critical")

        data = client.get("/dashboard/summary").json()
        assert len(data["recent_high_critical_changes"]) == 10

    def test_change_has_required_fields(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user)
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource, risk_level="critical")

        data = client.get("/dashboard/summary").json()
        c = data["recent_high_critical_changes"][0]
        assert "id" in c
        assert "integration_id" in c
        assert "risk_level" in c
        assert "change_type" in c
        assert "record_identifier" in c
        assert "created_at" in c

    def test_change_includes_integration_name_and_provider(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        integ = _make_integration(db_session, test_user, provider="cloudflare")
        resource = integ.resources[0]
        _make_change(db_session, test_user, integ, resource, risk_level="high")

        data = client.get("/dashboard/summary").json()
        c = data["recent_high_critical_changes"][0]
        assert c["integration_name"] == integ.display_name
        assert c["provider"] == "cloudflare"

    def test_user_isolation_changes(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        """Changes from another user must not appear."""
        import sqlalchemy as sa

        uid2 = uuid.uuid4().hex[:12]
        user2 = User(clerk_id=f"other_{uid2}", email=f"other_{uid2}@test.com")
        db_session.add(user2)
        db_session.commit()
        user2_id = user2.id
        try:
            integ2 = _make_integration(db_session, user2)
            resource2 = integ2.resources[0]
            _make_change(db_session, user2, integ2, resource2, risk_level="critical")

            data = client.get("/dashboard/summary").json()
            # user1 has no changes of their own
            assert data["recent_high_critical_changes"] == []
        finally:
            # Delete in dependency order to avoid FK / NOT NULL conflicts
            # (Change.resource_id is NOT NULL with RESTRICT, so raw SQL is safest)
            db_session.execute(
                sa.text("DELETE FROM changes WHERE user_id = :uid"), {"uid": user2_id}
            )
            db_session.execute(
                sa.text("DELETE FROM snapshots WHERE user_id = :uid"), {"uid": user2_id}
            )
            db_session.execute(
                sa.text("DELETE FROM users WHERE id = :uid"), {"uid": user2_id}
            )
            db_session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — recent failed syncs
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardRecentFailedSyncs:
    def test_failed_syncs_includes_recent_failures(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        now = datetime.now(timezone.utc)
        integ = _make_integration(
            db_session, test_user,
            last_failure_at=now - timedelta(hours=2),
        )
        _make_sync_run(
            db_session, test_user, integ,
            status="failed",
            failure_category="authentication",
            error_code="github_token_revoked",
            recommended_action="Reconnect the integration.",
        )

        data = client.get("/dashboard/summary").json()
        failed = data["recent_failed_syncs"]
        assert len(failed) == 1
        assert failed[0]["integration_id"] == str(integ.id)
        assert failed[0]["provider"] == "cloudflare"
        assert failed[0]["integration_name"] == integ.display_name

    def test_failed_syncs_older_than_7d_excluded(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        now = datetime.now(timezone.utc)
        integ = _make_integration(
            db_session, test_user,
            last_failure_at=now - timedelta(days=10),
        )
        data = client.get("/dashboard/summary").json()
        assert data["recent_failed_syncs"] == []

    def test_failed_syncs_max_5(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        now = datetime.now(timezone.utc)
        for _ in range(7):
            _make_integration(
                db_session, test_user,
                last_failure_at=now - timedelta(hours=1),
            )
        data = client.get("/dashboard/summary").json()
        assert len(data["recent_failed_syncs"]) <= 5

    def test_failed_sync_has_required_fields(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        now = datetime.now(timezone.utc)
        integ = _make_integration(
            db_session, test_user,
            last_failure_at=now - timedelta(hours=1),
        )
        data = client.get("/dashboard/summary").json()
        fs = data["recent_failed_syncs"][0]
        assert "integration_id" in fs
        assert "integration_name" in fs
        assert "provider" in fs
        assert "consecutive_failure_count" in fs
        assert "needs_attention" in fs

    def test_no_credential_fields_in_failed_sync(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        now = datetime.now(timezone.utc)
        _make_integration(
            db_session, test_user,
            last_failure_at=now - timedelta(hours=1),
        )
        data = client.get("/dashboard/summary").json()
        for fs in data["recent_failed_syncs"]:
            forbidden = {"api_token", "github_token", "vercel_token", "encrypted_credentials"}
            assert not forbidden.intersection(set(fs.keys()))


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — user isolation (broad)
# ─────────────────────────────────────────────────────────────────────────────


class TestDashboardUserIsolation:
    def test_integrations_scoped_to_user(
        self, client: TestClient, test_user: User, db_session: Session
    ) -> None:
        import sqlalchemy as sa

        uid2 = uuid.uuid4().hex[:12]
        user2 = User(clerk_id=f"other_{uid2}", email=f"other_{uid2}@test.com")
        db_session.add(user2)
        db_session.commit()
        user2_id = user2.id
        try:
            _make_integration(db_session, user2)
            data = client.get("/dashboard/summary").json()
            # user1 has no integrations
            assert data["integration_health"]["total"] == 0
        finally:
            db_session.execute(
                sa.text("DELETE FROM users WHERE id = :uid"), {"uid": user2_id}
            )
            db_session.commit()
