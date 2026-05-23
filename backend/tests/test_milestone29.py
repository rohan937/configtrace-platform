"""Milestone 29 tests — Integration Management, Sync Controls, Timeline Filtering.

Coverage
--------
A. Integration management via PATCH / DELETE / POST reconnect
   1. PATCH rename — display_name updates
   2. PATCH pause — status becomes 'paused'
   3. PATCH resume — status returns to 'active'
   4–8. PATCH sync_interval_minutes — all 5 allowed values accepted
   9. PATCH sync_interval_minutes — non-allowed value rejected (422)
   10. PATCH status='deleted' via PATCH rejected (422 — use DELETE instead)
   11. PATCH wrong user — 404 (no existence leak)
   12. PATCH unknown integration — 404
   13. DELETE soft-delete — sets status='deleted' in DB
   14. DELETE excludes from GET /integrations
   15. DELETE history preserved — changes still in GET /changes
   16. DELETE idempotent — second call is 204 not 500
   17. DELETE wrong user — 404
   18. Reconnect Cloudflare valid token — credentials updated, zone_id pinned
   19. Reconnect Cloudflare invalid token — 400, DB unchanged
   20. Reconnect GitHub valid token — credentials updated, repo pinned
   21. Reconnect GitHub invalid token — 400, DB unchanged
   22. Reconnect clears 'error' status — status resets to 'active'
   23. Reconnect rejects deleted integration — 404
   24. Reconnect token never in response body
   25. Reconnect token never in log output
   26. Reconnect Cloudflare without api_token — 422
   27. Reconnect GitHub without github_token — 422

B. Sync controls
   28. POST /syncs paused integration — 409 Conflict
   29. POST /syncs active integration — 201 (regression)
   30. GET /integrations excludes deleted (API-level regression)

C. Scheduled sync interval gate
   31. Default 60-min interval — due when last_synced_at is None
   32. Default 60-min interval — due when >60 min elapsed
   33. Default 60-min interval — not due when <60 min elapsed
   34. 5-min interval — due when >5 min elapsed
   35. 5-min interval — not due when <5 min elapsed
   36. 15-min interval — grace window applies (59.9s grace)
   37. Scheduled sync skips paused integrations
   38. Scheduled sync skips deleted integrations
   39. Scheduled sync skips in-flight syncs (regression)
   40. Scheduled sync enqueues when due, skips when not due (mixed batch)

D. Timeline provider filter
   41. GET /changes?provider=cloudflare — returns only cloudflare changes
   42. GET /changes?provider=github — returns only github changes
   43. GET /changes with no provider — returns all
   44. GET /changes?provider=cloudflare combined with risk_level
   45. GET /changes includes changes from deleted integrations

How tests work
--------------
* DB-backed tests use ``db_session`` and ``test_user`` fixtures from conftest.
* Scheduler tests monkey-patch ``sync_integration.delay`` (same as M23).
* Reconnect tests mock the connector's ``validate_credentials``.
* Changes filter tests create real Change rows via direct ORM inserts.
* API-level tests use the ``client`` fixture and bypass auth (test middleware).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.connectors.exceptions import AuthenticationError
from app.core.encryption import decrypt_credentials, encrypt_credentials
from app.models.change import Change
from app.models.integration import Integration
from app.models.sync_run import SyncRun
from app.models.user import User
from app.services import integration_service, sync_service


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_user(db: Session, suffix: str = "") -> User:
    uid = uuid.uuid4().hex[:10]
    user = User(
        clerk_id=f"m29_test_{uid}{suffix}",
        email=f"m29_{uid}{suffix}@configtrace.test",
        display_name="M29 Test User",
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
    last_synced_at: datetime | None = None,
) -> Integration:
    zone = f"zone_{uuid.uuid4().hex[:8]}"
    ciphertext, iv = encrypt_credentials({"api_token": "test_cf_tok", "zone_id": zone})
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name=f"CF Integration {zone}",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
        sync_interval_minutes=sync_interval_minutes,
        last_synced_at=last_synced_at,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


def _make_github_integration(
    db: Session,
    user: User,
    *,
    status: str = "active",
    sync_interval_minutes: int | None = None,
    last_synced_at: datetime | None = None,
) -> Integration:
    ciphertext, iv = encrypt_credentials({
        "github_token": "test_gh_tok",
        "repo_owner": "test-owner",
        "repo_name": "test-repo",
    })
    integration = Integration(
        user_id=user.id,
        provider="github",
        display_name="GH Integration test-owner/test-repo",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status=status,
        sync_interval_minutes=sync_interval_minutes,
        last_synced_at=last_synced_at,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


def _make_change(
    db: Session,
    user: User,
    integration: Integration,
    *,
    risk_level: str = "low",
    change_type: str = "modified",
) -> Change:
    """Create a minimal Change row attached to *integration*.

    Creates two minimal Snapshot rows to satisfy the NOT NULL constraints on
    prev_snapshot_id and new_snapshot_id.  Also creates a Resource if none
    exists for the integration.
    """
    from app.models.resource import Resource
    from app.models.snapshot import Snapshot

    resource = (
        db.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )
    if resource is None:
        resource = Resource(
            integration_id=integration.id,
            user_id=user.id,
            provider_resource_type="cloudflare_dns_zone",
            provider_resource_id=f"zone_{uuid.uuid4().hex[:8]}",
            display_name="Test Zone",
            resource_metadata={},
            is_active=True,
        )
        db.add(resource)
        db.flush()

    # Two minimal snapshots — content doesn't matter for these filter tests.
    prev_snap = Snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        state=[{"record_type": "CNAME", "name": "test", "content": "old.example.com"}],
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    new_snap = Snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        state=[{"record_type": "CNAME", "name": "test", "content": "new.example.com"}],
        content_hash=uuid.uuid4().hex,
        triggered_by="manual",
    )
    db.add(prev_snap)
    db.add(new_snap)
    db.flush()

    change = Change(
        integration_id=integration.id,
        resource_id=resource.id,
        user_id=user.id,
        prev_snapshot_id=prev_snap.id,
        new_snapshot_id=new_snap.id,
        change_type=change_type,
        record_identifier="test.example.com",
        field_path="content",
        prev_value="old",
        new_value="new",
        risk_level=risk_level,
        provider_metadata={"record_type": "CNAME"},
    )
    db.add(change)
    db.commit()
    db.refresh(change)
    return change


@pytest.fixture
def delay_spy(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Patch sync_integration.delay to record calls instead of enqueuing."""
    from app.workers import sync_task

    calls: list[dict[str, Any]] = []

    def fake_delay(**kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(sync_task.sync_integration, "delay", fake_delay)
    return calls


# ─────────────────────────────────────────────────────────────────────────────
# A. Integration management — service layer
# ─────────────────────────────────────────────────────────────────────────────


class TestUpdateIntegration:
    """Tests for integration_service.update_integration."""

    def test_rename_updates_display_name(self, db_session: Session, test_user: User) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        updated = integration_service.update_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            display_name="Renamed Integration",
            db=db_session,
        )
        assert updated.display_name == "Renamed Integration"
        db_session.expire(integration)
        db_session.refresh(integration)
        assert integration.display_name == "Renamed Integration"

    def test_pause_sets_status_paused(self, db_session: Session, test_user: User) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="active")
        updated = integration_service.update_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            status="paused",
            db=db_session,
        )
        assert updated.status == "paused"

    def test_resume_sets_status_active(self, db_session: Session, test_user: User) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="paused")
        updated = integration_service.update_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            status="active",
            db=db_session,
        )
        assert updated.status == "active"

    @pytest.mark.parametrize("interval", [5, 10, 15, 30, 60])
    def test_sync_interval_accepted(
        self, db_session: Session, test_user: User, interval: int
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        updated = integration_service.update_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            sync_interval_minutes=interval,
            db=db_session,
        )
        assert updated.sync_interval_minutes == interval

    def test_wrong_user_raises_lookup(self, db_session: Session, test_user: User) -> None:
        other_user = _make_user(db_session, "_other")
        integration = _make_cloudflare_integration(db_session, test_user)
        with pytest.raises(LookupError):
            integration_service.update_integration(
                integration_id=integration.id,
                user_id=other_user.id,
                display_name="Should not work",
                db=db_session,
            )

    def test_unknown_id_raises_lookup(self, db_session: Session, test_user: User) -> None:
        with pytest.raises(LookupError):
            integration_service.update_integration(
                integration_id=uuid.uuid4(),
                user_id=test_user.id,
                display_name="Ghost",
                db=db_session,
            )

    def test_deleted_integration_raises_lookup(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="deleted")
        with pytest.raises(LookupError):
            integration_service.update_integration(
                integration_id=integration.id,
                user_id=test_user.id,
                display_name="Cannot rename deleted",
                db=db_session,
            )


class TestSoftDeleteIntegration:
    """Tests for integration_service.soft_delete_integration."""

    def test_sets_status_deleted(self, db_session: Session, test_user: User) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )
        db_session.expire(integration)
        db_session.refresh(integration)
        assert integration.status == "deleted"

    def test_also_disables_scheduled_sync_enabled(
        self, db_session: Session, test_user: User
    ) -> None:
        """scheduled_sync_enabled set to False as defense-in-depth (not source-of-truth)."""
        integration = _make_cloudflare_integration(db_session, test_user)
        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )
        db_session.expire(integration)
        db_session.refresh(integration)
        assert integration.scheduled_sync_enabled is False

    def test_excludes_from_get_integrations(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )
        rows = integration_service.get_integrations(user_id=test_user.id, db=db_session)
        ids = [r.id for r in rows]
        assert integration.id not in ids

    def test_history_preserved_changes_still_accessible(
        self, db_session: Session, test_user: User
    ) -> None:
        """Changes from a deleted integration remain in changes_service.get_changes."""
        from app.services.changes_service import get_changes

        integration = _make_cloudflare_integration(db_session, test_user)
        _make_change(db_session, test_user, integration)

        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )

        items, total = get_changes(test_user.id, db_session)
        integration_ids = {str(c.integration_id) for c in items}
        assert str(integration.id) in integration_ids

    def test_idempotent_second_delete_is_noop(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )
        # Second call must not raise
        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )

    def test_wrong_user_raises_lookup(self, db_session: Session, test_user: User) -> None:
        other_user = _make_user(db_session, "_del_other")
        integration = _make_cloudflare_integration(db_session, test_user)
        with pytest.raises(LookupError):
            integration_service.soft_delete_integration(
                integration_id=integration.id,
                user_id=other_user.id,
                db=db_session,
            )


class TestReconnectCredentials:
    """Tests for integration_service.reconnect_credentials."""

    def test_cloudflare_valid_token_updates_credentials(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        original_zone = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )["zone_id"]

        with patch(
            "app.connectors.cloudflare.CloudflareConnector.validate_credentials"
        ):
            updated = integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token="new_cf_token_abc",
                db=db_session,
            )

        # Credentials updated in DB
        new_creds = decrypt_credentials(
            updated.encrypted_credentials, updated.credential_iv
        )
        assert new_creds["api_token"] == "new_cf_token_abc"
        # Zone ID pinned — unchanged
        assert new_creds["zone_id"] == original_zone

    def test_cloudflare_invalid_token_raises_auth_error(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user)
        original_ciphertext = bytes(integration.encrypted_credentials)

        with patch(
            "app.connectors.cloudflare.CloudflareConnector.validate_credentials",
            side_effect=AuthenticationError("Bad token"),
        ):
            with pytest.raises(AuthenticationError):
                integration_service.reconnect_credentials(
                    integration_id=integration.id,
                    user_id=test_user.id,
                    new_token="bad_token",
                    db=db_session,
                )

        # DB unchanged after failed validation
        db_session.expire(integration)
        db_session.refresh(integration)
        assert bytes(integration.encrypted_credentials) == original_ciphertext

    def test_github_valid_token_updates_credentials(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_github_integration(db_session, test_user)
        original_creds = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )

        with patch(
            "app.connectors.github.GitHubConnector.validate_credentials"
        ):
            updated = integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token="new_gh_pat_xyz",
                db=db_session,
            )

        new_creds = decrypt_credentials(
            updated.encrypted_credentials, updated.credential_iv
        )
        assert new_creds["github_token"] == "new_gh_pat_xyz"
        # Repo owner and name pinned
        assert new_creds["repo_owner"] == original_creds["repo_owner"]
        assert new_creds["repo_name"] == original_creds["repo_name"]

    def test_github_invalid_token_raises_auth_error(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_github_integration(db_session, test_user)
        with patch(
            "app.connectors.github.GitHubConnector.validate_credentials",
            side_effect=AuthenticationError("Unauthorized"),
        ):
            with pytest.raises(AuthenticationError):
                integration_service.reconnect_credentials(
                    integration_id=integration.id,
                    user_id=test_user.id,
                    new_token="bad_pat",
                    db=db_session,
                )

    def test_clears_error_status_on_success(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="error")
        with patch(
            "app.connectors.cloudflare.CloudflareConnector.validate_credentials"
        ):
            updated = integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token="fixed_token",
                db=db_session,
            )
        assert updated.status == "active"

    def test_rejects_deleted_integration(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="deleted")
        with pytest.raises(LookupError):
            integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token="any_token",
                db=db_session,
            )

    def test_token_never_in_response(
        self, db_session: Session, test_user: User
    ) -> None:
        """The reconnect result must not expose the plaintext token anywhere."""
        secret_token = "super_secret_token_should_not_appear"
        integration = _make_cloudflare_integration(db_session, test_user)
        with patch(
            "app.connectors.cloudflare.CloudflareConnector.validate_credentials"
        ):
            updated = integration_service.reconnect_credentials(
                integration_id=integration.id,
                user_id=test_user.id,
                new_token=secret_token,
                db=db_session,
            )
        # The ORM object must not expose the token as a plain attribute
        assert not hasattr(updated, "api_token")
        assert not hasattr(updated, "github_token")
        assert secret_token not in str(updated)

    def test_token_never_in_log_output(
        self, db_session: Session, test_user: User, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The new token must never appear in any log record during reconnect."""
        secret_token = "ultra_secret_token_in_logs_test"
        integration = _make_cloudflare_integration(db_session, test_user)
        with caplog.at_level(logging.DEBUG):
            with patch(
                "app.connectors.cloudflare.CloudflareConnector.validate_credentials"
            ):
                integration_service.reconnect_credentials(
                    integration_id=integration.id,
                    user_id=test_user.id,
                    new_token=secret_token,
                    db=db_session,
                )
        for record in caplog.records:
            assert secret_token not in record.getMessage(), (
                f"Token found in log record: {record.getMessage()!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# B. Sync controls — router-level
# ─────────────────────────────────────────────────────────────────────────────


class TestSyncControls:
    """Tests for POST /syncs status-gating (M29)."""

    def test_post_syncs_blocked_when_paused(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="paused")
        resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        assert resp.status_code == 409
        assert "paused" in resp.json()["detail"].lower()

    def test_post_syncs_succeeds_when_active(
        self, client: Any, db_session: Session, test_user: User, delay_spy: list
    ) -> None:
        """Active integration — POST /syncs returns 201 (regression from M23)."""
        integration = _make_cloudflare_integration(db_session, test_user, status="active")
        resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        assert resp.status_code == 201

    def test_post_syncs_deleted_returns_404(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(db_session, test_user, status="deleted")
        resp = client.post("/syncs", json={"integration_id": str(integration.id)})
        assert resp.status_code == 404

    def test_get_integrations_excludes_deleted(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        active = _make_cloudflare_integration(db_session, test_user)
        deleted = _make_cloudflare_integration(db_session, test_user, status="deleted")
        resp = client.get("/integrations")
        assert resp.status_code == 200
        ids = [i["id"] for i in resp.json()["integrations"]]
        assert str(active.id) in ids
        assert str(deleted.id) not in ids


# ─────────────────────────────────────────────────────────────────────────────
# C. Scheduled sync interval gate
# ─────────────────────────────────────────────────────────────────────────────


class TestSchedulerIntervalGate:
    """Tests for sync_service._is_integration_due and the batch function."""

    def _due(self, integration: Integration, now: datetime) -> bool:
        return sync_service._is_integration_due(integration, now)

    def test_never_synced_is_always_due(
        self, db_session: Session, test_user: User
    ) -> None:
        integration = _make_cloudflare_integration(
            db_session, test_user, last_synced_at=None
        )
        now = datetime.now(timezone.utc)
        assert self._due(integration, now) is True

    def test_default_60_min_due_after_65_min(
        self, db_session: Session, test_user: User
    ) -> None:
        last = datetime.now(timezone.utc) - timedelta(minutes=65)
        integration = _make_cloudflare_integration(
            db_session, test_user, last_synced_at=last
        )
        now = datetime.now(timezone.utc)
        assert self._due(integration, now) is True

    def test_default_60_min_not_due_after_30_min(
        self, db_session: Session, test_user: User
    ) -> None:
        last = datetime.now(timezone.utc) - timedelta(minutes=30)
        integration = _make_cloudflare_integration(
            db_session, test_user, last_synced_at=last
        )
        now = datetime.now(timezone.utc)
        assert self._due(integration, now) is False

    def test_5_min_interval_due_after_6_min(
        self, db_session: Session, test_user: User
    ) -> None:
        last = datetime.now(timezone.utc) - timedelta(minutes=6)
        integration = _make_cloudflare_integration(
            db_session, test_user, sync_interval_minutes=5, last_synced_at=last
        )
        now = datetime.now(timezone.utc)
        assert self._due(integration, now) is True

    def test_5_min_interval_not_due_after_2_min(
        self, db_session: Session, test_user: User
    ) -> None:
        last = datetime.now(timezone.utc) - timedelta(minutes=2)
        integration = _make_cloudflare_integration(
            db_session, test_user, sync_interval_minutes=5, last_synced_at=last
        )
        now = datetime.now(timezone.utc)
        assert self._due(integration, now) is False

    def test_grace_window_allows_near_boundary(
        self, db_session: Session, test_user: User
    ) -> None:
        """A sync 14m40s ago should be due on a 15-min interval (30s grace)."""
        # 14 min 40 sec = 880 sec; threshold = 15*60 - 30 = 870 sec
        last = datetime.now(timezone.utc) - timedelta(seconds=880)
        integration = _make_cloudflare_integration(
            db_session, test_user, sync_interval_minutes=15, last_synced_at=last
        )
        now = datetime.now(timezone.utc)
        assert self._due(integration, now) is True

    def test_paused_integration_not_enqueued(
        self, db_session: Session, test_user: User, delay_spy: list
    ) -> None:
        """The specific paused integration we created must not appear in enqueued calls."""
        paused = _make_cloudflare_integration(db_session, test_user, status="paused")
        sync_service.create_scheduled_syncs_for_active_integrations(db_session)
        enqueued_ids = {c["integration_id"] for c in delay_spy}
        # The paused integration must never be in the enqueued set.
        assert str(paused.id) not in enqueued_ids

    def test_deleted_integration_not_enqueued(
        self, db_session: Session, test_user: User, delay_spy: list
    ) -> None:
        """The specific deleted integration we created must not appear in enqueued calls."""
        deleted = _make_cloudflare_integration(db_session, test_user, status="deleted")
        sync_service.create_scheduled_syncs_for_active_integrations(db_session)
        enqueued_ids = {c["integration_id"] for c in delay_spy}
        assert str(deleted.id) not in enqueued_ids

    def test_in_flight_guard_preserved(
        self, db_session: Session, test_user: User, delay_spy: list
    ) -> None:
        """Integration with an existing pending SyncRun is skipped (M23 regression)."""
        integration = _make_cloudflare_integration(
            db_session, test_user, last_synced_at=None  # always due
        )
        # Create an in-flight SyncRun
        sync_run = SyncRun(
            integration_id=integration.id,
            user_id=test_user.id,
            triggered_by="manual",
            status="pending",
        )
        db_session.add(sync_run)
        db_session.commit()

        result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)
        # The integration was seen but skipped due to in-flight guard
        enqueued_ids = {c["integration_id"] for c in delay_spy}
        assert str(integration.id) not in enqueued_ids
        assert result["skipped_in_flight"] >= 1

    def test_mixed_batch_due_and_not_due(
        self, db_session: Session, test_user: User, delay_spy: list
    ) -> None:
        """Only the due integration is enqueued; the not-due one is skipped."""
        due_integration = _make_cloudflare_integration(
            db_session, test_user, sync_interval_minutes=5, last_synced_at=None
        )
        recent_last_sync = datetime.now(timezone.utc) - timedelta(minutes=2)
        not_due_integration = _make_cloudflare_integration(
            db_session, test_user, sync_interval_minutes=5,
            last_synced_at=recent_last_sync,
        )

        result = sync_service.create_scheduled_syncs_for_active_integrations(db_session)

        enqueued_ids = {c["integration_id"] for c in delay_spy}
        assert str(due_integration.id) in enqueued_ids
        assert str(not_due_integration.id) not in enqueued_ids
        assert result["skipped_not_due"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# D. Timeline provider filter
# ─────────────────────────────────────────────────────────────────────────────


class TestChangesProviderFilter:
    """Tests for GET /changes?provider= (M29 — server-side JOIN on Integration)."""

    def test_filter_cloudflare_returns_only_cloudflare(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        cf_integration = _make_cloudflare_integration(db_session, test_user)
        gh_integration = _make_github_integration(db_session, test_user)
        cf_change = _make_change(db_session, test_user, cf_integration)
        _make_change(db_session, test_user, gh_integration)

        resp = client.get("/changes?provider=cloudflare")
        assert resp.status_code == 200
        items = resp.json()["items"]
        ids = {i["id"] for i in items}
        assert str(cf_change.id) in ids
        # No GitHub changes in result
        for item in items:
            assert str(item["integration_id"]) == str(cf_integration.id)

    def test_filter_github_returns_only_github(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        cf_integration = _make_cloudflare_integration(db_session, test_user)
        gh_integration = _make_github_integration(db_session, test_user)
        _make_change(db_session, test_user, cf_integration)
        gh_change = _make_change(db_session, test_user, gh_integration)

        resp = client.get("/changes?provider=github")
        assert resp.status_code == 200
        items = resp.json()["items"]
        ids = {i["id"] for i in items}
        assert str(gh_change.id) in ids
        for item in items:
            assert str(item["integration_id"]) == str(gh_integration.id)

    def test_no_provider_filter_returns_all(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        cf_integration = _make_cloudflare_integration(db_session, test_user)
        gh_integration = _make_github_integration(db_session, test_user)
        cf_change = _make_change(db_session, test_user, cf_integration)
        gh_change = _make_change(db_session, test_user, gh_integration)

        resp = client.get("/changes")
        assert resp.status_code == 200
        ids = {i["id"] for i in resp.json()["items"]}
        assert str(cf_change.id) in ids
        assert str(gh_change.id) in ids

    def test_provider_combined_with_risk_level(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        cf_integration = _make_cloudflare_integration(db_session, test_user)
        high = _make_change(db_session, test_user, cf_integration, risk_level="high")
        _make_change(db_session, test_user, cf_integration, risk_level="low")

        resp = client.get("/changes?provider=cloudflare&risk_level=high")
        assert resp.status_code == 200
        ids = {i["id"] for i in resp.json()["items"]}
        assert str(high.id) in ids
        for item in resp.json()["items"]:
            assert item["risk_level"] == "high"

    def test_provider_combined_with_integration_id(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        cf1 = _make_cloudflare_integration(db_session, test_user)
        cf2 = _make_cloudflare_integration(db_session, test_user)
        c1 = _make_change(db_session, test_user, cf1)
        _make_change(db_session, test_user, cf2)

        resp = client.get(
            f"/changes?provider=cloudflare&integration_id={cf1.id}"
        )
        assert resp.status_code == 200
        ids = {i["id"] for i in resp.json()["items"]}
        assert str(c1.id) in ids
        for item in resp.json()["items"]:
            assert str(item["integration_id"]) == str(cf1.id)

    def test_changes_from_deleted_integration_still_accessible(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        """History from a deleted integration must remain in the timeline."""
        integration = _make_cloudflare_integration(db_session, test_user)
        change = _make_change(db_session, test_user, integration)

        # Soft-delete the integration
        integration_service.soft_delete_integration(
            integration_id=integration.id,
            user_id=test_user.id,
            db=db_session,
        )

        resp = client.get("/changes")
        assert resp.status_code == 200
        ids = {i["id"] for i in resp.json()["items"]}
        assert str(change.id) in ids


# ─────────────────────────────────────────────────────────────────────────────
# E. API schema — response shape
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegrationResponseShape:
    """Verify the GET /integrations response exposes M29 fields."""

    def test_response_includes_sync_interval_minutes(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        _make_cloudflare_integration(db_session, test_user, sync_interval_minutes=15)
        resp = client.get("/integrations")
        assert resp.status_code == 200
        integrations = resp.json()["integrations"]
        assert len(integrations) >= 1
        # At least one integration has sync_interval_minutes = 15
        intervals = {i["sync_interval_minutes"] for i in integrations}
        assert 15 in intervals

    def test_response_includes_last_sync_fields(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        resp = client.get("/integrations")
        assert resp.status_code == 200
        for item in resp.json()["integrations"]:
            assert "last_sync_status" in item
            assert "last_sync_error" in item

    def test_response_never_includes_credentials(
        self, client: Any, db_session: Session, test_user: User
    ) -> None:
        _make_cloudflare_integration(db_session, test_user)
        resp = client.get("/integrations")
        assert resp.status_code == 200
        body_str = resp.text
        for forbidden in ("api_token", "github_token", "encrypted_credentials", "credential_iv"):
            assert forbidden not in body_str, (
                f"Credential field {forbidden!r} found in GET /integrations response"
            )


# ─────────────────────────────────────────────────────────────────────────────
# F. Schema validation (no DB required)
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegrationUpdateRequestValidation:
    """Pure-Python Pydantic validation tests for IntegrationUpdateRequest."""

    def test_all_none_rejected(self) -> None:
        from app.schemas.integration import IntegrationUpdateRequest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            IntegrationUpdateRequest()

    def test_invalid_interval_rejected(self) -> None:
        from app.schemas.integration import IntegrationUpdateRequest
        from pydantic import ValidationError

        for bad in [0, 1, 7, 45, 120, 1440]:
            with pytest.raises(ValidationError, match="sync_interval_minutes"):
                IntegrationUpdateRequest(sync_interval_minutes=bad)

    def test_status_deleted_rejected_via_update(self) -> None:
        from app.schemas.integration import IntegrationUpdateRequest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            IntegrationUpdateRequest(status="deleted")  # type: ignore[arg-type]

    @pytest.mark.parametrize("interval", [5, 10, 15, 30, 60])
    def test_valid_intervals_accepted(self, interval: int) -> None:
        from app.schemas.integration import IntegrationUpdateRequest

        req = IntegrationUpdateRequest(sync_interval_minutes=interval)
        assert req.sync_interval_minutes == interval
