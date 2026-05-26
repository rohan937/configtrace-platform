"""Tests for scheduled sync reliability improvements.

Covers:
1.  _cleanup_stale_in_flight() — marks SyncRuns stuck >30 min as failed.
2.  stale_cleaned key in the result dict.
3.  AWS stale-run scenario: stale cleanup unblocks the next scheduled sync.
4.  Cleanup is called BEFORE has_in_flight_sync (order guarantee).
5.  Completion log includes skipped_not_due and stale_cleaned (observability).
6.  store_snapshot receives triggered_by from the SyncRun, not hardcoded 'manual'.
7.  Backward-compat eligibility: scheduled_sync_enabled=False with a configured
    interval is still eligible (covers integrations created before the flag
    defaulted to True).

Security notes:
- No credentials, tokens, or API keys are logged or inspected in any test.
- triggered_by bug fix is tested via behaviour (call args), not source reading.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services.sync_service import (
    _STALE_SYNC_THRESHOLD_MINUTES,
    _cleanup_stale_in_flight,
    create_scheduled_syncs_for_active_integrations,
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_integration(
    provider: str = "aws",
    scheduled_sync_enabled: bool = True,
    last_synced_at=None,
    sync_interval_minutes: int = 60,
):
    """Build a minimal MagicMock Integration."""
    i = MagicMock()
    i.provider = provider
    i.status = "active"
    i.scheduled_sync_enabled = scheduled_sync_enabled
    i.sync_interval_minutes = sync_interval_minutes
    i.last_synced_at = last_synced_at  # None → never synced → always due
    i.id = uuid.uuid4()
    i.user_id = uuid.uuid4()
    return i


def _make_sync_run(status: str = "running", minutes_ago: int = 35):
    """Build a minimal MagicMock SyncRun."""
    run = MagicMock()
    run.id = uuid.uuid4()
    run.status = status
    run.started_at = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return run


def _run_scheduler(integrations: list) -> dict:
    """Run create_scheduled_syncs_for_active_integrations with a mocked DB.

    Patches _cleanup_stale_in_flight to return 0 so the scheduler tests don't
    depend on the cleanup implementation.
    """
    from app.models.integration import Integration as _Integration

    def _query_side_effect(model_or_col):
        q = MagicMock()
        if model_or_col is _Integration:
            q.filter.return_value.all.return_value = integrations
        else:
            # SyncRun queries — no in-flight, no stale
            q.filter.return_value.first.return_value = None
            q.filter.return_value.all.return_value = []
        return q

    db = MagicMock()
    db.query.side_effect = _query_side_effect

    with patch("app.workers.sync_task.sync_integration") as mock_task, \
         patch("app.services.sync_service.create_sync_run") as mock_create_run, \
         patch("app.services.sync_service._cleanup_stale_in_flight", return_value=0):
        mock_task.delay = MagicMock()
        mock_run = MagicMock()
        mock_run.id = uuid.uuid4()
        mock_create_run.return_value = mock_run
        result = create_scheduled_syncs_for_active_integrations(db)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 1. _cleanup_stale_in_flight
# ─────────────────────────────────────────────────────────────────────────────


class TestCleanupStaleInFlight:
    """Unit tests for _cleanup_stale_in_flight() — the stale SyncRun detector."""

    def _make_db(self, stale_runs: list) -> MagicMock:
        """Build a mock DB whose SyncRun query returns *stale_runs*."""
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = stale_runs
        return db

    def test_stale_running_marked_failed(self):
        """A SyncRun in 'running' for 31 minutes is marked 'failed'."""
        run = _make_sync_run(status="running", minutes_ago=31)
        db = self._make_db([run])
        now = datetime.now(timezone.utc)

        _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        assert run.status == "failed"

    def test_stale_pending_marked_failed(self):
        """A SyncRun in 'pending' for 31 minutes is also marked 'failed'."""
        run = _make_sync_run(status="pending", minutes_ago=31)
        db = self._make_db([run])
        now = datetime.now(timezone.utc)

        _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        assert run.status == "failed"

    def test_stale_run_gets_completed_at(self):
        """Stale SyncRun must have completed_at set to 'now'."""
        run = _make_sync_run(status="running", minutes_ago=35)
        db = self._make_db([run])
        now = datetime.now(timezone.utc)

        _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        assert run.completed_at == now

    def test_stale_run_gets_informative_error_message(self):
        """Stale SyncRun error_message must be non-empty and mention stale/timeout."""
        run = _make_sync_run(status="running", minutes_ago=31)
        db = self._make_db([run])
        now = datetime.now(timezone.utc)

        _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        assert isinstance(run.error_message, str)
        assert len(run.error_message) > 20
        lower = run.error_message.lower()
        assert "stale" in lower or "timed out" in lower or "restart" in lower

    def test_no_stale_runs_returns_zero(self):
        """When no stale runs exist, return value is 0."""
        db = self._make_db([])
        now = datetime.now(timezone.utc)

        count = _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        assert count == 0

    def test_multiple_stale_runs_returns_count(self):
        """Return value equals the number of SyncRuns cleaned."""
        runs = [
            _make_sync_run(status="running", minutes_ago=35),
            _make_sync_run(status="pending", minutes_ago=40),
        ]
        db = self._make_db(runs)
        now = datetime.now(timezone.utc)

        count = _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        assert count == 2
        for run in runs:
            assert run.status == "failed"

    def test_commit_called_when_stale_found(self):
        """db.commit() must be called after marking stale runs failed."""
        run = _make_sync_run(status="running", minutes_ago=31)
        db = self._make_db([run])
        now = datetime.now(timezone.utc)

        _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        db.commit.assert_called_once()

    def test_no_commit_when_no_stale(self):
        """db.commit() must NOT be called when no stale runs are found."""
        db = self._make_db([])
        now = datetime.now(timezone.utc)

        _cleanup_stale_in_flight(uuid.uuid4(), db, now)

        db.commit.assert_not_called()

    def test_threshold_is_30_minutes(self):
        """The stale threshold constant must be exactly 30 minutes.

        30 minutes is deliberately conservative — even the heaviest AWS sync
        (M36–M38, multi-region EC2 + S3) completes in under 10 minutes.
        Raising this would cause legitimately running syncs to be killed.
        """
        assert _STALE_SYNC_THRESHOLD_MINUTES == 30


# ─────────────────────────────────────────────────────────────────────────────
# 2. stale_cleaned in the result dict
# ─────────────────────────────────────────────────────────────────────────────


class TestStaleCleanedKey:
    """The result dict from create_scheduled_syncs_for_active_integrations
    must include ``stale_cleaned`` after the reliability fix."""

    def test_result_dict_has_stale_cleaned(self):
        """stale_cleaned key must be present."""
        result = _run_scheduler([])
        assert "stale_cleaned" in result, (
            "result dict is missing 'stale_cleaned' — "
            "did create_scheduled_syncs_for_active_integrations get updated?"
        )

    def test_stale_cleaned_is_integer(self):
        """stale_cleaned must be an integer."""
        result = _run_scheduler([])
        assert isinstance(result["stale_cleaned"], int)

    def test_all_six_required_keys_present(self):
        """All six expected keys must be present in the result dict."""
        result = _run_scheduler([])
        required = {
            "integrations_seen",
            "enqueued",
            "skipped_not_due",
            "skipped_in_flight",
            "stale_cleaned",
            "errors",
        }
        missing = required - result.keys()
        assert not missing, f"Missing keys from result dict: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 3. AWS stale-run scenario
# ─────────────────────────────────────────────────────────────────────────────


class TestAWSStaleRunUnblocks:
    """End-to-end scenario: stale AWS SyncRun does not permanently block syncs."""

    def test_aws_integration_enqueued_after_stale_cleanup(self):
        """After stale cleanup, an AWS integration must be enqueued (not
        skipped_in_flight)."""
        from app.models.integration import Integration as _Integration

        aws_int = _make_integration(provider="aws", last_synced_at=None)

        def _query_side_effect(model_or_col):
            q = MagicMock()
            if model_or_col is _Integration:
                q.filter.return_value.all.return_value = [aws_int]
            else:
                # After stale cleanup, no in-flight runs remain
                q.filter.return_value.first.return_value = None
                q.filter.return_value.all.return_value = []
            return q

        db = MagicMock()
        db.query.side_effect = _query_side_effect

        with patch("app.workers.sync_task.sync_integration") as mock_task, \
             patch("app.services.sync_service.create_sync_run") as mock_create_run, \
             patch(
                 "app.services.sync_service._cleanup_stale_in_flight",
                 return_value=1,
             ) as mock_cleanup:
            mock_task.delay = MagicMock()
            mock_run = MagicMock()
            mock_run.id = uuid.uuid4()
            mock_create_run.return_value = mock_run
            result = create_scheduled_syncs_for_active_integrations(db)

        assert result["enqueued"] == 1, (
            f"AWS integration was not enqueued after stale cleanup. result={result}"
        )
        assert result["skipped_in_flight"] == 0
        assert result["stale_cleaned"] == 1

    def test_cleanup_called_before_has_in_flight(self):
        """_cleanup_stale_in_flight must be called BEFORE has_in_flight_sync.

        The order matters: stale rows must be cleared before the
        duplicate-prevention guard runs, or they will still block the sync.
        """
        from app.models.integration import Integration as _Integration

        aws_int = _make_integration(provider="aws")
        call_order: list[str] = []

        def mock_cleanup(integration_id, db, now):
            call_order.append("cleanup")
            return 0

        def mock_has_in_flight(integration_id, db):
            call_order.append("has_in_flight")
            return False

        def _query_side_effect(model_or_col):
            q = MagicMock()
            if model_or_col is _Integration:
                q.filter.return_value.all.return_value = [aws_int]
            else:
                q.filter.return_value.first.return_value = None
                q.filter.return_value.all.return_value = []
            return q

        db = MagicMock()
        db.query.side_effect = _query_side_effect

        with patch("app.workers.sync_task.sync_integration") as mock_task, \
             patch("app.services.sync_service.create_sync_run") as mock_create_run, \
             patch(
                 "app.services.sync_service._cleanup_stale_in_flight",
                 side_effect=mock_cleanup,
             ), \
             patch(
                 "app.services.sync_service.has_in_flight_sync",
                 side_effect=mock_has_in_flight,
             ):
            mock_task.delay = MagicMock()
            mock_run = MagicMock()
            mock_run.id = uuid.uuid4()
            mock_create_run.return_value = mock_run
            create_scheduled_syncs_for_active_integrations(db)

        assert "cleanup" in call_order, "_cleanup_stale_in_flight was never called"
        assert "has_in_flight" in call_order, "has_in_flight_sync was never called"
        assert call_order.index("cleanup") < call_order.index("has_in_flight"), (
            "cleanup must be called before has_in_flight_sync — "
            f"actual order: {call_order}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Completion log observability
# ─────────────────────────────────────────────────────────────────────────────


class TestScheduledTaskLogging:
    """enqueue_scheduled_syncs completion log must include skipped_not_due
    and stale_cleaned so operators can diagnose scheduling issues from Render
    logs without changing log levels."""

    def _run_task_with_result(self, mock_result: dict):
        """Call enqueue_scheduled_syncs, mock the service call, capture logs."""
        from app.workers.scheduled_tasks import enqueue_scheduled_syncs

        mock_db = MagicMock()

        with patch("app.database.SessionLocal", return_value=mock_db), \
             patch(
                 "app.services.sync_service"
                 ".create_scheduled_syncs_for_active_integrations",
                 return_value=mock_result,
             ), \
             patch("app.workers.scheduled_tasks.logger") as mock_logger:
            enqueue_scheduled_syncs()

        return mock_logger

    def test_completion_log_includes_skipped_not_due(self):
        """skipped_not_due must appear in the completion log."""
        mock_result = {
            "integrations_seen": 3,
            "enqueued": 1,
            "skipped_not_due": 2,
            "skipped_in_flight": 0,
            "stale_cleaned": 0,
            "errors": 0,
        }
        mock_logger = self._run_task_with_result(mock_result)

        # Stringify all info calls and find the 'completed' line
        all_calls = [str(c) for c in mock_logger.info.call_args_list]
        completed_calls = [c for c in all_calls if "completed" in c]
        assert completed_calls, f"No 'completed' log found in: {all_calls}"
        completed_log = completed_calls[0]
        assert "skipped_not_due" in completed_log, (
            f"'skipped_not_due' missing from completion log: {completed_log}"
        )

    def test_completion_log_includes_stale_cleaned(self):
        """stale_cleaned must appear in the completion log."""
        mock_result = {
            "integrations_seen": 1,
            "enqueued": 0,
            "skipped_not_due": 0,
            "skipped_in_flight": 0,
            "stale_cleaned": 1,
            "errors": 0,
        }
        mock_logger = self._run_task_with_result(mock_result)

        all_calls = [str(c) for c in mock_logger.info.call_args_list]
        completed_calls = [c for c in all_calls if "completed" in c]
        assert completed_calls, f"No 'completed' log found in: {all_calls}"
        completed_log = completed_calls[0]
        assert "stale_cleaned" in completed_log, (
            f"'stale_cleaned' missing from completion log: {completed_log}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5. triggered_by pass-through — store_snapshot must not hardcode "manual"
# ─────────────────────────────────────────────────────────────────────────────


class TestTriggeredByPassThrough:
    """store_snapshot must be called with the SyncRun's triggered_by value,
    not the old hardcoded 'manual' string.

    Before the fix (line 267 of sync_task.py):
        store_snapshot(..., triggered_by="manual", ...)
    After the fix:
        store_snapshot(..., triggered_by=_triggered_by, ...)

    This test would fail before the fix (triggered_by would be "manual" even
    for scheduled syncs) and passes after it.

    SECURITY: credentials are mocked as {} — no real keys are used or inspected.
    """

    def test_store_snapshot_receives_scheduled_triggered_by(self):
        """When SyncRun.triggered_by == 'scheduled', store_snapshot must receive
        triggered_by='scheduled', not the hardcoded 'manual'."""
        import app.workers.sync_task as sync_task_module

        _sync_run_id = uuid.uuid4()
        _integration_id = uuid.uuid4()
        _user_id = uuid.uuid4()
        _resource_id = uuid.uuid4()

        # SyncRun with triggered_by="scheduled"
        mock_sync_run = MagicMock()
        mock_sync_run.triggered_by = "scheduled"

        mock_integration = MagicMock()
        mock_integration.provider = "cloudflare"  # simplest provider path
        mock_integration.display_name = "Test CF"
        mock_integration.user_id = _user_id
        mock_integration.id = _integration_id
        mock_integration.encrypted_credentials = b"enc"
        mock_integration.credential_iv = b"iv"

        mock_resource = MagicMock()
        mock_resource.id = _resource_id
        mock_resource.user_id = _user_id
        mock_resource.is_active = True

        store_snapshot_calls: list[dict] = []

        def capture_store_snapshot(**kwargs):
            store_snapshot_calls.append(kwargs)
            # Return (snapshot, created=False) to skip the diff pipeline
            return (MagicMock(), False)

        # db.get() is called twice inside sync_integration:
        #   1st: db.get(SyncRun, _sync_run_uuid)   → mock_sync_run
        #   2nd: db.get(Integration, _integration_uuid) → mock_integration
        pk_map = {
            str(_sync_run_id): mock_sync_run,
            str(_integration_id): mock_integration,
        }
        mock_db = MagicMock()
        mock_db.get.side_effect = lambda model, pk: pk_map.get(str(pk))
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_resource]

        with patch("app.database.SessionLocal", return_value=mock_db), \
             patch.object(sync_task_module, "decrypt_credentials", return_value={}), \
             patch("app.services.sync_service.mark_sync_running"), \
             patch("app.services.sync_service.mark_sync_completed"), \
             patch("app.services.sync_service.reset_consecutive_failures"), \
             patch("app.connectors.cloudflare.CloudflareConnector.fetch", return_value=[]), \
             patch("app.services.snapshot_service.get_latest_snapshot", return_value=None), \
             patch(
                 "app.services.snapshot_service.store_snapshot",
                 side_effect=capture_store_snapshot,
             ):
            sync_task_module.sync_integration(
                sync_run_id=str(_sync_run_id),
                integration_id=str(_integration_id),
                user_id=str(_user_id),
            )

        assert len(store_snapshot_calls) == 1, (
            "store_snapshot should have been called exactly once for the resource"
        )
        called_triggered_by = store_snapshot_calls[0].get("triggered_by")
        assert called_triggered_by == "scheduled", (
            f"store_snapshot was called with triggered_by={called_triggered_by!r}, "
            f"expected 'scheduled'. "
            f"The old hardcoded triggered_by='manual' bug is still present in sync_task.py."
        )

    def test_store_snapshot_receives_manual_triggered_by_for_manual_sync(self):
        """Regression: manual syncs must still pass triggered_by='manual'."""
        import app.workers.sync_task as sync_task_module

        _sync_run_id = uuid.uuid4()
        _integration_id = uuid.uuid4()
        _user_id = uuid.uuid4()
        _resource_id = uuid.uuid4()

        mock_sync_run = MagicMock()
        mock_sync_run.triggered_by = "manual"

        mock_integration = MagicMock()
        mock_integration.provider = "cloudflare"
        mock_integration.display_name = "Test CF"
        mock_integration.user_id = _user_id
        mock_integration.id = _integration_id
        mock_integration.encrypted_credentials = b"enc"
        mock_integration.credential_iv = b"iv"

        mock_resource = MagicMock()
        mock_resource.id = _resource_id
        mock_resource.user_id = _user_id
        mock_resource.is_active = True

        store_snapshot_calls: list[dict] = []

        def capture_store_snapshot(**kwargs):
            store_snapshot_calls.append(kwargs)
            return (MagicMock(), False)

        pk_map = {
            str(_sync_run_id): mock_sync_run,
            str(_integration_id): mock_integration,
        }
        mock_db = MagicMock()
        mock_db.get.side_effect = lambda model, pk: pk_map.get(str(pk))
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_resource]

        with patch("app.database.SessionLocal", return_value=mock_db), \
             patch.object(sync_task_module, "decrypt_credentials", return_value={}), \
             patch("app.services.sync_service.mark_sync_running"), \
             patch("app.services.sync_service.mark_sync_completed"), \
             patch("app.services.sync_service.reset_consecutive_failures"), \
             patch("app.connectors.cloudflare.CloudflareConnector.fetch", return_value=[]), \
             patch("app.services.snapshot_service.get_latest_snapshot", return_value=None), \
             patch(
                 "app.services.snapshot_service.store_snapshot",
                 side_effect=capture_store_snapshot,
             ):
            sync_task_module.sync_integration(
                sync_run_id=str(_sync_run_id),
                integration_id=str(_integration_id),
                user_id=str(_user_id),
            )

        assert len(store_snapshot_calls) == 1
        called_triggered_by = store_snapshot_calls[0].get("triggered_by")
        assert called_triggered_by == "manual", (
            f"Manual sync should still pass triggered_by='manual', got {called_triggered_by!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 7. Backward-compat eligibility (production seen=0 regression)
# ─────────────────────────────────────────────────────────────────────────────


class TestScheduledSyncEligibilityBackwardCompat:
    """Regression tests for the 'seen=0' production bug.

    Root cause:
        The eligibility query filtered on ``scheduled_sync_enabled IS TRUE``.
        All integrations created before ``scheduled_sync_enabled`` defaulted
        to ``True`` have the value ``False`` (the old server_default).  After
        that filter was introduced, ``seen`` dropped from N to 0 in production.

    Fix:
        The eligibility condition is now:
            scheduled_sync_enabled IS TRUE
            OR sync_interval_minutes IS NOT NULL
        This provides backward compatibility for pre-existing integrations that
        have a configured interval but the old default flag value.

    These tests verify the scheduler's in-Python eligibility filter by passing
    mock Integration objects with different flag/interval combinations directly
    to the scheduler via the _run_scheduler helper.
    """

    def test_flag_true_with_interval_is_eligible(self):
        """Standard case: scheduled_sync_enabled=True + interval → enqueued."""
        i = _make_integration(scheduled_sync_enabled=True, sync_interval_minutes=60)
        result = _run_scheduler([i])
        assert result["enqueued"] == 1
        assert result["integrations_seen"] == 1

    def test_flag_false_with_interval_is_eligible_backward_compat(self):
        """Backward compat: scheduled_sync_enabled=False + interval IS NOT NULL → enqueued.

        This is the exact scenario that caused 'seen=0' in production:
        existing integrations have the old False default but a valid interval.
        They must be included in the eligibility scan without a data migration.
        """
        i = _make_integration(scheduled_sync_enabled=False, sync_interval_minutes=60)
        result = _run_scheduler([i])
        assert result["enqueued"] == 1, (
            "Integration with scheduled_sync_enabled=False but sync_interval_minutes=60 "
            "was not enqueued.  The backward-compat eligibility fix is not working."
        )
        assert result["integrations_seen"] == 1

    def test_flag_false_no_interval_is_not_eligible(self):
        """Explicit exclusion: scheduled_sync_enabled=False + no interval → not enqueued.

        An integration with neither an explicit flag nor a configured cadence
        should remain excluded.  This protects integrations that were never
        intended to be scheduled.
        """
        i = _make_integration(scheduled_sync_enabled=False, sync_interval_minutes=None)
        result = _run_scheduler([i])
        assert result["enqueued"] == 0, (
            "Integration with scheduled_sync_enabled=False and no interval was "
            "unexpectedly enqueued."
        )
        assert result["integrations_seen"] == 0

    def test_flag_true_no_interval_is_eligible(self):
        """Explicit opt-in: scheduled_sync_enabled=True, no interval → uses default cadence."""
        i = _make_integration(scheduled_sync_enabled=True, sync_interval_minutes=None)
        result = _run_scheduler([i])
        assert result["enqueued"] == 1

    def test_mixed_old_and_new_integrations(self):
        """Mixed batch: old-default (False+interval) and new (True+interval) both enqueued."""
        old_style = _make_integration(scheduled_sync_enabled=False, sync_interval_minutes=60)
        new_style = _make_integration(scheduled_sync_enabled=True, sync_interval_minutes=60)
        result = _run_scheduler([old_style, new_style])
        assert result["enqueued"] == 2, (
            f"Expected both old-style (flag=False, interval=60) and new-style "
            f"(flag=True, interval=60) to be enqueued; got enqueued={result['enqueued']}"
        )

    def test_excluded_integration_does_not_affect_eligible_count(self):
        """Ineligible integration (no flag, no interval) is silently skipped."""
        eligible = _make_integration(scheduled_sync_enabled=True, sync_interval_minutes=60)
        ineligible = _make_integration(scheduled_sync_enabled=False, sync_interval_minutes=None)
        result = _run_scheduler([eligible, ineligible])
        # Only the eligible one is seen and enqueued
        assert result["enqueued"] == 1
        assert result["integrations_seen"] == 1

    def test_all_five_providers_backward_compat(self):
        """All five providers with old-style False flag + interval are all enqueued."""
        integrations = [
            _make_integration(provider=p, scheduled_sync_enabled=False, sync_interval_minutes=60)
            for p in ("cloudflare", "github", "vercel", "stripe", "aws")
        ]
        result = _run_scheduler(integrations)
        assert result["enqueued"] == 5, (
            f"Expected all 5 providers to be enqueued with backward-compat flag; "
            f"got enqueued={result['enqueued']}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# M57.6: Shopify provider in scheduler + IntegrationResponse new fields
# ─────────────────────────────────────────────────────────────────────────────


class TestM576SyncHealthFields:
    """M57.6: Verify that the Shopify provider is included in the scheduler and
    that the IntegrationResponse schema exposes the new scheduled_sync_enabled
    and last_failure_at fields added in M57.6."""

    # ── 1. Shopify in _SUPPORTED_PROVIDERS ───────────────────────────────────

    def test_shopify_in_supported_providers(self):
        """'shopify' must be present in sync_service._SUPPORTED_PROVIDERS so
        Shopify integrations get scheduled syncs.

        Before M57.6 this was missing, causing Shopify scheduled syncs to be
        silently skipped on every Beat tick.
        """
        from app.services import sync_service
        # _SUPPORTED_PROVIDERS is module-level but constructed inside the function;
        # we instantiate it by calling the scheduler and inspecting the log,
        # OR we just read the source constant from the service module's function
        # by running a dry-run scheduler with a Shopify integration.
        shopify_int = _make_integration(
            provider="shopify",
            scheduled_sync_enabled=True,
            sync_interval_minutes=60,
            last_synced_at=None,
        )
        result = _run_scheduler([shopify_int])
        assert result["enqueued"] == 1, (
            "'shopify' provider is not in _SUPPORTED_PROVIDERS — "
            "Shopify integration was not enqueued.  "
            "Did you forget to add 'shopify' to the tuple?"
        )
        assert result["integrations_seen"] == 1

    def test_shopify_backward_compat_flag_false_with_interval(self):
        """Shopify with old-style False flag + interval is still eligible."""
        shopify_int = _make_integration(
            provider="shopify",
            scheduled_sync_enabled=False,
            sync_interval_minutes=60,
            last_synced_at=None,
        )
        result = _run_scheduler([shopify_int])
        assert result["enqueued"] == 1, (
            "Shopify integration with scheduled_sync_enabled=False but "
            "sync_interval_minutes=60 was not enqueued."
        )

    def test_all_eight_providers_backward_compat(self):
        """All eight providers (including shopify) with old-style flag are enqueued."""
        all_providers = (
            "cloudflare", "github", "vercel", "stripe",
            "aws", "firebase", "supabase", "shopify",
        )
        integrations = [
            _make_integration(provider=p, scheduled_sync_enabled=False, sync_interval_minutes=60)
            for p in all_providers
        ]
        result = _run_scheduler(integrations)
        assert result["enqueued"] == len(all_providers), (
            f"Expected all {len(all_providers)} providers to be enqueued; "
            f"got enqueued={result['enqueued']}.  "
            f"Check that _SUPPORTED_PROVIDERS includes all eight providers."
        )

    # ── 2. IntegrationResponse exposes new M57.6 fields ──────────────────────

    def test_integration_response_has_scheduled_sync_enabled_field(self):
        """IntegrationResponse must have a scheduled_sync_enabled field (M57.6)."""
        from app.schemas.integration import IntegrationResponse
        fields = IntegrationResponse.model_fields
        assert "scheduled_sync_enabled" in fields, (
            "IntegrationResponse is missing the 'scheduled_sync_enabled' field added "
            "in M57.6.  The frontend needs this to display honest monitoring cadence copy."
        )

    def test_integration_response_has_last_failure_at_field(self):
        """IntegrationResponse must have a last_failure_at field (M57.6)."""
        from app.schemas.integration import IntegrationResponse
        fields = IntegrationResponse.model_fields
        assert "last_failure_at" in fields, (
            "IntegrationResponse is missing the 'last_failure_at' field added "
            "in M57.6.  The frontend needs this for stale-sync warnings."
        )

    def test_integration_response_scheduled_sync_enabled_default_false(self):
        """scheduled_sync_enabled must default to False in IntegrationResponse."""
        from app.schemas.integration import IntegrationResponse
        field_info = IntegrationResponse.model_fields["scheduled_sync_enabled"]
        assert field_info.default is False, (
            "scheduled_sync_enabled default should be False "
            f"(safe default when field is absent), got {field_info.default!r}"
        )

    def test_integration_response_last_failure_at_default_none(self):
        """last_failure_at must default to None in IntegrationResponse."""
        from app.schemas.integration import IntegrationResponse
        field_info = IntegrationResponse.model_fields["last_failure_at"]
        assert field_info.default is None, (
            f"last_failure_at default should be None, got {field_info.default!r}"
        )

    def test_integration_response_serializes_scheduled_sync_enabled(self):
        """IntegrationResponse round-trips scheduled_sync_enabled correctly."""
        from app.schemas.integration import IntegrationResponse
        import uuid
        from datetime import datetime, timezone

        resp = IntegrationResponse(
            id=uuid.uuid4(),
            provider="shopify",
            display_name="Test Shopify",
            status="active",
            last_synced_at=None,
            created_at=datetime.now(timezone.utc),
            resource_count=0,
            scheduled_sync_enabled=True,
            last_failure_at=None,
        )
        data = resp.model_dump()
        assert data["scheduled_sync_enabled"] is True
        assert data["last_failure_at"] is None
