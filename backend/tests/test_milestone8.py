"""Milestone 8 tests: snapshot service and updated sync task.

Run with:
    docker compose run --rm api pytest tests/test_milestone8.py -v

Tests use the shared fixtures from conftest.py (real PostgreSQL + cleanup).
Cloudflare API calls are always mocked — no live network calls are made.
"""

from __future__ import annotations

from unittest.mock import patch

from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services.snapshot_service import (
    compute_content_hash,
    get_latest_snapshot,
    store_snapshot,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dns_record(
    record_id: str,
    name: str = "example.com",
    content: str = "1.2.3.4",
    record_type: str = "A",
) -> dict:
    """Return a minimal CloudflareDNSRecord-shaped dict."""
    return {
        "record_id": record_id,
        "record_type": record_type,
        "name": name,
        "content": content,
        "ttl": 300,
        "proxied": False,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-21T00:00:00Z",
    }


def _make_integration(db_session, user) -> Integration:
    """Insert an Integration + Resource directly (bypasses validation)."""
    from app.core.encryption import encrypt_credentials

    ciphertext, iv = encrypt_credentials(
        {"api_token": "fake_tok", "zone_id": "zone123"}
    )
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name="Test Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(integration)
    db_session.flush()  # populate integration.id

    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id="zone123",
        display_name="Zone 123",
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    db_session.refresh(resource)
    return integration


def _make_sync_run(db_session, user, integration):
    from app.services.sync_service import create_sync_run

    return create_sync_run(
        user_id=user.id,
        integration_id=integration.id,
        db=db_session,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. compute_content_hash — pure unit tests (no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_hash_is_deterministic() -> None:
    """Same records in any order produce the same hash."""
    r1 = _dns_record("rec-aaa", content="1.1.1.1")
    r2 = _dns_record("rec-bbb", content="2.2.2.2")

    h_forward = compute_content_hash([r1, r2])
    h_reverse = compute_content_hash([r2, r1])

    assert h_forward == h_reverse
    assert len(h_forward) == 64   # SHA-256 hex


def test_hash_changes_on_field_edit() -> None:
    """Modifying a record field produces a different hash."""
    r = _dns_record("rec-aaa", content="1.1.1.1")
    h_before = compute_content_hash([r])

    r_modified = {**r, "content": "9.9.9.9"}
    h_after = compute_content_hash([r_modified])

    assert h_before != h_after


def test_hash_changes_on_record_added() -> None:
    """Adding a record to the state produces a different hash."""
    r1 = _dns_record("rec-aaa")
    h_one = compute_content_hash([r1])

    r2 = _dns_record("rec-bbb")
    h_two = compute_content_hash([r1, r2])

    assert h_one != h_two


def test_hash_empty_state() -> None:
    """An empty state list produces a stable (non-crashing) hash."""
    h = compute_content_hash([])
    assert len(h) == 64


# ─────────────────────────────────────────────────────────────────────────────
# 2. store_snapshot — integration tests (real DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_first_snapshot_is_always_stored(db_session, test_user) -> None:
    """When no prior snapshot exists, store_snapshot always writes one."""
    integration = _make_integration(db_session, test_user)
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )

    state = [_dns_record("rec-001")]
    snapshot, created = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=state,
        triggered_by="manual",
        db=db_session,
    )

    assert created is True
    assert snapshot.id is not None
    assert snapshot.resource_id == resource.id
    assert snapshot.integration_id == integration.id
    assert snapshot.user_id == test_user.id
    assert snapshot.triggered_by == "manual"
    assert snapshot.content_hash == compute_content_hash(state)


def test_identical_state_is_deduplicated(db_session, test_user) -> None:
    """store_snapshot returns the existing snapshot if state is unchanged."""
    integration = _make_integration(db_session, test_user)
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )
    state = [_dns_record("rec-001")]

    first, _ = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=state,
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()

    second, created = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=state,         # same state
        triggered_by="manual",
        db=db_session,
    )

    assert created is False
    assert second.id == first.id   # same row returned

    # Confirm only one row in the DB
    count = (
        db_session.query(Snapshot)
        .filter(Snapshot.resource_id == resource.id)
        .count()
    )
    assert count == 1


def test_changed_state_creates_new_snapshot(db_session, test_user) -> None:
    """store_snapshot writes a new row when the state hash differs."""
    integration = _make_integration(db_session, test_user)
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )

    state_v1 = [_dns_record("rec-001", content="1.1.1.1")]
    first, _ = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=state_v1,
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()

    state_v2 = [_dns_record("rec-001", content="9.9.9.9")]  # content changed
    second, created = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=state_v2,
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()

    assert created is True
    assert second.id != first.id
    assert second.content_hash != first.content_hash

    count = (
        db_session.query(Snapshot)
        .filter(Snapshot.resource_id == resource.id)
        .count()
    )
    assert count == 2


def test_get_latest_snapshot_returns_newest(db_session, test_user) -> None:
    """get_latest_snapshot returns the most-recently-created row."""
    integration = _make_integration(db_session, test_user)
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )

    snap_a, _ = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=[_dns_record("rec-aaa")],
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()

    snap_b, _ = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        state=[_dns_record("rec-bbb")],   # different → new row
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()

    latest = get_latest_snapshot(resource.id, db_session)
    assert latest is not None
    assert latest.id == snap_b.id


def test_get_latest_snapshot_returns_none_for_new_resource(db_session, test_user) -> None:
    """get_latest_snapshot returns None when no snapshots exist yet."""
    integration = _make_integration(db_session, test_user)
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )

    result = get_latest_snapshot(resource.id, db_session)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. sync_task integration tests (real DB, mocked connector)
# ─────────────────────────────────────────────────────────────────────────────

@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_stores_snapshot_on_first_run(
    mock_connector_cls, db_session, test_user
) -> None:
    """First sync: new snapshot created, SyncRun completed with snapshot_count=1."""
    records = [_dns_record("rec-001"), _dns_record("rec-002")]
    mock_connector_cls.return_value.fetch.return_value = records

    integration = _make_integration(db_session, test_user)
    sync_run = _make_sync_run(db_session, test_user, integration)

    from app.workers.sync_task import sync_integration

    result = sync_integration.apply(
        args=[str(sync_run.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["status"] == "completed"
    assert result["snapshot_count"] == 1
    assert result["change_count"] == 0

    db_session.expire_all()
    db_session.refresh(sync_run)
    assert sync_run.status == "completed"
    assert sync_run.snapshot_count == 1
    assert sync_run.completed_at is not None

    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )
    assert resource.last_snapshot_at is not None

    snapshot_count = (
        db_session.query(Snapshot)
        .filter(Snapshot.integration_id == integration.id)
        .count()
    )
    assert snapshot_count == 1


@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_deduplicates_unchanged_state(
    mock_connector_cls, db_session, test_user
) -> None:
    """Second sync with identical state: snapshot_count=0 (dedup skips write)."""
    records = [_dns_record("rec-001")]
    mock_connector_cls.return_value.fetch.return_value = records

    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    # First sync
    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # Second sync — identical records
    run2 = _make_sync_run(db_session, test_user, integration)
    result = sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["snapshot_count"] == 0   # dedup: no new snapshot

    db_session.expire_all()
    db_session.refresh(run2)
    assert run2.status == "completed"
    assert run2.snapshot_count == 0

    # Still only one Snapshot row in total
    total = (
        db_session.query(Snapshot)
        .filter(Snapshot.integration_id == integration.id)
        .count()
    )
    assert total == 1
