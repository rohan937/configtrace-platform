"""Milestone 9 tests: diff service and change detection in sync task.

Run with:
    docker compose run --rm api pytest tests/test_milestone9.py -v

Pure diff tests (build_record_index, compute_diff) use MagicMock snapshots —
no database required.  store_changes and sync task tests use real PostgreSQL
via the fixtures in conftest.py.  Cloudflare API calls are always mocked.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services.diff_service import (
    build_record_index,
    compute_diff,
    format_record_identifier,
    store_changes,
)
from app.services.snapshot_service import store_snapshot


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dns_record(
    record_id: str,
    name: str = "example.com",
    content: str = "1.2.3.4",
    record_type: str = "A",
    ttl: int = 300,
    proxied: bool = False,
    priority: int | None = None,
    comment: str | None = None,
) -> dict:
    """Return a minimal CloudflareDNSRecord-shaped dict."""
    return {
        "record_id": record_id,
        "record_type": record_type,
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": proxied,
        "priority": priority,
        "comment": comment,
        "modified_on": "2026-05-21T00:00:00Z",
    }


def _mock_snapshot(state: list[dict]) -> MagicMock:
    """Return a mock Snapshot with the given state (no DB needed)."""
    snap = MagicMock(spec=Snapshot)
    snap.state = state
    snap.id = uuid.uuid4()
    return snap


def _make_integration(db_session, user) -> Integration:
    """Insert an Integration + Resource directly (bypasses API validation)."""
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
    db_session.flush()

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


def _get_resource(db_session, integration) -> Resource:
    return (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )


def _make_snapshot(db_session, user, integration, state: list[dict]) -> Snapshot:
    """Insert a Snapshot directly for use in store_changes tests."""
    resource = _get_resource(db_session, integration)
    snap, _ = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        state=state,
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()
    return snap


# ─────────────────────────────────────────────────────────────────────────────
# 1. build_record_index — pure unit tests (no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_build_record_index_by_external_id() -> None:
    """build_record_index prefers external_id over id and record_id."""
    record = {"external_id": "ext-123", "id": "id-456", "record_id": "rec-789",
              "name": "x.com", "record_type": "A"}
    index = build_record_index([record])

    assert "ext-123" in index
    assert index["ext-123"] is record


def test_build_record_index_by_id() -> None:
    """build_record_index uses id when external_id is absent."""
    record = {"id": "id-456", "record_id": "rec-789",
              "name": "x.com", "record_type": "A"}
    index = build_record_index([record])

    assert "id-456" in index
    assert index["id-456"] is record


def test_build_record_index_by_record_id() -> None:
    """build_record_index falls back to record_id (Cloudflare canonical field)."""
    record = _dns_record("rec-001")
    index = build_record_index([record])

    assert "rec-001" in index
    assert index["rec-001"] is record


def test_build_record_index_raises_on_missing_identifier() -> None:
    """build_record_index raises ValueError when no stable ID field is present."""
    record = {"name": "x.com", "record_type": "A", "content": "1.2.3.4"}

    with pytest.raises(ValueError, match="no stable identifier"):
        build_record_index([record])


# ─────────────────────────────────────────────────────────────────────────────
# 2. format_record_identifier — pure unit tests
# ─────────────────────────────────────────────────────────────────────────────

def test_format_record_identifier_uses_record_type_and_name() -> None:
    """format_record_identifier produces 'TYPE name' from normalised fields."""
    record = {"record_type": "A", "name": "api.example.com"}
    assert format_record_identifier(record) == "A api.example.com"


def test_format_record_identifier_falls_back_to_type_key() -> None:
    """format_record_identifier accepts raw 'type' key (future providers)."""
    record = {"type": "MX", "name": "example.com"}
    assert format_record_identifier(record) == "MX example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 3. compute_diff — pure unit tests (mock Snapshots, no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_compute_diff_identical_snapshots_returns_empty() -> None:
    """Identical state → empty change list."""
    state = [_dns_record("rec-001"), _dns_record("rec-002")]
    prev = _mock_snapshot(state)
    new = _mock_snapshot(state)

    assert compute_diff(prev, new) == []


def test_compute_diff_detects_added_record() -> None:
    """A record present in new but not prev → one 'added' change."""
    prev = _mock_snapshot([_dns_record("rec-001")])
    new = _mock_snapshot([_dns_record("rec-001"), _dns_record("rec-002")])

    changes = compute_diff(prev, new)

    assert len(changes) == 1
    c = changes[0]
    assert c["change_type"] == "added"
    assert c["field_path"] is None
    assert c["prev_value"] is None
    assert c["new_value"]["record_id"] == "rec-002"
    assert "rec-002" in c["record_identifier"] or c["record_identifier"]


def test_compute_diff_detects_removed_record() -> None:
    """A record present in prev but not new → one 'removed' change."""
    prev = _mock_snapshot([_dns_record("rec-001"), _dns_record("rec-002")])
    new = _mock_snapshot([_dns_record("rec-001")])

    changes = compute_diff(prev, new)

    assert len(changes) == 1
    c = changes[0]
    assert c["change_type"] == "removed"
    assert c["field_path"] is None
    assert c["prev_value"]["record_id"] == "rec-002"
    assert c["new_value"] is None


def test_compute_diff_detects_modified_ttl() -> None:
    """TTL change on a record → one 'modified' change with field_path='ttl'."""
    prev = _mock_snapshot([_dns_record("rec-001", ttl=3600)])
    new = _mock_snapshot([_dns_record("rec-001", ttl=60)])

    changes = compute_diff(prev, new)

    assert len(changes) == 1
    c = changes[0]
    assert c["change_type"] == "modified"
    assert c["field_path"] == "ttl"
    assert c["prev_value"] == 3600
    assert c["new_value"] == 60


def test_compute_diff_detects_modified_content() -> None:
    """Content change → one 'modified' change with field_path='content'."""
    prev = _mock_snapshot([_dns_record("rec-001", content="1.1.1.1")])
    new = _mock_snapshot([_dns_record("rec-001", content="9.9.9.9")])

    changes = compute_diff(prev, new)

    assert len(changes) == 1
    c = changes[0]
    assert c["change_type"] == "modified"
    assert c["field_path"] == "content"
    assert c["prev_value"] == "1.1.1.1"
    assert c["new_value"] == "9.9.9.9"


def test_compute_diff_detects_multiple_modified_fields() -> None:
    """Two changed fields on one record → two 'modified' change dicts."""
    prev = _mock_snapshot([_dns_record("rec-001", content="1.1.1.1", ttl=3600)])
    new = _mock_snapshot([_dns_record("rec-001", content="9.9.9.9", ttl=60)])

    changes = compute_diff(prev, new)

    modified = [c for c in changes if c["change_type"] == "modified"]
    assert len(modified) == 2
    fields = {c["field_path"] for c in modified}
    assert fields == {"content", "ttl"}


def test_compute_diff_ignores_modified_on_only() -> None:
    """A change only in modified_on produces zero change dicts."""
    rec_prev = {**_dns_record("rec-001"), "modified_on": "2026-01-01T00:00:00Z"}
    rec_new = {**_dns_record("rec-001"), "modified_on": "2026-06-01T00:00:00Z"}

    prev = _mock_snapshot([rec_prev])
    new = _mock_snapshot([rec_new])

    assert compute_diff(prev, new) == []


def test_compute_diff_ignores_created_on_only() -> None:
    """A change only in created_on produces zero change dicts."""
    rec_prev = {**_dns_record("rec-001"), "created_on": "2025-01-01T00:00:00Z"}
    rec_new = {**_dns_record("rec-001"), "created_on": "2026-01-01T00:00:00Z"}

    prev = _mock_snapshot([rec_prev])
    new = _mock_snapshot([rec_new])

    assert compute_diff(prev, new) == []


def test_compute_diff_provider_metadata_contains_record_context() -> None:
    """provider_metadata has record_type, record_name, and record_content."""
    prev = _mock_snapshot([])
    new = _mock_snapshot([_dns_record("rec-001", name="api.example.com",
                                      content="1.2.3.4", record_type="A")])

    changes = compute_diff(prev, new)

    assert len(changes) == 1
    meta = changes[0]["provider_metadata"]
    assert meta["record_type"] == "A"
    assert meta["record_name"] == "api.example.com"
    assert meta["record_content"] == "1.2.3.4"
    assert meta["record_id"] == "rec-001"


# ─────────────────────────────────────────────────────────────────────────────
# 4. store_changes — integration tests (real DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_store_changes_writes_with_unknown_risk_level(
    db_session, test_user
) -> None:
    """All Change rows written by store_changes have risk_level='unknown'."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    # Two real snapshot rows (FK constraints)
    snap_prev = _make_snapshot(db_session, test_user, integration,
                                [_dns_record("rec-001")])
    snap_new = _make_snapshot(db_session, test_user, integration,
                               [_dns_record("rec-001"), _dns_record("rec-002")])

    change_dicts = compute_diff(_mock_snapshot([_dns_record("rec-001")]),
                                _mock_snapshot([_dns_record("rec-001"),
                                                _dns_record("rec-002")]))

    changes = store_changes(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        prev_snapshot_id=snap_prev.id,
        new_snapshot_id=snap_new.id,
        change_dicts=change_dicts,
        db=db_session,
    )
    db_session.commit()

    assert len(changes) == 1
    assert changes[0].risk_level == "unknown"
    assert changes[0].risk_reason is None

    # Verify it's in the DB
    row = db_session.get(Change, changes[0].id)
    assert row is not None
    assert row.risk_level == "unknown"


def test_store_changes_snapshot_ids_are_correct(db_session, test_user) -> None:
    """store_changes sets prev_snapshot_id and new_snapshot_id correctly."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    snap_prev = _make_snapshot(db_session, test_user, integration,
                                [_dns_record("rec-001")])
    snap_new = _make_snapshot(db_session, test_user, integration,
                               [_dns_record("rec-002")])  # different → 2nd row

    change_dicts = [
        {
            "change_type": "added",
            "record_identifier": "A rec-002",
            "field_path": None,
            "prev_value": None,
            "new_value": _dns_record("rec-002"),
            "provider_metadata": {"record_id": "rec-002"},
        }
    ]

    changes = store_changes(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        prev_snapshot_id=snap_prev.id,
        new_snapshot_id=snap_new.id,
        change_dicts=change_dicts,
        db=db_session,
    )
    db_session.commit()

    assert len(changes) == 1
    row = db_session.get(Change, changes[0].id)
    assert row.prev_snapshot_id == snap_prev.id
    assert row.new_snapshot_id == snap_new.id


def test_store_changes_provider_metadata_is_stored(db_session, test_user) -> None:
    """provider_metadata dict is persisted verbatim in the Change row."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    snap_prev = _make_snapshot(db_session, test_user, integration, [])
    snap_new = _make_snapshot(db_session, test_user, integration,
                               [_dns_record("rec-001", name="api.example.com")])

    expected_meta = {
        "record_id": "rec-001",
        "record_type": "A",
        "record_name": "api.example.com",
        "record_content": "1.2.3.4",
    }
    change_dicts = [
        {
            "change_type": "added",
            "record_identifier": "A api.example.com",
            "field_path": None,
            "prev_value": None,
            "new_value": _dns_record("rec-001", name="api.example.com"),
            "provider_metadata": expected_meta,
        }
    ]

    changes = store_changes(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        prev_snapshot_id=snap_prev.id,
        new_snapshot_id=snap_new.id,
        change_dicts=change_dicts,
        db=db_session,
    )
    db_session.commit()

    row = db_session.get(Change, changes[0].id)
    assert row.provider_metadata == expected_meta


def test_store_changes_returns_empty_for_empty_input(db_session, test_user) -> None:
    """store_changes returns [] and writes nothing when change_dicts is empty."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    snap = _make_snapshot(db_session, test_user, integration,
                           [_dns_record("rec-001")])

    result = store_changes(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        prev_snapshot_id=snap.id,
        new_snapshot_id=snap.id,
        change_dicts=[],
        db=db_session,
    )

    assert result == []
    count = (
        db_session.query(Change)
        .filter(Change.resource_id == resource.id)
        .count()
    )
    assert count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Sync task integration — change detection (real DB, mocked connector)
# ─────────────────────────────────────────────────────────────────────────────

@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_baseline_creates_snapshot_zero_changes(
    mock_connector_cls, db_session, test_user
) -> None:
    """First sync: baseline snapshot stored, change_count=0 (no previous)."""
    mock_connector_cls.return_value.fetch.return_value = [_dns_record("rec-001")]

    integration = _make_integration(db_session, test_user)
    run = _make_sync_run(db_session, test_user, integration)

    from app.workers.sync_task import sync_integration

    result = sync_integration.apply(
        args=[str(run.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["snapshot_count"] == 1
    assert result["change_count"] == 0

    db_session.expire_all()
    db_session.refresh(run)
    assert run.snapshot_count == 1
    assert run.change_count == 0

    change_count = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .count()
    )
    assert change_count == 0


@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_no_change_sync_zero_snapshots_zero_changes(
    mock_connector_cls, db_session, test_user
) -> None:
    """Second sync with identical state: no new snapshot, no changes."""
    records = [_dns_record("rec-001")]
    mock_connector_cls.return_value.fetch.return_value = records

    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    run2 = _make_sync_run(db_session, test_user, integration)
    result = sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["snapshot_count"] == 0
    assert result["change_count"] == 0

    db_session.expire_all()
    db_session.refresh(run2)
    assert run2.snapshot_count == 0
    assert run2.change_count == 0

    total_changes = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .count()
    )
    assert total_changes == 0


@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_changed_sync_creates_change_rows(
    mock_connector_cls, db_session, test_user
) -> None:
    """Second sync with DNS changes: new snapshot + Change rows written."""
    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    # ── First sync — baseline ────────────────────────────────────────────────
    records_v1 = [_dns_record("rec-001", content="1.1.1.1")]
    mock_connector_cls.return_value.fetch.return_value = records_v1

    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # ── Second sync — content changed + new record added ─────────────────────
    records_v2 = [
        _dns_record("rec-001", content="9.9.9.9"),   # content modified
        _dns_record("rec-002", name="sub.example.com"),  # added
    ]
    mock_connector_cls.return_value.fetch.return_value = records_v2

    run2 = _make_sync_run(db_session, test_user, integration)
    result = sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["snapshot_count"] == 1
    # 1 modified (content on rec-001) + 1 added (rec-002)
    assert result["change_count"] == 2

    db_session.expire_all()
    db_session.refresh(run2)
    assert run2.change_count == 2

    changes = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .all()
    )
    assert len(changes) == 2

    change_types = {c.change_type for c in changes}
    assert "added" in change_types
    assert "modified" in change_types

    modified = next(c for c in changes if c.change_type == "modified")
    assert modified.field_path == "content"
    assert modified.prev_value == "1.1.1.1"
    assert modified.new_value == "9.9.9.9"
    assert modified.risk_level == "unknown"

    added = next(c for c in changes if c.change_type == "added")
    assert added.field_path is None
    assert added.prev_value is None


@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_change_count_on_sync_run(
    mock_connector_cls, db_session, test_user
) -> None:
    """SyncRun.change_count equals the number of Change rows written."""
    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    # Baseline
    mock_connector_cls.return_value.fetch.return_value = [
        _dns_record("rec-001"),
        _dns_record("rec-002"),
    ]
    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # Changed sync: rec-001 ttl modified, rec-002 removed, rec-003 added
    mock_connector_cls.return_value.fetch.return_value = [
        _dns_record("rec-001", ttl=60),
        _dns_record("rec-003", name="new.example.com"),
    ]
    run2 = _make_sync_run(db_session, test_user, integration)
    result = sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    # ttl modified (rec-001) + removed (rec-002) + added (rec-003) = 3
    assert result["change_count"] == 3

    db_session.expire_all()
    db_session.refresh(run2)
    assert run2.change_count == 3

    total_in_db = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .count()
    )
    assert total_in_db == 3
