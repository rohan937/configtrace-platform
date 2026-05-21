"""Milestone 11 tests: Changes API and Resources API.

Run with:
    docker compose run --rm api sh -lc "pip install -r requirements-dev.txt && pytest tests/test_milestone11.py -v"

All tests use the ``client`` and ``db_session`` fixtures from conftest.py.
No real Cloudflare credentials are required.  Change and Snapshot rows are
written directly to the database rather than via a live sync.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.models.user import User


# ─────────────────────────────────────────────────────────────────────────────
# Test data factories
# ─────────────────────────────────────────────────────────────────────────────

def _dns_record(
    record_id: str,
    name: str = "example.com",
    content: str = "1.2.3.4",
    record_type: str = "A",
) -> dict:
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


def _make_integration(db_session, user: User) -> Integration:
    """Insert an Integration + Resource (bypasses API/connector)."""
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


def _get_resource(db_session, integration: Integration) -> Resource:
    return (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )


def _make_snapshot(
    db_session,
    user: User,
    integration: Integration,
    resource: Resource,
    state: list[dict],
) -> Snapshot:
    snap = Snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        state=state,
        content_hash=str(uuid.uuid4()),   # unique per call for test isolation
        triggered_by="manual",
    )
    db_session.add(snap)
    db_session.commit()
    db_session.refresh(snap)
    return snap


def _make_change(
    db_session,
    user: User,
    integration: Integration,
    resource: Resource,
    prev_snap: Snapshot,
    new_snap: Snapshot,
    change_type: str = "modified",
    risk_level: str = "low",
    field_path: str | None = "content",
    prev_value=None,
    new_value=None,
    record_identifier: str = "A example.com",
) -> Change:
    change = Change(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        prev_snapshot_id=prev_snap.id,
        new_snapshot_id=new_snap.id,
        change_type=change_type,
        record_identifier=record_identifier,
        field_path=field_path,
        prev_value=prev_value or "1.1.1.1",
        new_value=new_value or "9.9.9.9",
        risk_level=risk_level,
        risk_reason="Test risk reason.",
        provider_metadata={
            "record_id": "rec-001",
            "record_type": "A",
            "record_name": "example.com",
            "record_content": "1.1.1.1",
        },
    )
    db_session.add(change)
    db_session.commit()
    db_session.refresh(change)
    return change


# ─────────────────────────────────────────────────────────────────────────────
# ── Changes API: GET /changes ─────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_get_changes_empty_when_no_changes(client, db_session, test_user) -> None:
    """GET /changes returns empty items list when the user has no changes."""
    resp = client.get("/changes")
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["page"] == 1


def test_get_changes_returns_changes_newest_first(
    client, db_session, test_user
) -> None:
    """GET /changes returns changes ordered by created_at DESC."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_c = _make_snapshot(db_session, test_user, integration, resource, state)

    change1 = _make_change(
        db_session, test_user, integration, resource, snap_a, snap_b,
        prev_value="1.1.1.1", new_value="2.2.2.2",
    )
    change2 = _make_change(
        db_session, test_user, integration, resource, snap_b, snap_c,
        prev_value="2.2.2.2", new_value="3.3.3.3",
    )

    resp = client.get("/changes")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    ids = [item["id"] for item in body["items"]]
    # Most recent first: change2 was inserted after change1
    assert ids[0] == str(change2.id)
    assert ids[1] == str(change1.id)


def test_get_changes_filter_by_risk_level(client, db_session, test_user) -> None:
    """GET /changes?risk_level=critical returns only critical changes."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_c = _make_snapshot(db_session, test_user, integration, resource, state)

    _make_change(
        db_session, test_user, integration, resource, snap_a, snap_b,
        risk_level="critical", change_type="removed", field_path=None,
    )
    _make_change(
        db_session, test_user, integration, resource, snap_b, snap_c,
        risk_level="low",
    )

    resp = client.get("/changes?risk_level=critical")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["risk_level"] == "critical"


def test_get_changes_filter_by_change_type(client, db_session, test_user) -> None:
    """GET /changes?change_type=added returns only added changes."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_c = _make_snapshot(db_session, test_user, integration, resource, state)

    _make_change(
        db_session, test_user, integration, resource, snap_a, snap_b,
        change_type="added", field_path=None,
        prev_value=None, new_value=_dns_record("rec-new"),
    )
    _make_change(
        db_session, test_user, integration, resource, snap_b, snap_c,
        change_type="removed", field_path=None,
        prev_value=_dns_record("rec-old"), new_value=None,
    )

    resp = client.get("/changes?change_type=added")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["change_type"] == "added"


def test_get_changes_filter_by_integration_id(client, db_session, test_user) -> None:
    """GET /changes?integration_id=... returns only that integration's changes."""
    int1 = _make_integration(db_session, test_user)
    res1 = _get_resource(db_session, int1)

    # Second integration (different zone ID to satisfy unique constraint)
    from app.core.encryption import encrypt_credentials
    ciphertext, iv = encrypt_credentials({"api_token": "tok2", "zone_id": "zone456"})
    int2 = Integration(
        user_id=test_user.id,
        provider="cloudflare",
        display_name="Second Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(int2)
    db_session.flush()
    res2 = Resource(
        integration_id=int2.id,
        user_id=test_user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id="zone456",
        display_name="Zone 456",
        is_active=True,
    )
    db_session.add(res2)
    db_session.commit()
    db_session.refresh(int2)
    db_session.refresh(res2)

    state = [_dns_record("rec-001")]
    snap1a = _make_snapshot(db_session, test_user, int1, res1, state)
    snap1b = _make_snapshot(db_session, test_user, int1, res1, state)
    snap2a = _make_snapshot(db_session, test_user, int2, res2, state)
    snap2b = _make_snapshot(db_session, test_user, int2, res2, state)

    _make_change(db_session, test_user, int1, res1, snap1a, snap1b)
    _make_change(db_session, test_user, int2, res2, snap2a, snap2b)

    resp = client.get(f"/changes?integration_id={int1.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["integration_id"] == str(int1.id)


def test_get_changes_filter_by_resource_id(client, db_session, test_user) -> None:
    """GET /changes?resource_id=... returns only that resource's changes."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)

    change = _make_change(db_session, test_user, integration, resource, snap_a, snap_b)

    resp = client.get(f"/changes?resource_id={resource.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == str(change.id)


def test_get_changes_pagination(client, db_session, test_user) -> None:
    """GET /changes pagination returns correct page and total."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    state = [_dns_record("rec-001")]

    # Create 5 changes with distinct snapshots
    snaps = [
        _make_snapshot(db_session, test_user, integration, resource, state)
        for _ in range(6)
    ]
    for i in range(5):
        _make_change(
            db_session, test_user, integration, resource,
            snaps[i], snaps[i + 1],
            prev_value=f"1.1.1.{i}",
            new_value=f"2.2.2.{i}",
        )

    # Page 1: first 3
    resp = client.get("/changes?page=1&page_size=3")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["items"]) == 3
    assert body["page"] == 1
    assert body["page_size"] == 3

    # Page 2: remaining 2
    resp2 = client.get("/changes?page=2&page_size=3")
    body2 = resp2.json()
    assert len(body2["items"]) == 2
    assert body2["page"] == 2

    # No overlap between pages
    ids1 = {item["id"] for item in body["items"]}
    ids2 = {item["id"] for item in body2["items"]}
    assert ids1.isdisjoint(ids2)


# ─────────────────────────────────────────────────────────────────────────────
# ── Changes API: GET /changes/{change_id} ────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_get_change_detail_includes_snapshot_states(
    client, db_session, test_user
) -> None:
    """GET /changes/{id} returns prev/new snapshot states and timestamps."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    prev_state = [_dns_record("rec-001", content="1.1.1.1")]
    new_state = [_dns_record("rec-001", content="9.9.9.9")]
    snap_prev = _make_snapshot(db_session, test_user, integration, resource, prev_state)
    snap_new = _make_snapshot(db_session, test_user, integration, resource, new_state)

    change = _make_change(
        db_session, test_user, integration, resource, snap_prev, snap_new,
        prev_value="1.1.1.1", new_value="9.9.9.9",
    )

    resp = client.get(f"/changes/{change.id}")
    assert resp.status_code == 200
    body = resp.json()

    assert body["id"] == str(change.id)
    assert body["change_type"] == "modified"
    assert body["field_path"] == "content"
    assert body["prev_value"] == "1.1.1.1"
    assert body["new_value"] == "9.9.9.9"
    assert body["risk_level"] == "low"
    assert body["risk_reason"] == "Test risk reason."

    # Snapshot references
    assert body["prev_snapshot_id"] == str(snap_prev.id)
    assert body["new_snapshot_id"] == str(snap_new.id)

    # Full states are included
    assert body["prev_snapshot_state"] is not None
    assert len(body["prev_snapshot_state"]) == 1
    assert body["prev_snapshot_state"][0]["content"] == "1.1.1.1"

    assert body["new_snapshot_state"] is not None
    assert len(body["new_snapshot_state"]) == 1
    assert body["new_snapshot_state"][0]["content"] == "9.9.9.9"

    # Snapshot timestamps
    assert body["prev_snapshot_created_at"] is not None
    assert body["new_snapshot_created_at"] is not None


def test_get_change_detail_404_for_unknown_id(client, db_session, test_user) -> None:
    """GET /changes/{id} returns 404 for a non-existent UUID."""
    resp = client.get(f"/changes/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_get_change_detail_404_for_another_users_change(
    client, db_session, test_user
) -> None:
    """GET /changes/{id} returns 404 when the change belongs to another user."""
    # Create a second user and their change
    other_user = User(
        clerk_id=f"other_clerk_{uuid.uuid4().hex[:8]}",
        email=f"other_{uuid.uuid4().hex[:8]}@example.com",
        display_name="Other User",
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    other_int = _make_integration(db_session, other_user)
    other_res = _get_resource(db_session, other_int)
    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, other_user, other_int, other_res, state)
    snap_b = _make_snapshot(db_session, other_user, other_int, other_res, state)
    other_change = _make_change(
        db_session, other_user, other_int, other_res, snap_a, snap_b
    )

    # test_user tries to access other_user's change
    resp = client.get(f"/changes/{other_change.id}")
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# ── Resources API: GET /resources ────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_get_resources_returns_user_resources(
    client, db_session, test_user
) -> None:
    """GET /resources returns resources belonging to the authenticated user."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    resp = client.get("/resources")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == str(resource.id)
    assert body["items"][0]["display_name"] == "Zone 123"
    assert body["items"][0]["integration_id"] == str(integration.id)


def test_get_resources_filter_by_integration_id(
    client, db_session, test_user
) -> None:
    """GET /resources?integration_id=... filters to one integration."""
    from app.core.encryption import encrypt_credentials

    int1 = _make_integration(db_session, test_user)

    ciphertext, iv = encrypt_credentials({"api_token": "tok2", "zone_id": "zone789"})
    int2 = Integration(
        user_id=test_user.id,
        provider="cloudflare",
        display_name="Integration 2",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(int2)
    db_session.flush()
    res2 = Resource(
        integration_id=int2.id,
        user_id=test_user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id="zone789",
        display_name="Zone 789",
        is_active=True,
    )
    db_session.add(res2)
    db_session.commit()

    resp = client.get(f"/resources?integration_id={int1.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["integration_id"] == str(int1.id)


def test_get_resources_pagination(client, db_session, test_user) -> None:
    """GET /resources pagination returns correct subset."""
    from app.core.encryption import encrypt_credentials

    for i in range(3):
        ciphertext, iv = encrypt_credentials(
            {"api_token": f"tok{i}", "zone_id": f"zone_pg_{i}"}
        )
        intg = Integration(
            user_id=test_user.id,
            provider="cloudflare",
            display_name=f"Integration {i}",
            encrypted_credentials=ciphertext,
            credential_iv=iv,
            status="active",
        )
        db_session.add(intg)
        db_session.flush()
        db_session.add(Resource(
            integration_id=intg.id,
            user_id=test_user.id,
            provider_resource_type="cloudflare_dns_zone",
            provider_resource_id=f"zone_pg_{i}",
            display_name=f"Zone {i}",
            is_active=True,
        ))
    db_session.commit()

    resp = client.get("/resources?page=1&page_size=2")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2

    resp2 = client.get("/resources?page=2&page_size=2")
    body2 = resp2.json()
    assert len(body2["items"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# ── Resources API: GET /resources/{resource_id} ───────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_get_resource_detail_includes_counts(
    client, db_session, test_user
) -> None:
    """GET /resources/{id} includes snapshot_count and change_count."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)
    _make_change(db_session, test_user, integration, resource, snap_a, snap_b)

    resp = client.get(f"/resources/{resource.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(resource.id)
    assert body["snapshot_count"] == 2
    assert body["change_count"] == 1
    assert body["provider_resource_type"] == "cloudflare_dns_zone"
    assert body["is_active"] is True


def test_get_resource_detail_404_for_unknown_id(
    client, db_session, test_user
) -> None:
    """GET /resources/{id} returns 404 for a non-existent UUID."""
    resp = client.get(f"/resources/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_get_resource_detail_404_for_another_users_resource(
    client, db_session, test_user
) -> None:
    """GET /resources/{id} returns 404 when resource belongs to another user."""
    other_user = User(
        clerk_id=f"other2_{uuid.uuid4().hex[:8]}",
        email=f"other2_{uuid.uuid4().hex[:8]}@example.com",
        display_name="Other User 2",
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    other_int = _make_integration(db_session, other_user)
    other_res = _get_resource(db_session, other_int)

    resp = client.get(f"/resources/{other_res.id}")
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# ── Resources API: GET /resources/{resource_id}/snapshots ────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_get_resource_snapshots_newest_first(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/snapshots returns snapshots in reverse chronological order."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    state_a = [_dns_record("rec-001", content="1.1.1.1")]
    state_b = [_dns_record("rec-001", content="2.2.2.2")]

    snap_a = _make_snapshot(db_session, test_user, integration, resource, state_a)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state_b)

    resp = client.get(f"/resources/{resource.id}/snapshots")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    # Newest first
    assert body["items"][0]["id"] == str(snap_b.id)
    assert body["items"][1]["id"] == str(snap_a.id)
    # State is included
    assert body["items"][0]["state"][0]["content"] == "2.2.2.2"


def test_get_resource_snapshots_empty_when_none_exist(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/snapshots returns empty list for a resource with no snapshots."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    resp = client.get(f"/resources/{resource.id}/snapshots")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["items"] == []


def test_get_resource_snapshots_404_for_unknown_resource(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/snapshots returns 404 for unknown resource."""
    resp = client.get(f"/resources/{uuid.uuid4()}/snapshots")
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# ── Resources API: GET /resources/{resource_id}/changes ──────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_get_resource_changes_newest_first(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/changes returns changes in reverse chronological order."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    state = [_dns_record("rec-001")]

    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_c = _make_snapshot(db_session, test_user, integration, resource, state)

    change1 = _make_change(
        db_session, test_user, integration, resource, snap_a, snap_b,
        prev_value="1.0.0.0", new_value="2.0.0.0",
    )
    change2 = _make_change(
        db_session, test_user, integration, resource, snap_b, snap_c,
        prev_value="2.0.0.0", new_value="3.0.0.0",
    )

    resp = client.get(f"/resources/{resource.id}/changes")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    ids = [item["id"] for item in body["items"]]
    assert ids[0] == str(change2.id)
    assert ids[1] == str(change1.id)


def test_get_resource_changes_empty_when_none_exist(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/changes returns empty list when no changes exist."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    resp = client.get(f"/resources/{resource.id}/changes")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["items"] == []


def test_get_resource_changes_404_for_unknown_resource(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/changes returns 404 for unknown resource."""
    resp = client.get(f"/resources/{uuid.uuid4()}/changes")
    assert resp.status_code == 404


def test_get_resource_changes_404_for_another_users_resource(
    client, db_session, test_user
) -> None:
    """GET /resources/{id}/changes returns 404 for another user's resource."""
    other_user = User(
        clerk_id=f"other3_{uuid.uuid4().hex[:8]}",
        email=f"other3_{uuid.uuid4().hex[:8]}@example.com",
        display_name="Other User 3",
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    other_int = _make_integration(db_session, other_user)
    other_res = _get_resource(db_session, other_int)

    resp = client.get(f"/resources/{other_res.id}/changes")
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# ── Response shape validation ─────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def test_change_list_item_shape(client, db_session, test_user) -> None:
    """GET /changes items contain all required fields."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    state = [_dns_record("rec-001")]
    snap_a = _make_snapshot(db_session, test_user, integration, resource, state)
    snap_b = _make_snapshot(db_session, test_user, integration, resource, state)
    _make_change(
        db_session, test_user, integration, resource, snap_a, snap_b,
        risk_level="high", change_type="modified", field_path="ttl",
        prev_value=3600, new_value=60,
    )

    resp = client.get("/changes")
    assert resp.status_code == 200
    item = resp.json()["items"][0]

    required_fields = {
        "id", "integration_id", "resource_id", "change_type",
        "record_identifier", "field_path", "prev_value", "new_value",
        "risk_level", "risk_reason", "provider_metadata", "created_at",
    }
    for field in required_fields:
        assert field in item, f"Missing field: {field}"

    assert item["change_type"] == "modified"
    assert item["field_path"] == "ttl"
    assert item["prev_value"] == 3600
    assert item["new_value"] == 60
    assert item["risk_level"] == "high"


def test_resource_list_item_shape(client, db_session, test_user) -> None:
    """GET /resources items contain all required fields."""
    integration = _make_integration(db_session, test_user)

    resp = client.get("/resources")
    assert resp.status_code == 200
    item = resp.json()["items"][0]

    required_fields = {
        "id", "integration_id", "provider_resource_type",
        "provider_resource_id", "display_name",
        "last_snapshot_at", "is_active", "created_at", "updated_at",
    }
    for field in required_fields:
        assert field in item, f"Missing field: {field}"

    assert item["provider_resource_type"] == "cloudflare_dns_zone"
    assert item["is_active"] is True


def test_snapshot_list_item_includes_state(client, db_session, test_user) -> None:
    """GET /resources/{id}/snapshots items include the full state array."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)
    records = [_dns_record("rec-001", content="5.5.5.5")]
    _make_snapshot(db_session, test_user, integration, resource, records)

    resp = client.get(f"/resources/{resource.id}/snapshots")
    assert resp.status_code == 200
    item = resp.json()["items"][0]

    assert "state" in item
    assert isinstance(item["state"], list)
    assert item["state"][0]["content"] == "5.5.5.5"
    assert item["triggered_by"] == "manual"
    assert "content_hash" in item
    assert "created_at" in item
