"""Tests for backend/scripts/seed_dev_data.py.

Strategy
--------
The tests call ``seed_for_user`` directly with the fixture test_user's ID so
that all seeded rows belong to that user and are automatically cleaned up by
the ``test_user`` fixture teardown (CASCADE delete on the user row).

The ``client`` fixture overrides ``get_current_user`` to return ``test_user``
so that the existing GET /changes and GET /resources route handlers scope
their queries to the same user the seed data was written under.

All assertions use the real PostgreSQL DB (same as the rest of the test suite).
"""

from __future__ import annotations

import pytest

from scripts.seed_dev_data import (
    SEED_PROVIDER_RESOURCE_ID,
    seed_for_user,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _seed(client, test_user, db_session):
    """Seed data for *test_user* and return the summary dict."""
    summary = seed_for_user(test_user.id, db_session)
    db_session.commit()
    return summary


# ── tests ─────────────────────────────────────────────────────────────────────

class TestSeedFunction:
    """seed_for_user() creates the expected rows without crashing."""

    def test_returns_summary_dict(self, client, test_user, db_session):
        summary = _seed(client, test_user, db_session)
        assert summary["snapshot_count"] == 3
        assert summary["change_count"] == 5
        assert summary["user_id"] == str(test_user.id)
        assert "integration_id" in summary
        assert "resource_id" in summary

    def test_idempotent_second_run(self, client, test_user, db_session):
        """Running seed_for_user twice should not raise and should give the
        same counts (old data deleted before recreating)."""
        _seed(client, test_user, db_session)
        summary = _seed(client, test_user, db_session)   # second run
        assert summary["snapshot_count"] == 3
        assert summary["change_count"] == 5


class TestChangesEndpoint:
    """GET /changes returns seeded rows after seeding."""

    def test_total_changes(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/changes")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5

    def test_ordered_newest_first(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/changes")
        items = resp.json()["items"]
        timestamps = [item["created_at"] for item in items]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_risk_levels_present(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/changes")
        levels = {item["risk_level"] for item in resp.json()["items"]}
        # Seed creates one of each: critical, high (×2), medium, low
        assert "critical" in levels
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels

    def test_filter_by_risk_critical(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/changes?risk_level=critical")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["risk_level"] == "critical"
        assert data["items"][0]["change_type"] == "removed"

    def test_filter_by_change_type_added(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/changes?change_type=added")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["record_identifier"] == "A api.example.com"

    def test_change_detail_includes_snapshot_state(self, client, test_user, db_session):
        """GET /changes/{id} should include prev/new snapshot states."""
        _seed(client, test_user, db_session)
        # Get the critical change (removed A example.com)
        resp = client.get("/changes?risk_level=critical")
        change_id = resp.json()["items"][0]["id"]

        resp = client.get(f"/changes/{change_id}")
        assert resp.status_code == 200
        detail = resp.json()
        # Removed record → new_snapshot_state present, prev_value is the record
        assert detail["new_snapshot_state"] is not None
        assert detail["prev_snapshot_state"] is not None
        assert detail["prev_value"] is not None
        assert detail["new_value"] is None


class TestResourcesEndpoint:
    """GET /resources and sub-routes return seeded rows after seeding."""

    def test_resource_count(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/resources")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    def test_resource_sentinel_id(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/resources")
        item = resp.json()["items"][0]
        assert item["provider_resource_id"] == SEED_PROVIDER_RESOURCE_ID
        assert item["display_name"] == "example.com"

    def test_resource_detail_counts(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/resources")
        resource_id = resp.json()["items"][0]["id"]

        resp = client.get(f"/resources/{resource_id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["snapshot_count"] == 3
        assert detail["change_count"] == 5

    def test_resource_snapshots(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/resources")
        resource_id = resp.json()["items"][0]["id"]

        resp = client.get(f"/resources/{resource_id}/snapshots")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        # Verify snapshots are ordered newest-first
        timestamps = [s["created_at"] for s in data["items"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_resource_changes(self, client, test_user, db_session):
        _seed(client, test_user, db_session)
        resp = client.get("/resources")
        resource_id = resp.json()["items"][0]["id"]

        resp = client.get(f"/resources/{resource_id}/changes")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
