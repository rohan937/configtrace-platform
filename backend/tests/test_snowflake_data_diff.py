"""Snowflake data-object Change-classification tests (Snowflake message 3
of 8).

Uses the REAL ``compute_diff()`` -> ``classify_snowflake_change()`` pipeline
(via ``risk_service.classify_change()``) for every case — no hand-built
Change dicts standing in for the real diff pipeline.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change

_ACCOUNT_ID = "id:acme-prod"


def _diff(prev_records: list[dict], new_records: list[dict]):
    prev = SimpleNamespace(state=prev_records)
    new = SimpleNamespace(state=new_records)
    return compute_diff(prev, new)


def _only_change(changes):
    assert len(changes) == 1, f"expected exactly 1 change, got {len(changes)}: {changes}"
    return changes[0]


def _database(name="MYDB", **overrides):
    record = {
        "record_type": "snowflake_database",
        "record_id": f"{_ACCOUNT_ID}/database/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "database_name": name,
        "database_kind": "standard",
        "owner": "SYSADMIN",
        "transient": "false",
        "retention_time": 1,
    }
    record.update(overrides)
    return record


def _schema(db="MYDB", name="PUBLIC", **overrides):
    record = {
        "record_type": "snowflake_schema",
        "record_id": f"{_ACCOUNT_ID}/schema/{db.lower()}.{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "database_name": db,
        "schema_name": name,
        "owner": "SYSADMIN",
        "managed_access": "false",
        "transient": "false",
    }
    record.update(overrides)
    return record


def _warehouse(name="COMPUTE_WH", **overrides):
    record = {
        "record_type": "snowflake_warehouse",
        "record_id": f"{_ACCOUNT_ID}/warehouse/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "warehouse_name": name,
        "owner": "SYSADMIN",
        "state": "started",
        "size": "X-Small",
        "auto_suspend": 600,
        "auto_resume": "true",
    }
    record.update(overrides)
    return record


def _share(name="MY_SHARE", **overrides):
    record = {
        "record_type": "snowflake_share",
        "record_id": f"{_ACCOUNT_ID}/share/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "share_name": name,
        "share_kind": "outbound",
        "owner": "SYSADMIN",
        "database_name": "MYDB",
        "consumer_count": 1,
        "consumer_count_may_be_truncated": False,
    }
    record.update(overrides)
    return record


def _object_grant(
    grantee="ANALYST", privilege="SELECT", privilege_category="data_read",
    object_type="table", object_fqn="MYDB.PUBLIC.ORDERS", future_grant=False, ownership=False, **overrides,
):
    record = {
        "record_type": "snowflake_object_grant",
        "record_id": (
            f"{_ACCOUNT_ID}/object_grant/account_role:{grantee.lower()}/{privilege.lower()}/"
            f"{object_type}/future={future_grant}/{object_fqn.lower()}"
        ),
        "account_id": _ACCOUNT_ID,
        "grantee_type": "account_role",
        "grantee_name": grantee,
        "privilege": privilege,
        "privilege_category": privilege_category,
        "object_type": object_type,
        "object_fqn": object_fqn,
        "grant_option": "false",
        "granted_by": "SYSADMIN",
        "future_grant": future_grant,
        "ownership": ownership,
    }
    record.update(overrides)
    return record


# ── Databases ─────────────────────────────────────────────────────────────────


class TestDatabaseChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_database()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_is_low(self):
        changes = _diff([_database()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_owner_change_is_medium(self):
        changes = _diff([_database(owner="SYSADMIN")], [_database(owner="ANALYST")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_owner_change_to_accountadmin_is_medium(self):
        changes = _diff([_database(owner="SYSADMIN")], [_database(owner="ACCOUNTADMIN")])
        level, reason = classify_change(_only_change(changes))
        assert level == "medium"
        assert "privileged" in reason.lower() or "accountadmin" in reason.lower()


# ── Schemas ───────────────────────────────────────────────────────────────────


class TestSchemaChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_schema()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_is_low(self):
        changes = _diff([_schema()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_owner_change_is_medium(self):
        changes = _diff([_schema(owner="SYSADMIN")], [_schema(owner="ANALYST")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_managed_access_toggle_is_low(self):
        changes = _diff([_schema(managed_access="false")], [_schema(managed_access="true")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_same_schema_name_different_database_is_distinct(self):
        schema_a = _schema(db="DB_A", name="PUBLIC")
        schema_b = _schema(db="DB_B", name="PUBLIC")
        changes = _diff([schema_a], [schema_a, schema_b])
        assert len(changes) == 1
        assert changes[0]["change_type"] == "added"


# ── Warehouses ────────────────────────────────────────────────────────────────


class TestWarehouseChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_warehouse()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_is_low(self):
        changes = _diff([_warehouse()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_owner_change_is_medium(self):
        changes = _diff([_warehouse(owner="SYSADMIN")], [_warehouse(owner="ANALYST")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_size_change_is_never_a_security_signal(self):
        changes = _diff([_warehouse(size="X-Small")], [_warehouse(size="4X-Large")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_auto_suspend_change_is_low(self):
        changes = _diff([_warehouse(auto_suspend=600)], [_warehouse(auto_suspend=60)])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"


# ── Shares ────────────────────────────────────────────────────────────────────


class TestShareChangeClassification:
    def test_added_is_medium(self):
        changes = _diff([], [_share()])
        level, reason = classify_change(_only_change(changes))
        assert level == "medium"
        assert "leak" not in reason.lower()
        assert "public" not in reason.lower()

    def test_removed_is_low(self):
        changes = _diff([_share()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_consumer_added_is_medium(self):
        changes = _diff([_share(consumer_count=1)], [_share(consumer_count=2)])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_consumer_removed_is_low(self):
        changes = _diff([_share(consumer_count=2)], [_share(consumer_count=1)])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_never_claims_data_leaked(self):
        changes = _diff([], [_share()])
        _level, reason = classify_change(_only_change(changes))
        assert "leaked" not in reason.lower()
        assert "data is public" not in reason.lower()


# ── Object grants ─────────────────────────────────────────────────────────────


class TestObjectGrantChangeClassification:
    def test_ordinary_select_grant_is_medium(self):
        changes = _diff([], [_object_grant(grantee="ANALYST", privilege="SELECT", privilege_category="data_read")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_ownership_grant_is_high(self):
        changes = _diff([], [_object_grant(grantee="ANALYST", privilege="OWNERSHIP", privilege_category="ownership", ownership=True)])
        level, _ = classify_change(_only_change(changes))
        assert level == "high"

    def test_monitor_only_grant_is_low(self):
        changes = _diff([], [_object_grant(grantee="ANALYST", privilege="MONITOR", privilege_category="monitor")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_public_select_grant_is_medium(self):
        changes = _diff([], [_object_grant(grantee="PUBLIC", privilege="SELECT", privilege_category="data_read")])
        level, reason = classify_change(_only_change(changes))
        assert level == "medium"
        assert "PUBLIC" in reason

    def test_public_ownership_grant_is_high(self):
        changes = _diff([], [_object_grant(grantee="PUBLIC", privilege="OWNERSHIP", privilege_category="ownership", ownership=True)])
        level, _ = classify_change(_only_change(changes))
        assert level == "high"

    def test_future_grant_to_public_is_high(self):
        changes = _diff([], [_object_grant(
            grantee="PUBLIC", privilege="SELECT", privilege_category="data_read",
            object_fqn="MYDB.PUBLIC.<TABLE>", future_grant=True,
        )])
        level, reason = classify_change(_only_change(changes))
        assert level == "high"
        assert "future" in reason.lower()

    def test_future_grant_ordinary_role_is_medium(self):
        changes = _diff([], [_object_grant(
            grantee="ANALYST", privilege="SELECT", privilege_category="data_read",
            object_fqn="MYDB.PUBLIC.<TABLE>", future_grant=True,
        )])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_accountadmin_grantee_never_creates_noise(self):
        """A grant to ACCOUNTADMIN is dampened to Low — it already has
        near-total access by design."""
        changes = _diff([], [_object_grant(grantee="ACCOUNTADMIN", privilege="OWNERSHIP", privilege_category="ownership", ownership=True)])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_grant_removed_is_low(self):
        changes = _diff([_object_grant()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_grant_option_added_on_powerful_privilege_is_high(self):
        changes = _diff(
            [_object_grant(privilege="OWNERSHIP", privilege_category="ownership", ownership=True, grant_option="false")],
            [_object_grant(privilege="OWNERSHIP", privilege_category="ownership", ownership=True, grant_option="true")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "high"

    def test_grant_option_added_on_ordinary_read_privilege_is_low(self):
        changes = _diff(
            [_object_grant(privilege="SELECT", privilege_category="data_read", grant_option="false")],
            [_object_grant(privilege="SELECT", privilege_category="data_read", grant_option="true")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_duplicate_grant_dedup_no_diff(self):
        grant = _object_grant()
        changes = _diff([grant], [dict(grant)])
        assert changes == []

    def test_provider_metadata_has_grant_context(self):
        changes = _diff([], [_object_grant(grantee="ANALYST", privilege="SELECT")])
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("grantee_name") == "ANALYST"
        assert pm.get("privilege") == "SELECT"

    def test_provider_metadata_excludes_object_data(self):
        changes = _diff([], [_object_grant()])
        pm = _only_change(changes)["provider_metadata"]
        for forbidden in ("rows", "sample_data", "query_result", "credentials"):
            assert forbidden not in pm


# ── Diff hygiene ──────────────────────────────────────────────────────────────


class TestDiffHygiene:
    def test_timestamps_never_tracked(self):
        """No timestamp-style field is in any message-3 tracked-fields
        list, so a record differing only in an untracked extra key
        produces no diff."""
        base = _database()
        drifted = dict(base)
        drifted["_not_a_tracked_field"] = "some-volatile-value"
        changes = _diff([base], [drifted])
        assert changes == []

    def test_reordered_records_produce_no_diff(self):
        db_a, db_b = _database(name="DB_A"), _database(name="DB_B")
        changes = _diff([db_a, db_b], [db_b, db_a])
        assert changes == []

    def test_unknown_record_type_fails_safe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "snowflake_future_thing"},
        }
        level, _reason = classify_snowflake_change(change)
        assert level == "low"
