"""Snowflake partial-sync / false-removal prevention tests (Snowflake
message 7 of 8).

Uses the REAL ``compute_diff()`` (never a hand-rolled removal-detection
stand-in) to verify:

* a denied/unavailable account-wide family never produces fabricated
  "removed" Changes for the records that would have belonged to it;
* an unrelated COMPLETE family still reports real removals normally;
* per-database completeness (schemas, database roles, future grants)
  scopes suppression to just the failed database, never every database;
* per-role completeness (role-hierarchy walk, object-grant walk) scopes
  suppression to just the failed role, never every role;
* derived records (privileged user/role, PUBLIC exposure) are suppressed
  using the correct underlying upstream family keys;
* first-sync / recovery-after-partial-sync semantics.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff

_ACCOUNT = "id:acme-prod"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _account(**family_completeness) -> dict:
    return {
        "record_type": "snowflake_account", "record_id": _ACCOUNT, "account_id": _ACCOUNT,
        "family_completeness": family_completeness,
    }


def _user(name: str, **kw) -> dict:
    r = {"record_type": "snowflake_user", "record_id": f"{_ACCOUNT}/user/{name.lower()}", "account_id": _ACCOUNT, "user_name": name, "user_type": "person", "disabled": "enabled"}
    r.update(kw)
    return r


def _account_role(name: str, **kw) -> dict:
    r = {
        "record_type": "snowflake_account_role", "record_id": f"{_ACCOUNT}/account_role/{name.lower()}",
        "account_id": _ACCOUNT, "role_name": name, "role_category": "custom",
        "role_hierarchy_collection_status": "complete", "object_grant_collection_status": "complete",
    }
    r.update(kw)
    return r


def _database_role(db: str, name: str, **kw) -> dict:
    r = {
        "record_type": "snowflake_database_role", "record_id": f"{_ACCOUNT}/database_role/{db.lower()}.{name.lower()}",
        "account_id": _ACCOUNT, "database_name": db, "role_name": name,
        "role_hierarchy_collection_status": "complete", "object_grant_collection_status": "complete",
    }
    r.update(kw)
    return r


def _database(name: str, **kw) -> dict:
    r = {
        "record_type": "snowflake_database", "record_id": f"{_ACCOUNT}/database/{name.lower()}",
        "account_id": _ACCOUNT, "database_name": name,
        "schema_collection_status": "complete", "database_role_collection_status": "complete",
        "future_grant_collection_status": "complete",
    }
    r.update(kw)
    return r


def _schema(db: str, name: str) -> dict:
    return {"record_type": "snowflake_schema", "record_id": f"{_ACCOUNT}/schema/{db.lower()}.{name.lower()}", "account_id": _ACCOUNT, "database_name": db, "schema_name": name}


def _user_role_grant(user: str, role: str, role_type: str = "account_role") -> dict:
    return {"record_type": "snowflake_user_role_grant", "record_id": f"{_ACCOUNT}/user_role_grant/{user.lower()}/{role.lower()}", "account_id": _ACCOUNT, "user_name": user, "role_name": role, "role_type": role_type}


def _hierarchy_grant(child: str, parent: str, child_type: str = "account_role", parent_type: str = "account_role") -> dict:
    return {
        "record_type": "snowflake_role_hierarchy_grant",
        "record_id": f"{_ACCOUNT}/role_hierarchy_grant/{child_type}:{child.lower()}/{parent_type}:{parent.lower()}",
        "account_id": _ACCOUNT, "child_role_name": child, "child_role_type": child_type,
        "parent_role_name": parent, "parent_role_type": parent_type,
    }


def _object_grant(grantee: str, grantee_type: str = "account_role", *, future_grant: bool = False, database_name: str = None, privilege: str = "SELECT") -> dict:
    return {
        "record_type": "snowflake_object_grant",
        "record_id": f"{_ACCOUNT}/object_grant/{grantee_type}:{grantee.lower()}/{privilege.lower()}/table/future={future_grant}/x",
        "account_id": _ACCOUNT, "grantee_name": grantee, "grantee_type": grantee_type,
        "privilege": privilege, "future_grant": future_grant, "database_name": database_name,
    }


def _privileged_user(name: str) -> dict:
    return {"record_type": "snowflake_privileged_user", "record_id": f"{_ACCOUNT}/privileged_user/{name.lower()}", "account_id": _ACCOUNT, "user_name": name, "highest_known_privilege_tier": "critical", "has_accountadmin": True}


def _privileged_role(name: str) -> dict:
    return {"record_type": "snowflake_privileged_role", "record_id": f"{_ACCOUNT}/privileged_role/account_role/{name.lower()}", "account_id": _ACCOUNT, "role_name": name, "highest_known_privilege_tier": "high"}


def _public_exposure() -> dict:
    return {"record_type": "snowflake_public_exposure", "record_id": f"{_ACCOUNT}/public_exposure", "account_id": _ACCOUNT, "future_public_exposure_count": 1}


def _removed_ids(changes: list[dict]) -> set[str]:
    return {c["provider_metadata"]["record_id"] for c in changes if c["change_type"] == "removed"}


def _added_ids(changes: list[dict]) -> set[str]:
    return {c["provider_metadata"]["record_id"] for c in changes if c["change_type"] == "added"}


class TestAccountWideSuppression:
    def test_users_denied_suppresses_user_removals(self):
        prev = _snap([_account(users="complete"), _user("ALICE"), _user("BOB")])
        new = _snap([_account(users="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_users_denied_does_not_suppress_unrelated_complete_family(self):
        prev = _snap([_account(users="complete", databases="complete"), _user("ALICE"), _database("DB1")])
        new = _snap([_account(users="denied", databases="complete")])
        changes = compute_diff(prev, new)
        removed = _removed_ids(changes)
        assert f"{_ACCOUNT}/user/alice" not in removed
        assert f"{_ACCOUNT}/database/db1" in removed

    def test_complete_family_reports_real_removal(self):
        prev = _snap([_account(users="complete"), _user("ALICE")])
        new = _snap([_account(users="complete")])
        changes = compute_diff(prev, new)
        assert f"{_ACCOUNT}/user/alice" in _removed_ids(changes)

    def test_account_record_own_removal_never_suppressed(self):
        prev = _snap([_account(), _user("ALICE")])
        new = _snap([])
        changes = compute_diff(prev, new)
        assert _ACCOUNT in _removed_ids(changes)

    def test_no_account_record_in_new_snapshot_falls_back_unsuppressed(self):
        prev = _snap([_account(users="complete"), _user("ALICE")])
        new = _snap([_user("BOB")])
        changes = compute_diff(prev, new)
        assert f"{_ACCOUNT}/user/alice" in _removed_ids(changes)

    def test_account_roles_denied_suppresses_role_removals(self):
        prev = _snap([_account(account_roles="complete"), _account_role("CUSTOM_ADMIN")])
        new = _snap([_account(account_roles="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_warehouses_denied_suppresses_warehouse_removals(self):
        prev = _snap([_account(warehouses="complete"), {"record_type": "snowflake_warehouse", "record_id": f"{_ACCOUNT}/warehouse/wh1", "account_id": _ACCOUNT, "warehouse_name": "WH1"}])
        new = _snap([_account(warehouses="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_network_policies_denied_suppresses_removals(self):
        prev = _snap([_account(network_policies="complete"), {"record_type": "snowflake_network_policy", "record_id": f"{_ACCOUNT}/network_policy/open", "account_id": _ACCOUNT, "policy_name": "OPEN"}])
        new = _snap([_account(network_policies="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()


class TestPerDatabaseSuppression:
    def test_schemas_for_db_b_denied_suppresses_only_db_b_schemas(self):
        prev = _snap([
            _account(),
            _database("DB_A", schema_collection_status="complete"),
            _database("DB_B", schema_collection_status="complete"),
            _schema("DB_A", "PUBLIC"),
            _schema("DB_B", "PUBLIC"),
        ])
        new = _snap([
            _account(),
            _database("DB_A", schema_collection_status="complete"),
            _database("DB_B", schema_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        removed = _removed_ids(changes)
        assert f"{_ACCOUNT}/schema/db_a.public" in removed
        assert f"{_ACCOUNT}/schema/db_b.public" not in removed

    def test_database_role_for_db_b_denied_suppresses_only_db_b_roles(self):
        prev = _snap([
            _account(),
            _database("DB_A", database_role_collection_status="complete"),
            _database("DB_B", database_role_collection_status="complete"),
            _database_role("DB_A", "READER"),
            _database_role("DB_B", "READER"),
        ])
        new = _snap([
            _account(),
            _database("DB_A", database_role_collection_status="complete"),
            _database("DB_B", database_role_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        removed = _removed_ids(changes)
        assert f"{_ACCOUNT}/database_role/db_a.reader" in removed
        assert f"{_ACCOUNT}/database_role/db_b.reader" not in removed

    def test_future_grants_for_db_b_denied_suppresses_only_db_b_future_grants(self):
        db_a_grant = _object_grant("ANALYST", future_grant=True, database_name="DB_A")
        db_b_grant = _object_grant("ANALYST", future_grant=True, database_name="DB_B")
        # Distinct record_ids so both survive the same dict-of-records
        # snapshot without colliding on identical grantee/privilege/object.
        db_a_grant["record_id"] = db_a_grant["record_id"] + "_a"
        db_b_grant["record_id"] = db_b_grant["record_id"] + "_b"
        prev = _snap([
            _account(),
            _database("DB_A", future_grant_collection_status="complete"),
            _database("DB_B", future_grant_collection_status="complete"),
            db_a_grant,
            db_b_grant,
        ])
        new = _snap([
            _account(),
            _database("DB_A", future_grant_collection_status="complete"),
            _database("DB_B", future_grant_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        removed = _removed_ids(changes)
        # DB_A's future-grant collection was complete in the new snapshot,
        # so its grant's disappearance IS a real removal.
        assert db_a_grant["record_id"] in removed
        # DB_B's future-grant collection was denied, so its grant's
        # disappearance must be suppressed, never reported as removed.
        assert db_b_grant["record_id"] not in removed

    def test_no_matching_database_falls_back_to_family_completeness(self):
        """If the database record itself is entirely absent from the new
        snapshot (not just its schema subtree), fall back to the
        account-wide 'schemas' family key rather than assuming complete."""
        prev = _snap([_account(databases="complete", schemas="complete"), _schema("DB_GONE", "PUBLIC")])
        new = _snap([_account(databases="complete", schemas="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()


class TestPerRoleSuppression:
    def test_role_b_hierarchy_denied_suppresses_only_role_b_hierarchy_edges(self):
        prev = _snap([
            _account(),
            _account_role("ROLE_A", role_hierarchy_collection_status="complete"),
            _account_role("ROLE_B", role_hierarchy_collection_status="complete"),
            _hierarchy_grant("ROLE_A", "SYSADMIN"),
            _hierarchy_grant("ROLE_B", "SYSADMIN"),
        ])
        new = _snap([
            _account(),
            _account_role("ROLE_A", role_hierarchy_collection_status="complete"),
            _account_role("ROLE_B", role_hierarchy_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        removed = _removed_ids(changes)
        assert any("role_a" in i for i in removed)
        assert not any("role_b" in i for i in removed)

    def test_role_b_object_grants_denied_suppresses_only_role_b_object_grants(self):
        prev = _snap([
            _account(),
            _account_role("ROLE_A", object_grant_collection_status="complete"),
            _account_role("ROLE_B", object_grant_collection_status="complete"),
            _object_grant("ROLE_A"),
            _object_grant("ROLE_B"),
        ])
        new = _snap([
            _account(),
            _account_role("ROLE_A", object_grant_collection_status="complete"),
            _account_role("ROLE_B", object_grant_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        removed = _removed_ids(changes)
        assert any("role_a" in i.lower() for i in removed)
        assert not any("role_b" in i.lower() for i in removed)

    def test_user_role_grant_suppressed_by_role_hierarchy_status(self):
        prev = _snap([
            _account(),
            _account_role("ACCOUNTADMIN", role_hierarchy_collection_status="complete"),
            _user_role_grant("ALICE", "ACCOUNTADMIN"),
        ])
        new = _snap([
            _account(),
            _account_role("ACCOUNTADMIN", role_hierarchy_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_database_role_object_grant_suppression(self):
        """A database-role grantee's object_grant record stores only the
        bare role name (no database qualifier), so precise per-role
        localization is not possible for this specific combination —
        suppression falls back to the account-wide ``object_grants``
        family status instead (which a real sync always sets to
        ``partial`` whenever any one role's SHOW GRANTS TO ROLE call
        fails, per ``_collect_object_and_future_grants``)."""
        prev = _snap([
            _account(object_grants="complete"),
            _database_role("MYDB", "DB_ROLE", object_grant_collection_status="complete"),
            _object_grant("DB_ROLE", grantee_type="database_role"),
        ])
        new = _snap([
            _account(object_grants="partial"),
            _database_role("MYDB", "DB_ROLE", object_grant_collection_status="denied"),
        ])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_missing_role_record_falls_back_to_family_completeness(self):
        prev = _snap([_account(object_grants="complete"), _object_grant("GONE_ROLE")])
        new = _snap([_account(object_grants="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()


class TestDerivedRecordSuppression:
    def test_privileged_user_suppressed_when_role_hierarchy_denied(self):
        prev = _snap([_account(users="complete", account_roles="complete", database_roles="complete", user_role_grants="complete", role_hierarchy="complete", object_grants="complete", future_grants="complete"), _privileged_user("ALICE")])
        new = _snap([_account(users="complete", account_roles="complete", database_roles="complete", user_role_grants="complete", role_hierarchy="denied", object_grants="complete", future_grants="complete")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_privileged_role_suppressed_when_object_grants_denied(self):
        prev = _snap([_account(account_roles="complete", database_roles="complete", role_hierarchy="complete", object_grants="complete", future_grants="complete"), _privileged_role("CUSTOM_ADMIN")])
        new = _snap([_account(account_roles="complete", database_roles="complete", role_hierarchy="complete", object_grants="denied", future_grants="complete")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_public_exposure_suppressed_when_future_grants_denied(self):
        prev = _snap([_account(object_grants="complete", future_grants="complete"), _public_exposure()])
        new = _snap([_account(object_grants="complete", future_grants="denied")])
        changes = compute_diff(prev, new)
        assert _removed_ids(changes) == set()

    def test_privileged_user_real_removal_when_all_inputs_complete(self):
        """When every upstream family is genuinely complete, a privileged
        user's disappearance IS a real (suppressible-free) removal —
        false-removal suppression must never blanket-hide real privilege
        loss."""
        prev = _snap([_account(users="complete", account_roles="complete", database_roles="complete", user_role_grants="complete", role_hierarchy="complete", object_grants="complete", future_grants="complete"), _privileged_user("ALICE")])
        new = _snap([_account(users="complete", account_roles="complete", database_roles="complete", user_role_grants="complete", role_hierarchy="complete", object_grants="complete", future_grants="complete")])
        changes = compute_diff(prev, new)
        assert f"{_ACCOUNT}/privileged_user/alice" in _removed_ids(changes)


class TestNonSnowflakeRecordsUnaffected:
    def test_okta_record_removal_not_touched_by_snowflake_suppression(self):
        prev = _snap([{"record_type": "okta_user", "record_id": "id:t1/user/u1", "tenant_id": "id:t1", "user_id": "u1", "login": "u1@x.com", "status": "ACTIVE"}])
        new = _snap([])
        changes = compute_diff(prev, new)
        assert "id:t1/user/u1" in _removed_ids(changes)


class TestFirstSyncAndRecovery:
    def test_first_sync_has_no_prior_state_produces_only_additions(self):
        """First baseline containing risky posture (ACCOUNTADMIN user)
        produces Added Changes, never a fabricated 'removed then added'
        pair — this is what 'no historical Changes' for a brand-new
        account means at the diff layer: nothing to compare against."""
        prev = _snap([])
        new = _snap([_account(), _privileged_user("ALICE")])
        changes = compute_diff(prev, new)
        assert _added_ids(changes) == {_ACCOUNT, f"{_ACCOUNT}/privileged_user/alice"}
        assert _removed_ids(changes) == set()

    def test_recovery_after_partial_sync_diffs_against_last_complete_state(self):
        """sync1 complete -> sync2 partial (suppressed) -> sync3 complete:
        comparing sync3 directly against sync1 (the last known-complete
        state, which is what ConfigTrace's snapshot-to-snapshot diffing
        naturally does when a partial sync's snapshot is itself later
        diffed against) still correctly reports a genuine removal."""
        sync1 = _snap([_account(users="complete"), _user("ALICE"), _user("BOB")])
        sync3 = _snap([_account(users="complete"), _user("ALICE")])
        changes = compute_diff(sync1, sync3)
        assert f"{_ACCOUNT}/user/bob" in _removed_ids(changes)

    def test_partial_sync_itself_produces_no_false_removal(self):
        sync1 = _snap([_account(users="complete"), _user("ALICE"), _user("BOB")])
        sync2 = _snap([_account(users="denied")])
        changes = compute_diff(sync1, sync2)
        assert _removed_ids(changes) == set()
