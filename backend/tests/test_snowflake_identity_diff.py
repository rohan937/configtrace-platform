"""Snowflake identity/role Change-classification tests (Snowflake message 2
of 8).

Uses the REAL ``compute_diff()`` -> ``classify_snowflake_change()`` pipeline
(via ``risk_service.classify_change()``) for every case — no hand-built
Change dicts standing in for the real diff pipeline, so a real
provider_metadata-population bug (e.g. a forgotten ``_build_provider_metadata``
stanza) would be caught here rather than masked.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change


def _diff(prev_records: list[dict], new_records: list[dict]):
    prev = SimpleNamespace(state=prev_records)
    new = SimpleNamespace(state=new_records)
    return compute_diff(prev, new)


def _only_change(changes):
    assert len(changes) == 1, f"expected exactly 1 change, got {len(changes)}: {changes}"
    return changes[0]


_ACCOUNT_ID = "id:acme-prod"


def _user(name="ALICE", **overrides):
    record = {
        "record_type": "snowflake_user",
        "record_id": f"{_ACCOUNT_ID}/user/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "user_name": name,
        "user_type": "person",
        "disabled": "enabled",
        "default_role": "ANALYST",
        "default_secondary_roles": "all",
        "rsa_key_configured": "true",
        "password_configured": "true",
        "programmatic_access_token_configured": "false",
        "owner": "USERADMIN",
    }
    record.update(overrides)
    return record


def _account_role(name="ANALYST", **overrides):
    record = {
        "record_type": "snowflake_account_role",
        "record_id": f"{_ACCOUNT_ID}/account_role/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "role_name": name,
        "role_category": "custom",
        "owner": "SYSADMIN",
        "assigned_to_users_count": 1,
        "granted_to_roles_count": 0,
        "granted_roles_count": 0,
    }
    record.update(overrides)
    return record


def _database_role(db="MYDB", name="DB_READER", **overrides):
    record = {
        "record_type": "snowflake_database_role",
        "record_id": f"{_ACCOUNT_ID}/database_role/{db.lower()}.{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "database_name": db,
        "role_name": name,
        "owner": "SYSADMIN",
        "granted_to_roles_count": 0,
        "granted_roles_count": 0,
    }
    record.update(overrides)
    return record


def _user_role_grant(user="ALICE", role="ANALYST", role_type="account_role", **overrides):
    record = {
        "record_type": "snowflake_user_role_grant",
        "record_id": f"{_ACCOUNT_ID}/user_role_grant/{user.lower()}/{role.lower()}",
        "account_id": _ACCOUNT_ID,
        "user_name": user,
        "role_name": role,
        "role_type": role_type,
        "default_role_match": False,
        "grant_option": "unknown",
        "granted_by": "USERADMIN",
    }
    record.update(overrides)
    return record


def _hierarchy_grant(child="ETL_ROLE", parent="SYSADMIN", child_type="account_role", parent_type="account_role", **overrides):
    record = {
        "record_type": "snowflake_role_hierarchy_grant",
        "record_id": f"{_ACCOUNT_ID}/role_hierarchy_grant/{child_type}:{child.lower()}/{parent_type}:{parent.lower()}",
        "account_id": _ACCOUNT_ID,
        "child_role_name": child,
        "child_role_type": child_type,
        "parent_role_name": parent,
        "parent_role_type": parent_type,
        "grant_option": "unknown",
        "granted_by": "USERADMIN",
    }
    record.update(overrides)
    return record


# ── Users ─────────────────────────────────────────────────────────────────────


class TestUserChangeClassification:
    def test_added_user_is_low(self):
        changes = _diff([], [_user()])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "low"

    def test_added_service_user_is_low(self):
        changes = _diff([], [_user(name="SVC_ETL", user_type="service")])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "low"

    def test_removed_user_is_low(self):
        changes = _diff([_user()], [])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "low"

    def test_disabled_to_enabled_is_medium(self):
        changes = _diff([_user(disabled="disabled")], [_user(disabled="enabled")])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "medium"
        assert "re-enabled" in reason.lower() or "restor" in reason.lower()

    def test_enabled_to_disabled_is_low(self):
        changes = _diff([_user(disabled="enabled")], [_user(disabled="disabled")])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "low"

    def test_default_role_change_to_ordinary_role_is_low(self):
        changes = _diff([_user(default_role="ANALYST")], [_user(default_role="DATA_ENGINEER")])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "low"

    def test_default_role_change_to_accountadmin_is_medium(self):
        changes = _diff([_user(default_role="ANALYST")], [_user(default_role="ACCOUNTADMIN")])
        change = _only_change(changes)
        level, reason = classify_change(change)
        assert level == "medium"

    def test_display_metadata_change_is_low(self):
        changes = _diff(
            [_user(rsa_key_configured="false")], [_user(rsa_key_configured="true")],
        )
        change = _only_change(changes)
        level, _reason = classify_change(change)
        assert level == "low"

    def test_reordered_users_produce_no_diff(self):
        a, b = _user(name="ALICE"), _user(name="BOB")
        changes = _diff([a, b], [b, a])
        assert changes == []


# ── Account roles ─────────────────────────────────────────────────────────────


class TestAccountRoleChangeClassification:
    def test_added_role_is_low(self):
        changes = _diff([], [_account_role()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_role_is_low(self):
        changes = _diff([_account_role()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_owner_change_is_low(self):
        changes = _diff([_account_role(owner="SYSADMIN")], [_account_role(owner="USERADMIN")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"


# ── Database roles ────────────────────────────────────────────────────────────


class TestDatabaseRoleChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_database_role()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_is_low(self):
        changes = _diff([_database_role()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_same_role_name_different_database_is_distinct_record(self):
        role_a = _database_role(db="DB_A", name="READER")
        role_b = _database_role(db="DB_B", name="READER")
        changes = _diff([role_a], [role_a, role_b])
        assert len(changes) == 1
        assert changes[0]["change_type"] == "added"


# ── User-role grants ──────────────────────────────────────────────────────────


class TestUserRoleGrantChangeClassification:
    def test_user_gets_accountadmin_is_high(self):
        changes = _diff([], [_user_role_grant(role="ACCOUNTADMIN")])
        level, reason = classify_change(_only_change(changes))
        assert level == "high"
        assert "ACCOUNTADMIN" in reason

    def test_user_gets_securityadmin_is_high(self):
        changes = _diff([], [_user_role_grant(role="SECURITYADMIN")])
        level, _ = classify_change(_only_change(changes))
        assert level == "high"

    def test_user_gets_sysadmin_is_medium(self):
        changes = _diff([], [_user_role_grant(role="SYSADMIN")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_user_gets_useradmin_is_medium(self):
        changes = _diff([], [_user_role_grant(role="USERADMIN")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_user_gets_ordinary_custom_role_is_low(self):
        changes = _diff([], [_user_role_grant(role="DATA_ANALYST")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_grant_removal_is_low(self):
        changes = _diff([_user_role_grant(role="ACCOUNTADMIN")], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_grant_metadata_field_change_is_low(self):
        changes = _diff(
            [_user_role_grant(role="ANALYST", default_role_match=False)],
            [_user_role_grant(role="ANALYST", default_role_match=True)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_duplicate_grant_dedup_no_diff(self):
        grant = _user_role_grant()
        changes = _diff([grant], [dict(grant)])
        assert changes == []


# ── Role hierarchy ────────────────────────────────────────────────────────────


class TestRoleHierarchyChangeClassification:
    def test_ordinary_child_to_parent_edge_added_is_medium(self):
        changes = _diff([], [_hierarchy_grant(child="ETL_ROLE", parent="SYSADMIN")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_accountadmin_parent_edge_added_is_high(self):
        changes = _diff([], [_hierarchy_grant(child="ETL_ROLE", parent="ACCOUNTADMIN")])
        level, reason = classify_change(_only_change(changes))
        assert level == "high"
        assert "ACCOUNTADMIN" in reason

    def test_securityadmin_parent_edge_added_is_high(self):
        changes = _diff([], [_hierarchy_grant(child="ETL_ROLE", parent="SECURITYADMIN")])
        level, _ = classify_change(_only_change(changes))
        assert level == "high"

    def test_hierarchy_edge_removed_is_low(self):
        changes = _diff([_hierarchy_grant()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_database_role_to_account_role_edge_ordinary_is_medium(self):
        changes = _diff([], [_hierarchy_grant(
            child="DB_READER", child_type="database_role", parent="SYSADMIN", parent_type="account_role",
        )])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_malformed_missing_parent_role_name_handled_safely(self):
        """A hierarchy row missing parent_role_name (should never happen
        given the connector's own row filtering, but the classifier must
        not crash if it ever does) falls back to the ordinary-edge path."""
        grant = _hierarchy_grant()
        del grant["parent_role_name"]
        changes = _diff([], [grant])
        level, _reason = classify_change(_only_change(changes))
        assert level in ("low", "medium")

    def test_direction_never_reversed_in_classification(self):
        """Only the PARENT role's identity drives severity — a critical
        CHILD role name must never trigger the same escalation."""
        changes = _diff([], [_hierarchy_grant(child="ACCOUNTADMIN", parent="CUSTOM_ROLE")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"  # ordinary edge; ACCOUNTADMIN-as-child does not escalate


# ── Provider metadata / diff hygiene ─────────────────────────────────────────


class TestProviderMetadataHygiene:
    def test_user_provider_metadata_excludes_credentials(self):
        changes = _diff(
            [_user(rsa_key_configured="false")], [_user(rsa_key_configured="true")],
        )
        pm = _only_change(changes)["provider_metadata"]
        assert pm["record_type"] == "snowflake_user"
        for forbidden in ("programmatic_access_token", "password", "rsa_public_key"):
            assert forbidden not in pm

    def test_user_role_grant_provider_metadata_has_role_context(self):
        changes = _diff([], [_user_role_grant(role="ACCOUNTADMIN")])
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("role_name") == "ACCOUNTADMIN"
        assert pm.get("user_name") == "ALICE"

    def test_hierarchy_provider_metadata_has_parent_and_child_context(self):
        changes = _diff([], [_hierarchy_grant(child="ETL_ROLE", parent="ACCOUNTADMIN")])
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("parent_role_name") == "ACCOUNTADMIN"
        assert pm.get("child_role_name") == "ETL_ROLE"

    def test_timestamps_never_tracked_no_diff_from_volatile_fields(self):
        """created_on-style fields are never included in the normalizer
        output at all in this message, so there is nothing volatile for
        the tracked-fields list to accidentally pick up — this test pins
        that a record differing ONLY in an untracked extra key produces no
        diff."""
        base = _user()
        drifted = dict(base)
        drifted["_not_a_tracked_field"] = "some-value-that-should-never-diff"
        changes = _diff([base], [drifted])
        assert changes == []
