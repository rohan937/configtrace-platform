"""Snowflake identity/role normalization tests (Snowflake message 2 of 8).

Covers field-by-field normalization: user type taxonomy, disabled tri-state,
default role/secondary roles, auth-material presence categories, built-in
account-role taxonomy, custom roles, database-role stable identity, grant
direction, unknown-field discipline, and sensitive-data exclusion. Unit-level
only — calls the connector's normalizer/categorizer functions directly, no
HTTP mocking needed.
"""

from __future__ import annotations

import pytest

from app.connectors.snowflake import SnowflakeConnector
from app.connectors.snowflake_schema import (
    DISABLED_DISABLED,
    DISABLED_ENABLED,
    DISABLED_UNKNOWN,
    GRANT_OPTION_UNKNOWN,
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    PRINCIPAL_TYPE_DATABASE_ROLE,
    PRINCIPAL_TYPE_UNKNOWN,
    PRINCIPAL_TYPE_USER,
    ROLE_CATEGORY_ACCOUNTADMIN,
    ROLE_CATEGORY_CUSTOM,
    ROLE_CATEGORY_ORGADMIN,
    ROLE_CATEGORY_PUBLIC,
    ROLE_CATEGORY_SECURITYADMIN,
    ROLE_CATEGORY_SYSADMIN,
    ROLE_CATEGORY_UNKNOWN,
    ROLE_CATEGORY_USERADMIN,
    SECONDARY_ROLES_ALL,
    SECONDARY_ROLES_NONE,
    SECONDARY_ROLES_SPECIFIC,
    SECONDARY_ROLES_UNKNOWN,
    SNOWFLAKE_ACCOUNT_ROLE,
    SNOWFLAKE_DATABASE_ROLE,
    SNOWFLAKE_ROLE_HIERARCHY_GRANT,
    SNOWFLAKE_USER,
    SNOWFLAKE_USER_ROLE_GRANT,
    TRISTATE_FALSE,
    TRISTATE_TRUE,
    TRISTATE_UNKNOWN,
    categorize_account_role,
    categorize_disabled,
    categorize_principal_type,
    categorize_secondary_roles,
    categorize_tristate_bool,
    categorize_user_type,
    is_public_role,
)

_ACCOUNT_ID = "id:acme-prod"


# ── User type taxonomy ────────────────────────────────────────────────────────


class TestUserTypeTaxonomy:
    def test_person(self):
        assert categorize_user_type("PERSON") == "person"

    def test_service(self):
        assert categorize_user_type("SERVICE") == "service"

    def test_service_agent(self):
        assert categorize_user_type("SERVICE_AGENT") == "service_agent"

    def test_legacy_service(self):
        assert categorize_user_type("LEGACY_SERVICE") == "legacy_service"

    def test_lowercase_input_normalized(self):
        assert categorize_user_type("person") == "person"

    def test_unrecognized_value_is_unknown(self):
        assert categorize_user_type("SOME_FUTURE_TYPE") == "unknown"

    def test_none_is_unknown(self):
        assert categorize_user_type(None) == "unknown"

    def test_non_string_is_unknown(self):
        assert categorize_user_type(42) == "unknown"


# ── Disabled tri-state ────────────────────────────────────────────────────────


class TestDisabledTriState:
    def test_bool_true_is_disabled(self):
        assert categorize_disabled(True) == DISABLED_DISABLED

    def test_bool_false_is_enabled(self):
        assert categorize_disabled(False) == DISABLED_ENABLED

    def test_string_true_is_disabled(self):
        assert categorize_disabled("true") == DISABLED_DISABLED

    def test_string_false_is_enabled(self):
        assert categorize_disabled("false") == DISABLED_ENABLED

    def test_none_is_unknown_never_enabled(self):
        """Missing (privilege-filtered SHOW USERS row) must be unknown, not
        coerced to a real 'enabled' state."""
        assert categorize_disabled(None) == DISABLED_UNKNOWN

    def test_malformed_string_is_unknown(self):
        assert categorize_disabled("maybe") == DISABLED_UNKNOWN


# ── Generic tri-state boolean (RSA key / password / PAT) ─────────────────────


class TestTristateBool:
    def test_true(self):
        assert categorize_tristate_bool(True) == TRISTATE_TRUE
        assert categorize_tristate_bool("true") == TRISTATE_TRUE

    def test_false(self):
        assert categorize_tristate_bool(False) == TRISTATE_FALSE
        assert categorize_tristate_bool("false") == TRISTATE_FALSE

    def test_missing_is_unknown_never_false(self):
        assert categorize_tristate_bool(None) == TRISTATE_UNKNOWN

    def test_malformed_is_unknown(self):
        assert categorize_tristate_bool("yes") == TRISTATE_UNKNOWN


# ── Secondary roles ───────────────────────────────────────────────────────────


class TestSecondaryRoles:
    def test_all(self):
        assert categorize_secondary_roles("ALL") == SECONDARY_ROLES_ALL
        assert categorize_secondary_roles("('ALL')") == SECONDARY_ROLES_ALL

    def test_none(self):
        assert categorize_secondary_roles("()") == SECONDARY_ROLES_NONE
        assert categorize_secondary_roles("") == SECONDARY_ROLES_NONE

    def test_missing_is_unknown(self):
        assert categorize_secondary_roles(None) == SECONDARY_ROLES_UNKNOWN

    def test_unexpected_value_is_specific(self):
        assert categorize_secondary_roles("SOME_OTHER_VALUE") == SECONDARY_ROLES_SPECIFIC


# ── Built-in account-role taxonomy ───────────────────────────────────────────


class TestBuiltInAccountRoleTaxonomy:
    def test_accountadmin(self):
        assert categorize_account_role("ACCOUNTADMIN") == ROLE_CATEGORY_ACCOUNTADMIN

    def test_securityadmin(self):
        assert categorize_account_role("SECURITYADMIN") == ROLE_CATEGORY_SECURITYADMIN

    def test_sysadmin(self):
        assert categorize_account_role("SYSADMIN") == ROLE_CATEGORY_SYSADMIN

    def test_useradmin(self):
        assert categorize_account_role("USERADMIN") == ROLE_CATEGORY_USERADMIN

    def test_orgadmin(self):
        assert categorize_account_role("ORGADMIN") == ROLE_CATEGORY_ORGADMIN

    def test_public(self):
        assert categorize_account_role("PUBLIC") == ROLE_CATEGORY_PUBLIC

    def test_custom_role(self):
        assert categorize_account_role("DATA_ANALYST") == ROLE_CATEGORY_CUSTOM

    def test_case_insensitive(self):
        assert categorize_account_role("accountadmin") == ROLE_CATEGORY_ACCOUNTADMIN

    def test_empty_is_unknown(self):
        assert categorize_account_role("") == ROLE_CATEGORY_UNKNOWN

    def test_none_is_unknown(self):
        assert categorize_account_role(None) == ROLE_CATEGORY_UNKNOWN

    def test_is_public_role_helper(self):
        assert is_public_role("PUBLIC") is True
        assert is_public_role("public") is True
        assert is_public_role("CUSTOM_ROLE") is False
        assert is_public_role(None) is False


# ── Principal type (grant direction discriminator) ───────────────────────────


class TestPrincipalType:
    def test_user(self):
        assert categorize_principal_type("USER") == PRINCIPAL_TYPE_USER

    def test_role(self):
        assert categorize_principal_type("ROLE") == PRINCIPAL_TYPE_ACCOUNT_ROLE

    def test_database_role(self):
        assert categorize_principal_type("DATABASE_ROLE") == PRINCIPAL_TYPE_DATABASE_ROLE

    def test_unrecognized_is_unknown(self):
        assert categorize_principal_type("APPLICATION_ROLE") == PRINCIPAL_TYPE_UNKNOWN

    def test_none_is_unknown(self):
        assert categorize_principal_type(None) == PRINCIPAL_TYPE_UNKNOWN


# ── User normalizer ──────────────────────────────────────────────────────────


class TestNormalizeUser:
    def test_full_row(self):
        row = {
            "NAME": "ALICE", "TYPE": "PERSON", "DISABLED": "false",
            "DEFAULT_ROLE": "ANALYST", "DEFAULT_SECONDARY_ROLES": "ALL",
            "HAS_RSA_PUBLIC_KEY": "true", "HAS_PASSWORD": "true", "HAS_PAT": "false",
            "OWNER": "USERADMIN",
        }
        record = SnowflakeConnector._normalize_user(_ACCOUNT_ID, row)
        assert record["record_type"] == SNOWFLAKE_USER
        assert record["user_name"] == "ALICE"
        assert record["user_type"] == "person"
        assert record["disabled"] == DISABLED_ENABLED
        assert record["default_role"] == "ANALYST"
        assert record["default_secondary_roles"] == SECONDARY_ROLES_ALL
        assert record["rsa_key_configured"] == TRISTATE_TRUE
        assert record["password_configured"] == TRISTATE_TRUE
        assert record["programmatic_access_token_configured"] == TRISTATE_FALSE
        assert record["owner"] == "USERADMIN"

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_user(_ACCOUNT_ID, {"NAME": None}) is None
        assert SnowflakeConnector._normalize_user(_ACCOUNT_ID, {"NAME": ""}) is None

    def test_privilege_filtered_row_all_unknown(self):
        """A SHOW USERS row for a caller without OWNERSHIP/MANAGE GRANTS
        returns NULL for everything but name — every field must normalize
        to unknown/None, never a false default."""
        row = {"NAME": "BOB"}
        record = SnowflakeConnector._normalize_user(_ACCOUNT_ID, row)
        assert record["disabled"] == DISABLED_UNKNOWN
        assert record["default_role"] is None
        assert record["default_secondary_roles"] == SECONDARY_ROLES_UNKNOWN
        assert record["rsa_key_configured"] == TRISTATE_UNKNOWN
        assert record["password_configured"] == TRISTATE_UNKNOWN
        assert record["programmatic_access_token_configured"] == TRISTATE_UNKNOWN
        assert record["owner"] is None

    def test_service_user_not_flagged_privileged_by_type_alone(self):
        row = {"NAME": "SVC_ETL", "TYPE": "SERVICE"}
        record = SnowflakeConnector._normalize_user(_ACCOUNT_ID, row)
        assert record["user_type"] == "service"
        assert "privilege" not in record
        assert "risk" not in record

    def test_stable_record_id_uses_account_and_lowercased_name(self):
        row = {"NAME": "Alice"}
        record = SnowflakeConnector._normalize_user(_ACCOUNT_ID, row)
        assert record["record_id"] == f"{_ACCOUNT_ID}/user/alice"

    def test_no_password_rsa_pat_secret_material_in_record(self):
        row = {
            "NAME": "ALICE", "HAS_RSA_PUBLIC_KEY": "true", "HAS_PASSWORD": "true", "HAS_PAT": "true",
        }
        record = SnowflakeConnector._normalize_user(_ACCOUNT_ID, row)
        blob = str(record)
        for forbidden in ("RSA_PUBLIC_KEY", "-----BEGIN", "PASSWORD_HASH"):
            assert forbidden not in blob


# ── Account role normalizer ──────────────────────────────────────────────────


class TestNormalizeAccountRole:
    def test_full_row(self):
        row = {"NAME": "ACCOUNTADMIN", "OWNER": None, "ASSIGNED_TO_USERS": "1", "GRANTED_TO_ROLES": "0", "GRANTED_ROLES": "2"}
        record = SnowflakeConnector._normalize_account_role(_ACCOUNT_ID, row)
        assert record["record_type"] == SNOWFLAKE_ACCOUNT_ROLE
        assert record["role_category"] == ROLE_CATEGORY_ACCOUNTADMIN
        assert record["assigned_to_users_count"] == 1
        assert record["granted_roles_count"] == 2

    def test_custom_role(self):
        row = {"NAME": "DATA_ANALYST", "OWNER": "SYSADMIN"}
        record = SnowflakeConnector._normalize_account_role(_ACCOUNT_ID, row)
        assert record["role_category"] == ROLE_CATEGORY_CUSTOM

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_account_role(_ACCOUNT_ID, {"NAME": None}) is None

    def test_missing_counts_are_none_not_zero(self):
        row = {"NAME": "SOME_ROLE"}
        record = SnowflakeConnector._normalize_account_role(_ACCOUNT_ID, row)
        assert record["assigned_to_users_count"] is None
        assert record["granted_to_roles_count"] is None
        assert record["granted_roles_count"] is None


# ── Database role normalizer ─────────────────────────────────────────────────


class TestNormalizeDatabaseRole:
    def test_full_row(self):
        row = {"NAME": "DB_READER", "OWNER": "SYSADMIN", "GRANTED_TO_ROLES": "1", "GRANTED_DATABASE_ROLES": "0"}
        record = SnowflakeConnector._normalize_database_role(_ACCOUNT_ID, "MYDB", row)
        assert record["record_type"] == SNOWFLAKE_DATABASE_ROLE
        assert record["database_name"] == "MYDB"
        assert record["role_name"] == "DB_READER"
        assert record["owner"] == "SYSADMIN"
        assert record["granted_to_roles_count"] == 1

    def test_same_role_name_in_two_databases_is_distinct(self):
        row = {"NAME": "READER"}
        record_a = SnowflakeConnector._normalize_database_role(_ACCOUNT_ID, "DB_A", row)
        record_b = SnowflakeConnector._normalize_database_role(_ACCOUNT_ID, "DB_B", row)
        assert record_a["record_id"] != record_b["record_id"]
        assert record_a["record_id"] == f"{_ACCOUNT_ID}/database_role/db_a.reader"
        assert record_b["record_id"] == f"{_ACCOUNT_ID}/database_role/db_b.reader"

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_database_role(_ACCOUNT_ID, "MYDB", {"NAME": None}) is None

    def test_alias_column_names_handled(self):
        """SHOW DATABASE ROLES' column table isn't fully documented — the
        normalizer tries multiple candidate aliases rather than assuming a
        single name."""
        row = {"NAME": "DB_READER", "GRANTED_TO_DATABASE_ROLES": "3", "GRANTED_ROLES": "1"}
        record = SnowflakeConnector._normalize_database_role(_ACCOUNT_ID, "MYDB", row)
        assert record["granted_to_roles_count"] == 3
        assert record["granted_roles_count"] == 1


# ── User-role grant normalizer ────────────────────────────────────────────────


class TestNormalizeUserRoleGrant:
    def test_basic_fields(self):
        record = SnowflakeConnector._normalize_user_role_grant(
            _ACCOUNT_ID, user_name="ALICE", role_name="ANALYST",
            role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, default_role_match=True, granted_by="USERADMIN",
        )
        assert record["record_type"] == SNOWFLAKE_USER_ROLE_GRANT
        assert record["user_name"] == "ALICE"
        assert record["role_name"] == "ANALYST"
        assert record["default_role_match"] is True
        assert record["granted_by"] == "USERADMIN"

    def test_grant_option_always_unknown(self):
        """SHOW GRANTS OF ROLE does not expose grant_option at all —
        message 2 must never guess true/false for it."""
        record = SnowflakeConnector._normalize_user_role_grant(
            _ACCOUNT_ID, user_name="ALICE", role_name="ANALYST",
            role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, default_role_match=False, granted_by=None,
        )
        assert record["grant_option"] == GRANT_OPTION_UNKNOWN

    def test_stable_record_id(self):
        record = SnowflakeConnector._normalize_user_role_grant(
            _ACCOUNT_ID, user_name="Alice", role_name="Analyst",
            role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, default_role_match=False, granted_by=None,
        )
        assert record["record_id"] == f"{_ACCOUNT_ID}/user_role_grant/alice/analyst"

    def test_missing_granted_by_is_none(self):
        record = SnowflakeConnector._normalize_user_role_grant(
            _ACCOUNT_ID, user_name="ALICE", role_name="ANALYST",
            role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, default_role_match=False, granted_by=None,
        )
        assert record["granted_by"] is None


# ── Role-hierarchy grant normalizer ───────────────────────────────────────────


class TestNormalizeRoleHierarchyGrant:
    def test_direction_preserved_child_to_parent(self):
        """GRANT ROLE child TO ROLE parent -> parent inherits child's
        privileges. Field names must never be swapped."""
        record = SnowflakeConnector._normalize_role_hierarchy_grant(
            _ACCOUNT_ID, child_role_name="ETL_ROLE", child_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE,
            parent_role_name="SYSADMIN", parent_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, granted_by="USERADMIN",
        )
        assert record["child_role_name"] == "ETL_ROLE"
        assert record["parent_role_name"] == "SYSADMIN"
        assert record["record_type"] == SNOWFLAKE_ROLE_HIERARCHY_GRANT

    def test_database_role_to_account_role_cross_type_edge(self):
        record = SnowflakeConnector._normalize_role_hierarchy_grant(
            _ACCOUNT_ID, child_role_name="DB_READER", child_role_type=PRINCIPAL_TYPE_DATABASE_ROLE,
            parent_role_name="SYSADMIN", parent_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, granted_by=None,
        )
        assert record["child_role_type"] == PRINCIPAL_TYPE_DATABASE_ROLE
        assert record["parent_role_type"] == PRINCIPAL_TYPE_ACCOUNT_ROLE

    def test_grant_option_always_unknown(self):
        record = SnowflakeConnector._normalize_role_hierarchy_grant(
            _ACCOUNT_ID, child_role_name="A", child_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE,
            parent_role_name="B", parent_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, granted_by=None,
        )
        assert record["grant_option"] == GRANT_OPTION_UNKNOWN

    def test_record_id_includes_both_role_types_to_avoid_cross_type_collision(self):
        """An account role and a database role that happen to share a name
        must not collide in record_id."""
        record_account = SnowflakeConnector._normalize_role_hierarchy_grant(
            _ACCOUNT_ID, child_role_name="READER", child_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE,
            parent_role_name="SYSADMIN", parent_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, granted_by=None,
        )
        record_db = SnowflakeConnector._normalize_role_hierarchy_grant(
            _ACCOUNT_ID, child_role_name="READER", child_role_type=PRINCIPAL_TYPE_DATABASE_ROLE,
            parent_role_name="SYSADMIN", parent_role_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, granted_by=None,
        )
        assert record_account["record_id"] != record_db["record_id"]
