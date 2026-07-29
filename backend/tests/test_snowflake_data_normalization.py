"""Snowflake data-object normalization tests (Snowflake message 3 of 8).

Covers field-by-field normalization: database/share/object-type taxonomies,
managed-access/transient OPTIONS-token parsing, warehouse posture,
privilege taxonomy, PUBLIC/ACCOUNTADMIN handling, ownership, grant-option,
future grants, unknown-field discipline, and sensitive-data exclusion.
Unit-level only — calls the connector's normalizer/categorizer functions
directly, no HTTP mocking needed.
"""

from __future__ import annotations

import pytest

from app.connectors.snowflake import SnowflakeConnector
from app.connectors.snowflake_schema import (
    DATABASE_KIND_APPLICATION,
    DATABASE_KIND_CATALOG_LINKED,
    DATABASE_KIND_IMPORTED,
    DATABASE_KIND_PERSONAL,
    DATABASE_KIND_STANDARD,
    DATABASE_KIND_UNKNOWN,
    GRANT_OPTION_FALSE,
    GRANT_OPTION_TRUE,
    GRANT_OPTION_UNKNOWN,
    OBJECT_TYPE_DATABASE,
    OBJECT_TYPE_FILE_FORMAT,
    OBJECT_TYPE_FUNCTION_PROCEDURE,
    OBJECT_TYPE_SCHEMA,
    OBJECT_TYPE_SHARE,
    OBJECT_TYPE_TABLE,
    OBJECT_TYPE_UNKNOWN,
    OBJECT_TYPE_VIEW,
    OBJECT_TYPE_WAREHOUSE,
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    PRINCIPAL_TYPE_DATABASE_ROLE,
    PRIVILEGE_CATEGORY_DATA_READ,
    PRIVILEGE_CATEGORY_DATA_WRITE,
    PRIVILEGE_CATEGORY_MONITOR,
    PRIVILEGE_CATEGORY_OBJECT_CREATE,
    PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL,
    PRIVILEGE_CATEGORY_OWNERSHIP,
    PRIVILEGE_CATEGORY_UNKNOWN,
    PRIVILEGE_CATEGORY_USAGE,
    SHARE_KIND_INBOUND,
    SHARE_KIND_OUTBOUND,
    SHARE_KIND_UNKNOWN,
    SNOWFLAKE_DATABASE,
    SNOWFLAKE_OBJECT_GRANT,
    SNOWFLAKE_SCHEMA,
    SNOWFLAKE_SHARE,
    SNOWFLAKE_WAREHOUSE,
    TRISTATE_FALSE,
    TRISTATE_TRUE,
    TRISTATE_UNKNOWN,
    WAREHOUSE_STATE_RESIZING,
    WAREHOUSE_STATE_STARTED,
    WAREHOUSE_STATE_SUSPENDED,
    WAREHOUSE_STATE_UNKNOWN,
    categorize_database_kind,
    categorize_grant_option,
    categorize_managed_access,
    categorize_object_type,
    categorize_privilege,
    categorize_share_kind,
    categorize_transient,
    categorize_warehouse_state,
    is_role_hierarchy_row,
)

_ACCOUNT_ID = "id:acme-prod"


# ── Database taxonomy ─────────────────────────────────────────────────────────


class TestDatabaseKindTaxonomy:
    def test_standard(self):
        assert categorize_database_kind("STANDARD") == DATABASE_KIND_STANDARD

    def test_imported(self):
        assert categorize_database_kind("IMPORTED DATABASE") == DATABASE_KIND_IMPORTED

    def test_application(self):
        assert categorize_database_kind("APPLICATION") == DATABASE_KIND_APPLICATION

    def test_personal(self):
        assert categorize_database_kind("PERSONAL DATABASE") == DATABASE_KIND_PERSONAL

    def test_catalog_linked(self):
        assert categorize_database_kind("CATALOG-LINKED DATABASE") == DATABASE_KIND_CATALOG_LINKED

    def test_unrecognized_is_unknown(self):
        assert categorize_database_kind("SOME_FUTURE_KIND") == DATABASE_KIND_UNKNOWN

    def test_none_is_unknown(self):
        assert categorize_database_kind(None) == DATABASE_KIND_UNKNOWN


# ── OPTIONS-column parsing (managed access / transient) ──────────────────────


class TestOptionsColumnParsing:
    def test_managed_access_present(self):
        assert categorize_managed_access("MANAGED ACCESS") == TRISTATE_TRUE

    def test_managed_access_absent(self):
        assert categorize_managed_access("TRANSIENT") == TRISTATE_FALSE

    def test_managed_access_missing_is_unknown(self):
        assert categorize_managed_access(None) == TRISTATE_UNKNOWN

    def test_transient_present(self):
        assert categorize_transient("TRANSIENT") == TRISTATE_TRUE

    def test_transient_absent(self):
        assert categorize_transient("MANAGED ACCESS") == TRISTATE_FALSE

    def test_transient_missing_is_unknown(self):
        assert categorize_transient(None) == TRISTATE_UNKNOWN

    def test_both_tokens_present(self):
        assert categorize_managed_access("TRANSIENT MANAGED ACCESS") == TRISTATE_TRUE
        assert categorize_transient("TRANSIENT MANAGED ACCESS") == TRISTATE_TRUE

    def test_empty_string_is_false_not_unknown(self):
        """An empty (but present) options string means neither token
        applies — a real, observed false, not a missing/unknown value."""
        assert categorize_managed_access("") == TRISTATE_FALSE
        assert categorize_transient("") == TRISTATE_FALSE


# ── Warehouse state ───────────────────────────────────────────────────────────


class TestWarehouseState:
    def test_started(self):
        assert categorize_warehouse_state("STARTED") == WAREHOUSE_STATE_STARTED

    def test_suspended(self):
        assert categorize_warehouse_state("SUSPENDED") == WAREHOUSE_STATE_SUSPENDED

    def test_resizing(self):
        assert categorize_warehouse_state("RESIZING") == WAREHOUSE_STATE_RESIZING

    def test_missing_is_unknown(self):
        assert categorize_warehouse_state(None) == WAREHOUSE_STATE_UNKNOWN


# ── Share kind ────────────────────────────────────────────────────────────────


class TestShareKind:
    def test_outbound(self):
        assert categorize_share_kind("OUTBOUND") == SHARE_KIND_OUTBOUND

    def test_inbound(self):
        assert categorize_share_kind("INBOUND") == SHARE_KIND_INBOUND

    def test_missing_is_unknown(self):
        assert categorize_share_kind(None) == SHARE_KIND_UNKNOWN


# ── Object-type taxonomy ──────────────────────────────────────────────────────


class TestObjectTypeTaxonomy:
    def test_database(self):
        assert categorize_object_type("DATABASE") == OBJECT_TYPE_DATABASE

    def test_schema(self):
        assert categorize_object_type("SCHEMA") == OBJECT_TYPE_SCHEMA

    def test_table(self):
        assert categorize_object_type("TABLE") == OBJECT_TYPE_TABLE

    def test_view(self):
        assert categorize_object_type("VIEW") == OBJECT_TYPE_VIEW

    def test_materialized_view_maps_to_view(self):
        assert categorize_object_type("MATERIALIZED VIEW") == OBJECT_TYPE_VIEW

    def test_warehouse(self):
        assert categorize_object_type("WAREHOUSE") == OBJECT_TYPE_WAREHOUSE

    def test_function_and_procedure_share_category(self):
        assert categorize_object_type("FUNCTION") == OBJECT_TYPE_FUNCTION_PROCEDURE
        assert categorize_object_type("PROCEDURE") == OBJECT_TYPE_FUNCTION_PROCEDURE

    def test_file_format(self):
        assert categorize_object_type("FILE FORMAT") == OBJECT_TYPE_FILE_FORMAT

    def test_share(self):
        assert categorize_object_type("SHARE") == OBJECT_TYPE_SHARE

    def test_unrecognized_is_unknown(self):
        assert categorize_object_type("SOME_FUTURE_OBJECT") == OBJECT_TYPE_UNKNOWN

    def test_none_is_unknown(self):
        assert categorize_object_type(None) == OBJECT_TYPE_UNKNOWN

    def test_role_and_database_role_are_hierarchy_rows(self):
        assert is_role_hierarchy_row("ROLE") is True
        assert is_role_hierarchy_row("DATABASE_ROLE") is True

    def test_table_is_not_a_hierarchy_row(self):
        assert is_role_hierarchy_row("TABLE") is False

    def test_none_is_not_a_hierarchy_row(self):
        assert is_role_hierarchy_row(None) is False


# ── Privilege taxonomy ────────────────────────────────────────────────────────


class TestPrivilegeTaxonomy:
    def test_ownership(self):
        assert categorize_privilege("OWNERSHIP") == PRIVILEGE_CATEGORY_OWNERSHIP

    def test_select_is_data_read(self):
        assert categorize_privilege("SELECT") == PRIVILEGE_CATEGORY_DATA_READ

    def test_references_is_data_read(self):
        assert categorize_privilege("REFERENCES") == PRIVILEGE_CATEGORY_DATA_READ

    def test_insert_update_delete_truncate_are_data_write(self):
        for priv in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert categorize_privilege(priv) == PRIVILEGE_CATEGORY_DATA_WRITE

    def test_usage_is_usage(self):
        assert categorize_privilege("USAGE") == PRIVILEGE_CATEGORY_USAGE

    def test_imported_privileges_is_usage(self):
        assert categorize_privilege("IMPORTED PRIVILEGES") == PRIVILEGE_CATEGORY_USAGE

    def test_monitor(self):
        assert categorize_privilege("MONITOR") == PRIVILEGE_CATEGORY_MONITOR

    def test_operate_modify_apply_are_operational_control(self):
        for priv in ("OPERATE", "MODIFY", "APPLY"):
            assert categorize_privilege(priv) == PRIVILEGE_CATEGORY_OPERATIONAL_CONTROL

    def test_create_prefix_is_object_create(self):
        assert categorize_privilege("CREATE TABLE") == PRIVILEGE_CATEGORY_OBJECT_CREATE
        assert categorize_privilege("CREATE SCHEMA") == PRIVILEGE_CATEGORY_OBJECT_CREATE
        assert categorize_privilege("CREATE DATABASE") == PRIVILEGE_CATEGORY_OBJECT_CREATE

    def test_lowercase_normalized(self):
        assert categorize_privilege("select") == PRIVILEGE_CATEGORY_DATA_READ

    def test_unrecognized_is_unknown(self):
        assert categorize_privilege("SOME_FUTURE_PRIVILEGE") == PRIVILEGE_CATEGORY_UNKNOWN

    def test_empty_is_unknown(self):
        assert categorize_privilege("") == PRIVILEGE_CATEGORY_UNKNOWN

    def test_none_is_unknown(self):
        assert categorize_privilege(None) == PRIVILEGE_CATEGORY_UNKNOWN


# ── Grant option ──────────────────────────────────────────────────────────────


class TestGrantOption:
    def test_true(self):
        assert categorize_grant_option(True) == GRANT_OPTION_TRUE
        assert categorize_grant_option("true") == GRANT_OPTION_TRUE

    def test_false(self):
        assert categorize_grant_option(False) == GRANT_OPTION_FALSE
        assert categorize_grant_option("false") == GRANT_OPTION_FALSE

    def test_missing_is_unknown_never_false(self):
        assert categorize_grant_option(None) == GRANT_OPTION_UNKNOWN

    def test_malformed_is_unknown(self):
        assert categorize_grant_option("maybe") == GRANT_OPTION_UNKNOWN


# ── Database normalizer ───────────────────────────────────────────────────────


class TestNormalizeDatabase:
    def test_full_row(self):
        row = {"NAME": "MYDB", "KIND": "STANDARD", "OWNER": "SYSADMIN", "OPTIONS": "", "RETENTION_TIME": "1", "ORIGIN": None}
        record = SnowflakeConnector._normalize_database(_ACCOUNT_ID, row)
        assert record["record_type"] == SNOWFLAKE_DATABASE
        assert record["database_name"] == "MYDB"
        assert record["database_kind"] == DATABASE_KIND_STANDARD
        assert record["owner"] == "SYSADMIN"
        assert record["transient"] == TRISTATE_FALSE
        assert record["retention_time"] == 1

    def test_imported_database_with_origin(self):
        row = {"NAME": "SHARED_DB", "KIND": "IMPORTED DATABASE", "ORIGIN": "SNOWFLAKE.ACCOUNT_USAGE"}
        record = SnowflakeConnector._normalize_database(_ACCOUNT_ID, row)
        assert record["database_kind"] == DATABASE_KIND_IMPORTED
        assert record["origin"] == "SNOWFLAKE.ACCOUNT_USAGE"

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_database(_ACCOUNT_ID, {"NAME": None}) is None

    def test_stable_record_id(self):
        record = SnowflakeConnector._normalize_database(_ACCOUNT_ID, {"NAME": "MyDb"})
        assert record["record_id"] == f"{_ACCOUNT_ID}/database/mydb"

    def test_no_comment_field_collected(self):
        """Arbitrary comment text is never read into the record at all."""
        row = {"NAME": "MYDB", "COMMENT": "contains PII details about customers"}
        record = SnowflakeConnector._normalize_database(_ACCOUNT_ID, row)
        assert "comment" not in record
        assert "PII" not in str(record)


# ── Schema normalizer ──────────────────────────────────────────────────────────


class TestNormalizeSchema:
    def test_managed_access_schema(self):
        row = {"NAME": "PUBLIC", "OWNER": "SYSADMIN", "OPTIONS": "MANAGED ACCESS", "RETENTION_TIME": "1"}
        record = SnowflakeConnector._normalize_schema(_ACCOUNT_ID, "MYDB", row)
        assert record["record_type"] == SNOWFLAKE_SCHEMA
        assert record["managed_access"] == TRISTATE_TRUE

    def test_unmanaged_schema(self):
        row = {"NAME": "PUBLIC", "OPTIONS": ""}
        record = SnowflakeConnector._normalize_schema(_ACCOUNT_ID, "MYDB", row)
        assert record["managed_access"] == TRISTATE_FALSE

    def test_managed_access_never_inferred_from_name(self):
        """A schema literally named 'MANAGED_SCHEMA' must NOT be treated
        as managed-access unless the OPTIONS column says so."""
        row = {"NAME": "MANAGED_SCHEMA", "OPTIONS": ""}
        record = SnowflakeConnector._normalize_schema(_ACCOUNT_ID, "MYDB", row)
        assert record["managed_access"] == TRISTATE_FALSE

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_schema(_ACCOUNT_ID, "MYDB", {"NAME": None}) is None

    def test_stable_identity_includes_database(self):
        record = SnowflakeConnector._normalize_schema(_ACCOUNT_ID, "MYDB", {"NAME": "PUBLIC"})
        assert record["record_id"] == f"{_ACCOUNT_ID}/schema/mydb.public"


# ── Warehouse normalizer ───────────────────────────────────────────────────────


class TestNormalizeWarehouse:
    def test_full_row(self):
        row = {
            "NAME": "COMPUTE_WH", "OWNER": "SYSADMIN", "STATE": "STARTED", "SIZE": "X-Small",
            "AUTO_SUSPEND": "600", "AUTO_RESUME": "true", "SCALING_POLICY": "STANDARD",
            "MIN_CLUSTER_COUNT": "1", "MAX_CLUSTER_COUNT": "1", "RESOURCE_MONITOR": "MY_MONITOR",
        }
        record = SnowflakeConnector._normalize_warehouse(_ACCOUNT_ID, row)
        assert record["record_type"] == SNOWFLAKE_WAREHOUSE
        assert record["state"] == WAREHOUSE_STATE_STARTED
        assert record["auto_suspend"] == 600
        assert record["auto_resume"] == TRISTATE_TRUE
        assert record["resource_monitor"] == "MY_MONITOR"

    def test_cost_performance_fields_not_collected(self):
        """Query acceleration / resource_constraint / generation fields
        are never read — this connector tracks security-relevant posture
        only, never turning cost controls into a security signal."""
        row = {"NAME": "WH", "ENABLE_QUERY_ACCELERATION": "true", "GENERATION": "2"}
        record = SnowflakeConnector._normalize_warehouse(_ACCOUNT_ID, row)
        assert "enable_query_acceleration" not in record
        assert "generation" not in record

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_warehouse(_ACCOUNT_ID, {"NAME": None}) is None


# ── Share normalizer ───────────────────────────────────────────────────────────


class TestNormalizeShare:
    def test_outbound_share(self):
        row = {"NAME": "MY_SHARE", "KIND": "OUTBOUND", "OWNER": "SYSADMIN", "DATABASE_NAME": "MYDB", "TO": "XY12345, YZ23456"}
        record = SnowflakeConnector._normalize_share(_ACCOUNT_ID, row)
        assert record["record_type"] == SNOWFLAKE_SHARE
        assert record["share_kind"] == SHARE_KIND_OUTBOUND
        assert record["consumer_count"] == 2
        assert record["consumer_count_may_be_truncated"] is False

    def test_consumer_count_truncation_flagged_at_three(self):
        """SHOW SHARES documents a max of 3 displayed consumer accounts
        even when more actually exist — the count must never be presented
        as precise when it hits that documented display cap."""
        row = {"NAME": "MY_SHARE", "KIND": "OUTBOUND", "TO": "A1, A2, A3"}
        record = SnowflakeConnector._normalize_share(_ACCOUNT_ID, row)
        assert record["consumer_count"] == 3
        assert record["consumer_count_may_be_truncated"] is True

    def test_inbound_share_no_consumers(self):
        row = {"NAME": "IMPORTED_SHARE", "KIND": "INBOUND"}
        record = SnowflakeConnector._normalize_share(_ACCOUNT_ID, row)
        assert record["share_kind"] == SHARE_KIND_INBOUND
        assert record["consumer_count"] == 0

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_share(_ACCOUNT_ID, {"NAME": None}) is None

    def test_share_existence_never_implies_public_data(self):
        """No field on a share record ever claims or implies public
        accessibility — a share is controlled Snowflake-to-Snowflake
        sharing only."""
        row = {"NAME": "MY_SHARE", "KIND": "OUTBOUND"}
        record = SnowflakeConnector._normalize_share(_ACCOUNT_ID, row)
        for forbidden in ("public", "is_public", "publicly_accessible"):
            assert forbidden not in record


# ── FQN splitting ──────────────────────────────────────────────────────────────


class TestSplitObjectFqn:
    def test_table_three_parts(self):
        db, schema, obj = SnowflakeConnector._split_object_fqn(OBJECT_TYPE_TABLE, "MYDB.PUBLIC.ORDERS")
        assert (db, schema, obj) == ("MYDB", "PUBLIC", "ORDERS")

    def test_schema_two_parts(self):
        db, schema, obj = SnowflakeConnector._split_object_fqn(OBJECT_TYPE_SCHEMA, "MYDB.PUBLIC")
        assert (db, schema, obj) == ("MYDB", "PUBLIC", None)

    def test_database_one_part(self):
        db, schema, obj = SnowflakeConnector._split_object_fqn(OBJECT_TYPE_DATABASE, "MYDB")
        assert (db, schema, obj) == ("MYDB", None, None)

    def test_warehouse_bare_name_not_decomposed_as_db(self):
        db, schema, obj = SnowflakeConnector._split_object_fqn(OBJECT_TYPE_WAREHOUSE, "COMPUTE_WH")
        assert db is None
        assert obj == "COMPUTE_WH"

    def test_quoted_name_never_decomposed(self):
        """A name containing a quote character is never split on dots —
        a quoted identifier can legally contain an embedded dot, so naive
        splitting could silently misparse it."""
        db, schema, obj = SnowflakeConnector._split_object_fqn(OBJECT_TYPE_TABLE, 'MYDB.PUBLIC."WEIRD.NAME"')
        assert (db, schema, obj) == (None, None, None)

    def test_none_name_returns_all_none(self):
        assert SnowflakeConnector._split_object_fqn(OBJECT_TYPE_TABLE, None) == (None, None, None)

    def test_empty_name_returns_all_none(self):
        assert SnowflakeConnector._split_object_fqn(OBJECT_TYPE_TABLE, "") == (None, None, None)


# ── Object grant normalizer ────────────────────────────────────────────────────


class TestNormalizeObjectGrant:
    def test_current_grant_full_row(self):
        row = {"PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE", "NAME": "MYDB.PUBLIC.ORDERS", "GRANT_OPTION": "false", "GRANTED_BY": "SYSADMIN"}
        record = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        assert record["record_type"] == SNOWFLAKE_OBJECT_GRANT
        assert record["privilege"] == "SELECT"
        assert record["privilege_category"] == PRIVILEGE_CATEGORY_DATA_READ
        assert record["object_type"] == OBJECT_TYPE_TABLE
        assert record["database_name"] == "MYDB"
        assert record["schema_name"] == "PUBLIC"
        assert record["object_name"] == "ORDERS"
        assert record["future_grant"] is False
        assert record["ownership"] is False

    def test_future_grant_uses_grant_on_column(self):
        row = {"PRIVILEGE": "SELECT", "GRANT_ON": "TABLE", "NAME": "MYDB.PUBLIC.<TABLE>", "GRANT_OPTION": "false"}
        record = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="PUBLIC", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=True,
        )
        assert record["future_grant"] is True
        assert record["object_type"] == OBJECT_TYPE_TABLE
        assert record["object_fqn"] == "MYDB.PUBLIC.<TABLE>"

    def test_ownership_flag_set_from_privilege(self):
        row = {"PRIVILEGE": "OWNERSHIP", "GRANTED_ON": "DATABASE", "NAME": "MYDB"}
        record = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="SYSADMIN", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        assert record["ownership"] is True

    def test_database_role_grantee_type_preserved(self):
        row = {"PRIVILEGE": "USAGE", "GRANTED_ON": "SCHEMA", "NAME": "MYDB.PUBLIC"}
        record = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="DB_READER", grantee_type=PRINCIPAL_TYPE_DATABASE_ROLE, future_grant=False,
        )
        assert record["grantee_type"] == PRINCIPAL_TYPE_DATABASE_ROLE

    def test_missing_privilege_returns_none(self):
        row = {"PRIVILEGE": None, "GRANTED_ON": "TABLE", "NAME": "MYDB.PUBLIC.ORDERS"}
        assert SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        ) is None

    def test_grant_option_missing_is_unknown(self):
        row = {"PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE", "NAME": "MYDB.PUBLIC.ORDERS"}
        record = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        assert record["grant_option"] == GRANT_OPTION_UNKNOWN

    def test_stable_grant_identity_deterministic(self):
        row = {"PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE", "NAME": "MYDB.PUBLIC.ORDERS"}
        r1 = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        r2 = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, dict(row), grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        assert r1["record_id"] == r2["record_id"]

    def test_current_and_future_grants_never_collide_in_identity(self):
        row = {"PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE", "NAME": "MYDB.PUBLIC.ORDERS"}
        current = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        future = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=True,
        )
        assert current["record_id"] != future["record_id"]

    def test_no_table_row_data_collected(self):
        """This normalizer only ever handles grant metadata rows — there
        is no code path anywhere that reads/stores actual table/view
        contents."""
        row = {"PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE", "NAME": "MYDB.PUBLIC.ORDERS"}
        record = SnowflakeConnector._normalize_object_grant(
            _ACCOUNT_ID, row, grantee_name="ANALYST", grantee_type=PRINCIPAL_TYPE_ACCOUNT_ROLE, future_grant=False,
        )
        for forbidden in ("rows", "columns", "sample_data", "query_result"):
            assert forbidden not in record
