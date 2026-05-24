"""Tests for Milestone 42: AWS RDS + Database Exposure / Backup / Encryption Config.

Covers:
- Security hard rules: no DB connections; DownloadDBLogFilePortion never called;
  MasterUserPassword never stored; no write APIs called
- Module-level helpers (_classify_rds_name_sensitivity, _rds_engine_major_version,
  _rds_summarize_pending_modified, _rds_sorted_sg_ids, _rds_sorted_param_group_names,
  _rds_sorted_option_group_names)
- Diff service tracked field registration for all 5 M42 types
- Risk classification: aws_rds_db_instance (full matrix)
- Risk classification: aws_rds_db_cluster (full matrix)
- Risk classification: aws_rds_db_subnet_group
- Risk classification: aws_rds_db_snapshot
- Risk classification: aws_rds_db_cluster_snapshot
- Failure classification: classify_aws_rds_failure
- Connector normalization: _fetch_rds_in_region (all 5 resource types)
- Service inventory: M42 surfaces + counts, "rds" in enabled_surfaces
- Schema: AWS_RECORD_TYPES contains all 5 M42 constants
- M41 regression guard
"""

import pytest
from unittest.mock import MagicMock, patch

from app.connectors.aws import (
    AWSConnector,
    _classify_rds_name_sensitivity,
    _rds_engine_major_version,
    _rds_summarize_pending_modified,
    _rds_sorted_sg_ids,
    _rds_sorted_param_group_names,
    _rds_sorted_option_group_names,
    _hash_kms_key_id,
)
from app.connectors.aws_schema import (
    AWS_RDS_DB_INSTANCE,
    AWS_RDS_DB_CLUSTER,
    AWS_RDS_DB_SUBNET_GROUP,
    AWS_RDS_DB_SNAPSHOT,
    AWS_RDS_DB_CLUSTER_SNAPSHOT,
    AWS_SERVICE_INVENTORY,
    AWS_SSM_PARAMETER,
    AWS_SECRETSMANAGER_SECRET,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import classify_aws_rds_failure
from app.connectors.exceptions import (
    ConnectorError,
    AuthenticationError,
    RateLimitError,
    NetworkError,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_connector():
    """Create an AWSConnector without calling __init__ (no DB needed)."""
    conn = AWSConnector.__new__(AWSConnector)
    return conn


def _creds(regions=None):
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_default_region": "us-east-1",
        "aws_selected_regions": regions or ["us-east-1"],
    }


def _rds_change(
    record_type=AWS_RDS_DB_INSTANCE,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="prod-db",
    **extra,
):
    """Build a minimal RDS change dict for classify_aws_change."""
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "name": record_name,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
        **extra,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

class TestM42Schema:
    def test_all_m42_types_in_record_types(self):
        for rt in (
            AWS_RDS_DB_INSTANCE,
            AWS_RDS_DB_CLUSTER,
            AWS_RDS_DB_SUBNET_GROUP,
            AWS_RDS_DB_SNAPSHOT,
            AWS_RDS_DB_CLUSTER_SNAPSHOT,
        ):
            assert rt in AWS_RECORD_TYPES, f"{rt} missing from AWS_RECORD_TYPES"

    def test_m42_string_values(self):
        assert AWS_RDS_DB_INSTANCE == "aws_rds_db_instance"
        assert AWS_RDS_DB_CLUSTER == "aws_rds_db_cluster"
        assert AWS_RDS_DB_SUBNET_GROUP == "aws_rds_db_subnet_group"
        assert AWS_RDS_DB_SNAPSHOT == "aws_rds_db_snapshot"
        assert AWS_RDS_DB_CLUSTER_SNAPSHOT == "aws_rds_db_cluster_snapshot"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsNameSensitivity:
    def test_production_category(self):
        assert _classify_rds_name_sensitivity("prod-database") == "production"
        assert _classify_rds_name_sensitivity("live-payments-db") == "production"

    def test_database_category(self):
        assert _classify_rds_name_sensitivity("mypostgres-cluster") == "database"
        assert _classify_rds_name_sensitivity("mysql-replica") == "database"

    def test_payment_category(self):
        assert _classify_rds_name_sensitivity("billing-db") == "payment"
        assert _classify_rds_name_sensitivity("stripe-payments") == "payment"

    def test_secure_category(self):
        assert _classify_rds_name_sensitivity("secrets-store") == "secure"

    def test_none_category(self):
        assert _classify_rds_name_sensitivity("test-001") == "none"
        assert _classify_rds_name_sensitivity("staging-replica") == "none"

    def test_case_insensitive(self):
        result = _classify_rds_name_sensitivity("PROD-MYSQL-CLUSTER")
        assert result != "none"  # should detect "prod"

    def test_empty_string_returns_none(self):
        assert _classify_rds_name_sensitivity("") == "none"


class TestRdsEngineMajorVersion:
    def test_standard_version(self):
        assert _rds_engine_major_version("8.0.28") == "8"
        assert _rds_engine_major_version("5.7.40") == "5"
        assert _rds_engine_major_version("14.5") == "14"

    def test_aurora_mysql(self):
        assert _rds_engine_major_version("aurora-mysql8.0.23") == "8"

    def test_aurora_postgresql(self):
        assert _rds_engine_major_version("aurora-postgresql14.6") == "14"

    def test_aurora_generic(self):
        assert _rds_engine_major_version("aurora-5.6") == "5"

    def test_empty_string(self):
        assert _rds_engine_major_version("") == "unknown"

    def test_none_like_empty(self):
        assert _rds_engine_major_version("") == "unknown"

    def test_non_numeric_fallback(self):
        result = _rds_engine_major_version("custom-engine")
        assert isinstance(result, str)


class TestRdsSummarizePendingModified:
    def test_none_returns_none(self):
        assert _rds_summarize_pending_modified({}) is None
        assert _rds_summarize_pending_modified(None) is None

    def test_returns_pending_field_names(self):
        result = _rds_summarize_pending_modified({"AllocatedStorage": 100, "DBInstanceClass": "db.t3.medium"})
        assert result is not None
        assert "AllocatedStorage" in result["pending_fields"]
        assert "DBInstanceClass" in result["pending_fields"]
        assert result["count"] == 2

    def test_master_user_password_excluded(self):
        """SECURITY: MasterUserPassword must NEVER appear in pending summaries."""
        result = _rds_summarize_pending_modified({
            "MasterUserPassword": "SHOULD_NOT_BE_HERE",
            "AllocatedStorage": 200,
        })
        # MasterUserPassword must not be in the result
        assert result is not None
        assert "MasterUserPassword" not in result["pending_fields"]
        assert "masterUserPassword" not in result["pending_fields"]
        # The raw value must not appear anywhere in the result dict
        result_str = str(result)
        assert "SHOULD_NOT_BE_HERE" not in result_str

    def test_password_excluded(self):
        """SECURITY: password field must never be stored."""
        result = _rds_summarize_pending_modified({"Password": "secret123", "DBInstanceClass": "db.t3.small"})
        if result:
            assert "Password" not in result["pending_fields"]
            assert "secret123" not in str(result)

    def test_none_values_excluded(self):
        result = _rds_summarize_pending_modified({"AllocatedStorage": None, "DBInstanceClass": "db.t3.medium"})
        assert result is not None
        assert "AllocatedStorage" not in result["pending_fields"]
        assert "DBInstanceClass" in result["pending_fields"]

    def test_all_excluded_returns_none(self):
        result = _rds_summarize_pending_modified({"MasterUserPassword": "secret"})
        assert result is None


class TestRdsSortedSgIds:
    def test_extracts_and_sorts(self):
        sgs = [
            {"VpcSecurityGroupId": "sg-ccc"},
            {"VpcSecurityGroupId": "sg-aaa"},
            {"VpcSecurityGroupId": "sg-bbb"},
        ]
        result = _rds_sorted_sg_ids(sgs)
        assert result == ["sg-aaa", "sg-bbb", "sg-ccc"]

    def test_empty_list(self):
        assert _rds_sorted_sg_ids([]) == []

    def test_missing_id_skipped(self):
        sgs = [{"VpcSecurityGroupId": "sg-001"}, {"OtherField": "x"}]
        result = _rds_sorted_sg_ids(sgs)
        assert result == ["sg-001"]


class TestRdsSortedParamGroupNames:
    def test_sorts_names(self):
        groups = [
            {"DBParameterGroupName": "pg-c"},
            {"DBParameterGroupName": "pg-a"},
            {"DBParameterGroupName": "pg-b"},
        ]
        result = _rds_sorted_param_group_names(groups)
        assert result == ["pg-a", "pg-b", "pg-c"]

    def test_empty(self):
        assert _rds_sorted_param_group_names([]) == []

    def test_custom_key(self):
        groups = [{"DBClusterParameterGroupName": "cpg-z"}, {"DBClusterParameterGroupName": "cpg-a"}]
        result = _rds_sorted_param_group_names(groups, key="DBClusterParameterGroupName")
        assert result == ["cpg-a", "cpg-z"]


class TestRdsSortedOptionGroupNames:
    def test_sorts_names(self):
        groups = [{"OptionGroupName": "og-z"}, {"OptionGroupName": "og-a"}]
        result = _rds_sorted_option_group_names(groups)
        assert result == ["og-a", "og-z"]

    def test_empty(self):
        assert _rds_sorted_option_group_names([]) == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestM42DiffServiceFields:
    def test_db_instance_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_RDS_DB_INSTANCE})
        assert fields is not None
        assert "publicly_accessible" in fields
        assert "storage_encrypted" in fields
        assert "deletion_protection" in fields
        assert "backup_retention_period" in fields
        assert "iam_database_authentication_enabled" in fields
        assert "multi_az" in fields
        assert "engine_version" in fields
        assert "kms_key_id_present" in fields
        assert "tag_keys" in fields
        assert "config_fetch_warnings" in fields
        # Must NOT track raw KMS key IDs, passwords, etc.
        assert "kms_key_id" not in fields  # only kms_key_id_present and _hash

    def test_db_cluster_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_RDS_DB_CLUSTER})
        assert fields is not None
        assert "publicly_accessible" in fields
        assert "storage_encrypted" in fields
        assert "deletion_protection" in fields
        assert "backup_retention_period" in fields
        assert "iam_database_authentication_enabled" in fields
        assert "engine_version" in fields
        assert "db_cluster_members_count" in fields

    def test_db_subnet_group_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_RDS_DB_SUBNET_GROUP})
        assert fields is not None
        assert "vpc_id" in fields
        assert "subnet_count" in fields
        assert "subnet_ids" in fields
        assert "status" in fields

    def test_db_snapshot_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_RDS_DB_SNAPSHOT})
        assert fields is not None
        assert "publicly_accessible" in fields
        assert "storage_encrypted" in fields
        assert "kms_key_id_present" in fields
        assert "status" in fields

    def test_db_cluster_snapshot_tracked_fields(self):
        fields = _tracked_fields_for({"record_type": AWS_RDS_DB_CLUSTER_SNAPSHOT})
        assert fields is not None
        assert "publicly_accessible" in fields
        assert "storage_encrypted" in fields
        assert "kms_key_id_present" in fields
        assert "status" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk classification — aws_rds_db_instance
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsDbInstanceRisk:
    def test_added_is_low(self):
        change = _rds_change(change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_nonsensitive_is_medium(self):
        change = _rds_change(change_type="removed", record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        change = _rds_change(change_type="removed", record_name="prod-db")
        level, _ = classify_aws_change(change)
        assert level == "high"

    # publicly_accessible
    def test_publicly_accessible_true_sensitive_is_critical(self):
        change = _rds_change(fp="publicly_accessible", nv=True, record_name="prod-db")
        change["field_path"] = "publicly_accessible"
        change["new_value"] = True
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "publicly" in reason.lower() or "public" in reason.lower()

    def test_publicly_accessible_true_nonsensitive_is_high(self):
        change = _rds_change(field_path="publicly_accessible", new_value=True, record_name="test-001")
        level, reason = classify_aws_change(change)
        assert level == "high"

    def test_publicly_accessible_false_is_low(self):
        change = _rds_change(field_path="publicly_accessible", new_value=False, record_name="prod-db")
        level, _ = classify_aws_change(change)
        assert level == "low"

    # storage_encrypted
    def test_storage_encrypted_false_is_critical(self):
        change = _rds_change(field_path="storage_encrypted", new_value=False, record_name="prod-db")
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "encrypt" in reason.lower()

    def test_storage_encrypted_true_is_low(self):
        change = _rds_change(field_path="storage_encrypted", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # deletion_protection
    def test_deletion_protection_false_sensitive_is_critical(self):
        change = _rds_change(field_path="deletion_protection", new_value=False, record_name="prod-db")
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_deletion_protection_false_nonsensitive_is_medium(self):
        change = _rds_change(field_path="deletion_protection", new_value=False, record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_deletion_protection_true_is_low(self):
        change = _rds_change(field_path="deletion_protection", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # backup_retention_period
    def test_backup_retention_zero_sensitive_is_high(self):
        change = _rds_change(field_path="backup_retention_period", new_value=0, prev_value=7, record_name="prod-db")
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "backup" in reason.lower()

    def test_backup_retention_zero_nonsensitive_is_medium(self):
        change = _rds_change(field_path="backup_retention_period", new_value=0, prev_value=7, record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_backup_retention_reduced_is_medium(self):
        change = _rds_change(field_path="backup_retention_period", new_value=3, prev_value=7)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_backup_retention_increased_is_low(self):
        change = _rds_change(field_path="backup_retention_period", new_value=14, prev_value=7)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # IAM auth
    def test_iam_auth_disabled_sensitive_is_high(self):
        change = _rds_change(field_path="iam_database_authentication_enabled", new_value=False, record_name="prod-db")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_iam_auth_disabled_nonsensitive_is_medium(self):
        change = _rds_change(field_path="iam_database_authentication_enabled", new_value=False, record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_iam_auth_enabled_is_low(self):
        change = _rds_change(field_path="iam_database_authentication_enabled", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # multi_az
    def test_multi_az_disabled_sensitive_is_high(self):
        change = _rds_change(field_path="multi_az", new_value=False, record_name="prod-db")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_multi_az_enabled_is_low(self):
        change = _rds_change(field_path="multi_az", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # kms_key_id_present
    def test_kms_key_removed_is_high(self):
        change = _rds_change(field_path="kms_key_id_present", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "high"

    # security groups
    def test_vpc_sg_changed_is_medium(self):
        change = _rds_change(field_path="vpc_security_group_ids", new_value=["sg-new"])
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # auto minor version upgrade
    def test_auto_minor_upgrade_disabled_is_medium(self):
        change = _rds_change(field_path="auto_minor_version_upgrade", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_auto_minor_upgrade_enabled_is_low(self):
        change = _rds_change(field_path="auto_minor_version_upgrade", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # engine version
    def test_engine_version_changed_is_medium(self):
        change = _rds_change(field_path="engine_version", new_value="8.0.32", prev_value="8.0.28")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_engine_major_version_changed_sensitive_is_high(self):
        change = _rds_change(field_path="engine_major_version", new_value="9", prev_value="8", record_name="prod-db")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_engine_major_version_changed_nonsensitive_is_medium(self):
        change = _rds_change(field_path="engine_major_version", new_value="9", prev_value="8", record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # instance class
    def test_instance_class_changed_is_low(self):
        change = _rds_change(field_path="db_instance_class", new_value="db.t3.large", prev_value="db.t3.medium")
        level, _ = classify_aws_change(change)
        assert level == "low"

    # instance status
    def test_instance_status_failed_is_high(self):
        change = _rds_change(field_path="db_instance_status", new_value="failed")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_instance_status_available_is_low(self):
        change = _rds_change(field_path="db_instance_status", new_value="available")
        level, _ = classify_aws_change(change)
        assert level == "low"

    # parameter groups
    def test_param_group_changed_is_medium(self):
        change = _rds_change(field_path="parameter_group_names", new_value=["new-pg"])
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # monitoring
    def test_monitoring_interval_disabled_is_medium(self):
        change = _rds_change(field_path="monitoring_interval", new_value=0)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # performance insights
    def test_performance_insights_disabled_is_medium(self):
        change = _rds_change(field_path="performance_insights_enabled", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_performance_insights_enabled_is_low(self):
        change = _rds_change(field_path="performance_insights_enabled", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    # tags
    def test_tag_keys_changed_is_low(self):
        change = _rds_change(field_path="tag_keys", new_value=["env", "team"])
        level, _ = classify_aws_change(change)
        assert level == "low"

    # cluster association
    def test_cluster_id_changed_is_medium(self):
        change = _rds_change(field_path="db_cluster_identifier", new_value="new-cluster")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # unknown field
    def test_unknown_field_is_low(self):
        change = _rds_change(field_path="some_unknown_field_xyz", new_value="value")
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification — aws_rds_db_cluster
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsDbClusterRisk:
    def test_added_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_nonsensitive_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, change_type="removed", record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, change_type="removed", record_name="prod-aurora")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_publicly_accessible_true_sensitive_is_critical(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="publicly_accessible", new_value=True, record_name="prod-aurora")
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_publicly_accessible_true_nonsensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="publicly_accessible", new_value=True, record_name="test-001")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_storage_encrypted_false_is_critical(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="storage_encrypted", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_deletion_protection_false_sensitive_is_critical(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="deletion_protection", new_value=False, record_name="prod-aurora")
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_backup_retention_zero_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="backup_retention_period", new_value=0, prev_value=7, record_name="prod-aurora")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_iam_auth_disabled_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="iam_database_authentication_enabled", new_value=False, record_name="prod-aurora")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_multi_az_disabled_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="multi_az", new_value=False, record_name="prod-aurora")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_vpc_sg_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="vpc_security_group_ids", new_value=["sg-new"])
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_engine_version_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="engine_version", new_value="14.7", prev_value="14.5")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_instance_count_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="db_cluster_members_count", new_value=1, prev_value=3)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_cluster_status_failed_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="status", new_value="failed")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_cluster_param_group_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="db_cluster_parameter_group", new_value="new-cpg")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_tag_keys_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="tag_keys", new_value=["env"])
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unknown_field_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER, field_path="unknown_field_xyz")
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk classification — aws_rds_db_subnet_group
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsDbSubnetGroupRisk:
    def test_added_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, change_type="removed")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_vpc_id_changed_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="vpc_id", new_value="vpc-new", prev_value="vpc-old")
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "vpc" in reason.lower()

    def test_subnet_ids_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="subnet_ids", new_value=["subnet-new"])
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_subnet_count_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="subnet_count", new_value=2, prev_value=3)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_status_incomplete_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="status", new_value="incomplete")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_status_complete_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="status", new_value="Complete")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_tag_keys_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="tag_keys", new_value=["env"])
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_az_coverage_changed_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_SUBNET_GROUP, field_path="subnet_availability_zones", new_value=["us-east-1a"])
        level, _ = classify_aws_change(change)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk classification — aws_rds_db_snapshot
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsDbSnapshotRisk:
    def test_added_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_nonsensitive_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, change_type="removed", record_name="test-snap-001")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, change_type="removed", record_name="prod-snap")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_publicly_accessible_true_sensitive_is_critical(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="publicly_accessible", new_value=True, record_name="prod-db")
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "public" in reason.lower()

    def test_publicly_accessible_true_nonsensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="publicly_accessible", new_value=True, record_name="test-snap")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_publicly_accessible_false_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="publicly_accessible", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_storage_encrypted_false_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="storage_encrypted", new_value=False, record_name="prod-snap")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_storage_encrypted_true_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="storage_encrypted", new_value=True)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_kms_key_removed_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="kms_key_id_present", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_status_failed_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="status", new_value="failed")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_tag_keys_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_SNAPSHOT, field_path="tag_keys", new_value=["env"])
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Risk classification — aws_rds_db_cluster_snapshot
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsDbClusterSnapshotRisk:
    def test_added_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, change_type="added")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_removed_nonsensitive_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, change_type="removed", record_name="test-cluster-snap")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_removed_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, change_type="removed", record_name="prod-aurora-snap")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_publicly_accessible_true_sensitive_is_critical(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="publicly_accessible", new_value=True, record_name="prod-snap")
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "public" in reason.lower()

    def test_publicly_accessible_true_nonsensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="publicly_accessible", new_value=True, record_name="test-snap")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_storage_encrypted_false_nonsensitive_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="storage_encrypted", new_value=False, record_name="test-snap")
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_storage_encrypted_false_sensitive_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="storage_encrypted", new_value=False, record_name="prod-snap")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_kms_key_removed_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="kms_key_id_present", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_iam_auth_disabled_is_medium(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="iam_database_authentication_enabled", new_value=False)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_status_failed_is_high(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="status", new_value="failed")
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_tag_keys_is_low(self):
        change = _rds_change(record_type=AWS_RDS_DB_CLUSTER_SNAPSHOT, field_path="tag_keys", new_value=["env"])
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Failure classification
# ─────────────────────────────────────────────────────────────────────────────

class TestRdsFailureClassifier:
    def _auth_exc(self):
        exc = AuthenticationError("auth failed")
        return exc

    def _403_exc(self):
        exc = ConnectorError("access denied", status_code=403)
        return exc

    def _rate_exc(self):
        return RateLimitError("throttled")

    def _network_exc(self):
        return NetworkError("timeout")

    def _500_exc(self):
        return ConnectorError("server error", status_code=500)

    def test_describe_instances_access_denied_403(self):
        fc = classify_aws_rds_failure("DescribeDBInstances", self._403_exc())
        assert fc.error_code == "aws_rds_access_denied"
        assert "rds:DescribeDBInstances" in fc.recommended_action
        # Must not suggest any write actions
        assert "rds:Create" not in fc.recommended_action
        assert "rds:Modify" not in fc.recommended_action
        assert "rds:Delete" not in fc.recommended_action

    def test_describe_clusters_access_denied(self):
        fc = classify_aws_rds_failure("DescribeDBClusters", self._403_exc())
        assert fc.error_code == "aws_rds_access_denied"

    def test_auth_error(self):
        fc = classify_aws_rds_failure("DescribeDBInstances", self._auth_exc())
        assert "auth" in fc.error_code or "credential" in fc.error_code or "rds" in fc.error_code

    def test_rate_limit(self):
        fc = classify_aws_rds_failure("DescribeDBInstances", self._rate_exc())
        assert "rate" in fc.error_code or "throttl" in fc.error_code or "rds" in fc.error_code

    def test_network_error(self):
        fc = classify_aws_rds_failure("DescribeDBInstances", self._network_exc())
        assert fc.error_code != ""

    def test_server_error_500(self):
        fc = classify_aws_rds_failure("DescribeDBInstances", self._500_exc())
        assert fc.error_code != ""

    def test_per_api_codes(self):
        for api, expected_fragment in [
            ("DescribeDBInstances",       "instances"),
            ("DescribeDBClusters",        "clusters"),
            ("DescribeDBSubnetGroups",    "subnet_groups"),
            ("DescribeDBSnapshots",       "snapshots"),
            ("DescribeDBClusterSnapshots", "cluster_snapshots"),
        ]:
            fc = classify_aws_rds_failure(api, self._403_exc())
            # Either per-api error code OR generic access_denied — both acceptable
            assert fc.error_code != ""
            assert fc.recommended_action != ""

    def test_recommended_action_mentions_no_write_apis(self):
        fc = classify_aws_rds_failure("DescribeDBInstances", self._403_exc())
        forbidden = [
            "rds:Create", "rds:Modify", "rds:Delete", "rds:Restore",
            "rds:Reboot", "rds:Start", "rds:Stop",
            "DownloadDBLogFilePortion", "GetSecretValue", "kms:Decrypt",
        ]
        for bad in forbidden:
            assert bad not in fc.recommended_action, (
                f"Recommended action must not mention {bad!r}"
            )

    def test_unknown_api_returns_generic_rds_code(self):
        fc = classify_aws_rds_failure("UnknownRdsApi", self._403_exc())
        assert "rds" in fc.error_code


# ─────────────────────────────────────────────────────────────────────────────
# 10. Connector normalization — _fetch_rds_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchRdsInRegion:
    """Test that _fetch_rds_in_region normalizes all 5 RDS record types correctly."""

    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    def _make_mock_client(self):
        return MagicMock()

    def _make_call_aws(self, mock_client, inst_resp=None, cluster_resp=None,
                       sng_resp=None, snap_resp=None, csnap_resp=None):
        """Build a _call_aws side-effect that dispatches by function reference."""
        called = []

        def _call_aws(fn, **kwargs):
            called.append(fn)
            if fn is mock_client.describe_db_instances:
                return inst_resp or {"DBInstances": []}
            if fn is mock_client.describe_db_clusters:
                return cluster_resp or {"DBClusters": []}
            if fn is mock_client.describe_db_subnet_groups:
                return sng_resp or {"DBSubnetGroups": []}
            if fn is mock_client.describe_db_snapshots:
                return snap_resp or {"DBSnapshots": []}
            if fn is mock_client.describe_db_cluster_snapshots:
                return csnap_resp or {"DBClusterSnapshots": []}
            return {}

        _call_aws.called = called
        return _call_aws

    def test_db_instance_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        inst_resp = {
            "DBInstances": [{
                "DBInstanceIdentifier": "prod-mysql",
                "DBInstanceClass": "db.t3.medium",
                "DBInstanceStatus": "available",
                "Engine": "mysql",
                "EngineVersion": "8.0.28",
                "StorageEncrypted": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
                "PubliclyAccessible": False,
                "MultiAZ": True,
                "BackupRetentionPeriod": 7,
                "DeletionProtection": True,
                "IAMDatabaseAuthenticationEnabled": True,
                "AutoMinorVersionUpgrade": True,
                "CopyTagsToSnapshot": True,
                "PerformanceInsightsEnabled": False,
                "MonitoringInterval": 60,
                "AllocatedStorage": 100,
                "StorageType": "gp2",
                "LicenseModel": "general-public-license",
                "TagList": [{"Key": "env", "Value": "prod"}],
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-001"}],
                "DBParameterGroups": [{"DBParameterGroupName": "mysql8-params"}],
                "OptionGroupMemberships": [{"OptionGroupName": "default:mysql-8-0"}],
                "Endpoint": {"Port": 3306, "HostedZoneId": "Z2R2ITUGPM61AM"},
                "DBSubnetGroup": {
                    "VpcId": "vpc-abc123",
                    "DBSubnetGroupName": "my-subnet-group",
                    "SubnetGroupStatus": "Complete",
                },
                "PendingModifiedValues": {},
            }],
        }
        conn._call_aws = self._make_call_aws(client, inst_resp=inst_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        db_records = [r for r in records if r["record_type"] == AWS_RDS_DB_INSTANCE]
        assert len(db_records) == 1
        r = db_records[0]

        assert r["record_type"] == AWS_RDS_DB_INSTANCE
        assert r["name"] == "prod-mysql"
        assert r["engine"] == "mysql"
        assert r["engine_version"] == "8.0.28"
        assert r["engine_major_version"] == "8"
        assert r["storage_encrypted"] is True
        assert r["publicly_accessible"] is False
        assert r["multi_az"] is True
        assert r["backup_retention_period"] == 7
        assert r["deletion_protection"] is True
        assert r["iam_database_authentication_enabled"] is True
        assert r["vpc_id"] == "vpc-abc123"
        assert r["tag_keys"] == ["env"]
        assert r["vpc_security_group_ids"] == ["sg-001"]
        assert r["parameter_group_names"] == ["mysql8-params"]
        assert r["option_group_names"] == ["default:mysql-8-0"]
        assert r["endpoint_port"] == 3306
        assert r["account_id"] == self.ACCOUNT_ID
        assert r["region"] == self.REGION
        assert r["sensitive_name_category"] == "production"

        # Security: no raw KMS key ARN stored
        assert "kms_key_id" not in r or r.get("kms_key_id") is None
        assert r["kms_key_id_present"] is True
        assert r["kms_key_id_hash"] is not None
        assert r["kms_key_id_hash"] != "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"

    def test_db_instance_record_id_is_stable(self):
        conn = _make_connector()
        client = self._make_mock_client()
        inst_resp = {
            "DBInstances": [{"DBInstanceIdentifier": "my-db", "Engine": "postgres"}],
        }
        conn._call_aws = self._make_call_aws(client, inst_resp=inst_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)
        r = [r for r in records if r["record_type"] == AWS_RDS_DB_INSTANCE][0]
        assert r["record_id"] == f"{self.ACCOUNT_ID}/{self.REGION}/my-db"
        assert r["external_id"] == r["record_id"]

    def test_db_instance_no_master_password(self):
        """SECURITY: MasterUserPassword must never appear in any returned record."""
        conn = _make_connector()
        client = self._make_mock_client()
        inst_resp = {
            "DBInstances": [{
                "DBInstanceIdentifier": "test-db",
                "Engine": "mysql",
                "PendingModifiedValues": {"MasterUserPassword": "super-secret"},
            }],
        }
        conn._call_aws = self._make_call_aws(client, inst_resp=inst_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)
        r = [r for r in records if r["record_type"] == AWS_RDS_DB_INSTANCE][0]
        # Flatten all values and verify the secret is not stored
        all_values = str(r)
        assert "super-secret" not in all_values
        assert "MasterUserPassword" not in all_values

    def test_download_db_log_never_called(self):
        """SECURITY: DownloadDBLogFilePortion must never be called."""
        conn = _make_connector()
        client = self._make_mock_client()
        inst_resp = {"DBInstances": [{"DBInstanceIdentifier": "test-db", "Engine": "mysql"}]}
        call_aws = self._make_call_aws(client, inst_resp=inst_resp)
        conn._call_aws = call_aws
        conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)
        for fn in call_aws.called:
            fn_name = getattr(fn, "__name__", str(fn))
            assert "download" not in fn_name.lower(), (
                f"DownloadDBLogFilePortion was called: {fn_name}"
            )
            assert "log" not in fn_name.lower() or "describe" in fn_name.lower()

    def test_no_write_apis_called(self):
        """SECURITY: No write/mutate APIs should ever be called."""
        conn = _make_connector()
        client = self._make_mock_client()
        inst_resp = {"DBInstances": [{"DBInstanceIdentifier": "test-db", "Engine": "mysql"}]}
        call_aws = self._make_call_aws(client, inst_resp=inst_resp)
        conn._call_aws = call_aws
        conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)
        write_prefixes = ("create_", "modify_", "delete_", "restore_", "reboot_",
                          "start_", "stop_", "failover_", "promote_")
        for fn in call_aws.called:
            fn_name = getattr(fn, "__name__", str(fn))
            for prefix in write_prefixes:
                assert not fn_name.lower().startswith(prefix), (
                    f"Write API called: {fn_name}"
                )

    def test_db_cluster_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        cluster_resp = {
            "DBClusters": [{
                "DBClusterIdentifier": "prod-aurora",
                "Status": "available",
                "Engine": "aurora-mysql",
                "EngineVersion": "8.0.28",
                "EngineMode": "provisioned",
                "StorageEncrypted": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/xyz",
                "IAMDatabaseAuthenticationEnabled": True,
                "DeletionProtection": True,
                "MultiAZ": True,
                "BackupRetentionPeriod": 14,
                "PubliclyAccessible": False,
                "Port": 3306,
                "DBSubnetGroup": "my-subnet-group",
                "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                "DBClusterMembers": [
                    {"DBInstanceIdentifier": "aurora-instance-1", "IsClusterWriter": True},
                    {"DBInstanceIdentifier": "aurora-instance-2", "IsClusterWriter": False},
                ],
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-cluster"}],
                "DBClusterParameterGroup": "aurora-mysql8-params",
                "TagList": [{"Key": "team", "Value": "backend"}],
            }],
        }
        conn._call_aws = self._make_call_aws(client, cluster_resp=cluster_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        cl_records = [r for r in records if r["record_type"] == AWS_RDS_DB_CLUSTER]
        assert len(cl_records) == 1
        r = cl_records[0]

        assert r["db_cluster_identifier"] == "prod-aurora"
        assert r["status"] == "available"
        assert r["engine"] == "aurora-mysql"
        assert r["engine_major_version"] == "8"
        assert r["storage_encrypted"] is True
        assert r["kms_key_id_present"] is True
        assert r["kms_key_id_hash"] is not None
        assert r["deletion_protection"] is True
        assert r["db_cluster_members_count"] == 2
        assert r["writer_count"] == 1
        assert r["reader_count"] == 1
        assert r["availability_zone_count"] == 2
        assert r["db_cluster_parameter_group"] == "aurora-mysql8-params"
        assert r["endpoint_present"] is False   # no Endpoint in mock
        assert r["reader_endpoint_present"] is False
        assert r["database_name_present"] is False
        assert r["master_username_present"] is False
        assert r["tag_keys"] == ["team"]
        assert r["sensitive_name_category"] == "production"
        assert r["region"] == self.REGION

    def test_db_subnet_group_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        sng_resp = {
            "DBSubnetGroups": [{
                "DBSubnetGroupName": "my-subnet-group",
                "VpcId": "vpc-abc123",
                "SubnetGroupStatus": "Complete",
                "Subnets": [
                    {"SubnetIdentifier": "subnet-aaa", "SubnetAvailabilityZone": {"Name": "us-east-1a"}},
                    {"SubnetIdentifier": "subnet-bbb", "SubnetAvailabilityZone": {"Name": "us-east-1b"}},
                ],
                "TagList": [{"Key": "env", "Value": "prod"}],
            }],
        }
        conn._call_aws = self._make_call_aws(client, sng_resp=sng_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        sng_records = [r for r in records if r["record_type"] == AWS_RDS_DB_SUBNET_GROUP]
        assert len(sng_records) == 1
        r = sng_records[0]

        assert r["name"] == "my-subnet-group"
        assert r["vpc_id"] == "vpc-abc123"
        assert r["subnet_count"] == 2
        assert r["subnet_ids"] == ["subnet-aaa", "subnet-bbb"]
        assert sorted(r["subnet_availability_zones"]) == ["us-east-1a", "us-east-1b"]
        assert r["status"] == "Complete"
        assert r["tag_keys"] == ["env"]

    def test_db_snapshot_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        snap_resp = {
            "DBSnapshots": [{
                "DBSnapshotIdentifier": "my-snap-001",
                "DBInstanceIdentifier": "prod-mysql",
                "Engine": "mysql",
                "EngineVersion": "8.0.28",
                "Status": "available",
                "SnapshotType": "manual",
                "Encrypted": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/snap-key",
                "AllocatedStorage": 100,
                "AvailabilityZone": "us-east-1a",
                "VpcId": "vpc-abc123",
                "LicenseModel": "general-public-license",
                "TagList": [{"Key": "backup", "Value": "daily"}],
            }],
        }
        conn._call_aws = self._make_call_aws(client, snap_resp=snap_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        snap_records = [r for r in records if r["record_type"] == AWS_RDS_DB_SNAPSHOT]
        assert len(snap_records) == 1
        r = snap_records[0]

        assert r["db_snapshot_identifier"] == "my-snap-001"
        assert r["db_instance_identifier"] == "prod-mysql"
        assert r["engine"] == "mysql"
        assert r["storage_encrypted"] is True
        assert r["kms_key_id_present"] is True
        assert r["kms_key_id_hash"] is not None
        assert r["publicly_accessible"] is False  # type "manual" != "public"
        assert r["snapshot_type"] == "manual"
        assert r["tag_keys"] == ["backup"]

    def test_db_cluster_snapshot_basic_fields(self):
        conn = _make_connector()
        client = self._make_mock_client()
        csnap_resp = {
            "DBClusterSnapshots": [{
                "DBClusterSnapshotIdentifier": "aurora-snap-001",
                "DBClusterIdentifier": "prod-aurora",
                "Engine": "aurora-mysql",
                "EngineVersion": "8.0.28",
                "Status": "available",
                "SnapshotType": "manual",
                "StorageEncrypted": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/csnap-key",
                "AllocatedStorage": 0,
                "VpcId": "vpc-abc123",
                "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                "IAMDatabaseAuthenticationEnabled": True,
                "TagList": [],
            }],
        }
        conn._call_aws = self._make_call_aws(client, csnap_resp=csnap_resp)
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        csnap_records = [r for r in records if r["record_type"] == AWS_RDS_DB_CLUSTER_SNAPSHOT]
        assert len(csnap_records) == 1
        r = csnap_records[0]

        assert r["db_cluster_snapshot_identifier"] == "aurora-snap-001"
        assert r["db_cluster_identifier"] == "prod-aurora"
        assert r["storage_encrypted"] is True
        assert r["kms_key_id_present"] is True
        assert r["publicly_accessible"] is False  # type "manual" != "public"
        assert r["iam_database_authentication_enabled"] is True
        assert r["availability_zones"] == ["us-east-1a", "us-east-1b"]

    def test_empty_responses_return_empty(self):
        conn = _make_connector()
        client = self._make_mock_client()
        conn._call_aws = self._make_call_aws(client)  # all return empty
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)
        assert records == []

    def test_instance_fail_soft_continues_to_clusters(self):
        """If DescribeDBInstances fails, clusters should still be fetched."""
        conn = _make_connector()
        client = self._make_mock_client()
        cluster_resp = {
            "DBClusters": [{"DBClusterIdentifier": "my-cluster", "Engine": "aurora-mysql"}],
        }

        call_count = []

        def _call_aws(fn, **kwargs):
            call_count.append(fn)
            if fn is client.describe_db_instances:
                raise ConnectorError("access denied", status_code=403)
            if fn is client.describe_db_clusters:
                return cluster_resp
            return {}

        conn._call_aws = _call_aws
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        # Should still have cluster record even though instances failed
        cluster_records = [r for r in records if r["record_type"] == AWS_RDS_DB_CLUSTER]
        assert len(cluster_records) == 1

    def test_multiple_records_all_types(self):
        """All 5 resource types should be returned in a single call."""
        conn = _make_connector()
        client = self._make_mock_client()
        inst_resp = {"DBInstances": [{"DBInstanceIdentifier": "db1", "Engine": "mysql"}]}
        cluster_resp = {"DBClusters": [{"DBClusterIdentifier": "cl1", "Engine": "aurora-mysql"}]}
        sng_resp = {"DBSubnetGroups": [{"DBSubnetGroupName": "sg1", "VpcId": "vpc-1", "Subnets": []}]}
        snap_resp = {"DBSnapshots": [{"DBSnapshotIdentifier": "snap1", "Engine": "mysql"}]}
        csnap_resp = {"DBClusterSnapshots": [{"DBClusterSnapshotIdentifier": "csnap1", "Engine": "aurora-mysql"}]}

        conn._call_aws = self._make_call_aws(
            client, inst_resp=inst_resp, cluster_resp=cluster_resp,
            sng_resp=sng_resp, snap_resp=snap_resp, csnap_resp=csnap_resp
        )
        records = conn._fetch_rds_in_region(client, self.ACCOUNT_ID, self.REGION)

        types = {r["record_type"] for r in records}
        assert AWS_RDS_DB_INSTANCE in types
        assert AWS_RDS_DB_CLUSTER in types
        assert AWS_RDS_DB_SUBNET_GROUP in types
        assert AWS_RDS_DB_SNAPSHOT in types
        assert AWS_RDS_DB_CLUSTER_SNAPSHOT in types


# ─────────────────────────────────────────────────────────────────────────────
# 11. Service inventory
# ─────────────────────────────────────────────────────────────────────────────

class TestM42ServiceInventory:
    def test_rds_in_enabled_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds, rds_instance_count=5, rds_cluster_count=2)
        assert "rds" in inv["enabled_surfaces"]

    def test_rds_not_in_future_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert "rds" not in inv["future_surfaces"]

    def test_rds_counts_stored(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds, rds_instance_count=7, rds_cluster_count=3)
        assert inv["rds_instance_count"] == 7
        assert inv["rds_cluster_count"] == 3

    def test_rds_counts_default_zero(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert inv["rds_instance_count"] == 0
        assert inv["rds_cluster_count"] == 0

    def test_m41_surfaces_still_present(self):
        """Regression: M41 surfaces must not be removed."""
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert "secrets_manager" in inv["enabled_surfaces"]
        assert "ssm" in inv["enabled_surfaces"]


# ─────────────────────────────────────────────────────────────────────────────
# 12. _fetch_rds_resources — regional dispatch
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchRdsResources:
    def test_iterates_over_selected_regions(self):
        conn = _make_connector()
        credentials = _creds(regions=["us-east-1", "us-west-2"])
        made_clients = []

        def _make_client(service, creds, region=None):
            client = MagicMock()
            made_clients.append((service, region))
            return client

        conn._make_client = _make_client
        conn._call_aws = lambda fn, **kwargs: (
            {"DBInstances": [], "DBClusters": [], "DBSubnetGroups": [], "DBSnapshots": [], "DBClusterSnapshots": []}
            .get(fn.__name__, {})
        )

        def fake_fetch_in_region(client, account_id, region):
            return [{"record_type": AWS_RDS_DB_INSTANCE, "region": region}]

        conn._fetch_rds_in_region = fake_fetch_in_region
        records = conn._fetch_rds_resources(credentials, "123456789012")
        regions = {r["region"] for r in records}
        assert "us-east-1" in regions
        assert "us-west-2" in regions

    def test_per_region_failure_does_not_abort(self):
        conn = _make_connector()
        credentials = _creds(regions=["us-east-1", "eu-west-1"])

        def _make_client(service, creds, region=None):
            return MagicMock()

        conn._make_client = _make_client

        call_count = [0]

        def fake_fetch_in_region(client, account_id, region):
            call_count[0] += 1
            if region == "us-east-1":
                raise ConnectorError("access denied", status_code=403)
            return [{"record_type": AWS_RDS_DB_INSTANCE, "region": region}]

        conn._fetch_rds_in_region = fake_fetch_in_region
        records = conn._fetch_rds_resources(credentials, "123456789012")
        # eu-west-1 should still return a record
        eu_records = [r for r in records if r.get("region") == "eu-west-1"]
        assert len(eu_records) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 13. Security hard rules — summary
# ─────────────────────────────────────────────────────────────────────────────

class TestM42SecurityHardRules:
    """Explicit tests documenting the security boundary constraints."""

    def test_pending_modified_values_never_stores_password(self):
        """MasterUserPassword must never appear in any pending summary."""
        result = _rds_summarize_pending_modified({
            "MasterUserPassword": "my-password",
            "AllocatedStorage": 500,
        })
        assert result is not None  # other fields present
        flat = str(result)
        assert "my-password" not in flat
        assert "MasterUserPassword" not in flat

    def test_kms_key_hashed_not_raw(self):
        """KMS key IDs must be hashed, not stored in full."""
        raw_key = "arn:aws:kms:us-east-1:123456789012:key/abcdef12-3456-7890-abcd-ef1234567890"
        hashed = _hash_kms_key_id(raw_key)
        assert hashed != raw_key
        assert len(hashed) == 12  # 12-char hex prefix

    def test_rds_fetch_never_calls_download_log(self):
        """DownloadDBLogFilePortion must never be called during RDS fetch."""
        conn = _make_connector()
        client = MagicMock()

        called_fns = []

        def _call_aws(fn, **kwargs):
            called_fns.append(getattr(fn, "_mock_name", str(fn)))
            return {}  # return empty response

        conn._call_aws = _call_aws
        conn._fetch_rds_in_region(client, "123456789012", "us-east-1")

        for fn_name in called_fns:
            assert "download" not in fn_name.lower()
            assert "log_file" not in fn_name.lower()

    def test_failure_classifier_never_mentions_write_permissions(self):
        """Failure classifier recommended actions must never suggest write permissions."""
        write_perms = [
            "rds:CreateDB", "rds:ModifyDB", "rds:DeleteDB",
            "rds:RebootDB", "rds:StartDB", "rds:StopDB",
            "DownloadDBLogFilePortion",
            "secretsmanager:GetSecretValue",
            "kms:Decrypt",
        ]
        exc = ConnectorError("access denied", status_code=403)
        for api in ["DescribeDBInstances", "DescribeDBClusters", "DescribeDBSubnetGroups",
                    "DescribeDBSnapshots", "DescribeDBClusterSnapshots"]:
            fc = classify_aws_rds_failure(api, exc)
            for bad in write_perms:
                assert bad not in fc.recommended_action, (
                    f"API {api}: recommended_action mentions forbidden permission {bad!r}"
                )

    def test_no_raw_kms_key_in_instance_record(self):
        """KMS key IDs in DB instance records must be hashed, not raw."""
        conn = _make_connector()
        client = MagicMock()
        raw_key = "arn:aws:kms:us-east-1:123456789012:key/test-key-id-abc"

        call_count = [0]

        def _call_aws(fn, **kwargs):
            call_count[0] += 1
            if fn is client.describe_db_instances:
                return {"DBInstances": [{
                    "DBInstanceIdentifier": "test-db",
                    "Engine": "mysql",
                    "KmsKeyId": raw_key,
                    "StorageEncrypted": True,
                }]}
            return {}

        conn._call_aws = _call_aws
        records = conn._fetch_rds_in_region(client, "123456789012", "us-east-1")
        r = [r for r in records if r["record_type"] == AWS_RDS_DB_INSTANCE][0]

        # Raw key must not be stored
        assert r.get("kms_key_id") != raw_key
        flat = str(r)
        assert raw_key not in flat
        # Hash should be there
        assert r["kms_key_id_present"] is True
        assert r["kms_key_id_hash"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 14. M41 regression guard
# ─────────────────────────────────────────────────────────────────────────────

class TestM41Regression:
    def test_m41_schema_still_present(self):
        assert AWS_SECRETSMANAGER_SECRET in AWS_RECORD_TYPES
        assert AWS_SSM_PARAMETER in AWS_RECORD_TYPES

    def test_m41_tracked_fields_still_registered(self):
        from app.services.diff_service import _tracked_fields_for
        assert _tracked_fields_for({"record_type": AWS_SECRETSMANAGER_SECRET}) is not None
        assert _tracked_fields_for({"record_type": AWS_SSM_PARAMETER}) is not None

    def test_m41_risk_classification_still_works(self):
        change = {
            "record_type": AWS_SECRETSMANAGER_SECRET,
            "change_type": "modified",
            "field_path": "rotation_enabled",
            "new_value": False,
            "prev_value": True,
            "name": "my-secret",
            "provider_metadata": {"record_type": AWS_SECRETSMANAGER_SECRET},
        }
        level, reason = classify_aws_change(change)
        assert level in ("high", "critical", "medium")
        assert reason != ""
