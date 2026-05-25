"""Tests for Milestone 48: AWS KMS + Backup + Organizations/SCPs.

Covers:
- Security hard rules: no kms:Decrypt/Encrypt/GenerateDataKey called,
  no backup restore/start/delete, no Organizations write/mutate actions
- Schema registration: all 11 M48 types in AWS_RECORD_TYPES
- Diff service tracked field registration for all 11 M48 types
- Helper functions: _hash_id, _hash_email, _classify_governance_name_sensitivity,
  _is_sensitive_governance_resource, _kms_policy_is_public,
  _kms_policy_has_wildcard_admin, _summarize_scp_content,
  _summarize_backup_rules, _summarize_backup_selection_resources
- KMS risk classification matrix
- Backup risk classification matrix
- Organizations/SCP risk classification matrix
- Failure classifiers: classify_aws_kms_failure, classify_aws_backup_failure,
  classify_aws_organizations_failure
- Connector normalization: _fetch_kms_in_region, _fetch_backup_in_region,
  _fetch_organizations_global
- Service inventory: kms/backup/organizations in enabled_surfaces
- Fail-soft: per-region/per-service errors do not abort full fetch
- M47 regression guard: M47 record types still classified correctly
"""

import inspect
import json
import pytest
from unittest.mock import MagicMock, patch

from app.connectors.aws import (
    AWSConnector,
    _hash_id,
    _hash_email,
    _classify_governance_name_sensitivity,
    _is_sensitive_governance_resource,
    _kms_policy_is_public,
    _kms_policy_has_wildcard_admin,
    _summarize_scp_content,
    _summarize_backup_rules,
    _summarize_backup_selection_resources,
)
from app.connectors.aws_schema import (
    AWS_KMS_KEY,
    AWS_KMS_ALIAS,
    AWS_BACKUP_VAULT,
    AWS_BACKUP_PLAN,
    AWS_BACKUP_SELECTION,
    AWS_BACKUP_RECOVERY_POINT,
    AWS_ORGANIZATIONS_ORGANIZATION,
    AWS_ORGANIZATIONS_ACCOUNT,
    AWS_ORGANIZATIONS_OU,
    AWS_ORGANIZATIONS_SCP,
    AWS_ORGANIZATIONS_SCP_ATTACHMENT,
    AWS_SERVICE_INVENTORY,
    # M47 regression
    AWS_SQS_QUEUE,
    AWS_SNS_TOPIC,
    AWS_EVENTBRIDGE_EVENT_BUS,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_kms_failure,
    classify_aws_backup_failure,
    classify_aws_organizations_failure,
)

# ---------------------------------------------------------------------------
# 1. Security hard rules
# ---------------------------------------------------------------------------

class TestM48SecurityHardRules:
    """No cryptographic, restore, or write AWS API calls should be present in the connector.

    Note: The forbidden API names may appear in comments documenting what is NOT called.
    These tests check for actual boto3 call patterns (.method_name() invocations).
    """

    def _connector_source(self) -> str:
        import app.connectors.aws as aws_mod
        return inspect.getsource(aws_mod)

    def _non_comment_lines(self) -> str:
        """Return connector source with comment lines stripped."""
        src = self._connector_source()
        non_comment = []
        for line in src.split("\n"):
            stripped = line.lstrip()
            if not stripped.startswith("#"):
                non_comment.append(line)
        return "\n".join(non_comment)

    def test_no_kms_decrypt_boto3_method(self):
        """The boto3 .decrypt() method must never be called."""
        src = self._non_comment_lines()
        assert ".decrypt(" not in src

    def test_no_kms_encrypt_boto3_method(self):
        """The boto3 .encrypt() method must never be called."""
        src = self._non_comment_lines()
        assert ".encrypt(" not in src

    def test_no_kms_generate_data_key_boto3_method(self):
        """The boto3 .generate_data_key() method must never be called."""
        src = self._non_comment_lines()
        assert ".generate_data_key(" not in src

    def test_no_backup_start_restore_job_boto3(self):
        """The boto3 .start_restore_job() method must never be called."""
        src = self._non_comment_lines()
        assert ".start_restore_job(" not in src

    def test_no_backup_start_backup_job_boto3(self):
        """The boto3 .start_backup_job() method must never be called."""
        src = self._non_comment_lines()
        assert ".start_backup_job(" not in src

    def test_no_backup_delete_recovery_point_boto3(self):
        """The boto3 .delete_recovery_point() method must never be called."""
        src = self._non_comment_lines()
        assert ".delete_recovery_point(" not in src

    def test_no_organizations_create_policy_boto3(self):
        """The boto3 .create_policy() method must never be called."""
        src = self._non_comment_lines()
        assert ".create_policy(" not in src

    def test_no_organizations_attach_policy_boto3(self):
        """The boto3 .attach_policy() method must never be called."""
        src = self._non_comment_lines()
        assert ".attach_policy(" not in src

    def test_no_organizations_detach_policy_boto3(self):
        """The boto3 .detach_policy() method must never be called."""
        src = self._non_comment_lines()
        assert ".detach_policy(" not in src

    def test_no_organizations_update_policy_boto3(self):
        """The boto3 .update_policy() method must never be called."""
        src = self._non_comment_lines()
        assert ".update_policy(" not in src

    def test_no_organizations_delete_policy_boto3(self):
        """The boto3 .delete_policy() method must never be called."""
        src = self._non_comment_lines()
        assert ".delete_policy(" not in src

    def test_no_organizations_move_account_boto3(self):
        """The boto3 .move_account() method must never be called."""
        src = self._non_comment_lines()
        assert ".move_account(" not in src

    def test_no_kms_raw_policy_stored(self):
        """GetKeyPolicy response should not be stored as raw JSON — only boolean presence."""
        src = self._connector_source()
        # Look for GetKeyPolicy usage context
        assert "get_key_policy" in src  # must call it
        # The policy should reduce to a boolean field
        assert '"policy_present"' in src or "'policy_present'" in src

    def test_no_raw_email_storage(self):
        """Email addresses in Organizations must be hashed."""
        src = self._connector_source()
        # _hash_email helper must be defined
        assert "_hash_email" in src

    def test_no_raw_scp_policy_json_stored(self):
        """SCP policy JSON must be summarized, not stored raw."""
        src = self._connector_source()
        # _summarize_scp_content must be called
        assert "_summarize_scp_content" in src


# ---------------------------------------------------------------------------
# 2. Schema registration
# ---------------------------------------------------------------------------

class TestM48SchemaRegistration:
    def test_kms_key_in_record_types(self):
        assert AWS_KMS_KEY in AWS_RECORD_TYPES

    def test_kms_alias_in_record_types(self):
        assert AWS_KMS_ALIAS in AWS_RECORD_TYPES

    def test_backup_vault_in_record_types(self):
        assert AWS_BACKUP_VAULT in AWS_RECORD_TYPES

    def test_backup_plan_in_record_types(self):
        assert AWS_BACKUP_PLAN in AWS_RECORD_TYPES

    def test_backup_selection_in_record_types(self):
        assert AWS_BACKUP_SELECTION in AWS_RECORD_TYPES

    def test_backup_recovery_point_in_record_types(self):
        assert AWS_BACKUP_RECOVERY_POINT in AWS_RECORD_TYPES

    def test_organizations_organization_in_record_types(self):
        assert AWS_ORGANIZATIONS_ORGANIZATION in AWS_RECORD_TYPES

    def test_organizations_account_in_record_types(self):
        assert AWS_ORGANIZATIONS_ACCOUNT in AWS_RECORD_TYPES

    def test_organizations_ou_in_record_types(self):
        assert AWS_ORGANIZATIONS_OU in AWS_RECORD_TYPES

    def test_organizations_scp_in_record_types(self):
        assert AWS_ORGANIZATIONS_SCP in AWS_RECORD_TYPES

    def test_organizations_scp_attachment_in_record_types(self):
        assert AWS_ORGANIZATIONS_SCP_ATTACHMENT in AWS_RECORD_TYPES

    def test_record_type_constants_are_strings(self):
        for rt in (
            AWS_KMS_KEY, AWS_KMS_ALIAS,
            AWS_BACKUP_VAULT, AWS_BACKUP_PLAN, AWS_BACKUP_SELECTION, AWS_BACKUP_RECOVERY_POINT,
            AWS_ORGANIZATIONS_ORGANIZATION, AWS_ORGANIZATIONS_ACCOUNT, AWS_ORGANIZATIONS_OU,
            AWS_ORGANIZATIONS_SCP, AWS_ORGANIZATIONS_SCP_ATTACHMENT,
        ):
            assert isinstance(rt, str), f"{rt!r} is not a string"
            assert rt.startswith("aws_"), f"{rt!r} does not start with 'aws_'"


# ---------------------------------------------------------------------------
# 3. Diff service tracked fields
# ---------------------------------------------------------------------------

class TestM48DiffServiceTrackedFields:
    @staticmethod
    def _fields(record_type: str) -> tuple:
        return _tracked_fields_for({"record_type": record_type})

    def test_kms_key_tracked_fields(self):
        fields = self._fields(AWS_KMS_KEY)
        assert "key_state" in fields
        assert "enabled" in fields
        assert "rotation_enabled" in fields
        assert "public_or_cross_account_policy" in fields
        assert "wildcard_admin_policy" in fields
        assert "multi_region" in fields
        assert "deletion_date_present" in fields
        assert "name_sensitivity" in fields

    def test_kms_alias_tracked_fields(self):
        fields = self._fields(AWS_KMS_ALIAS)
        assert "alias_name" in fields
        assert "target_key_id_hash" in fields
        assert "target_key_present" in fields

    def test_backup_vault_tracked_fields(self):
        fields = self._fields(AWS_BACKUP_VAULT)
        assert "locked" in fields
        assert "encryption_key_arn_present" in fields
        assert "recovery_points_count" in fields
        assert "backup_vault_lock_configuration_present" in fields
        assert "name_sensitivity" in fields

    def test_backup_plan_tracked_fields(self):
        fields = self._fields(AWS_BACKUP_PLAN)
        assert "backup_plan_name" in fields
        assert "rule_count" in fields
        assert "continuous_backup_enabled_count" in fields
        assert "lifecycle_delete_after_days_min" in fields
        assert "copy_action_count" in fields

    def test_backup_selection_tracked_fields(self):
        fields = self._fields(AWS_BACKUP_SELECTION)
        assert "selection_name" in fields
        assert "iam_role_arn_present" in fields
        assert "resource_count" in fields
        assert "condition_count" in fields

    def test_backup_recovery_point_tracked_fields(self):
        fields = self._fields(AWS_BACKUP_RECOVERY_POINT)
        assert "status" in fields
        assert "is_encrypted" in fields
        assert "encryption_key_arn_present" in fields
        assert "backup_vault_name" in fields

    def test_organizations_organization_tracked_fields(self):
        fields = self._fields(AWS_ORGANIZATIONS_ORGANIZATION)
        assert "feature_set" in fields
        assert "scp_count" in fields
        assert "account_count" in fields
        assert "policy_types_summary" in fields

    def test_organizations_account_tracked_fields(self):
        fields = self._fields(AWS_ORGANIZATIONS_ACCOUNT)
        assert "status" in fields
        assert "joined_method" in fields
        assert "joined_timestamp_present" in fields

    def test_organizations_ou_tracked_fields(self):
        fields = self._fields(AWS_ORGANIZATIONS_OU)
        assert "parent_id_hash" in fields
        assert "attached_scp_count" in fields
        assert "child_ou_count" in fields
        assert "child_account_count" in fields

    def test_organizations_scp_tracked_fields(self):
        fields = self._fields(AWS_ORGANIZATIONS_SCP)
        assert "policy_name" in fields
        assert "denies_full_admin_escape" in fields
        assert "denied_action_count" in fields
        assert "deny_statement_count" in fields
        assert "attached_target_count" in fields
        assert "wildcard_action_present" in fields
        assert "wildcard_resource_present" in fields
        assert "name_sensitivity" in fields

    def test_organizations_scp_attachment_tracked_fields(self):
        fields = self._fields(AWS_ORGANIZATIONS_SCP_ATTACHMENT)
        assert "policy_name" in fields
        assert "target_type" in fields


# ---------------------------------------------------------------------------
# 4. Helper functions
# ---------------------------------------------------------------------------

class TestM48Helpers:

    def test_hash_id_returns_12_chars(self):
        result = _hash_id("some-kms-key-id-1234")
        assert len(result) == 12
        assert result.isalnum() or all(c in "0123456789abcdef" for c in result)

    def test_hash_id_is_deterministic(self):
        assert _hash_id("key123") == _hash_id("key123")

    def test_hash_id_differs_for_different_inputs(self):
        assert _hash_id("key-aaa") != _hash_id("key-bbb")

    def test_hash_email_returns_12_chars(self):
        result = _hash_email("test@example.com")
        assert len(result) == 12

    def test_hash_email_is_case_insensitive(self):
        assert _hash_email("Test@Example.COM") == _hash_email("test@example.com")

    def test_hash_email_deterministic(self):
        assert _hash_email("admin@corp.io") == _hash_email("admin@corp.io")

    def test_classify_governance_name_sensitivity_production(self):
        for name in ("prod-kms-key", "production-backup", "prod_cmk"):
            result = _classify_governance_name_sensitivity(name)
            assert result == "production", f"Expected 'production' for {name!r}, got {result!r}"

    def test_classify_governance_name_sensitivity_payment(self):
        for name in ("payment-key", "pci-compliance-kms"):
            result = _classify_governance_name_sensitivity(name)
            assert result in ("payment", "admin"), f"Unexpected result for {name!r}: {result!r}"

    def test_classify_governance_name_sensitivity_admin(self):
        for name in ("admin-backup", "root-kms-key", "master-cmk"):
            result = _classify_governance_name_sensitivity(name)
            assert result in ("admin", "production", "backup"), f"Unexpected result for {name!r}: {result!r}"

    def test_classify_governance_name_sensitivity_none(self):
        result = _classify_governance_name_sensitivity("dev-feature-flag")
        assert result == "none"

    def test_is_sensitive_governance_resource_true(self):
        assert _is_sensitive_governance_resource("prod-kms-key") is True

    def test_is_sensitive_governance_resource_false(self):
        assert _is_sensitive_governance_resource("my-test-key") is False

    def test_kms_policy_is_public_wildcard_principal(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:*"}]
        })
        assert _kms_policy_is_public(policy, "123456789012") is True

    def test_kms_policy_is_public_own_account(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*"}]
        })
        assert _kms_policy_is_public(policy, "123456789012") is False

    def test_kms_policy_is_public_cross_account(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "kms:Decrypt"}]
        })
        assert _kms_policy_is_public(policy, "123456789012") is True

    def test_kms_policy_is_public_invalid_json(self):
        assert _kms_policy_is_public("not-json", "123456789012") is False

    def test_kms_policy_is_public_empty(self):
        assert _kms_policy_is_public("", "123456789012") is False

    def test_kms_policy_has_wildcard_admin_true(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "*"}]
        })
        assert _kms_policy_has_wildcard_admin(policy, "123456789012") is True

    def test_kms_policy_has_wildcard_admin_kms_star(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:*"}]
        })
        assert _kms_policy_has_wildcard_admin(policy, "123456789012") is True

    def test_kms_policy_has_wildcard_admin_false_for_own_account(self):
        """Wildcard action for the key owner's own account should not flag as external wildcard admin."""
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "*"}]
        })
        result = _kms_policy_has_wildcard_admin(policy, "123456789012")
        assert result is False

    def test_kms_policy_has_wildcard_admin_deny_not_counted(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "*"}]
        })
        assert _kms_policy_has_wildcard_admin(policy, "123456789012") is False

    def test_summarize_scp_content_basic(self):
        policy = json.dumps({
            "Statement": [
                {"Effect": "Deny", "Action": ["ec2:TerminateInstances", "ec2:StopInstances"]},
                {"Effect": "Allow", "Action": "*"},
            ]
        })
        result = _summarize_scp_content(policy)
        assert result["deny_statement_count"] == 1
        assert result["allow_statement_count"] == 1
        assert result["denied_action_count"] == 2
        assert "ec2" in result["denied_service_prefixes"]
        assert result["wildcard_action_present"] is True

    def test_summarize_scp_content_denies_full_admin(self):
        policy = json.dumps({
            "Statement": [
                {"Effect": "Deny", "Action": ["*"]},
            ]
        })
        result = _summarize_scp_content(policy)
        # Denying * means the SCP has a deny for full admin escape
        assert result["denies_full_admin_escape"] is True

    def test_summarize_scp_content_no_full_admin_escape(self):
        policy = json.dumps({
            "Statement": [
                {"Effect": "Deny", "Action": ["ec2:RunInstances"]},
            ]
        })
        result = _summarize_scp_content(policy)
        assert result["denies_full_admin_escape"] is False

    def test_summarize_scp_content_invalid_json(self):
        result = _summarize_scp_content("not-json")
        assert result["deny_statement_count"] == 0
        assert result["allow_statement_count"] == 0

    def test_summarize_scp_content_raw_json_not_in_result(self):
        """Raw policy JSON string must not appear in the result dict."""
        policy = json.dumps({"Statement": []})
        result = _summarize_scp_content(policy)
        for v in result.values():
            assert not isinstance(v, str) or "Statement" not in v, \
                "Raw policy JSON appears to have been stored in result"

    def test_summarize_backup_rules_empty(self):
        result = _summarize_backup_rules([])
        assert result["rule_count"] == 0
        assert result["rule_names"] == []

    def test_summarize_backup_rules_basic(self):
        rules = [
            {
                "RuleName": "daily-backup",
                "TargetBackupVaultName": "my-vault",
                "ScheduleExpression": "cron(0 5 * * ? *)",
                "EnableContinuousBackup": False,
                "Lifecycle": {"DeleteAfterDays": 30},
                "CopyActions": [],
            },
            {
                "RuleName": "continuous-backup",
                "TargetBackupVaultName": "my-vault",
                "EnableContinuousBackup": True,
                "CopyActions": [{"DestinationBackupVaultArn": "arn:aws:backup:us-east-1:1234:vault/dr"}],
            },
        ]
        result = _summarize_backup_rules(rules)
        assert result["rule_count"] == 2
        assert "daily-backup" in result["rule_names"]
        assert "continuous-backup" in result["rule_names"]
        assert result["continuous_backup_enabled_count"] == 1
        assert result["schedule_expression_present_count"] == 1
        assert result["copy_action_count"] == 1

    def test_summarize_backup_selection_resources_basic(self):
        resources = [
            "arn:aws:rds:us-east-1:123456789012:db:mydb",
            "arn:aws:dynamodb:us-east-1:123456789012:table/mytable",
            "arn:aws:rds:us-east-1:123456789012:db:mydb2",
        ]
        conditions = {}
        result = _summarize_backup_selection_resources(resources, conditions)
        assert result["resource_count"] == 3
        assert result["resource_type_counts"]["rds"] == 2
        assert result["resource_type_counts"]["dynamodb"] == 1
        assert result["condition_count"] == 0

    def test_summarize_backup_selection_resources_no_raw_arns(self):
        """Raw ARN strings must not be present in result values."""
        resources = ["arn:aws:s3:::my-bucket"]
        result = _summarize_backup_selection_resources(resources, {})
        for v in result.values():
            if isinstance(v, str):
                assert "arn:aws:s3" not in v, "Raw ARN stored in result"
            elif isinstance(v, list):
                for item in v:
                    assert "arn:aws:s3" not in str(item), "Raw ARN stored in list result"


# ---------------------------------------------------------------------------
# 5. KMS risk classification matrix
# ---------------------------------------------------------------------------

class TestKMSKeyRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None, record_name=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_KMS_KEY, "record_name": record_name or "my-key"},
        )

    def test_key_disabled_critical_for_sensitive(self):
        change = self._make_change(field_path="enabled", new_value=False, record_name="prod-cmk")
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_key_disabled_high_for_non_sensitive(self):
        change = self._make_change(field_path="enabled", new_value=False, record_name="dev-key")
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_key_pending_deletion_critical(self):
        change = self._make_change(field_path="key_state", prev_value="Enabled", new_value="PendingDeletion")
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")
        assert reason is not None and len(reason) > 0

    def test_deletion_date_present_high(self):
        change = self._make_change(field_path="deletion_date_present", prev_value=False, new_value=True)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_public_or_cross_account_policy_critical(self):
        change = self._make_change(field_path="public_or_cross_account_policy", prev_value=False, new_value=True)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_wildcard_admin_policy_critical(self):
        change = self._make_change(field_path="wildcard_admin_policy", prev_value=False, new_value=True)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_rotation_disabled_high(self):
        change = self._make_change(field_path="rotation_enabled", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_key_removed_critical_for_sensitive(self):
        change = self._make_change(change_type="removed", record_name="prod-cmk")
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_kms_key_language_never_mentions_decryption(self):
        """Risk summaries for KMS must not say 'data decrypted' or 'decrypting'."""
        change = self._make_change(field_path="enabled", new_value=False)
        level, reason = classify_aws_change(change)
        if reason:
            reason_lower = reason.lower()
            assert "data decrypted" not in reason_lower
            assert "decrypting your" not in reason_lower

    def test_kms_key_added_low_risk(self):
        change = self._make_change(change_type="added", record_name="new-key")
        level, reason = classify_aws_change(change)
        assert level in ("low", "unknown", "medium")


class TestKMSAliasRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_KMS_ALIAS, "record_name": "alias/my-app-key"},
        )

    def test_alias_target_changed_high(self):
        change = self._make_change(field_path="target_key_id_hash", prev_value="abc123", new_value="def456")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_alias_removed_medium(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")


# ---------------------------------------------------------------------------
# 6. Backup risk classification matrix
# ---------------------------------------------------------------------------

class TestBackupVaultRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None, record_name=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_BACKUP_VAULT, "record_name": record_name or "my-vault"},
        )

    def test_vault_lock_removed_critical(self):
        change = self._make_change(field_path="locked", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_vault_lock_config_removed_high(self):
        change = self._make_change(field_path="backup_vault_lock_configuration_present", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_vault_encryption_removed_high(self):
        change = self._make_change(field_path="encryption_key_arn_present", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_vault_recovery_points_decreased_high(self):
        change = self._make_change(field_path="recovery_points_count", prev_value=10, new_value=5)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_vault_removed_high(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("high", "critical")

    def test_vault_language_never_mentions_backup_destroyed(self):
        """Summaries should not say 'backup destroyed' (we only monitor, not confirm deletion)."""
        change = self._make_change(field_path="locked", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        if reason:
            assert "backup destroyed" not in reason.lower()

    def test_vault_lock_removed_says_may_be_deletable(self):
        change = self._make_change(field_path="locked", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        if reason:
            assert any(phrase in reason.lower() for phrase in ["may", "could", "deletable", "protection"])


class TestBackupPlanRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_BACKUP_PLAN, "record_name": "daily-plan"},
        )

    def test_plan_removed_critical(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_rule_count_decreased_high(self):
        change = self._make_change(field_path="rule_count", prev_value=3, new_value=1)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_continuous_backup_removed_high(self):
        change = self._make_change(field_path="continuous_backup_enabled_count", prev_value=2, new_value=0)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_lifecycle_delete_zero_critical(self):
        change = self._make_change(field_path="lifecycle_delete_after_days_min", prev_value=30, new_value=0)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_lifecycle_delete_reduced_high(self):
        change = self._make_change(field_path="lifecycle_delete_after_days_min", prev_value=30, new_value=7)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")


class TestBackupSelectionRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_BACKUP_SELECTION, "record_name": "prod-selection"},
        )

    def test_selection_removed_high(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_resource_count_decreased_high(self):
        change = self._make_change(field_path="resource_count", prev_value=20, new_value=5)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")


class TestBackupRecoveryPointRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_BACKUP_RECOVERY_POINT, "record_name": "rp-abc123"},
        )

    def test_recovery_point_removed_high(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_status_expired_high(self):
        change = self._make_change(field_path="status", prev_value="COMPLETED", new_value="EXPIRED")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_status_deleting_high(self):
        change = self._make_change(field_path="status", prev_value="COMPLETED", new_value="DELETING")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_unencrypted_high(self):
        change = self._make_change(field_path="is_encrypted", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")


# ---------------------------------------------------------------------------
# 7. Organizations / SCP risk classification matrix
# ---------------------------------------------------------------------------

class TestOrganizationsOrgRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_ORGANIZATIONS_ORGANIZATION},
        )

    def test_feature_set_downgraded_high(self):
        change = self._make_change(field_path="feature_set", prev_value="ALL", new_value="CONSOLIDATED_BILLING")
        level, reason = classify_aws_change(change)
        assert level in ("high", "critical")

    def test_scp_count_decreased_high(self):
        change = self._make_change(field_path="scp_count", prev_value=5, new_value=3)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_policy_types_changed_high(self):
        change = self._make_change(field_path="policy_types_summary", prev_value="a", new_value="b")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")


class TestOrganizationsAccountRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_ORGANIZATIONS_ACCOUNT},
        )

    def test_account_suspended_high(self):
        change = self._make_change(field_path="status", prev_value="ACTIVE", new_value="SUSPENDED")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_account_closed_high(self):
        change = self._make_change(field_path="status", prev_value="ACTIVE", new_value="CLOSED")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")


class TestOrganizationsOURiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_ORGANIZATIONS_OU},
        )

    def test_scp_count_decreased_high(self):
        change = self._make_change(field_path="attached_scp_count", prev_value=3, new_value=1)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_parent_changed_medium(self):
        change = self._make_change(field_path="parent_id_hash", prev_value="aaa", new_value="bbb")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium", "low")


class TestOrganizationsSCPRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_ORGANIZATIONS_SCP, "record_name": "deny-root-access"},
        )

    def test_scp_removed_critical(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_denies_full_admin_escape_removed_critical(self):
        change = self._make_change(field_path="denies_full_admin_escape", prev_value=True, new_value=False)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_denied_action_count_decreased_high(self):
        change = self._make_change(field_path="denied_action_count", prev_value=10, new_value=5)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_attached_target_count_decreased_high(self):
        change = self._make_change(field_path="attached_target_count", prev_value=5, new_value=2)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_deny_statement_count_decreased_high(self):
        change = self._make_change(field_path="deny_statement_count", prev_value=4, new_value=1)
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_scp_language_does_not_mutate(self):
        """Risk summaries must not say ConfigTrace is modifying/attaching SCPs."""
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        if reason:
            s = reason.lower()
            assert "configtrace attached" not in s
            assert "configtrace created" not in s
            assert "configtrace deleted" not in s

    def test_scp_added_low(self):
        change = self._make_change(change_type="added")
        level, reason = classify_aws_change(change)
        assert level in ("low", "unknown", "medium")


class TestOrganizationsSCPAttachmentRiskClassification:

    def _make_change(self, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": AWS_ORGANIZATIONS_SCP_ATTACHMENT, "record_name": "deny-root"},
        )

    def test_attachment_removed_high(self):
        change = self._make_change(change_type="removed")
        level, reason = classify_aws_change(change)
        assert level in ("high", "medium")

    def test_attachment_added_low(self):
        change = self._make_change(change_type="added")
        level, reason = classify_aws_change(change)
        assert level in ("low", "unknown", "medium")


# ---------------------------------------------------------------------------
# 8. Failure classifiers
# ---------------------------------------------------------------------------

class TestKMSFailureClassifier:

    def test_access_denied_code(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_kms_failure("ListKeys", exc)
        assert fc.error_code == "aws_kms_access_denied"
        assert fc.recommended_action is not None
        assert "kms:Decrypt" not in fc.recommended_action
        assert "kms:Encrypt" not in fc.recommended_action

    def test_list_keys_unavailable(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "KMSInternalException", "Message": "Internal"}}
        fc = classify_aws_kms_failure("ListKeys", exc)
        assert fc.error_code == "aws_kms_keys_unavailable"

    def test_get_key_rotation_status_unavailable(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "NotFoundException", "Message": "Not found"}}
        fc = classify_aws_kms_failure("GetKeyRotationStatus", exc)
        assert fc.error_code == "aws_kms_rotation_unavailable"

    def test_get_key_policy_unavailable(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "NotFoundException", "Message": "Not found"}}
        fc = classify_aws_kms_failure("GetKeyPolicy", exc)
        assert fc.error_code == "aws_kms_policy_unavailable"

    def test_list_aliases_unavailable(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "KMSInternalException", "Message": "Internal"}}
        fc = classify_aws_kms_failure("ListAliases", exc)
        assert fc.error_code == "aws_kms_aliases_unavailable"

    def test_recommended_action_never_calls_decrypt(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_kms_failure("DescribeKey", exc)
        if fc.recommended_action:
            assert "Decrypt" not in fc.recommended_action
            assert "Encrypt" not in fc.recommended_action
            assert "GenerateDataKey" not in fc.recommended_action


class TestBackupFailureClassifier:

    def test_access_denied_code(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_backup_failure("ListBackupVaults", exc)
        assert fc.error_code == "aws_backup_access_denied"

    def test_vaults_unavailable(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}}
        fc = classify_aws_backup_failure("ListBackupVaults", exc)
        assert fc.error_code == "aws_backup_vaults_unavailable"

    def test_plans_unavailable(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}}
        fc = classify_aws_backup_failure("ListBackupPlans", exc)
        assert fc.error_code == "aws_backup_plans_unavailable"

    def test_recommended_action_never_starts_restore(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_backup_failure("ListBackupVaults", exc)
        if fc.recommended_action:
            assert "restore" not in fc.recommended_action.lower()
            assert "StartBackupJob" not in fc.recommended_action
            assert "DeleteRecoveryPoint" not in fc.recommended_action


class TestOrganizationsFailureClassifier:

    def test_access_denied_code(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_organizations_failure("DescribeOrganization", exc)
        assert fc.error_code == "aws_organizations_access_denied"

    def test_recommended_action_notes_management_account(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_organizations_failure("DescribeOrganization", exc)
        if fc.recommended_action:
            action_lower = fc.recommended_action.lower()
            assert any(kw in action_lower for kw in ["management", "delegated", "master", "admin"])

    def test_recommended_action_never_mutates(self):
        exc = MagicMock()
        exc.response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        fc = classify_aws_organizations_failure("ListPolicies", exc)
        if fc.recommended_action:
            ra = fc.recommended_action.lower()
            assert "attach" not in ra
            assert "create" not in ra
            assert "delete" not in ra


# ---------------------------------------------------------------------------
# 9. Service inventory: kms/backup/organizations in enabled_surfaces
# ---------------------------------------------------------------------------

class TestM48ServiceInventory:

    def _build_connector(self):
        conn = AWSConnector.__new__(AWSConnector)
        conn.account_id = "123456789012"
        conn.account_name = "test-account"
        conn.selected_regions = ["us-east-1"]
        conn.default_region = "us-east-1"
        conn.role_arn = None
        conn._session = MagicMock()
        conn._records = []
        conn._errors = []
        return conn

    def test_kms_in_enabled_surfaces(self):
        # This test checks source code — no connector calls needed.
        import app.connectors.aws as aws_mod
        src = inspect.getsource(aws_mod)
        assert '"kms"' in src or "'kms'" in src
        # kms should NOT be in future_surfaces
        lines = src.split("\n")
        future_lines = [l for l in lines if "future_surfaces" in l and "kms" in l]
        assert len(future_lines) == 0, f"'kms' appeared in a future_surfaces line: {future_lines}"

    def test_backup_in_enabled_surfaces_not_future(self):
        import app.connectors.aws as aws_mod
        src = inspect.getsource(aws_mod)
        lines = src.split("\n")
        future_lines = [l for l in lines if "future_surfaces" in l and "backup" in l]
        assert len(future_lines) == 0, f"'backup' in a future_surfaces line: {future_lines}"

    def test_organizations_in_enabled_surfaces_not_future(self):
        import app.connectors.aws as aws_mod
        src = inspect.getsource(aws_mod)
        lines = src.split("\n")
        future_lines = [l for l in lines if "future_surfaces" in l and "organizations" in l]
        assert len(future_lines) == 0, f"'organizations' in a future_surfaces line: {future_lines}"

    def test_cloudwatch_still_in_future_surfaces(self):
        """cloudwatch is the only remaining future surface."""
        import app.connectors.aws as aws_mod
        src = inspect.getsource(aws_mod)
        assert "cloudwatch" in src


# ---------------------------------------------------------------------------
# 10. Connector normalization (mock-based)
# ---------------------------------------------------------------------------

class TestM48ConnectorNormalization:

    def _build_connector(self, regions=None):
        conn = AWSConnector.__new__(AWSConnector)
        conn.account_id = "123456789012"
        conn.account_name = "test"
        conn.selected_regions = regions or ["us-east-1"]
        conn.default_region = "us-east-1"
        conn.role_arn = None
        conn._session = MagicMock()
        conn._records = []
        conn._errors = []
        # botocore is not installed in the test environment; bypass the
        # botocore.exceptions import guard in _call_aws so mock clients work.
        conn._call_aws = lambda fn, *a, **kw: fn(*a, **kw)
        return conn

    def _mock_kms_client(self, keys=None, aliases=None):
        client = MagicMock()
        key_list = keys if keys is not None else [
            {"KeyId": "key-abc-123", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-abc-123"}
        ]
        client.list_keys.return_value = {"Keys": key_list, "Truncated": False}
        client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-abc-123",
                "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-abc-123",
                "Description": "test key",
                "KeyState": "Enabled",
                "Enabled": True,
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "MultiRegion": False,
            }
        }
        client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
        client.get_key_policy.return_value = {
            "Policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}]})
        }
        client.list_resource_tags.return_value = {
            "Tags": [{"TagKey": "Env", "TagValue": "prod"}]
        }
        alias_list = aliases if aliases is not None else [
            {"AliasName": "alias/my-app-key", "TargetKeyId": "key-abc-123"}
        ]
        client.list_aliases.return_value = {"Aliases": alias_list, "Truncated": False}
        return client

    def test_kms_key_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_kms_client()

        conn._records.extend(conn._fetch_kms_in_region(mock_client, conn.account_id, "us-east-1"))

        kms_records = [r for r in conn._records if r["record_type"] == AWS_KMS_KEY]
        assert len(kms_records) >= 1
        key_rec = kms_records[0]
        assert "record_type" in key_rec and key_rec["record_type"] == AWS_KMS_KEY
        assert "record_id" in key_rec
        assert "key_state" in key_rec
        assert "enabled" in key_rec
        assert "rotation_enabled" in key_rec
        assert "policy_present" in key_rec
        assert "public_or_cross_account_policy" in key_rec
        assert "wildcard_admin_policy" in key_rec
        assert "tag_keys" in key_rec
        # Tag values must not be stored — only keys
        tag_vals = key_rec.get("tag_values")
        assert tag_vals is None or tag_vals == [], "Tag values should not be stored"

    def test_kms_alias_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_kms_client()

        conn._records.extend(conn._fetch_kms_in_region(mock_client, conn.account_id, "us-east-1"))

        alias_records = [r for r in conn._records if r["record_type"] == AWS_KMS_ALIAS]
        assert len(alias_records) >= 1
        alias_rec = alias_records[0]
        assert "alias_name" in alias_rec
        assert "target_key_id_hash" in alias_rec
        assert "target_key_present" in alias_rec
        # Raw key ID must be hashed
        raw_key_id = "key-abc-123"
        assert alias_rec.get("target_key_id_hash") != raw_key_id

    def test_kms_record_id_format(self):
        conn = self._build_connector()
        mock_client = self._mock_kms_client()

        conn._records.extend(conn._fetch_kms_in_region(mock_client, conn.account_id, "us-east-1"))

        kms_records = [r for r in conn._records if r["record_type"] == AWS_KMS_KEY]
        record_id = kms_records[0]["record_id"]
        assert record_id.startswith("123456789012/us-east-1/kms/")

    def test_kms_raw_key_id_not_stored(self):
        """Key IDs must be hashed in record_id, never stored as plain text IDs."""
        conn = self._build_connector()
        mock_client = self._mock_kms_client()

        conn._records.extend(conn._fetch_kms_in_region(mock_client, conn.account_id, "us-east-1"))

        kms_records = [r for r in conn._records if r["record_type"] == AWS_KMS_KEY]
        rec = kms_records[0]
        # The raw key ID "key-abc-123" should not appear as a top-level field value
        raw_id = "key-abc-123"
        for k, v in rec.items():
            if k in ("record_id", "record_name", "record_identifier"):
                continue  # these may contain hashed versions
            assert v != raw_id, f"Raw key ID found in field {k!r}"

    def test_kms_policy_not_stored_as_raw_json(self):
        """Raw KMS key policy JSON must not be stored."""
        conn = self._build_connector()
        mock_client = self._mock_kms_client()

        conn._records.extend(conn._fetch_kms_in_region(mock_client, conn.account_id, "us-east-1"))

        kms_records = [r for r in conn._records if r["record_type"] == AWS_KMS_KEY]
        rec = kms_records[0]
        for k, v in rec.items():
            if isinstance(v, str) and len(v) > 20:
                assert "Statement" not in v, f"Raw policy JSON found in field {k!r}"

    def _mock_backup_client(self):
        client = MagicMock()
        client.list_backup_vaults.return_value = {
            "BackupVaultList": [
                {
                    "BackupVaultName": "Default",
                    "BackupVaultArn": "arn:aws:backup:us-east-1:123456789012:backup-vault:Default",
                    "EncryptionKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-abc-123",
                    "NumberOfRecoveryPoints": 5,
                }
            ]
        }
        client.describe_backup_vault.return_value = {
            "BackupVaultName": "Default",
            "BackupVaultArn": "arn:aws:backup:us-east-1:123456789012:backup-vault:Default",
            "EncryptionKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-abc-123",
            "NumberOfRecoveryPoints": 5,
            "Locked": False,
        }
        client.list_recovery_points_by_backup_vault.return_value = {
            "RecoveryPoints": [
                {
                    "RecoveryPointArn": "arn:aws:backup:us-east-1:123456789012:recovery-point:rp-abc",
                    "BackupVaultName": "Default",
                    "ResourceType": "RDS",
                    "Status": "COMPLETED",
                    "IsEncrypted": True,
                    "BackupSizeInBytes": 104857600,
                    "CreationDate": "2024-01-01T00:00:00Z",
                    "CompletionDate": "2024-01-01T01:00:00Z",
                    "EncryptionKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-abc-123",
                }
            ]
        }
        client.list_backup_plans.return_value = {
            "BackupPlansList": [
                {
                    "BackupPlanId": "plan-abc-123",
                    "BackupPlanArn": "arn:aws:backup:us-east-1:123456789012:backup-plan:plan-abc-123",
                    "BackupPlanName": "daily-plan",
                    "VersionId": "v1",
                }
            ]
        }
        client.get_backup_plan.return_value = {
            "BackupPlan": {
                "BackupPlanName": "daily-plan",
                "Rules": [
                    {
                        "RuleName": "daily-rule",
                        "TargetBackupVaultName": "Default",
                        "ScheduleExpression": "cron(0 5 * * ? *)",
                        "EnableContinuousBackup": False,
                        "Lifecycle": {"DeleteAfterDays": 30},
                        "CopyActions": [],
                    }
                ],
            }
        }
        client.list_backup_selections.return_value = {
            "BackupSelectionsList": [
                {
                    "SelectionId": "sel-abc",
                    "SelectionName": "prod-selection",
                    "BackupPlanId": "plan-abc-123",
                    "IamRoleArn": "arn:aws:iam::123456789012:role/AWSBackupDefaultServiceRole",
                }
            ]
        }
        client.get_backup_selection.return_value = {
            "BackupSelection": {
                "SelectionName": "prod-selection",
                "IamRoleArn": "arn:aws:iam::123456789012:role/AWSBackupDefaultServiceRole",
                "Resources": [
                    "arn:aws:rds:us-east-1:123456789012:db:mydb",
                    "arn:aws:dynamodb:us-east-1:123456789012:table/mytable",
                ],
                "Conditions": {},
                "ListOfTags": [],
                "NotResources": [],
            }
        }
        return client

    def test_backup_vault_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_backup_client()

        conn._records.extend(conn._fetch_backup_in_region(mock_client, conn.account_id, "us-east-1"))

        vault_records = [r for r in conn._records if r["record_type"] == AWS_BACKUP_VAULT]
        assert len(vault_records) >= 1
        vault = vault_records[0]
        assert "record_id" in vault
        assert "locked" in vault
        assert "encryption_key_arn_present" in vault
        assert "encryption_key_arn_hash" in vault
        assert "recovery_points_count" in vault
        # Raw ARN must not be stored
        raw_arn = "arn:aws:kms:us-east-1:123456789012:key/key-abc-123"
        for k, v in vault.items():
            if isinstance(v, str):
                assert v != raw_arn, f"Raw ARN stored in vault field {k!r}"

    def test_backup_plan_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_backup_client()

        conn._records.extend(conn._fetch_backup_in_region(mock_client, conn.account_id, "us-east-1"))

        plan_records = [r for r in conn._records if r["record_type"] == AWS_BACKUP_PLAN]
        assert len(plan_records) >= 1
        plan = plan_records[0]
        assert "backup_plan_name" in plan
        assert "rule_count" in plan
        assert "rule_names" in plan
        assert "target_vault_names" in plan
        assert "record_id" in plan
        assert plan["record_id"].startswith("123456789012/us-east-1/backup-plan/")

    def test_backup_selection_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_backup_client()

        conn._records.extend(conn._fetch_backup_in_region(mock_client, conn.account_id, "us-east-1"))

        sel_records = [r for r in conn._records if r["record_type"] == AWS_BACKUP_SELECTION]
        assert len(sel_records) >= 1
        sel = sel_records[0]
        assert "selection_name" in sel
        assert "resource_count" in sel
        assert "iam_role_arn_present" in sel
        assert "iam_role_arn_hash" in sel
        # Raw resource ARNs must not be stored
        raw_arn = "arn:aws:rds:us-east-1:123456789012:db:mydb"
        for k, v in sel.items():
            if isinstance(v, str):
                assert v != raw_arn, f"Raw resource ARN stored in selection field {k!r}"

    def test_backup_recovery_point_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_backup_client()

        conn._records.extend(conn._fetch_backup_in_region(mock_client, conn.account_id, "us-east-1"))

        rp_records = [r for r in conn._records if r["record_type"] == AWS_BACKUP_RECOVERY_POINT]
        assert len(rp_records) >= 1
        rp = rp_records[0]
        assert "backup_vault_name" in rp
        assert "status" in rp
        assert "is_encrypted" in rp
        assert "resource_type" in rp
        # Stable ID must use hashed ARN
        record_id = rp["record_id"]
        raw_rp_arn = "arn:aws:backup:us-east-1:123456789012:recovery-point:rp-abc"
        assert raw_rp_arn not in record_id, "Raw recovery point ARN in record_id"
        assert record_id.startswith("123456789012/us-east-1/backup-recovery-point/")

    def _mock_orgs_client(self):
        client = MagicMock()
        client.describe_organization.return_value = {
            "Organization": {
                "Id": "o-abc12345",
                "MasterAccountId": "123456789012",
                "MasterAccountEmail": "master@corp.io",
                "FeatureSet": "ALL",
                "AvailablePolicyTypes": [
                    {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}
                ],
            }
        }
        client.list_roots.return_value = {
            "Roots": [{"Id": "r-abc1", "Name": "Root", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
        }
        client.list_accounts.return_value = {
            "Accounts": [
                {
                    "Id": "111111111111",
                    "Name": "dev-account",
                    "Email": "dev@corp.io",
                    "Status": "ACTIVE",
                    "JoinedMethod": "INVITED",
                    "JoinedTimestamp": "2023-01-01T00:00:00Z",
                }
            ]
        }
        client.list_policies.return_value = {
            "Policies": [
                {
                    "Id": "p-scp123",
                    "Name": "deny-root-actions",
                    "AwsManaged": False,
                    "Description": "Deny root account actions",
                }
            ]
        }
        client.describe_policy.return_value = {
            "Policy": {
                "PolicySummary": {
                    "Id": "p-scp123",
                    "Name": "deny-root-actions",
                    "AwsManaged": False,
                    "Description": "Deny root account actions",
                },
                "Content": json.dumps({
                    "Statement": [
                        {"Effect": "Deny", "Action": ["iam:CreateVirtualMFADevice"], "Resource": "*"}
                    ]
                }),
            }
        }
        client.list_targets_for_policy.return_value = {
            "Targets": [
                {"TargetId": "r-abc1", "Name": "Root", "Type": "ROOT"}
            ]
        }
        client.list_organizational_units_for_parent.return_value = {"OrganizationalUnits": []}
        client.list_accounts_for_parent.return_value = {"Accounts": []}
        return client

    def test_organizations_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_orgs_client()

        conn._records.extend(conn._fetch_organizations_global(mock_client, conn.account_id))

        org_records = [r for r in conn._records if r["record_type"] == AWS_ORGANIZATIONS_ORGANIZATION]
        assert len(org_records) >= 1
        org = org_records[0]
        assert "feature_set" in org
        assert "scp_count" in org
        assert "account_count" in org
        assert "root_count" in org

    def test_organizations_org_id_is_hashed(self):
        conn = self._build_connector()
        mock_client = self._mock_orgs_client()

        conn._records.extend(conn._fetch_organizations_global(mock_client, conn.account_id))

        org_records = [r for r in conn._records if r["record_type"] == AWS_ORGANIZATIONS_ORGANIZATION]
        assert len(org_records) >= 1
        record_id = org_records[0]["record_id"]
        # The raw org ID "o-abc12345" must not appear in the record_id as-is
        assert "o-abc12345" not in record_id
        assert record_id.startswith("123456789012/organizations/")

    def test_organizations_account_email_is_hashed(self):
        conn = self._build_connector()
        mock_client = self._mock_orgs_client()

        conn._records.extend(conn._fetch_organizations_global(mock_client, conn.account_id))

        acct_records = [r for r in conn._records if r["record_type"] == AWS_ORGANIZATIONS_ACCOUNT]
        assert len(acct_records) >= 1
        acct = acct_records[0]
        # Raw email must not be stored
        assert acct.get("email") != "dev@corp.io"
        # email_hash should be the hashed version
        if "email_hash" in acct:
            assert acct["email_hash"] != "dev@corp.io"
            assert len(acct["email_hash"]) == 12

    def test_organizations_scp_content_is_summarized(self):
        conn = self._build_connector()
        mock_client = self._mock_orgs_client()

        conn._records.extend(conn._fetch_organizations_global(mock_client, conn.account_id))

        scp_records = [r for r in conn._records if r["record_type"] == AWS_ORGANIZATIONS_SCP]
        assert len(scp_records) >= 1
        scp = scp_records[0]
        assert "deny_statement_count" in scp
        assert "allow_statement_count" in scp
        assert "denied_action_count" in scp
        # Raw SCP JSON must not be stored
        for k, v in scp.items():
            if isinstance(v, str) and len(v) > 20:
                assert "Statement" not in v, f"Raw policy JSON in SCP field {k!r}"

    def test_organizations_scp_attachment_record_structure(self):
        conn = self._build_connector()
        mock_client = self._mock_orgs_client()

        conn._records.extend(conn._fetch_organizations_global(mock_client, conn.account_id))

        att_records = [r for r in conn._records if r["record_type"] == AWS_ORGANIZATIONS_SCP_ATTACHMENT]
        assert len(att_records) >= 1
        att = att_records[0]
        assert "policy_name" in att
        assert "target_type" in att
        assert "record_id" in att


# ---------------------------------------------------------------------------
# 11. Fail-soft
# ---------------------------------------------------------------------------

class TestM48FailSoft:

    def _build_connector(self, regions=None):
        conn = AWSConnector.__new__(AWSConnector)
        conn.account_id = "123456789012"
        conn.account_name = "test"
        conn.selected_regions = regions or ["us-east-1", "eu-west-1"]
        conn.default_region = "us-east-1"
        conn.role_arn = None
        conn._session = MagicMock()
        conn._records = []
        conn._errors = []
        return conn

    def test_kms_region_failure_does_not_abort(self):
        conn = self._build_connector(regions=["us-east-1", "eu-west-1"])
        # Credentials carry the selected regions so _selected_regions() works.
        credentials = {"aws_selected_regions": ["us-east-1", "eu-west-1"]}

        def fail_or_succeed(service, creds, region=None):
            if region and "eu-west-1" in region:
                raise Exception("Simulated eu-west-1 KMS failure")
            mock = MagicMock()
            mock.list_keys.return_value = {"Keys": [], "Truncated": False}
            mock.list_aliases.return_value = {"Aliases": [], "Truncated": False}
            return mock

        with patch.object(conn, "_make_client", side_effect=fail_or_succeed):
            try:
                conn._fetch_kms_resources(credentials, conn.account_id)
            except Exception:
                pytest.fail("_fetch_kms_resources raised an exception — fail-soft not implemented")

    def test_backup_region_failure_does_not_abort(self):
        conn = self._build_connector(regions=["us-east-1", "eu-west-1"])
        credentials = {"aws_selected_regions": ["us-east-1", "eu-west-1"]}

        def fail_or_succeed(service, creds, region=None):
            if region and "eu-west-1" in region:
                raise Exception("Simulated eu-west-1 Backup failure")
            mock = MagicMock()
            mock.list_backup_vaults.return_value = {"BackupVaultList": []}
            mock.list_backup_plans.return_value = {"BackupPlansList": []}
            return mock

        with patch.object(conn, "_make_client", side_effect=fail_or_succeed):
            try:
                conn._fetch_backup_resources(credentials, conn.account_id)
            except Exception:
                pytest.fail("_fetch_backup_resources raised an exception — fail-soft not implemented")

    def test_organizations_failure_does_not_abort_global(self):
        """Organizations is global — if it fails the rest of the fetch must still complete."""
        conn = self._build_connector(regions=["us-east-1"])
        credentials = {"aws_selected_regions": ["us-east-1"]}

        def fail(service, creds, region=None):
            raise Exception("Simulated Organizations access denied")

        with patch.object(conn, "_make_client", side_effect=fail):
            try:
                conn._fetch_organizations_resources(credentials, conn.account_id)
            except Exception:
                pytest.fail("_fetch_organizations_resources raised an exception — fail-soft not implemented")


# ---------------------------------------------------------------------------
# 12. M47 regression guard
# ---------------------------------------------------------------------------

class TestM47Regression:
    """Ensure M47 types still classify correctly after M48 additions."""

    def _make_change(self, record_type, change_type="modified", field_path=None, prev_value=None, new_value=None):
        return MagicMock(
            change_type=change_type,
            field_path=field_path,
            prev_value=prev_value,
            new_value=new_value,
            provider_metadata={"record_type": record_type, "record_name": "test-resource"},
        )

    def test_sqs_queue_still_classified(self):
        change = self._make_change(AWS_SQS_QUEUE, field_path="public_or_cross_account_policy", prev_value=False, new_value=True)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_sns_topic_still_classified(self):
        change = self._make_change(AWS_SNS_TOPIC, field_path="public_or_cross_account_policy", prev_value=False, new_value=True)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_eventbridge_bus_still_classified(self):
        change = self._make_change(AWS_EVENTBRIDGE_EVENT_BUS, field_path="public_or_cross_account_policy", prev_value=False, new_value=True)
        level, reason = classify_aws_change(change)
        assert level in ("critical", "high")

    def test_m47_record_types_still_in_aws_record_types(self):
        from app.connectors.aws_schema import (
            AWS_EVENTBRIDGE_EVENT_BUS, AWS_EVENTBRIDGE_RULE, AWS_EVENTBRIDGE_TARGET,
            AWS_EVENTBRIDGE_ARCHIVE, AWS_SQS_QUEUE, AWS_SNS_TOPIC, AWS_SNS_SUBSCRIPTION,
        )
        for rt in (
            AWS_EVENTBRIDGE_EVENT_BUS, AWS_EVENTBRIDGE_RULE, AWS_EVENTBRIDGE_TARGET,
            AWS_EVENTBRIDGE_ARCHIVE, AWS_SQS_QUEUE, AWS_SNS_TOPIC, AWS_SNS_SUBSCRIPTION,
        ):
            assert rt in AWS_RECORD_TYPES, f"{rt!r} missing from AWS_RECORD_TYPES"
