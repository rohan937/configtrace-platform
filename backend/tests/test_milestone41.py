"""Tests for Milestone 41: AWS Secrets Manager + SSM Parameter Metadata.

Covers:
- Security hard rules: GetSecretValue / GetParameter never called; no values stored
- Module-level helpers (_hash_kms_key_id, _classify_secret_name_sensitivity,
  _classify_ssm_name_sensitivity, _analyze_secret_resource_policy,
  _summarize_rotation_rules, _summarize_iam_arn, _summarize_ssm_policies)
- Diff service tracked field registration for both M41 types
- Risk classification: Secrets Manager (all matrix entries)
- Risk classification: SSM Parameter (all matrix entries)
- Failure classification: classify_aws_secretsmanager_failure
- Failure classification: classify_aws_ssm_failure
- Connector normalization: _fetch_secrets_in_region + _fetch_ssm_in_region
- Service inventory: M41 surfaces + counts
- Schema: AWS_RECORD_TYPES contains M41 constants
- M40 regression guards
"""

import hashlib
import json
import pytest
from unittest.mock import MagicMock, patch, call

from app.connectors.aws import (
    AWSConnector,
    _hash_kms_key_id,
    _classify_secret_name_sensitivity,
    _classify_ssm_name_sensitivity,
    _analyze_secret_resource_policy,
    _summarize_rotation_rules,
    _summarize_iam_arn,
    _summarize_ssm_policies,
)
from app.connectors.aws_schema import (
    AWS_SECRETSMANAGER_SECRET,
    AWS_SSM_PARAMETER,
    AWS_SERVICE_INVENTORY,
    AWS_CLOUDFRONT_DISTRIBUTION,
    AWS_ROUTE53_HOSTED_ZONE,
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_secretsmanager_failure,
    classify_aws_ssm_failure,
)
from app.connectors.exceptions import (
    ConnectorError,
    AuthenticationError,
    RateLimitError,
    NetworkError,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sm_change(change_type="modified", field_path=None, new_value=None, prev_value=None, record_name="my-secret", **pm_extra):
    """Build a minimal Secrets Manager change dict for testing."""
    return {
        "record_type": AWS_SECRETSMANAGER_SECRET,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": AWS_SECRETSMANAGER_SECRET,
            "record_name": record_name,
            **pm_extra,
        },
    }


def _ssm_change(change_type="modified", field_path=None, new_value=None, prev_value=None, record_name="/app/config", **pm_extra):
    """Build a minimal SSM Parameter change dict for testing."""
    return {
        "record_type": AWS_SSM_PARAMETER,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": AWS_SSM_PARAMETER,
            "record_name": record_name,
            **pm_extra,
        },
    }


def _make_connector():
    """Create an AWSConnector without calling __init__ (no DB needed)."""
    conn = AWSConnector.__new__(AWSConnector)
    return conn


def _creds():
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_default_region": "us-east-1",
        "aws_selected_regions": ["us-east-1"],
    }


def _make_secrets_call_aws(mock_client, list_resp, policy_resp=None, versions_resp=None):
    """Return a _call_aws side_effect that routes calls to the right responses.

    Tracks which functions are passed to _call_aws so security assertions can
    inspect them.  `get_secret_value` MUST never appear in this list.
    """
    called_functions = []

    def _call_aws(fn, *args, **kwargs):
        called_functions.append(fn)
        if fn is mock_client.list_secrets:
            return list_resp
        if fn is mock_client.get_resource_policy:
            return policy_resp if policy_resp is not None else {}
        if fn is mock_client.list_secret_version_ids:
            return versions_resp if versions_resp is not None else {"Versions": []}
        raise ConnectorError(f"Unexpected function call: {fn}", status_code=None)

    _call_aws.called_functions = called_functions
    return _call_aws


def _make_ssm_call_aws(mock_client, describe_resp, tags_resp=None):
    """Return a _call_aws side_effect that routes SSM calls."""
    called_functions = []

    def _call_aws(fn, *args, **kwargs):
        called_functions.append(fn)
        if fn is mock_client.describe_parameters:
            return describe_resp
        if fn is mock_client.list_tags_for_resource:
            return tags_resp if tags_resp is not None else {"TagList": []}
        raise ConnectorError(f"Unexpected function call: {fn}", status_code=None)

    _call_aws.called_functions = called_functions
    return _call_aws


# ─────────────────────────────────────────────────────────────────────────────
# 1. Security hard rules
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHardRules:
    """Verify forbidden API calls are never made and values never appear."""

    def test_get_secret_value_never_called(self):
        """GetSecretValue must never appear in calls to _call_aws."""
        conn = _make_connector()
        mock_client = MagicMock()

        call_aws = _make_secrets_call_aws(
            mock_client,
            list_resp={
                "SecretList": [
                    {
                        "Name": "prod/db/password",
                        "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db/password",
                        "RotationEnabled": False,
                    }
                ],
            },
        )
        conn._call_aws = call_aws

        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")

        # GetSecretValue must NEVER be passed to _call_aws
        assert mock_client.get_secret_value not in call_aws.called_functions
        assert len(records) == 1

    def test_get_parameter_never_called(self):
        """GetParameter / GetParameters / GetParameterHistory must never appear."""
        conn = _make_connector()
        mock_client = MagicMock()

        call_aws = _make_ssm_call_aws(
            mock_client,
            describe_resp={
                "Parameters": [
                    {
                        "Name": "/prod/db/password",
                        "Type": "SecureString",
                        "Version": 1,
                    }
                ],
            },
        )
        conn._call_aws = call_aws

        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")

        assert mock_client.get_parameter not in call_aws.called_functions
        assert mock_client.get_parameters not in call_aws.called_functions
        assert mock_client.get_parameter_history not in call_aws.called_functions
        assert len(records) == 1

    def test_secret_records_contain_no_value_field(self):
        """Secret records must not contain any 'value' or 'secret_value' field."""
        conn = _make_connector()
        mock_client = MagicMock()

        conn._call_aws = _make_secrets_call_aws(
            mock_client,
            list_resp={
                "SecretList": [
                    {
                        "Name": "my/secret",
                        "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:my/secret",
                        "SecretString": "SHOULD_NEVER_BE_HERE",  # ignored
                    }
                ],
            },
        )

        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        rec = records[0]
        forbidden = {"value", "secret_value", "SecretString", "SecretBinary",
                     "secret_string", "secret_binary", "plaintext"}
        for key in forbidden:
            assert key not in rec, f"Forbidden field {key!r} found in secret record"

    def test_ssm_records_contain_no_value_field(self):
        """SSM parameter records must not contain any 'value' or 'Value' field."""
        conn = _make_connector()
        mock_client = MagicMock()

        conn._call_aws = _make_ssm_call_aws(
            mock_client,
            describe_resp={
                "Parameters": [
                    {
                        "Name": "/app/db/password",
                        "Type": "SecureString",
                        "Value": "SUPER_SECRET",  # ignored
                        "Version": 1,
                    }
                ],
            },
        )

        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        rec = records[0]
        forbidden = {"value", "Value", "parameter_value", "plaintext"}
        for key in forbidden:
            assert key not in rec, f"Forbidden field {key!r} found in SSM record"

    def test_resource_policy_raw_json_not_stored(self):
        """Raw resource policy JSON must never appear in any record field."""
        raw_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue"}]
        })
        conn = _make_connector()
        mock_client = MagicMock()

        conn._call_aws = _make_secrets_call_aws(
            mock_client,
            list_resp={
                "SecretList": [
                    {"Name": "test-secret", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:test-secret"}
                ],
            },
            policy_resp={"ResourcePolicy": raw_policy},
        )

        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        rec = records[0]

        # The raw JSON must not appear anywhere in the record
        rec_str = json.dumps(rec)
        assert "Statement" not in rec_str, "Raw policy JSON 'Statement' found in record"
        assert "GetSecretValue" not in rec_str, "Raw policy action found in record"
        # The summarized form is OK — wildcard should be detected
        assert "policy_summary" in rec
        assert rec["policy_summary"]["has_wildcard_principal"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 2. Helper functions
# ─────────────────────────────────────────────────────────────────────────────

class TestHelperFunctions:

    def test_hash_kms_key_id_returns_12_hex(self):
        result = _hash_kms_key_id("arn:aws:kms:us-east-1:123:key/abc-123")
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_kms_key_id_is_deterministic(self):
        key = "arn:aws:kms:us-east-1:123:key/abc-123"
        assert _hash_kms_key_id(key) == _hash_kms_key_id(key)

    def test_hash_kms_key_id_differs_for_different_keys(self):
        assert _hash_kms_key_id("key-a") != _hash_kms_key_id("key-b")

    def test_hash_kms_key_id_matches_sha256(self):
        key = "test-key-id"
        expected = hashlib.sha256(key.encode()).hexdigest()[:12]
        assert _hash_kms_key_id(key) == expected

    # ── Secret name sensitivity ────────────────────────────────────────────────

    def test_classify_secret_production(self):
        # "prod-only" name has no other more specific match
        assert _classify_secret_name_sensitivity("prod-only") == "production"

    def test_classify_secret_credential(self):
        assert _classify_secret_name_sensitivity("app/credentials") == "credential"

    def test_classify_secret_api_key(self):
        assert _classify_secret_name_sensitivity("stripe/api_key") == "api_key"

    def test_classify_secret_auth(self):
        assert _classify_secret_name_sensitivity("auth/jwt-signing-key") == "auth"

    def test_classify_secret_payment(self):
        # "payment/billing-info" — no secret/credential/api_key/auth/database patterns
        assert _classify_secret_name_sensitivity("payment/billing-info") == "payment"

    def test_classify_secret_database(self):
        assert _classify_secret_name_sensitivity("database/postgres/url") == "database"

    def test_classify_secret_none(self):
        assert _classify_secret_name_sensitivity("feature-flags") == "none"

    def test_classify_secret_sensitive_categories(self):
        # Verify that names with sensitive keywords DO get a non-"none" category
        sensitive_names = [
            "prod/db/password",        # "password" matches credential
            "PROD/MySecret",           # "secret" matches secret
            "payment/stripe-secret",   # "secret" matches secret (first match wins)
            "auth/jwt",                # "auth" matches auth
            "rds-endpoint",            # "rds" matches database
        ]
        for name in sensitive_names:
            result = _classify_secret_name_sensitivity(name)
            assert result != "none", f"Expected sensitive category for {name!r}, got 'none'"

    # ── SSM name sensitivity ──────────────────────────────────────────────────

    def test_classify_ssm_production(self):
        assert _classify_ssm_name_sensitivity("/prod/app/config") == "production"

    def test_classify_ssm_database(self):
        assert _classify_ssm_name_sensitivity("/app/db/connection_string") == "database"

    def test_classify_ssm_none(self):
        assert _classify_ssm_name_sensitivity("/feature-flags/dark-mode") == "none"

    # ── summarize_iam_arn ──────────────────────────────────────────────────────

    def test_summarize_iam_arn_user(self):
        arn = "arn:aws:iam::123456789012:user/alice"
        result = _summarize_iam_arn(arn)
        assert result == "user/alice"

    def test_summarize_iam_arn_role(self):
        arn = "arn:aws:iam::123456789012:role/LambdaRole"
        result = _summarize_iam_arn(arn)
        assert result == "role/LambdaRole"

    def test_summarize_iam_arn_none(self):
        assert _summarize_iam_arn(None) is None

    def test_summarize_iam_arn_empty(self):
        assert _summarize_iam_arn("") is None

    def test_summarize_iam_arn_no_raw_arn_stored(self):
        arn = "arn:aws:iam::123456789012:user/alice"
        result = _summarize_iam_arn(arn)
        # Full ARN prefix must not be stored in the result
        assert "arn:aws" not in (result or "")

    # ── analyze_secret_resource_policy ────────────────────────────────────────

    def test_analyze_policy_wildcard_principal(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue"}]
        })
        result = _analyze_secret_resource_policy(policy, "123456789012")
        assert result["has_wildcard_principal"] is True

    def test_analyze_policy_no_wildcard(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/App"}, "Action": "secretsmanager:GetSecretValue"}]
        })
        result = _analyze_secret_resource_policy(policy, "123456789012")
        assert result["has_wildcard_principal"] is False

    def test_analyze_policy_cross_account(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "secretsmanager:GetSecretValue"}]
        })
        result = _analyze_secret_resource_policy(policy, "123456789012")
        assert result["cross_account_principal_count"] == 1

    def test_analyze_policy_empty(self):
        result = _analyze_secret_resource_policy("{}", "123456789012")
        assert result["has_wildcard_principal"] is False
        assert result["statement_count"] == 0

    def test_analyze_policy_malformed_returns_empty(self):
        result = _analyze_secret_resource_policy("not-json", "123456789012")
        assert result["has_wildcard_principal"] is False

    def test_analyze_policy_raw_json_never_in_result(self):
        raw_policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]
        })
        result = _analyze_secret_resource_policy(raw_policy, "123456789012")
        result_str = json.dumps(result)
        assert "GetSecretValue" not in result_str
        assert "Statement" not in result_str

    # ── summarize_rotation_rules ──────────────────────────────────────────────

    def test_summarize_rotation_rules_basic(self):
        rules = {"AutomaticallyAfterDays": 30}
        result = _summarize_rotation_rules(rules)
        assert result is not None
        assert result["automatically_after_days"] == 30

    def test_summarize_rotation_rules_empty(self):
        assert _summarize_rotation_rules({}) is None
        assert _summarize_rotation_rules(None) is None  # type: ignore[arg-type]

    def test_summarize_rotation_rules_schedule(self):
        rules = {"ScheduleExpression": "cron(0 12 * * ? *)"}
        result = _summarize_rotation_rules(rules)
        assert result["schedule_expression_present"] is True
        # Raw schedule expression must not be stored
        result_str = json.dumps(result)
        assert "cron" not in result_str

    # ── summarize_ssm_policies ────────────────────────────────────────────────

    def test_summarize_ssm_policies_empty(self):
        assert _summarize_ssm_policies([]) is None

    def test_summarize_ssm_policies_counts(self):
        policies = [
            {"Type": "Expiration", "Status": "Active"},
            {"Type": "Expiration", "Status": "Active"},
            {"Type": "NoChangeNotification", "Status": "Active"},
        ]
        result = _summarize_ssm_policies(policies)
        assert result is not None
        assert result["total"] == 3
        assert result["type_counts"]["Expiration"] == 2
        assert result["type_counts"]["NoChangeNotification"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 3. Schema — AWS_RECORD_TYPES
# ─────────────────────────────────────────────────────────────────────────────

class TestSchema:
    def test_secretsmanager_in_record_types(self):
        assert AWS_SECRETSMANAGER_SECRET in AWS_RECORD_TYPES

    def test_ssm_in_record_types(self):
        assert AWS_SSM_PARAMETER in AWS_RECORD_TYPES

    def test_m40_types_still_present(self):
        assert AWS_ROUTE53_HOSTED_ZONE in AWS_RECORD_TYPES
        assert AWS_CLOUDFRONT_DISTRIBUTION in AWS_RECORD_TYPES


# ─────────────────────────────────────────────────────────────────────────────
# 4. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffServiceTrackedFields:

    def test_secretsmanager_tracked_fields_present(self):
        record = {"record_type": AWS_SECRETSMANAGER_SECRET}
        fields = _tracked_fields_for(record)
        required = {
            "rotation_enabled", "kms_key_id_present", "kms_key_id_hash",
            "deleted_date", "has_resource_policy", "policy_summary",
            "description_present", "tag_keys", "sensitive_name_category",
        }
        assert required.issubset(set(fields)), f"Missing: {required - set(fields)}"

    def test_ssm_tracked_fields_present(self):
        record = {"record_type": AWS_SSM_PARAMETER}
        fields = _tracked_fields_for(record)
        required = {
            "parameter_type", "tier", "key_id_present", "key_id_hash",
            "version", "policy_count", "tag_keys", "sensitive_name_category",
        }
        assert required.issubset(set(fields)), f"Missing: {required - set(fields)}"

    def test_no_value_fields_in_tracked(self):
        """Ensure 'value' or 'secret_value' fields are not tracked."""
        sm_fields = _tracked_fields_for({"record_type": AWS_SECRETSMANAGER_SECRET})
        ssm_fields = _tracked_fields_for({"record_type": AWS_SSM_PARAMETER})
        forbidden = {"value", "secret_value", "parameter_value", "plaintext"}
        assert not forbidden.intersection(set(sm_fields))
        assert not forbidden.intersection(set(ssm_fields))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification — Secrets Manager
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretsManagerRiskClassifier:

    # ── Added ─────────────────────────────────────────────────────────────────

    def test_added_sensitive_no_rotation_is_high(self):
        change = _sm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "production",
                "rotation_enabled": False,
                "has_resource_policy": False,
                "policy_summary": None,
            },
            record_name="prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "rotation" in reason.lower()

    def test_added_sensitive_with_rotation_is_medium(self):
        change = _sm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "production",
                "rotation_enabled": True,
                "has_resource_policy": False,
                "policy_summary": None,
            },
            record_name="prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "medium"

    def test_added_non_sensitive_is_low(self):
        change = _sm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "none",
                "rotation_enabled": False,
                "has_resource_policy": False,
                "policy_summary": None,
            },
            record_name="my-feature-flag",
        )
        level, reason = classify_aws_change(change)
        assert level == "low"

    def test_added_wildcard_policy_is_critical(self):
        change = _sm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "none",
                "rotation_enabled": True,
                "has_resource_policy": True,
                "policy_summary": {"has_wildcard_principal": True},
            },
            record_name="some-secret",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "wildcard" in reason.lower()

    # ── Removed ───────────────────────────────────────────────────────────────

    def test_removed_sensitive_is_critical(self):
        change = _sm_change(
            change_type="removed",
            prev_value={"sensitive_name_category": "credential"},
            record_name="app/credentials",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"

    def test_removed_non_sensitive_is_high(self):
        change = _sm_change(
            change_type="removed",
            prev_value={"sensitive_name_category": "none"},
            record_name="my-feature-toggle",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"

    # ── rotation_enabled ──────────────────────────────────────────────────────

    def test_rotation_disabled_sensitive_is_critical(self):
        change = _sm_change(
            field_path="rotation_enabled",
            new_value=False,
            prev_value=True,
            record_name="prod/api/key",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "rotation" in reason.lower()

    def test_rotation_disabled_non_sensitive_is_high(self):
        change = _sm_change(
            field_path="rotation_enabled",
            new_value=False,
            prev_value=True,
            record_name="dev-config",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"

    def test_rotation_enabled_is_low(self):
        change = _sm_change(
            field_path="rotation_enabled",
            new_value=True,
            prev_value=False,
            record_name="prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "low"

    # ── kms_key_id_present ────────────────────────────────────────────────────

    def test_kms_key_removed_sensitive_is_critical(self):
        change = _sm_change(
            field_path="kms_key_id_present",
            new_value=False,
            prev_value=True,
            record_name="prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"

    def test_kms_key_removed_non_sensitive_is_high(self):
        change = _sm_change(
            field_path="kms_key_id_present",
            new_value=False,
            prev_value=True,
            record_name="dev-config",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"

    def test_kms_key_added_is_low(self):
        change = _sm_change(
            field_path="kms_key_id_present",
            new_value=True,
            prev_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    # ── deleted_date ──────────────────────────────────────────────────────────

    def test_deletion_scheduled_sensitive_is_critical(self):
        change = _sm_change(
            field_path="deleted_date",
            new_value="2026-06-01T00:00:00",
            prev_value=None,
            record_name="prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "delet" in reason.lower()

    def test_deletion_scheduled_non_sensitive_is_high(self):
        change = _sm_change(
            field_path="deleted_date",
            new_value="2026-06-01T00:00:00",
            prev_value=None,
            record_name="dev-config",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"

    def test_deletion_cancelled_is_low(self):
        change = _sm_change(
            field_path="deleted_date",
            new_value=None,
            prev_value="2026-06-01T00:00:00",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    # ── policy_summary ────────────────────────────────────────────────────────

    def test_policy_wildcard_added_is_critical(self):
        change = _sm_change(
            field_path="policy_summary",
            new_value={"has_wildcard_principal": True},
            prev_value={"has_wildcard_principal": False},
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "wildcard" in reason.lower()

    def test_policy_wildcard_removed_is_low(self):
        change = _sm_change(
            field_path="policy_summary",
            new_value={"has_wildcard_principal": False},
            prev_value={"has_wildcard_principal": True},
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_policy_changed_no_wildcard_is_medium(self):
        change = _sm_change(
            field_path="policy_summary",
            new_value={"has_wildcard_principal": False, "statement_count": 3},
            prev_value={"has_wildcard_principal": False, "statement_count": 1},
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # ── Other fields ──────────────────────────────────────────────────────────

    def test_tag_keys_is_low(self):
        change = _sm_change(field_path="tag_keys", new_value=["env", "team"], prev_value=["env"])
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_description_present_is_low(self):
        change = _sm_change(field_path="description_present", new_value=True, prev_value=False)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_rotation_rules_summary_is_low(self):
        change = _sm_change(
            field_path="rotation_rules_summary",
            new_value={"automatically_after_days": 60},
            prev_value={"automatically_after_days": 30},
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_has_resource_policy_removed_is_medium(self):
        change = _sm_change(field_path="has_resource_policy", new_value=False, prev_value=True)
        level, _ = classify_aws_change(change)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk classification — SSM Parameter
# ─────────────────────────────────────────────────────────────────────────────

class TestSSMParameterRiskClassifier:

    # ── Added ─────────────────────────────────────────────────────────────────

    def test_added_sensitive_non_secure_string_is_critical(self):
        change = _ssm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "production",
                "parameter_type": "String",
                "key_id_present": False,
            },
            record_name="/prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "SecureString" in reason or "encrypt" in reason.lower()

    def test_added_sensitive_secure_string_is_medium(self):
        change = _ssm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "credential",
                "parameter_type": "SecureString",
                "key_id_present": True,
            },
            record_name="/prod/db/password",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_added_non_sensitive_is_low(self):
        change = _ssm_change(
            change_type="added",
            new_value={
                "sensitive_name_category": "none",
                "parameter_type": "String",
                "key_id_present": False,
            },
            record_name="/app/feature-flags",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    # ── Removed ───────────────────────────────────────────────────────────────

    def test_removed_sensitive_is_critical(self):
        change = _ssm_change(
            change_type="removed",
            prev_value={"sensitive_name_category": "database"},
            record_name="/prod/db/password",
        )
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_removed_non_sensitive_is_medium(self):
        change = _ssm_change(
            change_type="removed",
            prev_value={"sensitive_name_category": "none"},
            record_name="/app/feature-toggle",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # ── parameter_type ────────────────────────────────────────────────────────

    def test_secure_to_string_sensitive_is_critical(self):
        change = _ssm_change(
            field_path="parameter_type",
            new_value="String",
            prev_value="SecureString",
            record_name="/prod/db/password",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "SecureString" in reason or "encrypt" in reason.lower()

    def test_secure_to_string_non_sensitive_is_high(self):
        change = _ssm_change(
            field_path="parameter_type",
            new_value="String",
            prev_value="SecureString",
            record_name="/app/config",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_string_to_secure_is_low(self):
        change = _ssm_change(
            field_path="parameter_type",
            new_value="SecureString",
            prev_value="String",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    # ── key_id_present ────────────────────────────────────────────────────────

    def test_kms_key_removed_sensitive_is_critical(self):
        change = _ssm_change(
            field_path="key_id_present",
            new_value=False,
            prev_value=True,
            record_name="/prod/db/password",
        )
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_kms_key_removed_non_sensitive_is_high(self):
        change = _ssm_change(
            field_path="key_id_present",
            new_value=False,
            prev_value=True,
            record_name="/app/config",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_kms_key_added_is_low(self):
        change = _ssm_change(
            field_path="key_id_present",
            new_value=True,
            prev_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    # ── Other fields ──────────────────────────────────────────────────────────

    def test_tier_change_is_low(self):
        change = _ssm_change(field_path="tier", new_value="Advanced", prev_value="Standard")
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_version_change_is_low(self):
        change = _ssm_change(field_path="version", new_value=2, prev_value=1)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_policy_count_decreased_is_medium(self):
        change = _ssm_change(field_path="policy_count", new_value=0, prev_value=2)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_policy_count_increased_is_low(self):
        change = _ssm_change(field_path="policy_count", new_value=2, prev_value=0)
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_allowed_pattern_removed_is_medium(self):
        change = _ssm_change(field_path="allowed_pattern_present", new_value=False, prev_value=True)
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_tag_keys_is_low(self):
        change = _ssm_change(field_path="tag_keys", new_value=["env"], prev_value=[])
        level, _ = classify_aws_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Failure classification — Secrets Manager
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretsManagerFailureClassifier:

    def test_access_denied_returns_access_denied_code(self):
        exc = AuthenticationError("Access denied", status_code=403)
        fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
        assert fc.error_code == "aws_secretsmanager_access_denied"
        assert fc.category == "authentication"
        # Action must not instruct user to grant GetSecretValue permission
        assert "secretsmanager:GetSecretValue" not in fc.recommended_action

    def test_connector_error_403_access_denied(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
        assert fc.error_code == "aws_secretsmanager_access_denied"

    def test_rate_limited(self):
        exc = RateLimitError("Throttling")
        fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
        assert fc.error_code == "aws_secretsmanager_rate_limited"
        assert fc.category == "rate_limited"

    def test_network_error(self):
        exc = NetworkError("Connection refused")
        fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
        assert fc.error_code == "network_error"
        assert fc.category == "network"

    def test_5xx_unavailable(self):
        exc = ConnectorError("Internal Server Error", status_code=503)
        fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
        assert fc.error_code == "aws_secretsmanager_api_unavailable"
        assert fc.category == "provider_unavailable"

    def test_list_secrets_unavailable(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
        assert fc.error_code == "aws_secretsmanager_list_unavailable"

    def test_describe_secret_unavailable(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_secretsmanager_failure("DescribeSecret", exc)
        assert fc.error_code == "aws_secretsmanager_describe_unavailable"

    def test_get_resource_policy_unavailable(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_secretsmanager_failure("GetResourcePolicy", exc)
        assert fc.error_code == "aws_secretsmanager_policy_unavailable"

    def test_list_secret_version_ids_unavailable(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_secretsmanager_failure("ListSecretVersionIds", exc)
        assert fc.error_code == "aws_secretsmanager_versions_unavailable"

    def test_unknown_api_name_returns_generic(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_secretsmanager_failure("UnknownAPI", exc)
        assert fc.error_code == "aws_secretsmanager_api_unavailable"

    def test_action_never_grants_get_secret_value_permission(self):
        """Ensure recommended_action never instructs granting secretsmanager:GetSecretValue."""
        for api_name in ["ListSecrets", "DescribeSecret", "GetResourcePolicy", "ListSecretVersionIds"]:
            exc = ConnectorError("test")
            fc = classify_aws_secretsmanager_failure(api_name, exc)
            assert "secretsmanager:GetSecretValue" not in fc.recommended_action, \
                f"Permission 'secretsmanager:GetSecretValue' found in action for {api_name}"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Failure classification — SSM
# ─────────────────────────────────────────────────────────────────────────────

class TestSSMFailureClassifier:

    def test_access_denied(self):
        exc = AuthenticationError("Access denied", status_code=403)
        fc = classify_aws_ssm_failure("DescribeParameters", exc)
        assert fc.error_code == "aws_ssm_access_denied"
        assert fc.category == "authentication"

    def test_action_mentions_no_get_parameter(self):
        exc = AuthenticationError("Access denied", status_code=403)
        fc = classify_aws_ssm_failure("DescribeParameters", exc)
        # The action must explicitly say GetParameter is not used, or must not reference it
        assert "GetParameter," not in fc.recommended_action or "never" in fc.recommended_action.lower()

    def test_rate_limited(self):
        exc = RateLimitError("Throttling")
        fc = classify_aws_ssm_failure("DescribeParameters", exc)
        assert fc.error_code == "aws_ssm_rate_limited"
        assert fc.category == "rate_limited"

    def test_network_error(self):
        exc = NetworkError("Timeout")
        fc = classify_aws_ssm_failure("DescribeParameters", exc)
        assert fc.error_code == "network_error"

    def test_5xx_unavailable(self):
        exc = ConnectorError("Service Unavailable", status_code=503)
        fc = classify_aws_ssm_failure("DescribeParameters", exc)
        assert fc.error_code == "aws_ssm_api_unavailable"

    def test_describe_parameters_unavailable(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_ssm_failure("DescribeParameters", exc)
        assert fc.error_code == "aws_ssm_describe_parameters_unavailable"

    def test_list_tags_unavailable(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_ssm_failure("ListTagsForResource", exc)
        assert fc.error_code == "aws_ssm_tags_unavailable"

    def test_unknown_api_name(self):
        exc = ConnectorError("Unexpected error")
        fc = classify_aws_ssm_failure("UnknownAPI", exc)
        assert fc.error_code == "aws_ssm_api_unavailable"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Connector normalization
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectorNormalization:

    # ── Secrets Manager ───────────────────────────────────────────────────────

    def test_secrets_record_structure(self):
        conn = _make_connector()
        mock_client = MagicMock()

        conn._call_aws = _make_secrets_call_aws(
            mock_client,
            list_resp={
                "SecretList": [
                    {
                        "Name": "prod/db/password",
                        "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db/password",
                        "RotationEnabled": True,
                        "RotationRules": {"AutomaticallyAfterDays": 30},
                        "Tags": [{"Key": "env", "Value": "prod"}],
                    }
                ],
            },
            versions_resp={
                "Versions": [
                    {"VersionId": "v1", "VersionStages": ["AWSCURRENT"]},
                    {"VersionId": "v0", "VersionStages": ["AWSDEPRECATED"]},
                ]
            },
        )

        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        rec = records[0]

        assert rec["record_type"] == AWS_SECRETSMANAGER_SECRET
        assert rec["record_id"] == "123/us-east-1/prod/db/password"
        assert rec["name"] == "prod/db/password"
        assert rec["rotation_enabled"] is True
        assert rec["rotation_rules_summary"] is not None
        assert rec["rotation_rules_summary"]["automatically_after_days"] == 30
        assert rec["tag_keys"] == ["env"]
        # "prod/db/password" → "credential" (password matches credential patterns first)
        assert rec["sensitive_name_category"] in ("production", "credential", "database")
        assert rec["sensitive_name_category"] != "none"  # must be sensitive
        assert rec["version_count"] == 2
        assert rec["active_version_count"] == 1
        assert rec["deprecated_version_count"] == 1

        # Security: no value fields
        assert "value" not in rec
        assert "SecretString" not in rec

    def test_secrets_kms_key_hashed(self):
        conn = _make_connector()
        mock_client = MagicMock()
        kms_key = "arn:aws:kms:us-east-1:123:key/abc-123"

        conn._call_aws = _make_secrets_call_aws(
            mock_client,
            list_resp={
                "SecretList": [
                    {"Name": "test", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:test", "KmsKeyId": kms_key}
                ],
            },
        )

        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        rec = records[0]
        assert rec["kms_key_id_present"] is True
        assert rec["kms_key_id_hash"] == _hash_kms_key_id(kms_key)
        # Raw KMS ARN must not be stored as its own field
        assert "kms_key_id" not in rec

    def test_secrets_pagination(self):
        conn = _make_connector()
        mock_client = MagicMock()
        call_count = [0]

        def paged_call_aws(fn, *args, **kwargs):
            if fn is mock_client.list_secrets:
                call_count[0] += 1
                if call_count[0] == 1:
                    return {
                        "SecretList": [{"Name": "secret-1", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:secret-1"}],
                        "NextToken": "page2",
                    }
                return {
                    "SecretList": [{"Name": "secret-2", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:secret-2"}],
                }
            if fn is mock_client.get_resource_policy:
                return {}
            if fn is mock_client.list_secret_version_ids:
                return {"Versions": []}
            raise ConnectorError("unexpected")

        conn._call_aws = paged_call_aws
        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 2
        names = {r["name"] for r in records}
        assert "secret-1" in names
        assert "secret-2" in names

    def test_secrets_fail_soft_on_policy_error(self):
        """GetResourcePolicy failure must not abort the secret fetch."""
        conn = _make_connector()
        mock_client = MagicMock()

        def call_aws(fn, *args, **kwargs):
            if fn is mock_client.list_secrets:
                return {"SecretList": [{"Name": "test", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:test"}]}
            if fn is mock_client.get_resource_policy:
                raise ConnectorError("AccessDenied", status_code=403)
            if fn is mock_client.list_secret_version_ids:
                return {"Versions": []}
            raise ConnectorError("unexpected")

        conn._call_aws = call_aws
        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        rec = records[0]
        assert rec["has_resource_policy"] is False
        assert rec["config_fetch_warnings"] is not None

    def test_secrets_fail_soft_on_versions_error(self):
        """ListSecretVersionIds failure must not abort the secret fetch."""
        conn = _make_connector()
        mock_client = MagicMock()

        def call_aws(fn, *args, **kwargs):
            if fn is mock_client.list_secrets:
                return {"SecretList": [{"Name": "test", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:test"}]}
            if fn is mock_client.get_resource_policy:
                return {}
            if fn is mock_client.list_secret_version_ids:
                raise ConnectorError("AccessDenied", status_code=403)
            raise ConnectorError("unexpected")

        conn._call_aws = call_aws
        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        assert records[0]["version_count"] == 0

    # ── SSM ───────────────────────────────────────────────────────────────────

    def test_ssm_record_structure(self):
        conn = _make_connector()
        mock_client = MagicMock()
        kms_key = "arn:aws:kms:us-east-1:123:key/abc"

        conn._call_aws = _make_ssm_call_aws(
            mock_client,
            describe_resp={
                "Parameters": [
                    {
                        "Name": "/prod/db/password",
                        "Type": "SecureString",
                        "Tier": "Standard",
                        "DataType": "text",
                        "KeyId": kms_key,
                        "Version": 3,
                        "AllowedPattern": "[a-zA-Z0-9]+",
                        "Policies": [{"Type": "Expiration", "Status": "Active"}],
                    }
                ],
            },
            tags_resp={"TagList": [{"Key": "env", "Value": "prod"}]},
        )

        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        rec = records[0]

        assert rec["record_type"] == AWS_SSM_PARAMETER
        assert rec["record_id"] == "123/us-east-1//prod/db/password"
        assert rec["parameter_type"] == "SecureString"
        assert rec["tier"] == "Standard"
        assert rec["key_id_present"] is True
        assert rec["version"] == 3
        assert rec["allowed_pattern_present"] is True
        assert rec["policy_count"] == 1
        assert rec["tag_keys"] == ["env"]
        # "prod/db/password" → "credential" (password matches credential patterns first)
        assert rec["sensitive_name_category"] in ("production", "credential", "database")
        assert rec["sensitive_name_category"] != "none"  # must be sensitive
        assert rec["path_depth"] == 3  # prod, db, password

        # Security: no value fields
        assert "value" not in rec
        assert "Value" not in rec

    def test_ssm_kms_key_hashed(self):
        conn = _make_connector()
        mock_client = MagicMock()
        kms_key = "arn:aws:kms:us-east-1:123:key/abc-456"

        conn._call_aws = _make_ssm_call_aws(
            mock_client,
            describe_resp={
                "Parameters": [
                    {"Name": "/test", "Type": "SecureString", "KeyId": kms_key, "Version": 1}
                ],
            },
        )

        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")
        rec = records[0]
        assert rec["key_id_present"] is True
        assert rec["key_id_hash"] == _hash_kms_key_id(kms_key)
        assert "key_id" not in rec

    def test_ssm_pagination(self):
        conn = _make_connector()
        mock_client = MagicMock()
        call_count = [0]

        def paged_call_aws(fn, *args, **kwargs):
            if fn is mock_client.describe_parameters:
                call_count[0] += 1
                if call_count[0] == 1:
                    return {
                        "Parameters": [{"Name": "/app/param1", "Type": "String", "Version": 1}],
                        "NextToken": "page2",
                    }
                return {
                    "Parameters": [{"Name": "/app/param2", "Type": "String", "Version": 1}],
                }
            if fn is mock_client.list_tags_for_resource:
                return {"TagList": []}
            raise ConnectorError("unexpected")

        conn._call_aws = paged_call_aws
        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 2

    def test_ssm_fail_soft_on_tags_error(self):
        """ListTagsForResource failure must not abort the SSM parameter fetch."""
        conn = _make_connector()
        mock_client = MagicMock()

        def call_aws(fn, *args, **kwargs):
            if fn is mock_client.describe_parameters:
                return {"Parameters": [{"Name": "/test", "Type": "String", "Version": 1}]}
            if fn is mock_client.list_tags_for_resource:
                raise ConnectorError("AccessDenied", status_code=403)
            raise ConnectorError("unexpected")

        conn._call_aws = call_aws
        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")
        assert len(records) == 1
        assert records[0]["tag_keys"] is None
        assert records[0]["config_fetch_warnings"] is not None

    def test_ssm_last_modified_user_summarized(self):
        """LastModifiedUser ARN is summarized, not stored in full."""
        conn = _make_connector()
        mock_client = MagicMock()

        conn._call_aws = _make_ssm_call_aws(
            mock_client,
            describe_resp={
                "Parameters": [
                    {
                        "Name": "/test",
                        "Type": "String",
                        "Version": 1,
                        "LastModifiedUser": "arn:aws:iam::123456789012:user/alice",
                    }
                ],
            },
        )

        records = conn._fetch_ssm_in_region(mock_client, "123456789012", "us-east-1")
        rec = records[0]
        assert "last_modified_user_summary" in rec
        summary = rec["last_modified_user_summary"]
        # Summary must not contain the full ARN prefix
        if summary:
            assert "arn:aws" not in summary


# ─────────────────────────────────────────────────────────────────────────────
# 10. Service inventory
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceInventory:

    def test_service_inventory_includes_m41_surfaces(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(
            creds,
            secrets_count=5,
            ssm_parameter_count=12,
        )
        assert "secrets_manager" in inv["enabled_surfaces"]
        assert "ssm" in inv["enabled_surfaces"]
        assert inv["secrets_count"] == 5
        assert inv["ssm_parameter_count"] == 12

    def test_service_inventory_m41_counts_default_to_zero(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        assert inv["secrets_count"] == 0
        assert inv["ssm_parameter_count"] == 0

    def test_service_inventory_secrets_moved_from_future(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        # "secrets" was moved from future_surfaces to enabled_surfaces in M41
        future = inv.get("future_surfaces", [])
        assert "secrets" not in future

    def test_service_inventory_previous_surfaces_still_present(self):
        conn = _make_connector()
        creds = _creds()
        inv = conn._fetch_service_inventory(creds)
        for surface in ("account_inventory", "s3", "security_groups", "vpc", "iam", "route53", "cloudfront"):
            assert surface in inv["enabled_surfaces"], f"Missing surface: {surface}"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Regional fail-soft (_fetch_secrets_resources / _fetch_ssm_resources)
# ─────────────────────────────────────────────────────────────────────────────

class TestRegionalFailSoft:

    def test_secrets_regional_failure_does_not_abort(self):
        """ConnectorError on make_client must not abort entire fetch."""
        conn = _make_connector()
        creds = _creds()
        creds["aws_selected_regions"] = ["us-east-1", "eu-west-1"]

        with patch.object(conn, "_make_client") as mock_make:
            mock_make.side_effect = ConnectorError("Region unavailable", status_code=503)
            # Should not raise — fail-soft
            result = conn._fetch_secrets_resources(creds, "123")
            assert isinstance(result, list)
            assert result == []

    def test_ssm_regional_failure_does_not_abort(self):
        """ConnectorError on make_client must not abort entire SSM fetch."""
        conn = _make_connector()
        creds = _creds()
        creds["aws_selected_regions"] = ["us-east-1", "eu-west-1"]

        with patch.object(conn, "_make_client") as mock_make:
            mock_make.side_effect = ConnectorError("Region unavailable", status_code=503)
            result = conn._fetch_ssm_resources(creds, "123")
            assert isinstance(result, list)
            assert result == []

    def test_secrets_list_failure_breaks_loop_not_region(self):
        """ListSecrets ConnectorError causes break (loop exit), not full abort."""
        conn = _make_connector()
        mock_client = MagicMock()

        def call_aws(fn, *args, **kwargs):
            if fn is mock_client.list_secrets:
                raise ConnectorError("AccessDenied", status_code=403)
            raise ConnectorError("unexpected")

        conn._call_aws = call_aws
        # Should return empty list, not raise
        records = conn._fetch_secrets_in_region(mock_client, "123", "us-east-1")
        assert records == []

    def test_ssm_describe_failure_breaks_loop_not_region(self):
        """DescribeParameters ConnectorError causes break, not full abort."""
        conn = _make_connector()
        mock_client = MagicMock()

        def call_aws(fn, *args, **kwargs):
            if fn is mock_client.describe_parameters:
                raise ConnectorError("AccessDenied", status_code=403)
            raise ConnectorError("unexpected")

        conn._call_aws = call_aws
        records = conn._fetch_ssm_in_region(mock_client, "123", "us-east-1")
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 12. M40 regression guards
# ─────────────────────────────────────────────────────────────────────────────

class TestM40Regression:
    """Quick regression checks to ensure M40 functionality still works."""

    def test_route53_hosted_zone_in_record_types(self):
        assert AWS_ROUTE53_HOSTED_ZONE in AWS_RECORD_TYPES

    def test_cloudfront_distribution_in_record_types(self):
        assert AWS_CLOUDFRONT_DISTRIBUTION in AWS_RECORD_TYPES

    def test_route53_hosted_zone_tracked_fields(self):
        record = {"record_type": AWS_ROUTE53_HOSTED_ZONE}
        fields = _tracked_fields_for(record)
        assert "zone_type" in fields
        assert "name_servers" in fields

    def test_cloudfront_tracked_fields(self):
        record = {"record_type": AWS_CLOUDFRONT_DISTRIBUTION}
        fields = _tracked_fields_for(record)
        assert "web_acl_id" in fields
        assert "default_cache_behavior_summary" in fields

    def test_route53_hosted_zone_risk_removed_is_high_or_critical(self):
        change = {
            "change_type": "removed",
            "field_path": None,
            "new_value": None,
            "prev_value": None,
            "provider_metadata": {
                "record_type": AWS_ROUTE53_HOSTED_ZONE,
                "record_name": "example.com",
            },
        }
        level, _ = classify_aws_change(change)
        assert level in ("high", "critical")

    def test_cloudfront_waf_removed_is_high_or_critical(self):
        # Note: CloudFront classifier uses "previous_value" (M40 field naming convention)
        change = {
            "change_type": "modified",
            "field_path": "web_acl_id",
            "new_value": None,
            "previous_value": "arn:aws:wafv2:us-east-1:123:global/webacl/myACL/abc",
            "provider_metadata": {
                "record_type": AWS_CLOUDFRONT_DISTRIBUTION,
                "record_name": "d1234.cloudfront.net",
            },
        }
        level, reason = classify_aws_change(change)
        assert level in ("high", "critical")
        assert "waf" in reason.lower() or "acl" in reason.lower()
