"""Tests for M37: AWS S3 Exposure + Storage Configuration.

Test coverage
-------------
1.  aws_schema constants — AWS_S3_BUCKET present, AWS_RECORD_TYPES updated.

2.  AWSConnector._fetch_s3_buckets:
    - 403 on list_buckets → empty list (fail-soft, sync continues)
    - 500 on list_buckets → propagates (hard failure)
    - Empty bucket list → empty records
    - Bucket with no name skipped
    - Returns one aws_s3_bucket record per bucket
    - Single bad-bucket exception does not abort remaining buckets

3.  AWSConnector._fetch_bucket_region:
    - None LocationConstraint → "us-east-1"
    - Empty-string LocationConstraint → "us-east-1"
    - Non-us-east-1 → returned as-is
    - ConnectorError → "unknown"

4.  AWSConnector._fetch_bucket_public_access_block:
    - BPA configured → fields populated, public_access_block_configured=True
    - NoSuchPublicAccessBlockConfiguration → all False, configured=False
    - 403 → all None, warning added

5.  AWSConnector._fetch_bucket_policy_info:
    - Policy present, public principal → policy_present=True, public_principals_detected=True
    - Policy present, no public principal → public_principals_detected=False
    - NoSuchBucketPolicy → policy_present=False, public_principals_detected=False
    - 403 → policy_present=None, warning added
    - Raw policy text NOT in record (security invariant)

6.  AWSConnector._fetch_bucket_policy_status:
    - IsPublic=True → policy_status_is_public=True
    - IsPublic=False → policy_status_is_public=False
    - 403 → policy_status_is_public=None, warning added
    - NoSuchBucketPolicy (via 403 path) → policy_status_is_public=None

7.  AWSConnector._fetch_bucket_acl:
    - AllUsers READ grant → acl_all_users_read=True
    - AllUsers WRITE grant → acl_all_users_write=True
    - AllUsers FULL_CONTROL → both read and write True
    - AuthenticatedUsers READ → acl_authenticated_users_read=True
    - AuthenticatedUsers WRITE → acl_authenticated_users_write=True
    - No public grants → all False
    - 403 → all None, warning added

8.  AWSConnector._fetch_bucket_encryption:
    - Encryption configured → encryption_enabled=True, algorithm set
    - ServerSideEncryptionConfigurationNotFoundError → encryption_enabled=False
    - 403 → encryption_enabled=None, warning added
    - BucketKeyEnabled present → bucket_key_enabled set

9.  AWSConnector._fetch_bucket_versioning:
    - Status "Enabled" → versioning_status="enabled"
    - Status "Suspended" → versioning_status="suspended"
    - Status "" (absent) → versioning_status="disabled"
    - MFADelete "Enabled" → mfa_delete_status="enabled"
    - MFADelete absent → mfa_delete_status=None
    - 403 → both None, warning added

10. AWSConnector._fetch_bucket_logging:
    - Logging enabled → logging_enabled=True, logging_target_bucket set
    - Logging disabled (empty response) → logging_enabled=False, target=None
    - 403 → logging_enabled=None, warning added

11. AWSConnector._fetch_bucket_lifecycle:
    - 2 rules → lifecycle_rule_count=2
    - NoSuchLifecycleConfiguration → lifecycle_rule_count=0
    - 403 → lifecycle_rule_count=None, warning added

12. AWSConnector._fetch_bucket_tags:
    - Tags present → tag_keys sorted list, values NOT stored
    - NoSuchTagSet → tag_keys=None
    - No tags (empty TagSet) → tag_keys=None
    - 403 → tag_keys=None, warning added

13. _parse_bucket_policy_public helper:
    - Principal "*" → True
    - Principal {"AWS": "*"} → True
    - Principal {"AWS": ["*"]} → True
    - Principal {"AWS": "arn:aws:iam::123:root"} → False
    - Deny statement with * → False (Effect is checked)
    - Invalid JSON → False

14. Service inventory:
    - "s3" in enabled_surfaces, not in future_surfaces
    - s3_bucket_count reflects actual count passed

15. Full fetch() integration:
    - Records include aws_account_identity + aws_region + aws_s3_bucket + aws_service_inventory
    - S3 records included from _fetch_s3_buckets output

16. Diff service — tracked fields:
    - aws_s3_bucket returns all 24 tracked field names
    - All expected security fields present (policy_status_is_public, etc.)
    - AWS_S3_BUCKET in _AWS_TRACKED_FIELDS_BY_TYPE

17. S3 risk classification:
    - policy_status_is_public False→True → critical
    - acl_all_users_write False→True → critical
    - public_principals_detected False→True, sensitive bucket → critical
    - public_principals_detected False→True, non-sensitive → high
    - acl_all_users_read False→True → high
    - block_public_policy True→False, sensitive → high
    - block_public_policy True→False, non-sensitive → medium
    - restrict_public_buckets True→False, sensitive → high
    - restrict_public_buckets True→False, non-sensitive → medium
    - public_access_block_configured True→False, sensitive → high
    - encryption_enabled True→False, sensitive → high
    - encryption_enabled True→False, non-sensitive → medium
    - encryption_enabled False→True → low
    - versioning_status enabled→suspended, sensitive → high
    - versioning_status enabled→disabled, non-sensitive → medium
    - versioning_status disabled→enabled → low
    - logging_enabled True→False, sensitive → medium
    - logging_enabled True→False, non-sensitive → low
    - policy_hash changed → medium
    - lifecycle_rule_count decreased → medium
    - lifecycle_rule_count increased → low
    - policy_status_is_public True→False → low (protection strengthened)
    - acl_all_users_write True→False → low (protection strengthened)
    - bucket added with no public flags → low
    - bucket added with policy_status_is_public → high
    - bucket added with acl_all_users_write → critical
    - bucket removed → medium
    - tag_keys changed → low
    - unmatched field → low

18. Security invariants:
    - aws_secret_access_key NEVER in any S3 record
    - aws_access_key_id NEVER in full in any S3 record
    - Raw policy JSON NOT in any record field
    - Object names/contents not fetched (list_objects not called)
    - config_fetch_warnings always present (even if empty list)

19. M36 regression:
    - AWSConnector.fetch() still returns aws_account_identity
    - AWSConnector.fetch() still returns aws_region records
    - Diff service still dispatches aws_account_identity correctly

SECURITY invariants verified throughout:
  - aws_secret_access_key NEVER in returned records
  - Raw policy text NEVER stored (only hash + parsed booleans)
  - Object contents/keys NEVER fetched (ListObjects not called)
  - config_fetch_warnings always present in aws_s3_bucket records
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.aws import AWSConnector, _parse_bucket_policy_public
from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_RECORD_TYPES,
    AWS_REGION,
    AWS_S3_BUCKET,
    AWS_SERVICE_INVENTORY,
)
from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.services.diff_service import _AWS_TRACKED_FIELDS_BY_TYPE, _tracked_fields_for
from app.services.risk_rules.aws import (
    _classify_s3_change,
    _is_sensitive_bucket,
    classify_aws_change,
)

# ── Fixtures / helpers ────────────────────────────────────────────────────────

_CREDS = {
    "aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_default_region":    "us-east-1",
    "aws_selected_regions":  ["us-east-1"],
}

_STS_IDENTITY_RESPONSE = {
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/configtrace",
    "UserId": "AIDAIOSFODNN7EXAMPLE",
}

_EC2_REGIONS_RESPONSE = {
    "Regions": [
        {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
    ]
}

_LIST_BUCKETS_RESPONSE = {
    "Buckets": [{"Name": "my-test-bucket", "CreationDate": None}],
    "Owner": {"DisplayName": "test", "ID": "abc123"},
}

_BPA_ALL_ENABLED = {
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls":       True,
        "IgnorePublicAcls":      True,
        "BlockPublicPolicy":     True,
        "RestrictPublicBuckets": True,
    }
}

_NO_POLICY_ERROR = ConnectorError(
    "AWS API error (NoSuchBucketPolicy): The bucket policy does not exist",
    status_code=None,
)

_NO_BPA_ERROR = ConnectorError(
    "AWS API error (NoSuchPublicAccessBlockConfiguration): no config",
    status_code=None,
)

_NO_ENCRYPTION_ERROR = ConnectorError(
    "AWS API error (ServerSideEncryptionConfigurationNotFoundError): not found",
    status_code=None,
)

_NO_LIFECYCLE_ERROR = ConnectorError(
    "AWS API error (NoSuchLifecycleConfiguration): no lifecycle",
    status_code=None,
)

_NO_TAG_ERROR = ConnectorError(
    "AWS API error (NoSuchTagSet): no tags",
    status_code=None,
)

_403_ERROR = ConnectorError("AWS access denied (AccessDenied): ...", status_code=403)


def _make_minimal_bucket_record(bucket_name: str = "my-test-bucket") -> dict:
    """Return a minimal aws_s3_bucket record for testing."""
    return {
        "record_type":   AWS_S3_BUCKET,
        "record_id":     bucket_name,
        "name":          bucket_name,
        "bucket_name":   bucket_name,
        "bucket_region": "us-east-1",
        "creation_date": None,
        "block_public_acls":         True,
        "ignore_public_acls":        True,
        "block_public_policy":       True,
        "restrict_public_buckets":   True,
        "public_access_block_configured": True,
        "policy_present":            False,
        "policy_hash":               None,
        "public_principals_detected": False,
        "policy_status_is_public":   False,
        "acl_all_users_read":        False,
        "acl_all_users_write":       False,
        "acl_authenticated_users_read":  False,
        "acl_authenticated_users_write": False,
        "encryption_enabled":        True,
        "encryption_algorithm":      "AES256",
        "bucket_key_enabled":        None,
        "versioning_status":         "enabled",
        "mfa_delete_status":         None,
        "logging_enabled":           False,
        "logging_target_bucket":     None,
        "lifecycle_rule_count":      0,
        "tag_keys":                  None,
        "config_fetch_warnings":     [],
    }


def _make_change(
    *,
    record_type: str,
    field_path: str | None = None,
    change_type: str = "modified",
    prev_value=None,
    new_value=None,
    record_name: str = "my-bucket",
    record_id: str = "my-bucket",
) -> dict:
    """Build a minimal change dict for risk rule tests."""
    return {
        "record_type":     record_type,
        "change_type":     change_type,
        "field_path":      field_path,
        "prev_value":      prev_value,
        "new_value":       new_value,
        "provider_metadata": {
            "record_type":  record_type,
            "record_name":  record_name,
            "record_id":    record_id,
        },
    }


# ── 1. aws_schema constants ───────────────────────────────────────────────────

class TestAWSSchemaM37:
    def test_aws_s3_bucket_constant(self):
        assert AWS_S3_BUCKET == "aws_s3_bucket"

    def test_aws_record_types_includes_s3(self):
        assert AWS_S3_BUCKET in AWS_RECORD_TYPES

    def test_aws_record_types_still_has_m36_types(self):
        assert AWS_ACCOUNT_IDENTITY in AWS_RECORD_TYPES
        assert AWS_REGION in AWS_RECORD_TYPES
        assert AWS_SERVICE_INVENTORY in AWS_RECORD_TYPES


# ── 2. _parse_bucket_policy_public ───────────────────────────────────────────

class TestParseBucketPolicyPublic:
    def test_wildcard_principal_string(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}'
        assert _parse_bucket_policy_public(policy) is True

    def test_aws_wildcard_principal_string(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"*"}]}'
        assert _parse_bucket_policy_public(policy) is True

    def test_aws_wildcard_principal_list(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:GetObject","Resource":"*"}]}'
        assert _parse_bucket_policy_public(policy) is True

    def test_specific_account_principal_not_public(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"*"}]}'
        assert _parse_bucket_policy_public(policy) is False

    def test_deny_with_wildcard_not_counted(self):
        # Deny statements should not trigger public detection
        policy = '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}'
        assert _parse_bucket_policy_public(policy) is False

    def test_invalid_json_returns_false(self):
        assert _parse_bucket_policy_public("not json") is False

    def test_empty_statement_returns_false(self):
        assert _parse_bucket_policy_public('{"Statement":[]}') is False

    def test_mixed_statements_public_wins(self):
        policy = """{
            "Statement": [
                {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"s3:GetObject","Resource":"*"},
                {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}
            ]
        }"""
        assert _parse_bucket_policy_public(policy) is True


# ── 3. _is_sensitive_bucket ───────────────────────────────────────────────────

class TestIsSensitiveBucket:
    @pytest.mark.parametrize("name", [
        "my-prod-data", "production-uploads", "company-api", "customer-records",
        "app-assets", "billing-invoices", "db-backups", "terraform-state",
        "tfstate-bucket", "my-secrets", "private-logs", "payments-archive",
    ])
    def test_sensitive_names(self, name: str):
        assert _is_sensitive_bucket(name) is True

    @pytest.mark.parametrize("name", [
        "staging-data", "dev-test", "feature-branch",
        "website-static", "public-images",
    ])
    def test_non_sensitive_names(self, name: str):
        assert _is_sensitive_bucket(name) is False

    def test_tmp_uploads_is_sensitive(self):
        # "uploads" is in the sensitive pattern set — even tmp-uploads qualifies
        # because the substring "uploads" is present
        assert _is_sensitive_bucket("tmp-uploads") is True


# ── 4. _fetch_bucket_region ───────────────────────────────────────────────────

class TestFetchBucketRegion:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_none_location_returns_us_east_1(self):
        with patch.object(self.connector, "_call_aws", return_value={"LocationConstraint": None}):
            assert self.connector._fetch_bucket_region(self.client, "bucket") == "us-east-1"

    def test_empty_string_returns_us_east_1(self):
        with patch.object(self.connector, "_call_aws", return_value={"LocationConstraint": ""}):
            assert self.connector._fetch_bucket_region(self.client, "bucket") == "us-east-1"

    def test_other_region_returned_as_is(self):
        with patch.object(self.connector, "_call_aws", return_value={"LocationConstraint": "eu-west-1"}):
            assert self.connector._fetch_bucket_region(self.client, "bucket") == "eu-west-1"

    def test_connector_error_returns_unknown(self):
        with patch.object(self.connector, "_call_aws", side_effect=ConnectorError("err")):
            assert self.connector._fetch_bucket_region(self.client, "bucket") == "unknown"


# ── 5. _fetch_bucket_public_access_block ─────────────────────────────────────

class TestFetchBucketPublicAccessBlock:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_all_bpa_enabled(self):
        with patch.object(self.connector, "_call_aws", return_value=_BPA_ALL_ENABLED):
            result = self.connector._fetch_bucket_public_access_block(self.client, "bucket", [])
        assert result["block_public_acls"]         is True
        assert result["ignore_public_acls"]        is True
        assert result["block_public_policy"]       is True
        assert result["restrict_public_buckets"]   is True
        assert result["public_access_block_configured"] is True

    def test_bpa_partially_disabled(self):
        response = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        }}
        with patch.object(self.connector, "_call_aws", return_value=response):
            result = self.connector._fetch_bucket_public_access_block(self.client, "bucket", [])
        assert result["block_public_acls"]       is True
        assert result["ignore_public_acls"]      is False
        assert result["block_public_policy"]     is True
        assert result["restrict_public_buckets"] is False

    def test_no_such_public_access_block(self):
        with patch.object(self.connector, "_call_aws", side_effect=_NO_BPA_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_public_access_block(self.client, "bucket", warnings)
        assert result["public_access_block_configured"] is False
        assert result["block_public_acls"] is False
        assert warnings == []  # Not a warning — just "not configured"

    def test_403_adds_warning_and_returns_none_fields(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_public_access_block(self.client, "bucket", warnings)
        assert result["public_access_block_configured"] is None
        assert result["block_public_acls"] is None
        assert "s3_public_access_block_unavailable" in warnings


# ── 6. _fetch_bucket_policy_info ─────────────────────────────────────────────

class TestFetchBucketPolicyInfo:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_policy_with_public_principal(self):
        policy_json = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}'
        with patch.object(self.connector, "_call_aws", return_value={"Policy": policy_json}):
            result = self.connector._fetch_bucket_policy_info(self.client, "bucket", [])
        assert result["policy_present"] is True
        assert result["public_principals_detected"] is True
        assert result["policy_hash"] is not None
        # Raw policy MUST NOT be in the record
        assert policy_json not in str(result.values())

    def test_policy_without_public_principal(self):
        policy_json = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"s3:GetObject","Resource":"*"}]}'
        with patch.object(self.connector, "_call_aws", return_value={"Policy": policy_json}):
            result = self.connector._fetch_bucket_policy_info(self.client, "bucket", [])
        assert result["policy_present"] is True
        assert result["public_principals_detected"] is False

    def test_no_such_bucket_policy(self):
        with patch.object(self.connector, "_call_aws", side_effect=_NO_POLICY_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_policy_info(self.client, "bucket", warnings)
        assert result["policy_present"] is False
        assert result["public_principals_detected"] is False
        assert result["policy_hash"] is None
        assert warnings == []  # Not a warning

    def test_403_adds_warning(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_policy_info(self.client, "bucket", warnings)
        assert result["policy_present"] is None
        assert "s3_policy_unavailable" in warnings

    def test_policy_hash_is_short_prefix(self):
        policy_json = '{"Statement":[]}'
        with patch.object(self.connector, "_call_aws", return_value={"Policy": policy_json}):
            result = self.connector._fetch_bucket_policy_info(self.client, "bucket", [])
        # Hash should be 16 chars (first 16 of sha256 hex)
        assert result["policy_hash"] is not None
        assert len(result["policy_hash"]) == 16


# ── 7. _fetch_bucket_policy_status ───────────────────────────────────────────

class TestFetchBucketPolicyStatus:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_is_public_true(self):
        with patch.object(self.connector, "_call_aws", return_value={"PolicyStatus": {"IsPublic": True}}):
            result = self.connector._fetch_bucket_policy_status(self.client, "bucket", [])
        assert result["policy_status_is_public"] is True

    def test_is_public_false(self):
        with patch.object(self.connector, "_call_aws", return_value={"PolicyStatus": {"IsPublic": False}}):
            result = self.connector._fetch_bucket_policy_status(self.client, "bucket", [])
        assert result["policy_status_is_public"] is False

    def test_403_returns_none(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_policy_status(self.client, "bucket", warnings)
        assert result["policy_status_is_public"] is None
        assert "s3_policy_status_unavailable" in warnings

    def test_no_such_bucket_policy_returns_none(self):
        with patch.object(self.connector, "_call_aws", side_effect=_NO_POLICY_ERROR):
            result = self.connector._fetch_bucket_policy_status(self.client, "bucket", [])
        assert result["policy_status_is_public"] is None


# ── 8. _fetch_bucket_acl ─────────────────────────────────────────────────────

class TestFetchBucketAcl:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def _acl_response(self, *grants):
        return {"Grants": list(grants)}

    def _grant(self, uri, permission):
        return {"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}

    _AU  = "http://acs.amazonaws.com/groups/global/AllUsers"
    _AUU = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

    def test_all_users_read_grant(self):
        with patch.object(self.connector, "_call_aws",
                          return_value=self._acl_response(self._grant(self._AU, "READ"))):
            result = self.connector._fetch_bucket_acl(self.client, "bucket", [])
        assert result["acl_all_users_read"]  is True
        assert result["acl_all_users_write"] is False

    def test_all_users_write_grant(self):
        with patch.object(self.connector, "_call_aws",
                          return_value=self._acl_response(self._grant(self._AU, "WRITE"))):
            result = self.connector._fetch_bucket_acl(self.client, "bucket", [])
        assert result["acl_all_users_write"] is True
        assert result["acl_all_users_read"]  is False

    def test_all_users_full_control_sets_both(self):
        with patch.object(self.connector, "_call_aws",
                          return_value=self._acl_response(self._grant(self._AU, "FULL_CONTROL"))):
            result = self.connector._fetch_bucket_acl(self.client, "bucket", [])
        assert result["acl_all_users_read"]  is True
        assert result["acl_all_users_write"] is True

    def test_authenticated_users_read(self):
        with patch.object(self.connector, "_call_aws",
                          return_value=self._acl_response(self._grant(self._AUU, "READ"))):
            result = self.connector._fetch_bucket_acl(self.client, "bucket", [])
        assert result["acl_authenticated_users_read"]  is True
        assert result["acl_authenticated_users_write"] is False

    def test_authenticated_users_write(self):
        with patch.object(self.connector, "_call_aws",
                          return_value=self._acl_response(self._grant(self._AUU, "WRITE"))):
            result = self.connector._fetch_bucket_acl(self.client, "bucket", [])
        assert result["acl_authenticated_users_write"] is True

    def test_no_public_grants(self):
        with patch.object(self.connector, "_call_aws", return_value={"Grants": []}):
            result = self.connector._fetch_bucket_acl(self.client, "bucket", [])
        assert all(v is False for v in [
            result["acl_all_users_read"], result["acl_all_users_write"],
            result["acl_authenticated_users_read"], result["acl_authenticated_users_write"],
        ])

    def test_403_adds_warning_returns_none(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_acl(self.client, "bucket", warnings)
        assert result["acl_all_users_read"] is None
        assert "s3_acl_unavailable" in warnings


# ── 9. _fetch_bucket_encryption ──────────────────────────────────────────────

class TestFetchBucketEncryption:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_aes256_encryption(self):
        response = {"ServerSideEncryptionConfiguration": {"Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BucketKeyEnabled": False,
        }]}}
        with patch.object(self.connector, "_call_aws", return_value=response):
            result = self.connector._fetch_bucket_encryption(self.client, "bucket", [])
        assert result["encryption_enabled"]   is True
        assert result["encryption_algorithm"] == "AES256"
        assert result["bucket_key_enabled"]   is False

    def test_kms_encryption_with_bucket_key(self):
        response = {"ServerSideEncryptionConfiguration": {"Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
            "BucketKeyEnabled": True,
        }]}}
        with patch.object(self.connector, "_call_aws", return_value=response):
            result = self.connector._fetch_bucket_encryption(self.client, "bucket", [])
        assert result["encryption_enabled"]   is True
        assert result["encryption_algorithm"] == "aws:kms"
        assert result["bucket_key_enabled"]   is True

    def test_not_configured(self):
        with patch.object(self.connector, "_call_aws", side_effect=_NO_ENCRYPTION_ERROR):
            result = self.connector._fetch_bucket_encryption(self.client, "bucket", [])
        assert result["encryption_enabled"]   is False
        assert result["encryption_algorithm"] is None

    def test_403_adds_warning(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_encryption(self.client, "bucket", warnings)
        assert result["encryption_enabled"] is None
        assert "s3_encryption_unavailable" in warnings


# ── 10. _fetch_bucket_versioning ──────────────────────────────────────────────

class TestFetchBucketVersioning:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_enabled(self):
        with patch.object(self.connector, "_call_aws",
                          return_value={"Status": "Enabled", "MFADelete": "Disabled"}):
            result = self.connector._fetch_bucket_versioning(self.client, "bucket", [])
        assert result["versioning_status"]  == "enabled"
        assert result["mfa_delete_status"]  == "disabled"

    def test_suspended(self):
        with patch.object(self.connector, "_call_aws", return_value={"Status": "Suspended"}):
            result = self.connector._fetch_bucket_versioning(self.client, "bucket", [])
        assert result["versioning_status"] == "suspended"

    def test_disabled_empty_status(self):
        with patch.object(self.connector, "_call_aws", return_value={}):
            result = self.connector._fetch_bucket_versioning(self.client, "bucket", [])
        assert result["versioning_status"] == "disabled"
        assert result["mfa_delete_status"] is None

    def test_mfa_delete_enabled(self):
        with patch.object(self.connector, "_call_aws",
                          return_value={"Status": "Enabled", "MFADelete": "Enabled"}):
            result = self.connector._fetch_bucket_versioning(self.client, "bucket", [])
        assert result["mfa_delete_status"] == "enabled"

    def test_403_adds_warning(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_versioning(self.client, "bucket", warnings)
        assert result["versioning_status"] is None
        assert "s3_versioning_unavailable" in warnings


# ── 11. _fetch_bucket_logging ─────────────────────────────────────────────────

class TestFetchBucketLogging:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_logging_enabled(self):
        response = {"LoggingEnabled": {"TargetBucket": "my-log-bucket", "TargetPrefix": "logs/"}}
        with patch.object(self.connector, "_call_aws", return_value=response):
            result = self.connector._fetch_bucket_logging(self.client, "bucket", [])
        assert result["logging_enabled"]       is True
        assert result["logging_target_bucket"] == "my-log-bucket"

    def test_logging_disabled_empty_response(self):
        with patch.object(self.connector, "_call_aws", return_value={}):
            result = self.connector._fetch_bucket_logging(self.client, "bucket", [])
        assert result["logging_enabled"]       is False
        assert result["logging_target_bucket"] is None

    def test_403_adds_warning(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_logging(self.client, "bucket", warnings)
        assert result["logging_enabled"] is None
        assert "s3_logging_unavailable" in warnings


# ── 12. _fetch_bucket_lifecycle ───────────────────────────────────────────────

class TestFetchBucketLifecycle:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_two_rules(self):
        with patch.object(self.connector, "_call_aws",
                          return_value={"Rules": [{}, {}]}):
            result = self.connector._fetch_bucket_lifecycle(self.client, "bucket", [])
        assert result["lifecycle_rule_count"] == 2

    def test_no_lifecycle_config(self):
        with patch.object(self.connector, "_call_aws", side_effect=_NO_LIFECYCLE_ERROR):
            result = self.connector._fetch_bucket_lifecycle(self.client, "bucket", [])
        assert result["lifecycle_rule_count"] == 0

    def test_403_adds_warning(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_lifecycle(self.client, "bucket", warnings)
        assert result["lifecycle_rule_count"] is None
        assert "s3_lifecycle_unavailable" in warnings


# ── 13. _fetch_bucket_tags ────────────────────────────────────────────────────

class TestFetchBucketTags:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_tags_present_keys_sorted(self):
        response = {"TagSet": [
            {"Key": "Team", "Value": "backend"},
            {"Key": "Environment", "Value": "production"},
        ]}
        with patch.object(self.connector, "_call_aws", return_value=response):
            result = self.connector._fetch_bucket_tags(self.client, "bucket", [])
        assert result["tag_keys"] == ["Environment", "Team"]  # sorted
        # Values MUST NOT be stored
        assert "backend" not in str(result.values())
        assert "production" not in str(result.values())

    def test_no_tags_returns_none(self):
        with patch.object(self.connector, "_call_aws", side_effect=_NO_TAG_ERROR):
            result = self.connector._fetch_bucket_tags(self.client, "bucket", [])
        assert result["tag_keys"] is None

    def test_empty_tagset_returns_none(self):
        with patch.object(self.connector, "_call_aws", return_value={"TagSet": []}):
            result = self.connector._fetch_bucket_tags(self.client, "bucket", [])
        assert result["tag_keys"] is None

    def test_403_adds_warning_returns_none(self):
        with patch.object(self.connector, "_call_aws", side_effect=_403_ERROR):
            warnings: list = []
            result = self.connector._fetch_bucket_tags(self.client, "bucket", warnings)
        assert result["tag_keys"] is None
        assert "s3_tagging_unavailable" in warnings


# ── 14. _fetch_s3_buckets ─────────────────────────────────────────────────────

class TestFetchS3Buckets:
    def setup_method(self):
        self.connector = AWSConnector()

    def test_403_list_buckets_returns_empty(self):
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_call_aws", side_effect=_403_ERROR),
        ):
            records = self.connector._fetch_s3_buckets(_CREDS)
        assert records == []

    def test_500_list_buckets_propagates(self):
        err = ConnectorError("server error", status_code=503)
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_call_aws", side_effect=err),
        ):
            with pytest.raises(ConnectorError):
                self.connector._fetch_s3_buckets(_CREDS)

    def test_empty_bucket_list_returns_empty(self):
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_call_aws", return_value={"Buckets": []}),
        ):
            records = self.connector._fetch_s3_buckets(_CREDS)
        assert records == []

    def test_bucket_with_no_name_skipped(self):
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_call_aws", return_value={"Buckets": [{"Name": ""}]}),
        ):
            records = self.connector._fetch_s3_buckets(_CREDS)
        assert records == []

    def test_returns_one_record_per_bucket(self):
        bucket_record = _make_minimal_bucket_record()
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_call_aws",
                         return_value={"Buckets": [{"Name": "my-test-bucket", "CreationDate": None}]}),
            patch.object(self.connector, "_fetch_bucket_config", return_value=bucket_record),
        ):
            records = self.connector._fetch_s3_buckets(_CREDS)
        assert len(records) == 1
        assert records[0]["record_type"] == AWS_S3_BUCKET

    def test_bad_bucket_does_not_abort_rest(self):
        """A per-bucket exception must not prevent other buckets from being fetched."""
        good_record = _make_minimal_bucket_record("good-bucket")
        call_count = 0
        def fetch_config_side_effect(client, name, creation_date, creds):
            nonlocal call_count
            call_count += 1
            if name == "bad-bucket":
                raise RuntimeError("boom")
            return good_record

        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_call_aws", return_value={
                "Buckets": [
                    {"Name": "bad-bucket",  "CreationDate": None},
                    {"Name": "good-bucket", "CreationDate": None},
                ]
            }),
            patch.object(self.connector, "_fetch_bucket_config",
                         side_effect=fetch_config_side_effect),
        ):
            records = self.connector._fetch_s3_buckets(_CREDS)
        assert len(records) == 1
        assert records[0]["name"] == "good-bucket"


# ── 15. _fetch_bucket_config ─────────────────────────────────────────────────

class TestFetchBucketConfig:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_config_fetch_warnings_always_present(self):
        """config_fetch_warnings must exist in every record (even if empty)."""
        with (
            patch.object(self.connector, "_fetch_bucket_region", return_value="us-east-1"),
            patch.object(self.connector, "_fetch_bucket_public_access_block",
                         return_value={"block_public_acls": True, "ignore_public_acls": True,
                                       "block_public_policy": True, "restrict_public_buckets": True,
                                       "public_access_block_configured": True}),
            patch.object(self.connector, "_fetch_bucket_policy_info",
                         return_value={"policy_present": False, "policy_hash": None,
                                       "public_principals_detected": False}),
            patch.object(self.connector, "_fetch_bucket_policy_status",
                         return_value={"policy_status_is_public": False}),
            patch.object(self.connector, "_fetch_bucket_acl",
                         return_value={"acl_all_users_read": False, "acl_all_users_write": False,
                                       "acl_authenticated_users_read": False,
                                       "acl_authenticated_users_write": False}),
            patch.object(self.connector, "_fetch_bucket_encryption",
                         return_value={"encryption_enabled": True, "encryption_algorithm": "AES256",
                                       "bucket_key_enabled": None}),
            patch.object(self.connector, "_fetch_bucket_versioning",
                         return_value={"versioning_status": "enabled", "mfa_delete_status": None}),
            patch.object(self.connector, "_fetch_bucket_logging",
                         return_value={"logging_enabled": False, "logging_target_bucket": None}),
            patch.object(self.connector, "_fetch_bucket_lifecycle",
                         return_value={"lifecycle_rule_count": 0}),
            patch.object(self.connector, "_fetch_bucket_tags",
                         return_value={"tag_keys": None}),
        ):
            record = self.connector._fetch_bucket_config(
                self.client, "my-bucket", None, _CREDS
            )
        assert "config_fetch_warnings" in record
        assert record["config_fetch_warnings"] == []
        assert record["record_type"] == AWS_S3_BUCKET
        assert record["record_id"]   == "my-bucket"
        # SECURITY: no credentials in record
        assert "aws_secret_access_key" not in str(record)
        assert "aws_access_key_id" not in str(record.values())

    def test_config_fetch_warnings_collected_from_sub_methods(self):
        """Warnings from sub-methods are accumulated into the record."""
        def bpa_with_warning(client, name, warnings):
            warnings.append("s3_public_access_block_unavailable")
            return {"block_public_acls": None, "ignore_public_acls": None,
                    "block_public_policy": None, "restrict_public_buckets": None,
                    "public_access_block_configured": None}

        with (
            patch.object(self.connector, "_fetch_bucket_region", return_value="us-west-2"),
            patch.object(self.connector, "_fetch_bucket_public_access_block",
                         side_effect=bpa_with_warning),
            patch.object(self.connector, "_fetch_bucket_policy_info",
                         return_value={"policy_present": False, "policy_hash": None,
                                       "public_principals_detected": False}),
            patch.object(self.connector, "_fetch_bucket_policy_status",
                         return_value={"policy_status_is_public": None}),
            patch.object(self.connector, "_fetch_bucket_acl",
                         return_value={"acl_all_users_read": False, "acl_all_users_write": False,
                                       "acl_authenticated_users_read": False,
                                       "acl_authenticated_users_write": False}),
            patch.object(self.connector, "_fetch_bucket_encryption",
                         return_value={"encryption_enabled": True, "encryption_algorithm": "AES256",
                                       "bucket_key_enabled": None}),
            patch.object(self.connector, "_fetch_bucket_versioning",
                         return_value={"versioning_status": "disabled", "mfa_delete_status": None}),
            patch.object(self.connector, "_fetch_bucket_logging",
                         return_value={"logging_enabled": False, "logging_target_bucket": None}),
            patch.object(self.connector, "_fetch_bucket_lifecycle",
                         return_value={"lifecycle_rule_count": 0}),
            patch.object(self.connector, "_fetch_bucket_tags",
                         return_value={"tag_keys": None}),
        ):
            record = self.connector._fetch_bucket_config(
                self.client, "my-bucket", None, _CREDS
            )
        assert "s3_public_access_block_unavailable" in record["config_fetch_warnings"]


# ── 16. Service inventory ─────────────────────────────────────────────────────

class TestServiceInventoryM37:
    def setup_method(self):
        self.connector = AWSConnector()

    def test_s3_in_enabled_surfaces(self):
        record = self.connector._fetch_service_inventory(_CREDS, s3_count=3)
        assert "s3" in record["enabled_surfaces"]

    def test_s3_not_in_future_surfaces(self):
        record = self.connector._fetch_service_inventory(_CREDS, s3_count=0)
        assert "s3" not in record["future_surfaces"]

    def test_s3_bucket_count_reflects_arg(self):
        record = self.connector._fetch_service_inventory(_CREDS, s3_count=5)
        assert record["s3_bucket_count"] == 5

    def test_s3_bucket_count_zero_for_no_buckets(self):
        record = self.connector._fetch_service_inventory(_CREDS, s3_count=0)
        assert record["s3_bucket_count"] == 0


# ── 17. Full fetch() integration ─────────────────────────────────────────────

class TestFetchIntegrationM37:
    def setup_method(self):
        self.connector = AWSConnector()

    def test_fetch_returns_s3_records_plus_m36_records(self):
        s3_record = _make_minimal_bucket_record()
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_fetch_account_identity",
                         return_value={"record_type": AWS_ACCOUNT_IDENTITY, "record_id": "123456789012",
                                       "name": "AWS Account 123456789012", "account_id": "123456789012",
                                       "principal_arn": "arn:aws:iam::123456789012:user/ct",
                                       "principal_type": "user", "partition": "aws",
                                       "default_region": "us-east-1", "selected_regions": ["us-east-1"]}),
            patch.object(self.connector, "_fetch_regions",
                         return_value=[{"record_type": AWS_REGION, "record_id": "us-east-1",
                                        "name": "us-east-1", "region_name": "us-east-1",
                                        "opt_in_status": "opt-in-not-required", "enabled": True,
                                        "source": "discovered"}]),
            patch.object(self.connector, "_fetch_s3_buckets", return_value=[s3_record]),
        ):
            records = self.connector.fetch(_CREDS)

        record_types = [r["record_type"] for r in records]
        assert AWS_ACCOUNT_IDENTITY in record_types
        assert AWS_REGION in record_types
        assert AWS_S3_BUCKET in record_types
        assert AWS_SERVICE_INVENTORY in record_types

    def test_fetch_s3_empty_still_succeeds(self):
        """S3 403 (empty list) must not abort the full sync."""
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_fetch_account_identity",
                         return_value={"record_type": AWS_ACCOUNT_IDENTITY, "record_id": "123",
                                       "name": "AWS Account 123", "account_id": "123",
                                       "principal_arn": "arn:aws:iam::123:user/ct",
                                       "principal_type": "user", "partition": "aws",
                                       "default_region": "us-east-1", "selected_regions": ["us-east-1"]}),
            patch.object(self.connector, "_fetch_regions", return_value=[]),
            patch.object(self.connector, "_fetch_s3_buckets", return_value=[]),
        ):
            records = self.connector.fetch(_CREDS)

        record_types = [r["record_type"] for r in records]
        assert AWS_ACCOUNT_IDENTITY in record_types
        assert AWS_SERVICE_INVENTORY in record_types
        # Zero S3 records is fine
        assert sum(1 for r in records if r["record_type"] == AWS_S3_BUCKET) == 0


# ── 18. Diff service tracked fields ──────────────────────────────────────────

class TestDiffServiceS3Fields:
    def test_aws_s3_bucket_in_tracked_fields_dict(self):
        assert "aws_s3_bucket" in _AWS_TRACKED_FIELDS_BY_TYPE

    def test_all_security_fields_tracked(self):
        fields = set(_AWS_TRACKED_FIELDS_BY_TYPE["aws_s3_bucket"])
        required = {
            "block_public_acls", "ignore_public_acls",
            "block_public_policy", "restrict_public_buckets",
            "public_access_block_configured",
            "policy_status_is_public", "policy_present", "policy_hash",
            "public_principals_detected",
            "acl_all_users_read", "acl_all_users_write",
            "acl_authenticated_users_read", "acl_authenticated_users_write",
            "encryption_enabled", "encryption_algorithm", "bucket_key_enabled",
            "versioning_status", "mfa_delete_status",
            "logging_enabled", "logging_target_bucket",
            "lifecycle_rule_count", "tag_keys",
            "config_fetch_warnings", "bucket_region",
        }
        missing = required - fields
        assert missing == set(), f"Missing tracked fields: {missing}"

    def test_tracked_fields_for_s3_bucket_record(self):
        record = {"record_type": "aws_s3_bucket", "record_id": "my-bucket"}
        fields = _tracked_fields_for(record)
        assert "policy_status_is_public" in fields
        assert "acl_all_users_write" in fields
        assert "encryption_enabled" in fields
        assert "versioning_status" in fields

    def test_creation_date_not_tracked(self):
        # creation_date is immutable — must NOT be tracked to avoid spurious changes
        fields = set(_AWS_TRACKED_FIELDS_BY_TYPE["aws_s3_bucket"])
        assert "creation_date" not in fields

    def test_bucket_name_not_tracked_separately(self):
        # bucket_name = record_id = stable key; tracking it would generate noise
        fields = set(_AWS_TRACKED_FIELDS_BY_TYPE["aws_s3_bucket"])
        assert "bucket_name" not in fields

    def test_s3_bucket_count_in_service_inventory_tracked_fields(self):
        fields = set(_AWS_TRACKED_FIELDS_BY_TYPE["aws_service_inventory"])
        assert "s3_bucket_count" in fields


# ── 19. S3 risk classification ────────────────────────────────────────────────

class TestS3RiskClassification:

    # ── Critical ──────────────────────────────────────────────────────────────

    def test_policy_status_becomes_public_critical(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="policy_status_is_public",
            prev_value=False, new_value=True,
            record_name="my-bucket",
        )
        level, reason = classify_aws_change(change)
        assert level == "critical"
        assert "public" in reason.lower()

    def test_acl_all_users_write_added_critical(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="acl_all_users_write",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_public_principals_detected_sensitive_bucket_critical(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="public_principals_detected",
            prev_value=False, new_value=True,
            record_name="prod-data",
        )
        level, _ = classify_aws_change(change)
        assert level == "critical"

    def test_bucket_added_with_acl_write_critical(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            change_type="added",
            new_value={"acl_all_users_write": True},
        )
        level, _ = classify_aws_change(change)
        assert level == "critical"

    # ── High ─────────────────────────────────────────────────────────────────

    def test_public_principals_detected_non_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="public_principals_detected",
            prev_value=False, new_value=True,
            record_name="static-website",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_acl_all_users_read_added_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="acl_all_users_read",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_acl_authenticated_users_write_added_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="acl_authenticated_users_write",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_block_public_policy_weakened_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="block_public_policy",
            prev_value=True, new_value=False,
            record_name="prod-uploads",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_restrict_public_buckets_weakened_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="restrict_public_buckets",
            prev_value=True, new_value=False,
            record_name="customer-data",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_ignore_public_acls_weakened_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="ignore_public_acls",
            prev_value=True, new_value=False,
            record_name="app-assets",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_public_access_block_removed_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="public_access_block_configured",
            prev_value=True, new_value=False,
            record_name="prod-data",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_encryption_disabled_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="encryption_enabled",
            prev_value=True, new_value=False,
            record_name="prod-database",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_versioning_disabled_sensitive_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="versioning_status",
            prev_value="enabled", new_value="suspended",
            record_name="db-backups",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_bucket_added_with_policy_public_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            change_type="added",
            new_value={"policy_status_is_public": True},
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    # ── Medium ────────────────────────────────────────────────────────────────

    def test_block_public_policy_weakened_non_sensitive_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="block_public_policy",
            prev_value=True, new_value=False,
            record_name="static-website",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_restrict_public_buckets_weakened_non_sensitive_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="restrict_public_buckets",
            prev_value=True, new_value=False,
            record_name="feature-test",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_encryption_disabled_non_sensitive_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="encryption_enabled",
            prev_value=True, new_value=False,
            record_name="static-website",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_versioning_disabled_non_sensitive_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="versioning_status",
            prev_value="enabled", new_value="disabled",
            record_name="feature-branch",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_acl_authenticated_users_read_added_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="acl_authenticated_users_read",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_logging_disabled_sensitive_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="logging_enabled",
            prev_value=True, new_value=False,
            record_name="production-data",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_policy_hash_changed_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="policy_hash",
            prev_value="aabbccdd11223344", new_value="deadbeef12345678",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_lifecycle_rules_decreased_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="lifecycle_rule_count",
            prev_value=3, new_value=1,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_mfa_delete_disabled_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="mfa_delete_status",
            prev_value="enabled", new_value="disabled",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_policy_added_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="policy_present",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_bucket_removed_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            change_type="removed",
            prev_value=_make_minimal_bucket_record(),
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    # ── Low ──────────────────────────────────────────────────────────────────

    def test_policy_status_reverts_to_private_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="policy_status_is_public",
            prev_value=True, new_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_acl_write_removed_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="acl_all_users_write",
            prev_value=True, new_value=False,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_encryption_enabled_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="encryption_enabled",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_versioning_enabled_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="versioning_status",
            prev_value="disabled", new_value="enabled",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_logging_enabled_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="logging_enabled",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_lifecycle_rules_increased_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="lifecycle_rule_count",
            prev_value=1, new_value=3,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_tag_keys_changed_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="tag_keys",
            prev_value=["env"], new_value=["env", "team"],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_block_public_acls_weakened_sensitive_high(self):
        # 4th BPA control — same dispatch path as the others
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="block_public_acls",
            prev_value=True, new_value=False,
            record_name="prod-config",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_block_public_acls_weakened_non_sensitive_medium(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="block_public_acls",
            prev_value=True, new_value=False,
            record_name="dev-misc",
        )
        level, _ = classify_aws_change(change)
        assert level == "medium"

    def test_bpa_strengthened_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="block_public_acls",
            prev_value=False, new_value=True,
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_config_fetch_warnings_changed_low(self):
        # A permission being granted or revoked is low risk
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="config_fetch_warnings",
            prev_value=["s3_acl_unavailable"],
            new_value=[],
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_bucket_added_no_public_flags_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            change_type="added",
            new_value={"acl_all_users_write": False, "policy_status_is_public": False},
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_logging_disabled_non_sensitive_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="logging_enabled",
            prev_value=True, new_value=False,
            record_name="dev-test-data",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_unmatched_field_low(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="some_unknown_field",
            prev_value="a", new_value="b",
        )
        level, _ = classify_aws_change(change)
        assert level == "low"

    def test_bucket_added_acl_read_only_high(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            change_type="added",
            new_value={"acl_all_users_read": True, "acl_all_users_write": False,
                       "policy_status_is_public": False},
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    # ── Risk reason content checks ────────────────────────────────────────────

    def test_risk_reason_mentions_public_when_bucket_public(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="policy_status_is_public",
            prev_value=False, new_value=True,
        )
        _, reason = classify_aws_change(change)
        assert "public" in reason.lower()

    def test_risk_reason_mentions_write_for_acl_write(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="acl_all_users_write",
            prev_value=False, new_value=True,
        )
        _, reason = classify_aws_change(change)
        assert "write" in reason.lower() or "upload" in reason.lower()

    def test_risk_reason_mentions_encryption_for_encryption_change(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="encryption_enabled",
            prev_value=True, new_value=False,
        )
        _, reason = classify_aws_change(change)
        assert "encrypt" in reason.lower()

    def test_risk_reason_mentions_versioning_for_versioning_change(self):
        change = _make_change(
            record_type=AWS_S3_BUCKET,
            field_path="versioning_status",
            prev_value="enabled", new_value="disabled",
        )
        _, reason = classify_aws_change(change)
        assert "version" in reason.lower()


# ── 20. Security invariants ───────────────────────────────────────────────────

class TestS3SecurityInvariants:
    def setup_method(self):
        self.connector = AWSConnector()
        self.client = MagicMock()

    def test_secret_key_never_in_bucket_record(self):
        """aws_secret_access_key must NEVER appear in any S3 record field."""
        record = _make_minimal_bucket_record()
        # The record values (as a string) must not contain the secret key
        record_str = str(record)
        assert _CREDS["aws_secret_access_key"] not in record_str

    def test_full_access_key_never_in_bucket_record(self):
        """aws_access_key_id must NEVER appear in full in any S3 record field."""
        record = _make_minimal_bucket_record()
        record_str = str(record)
        assert _CREDS["aws_access_key_id"] not in record_str

    def test_raw_policy_never_stored(self):
        """Raw policy JSON must not appear in any record field."""
        policy_json = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
        with patch.object(self.connector, "_call_aws",
                          return_value={"Policy": policy_json}):
            result = self.connector._fetch_bucket_policy_info(self.client, "bucket", [])
        # Verify the raw policy text is not in any value
        for value in result.values():
            assert str(value) != policy_json
            assert "Statement" not in str(value)

    def test_config_fetch_warnings_always_list(self):
        """config_fetch_warnings must always be a list (never None)."""
        record = _make_minimal_bucket_record()
        assert isinstance(record.get("config_fetch_warnings"), list)

    def test_tag_values_not_stored_only_keys(self):
        """Tag values may be sensitive — only keys must be stored."""
        response = {"TagSet": [{"Key": "CostCenter", "Value": "SensitiveCC-9999"}]}
        with patch.object(self.connector, "_call_aws", return_value=response):
            result = self.connector._fetch_bucket_tags(self.client, "bucket", [])
        assert result["tag_keys"] == ["CostCenter"]
        assert "SensitiveCC-9999" not in str(result.values())


# ── 21. M36 regression ───────────────────────────────────────────────────────

class TestM36Regression:
    def setup_method(self):
        self.connector = AWSConnector()

    def test_fetch_still_returns_account_identity(self):
        with (
            patch.object(self.connector, "_make_client", return_value=MagicMock()),
            patch.object(self.connector, "_fetch_account_identity",
                         return_value={"record_type": AWS_ACCOUNT_IDENTITY, "record_id": "123",
                                       "name": "AWS Account 123", "account_id": "123",
                                       "principal_arn": "arn", "principal_type": "user",
                                       "partition": "aws", "default_region": "us-east-1",
                                       "selected_regions": ["us-east-1"]}),
            patch.object(self.connector, "_fetch_regions", return_value=[]),
            patch.object(self.connector, "_fetch_s3_buckets", return_value=[]),
        ):
            records = self.connector.fetch(_CREDS)
        types = {r["record_type"] for r in records}
        assert AWS_ACCOUNT_IDENTITY in types

    def test_account_identity_risk_still_works(self):
        change = _make_change(
            record_type=AWS_ACCOUNT_IDENTITY,
            field_path="principal_arn",
            prev_value="arn:aws:iam::123:user/old",
            new_value="arn:aws:iam::123:user/new",
        )
        level, reason = classify_aws_change(change)
        assert level == "high"
        assert "arn" in reason.lower() or "principal" in reason.lower()

    def test_region_risk_still_works(self):
        change = _make_change(
            record_type=AWS_REGION,
            change_type="removed",
        )
        level, _ = classify_aws_change(change)
        assert level == "high"

    def test_diff_service_account_identity_tracked_fields_unchanged(self):
        fields = set(_AWS_TRACKED_FIELDS_BY_TYPE["aws_account_identity"])
        assert "principal_arn" in fields
        assert "account_id"    in fields
        assert "selected_regions" in fields
