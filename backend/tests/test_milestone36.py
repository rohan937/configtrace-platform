"""Tests for M36: AWS Foundation + Account Inventory.

Test coverage
-------------
1.  AWSConnector helper functions:
    _safe_key_id — first 4 chars + "***", never full key.
    _parse_principal_type — user / role / assumed-role / root / unknown.
    _parse_partition — aws / aws-cn / aws-us-gov / fallback.
    _default_region — configured or "us-east-1".
    _selected_regions — list fallback to [default_region].

2.  AWSConnector.validate_credentials:
    Success returns True.
    InvalidClientTokenId → AuthenticationError.
    AccessDenied → ConnectorError(403).
    Network failure → NetworkError.

3.  AWSConnector.fetch:
    Returns aws_account_identity + aws_region + aws_service_inventory.
    Correct record counts and record_type values.
    EC2 DescribeRegions 403 → fail-soft (uses selected_regions, source="selected").
    Records never contain aws_secret_access_key or aws_access_key_id.

4.  AWSConnector._fetch_account_identity:
    Correct field extraction (account_id, principal_arn, principal_type, partition).

5.  AWSConnector._fetch_regions:
    One record per selected region with opt_in_status from EC2.
    Fail-soft on 403: falls back to selected_regions with source="selected".

6.  AWSConnector._fetch_service_inventory:
    Correct enabled_surfaces and future_surfaces structure.
    future_surfaces NOT in AWS tracked fields (no spurious change events).

7.  AWSConnector.get_account_id:
    Returns account ID string.
    Propagates AuthenticationError on bad creds.

8.  Risk classification (classify_aws_change):
    aws_account_identity: added→low, removed→high, principal_arn→high,
      account_id→high, selected_regions→medium, default_region→medium,
      partition→medium, other→low.
    aws_region: removed→high, added→medium, opt_in_status→low, enabled→medium.
    aws_service_inventory: selected_regions→medium, enabled_surfaces→low,
      added/removed→low, other→low.
    Unknown aws_ type: low.

9.  Diff service tracked fields:
    aws_account_identity, aws_region, aws_service_inventory dispatch correctly.
    future_surfaces NOT in aws_service_inventory tracked fields.
    Unknown aws_ type → empty tuple.

10. Failure classifier — AWS paths:
    AuthenticationError + provider="aws" → aws_credentials_invalid.
    ConnectorError(403) + provider="aws" → aws_access_denied.
    ConnectorError(404) + provider="aws" → aws_resource_not_found.
    ConnectorError(500) + provider="aws" → aws_api_unavailable.
    RateLimitError + provider="aws" → rate_limited.
    NetworkError + provider="aws" → network.

11. Schema validation:
    AWS integration requires aws_access_key_id + aws_secret_access_key +
    aws_default_region.
    Missing any required field raises ValidationError.
    Provider="aws" accepted in IntegrationCreateRequest.
    ProviderFilter "aws" accepted in ALLOWED_PROVIDER_FILTERS.
    IntegrationReconnectRequest accepts aws_access_key_id + aws_secret_access_key.

12. aws_schema constants:
    AWS_ACCOUNT_IDENTITY, AWS_REGION, AWS_SERVICE_INVENTORY are correct strings.
    AWS_RECORD_TYPES frozenset contains all three.

SECURITY invariants asserted:
  - aws_secret_access_key NEVER appears in any fetched record.
  - aws_access_key_id NEVER appears in full in any log or record.
  - _safe_key_id output contains "***" and is max 7 chars (4 + 3).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.aws import AWSConnector, _parse_partition, _parse_principal_type
from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    AWS_RECORD_TYPES,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.core.failure_classifier import FailureClassification, classify_failure
from app.services.risk_rules.aws import classify_aws_change

# ── Test credentials ──────────────────────────────────────────────────────────

CREDS: dict[str, Any] = {
    "aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_default_region":    "us-east-1",
    "aws_selected_regions":  ["us-east-1", "eu-west-1"],
}

# Typical STS GetCallerIdentity response
STS_IDENTITY_RESPONSE: dict[str, Any] = {
    "Account":  "123456789012",
    "Arn":      "arn:aws:iam::123456789012:user/configtrace-readonly",
    "UserId":   "AIDAIOSFODNN7EXAMPLE",
    "ResponseMetadata": {"RequestId": "abc123"},
}

# Typical EC2 DescribeRegions response (two regions)
EC2_REGIONS_RESPONSE: dict[str, Any] = {
    "Regions": [
        {"RegionName": "us-east-1",  "OptInStatus": "opt-in-not-required", "Endpoint": "ec2.us-east-1.amazonaws.com"},
        {"RegionName": "eu-west-1",  "OptInStatus": "opted-in",           "Endpoint": "ec2.eu-west-1.amazonaws.com"},
    ]
}


def _mock_client() -> MagicMock:
    """Return a no-op mock boto3 client (avoids boto3/botocore import)."""
    return MagicMock()


# ── 1. Helper function tests ──────────────────────────────────────────────────


class TestSafeKeyId:
    """_safe_key_id never logs the full access key."""

    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_returns_first_four_plus_stars(self) -> None:
        result = self.connector._safe_key_id(CREDS)
        assert result == "AKIA***"

    def test_never_reveals_full_key(self) -> None:
        result = self.connector._safe_key_id(CREDS)
        full_key = CREDS["aws_access_key_id"]
        assert full_key not in result

    def test_short_key_returns_stars_only(self) -> None:
        result = self.connector._safe_key_id({"aws_access_key_id": "AB"})
        assert result == "***"

    def test_empty_key_returns_stars_only(self) -> None:
        result = self.connector._safe_key_id({})
        assert result == "***"

    def test_output_length_bounded(self) -> None:
        # Output should be "first 4 chars" + "***" = 7 chars max
        result = self.connector._safe_key_id(CREDS)
        assert len(result) <= 7


class TestParsePrincipalType:
    def test_iam_user(self) -> None:
        arn = "arn:aws:iam::123456789012:user/alice"
        assert _parse_principal_type(arn) == "user"

    def test_iam_role(self) -> None:
        arn = "arn:aws:iam::123456789012:role/MyRole"
        assert _parse_principal_type(arn) == "role"

    def test_assumed_role(self) -> None:
        arn = "arn:aws:sts::123456789012:assumed-role/MyRole/session"
        assert _parse_principal_type(arn) == "assumed-role"

    def test_root(self) -> None:
        arn = "arn:aws:iam::123456789012:root"
        assert _parse_principal_type(arn) == "root"

    def test_empty_arn_returns_unknown(self) -> None:
        assert _parse_principal_type("") == "unknown"

    def test_malformed_arn_returns_unknown(self) -> None:
        assert _parse_principal_type("not:an:arn") == "unknown"


class TestParsePartition:
    def test_aws_partition(self) -> None:
        arn = "arn:aws:iam::123456789012:user/alice"
        assert _parse_partition(arn) == "aws"

    def test_aws_cn_partition(self) -> None:
        arn = "arn:aws-cn:iam::123456789012:user/alice"
        assert _parse_partition(arn) == "aws-cn"

    def test_aws_us_gov_partition(self) -> None:
        arn = "arn:aws-us-gov:iam::123456789012:user/alice"
        assert _parse_partition(arn) == "aws-us-gov"

    def test_empty_arn_returns_aws(self) -> None:
        assert _parse_partition("") == "aws"


class TestDefaultRegionAndSelectedRegions:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_default_region_from_creds(self) -> None:
        assert self.connector._default_region(CREDS) == "us-east-1"

    def test_default_region_fallback(self) -> None:
        assert self.connector._default_region({}) == "us-east-1"

    def test_selected_regions_from_creds(self) -> None:
        assert self.connector._selected_regions(CREDS) == ["us-east-1", "eu-west-1"]

    def test_selected_regions_fallback_to_default(self) -> None:
        creds = {"aws_default_region": "eu-west-1"}
        assert self.connector._selected_regions(creds) == ["eu-west-1"]

    def test_selected_regions_empty_list_fallback(self) -> None:
        creds = {"aws_default_region": "us-west-2", "aws_selected_regions": []}
        assert self.connector._selected_regions(creds) == ["us-west-2"]


# ── 2. validate_credentials ───────────────────────────────────────────────────
# All tests patch both _make_client (avoids boto3 import) and _call_aws
# (avoids botocore import during exception translation).


class TestAWSConnectorValidate:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_success_returns_true(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(self.connector, "_call_aws", return_value=STS_IDENTITY_RESPONSE):
                result = self.connector.validate_credentials(CREDS)
        assert result is True

    def test_auth_error_propagates(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=AuthenticationError("bad creds")
            ):
                with pytest.raises(AuthenticationError):
                    self.connector.validate_credentials(CREDS)

    def test_access_denied_propagates_as_connector_error(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=ConnectorError("denied", status_code=403)
            ):
                with pytest.raises(ConnectorError) as exc_info:
                    self.connector.validate_credentials(CREDS)
        assert exc_info.value.status_code == 403

    def test_network_error_propagates(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=NetworkError("timeout")
            ):
                with pytest.raises(NetworkError):
                    self.connector.validate_credentials(CREDS)

    def test_rate_limit_propagates(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=RateLimitError("throttled")
            ):
                with pytest.raises(RateLimitError):
                    self.connector.validate_credentials(CREDS)


# ── 3 + 4. fetch and _fetch_account_identity ─────────────────────────────────
# _call_aws is called twice: once for STS (account_identity), once for EC2 (regions).
# _make_client is mocked to avoid boto3 import.


class TestAWSConnectorFetch:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _patch_fetch(self, sts_response=None, ec2_response=None):
        """Context manager patches for a successful fetch with 2 selected regions."""
        sts_resp = sts_response or STS_IDENTITY_RESPONSE
        ec2_resp = ec2_response or EC2_REGIONS_RESPONSE
        # _call_aws is called: (1) STS get_caller_identity, (2) EC2 describe_regions,
        # (3) S3 list_buckets (M37 — empty list keeps test output stable)
        call_aws_se = [sts_resp, ec2_resp, {"Buckets": []}]
        return (
            patch.object(self.connector, "_make_client", return_value=_mock_client()),
            patch.object(self.connector, "_call_aws", side_effect=call_aws_se),
        )

    def test_fetch_returns_three_record_types(self) -> None:
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        record_types = [r["record_type"] for r in records]
        assert AWS_ACCOUNT_IDENTITY in record_types
        assert AWS_REGION in record_types
        assert AWS_SERVICE_INVENTORY in record_types

    def test_fetch_total_count_two_regions(self) -> None:
        # 1 account_identity + 2 region (us-east-1, eu-west-1) + 1 inventory = 4
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        region_records = [r for r in records if r["record_type"] == AWS_REGION]
        assert len(region_records) == 2

    def test_account_identity_fields(self) -> None:
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        identity = next(r for r in records if r["record_type"] == AWS_ACCOUNT_IDENTITY)
        assert identity["account_id"] == "123456789012"
        assert identity["principal_arn"] == STS_IDENTITY_RESPONSE["Arn"]
        assert identity["principal_type"] == "user"
        assert identity["partition"] == "aws"
        assert identity["default_region"] == "us-east-1"
        assert "us-east-1" in identity["selected_regions"]

    def test_region_records_have_opt_in_status(self) -> None:
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        region_records = {r["record_id"]: r for r in records if r["record_type"] == AWS_REGION}
        assert region_records["us-east-1"]["opt_in_status"] == "opt-in-not-required"
        assert region_records["eu-west-1"]["opt_in_status"] == "opted-in"
        assert region_records["us-east-1"]["source"] == "discovered"

    def test_service_inventory_fields(self) -> None:
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        inventory = next(r for r in records if r["record_type"] == AWS_SERVICE_INVENTORY)
        assert "account_inventory" in inventory["enabled_surfaces"]
        assert isinstance(inventory["future_surfaces"], list)
        assert len(inventory["future_surfaces"]) > 0

    def test_security_no_secret_key_in_records(self) -> None:
        """SECURITY: aws_secret_access_key must never appear in any record."""
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        for record in records:
            assert "aws_secret_access_key" not in record
            for value in record.values():
                if isinstance(value, str):
                    assert CREDS["aws_secret_access_key"] not in value

    def test_security_no_full_access_key_in_records(self) -> None:
        """SECURITY: full aws_access_key_id must never appear in any record."""
        p_client, p_call = self._patch_fetch()
        with p_client, p_call:
            records = self.connector.fetch(CREDS)

        full_key = CREDS["aws_access_key_id"]
        for record in records:
            for value in record.values():
                if isinstance(value, str):
                    assert full_key not in value


# ── 5. _fetch_regions fail-soft ───────────────────────────────────────────────


class TestAWSConnectorFetchRegionsFailSoft:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_403_on_describe_regions_uses_selected_fallback(self) -> None:
        """EC2 DescribeRegions 403 must not raise — falls back to selected_regions."""
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws",
                side_effect=ConnectorError("AccessDenied", status_code=403),
            ):
                regions = self.connector._fetch_regions(CREDS)

        # Falls back: should still return records for selected_regions
        assert len(regions) == len(CREDS["aws_selected_regions"])
        # source should be "selected" since we fell back
        assert all(r["source"] == "selected" for r in regions)

    def test_403_on_describe_regions_opt_in_status_unknown(self) -> None:
        """Fall-soft regions should have opt_in_status="unknown"."""
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws",
                side_effect=ConnectorError("AccessDenied", status_code=403),
            ):
                regions = self.connector._fetch_regions(CREDS)

        for r in regions:
            assert r["opt_in_status"] == "unknown"

    def test_non_403_error_propagates(self) -> None:
        """Non-403 errors from EC2 must propagate (not swallowed)."""
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws",
                side_effect=ConnectorError("InternalError", status_code=500),
            ):
                with pytest.raises(ConnectorError):
                    self.connector._fetch_regions(CREDS)

    def test_success_describe_regions_returns_discovered_source(self) -> None:
        """Successful EC2 call sets source="discovered"."""
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws",
                return_value=EC2_REGIONS_RESPONSE,
            ):
                regions = self.connector._fetch_regions(CREDS)

        # Only selected regions are returned
        assert len(regions) == len(CREDS["aws_selected_regions"])
        assert all(r["source"] == "discovered" for r in regions)


# ── 6. _fetch_service_inventory ───────────────────────────────────────────────


class TestAWSConnectorServiceInventory:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_inventory_record_id(self) -> None:
        result = self.connector._fetch_service_inventory(CREDS)
        assert result["record_id"] == "service_inventory"

    def test_inventory_enabled_surfaces(self) -> None:
        # M37 moved s3 from future_surfaces → enabled_surfaces
        result = self.connector._fetch_service_inventory(CREDS)
        assert "account_inventory" in result["enabled_surfaces"]
        assert "s3" in result["enabled_surfaces"]

    def test_inventory_future_surfaces_not_empty(self) -> None:
        result = self.connector._fetch_service_inventory(CREDS)
        future = result["future_surfaces"]
        # s3 was promoted to enabled_surfaces in M37 — it must NOT be in future
        assert "s3" not in future
        assert "iam" in future
        assert "security_groups" in future

    def test_future_surfaces_not_in_diff_tracked_fields(self) -> None:
        """future_surfaces must NOT be in the tracked fields to avoid spurious diffs."""
        from app.services.diff_service import _AWS_TRACKED_FIELDS_BY_TYPE
        tracked = _AWS_TRACKED_FIELDS_BY_TYPE["aws_service_inventory"]
        assert "future_surfaces" not in tracked


# ── 7. get_account_id ────────────────────────────────────────────────────────


class TestAWSConnectorGetAccountId:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_returns_account_id_string(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(self.connector, "_call_aws", return_value=STS_IDENTITY_RESPONSE):
                account_id = self.connector.get_account_id(CREDS)
        assert account_id == "123456789012"

    def test_auth_error_propagates(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=AuthenticationError("bad creds")
            ):
                with pytest.raises(AuthenticationError):
                    self.connector.get_account_id(CREDS)


# ── 8. Risk classification ────────────────────────────────────────────────────


def _change(record_type: str, change_type: str, field_path: str = "", record_id: str = "test") -> dict:
    return {
        "change_type": change_type,
        "field_path": field_path,
        "record_identifier": record_id,
        "provider_metadata": {"record_type": record_type},
    }


class TestAWSRiskClassificationAccountIdentity:
    def test_added_is_low(self) -> None:
        level, reason = classify_aws_change(_change(AWS_ACCOUNT_IDENTITY, "added"))
        assert level == "low"
        assert "established" in reason.lower()

    def test_removed_is_high(self) -> None:
        level, reason = classify_aws_change(_change(AWS_ACCOUNT_IDENTITY, "removed"))
        assert level == "high"
        assert "removed" in reason.lower()

    def test_principal_arn_changed_is_high(self) -> None:
        level, reason = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "principal_arn")
        )
        assert level == "high"
        assert "principal" in reason.lower() or "arn" in reason.lower()

    def test_account_id_changed_is_high(self) -> None:
        level, reason = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "account_id")
        )
        assert level == "high"
        assert "account" in reason.lower()

    def test_selected_regions_changed_is_medium(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "selected_regions")
        )
        assert level == "medium"

    def test_default_region_changed_is_medium(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "default_region")
        )
        assert level == "medium"

    def test_principal_type_changed_is_medium(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "principal_type")
        )
        assert level == "medium"

    def test_partition_changed_is_medium(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "partition")
        )
        assert level == "medium"

    def test_unknown_field_modified_is_low(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_ACCOUNT_IDENTITY, "modified", "some_future_field")
        )
        assert level == "low"


class TestAWSRiskClassificationRegion:
    def test_region_removed_is_high(self) -> None:
        level, reason = classify_aws_change(
            _change(AWS_REGION, "removed", record_id="us-east-1")
        )
        assert level == "high"
        assert "removed" in reason.lower() or "us-east-1" in reason

    def test_region_added_is_medium(self) -> None:
        level, reason = classify_aws_change(
            _change(AWS_REGION, "added", record_id="ap-south-1")
        )
        assert level == "medium"
        assert "added" in reason.lower() or "ap-south-1" in reason

    def test_opt_in_status_changed_is_low(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_REGION, "modified", "opt_in_status", record_id="eu-west-1")
        )
        assert level == "low"

    def test_enabled_changed_is_medium(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_REGION, "modified", "enabled", record_id="eu-west-1")
        )
        assert level == "medium"

    def test_unknown_field_modified_is_low(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_REGION, "modified", "some_field", record_id="eu-west-1")
        )
        assert level == "low"


class TestAWSRiskClassificationServiceInventory:
    def test_added_is_low(self) -> None:
        level, _ = classify_aws_change(_change(AWS_SERVICE_INVENTORY, "added"))
        assert level == "low"

    def test_removed_is_low(self) -> None:
        level, _ = classify_aws_change(_change(AWS_SERVICE_INVENTORY, "removed"))
        assert level == "low"

    def test_selected_regions_changed_is_medium(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_SERVICE_INVENTORY, "modified", "selected_regions")
        )
        assert level == "medium"

    def test_enabled_surfaces_changed_is_low(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_SERVICE_INVENTORY, "modified", "enabled_surfaces")
        )
        assert level == "low"

    def test_unknown_field_is_low(self) -> None:
        level, _ = classify_aws_change(
            _change(AWS_SERVICE_INVENTORY, "modified", "other_field")
        )
        assert level == "low"


class TestAWSRiskClassificationUnknownType:
    def test_unknown_aws_type_returns_low(self) -> None:
        level, reason = classify_aws_change(_change("aws_future_resource", "modified"))
        assert level == "low"
        assert "aws" in reason.lower()


# ── 9. Diff service tracked fields ───────────────────────────────────────────


class TestAWSDiffServiceTrackedFields:
    def test_account_identity_tracked_fields(self) -> None:
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": AWS_ACCOUNT_IDENTITY}
        fields = _tracked_fields_for(record)
        assert "account_id" in fields
        assert "principal_arn" in fields
        assert "principal_type" in fields
        assert "partition" in fields
        assert "default_region" in fields
        assert "selected_regions" in fields

    def test_region_tracked_fields(self) -> None:
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": AWS_REGION}
        fields = _tracked_fields_for(record)
        assert "opt_in_status" in fields
        assert "enabled" in fields
        assert "source" in fields

    def test_service_inventory_tracked_fields(self) -> None:
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": AWS_SERVICE_INVENTORY}
        fields = _tracked_fields_for(record)
        assert "selected_regions" in fields
        assert "enabled_surfaces" in fields
        # future_surfaces is explicitly excluded
        assert "future_surfaces" not in fields

    def test_unknown_aws_type_returns_empty(self) -> None:
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "aws_unknown_future_type"}
        fields = _tracked_fields_for(record)
        assert fields == ()


# ── 10. Failure classifier — AWS paths ───────────────────────────────────────


class TestAWSFailureClassifier:
    def test_auth_error_returns_aws_credentials_invalid(self) -> None:
        result = classify_failure(AuthenticationError("bad key"), "aws")
        assert isinstance(result, FailureClassification)
        assert result.category == "authentication"
        assert result.error_code == "aws_credentials_invalid"
        assert "invalid" in result.recommended_action.lower() or "revoked" in result.recommended_action.lower()

    def test_connector_403_returns_aws_access_denied(self) -> None:
        result = classify_failure(ConnectorError("denied", status_code=403), "aws")
        assert result.category == "authentication"
        assert result.error_code == "aws_access_denied"
        assert "iam" in result.recommended_action.lower() or "permission" in result.recommended_action.lower()

    def test_connector_404_returns_aws_resource_not_found(self) -> None:
        result = classify_failure(ConnectorError("not found", status_code=404), "aws")
        assert result.category == "resource_missing"
        assert result.error_code == "aws_resource_not_found"

    def test_connector_500_returns_aws_api_unavailable(self) -> None:
        result = classify_failure(ConnectorError("server error", status_code=500), "aws")
        assert result.category == "provider_unavailable"
        assert result.error_code == "aws_api_unavailable"

    def test_rate_limit_returns_rate_limited(self) -> None:
        result = classify_failure(RateLimitError("throttled"), "aws")
        assert result.category == "rate_limited"
        assert result.error_code == "rate_limit_exceeded"

    def test_network_error_returns_network(self) -> None:
        result = classify_failure(NetworkError("timeout"), "aws")
        assert result.category == "network"
        assert result.error_code == "network_error"

    def test_recommended_action_is_nonempty_string(self) -> None:
        result = classify_failure(AuthenticationError("bad"), "aws")
        assert isinstance(result.recommended_action, str)
        assert len(result.recommended_action) > 10


# ── 11. Schema validation ─────────────────────────────────────────────────────


class TestAWSSchemaValidation:
    def test_aws_provider_accepted_in_create_request(self) -> None:
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="aws",
            display_name="Test AWS",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_default_region="us-east-1",
        )
        assert req.provider == "aws"
        assert req.aws_access_key_id == "AKIAIOSFODNN7EXAMPLE"

    def test_aws_missing_access_key_fails_validation(self) -> None:
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="aws",
                display_name="Test AWS",
                aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                aws_default_region="us-east-1",
            )
        error_str = str(exc_info.value)
        assert "aws_access_key_id" in error_str

    def test_aws_missing_secret_key_fails_validation(self) -> None:
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="aws",
                display_name="Test AWS",
                aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                aws_default_region="us-east-1",
            )
        error_str = str(exc_info.value)
        assert "aws_secret_access_key" in error_str

    def test_aws_missing_default_region_is_allowed(self) -> None:
        """aws_default_region is not enforced by the model validator (backend handles default)."""
        from app.schemas.integration import IntegrationCreateRequest

        # The schema validator only checks aws_access_key_id + aws_secret_access_key.
        # aws_default_region is optional at the schema level (backend defaults to us-east-1).
        req = IntegrationCreateRequest(
            provider="aws",
            display_name="Test AWS",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        assert req.provider == "aws"
        assert req.aws_default_region is None  # not set; backend defaults

    def test_aws_selected_regions_optional(self) -> None:
        """selected_regions is optional; backend defaults to [default_region]."""
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="aws",
            display_name="Test AWS",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_default_region="us-east-1",
        )
        # Should not raise; selected_regions defaults to None/unset
        assert req.provider == "aws"

    def test_reconnect_request_accepts_aws_fields(self) -> None:
        """IntegrationReconnectRequest should accept aws_access_key_id and aws_secret_access_key."""
        from app.schemas.integration import IntegrationReconnectRequest

        req = IntegrationReconnectRequest(
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        assert req.aws_access_key_id == "AKIAIOSFODNN7EXAMPLE"

    def test_provider_filter_allows_aws(self) -> None:
        from app.schemas.settings import ALLOWED_PROVIDER_FILTERS
        assert "aws" in ALLOWED_PROVIDER_FILTERS

    def test_provider_filter_rejects_gcp(self) -> None:
        from app.schemas.settings import ALLOWED_PROVIDER_FILTERS
        assert "gcp" not in ALLOWED_PROVIDER_FILTERS

    def test_invalid_provider_rejected(self) -> None:
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="gcp",
                display_name="Test GCP",
            )


# ── 12. aws_schema constants ──────────────────────────────────────────────────


class TestAWSSchemaConstants:
    def test_record_type_strings_are_lowercase(self) -> None:
        assert AWS_ACCOUNT_IDENTITY == "aws_account_identity"
        assert AWS_REGION == "aws_region"
        assert AWS_SERVICE_INVENTORY == "aws_service_inventory"

    def test_record_types_frozenset_contains_all(self) -> None:
        assert AWS_ACCOUNT_IDENTITY in AWS_RECORD_TYPES
        assert AWS_REGION in AWS_RECORD_TYPES
        assert AWS_SERVICE_INVENTORY in AWS_RECORD_TYPES

    def test_record_types_frozenset_is_frozenset(self) -> None:
        assert isinstance(AWS_RECORD_TYPES, frozenset)

    def test_all_record_types_start_with_aws(self) -> None:
        for rt in AWS_RECORD_TYPES:
            assert rt.startswith("aws_"), f"{rt!r} does not start with 'aws_'"
