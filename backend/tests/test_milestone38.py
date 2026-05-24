"""Tests for M38: AWS Security Groups + VPC Network Exposure.

Test coverage
-------------
1.  Module-level helpers (aws.py):
    _cidr_is_public — True for 0.0.0.0/0 and ::/0 only.
    _has_port_in_range — port-in-range with protocol=-1 edge cases.
    _port_category — all / admin / database / web / other classification.
    _sg_rule_stable_id — deterministic, stable across identical inputs.
    _extract_tag_keys — sorted keys, None for empty.

2.  AWSConnector._make_sg_rule:
    record_id format {region}/{group_id}/{hash}.
    is_public=True for 0.0.0.0/0 CIDRs.
    port_category correctly derived.
    cidr_ipv4 / cidr_ipv6 / referenced_group_id populated correctly.
    description not in record_id (so description changes → field modification).

3.  AWSConnector._flatten_permission:
    One rule per IPv4 CIDR.
    One rule per IPv6 CIDR.
    One rule per UserIdGroupPair.
    Empty IpRanges → zero rules.

4.  AWSConnector._fetch_security_groups:
    Returns aws_security_group + aws_security_group_rule records.
    Handles pagination (NextToken).
    has_public_ssh / has_public_rdp / has_public_database_port / has_public_inbound computed correctly.
    403 → propagates ConnectorError(403) (caught by caller).
    Empty SecurityGroups → empty list.

5.  AWSConnector._fetch_vpcs:
    One aws_vpc per VPC.
    is_default from IsDefault.
    No vpc records when Vpcs is empty.

6.  AWSConnector._fetch_igws:
    attached_vpc_id set from first available attachment.
    Detached IGW → attached_vpc_id=None, state="detached".
    Pagination handled.

7.  AWSConnector._fetch_route_tables:
    has_igw_route=True when a route points to igw-*.
    igw_id set from matching route GatewayId.
    is_main from associations.
    associated_subnet_ids collected and sorted.

8.  AWSConnector._fetch_subnets:
    map_public_ip_on_launch from MapPublicIpOnLaunch.
    is_default from DefaultForAz.

9.  AWSConnector._fetch_network_acls:
    inbound_allow_all_count counts inbound ALLOW entries with 0.0.0.0/0.
    outbound_allow_all_count counts egress ALLOW entries.
    DENY entries not counted.

10. AWSConnector._fetch_network_resources:
    Calls all 6 sub-methods per region.
    403 on one sub-method → skipped, others still run.
    Client creation failure → region skipped, others still run.
    Multi-region: records from all regions included.

11. AWSConnector.fetch() integration (M38):
    Returns aws_security_group + aws_security_group_rule + aws_vpc + … records.
    security_group_count / vpc_count in service inventory.
    Credentials never in any returned record.

12. Service inventory:
    enabled_surfaces includes "security_groups" and "vpc".
    "security_groups" NOT in future_surfaces.
    security_group_count and vpc_count fields present.

13. Diff service tracked fields:
    aws_security_group → correct tracked fields.
    aws_security_group_rule → only "description".
    aws_vpc → correct tracked fields.
    aws_subnet → map_public_ip_on_launch tracked.
    aws_route_table → has_igw_route tracked.
    aws_internet_gateway → attached_vpc_id tracked.
    aws_network_acl → inbound_allow_all_count tracked.

14. Risk classification — aws_security_group_rule:
    added, ingress, SSH 0.0.0.0/0 → critical.
    added, ingress, RDP 0.0.0.0/0 → critical.
    added, ingress, PostgreSQL 0.0.0.0/0 → critical.
    added, ingress, all-traffic 0.0.0.0/0 → critical.
    added, ingress, HTTP 0.0.0.0/0 → medium.
    added, ingress, HTTPS 0.0.0.0/0 non-sensitive → medium.
    added, ingress, HTTPS 0.0.0.0/0 sensitive/prod-named group → high.
    added, ingress, HTTP 0.0.0.0/0 sensitive/prod-named group → high.
    added, ingress, HTTPS ::/0 non-sensitive → medium.
    added, ingress, HTTP ::/0 → medium.
    added, ingress, private CIDR → low.
    added, egress, all-traffic 0.0.0.0/0 → low.
    added, group-to-group ref → low.
    removed, was public SSH → low.
    removed, other rule → low.
    modified, description → low.

15. Risk classification — aws_security_group:
    added with has_public_ssh → high.
    added with has_public_rdp → high.
    added with has_public_database_port → high.
    added with has_public_inbound only → medium.
    added, no public rules → low.
    removed → medium.
    has_public_ssh False→True → high.
    has_public_rdp False→True → high.
    has_public_database_port False→True → high.
    has_public_inbound False→True → medium.
    has_public_ssh True→False → low.
    inbound_rule_count decreased → medium.
    inbound_rule_count increased → low.

16. Risk classification — aws_vpc:
    added → low.
    removed → medium.
    state changed to non-available → medium.
    state changed to available → low.
    instance_tenancy changed → medium.
    dhcp_options_id changed → medium.

17. Risk classification — aws_subnet:
    map_public_ip_on_launch False→True → high.
    map_public_ip_on_launch True→False → low.
    added → low.
    removed → low.

18. Risk classification — aws_route_table:
    has_igw_route False→True → high.
    has_igw_route True→False → low.
    route_count decreased → medium.
    added → low.
    removed → low.

19. Risk classification — aws_internet_gateway:
    attached_vpc_id None→vpc-id → high.
    attached_vpc_id vpc-id→None → low.
    added with attached_vpc_id → medium.
    added without attached → low.
    removed → low.

20. Risk classification — aws_network_acl:
    inbound_allow_all_count increased → medium.
    inbound_allow_all_count decreased → low.
    outbound_allow_all_count increased → low.
    added → low.
    removed → low.

21. Schema constants:
    All 7 M38 record type constants correct.
    AWS_RECORD_TYPES contains all M38 types.

22. Security invariants:
    Credentials never appear in any network record.
    No write API calls made.

23. M37 / M36 regression:
    fetch() still returns aws_account_identity, aws_region, aws_s3_bucket.
    classify_aws_change still routes M36/M37 types correctly.

SECURITY invariants verified:
  - aws_secret_access_key NEVER in returned records.
  - aws_access_key_id NEVER in returned records.
  - No write operations performed by any M38 connector method.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from app.connectors.aws import (
    AWSConnector,
    _cidr_is_public,
    _extract_tag_keys,
    _has_port_in_range,
    _port_category,
    _sg_rule_stable_id,
)
from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_INTERNET_GATEWAY,
    AWS_NETWORK_ACL,
    AWS_RECORD_TYPES,
    AWS_REGION,
    AWS_ROUTE_TABLE,
    AWS_S3_BUCKET,
    AWS_SECURITY_GROUP,
    AWS_SECURITY_GROUP_RULE,
    AWS_SERVICE_INVENTORY,
    AWS_SUBNET,
    AWS_VPC,
)
from app.connectors.exceptions import ConnectorError
from app.services.diff_service import _AWS_TRACKED_FIELDS_BY_TYPE, _tracked_fields_for
from app.services.risk_rules.aws import (
    _classify_igw_change,
    _classify_network_acl_change,
    _classify_route_table_change,
    _classify_security_group_change,
    _classify_security_group_rule_change,
    _classify_subnet_change,
    _classify_vpc_change,
    classify_aws_change,
)

# ── Test credentials ──────────────────────────────────────────────────────────

_CREDS: dict[str, Any] = {
    "aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_default_region":    "us-east-1",
    "aws_selected_regions":  ["us-east-1"],
}

_STS_RESP = {
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/configtrace",
    "UserId": "AIDAIOSFODNN7EXAMPLE",
}

_EC2_REGIONS_RESP = {
    "Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]
}

# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_client() -> MagicMock:
    return MagicMock()


def _change(
    record_type: str,
    change_type: str = "modified",
    field_path: str | None = None,
    new_value: Any = None,
    prev_value: Any = None,
    record_id: str = "us-east-1/sg-12345678",
    record_name: str = "web-sg (sg-12345678)",
) -> dict:
    """Build a minimal change dict for risk classification tests."""
    return {
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_id": record_id,
            "record_name": record_name,
        },
    }


def _sg_rule_dict(
    group_id: str = "sg-12345678",
    region: str = "us-east-1",
    direction: str = "ingress",
    protocol: str = "tcp",
    from_port: int | None = 22,
    to_port: int | None = 22,
    cidr_ipv4: str | None = "0.0.0.0/0",
    cidr_ipv6: str | None = None,
    referenced_group_id: str | None = None,
    is_public: bool = True,
    port_category: str = "admin",
    description: str = "",
) -> dict:
    """Build a full aws_security_group_rule dict as returned by the connector."""
    return {
        "record_type":         AWS_SECURITY_GROUP_RULE,
        "record_id":           f"{region}/{group_id}/abc123def456",
        "name":                f"{direction} {protocol} {from_port}-{to_port} {cidr_ipv4 or cidr_ipv6 or ''}",
        "group_id":            group_id,
        "region":              region,
        "direction":           direction,
        "protocol":            protocol,
        "from_port":           from_port,
        "to_port":             to_port,
        "cidr_ipv4":           cidr_ipv4,
        "cidr_ipv6":           cidr_ipv6,
        "referenced_group_id": referenced_group_id,
        "is_public":           is_public,
        "port_category":       port_category,
        "description":         description,
    }


# ── 1. Module-level helpers ───────────────────────────────────────────────────


class TestCIDRIsPublic:
    def test_ipv4_any(self) -> None:
        assert _cidr_is_public("0.0.0.0/0") is True

    def test_ipv6_any(self) -> None:
        assert _cidr_is_public("::/0") is True

    def test_private_rfc1918_10(self) -> None:
        assert _cidr_is_public("10.0.0.0/8") is False

    def test_private_rfc1918_172(self) -> None:
        assert _cidr_is_public("172.16.0.0/12") is False

    def test_private_rfc1918_192(self) -> None:
        assert _cidr_is_public("192.168.0.0/16") is False

    def test_specific_public_prefix(self) -> None:
        # A public prefix but not "all" — not treated as public by our definition
        assert _cidr_is_public("1.2.3.0/24") is False

    def test_group_ref_not_public(self) -> None:
        assert _cidr_is_public("group:sg-abc") is False

    def test_empty_string(self) -> None:
        assert _cidr_is_public("") is False


class TestHasPortInRange:
    def test_all_traffic_protocol_includes_any_port(self) -> None:
        assert _has_port_in_range(22, None, None, "-1") is True
        assert _has_port_in_range(5432, None, None, "-1") is True

    def test_port_in_range(self) -> None:
        assert _has_port_in_range(22, 22, 22, "tcp") is True
        assert _has_port_in_range(443, 443, 443, "tcp") is True

    def test_port_in_wide_range(self) -> None:
        assert _has_port_in_range(22, 20, 25, "tcp") is True
        assert _has_port_in_range(3389, 3300, 3400, "tcp") is True

    def test_port_not_in_range(self) -> None:
        assert _has_port_in_range(22, 80, 80, "tcp") is False
        assert _has_port_in_range(5432, 8000, 9000, "tcp") is False

    def test_none_ports_false(self) -> None:
        # ICMP-like rules have None ports
        assert _has_port_in_range(22, None, None, "tcp") is False
        assert _has_port_in_range(22, 22, None, "tcp") is False


class TestPortCategory:
    def test_all_traffic_protocol(self) -> None:
        assert _port_category(None, None, "-1") == "all"

    def test_ssh_port_22(self) -> None:
        assert _port_category(22, 22, "tcp") == "admin"

    def test_rdp_port_3389(self) -> None:
        assert _port_category(3389, 3389, "tcp") == "admin"

    def test_winrm_ports(self) -> None:
        assert _port_category(5985, 5985, "tcp") == "admin"
        assert _port_category(5986, 5986, "tcp") == "admin"

    def test_postgresql(self) -> None:
        assert _port_category(5432, 5432, "tcp") == "database"

    def test_mysql(self) -> None:
        assert _port_category(3306, 3306, "tcp") == "database"

    def test_redis(self) -> None:
        assert _port_category(6379, 6379, "tcp") == "database"

    def test_elasticsearch(self) -> None:
        assert _port_category(9200, 9200, "tcp") == "database"

    def test_mongodb(self) -> None:
        assert _port_category(27017, 27017, "tcp") == "database"

    def test_http_port_80(self) -> None:
        assert _port_category(80, 80, "tcp") == "web"

    def test_https_port_443(self) -> None:
        assert _port_category(443, 443, "tcp") == "web"

    def test_http_alt_8080(self) -> None:
        assert _port_category(8080, 8080, "tcp") == "web"

    def test_https_alt_8443(self) -> None:
        assert _port_category(8443, 8443, "tcp") == "web"

    def test_admin_in_wide_range(self) -> None:
        # A wide range that includes SSH should be classified as admin
        assert _port_category(20, 25, "tcp") == "admin"

    def test_db_in_wide_range(self) -> None:
        assert _port_category(5400, 5435, "tcp") == "database"

    def test_other_port(self) -> None:
        assert _port_category(12345, 12345, "tcp") == "other"

    def test_none_ports_other(self) -> None:
        assert _port_category(None, None, "tcp") == "other"


class TestSGRuleStableID:
    def test_deterministic(self) -> None:
        h1 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "0.0.0.0/0")
        h2 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "0.0.0.0/0")
        assert h1 == h2

    def test_length_12_hex_chars(self) -> None:
        h = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "0.0.0.0/0")
        assert len(h) == 12
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_cidr_different_id(self) -> None:
        h1 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "0.0.0.0/0")
        h2 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "10.0.0.0/8")
        assert h1 != h2

    def test_different_port_different_id(self) -> None:
        h1 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "0.0.0.0/0")
        h2 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 80, 80, "0.0.0.0/0")
        assert h1 != h2

    def test_different_direction_different_id(self) -> None:
        h1 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "tcp", 22, 22, "0.0.0.0/0")
        h2 = _sg_rule_stable_id("us-east-1", "sg-123", "egress", "tcp", 22, 22, "0.0.0.0/0")
        assert h1 != h2

    def test_none_ports_stable(self) -> None:
        h1 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "-1", None, None, "0.0.0.0/0")
        h2 = _sg_rule_stable_id("us-east-1", "sg-123", "ingress", "-1", None, None, "0.0.0.0/0")
        assert h1 == h2


class TestExtractTagKeys:
    def test_returns_sorted_keys(self) -> None:
        tags = [{"Key": "Env", "Value": "prod"}, {"Key": "App", "Value": "web"}]
        assert _extract_tag_keys(tags) == ["App", "Env"]

    def test_empty_tags_returns_none(self) -> None:
        assert _extract_tag_keys([]) is None

    def test_missing_key_field_skipped(self) -> None:
        tags = [{"Value": "no-key"}]
        assert _extract_tag_keys(tags) is None


# ── 2. AWSConnector._make_sg_rule ─────────────────────────────────────────────


class TestMakeSGRule:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_record_id_format(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        parts = rule["record_id"].split("/")
        assert parts[0] == "us-east-1"
        assert parts[1] == "sg-abc"
        assert len(parts[2]) == 12  # rule hash

    def test_is_public_for_ipv4_any(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        assert rule["is_public"] is True

    def test_is_public_for_ipv6_any(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "::/0", ""
        )
        assert rule["is_public"] is True

    def test_is_not_public_for_private_cidr(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "10.0.0.0/8", ""
        )
        assert rule["is_public"] is False

    def test_ipv4_cidr_populated(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        assert rule["cidr_ipv4"] == "0.0.0.0/0"
        assert rule["cidr_ipv6"] is None
        assert rule["referenced_group_id"] is None

    def test_ipv6_cidr_populated(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "::/0", ""
        )
        assert rule["cidr_ipv4"] is None
        assert rule["cidr_ipv6"] == "::/0"
        assert rule["referenced_group_id"] is None

    def test_group_reference_populated(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 3306, 3306,
            "group:123456789012/sg-xyz", "",
        )
        assert rule["cidr_ipv4"] is None
        assert rule["cidr_ipv6"] is None
        assert rule["referenced_group_id"] == "123456789012/sg-xyz"

    def test_port_category_admin(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        assert rule["port_category"] == "admin"

    def test_port_category_database(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 5432, 5432, "0.0.0.0/0", ""
        )
        assert rule["port_category"] == "database"

    def test_port_category_all_for_minus_one_protocol(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "egress", "-1", None, None, "0.0.0.0/0", ""
        )
        assert rule["port_category"] == "all"

    def test_description_stored_but_not_in_record_id(self) -> None:
        rule1 = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", "desc A"
        )
        rule2 = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", "desc B"
        )
        # Record IDs must be the same (description not in hash)
        assert rule1["record_id"] == rule2["record_id"]
        # But descriptions differ
        assert rule1["description"] == "desc A"
        assert rule2["description"] == "desc B"

    def test_all_traffic_rule_name(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "egress", "-1", None, None, "0.0.0.0/0", ""
        )
        assert "all" in rule["name"]

    def test_single_port_rule_name(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        assert "22" in rule["name"]

    def test_record_type(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        assert rule["record_type"] == AWS_SECURITY_GROUP_RULE


# ── 3. AWSConnector._flatten_permission ───────────────────────────────────────


class TestFlattenPermission:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _perm(
        self,
        protocol: str = "tcp",
        from_port: int = 22,
        to_port: int = 22,
        ip_ranges: list | None = None,
        ipv6_ranges: list | None = None,
        group_pairs: list | None = None,
    ) -> dict:
        return {
            "IpProtocol": protocol,
            "FromPort": from_port,
            "ToPort": to_port,
            "IpRanges": ip_ranges or [],
            "Ipv6Ranges": ipv6_ranges or [],
            "UserIdGroupPairs": group_pairs or [],
        }

    def test_one_ipv4_range_produces_one_rule(self) -> None:
        perm = self._perm(ip_ranges=[{"CidrIp": "0.0.0.0/0"}])
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert len(rules) == 1
        assert rules[0]["cidr_ipv4"] == "0.0.0.0/0"

    def test_two_ipv4_ranges_produce_two_rules(self) -> None:
        perm = self._perm(
            ip_ranges=[{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/8"}]
        )
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert len(rules) == 2

    def test_ipv6_range_produces_rule(self) -> None:
        perm = self._perm(ipv6_ranges=[{"CidrIpv6": "::/0"}])
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert len(rules) == 1
        assert rules[0]["cidr_ipv6"] == "::/0"

    def test_group_pair_produces_rule(self) -> None:
        perm = self._perm(
            group_pairs=[{"GroupId": "sg-xyz", "UserId": "123456789012"}]
        )
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert len(rules) == 1
        assert "sg-xyz" in rules[0]["referenced_group_id"]

    def test_mixed_sources_produce_multiple_rules(self) -> None:
        perm = self._perm(
            ip_ranges=[{"CidrIp": "10.0.0.0/8"}],
            ipv6_ranges=[{"CidrIpv6": "fd00::/8"}],
            group_pairs=[{"GroupId": "sg-xyz"}],
        )
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert len(rules) == 3

    def test_empty_cidr_skipped(self) -> None:
        perm = self._perm(ip_ranges=[{"CidrIp": ""}])
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert len(rules) == 0

    def test_description_included(self) -> None:
        perm = self._perm(
            ip_ranges=[{"CidrIp": "0.0.0.0/0", "Description": "my-desc"}]
        )
        rules = self.connector._flatten_permission("sg-abc", "us-east-1", "ingress", perm)
        assert rules[0]["description"] == "my-desc"


# ── 4. AWSConnector._fetch_security_groups ────────────────────────────────────


_SG_RESPONSE_SSH_PUBLIC = {
    "SecurityGroups": [
        {
            "GroupId": "sg-11111111",
            "GroupName": "web-sg",
            "Description": "Web servers",
            "VpcId": "vpc-aaaaaaaa",
            "OwnerId": "123456789012",
            "Tags": [{"Key": "Env", "Value": "prod"}],
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                },
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                }
            ],
        }
    ]
}

_SG_RESPONSE_POSTGRES_PUBLIC = {
    "SecurityGroups": [
        {
            "GroupId": "sg-db111111",
            "GroupName": "db-sg",
            "Description": "Database servers",
            "VpcId": "vpc-aaaaaaaa",
            "OwnerId": "123456789012",
            "Tags": [],
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                },
            ],
            "IpPermissionsEgress": [],
        }
    ]
}


class TestFetchSecurityGroups:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _call(self, response: dict) -> list[dict]:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=response):
            return self.connector._fetch_security_groups(client, "us-east-1")

    def test_returns_sg_and_rule_records(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        types = [r["record_type"] for r in records]
        assert AWS_SECURITY_GROUP in types
        assert AWS_SECURITY_GROUP_RULE in types

    def test_sg_record_fields(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        assert sg["group_id"] == "sg-11111111"
        assert sg["group_name"] == "web-sg"
        assert sg["vpc_id"] == "vpc-aaaaaaaa"
        assert sg["region"] == "us-east-1"

    def test_has_public_ssh_detected(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        assert sg["has_public_ssh"] is True
        assert sg["has_public_inbound"] is True

    def test_has_public_database_port_detected(self) -> None:
        records = self._call(_SG_RESPONSE_POSTGRES_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        assert sg["has_public_database_port"] is True

    def test_has_no_rdp_when_not_present(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        assert sg["has_public_rdp"] is False

    def test_inbound_rule_count(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        # 2 inbound rules: SSH + HTTPS
        assert sg["inbound_rule_count"] == 2

    def test_outbound_rule_count(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        # 1 egress rule: all-traffic
        assert sg["outbound_rule_count"] == 1

    def test_tag_keys_populated(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        assert sg["tag_keys"] == ["Env"]

    def test_empty_response_returns_empty_list(self) -> None:
        records = self._call({"SecurityGroups": []})
        assert records == []

    def test_rule_records_count(self) -> None:
        # SSH + HTTPS (inbound) + all-traffic (egress) = 3 rule records
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        rules = [r for r in records if r["record_type"] == AWS_SECURITY_GROUP_RULE]
        assert len(rules) == 3

    def test_sg_record_id_format(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        sg = next(r for r in records if r["record_type"] == AWS_SECURITY_GROUP)
        assert sg["record_id"] == "us-east-1/sg-11111111"

    def test_pagination_followed(self) -> None:
        """NextToken in first response triggers a second call."""
        page1 = {
            "SecurityGroups": [_SG_RESPONSE_SSH_PUBLIC["SecurityGroups"][0]],
            "NextToken": "token-abc",
        }
        page2 = {"SecurityGroups": []}  # second page empty
        client = _mock_client()
        side_effect = [page1, page2]
        with patch.object(self.connector, "_call_aws", side_effect=side_effect):
            records = self.connector._fetch_security_groups(client, "us-east-1")
        # One SG from page 1
        sgs = [r for r in records if r["record_type"] == AWS_SECURITY_GROUP]
        assert len(sgs) == 1

    def test_credentials_not_in_records(self) -> None:
        records = self._call(_SG_RESPONSE_SSH_PUBLIC)
        for record in records:
            assert "aws_secret_access_key" not in str(record)
            assert "wJalrXUtnFEMI" not in str(record)


# ── 5. AWSConnector._fetch_vpcs ───────────────────────────────────────────────


_VPC_RESPONSE = {
    "Vpcs": [
        {
            "VpcId": "vpc-aaaaaaaa",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "DhcpOptionsId": "dopt-11111111",
            "InstanceTenancy": "default",
            "Tags": [{"Key": "Name", "Value": "main"}],
        }
    ]
}


class TestFetchVPCs:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _call(self, response: dict) -> list[dict]:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=response):
            return self.connector._fetch_vpcs(client, "us-east-1")

    def test_returns_vpc_record(self) -> None:
        records = self._call(_VPC_RESPONSE)
        assert len(records) == 1
        assert records[0]["record_type"] == AWS_VPC

    def test_vpc_fields(self) -> None:
        records = self._call(_VPC_RESPONSE)
        vpc = records[0]
        assert vpc["vpc_id"] == "vpc-aaaaaaaa"
        assert vpc["cidr_block"] == "10.0.0.0/16"
        assert vpc["state"] == "available"
        assert vpc["is_default"] is False
        assert vpc["dhcp_options_id"] == "dopt-11111111"
        assert vpc["instance_tenancy"] == "default"

    def test_record_id_format(self) -> None:
        records = self._call(_VPC_RESPONSE)
        assert records[0]["record_id"] == "us-east-1/vpc-aaaaaaaa"

    def test_empty_response(self) -> None:
        assert self._call({"Vpcs": []}) == []


# ── 6. AWSConnector._fetch_igws ───────────────────────────────────────────────


class TestFetchIGWs:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _call(self, response: dict) -> list[dict]:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=response):
            return self.connector._fetch_igws(client, "us-east-1")

    def test_attached_igw(self) -> None:
        resp = {
            "InternetGateways": [
                {
                    "InternetGatewayId": "igw-12345678",
                    "Attachments": [
                        {"VpcId": "vpc-aaaaaaaa", "State": "available"}
                    ],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        assert len(records) == 1
        igw = records[0]
        assert igw["record_type"] == AWS_INTERNET_GATEWAY
        assert igw["igw_id"] == "igw-12345678"
        assert igw["attached_vpc_id"] == "vpc-aaaaaaaa"
        assert igw["state"] == "available"

    def test_detached_igw(self) -> None:
        resp = {
            "InternetGateways": [
                {
                    "InternetGatewayId": "igw-detached",
                    "Attachments": [],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        assert records[0]["attached_vpc_id"] is None
        assert records[0]["state"] == "detached"

    def test_record_id_format(self) -> None:
        resp = {
            "InternetGateways": [
                {
                    "InternetGatewayId": "igw-12345678",
                    "Attachments": [],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        assert records[0]["record_id"] == "us-east-1/igw-12345678"


# ── 7. AWSConnector._fetch_route_tables ───────────────────────────────────────


class TestFetchRouteTables:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _call(self, response: dict) -> list[dict]:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=response):
            return self.connector._fetch_route_tables(client, "us-east-1")

    def test_has_igw_route_true(self) -> None:
        resp = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-11111111",
                    "VpcId": "vpc-aaaaaaaa",
                    "Associations": [{"Main": True}],
                    "Routes": [
                        {
                            "DestinationCidrBlock": "10.0.0.0/16",
                            "GatewayId": "local",
                            "State": "active",
                        },
                        {
                            "DestinationCidrBlock": "0.0.0.0/0",
                            "GatewayId": "igw-12345678",
                            "State": "active",
                        },
                    ],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        rt = records[0]
        assert rt["has_igw_route"] is True
        assert rt["igw_id"] == "igw-12345678"

    def test_no_igw_route(self) -> None:
        resp = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-private",
                    "VpcId": "vpc-aaaaaaaa",
                    "Associations": [],
                    "Routes": [
                        {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
                    ],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        assert records[0]["has_igw_route"] is False
        assert records[0]["igw_id"] is None

    def test_is_main_route_table(self) -> None:
        resp = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-main",
                    "VpcId": "vpc-aaaaaaaa",
                    "Associations": [{"Main": True}],
                    "Routes": [],
                    "Tags": [],
                }
            ]
        }
        assert self._call(resp)[0]["is_main"] is True

    def test_associated_subnet_ids_sorted(self) -> None:
        resp = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-assoc",
                    "VpcId": "vpc-aaaaaaaa",
                    "Associations": [
                        {"Main": False, "SubnetId": "subnet-bbb"},
                        {"Main": False, "SubnetId": "subnet-aaa"},
                    ],
                    "Routes": [],
                    "Tags": [],
                }
            ]
        }
        rt = self._call(resp)[0]
        assert rt["associated_subnet_ids"] == ["subnet-aaa", "subnet-bbb"]

    def test_blackhole_igw_route_not_counted(self) -> None:
        """A blackhole route should not set has_igw_route=True."""
        resp = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-bh",
                    "VpcId": "vpc-aaaaaaaa",
                    "Associations": [],
                    "Routes": [
                        {
                            "DestinationCidrBlock": "0.0.0.0/0",
                            "GatewayId": "igw-blackhole",
                            "State": "blackhole",
                        }
                    ],
                    "Tags": [],
                }
            ]
        }
        assert self._call(resp)[0]["has_igw_route"] is False


# ── 8. AWSConnector._fetch_subnets ────────────────────────────────────────────


class TestFetchSubnets:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _call(self, response: dict) -> list[dict]:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=response):
            return self.connector._fetch_subnets(client, "us-east-1")

    def test_subnet_record_fields(self) -> None:
        resp = {
            "Subnets": [
                {
                    "SubnetId": "subnet-11111111",
                    "VpcId": "vpc-aaaaaaaa",
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": "us-east-1a",
                    "State": "available",
                    "AvailableIpAddressCount": 251,
                    "MapPublicIpOnLaunch": False,
                    "DefaultForAz": False,
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        s = records[0]
        assert s["record_type"] == AWS_SUBNET
        assert s["subnet_id"] == "subnet-11111111"
        assert s["map_public_ip_on_launch"] is False
        assert s["is_default"] is False
        assert s["available_ip_count"] == 251

    def test_map_public_ip_true(self) -> None:
        resp = {
            "Subnets": [
                {
                    "SubnetId": "subnet-pub",
                    "VpcId": "vpc-aaa",
                    "CidrBlock": "10.0.0.0/24",
                    "AvailabilityZone": "us-east-1a",
                    "State": "available",
                    "AvailableIpAddressCount": 100,
                    "MapPublicIpOnLaunch": True,
                    "DefaultForAz": False,
                    "Tags": [],
                }
            ]
        }
        assert self._call(resp)[0]["map_public_ip_on_launch"] is True


# ── 9. AWSConnector._fetch_network_acls ───────────────────────────────────────


class TestFetchNetworkACLs:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _call(self, response: dict) -> list[dict]:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=response):
            return self.connector._fetch_network_acls(client, "us-east-1")

    def test_inbound_allow_all_counted(self) -> None:
        resp = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-11111111",
                    "VpcId": "vpc-aaaaaaaa",
                    "IsDefault": True,
                    "Entries": [
                        # inbound ALLOW 0.0.0.0/0
                        {
                            "RuleNumber": 100,
                            "Protocol": "-1",
                            "RuleAction": "allow",
                            "Egress": False,
                            "CidrBlock": "0.0.0.0/0",
                        },
                        # inbound DENY 0.0.0.0/0 — should NOT count
                        {
                            "RuleNumber": 32767,
                            "Protocol": "-1",
                            "RuleAction": "deny",
                            "Egress": False,
                            "CidrBlock": "0.0.0.0/0",
                        },
                        # outbound ALLOW — should not count for inbound
                        {
                            "RuleNumber": 100,
                            "Protocol": "-1",
                            "RuleAction": "allow",
                            "Egress": True,
                            "CidrBlock": "0.0.0.0/0",
                        },
                    ],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        acl = records[0]
        assert acl["record_type"] == AWS_NETWORK_ACL
        assert acl["inbound_allow_all_count"] == 1
        assert acl["outbound_allow_all_count"] == 1
        assert acl["rule_count"] == 3

    def test_ipv6_allow_all_counted(self) -> None:
        resp = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-ipv6",
                    "VpcId": "vpc-aaa",
                    "IsDefault": False,
                    "Entries": [
                        {
                            "RuleNumber": 100,
                            "Protocol": "-1",
                            "RuleAction": "allow",
                            "Egress": False,
                            "Ipv6CidrBlock": "::/0",
                        },
                    ],
                    "Tags": [],
                }
            ]
        }
        records = self._call(resp)
        assert records[0]["inbound_allow_all_count"] == 1


# ── 10. AWSConnector._fetch_network_resources ─────────────────────────────────


class TestFetchNetworkResources:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _empty_network_responses(self) -> list[dict]:
        """Six empty responses for the 6 EC2 describe calls per region."""
        return [
            {"SecurityGroups": []},
            {"Vpcs": []},
            {"InternetGateways": []},
            {"RouteTables": []},
            {"Subnets": []},
            {"NetworkAcls": []},
        ]

    def test_returns_empty_when_all_empty(self) -> None:
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=self._empty_network_responses()
            ):
                records = self.connector._fetch_network_resources(_CREDS)
        assert records == []

    def test_403_on_describe_sgs_skips_but_continues(self) -> None:
        """If DescribeSecurityGroups returns 403, the other APIs still run."""
        side_effects = [
            ConnectorError("denied", status_code=403),  # SGs → denied
            {"Vpcs": [
                {"VpcId": "vpc-aaa", "CidrBlock": "10.0.0.0/16",
                 "State": "available", "IsDefault": False, "Tags": []}
            ]},
            {"InternetGateways": []},
            {"RouteTables": []},
            {"Subnets": []},
            {"NetworkAcls": []},
        ]
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(self.connector, "_call_aws", side_effect=side_effects):
                records = self.connector._fetch_network_resources(_CREDS)
        # No SG records, but VPC should be present
        types = {r["record_type"] for r in records}
        assert AWS_SECURITY_GROUP not in types
        assert AWS_VPC in types

    def test_multi_region_collects_from_both(self) -> None:
        creds = {**_CREDS, "aws_selected_regions": ["us-east-1", "eu-west-1"]}
        # 6 empty calls per region × 2 regions = 12 calls
        side_effects = self._empty_network_responses() * 2

        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            with patch.object(
                self.connector, "_call_aws", side_effect=side_effects
            ):
                records = self.connector._fetch_network_resources(creds)
        # All empty — just confirms no crash across 2 regions
        assert records == []

    def test_client_creation_failure_skips_region(self) -> None:
        with patch.object(
            self.connector, "_make_client", side_effect=Exception("no creds")
        ):
            records = self.connector._fetch_network_resources(_CREDS)
        assert records == []


# ── 11. AWSConnector.fetch() integration (M38) ────────────────────────────────


class TestFetchIntegrationM38:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _patch_fetch_m38(self, sg_records: list[dict] | None = None):
        """Patch fetch() with mocked account/region/S3 responses, then network."""
        # Patch _fetch_network_resources separately to keep test simple
        call_aws_se = [
            _STS_RESP,               # STS GetCallerIdentity
            _EC2_REGIONS_RESP,       # EC2 DescribeRegions
            {"Buckets": []},         # S3 ListBuckets (M37 — empty)
        ]
        return (
            patch.object(self.connector, "_make_client", return_value=_mock_client()),
            patch.object(self.connector, "_call_aws", side_effect=call_aws_se),
            patch.object(
                self.connector,
                "_fetch_network_resources",
                return_value=sg_records or [],
            ),
        )

    def test_fetch_includes_network_records(self) -> None:
        fake_sg = {
            "record_type": AWS_SECURITY_GROUP,
            "record_id": "us-east-1/sg-fake",
            "name": "fake-sg",
            "group_id": "sg-fake",
        }
        p1, p2, p3 = self._patch_fetch_m38(sg_records=[fake_sg])
        with p1, p2, p3:
            records = self.connector.fetch(_CREDS)
        types = {r["record_type"] for r in records}
        assert AWS_SECURITY_GROUP in types

    def test_fetch_includes_base_record_types(self) -> None:
        p1, p2, p3 = self._patch_fetch_m38()
        with p1, p2, p3:
            records = self.connector.fetch(_CREDS)
        types = {r["record_type"] for r in records}
        assert AWS_ACCOUNT_IDENTITY in types
        assert AWS_REGION in types
        assert AWS_SERVICE_INVENTORY in types

    def test_service_inventory_sg_count(self) -> None:
        fake_sgs = [
            {"record_type": AWS_SECURITY_GROUP, "record_id": "us-east-1/sg-1"},
            {"record_type": AWS_SECURITY_GROUP, "record_id": "us-east-1/sg-2"},
        ]
        p1, p2, p3 = self._patch_fetch_m38(sg_records=fake_sgs)
        with p1, p2, p3:
            records = self.connector.fetch(_CREDS)
        inv = next(r for r in records if r["record_type"] == AWS_SERVICE_INVENTORY)
        assert inv["security_group_count"] == 2

    def test_service_inventory_vpc_count(self) -> None:
        fake_vpcs = [
            {"record_type": AWS_VPC, "record_id": "us-east-1/vpc-1"},
        ]
        p1, p2, p3 = self._patch_fetch_m38(sg_records=fake_vpcs)
        with p1, p2, p3:
            records = self.connector.fetch(_CREDS)
        inv = next(r for r in records if r["record_type"] == AWS_SERVICE_INVENTORY)
        assert inv["vpc_count"] == 1

    def test_credentials_not_in_any_record(self) -> None:
        p1, p2, p3 = self._patch_fetch_m38()
        with p1, p2, p3:
            records = self.connector.fetch(_CREDS)
        for record in records:
            content = str(record)
            assert "wJalrXUtnFEMI" not in content  # secret key
            assert "AKIAIOSFODNN7EXAMPLE" not in content  # full access key ID


# ── 12. Service inventory ─────────────────────────────────────────────────────


class TestServiceInventoryM38:
    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def _get_inventory(self, sg_count: int = 0, vpc_count: int = 0) -> dict:
        return self.connector._fetch_service_inventory(
            _CREDS,
            s3_count=0,
            security_group_count=sg_count,
            vpc_count=vpc_count,
        )

    def test_security_groups_in_enabled_surfaces(self) -> None:
        inv = self._get_inventory()
        assert "security_groups" in inv["enabled_surfaces"]

    def test_vpc_in_enabled_surfaces(self) -> None:
        inv = self._get_inventory()
        assert "vpc" in inv["enabled_surfaces"]

    def test_security_groups_not_in_future_surfaces(self) -> None:
        inv = self._get_inventory()
        assert "security_groups" not in inv["future_surfaces"]

    def test_security_group_count_field(self) -> None:
        inv = self._get_inventory(sg_count=5)
        assert inv["security_group_count"] == 5

    def test_vpc_count_field(self) -> None:
        inv = self._get_inventory(vpc_count=3)
        assert inv["vpc_count"] == 3

    def test_s3_still_in_enabled_surfaces(self) -> None:
        inv = self._get_inventory()
        assert "s3" in inv["enabled_surfaces"]


# ── 13. Diff service tracked fields ──────────────────────────────────────────


class TestDiffServiceM38TrackedFields:
    def test_security_group_tracked_fields(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_security_group"]
        for f in (
            "group_name", "description", "vpc_id",
            "inbound_rule_count", "outbound_rule_count",
            "has_public_inbound", "has_public_ssh", "has_public_rdp",
            "has_public_database_port", "tag_keys",
        ):
            assert f in fields, f"Missing tracked field: {f}"

    def test_sg_rule_only_description_tracked(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_security_group_rule"]
        assert "description" in fields
        # Structural fields are in the record_id — not tracked here
        assert "protocol" not in fields
        assert "from_port" not in fields
        assert "cidr_ipv4" not in fields

    def test_vpc_tracked_fields(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_vpc"]
        for f in ("state", "cidr_block", "dhcp_options_id", "instance_tenancy"):
            assert f in fields

    def test_subnet_map_public_ip_tracked(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_subnet"]
        assert "map_public_ip_on_launch" in fields

    def test_route_table_has_igw_route_tracked(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_route_table"]
        assert "has_igw_route" in fields
        assert "igw_id" in fields

    def test_igw_attached_vpc_id_tracked(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_internet_gateway"]
        assert "attached_vpc_id" in fields

    def test_nacl_allow_all_counts_tracked(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_network_acl"]
        assert "inbound_allow_all_count" in fields
        assert "outbound_allow_all_count" in fields

    def test_service_inventory_has_sg_vpc_count_fields(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_service_inventory"]
        assert "security_group_count" in fields
        assert "vpc_count" in fields

    def test_future_surfaces_not_tracked(self) -> None:
        fields = _AWS_TRACKED_FIELDS_BY_TYPE["aws_service_inventory"]
        assert "future_surfaces" not in fields

    def test_tracked_fields_for_dispatch_sg(self) -> None:
        record = {"record_type": "aws_security_group"}
        fields = _tracked_fields_for(record)
        assert "has_public_ssh" in fields

    def test_tracked_fields_for_dispatch_sg_rule(self) -> None:
        record = {"record_type": "aws_security_group_rule"}
        fields = _tracked_fields_for(record)
        assert "description" in fields
        assert "protocol" not in fields

    def test_tracked_fields_for_dispatch_vpc(self) -> None:
        record = {"record_type": "aws_vpc"}
        fields = _tracked_fields_for(record)
        assert "state" in fields


# ── 14. Risk — aws_security_group_rule ───────────────────────────────────────


class TestSGRuleRiskAdded:
    """Risk for added aws_security_group_rule records."""

    def _added(self, rule: dict) -> tuple[str, str]:
        return _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="added",
                new_value=rule,
            )
        )

    def test_public_ssh_critical(self) -> None:
        rule = _sg_rule_dict(from_port=22, to_port=22, port_category="admin")
        level, reason = self._added(rule)
        assert level == "critical"
        assert "SSH" in reason
        assert "may be reachable" in reason

    def test_public_rdp_critical(self) -> None:
        rule = _sg_rule_dict(from_port=3389, to_port=3389, port_category="admin")
        level, reason = self._added(rule)
        assert level == "critical"
        assert "RDP" in reason

    def test_public_postgres_critical(self) -> None:
        rule = _sg_rule_dict(
            from_port=5432, to_port=5432,
            port_category="database",
        )
        level, reason = self._added(rule)
        assert level == "critical"
        assert "database" in reason.lower()

    def test_public_all_traffic_critical(self) -> None:
        rule = _sg_rule_dict(
            protocol="-1", from_port=None, to_port=None,
            port_category="all",
        )
        level, reason = self._added(rule)
        assert level == "critical"
        assert "ALL" in reason or "all" in reason.lower()

    def test_public_http_medium(self) -> None:
        rule = _sg_rule_dict(
            from_port=80, to_port=80, port_category="web",
        )
        level, reason = self._added(rule)
        assert level == "medium"
        assert "HTTP" in reason

    def test_public_https_medium_non_sensitive(self) -> None:
        """HTTPS 443 from 0.0.0.0/0 on a non-sensitive group → medium (not low)."""
        rule = _sg_rule_dict(
            from_port=443, to_port=443, port_category="web",
            cidr_ipv4="0.0.0.0/0",
        )
        # _change default record_name="web-sg (sg-12345678)" — not sensitive
        level, reason = self._added(rule)
        assert level == "medium"
        assert "HTTPS" in reason

    def test_public_https_medium_ipv6(self) -> None:
        """HTTPS 443 from ::/0 on a non-sensitive group → medium."""
        rule = _sg_rule_dict(
            from_port=443, to_port=443, port_category="web",
            cidr_ipv4=None, cidr_ipv6="::/0",
        )
        level, _ = self._added(rule)
        assert level == "medium"

    def test_public_https_8443_medium(self) -> None:
        """HTTPS alt port 8443 from 0.0.0.0/0 non-sensitive → medium."""
        rule = _sg_rule_dict(
            from_port=8443, to_port=8443, port_category="web",
            cidr_ipv4="0.0.0.0/0",
        )
        level, _ = self._added(rule)
        assert level == "medium"

    def test_public_https_sensitive_group_high(self) -> None:
        """HTTPS 443 from 0.0.0.0/0 on a prod/backend-named group → high."""
        rule = _sg_rule_dict(
            from_port=443, to_port=443, port_category="web",
            cidr_ipv4="0.0.0.0/0",
        )
        level, reason = _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="added",
                new_value=rule,
                record_name="prod-backend-sg",  # sensitive pattern
            )
        )
        assert level == "high"
        assert "HTTPS" in reason

    def test_public_https_internal_group_high(self) -> None:
        """HTTPS 443 from ::/0 on an 'internal'-named group → high."""
        rule = _sg_rule_dict(
            from_port=443, to_port=443, port_category="web",
            cidr_ipv4=None, cidr_ipv6="::/0",
        )
        level, _ = _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="added",
                new_value=rule,
                record_name="internal-api-sg",  # matches "api" pattern
            )
        )
        assert level == "high"

    def test_public_http_sensitive_group_high(self) -> None:
        """HTTP 80 from 0.0.0.0/0 on a prod-named group → high."""
        rule = _sg_rule_dict(
            from_port=80, to_port=80, port_category="web",
            cidr_ipv4="0.0.0.0/0",
        )
        level, reason = _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="added",
                new_value=rule,
                record_name="prod-web-sg",  # sensitive pattern
            )
        )
        assert level == "high"

    def test_public_http_ipv6_medium(self) -> None:
        """HTTP 80 from ::/0 non-sensitive → medium (same as IPv4)."""
        rule = _sg_rule_dict(
            from_port=80, to_port=80, port_category="web",
            cidr_ipv4=None, cidr_ipv6="::/0",
        )
        level, reason = self._added(rule)
        assert level == "medium"

    def test_ssh_still_critical(self) -> None:
        """SSH 22 public remains critical regardless of sensitivity."""
        rule = _sg_rule_dict(from_port=22, to_port=22, port_category="admin")
        level, _ = self._added(rule)
        assert level == "critical"

    def test_postgres_still_critical(self) -> None:
        """Postgres 5432 public remains critical regardless of sensitivity."""
        rule = _sg_rule_dict(
            from_port=5432, to_port=5432, port_category="database",
        )
        level, _ = self._added(rule)
        assert level == "critical"

    def test_all_ports_still_critical(self) -> None:
        """All-ports/all-protocols public remains critical."""
        rule = _sg_rule_dict(
            protocol="-1", from_port=None, to_port=None, port_category="all",
        )
        level, _ = self._added(rule)
        assert level == "critical"

    def test_redis_still_critical(self) -> None:
        """Redis 6379 public inbound is database-category → critical.

        Redis exposure to the public internet is as dangerous as Postgres.
        Confirming that the web-port Medium fix did not accidentally reclassify
        database ports.
        """
        rule = _sg_rule_dict(
            from_port=6379, to_port=6379, port_category="database",
        )
        level, reason = self._added(rule)
        assert level == "critical"
        assert "database" in reason.lower()

    def test_public_other_port_medium(self) -> None:
        rule = _sg_rule_dict(
            from_port=9090, to_port=9090, port_category="other",
        )
        level, reason = self._added(rule)
        assert level == "medium"

    def test_private_cidr_ingress_low(self) -> None:
        rule = _sg_rule_dict(
            cidr_ipv4="10.0.0.0/8",
            is_public=False,
            port_category="admin",
        )
        level, _ = self._added(rule)
        assert level == "low"

    def test_group_to_group_low(self) -> None:
        rule = _sg_rule_dict(
            cidr_ipv4=None,
            referenced_group_id="sg-appservers",
            is_public=False,
            port_category="database",
        )
        level, _ = self._added(rule)
        assert level == "low"

    def test_egress_all_traffic_public_low(self) -> None:
        rule = _sg_rule_dict(
            direction="egress",
            protocol="-1",
            from_port=None,
            to_port=None,
            port_category="all",
        )
        level, _ = self._added(rule)
        assert level == "low"

    def test_public_winrm_5985_critical(self) -> None:
        rule = _sg_rule_dict(
            from_port=5985, to_port=5985, port_category="admin",
        )
        level, _ = self._added(rule)
        assert level == "critical"


class TestSGRuleRiskRemovedAndModified:
    def test_removed_public_ssh_low(self) -> None:
        rule = _sg_rule_dict(port_category="admin")
        level, reason = _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="removed",
                prev_value=rule,
            )
        )
        assert level == "low"
        assert "removed" in reason.lower()

    def test_removed_any_rule_low(self) -> None:
        rule = _sg_rule_dict(port_category="other", is_public=False)
        level, _ = _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="removed",
                prev_value=rule,
            )
        )
        assert level == "low"

    def test_modified_description_low(self) -> None:
        level, _ = _classify_security_group_rule_change(
            _change(
                AWS_SECURITY_GROUP_RULE,
                change_type="modified",
                field_path="description",
                new_value="new description",
                prev_value="old description",
            )
        )
        assert level == "low"


# ── 15. Risk — aws_security_group ─────────────────────────────────────────────


class TestSGAggregateRisk:
    def _modified(self, field: str, nv: Any, pv: Any = None) -> tuple[str, str]:
        return _classify_security_group_change(
            _change(
                AWS_SECURITY_GROUP,
                change_type="modified",
                field_path=field,
                new_value=nv,
                prev_value=pv,
            )
        )

    def test_added_with_public_ssh_high(self) -> None:
        level, _ = _classify_security_group_change(
            _change(
                AWS_SECURITY_GROUP,
                change_type="added",
                new_value={"has_public_ssh": True, "has_public_inbound": True},
            )
        )
        assert level == "high"

    def test_added_with_public_rdp_high(self) -> None:
        level, _ = _classify_security_group_change(
            _change(
                AWS_SECURITY_GROUP,
                change_type="added",
                new_value={"has_public_rdp": True, "has_public_inbound": True},
            )
        )
        assert level == "high"

    def test_added_with_public_db_high(self) -> None:
        level, _ = _classify_security_group_change(
            _change(
                AWS_SECURITY_GROUP,
                change_type="added",
                new_value={"has_public_database_port": True, "has_public_inbound": True},
            )
        )
        assert level == "high"

    def test_added_with_only_public_inbound_medium(self) -> None:
        level, _ = _classify_security_group_change(
            _change(
                AWS_SECURITY_GROUP,
                change_type="added",
                new_value={"has_public_inbound": True, "has_public_ssh": False},
            )
        )
        assert level == "medium"

    def test_added_no_public_rules_low(self) -> None:
        level, _ = _classify_security_group_change(
            _change(
                AWS_SECURITY_GROUP,
                change_type="added",
                new_value={"has_public_inbound": False},
            )
        )
        assert level == "low"

    def test_removed_medium(self) -> None:
        level, _ = _classify_security_group_change(
            _change(AWS_SECURITY_GROUP, change_type="removed")
        )
        assert level == "medium"

    def test_has_public_ssh_false_to_true_high(self) -> None:
        level, reason = self._modified("has_public_ssh", True, False)
        assert level == "high"
        assert "SSH" in reason

    def test_has_public_rdp_false_to_true_high(self) -> None:
        level, reason = self._modified("has_public_rdp", True, False)
        assert level == "high"
        assert "RDP" in reason

    def test_has_public_database_false_to_true_high(self) -> None:
        level, reason = self._modified("has_public_database_port", True, False)
        assert level == "high"

    def test_has_public_inbound_false_to_true_medium(self) -> None:
        level, _ = self._modified("has_public_inbound", True, False)
        assert level == "medium"

    def test_has_public_ssh_true_to_false_low(self) -> None:
        level, _ = self._modified("has_public_ssh", False, True)
        assert level == "low"

    def test_inbound_rule_count_decreased_medium(self) -> None:
        level, reason = self._modified("inbound_rule_count", 1, 3)
        assert level == "medium"
        assert "inbound" in reason

    def test_inbound_rule_count_increased_low(self) -> None:
        level, _ = self._modified("inbound_rule_count", 5, 3)
        assert level == "low"

    def test_description_changed_low(self) -> None:
        level, _ = self._modified("description", "new desc", "old desc")
        assert level == "low"


# ── 16. Risk — aws_vpc ────────────────────────────────────────────────────────


class TestVPCRisk:
    def _change_vpc(self, ct: str = "modified", fp: str | None = None,
                    nv: Any = None, pv: Any = None,
                    rid: str = "us-east-1/vpc-aaaaaaaa") -> dict:
        return _change(AWS_VPC, change_type=ct, field_path=fp, new_value=nv,
                       prev_value=pv, record_id=rid)

    def test_added_low(self) -> None:
        level, _ = _classify_vpc_change(self._change_vpc("added"))
        assert level == "low"

    def test_removed_medium(self) -> None:
        level, _ = _classify_vpc_change(self._change_vpc("removed"))
        assert level == "medium"

    def test_state_non_available_medium(self) -> None:
        level, _ = _classify_vpc_change(
            self._change_vpc("modified", "state", "pending", "available")
        )
        assert level == "medium"

    def test_state_available_low(self) -> None:
        level, _ = _classify_vpc_change(
            self._change_vpc("modified", "state", "available", "pending")
        )
        assert level == "low"

    def test_instance_tenancy_medium(self) -> None:
        level, _ = _classify_vpc_change(
            self._change_vpc("modified", "instance_tenancy", "dedicated", "default")
        )
        assert level == "medium"

    def test_dhcp_options_medium(self) -> None:
        level, _ = _classify_vpc_change(
            self._change_vpc("modified", "dhcp_options_id", "dopt-new", "dopt-old")
        )
        assert level == "medium"

    def test_other_field_low(self) -> None:
        level, _ = _classify_vpc_change(
            self._change_vpc("modified", "tag_keys", ["Name"], None)
        )
        assert level == "low"


# ── 17. Risk — aws_subnet ─────────────────────────────────────────────────────


class TestSubnetRisk:
    def _change_subnet(self, ct: str = "modified", fp: str | None = None,
                       nv: Any = None, pv: Any = None) -> dict:
        return _change(AWS_SUBNET, change_type=ct, field_path=fp, new_value=nv,
                       prev_value=pv, record_id="us-east-1/subnet-11111111")

    def test_added_low(self) -> None:
        level, _ = _classify_subnet_change(self._change_subnet("added"))
        assert level == "low"

    def test_removed_low(self) -> None:
        level, _ = _classify_subnet_change(self._change_subnet("removed"))
        assert level == "low"

    def test_map_public_ip_false_to_true_high(self) -> None:
        level, reason = _classify_subnet_change(
            self._change_subnet("modified", "map_public_ip_on_launch", True, False)
        )
        assert level == "high"
        assert "public" in reason.lower()

    def test_map_public_ip_true_to_false_low(self) -> None:
        level, _ = _classify_subnet_change(
            self._change_subnet("modified", "map_public_ip_on_launch", False, True)
        )
        assert level == "low"

    def test_state_changed_low(self) -> None:
        level, _ = _classify_subnet_change(
            self._change_subnet("modified", "state", "pending", "available")
        )
        assert level == "low"


# ── 18. Risk — aws_route_table ────────────────────────────────────────────────


class TestRouteTableRisk:
    def _change_rt(self, ct: str = "modified", fp: str | None = None,
                   nv: Any = None, pv: Any = None) -> dict:
        return _change(AWS_ROUTE_TABLE, change_type=ct, field_path=fp,
                       new_value=nv, prev_value=pv,
                       record_id="us-east-1/rtb-11111111")

    def test_added_low(self) -> None:
        level, _ = _classify_route_table_change(self._change_rt("added"))
        assert level == "low"

    def test_removed_low(self) -> None:
        level, _ = _classify_route_table_change(self._change_rt("removed"))
        assert level == "low"

    def test_has_igw_route_false_to_true_high(self) -> None:
        level, reason = _classify_route_table_change(
            self._change_rt("modified", "has_igw_route", True, False)
        )
        assert level == "high"
        assert "Internet Gateway" in reason

    def test_has_igw_route_true_to_false_low(self) -> None:
        level, _ = _classify_route_table_change(
            self._change_rt("modified", "has_igw_route", False, True)
        )
        assert level == "low"

    def test_route_count_decreased_medium(self) -> None:
        level, _ = _classify_route_table_change(
            self._change_rt("modified", "route_count", 1, 3)
        )
        assert level == "medium"

    def test_route_count_increased_low(self) -> None:
        level, _ = _classify_route_table_change(
            self._change_rt("modified", "route_count", 5, 3)
        )
        assert level == "low"


# ── 19. Risk — aws_internet_gateway ──────────────────────────────────────────


class TestIGWRisk:
    def _change_igw(self, ct: str = "modified", fp: str | None = None,
                    nv: Any = None, pv: Any = None) -> dict:
        return _change(AWS_INTERNET_GATEWAY, change_type=ct, field_path=fp,
                       new_value=nv, prev_value=pv,
                       record_id="us-east-1/igw-12345678")

    def test_added_without_vpc_low(self) -> None:
        level, _ = _classify_igw_change(
            _change(AWS_INTERNET_GATEWAY, change_type="added",
                    new_value={"attached_vpc_id": None},
                    record_id="us-east-1/igw-12345678")
        )
        assert level == "low"

    def test_added_with_vpc_attached_medium(self) -> None:
        level, _ = _classify_igw_change(
            _change(AWS_INTERNET_GATEWAY, change_type="added",
                    new_value={"attached_vpc_id": "vpc-aaaaaaaa"},
                    record_id="us-east-1/igw-12345678")
        )
        assert level == "medium"

    def test_removed_low(self) -> None:
        level, _ = _classify_igw_change(self._change_igw("removed"))
        assert level == "low"

    def test_attached_vpc_none_to_vpc_high(self) -> None:
        level, reason = _classify_igw_change(
            self._change_igw("modified", "attached_vpc_id", "vpc-aaaaaaaa", None)
        )
        assert level == "high"
        assert "attached" in reason.lower()

    def test_attached_vpc_to_none_low(self) -> None:
        level, _ = _classify_igw_change(
            self._change_igw("modified", "attached_vpc_id", None, "vpc-aaaaaaaa")
        )
        assert level == "low"

    def test_state_changed_low(self) -> None:
        level, _ = _classify_igw_change(
            self._change_igw("modified", "state", "available", "pending")
        )
        assert level == "low"


# ── 20. Risk — aws_network_acl ───────────────────────────────────────────────


class TestNetworkACLRisk:
    def _change_nacl(self, ct: str = "modified", fp: str | None = None,
                     nv: Any = None, pv: Any = None) -> dict:
        return _change(AWS_NETWORK_ACL, change_type=ct, field_path=fp,
                       new_value=nv, prev_value=pv,
                       record_id="us-east-1/acl-11111111")

    def test_added_low(self) -> None:
        level, _ = _classify_network_acl_change(self._change_nacl("added"))
        assert level == "low"

    def test_removed_low(self) -> None:
        level, _ = _classify_network_acl_change(self._change_nacl("removed"))
        assert level == "low"

    def test_inbound_allow_all_increased_medium(self) -> None:
        level, reason = _classify_network_acl_change(
            self._change_nacl("modified", "inbound_allow_all_count", 2, 1)
        )
        assert level == "medium"
        assert "inbound" in reason.lower()

    def test_inbound_allow_all_decreased_low(self) -> None:
        level, _ = _classify_network_acl_change(
            self._change_nacl("modified", "inbound_allow_all_count", 0, 1)
        )
        assert level == "low"

    def test_outbound_allow_all_increased_low(self) -> None:
        level, _ = _classify_network_acl_change(
            self._change_nacl("modified", "outbound_allow_all_count", 2, 1)
        )
        assert level == "low"

    def test_rule_count_changed_low(self) -> None:
        level, _ = _classify_network_acl_change(
            self._change_nacl("modified", "rule_count", 5, 4)
        )
        assert level == "low"


# ── 21. Schema constants ──────────────────────────────────────────────────────


class TestAWSSchemaM38:
    def test_security_group_constant(self) -> None:
        assert AWS_SECURITY_GROUP == "aws_security_group"

    def test_security_group_rule_constant(self) -> None:
        assert AWS_SECURITY_GROUP_RULE == "aws_security_group_rule"

    def test_vpc_constant(self) -> None:
        assert AWS_VPC == "aws_vpc"

    def test_subnet_constant(self) -> None:
        assert AWS_SUBNET == "aws_subnet"

    def test_route_table_constant(self) -> None:
        assert AWS_ROUTE_TABLE == "aws_route_table"

    def test_internet_gateway_constant(self) -> None:
        assert AWS_INTERNET_GATEWAY == "aws_internet_gateway"

    def test_network_acl_constant(self) -> None:
        assert AWS_NETWORK_ACL == "aws_network_acl"

    def test_all_m38_types_in_record_types(self) -> None:
        for rt in (
            AWS_SECURITY_GROUP, AWS_SECURITY_GROUP_RULE, AWS_VPC,
            AWS_SUBNET, AWS_ROUTE_TABLE, AWS_INTERNET_GATEWAY, AWS_NETWORK_ACL,
        ):
            assert rt in AWS_RECORD_TYPES, f"{rt!r} missing from AWS_RECORD_TYPES"

    def test_record_types_frozenset(self) -> None:
        assert isinstance(AWS_RECORD_TYPES, frozenset)


# ── 22. Security invariants ───────────────────────────────────────────────────


class TestSecurityInvariantsM38:
    """Verify that no credentials appear in network records."""

    def setup_method(self) -> None:
        self.connector = AWSConnector()

    def test_make_sg_rule_no_credentials(self) -> None:
        rule = self.connector._make_sg_rule(
            "sg-abc", "us-east-1", "ingress", "tcp", 22, 22, "0.0.0.0/0", ""
        )
        content = str(rule)
        assert "AKIAIOSFODNN7EXAMPLE" not in content
        assert "wJalrXUtnFEMI" not in content

    def test_fetch_security_groups_no_credentials(self) -> None:
        client = _mock_client()
        with patch.object(self.connector, "_call_aws", return_value=_SG_RESPONSE_SSH_PUBLIC):
            records = self.connector._fetch_security_groups(client, "us-east-1")
        for r in records:
            content = str(r)
            assert "wJalrXUtnFEMI" not in content
            assert "AKIAIOSFODNN7EXAMPLE" not in content

    def test_no_write_api_calls(self) -> None:
        """_fetch_network_resources must only call read/describe APIs."""
        side_effects = [
            {"SecurityGroups": []},
            {"Vpcs": []},
            {"InternetGateways": []},
            {"RouteTables": []},
            {"Subnets": []},
            {"NetworkAcls": []},
        ]
        with patch.object(self.connector, "_make_client", return_value=_mock_client()):
            mock_call = MagicMock(side_effect=side_effects)
            with patch.object(self.connector, "_call_aws", mock_call):
                self.connector._fetch_network_resources(_CREDS)

        # Verify only describe/list calls were made
        for c in mock_call.call_args_list:
            fn = c[0][0]
            fn_name = getattr(fn, "_mock_name", str(fn))
            write_verbs = ("create", "delete", "modify", "authorize", "revoke",
                           "put", "attach", "detach", "enable", "disable")
            for verb in write_verbs:
                assert verb not in fn_name.lower(), f"Write API call detected: {fn_name}"


# ── 23. M36 / M37 regression ─────────────────────────────────────────────────


class TestM36M37Regression:
    """Ensure M38 does not break previously-passing M36/M37 behaviour."""

    def test_classify_aws_still_routes_account_identity(self) -> None:
        c = _change(AWS_ACCOUNT_IDENTITY, "modified", "principal_arn",
                    "arn:new", "arn:old", record_id="123456789012")
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_classify_aws_still_routes_s3_bucket_critical(self) -> None:
        c = _change(
            AWS_S3_BUCKET,
            change_type="modified",
            field_path="policy_status_is_public",
            new_value=True,
            prev_value=False,
            record_id="my-prod-bucket",
        )
        level, _ = classify_aws_change(c)
        assert level == "critical"

    def test_classify_aws_dispatches_sg_rule(self) -> None:
        rule = _sg_rule_dict()
        c = _change(AWS_SECURITY_GROUP_RULE, "added", new_value=rule)
        level, _ = classify_aws_change(c)
        assert level == "critical"  # public SSH

    def test_classify_aws_dispatches_igw(self) -> None:
        c = _change(AWS_INTERNET_GATEWAY, "modified", "attached_vpc_id",
                    "vpc-new", None, record_id="us-east-1/igw-12345678")
        level, _ = classify_aws_change(c)
        assert level == "high"

    def test_classify_aws_unknown_type_low(self) -> None:
        c = _change("aws_future_surface", "modified")
        level, _ = classify_aws_change(c)
        assert level == "low"


# ── 24. classify_aws_ec2_failure — M38 ────────────────────────────────────────


class TestClassifyAwsEC2Failure:
    """Unit tests for failure_classifier.classify_aws_ec2_failure (M38)."""

    def _exc_403(self) -> "ConnectorError":
        from app.connectors.exceptions import ConnectorError
        return ConnectorError("AccessDenied", status_code=403)

    def _exc_500(self) -> "ConnectorError":
        from app.connectors.exceptions import ConnectorError
        return ConnectorError("ServiceUnavailable", status_code=503)

    def _exc_rate(self) -> "RateLimitError":
        from app.connectors.exceptions import RateLimitError
        return RateLimitError("Throttling")

    def _exc_network(self) -> "NetworkError":
        from app.connectors.exceptions import NetworkError
        return NetworkError("Connection refused")

    def _classify(self, api_name: str, exc: Exception):
        from app.core.failure_classifier import classify_aws_ec2_failure
        return classify_aws_ec2_failure(api_name, exc)

    def test_403_returns_ec2_access_denied(self) -> None:
        fc = self._classify("DescribeSecurityGroups", self._exc_403())
        assert fc.error_code == "aws_ec2_access_denied"
        assert fc.category == "authentication"

    def test_403_auth_error_returns_ec2_access_denied(self) -> None:
        from app.connectors.exceptions import AuthenticationError
        fc = self._classify("DescribeVpcs", AuthenticationError("InvalidClientTokenId"))
        assert fc.error_code == "aws_ec2_access_denied"
        assert fc.category == "authentication"

    def test_403_action_mentions_describe_permissions(self) -> None:
        fc = self._classify("DescribeSecurityGroups", self._exc_403())
        assert "ec2:DescribeSecurityGroups" in fc.recommended_action
        assert "ec2:DescribeVpcs" in fc.recommended_action

    def test_rate_limit_returns_ec2_rate_limited(self) -> None:
        fc = self._classify("DescribeSubnets", self._exc_rate())
        assert fc.error_code == "aws_ec2_rate_limited"
        assert fc.category == "rate_limited"

    def test_rate_limit_action_mentions_retry(self) -> None:
        fc = self._classify("DescribeSubnets", self._exc_rate())
        assert "retry" in fc.recommended_action.lower()

    def test_network_error_returns_network_error(self) -> None:
        fc = self._classify("DescribeRouteTables", self._exc_network())
        assert fc.error_code == "network_error"
        assert fc.category == "network"

    def test_5xx_returns_ec2_api_unavailable(self) -> None:
        fc = self._classify("DescribeVpcs", self._exc_500())
        assert fc.error_code == "aws_ec2_api_unavailable"
        assert fc.category == "provider_unavailable"

    def test_describe_security_groups_unavailable(self) -> None:
        fc = self._classify("DescribeSecurityGroups", RuntimeError("unexpected"))
        assert fc.error_code == "aws_security_groups_unavailable"
        assert fc.category == "provider_unavailable"

    def test_describe_vpcs_unavailable(self) -> None:
        fc = self._classify("DescribeVpcs", RuntimeError("unexpected"))
        assert fc.error_code == "aws_vpc_unavailable"

    def test_describe_subnets_unavailable(self) -> None:
        fc = self._classify("DescribeSubnets", RuntimeError("unexpected"))
        assert fc.error_code == "aws_subnets_unavailable"

    def test_describe_route_tables_unavailable(self) -> None:
        fc = self._classify("DescribeRouteTables", RuntimeError("unexpected"))
        assert fc.error_code == "aws_route_tables_unavailable"

    def test_describe_igws_unavailable(self) -> None:
        fc = self._classify("DescribeInternetGateways", RuntimeError("unexpected"))
        assert fc.error_code == "aws_internet_gateways_unavailable"

    def test_describe_network_acls_unavailable(self) -> None:
        fc = self._classify("DescribeNetworkAcls", RuntimeError("unexpected"))
        assert fc.error_code == "aws_network_acls_unavailable"

    def test_describe_sg_rules_unavailable(self) -> None:
        fc = self._classify("DescribeSecurityGroupRules", RuntimeError("unexpected"))
        assert fc.error_code == "aws_security_group_rules_unavailable"

    def test_unknown_api_name_returns_ec2_api_unavailable(self) -> None:
        fc = self._classify("DescribeSomethingFuture", RuntimeError("unexpected"))
        assert fc.error_code == "aws_ec2_api_unavailable"

    def test_action_never_contains_credentials(self) -> None:
        """Recommended actions must never leak credential strings."""
        import secrets
        fake_key = "AKIA" + secrets.token_hex(8)
        fc = self._classify("DescribeSecurityGroups", self._exc_403())
        assert fake_key not in fc.recommended_action
        assert "secret" not in fc.recommended_action.lower()

    def test_partial_failure_action_mentions_other_checks(self) -> None:
        fc = self._classify("DescribeSecurityGroups", RuntimeError("unexpected"))
        assert "other AWS checks may still work" in fc.recommended_action
