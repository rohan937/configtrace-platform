"""AWS connector record type constants — M36 / M37 / M38."""
from __future__ import annotations

# ── M36 record types ──────────────────────────────────────────────────────────
AWS_ACCOUNT_IDENTITY = "aws_account_identity"
AWS_REGION = "aws_region"
AWS_SERVICE_INVENTORY = "aws_service_inventory"

# ── M37 record types ──────────────────────────────────────────────────────────
AWS_S3_BUCKET = "aws_s3_bucket"

# ── M38 record types — Security Groups + VPC Network Exposure ─────────────────
AWS_SECURITY_GROUP = "aws_security_group"
AWS_SECURITY_GROUP_RULE = "aws_security_group_rule"
AWS_VPC = "aws_vpc"
AWS_SUBNET = "aws_subnet"
AWS_ROUTE_TABLE = "aws_route_table"
AWS_INTERNET_GATEWAY = "aws_internet_gateway"
AWS_NETWORK_ACL = "aws_network_acl"

AWS_RECORD_TYPES: frozenset[str] = frozenset({
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    # M37
    AWS_S3_BUCKET,
    # M38
    AWS_SECURITY_GROUP,
    AWS_SECURITY_GROUP_RULE,
    AWS_VPC,
    AWS_SUBNET,
    AWS_ROUTE_TABLE,
    AWS_INTERNET_GATEWAY,
    AWS_NETWORK_ACL,
})
