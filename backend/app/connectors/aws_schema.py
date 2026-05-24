"""AWS connector record type constants — M36 / M37 / M38 / M39 / M40 / M41 / M42."""
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

# ── M39 record types — IAM Identity, Permissions, Policy and Trust Risk ───────
# One per AWS account — aggregate account-level IAM posture.
AWS_IAM_ACCOUNT_SUMMARY = "aws_iam_account_summary"
# One per IAM user — identity, MFA, access key counts, group/policy membership.
AWS_IAM_USER = "aws_iam_user"
# One per IAM access key — metadata only; secret key is NEVER stored.
AWS_IAM_ACCESS_KEY = "aws_iam_access_key"
# One per IAM group — members, attached and inline policies.
AWS_IAM_GROUP = "aws_iam_group"
# One per IAM role — trust summary, attached and inline policies.
AWS_IAM_ROLE = "aws_iam_role"
# One per customer-managed IAM policy — default-version policy summary.
AWS_IAM_POLICY = "aws_iam_policy"
# One per principal-to-managed-policy attachment (user, group, or role).
AWS_IAM_POLICY_ATTACHMENT = "aws_iam_policy_attachment"
# One per inline policy per principal (user, group, or role).
AWS_IAM_INLINE_POLICY = "aws_iam_inline_policy"
# One per OIDC or SAML identity provider registered in the account.
AWS_IAM_IDENTITY_PROVIDER = "aws_iam_identity_provider"

# ── M40 record types — Route53 DNS + CloudFront CDN Routing Config ────────────
# One per Route53 hosted zone — zone-level posture (public/private, NS, VPC links).
AWS_ROUTE53_HOSTED_ZONE = "aws_route53_hosted_zone"
# One per Route53 resource record set — individual DNS record (A, CNAME, MX, TXT, …).
AWS_ROUTE53_RECORD = "aws_route53_record"
# One per CloudFront distribution — CDN config, origins, protocol, aliases, WAF.
AWS_CLOUDFRONT_DISTRIBUTION = "aws_cloudfront_distribution"

# ── M41 record types — Secrets Manager + SSM Parameter Metadata ──────────────
# One per Secrets Manager secret — metadata only; secret value is NEVER stored.
AWS_SECRETSMANAGER_SECRET = "aws_secretsmanager_secret"
# One per SSM Parameter — metadata only; parameter value is NEVER stored.
AWS_SSM_PARAMETER = "aws_ssm_parameter"

# ── M42 record types — RDS Database Exposure / Backup / Encryption Config ────
# One per RDS DB instance — metadata only; no DB data, passwords, or connections.
AWS_RDS_DB_INSTANCE = "aws_rds_db_instance"
# One per RDS/Aurora DB cluster — metadata only.
AWS_RDS_DB_CLUSTER = "aws_rds_db_cluster"
# One per RDS DB subnet group — VPC/subnet topology metadata.
AWS_RDS_DB_SUBNET_GROUP = "aws_rds_db_subnet_group"
# One per RDS DB snapshot — metadata only; no log downloads or data access.
AWS_RDS_DB_SNAPSHOT = "aws_rds_db_snapshot"
# One per RDS DB cluster snapshot — metadata only.
AWS_RDS_DB_CLUSTER_SNAPSHOT = "aws_rds_db_cluster_snapshot"

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
    # M39
    AWS_IAM_ACCOUNT_SUMMARY,
    AWS_IAM_USER,
    AWS_IAM_ACCESS_KEY,
    AWS_IAM_GROUP,
    AWS_IAM_ROLE,
    AWS_IAM_POLICY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_IAM_INLINE_POLICY,
    AWS_IAM_IDENTITY_PROVIDER,
    # M40
    AWS_ROUTE53_HOSTED_ZONE,
    AWS_ROUTE53_RECORD,
    AWS_CLOUDFRONT_DISTRIBUTION,
    # M41
    AWS_SECRETSMANAGER_SECRET,
    AWS_SSM_PARAMETER,
    # M42
    AWS_RDS_DB_INSTANCE,
    AWS_RDS_DB_CLUSTER,
    AWS_RDS_DB_SUBNET_GROUP,
    AWS_RDS_DB_SNAPSHOT,
    AWS_RDS_DB_CLUSTER_SNAPSHOT,
})
