"""AWS connector record type constants — M36 / M37 / M38 / M39 / M40 / M41 / M42 / M43 / M44."""
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

# ── M44 record types — Load Balancers + WAF Config ───────────────────────────
# One per ELBv2 load balancer (Application, Network, Gateway) — metadata only.
AWS_ELBV2_LOAD_BALANCER = "aws_elbv2_load_balancer"
# One per ELBv2 target group — metadata only; no target contents.
AWS_ELBV2_TARGET_GROUP = "aws_elbv2_target_group"
# One per ELBv2 listener — metadata only; no request/response traffic.
AWS_ELBV2_LISTENER = "aws_elbv2_listener"
# One per ELBv2 listener rule — metadata only; no rule-matched traffic.
AWS_ELBV2_LISTENER_RULE = "aws_elbv2_listener_rule"
# One per Classic (v1) ELB — metadata only; no access log objects.
AWS_ELB_CLASSIC_LOAD_BALANCER = "aws_elb_classic_load_balancer"
# One per WAFv2 Web ACL — metadata only; sampled requests NEVER accessed.
AWS_WAFV2_WEB_ACL = "aws_wafv2_web_acl"
# One per WAFv2 Web ACL association — maps Web ACL to a protected resource.
AWS_WAFV2_WEB_ACL_ASSOCIATION = "aws_wafv2_web_acl_association"

# ── M43 record types — Lambda + API Gateway Runtime/API Config ───────────────
# One per Lambda function — metadata only; function code is NEVER accessed.
AWS_LAMBDA_FUNCTION = "aws_lambda_function"
# One per Lambda alias — routing/traffic split metadata.
AWS_LAMBDA_ALIAS = "aws_lambda_alias"
# One per Lambda event source mapping — trigger/stream metadata.
AWS_LAMBDA_EVENT_SOURCE_MAPPING = "aws_lambda_event_source_mapping"
# One per Lambda function URL — public endpoint auth/CORS metadata.
AWS_LAMBDA_FUNCTION_URL = "aws_lambda_function_url"
# One per API Gateway REST API — metadata; no request/response bodies or logs.
AWS_APIGATEWAY_REST_API = "aws_apigateway_rest_api"
# One per API Gateway REST API stage — deployment/logging/throttling metadata.
AWS_APIGATEWAY_REST_STAGE = "aws_apigateway_rest_stage"
# One per API Gateway V2 (HTTP/WebSocket) API — metadata only.
AWS_APIGATEWAYV2_API = "aws_apigatewayv2_api"
# One per API Gateway V2 stage — deployment/logging/routing metadata.
AWS_APIGATEWAYV2_STAGE = "aws_apigatewayv2_stage"

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
    # M43
    AWS_LAMBDA_FUNCTION,
    AWS_LAMBDA_ALIAS,
    AWS_LAMBDA_EVENT_SOURCE_MAPPING,
    AWS_LAMBDA_FUNCTION_URL,
    AWS_APIGATEWAY_REST_API,
    AWS_APIGATEWAY_REST_STAGE,
    AWS_APIGATEWAYV2_API,
    AWS_APIGATEWAYV2_STAGE,
    # M44
    AWS_ELBV2_LOAD_BALANCER,
    AWS_ELBV2_TARGET_GROUP,
    AWS_ELBV2_LISTENER,
    AWS_ELBV2_LISTENER_RULE,
    AWS_ELB_CLASSIC_LOAD_BALANCER,
    AWS_WAFV2_WEB_ACL,
    AWS_WAFV2_WEB_ACL_ASSOCIATION,
})
