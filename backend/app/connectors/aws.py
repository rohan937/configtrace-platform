"""AWS connector — M36: Foundation + Account Inventory; M37: S3 Exposure; M38: Security Groups + VPC.

Fetches safe account/inventory metadata from AWS using read-only IAM credentials.

Resources fetched in M36
-----------------------
aws_account_identity
    STS GetCallerIdentity — stable account ID, principal type, partition.
    Always fetched first; also used for duplicate-account detection.

aws_region
    EC2 DescribeRegions — one record per selected region.
    OPTIONAL: if ec2:DescribeRegions is not permitted (403/AccessDenied),
    falls back to the user-configured selected_regions list silently.

aws_service_inventory
    Lists which surfaces are actively monitored and which are planned.

Resources fetched in M37
-----------------------
aws_s3_bucket
    One record per S3 bucket visible to the credentials.

Resources fetched in M38
-----------------------
aws_security_group
    One record per EC2 security group per selected region.
    Includes aggregate posture fields (has_public_ssh, has_public_rdp, etc.)
    computed from the group's ingress rules.
aws_security_group_rule
    One record per flattened ingress/egress rule per security group.
    Rules are flattened so each CIDR (IPv4, IPv6) or referenced group is
    a separate record.  Stable IDs are deterministic hashes of
    region|group_id|direction|protocol|from_port|to_port|cidr.
aws_vpc
    One record per VPC per selected region.
aws_subnet
    One record per subnet per selected region.  Tracks
    map_public_ip_on_launch as the primary exposure signal.
aws_route_table
    One record per route table per selected region.  Tracks
    has_igw_route as the key internet-routing signal.
aws_internet_gateway
    One record per IGW per selected region.  Tracks attached_vpc_id.
aws_network_acl
    One record per Network ACL per selected region.  Tracks
    inbound_allow_all_count / outbound_allow_all_count.

SECURITY (M38)
--------------
- No write operations are performed.  No resource mutations.
- No AdministratorAccess is requested or required.
- All network resource calls are read-only describe operations.
- "may be reachable" language is used in risk messages: a SG rule
  allowing public CIDR does not prove reachability without subnet/IGW
  context, so risk reasons hedge appropriately.
    Includes Block Public Access, policy public status, ACL public grants,
    encryption, versioning, logging, lifecycle rule count, and tag keys.
    Per-field optional failures are recorded as config_fetch_warnings rather
    than failing the entire sync (fail-soft design).

    SECURITY: object names/contents are NEVER fetched. Raw bucket policies are
    NEVER stored — only a short SHA-256 prefix (policy_hash) and parsed summary
    fields (public_principals_detected, policy_status_is_public) are kept.

Auth / credentials
------------------
Credentials dict:
    aws_access_key_id      : str          — IAM access key ID (AKIA...)
    aws_secret_access_key  : str          — IAM secret access key
    aws_default_region     : str          — primary region (default: us-east-1)
    aws_selected_regions   : list[str]    — regions to monitor

SECURITY
--------
- aws_access_key_id is NEVER logged in full. Only _safe_key_id() output is logged.
- aws_secret_access_key is NEVER logged under any circumstances.
- All API calls are read-only. No write operations are ever performed.
- Temporary session tokens are not stored or returned.
- S3 object contents and object keys are NEVER fetched or stored.
- Raw bucket policy text is NEVER stored; only policy_hash + parsed fields.

Future extension
----------------
Add new methods to AWSConnector for each new AWS milestone.
The _make_client() and _call_aws() helpers provide consistent error handling.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.core.failure_classifier import (
    classify_aws_ec2_failure,
    classify_aws_iam_failure,
    classify_aws_route53_failure,
    classify_aws_cloudfront_failure,
    classify_aws_secretsmanager_failure,
    classify_aws_ssm_failure,
    classify_aws_rds_failure,
    classify_aws_lambda_failure,
    classify_aws_apigateway_failure,
    classify_aws_elbv2_failure,
    classify_aws_elb_classic_failure,
    classify_aws_wafv2_failure,
    classify_aws_cloudtrail_failure,
    classify_aws_guardduty_failure,
    classify_aws_securityhub_failure,
    classify_aws_ecs_failure,
    classify_aws_eks_failure,
    classify_aws_ecr_failure,
    classify_aws_eventbridge_failure,
    classify_aws_sqs_failure,
    classify_aws_sns_failure,
    classify_aws_kms_failure,
    classify_aws_backup_failure,
    classify_aws_organizations_failure,
    classify_aws_cloudwatch_failure,
    classify_aws_cloudwatch_logs_failure,
)
from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    AWS_S3_BUCKET,
    AWS_SECURITY_GROUP,
    AWS_SECURITY_GROUP_RULE,
    AWS_VPC,
    AWS_SUBNET,
    AWS_ROUTE_TABLE,
    AWS_INTERNET_GATEWAY,
    AWS_NETWORK_ACL,
    AWS_IAM_ACCOUNT_SUMMARY,
    AWS_IAM_USER,
    AWS_IAM_ACCESS_KEY,
    AWS_IAM_GROUP,
    AWS_IAM_ROLE,
    AWS_IAM_POLICY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_IAM_INLINE_POLICY,
    AWS_IAM_IDENTITY_PROVIDER,
    AWS_ROUTE53_HOSTED_ZONE,
    AWS_ROUTE53_RECORD,
    AWS_CLOUDFRONT_DISTRIBUTION,
    AWS_SECRETSMANAGER_SECRET,
    AWS_SSM_PARAMETER,
    AWS_RDS_DB_INSTANCE,
    AWS_RDS_DB_CLUSTER,
    AWS_RDS_DB_SUBNET_GROUP,
    AWS_RDS_DB_SNAPSHOT,
    AWS_RDS_DB_CLUSTER_SNAPSHOT,
    AWS_LAMBDA_FUNCTION,
    AWS_LAMBDA_ALIAS,
    AWS_LAMBDA_EVENT_SOURCE_MAPPING,
    AWS_LAMBDA_FUNCTION_URL,
    AWS_APIGATEWAY_REST_API,
    AWS_APIGATEWAY_REST_STAGE,
    AWS_APIGATEWAYV2_API,
    AWS_APIGATEWAYV2_STAGE,
    AWS_ELBV2_LOAD_BALANCER,
    AWS_ELBV2_TARGET_GROUP,
    AWS_ELBV2_LISTENER,
    AWS_ELBV2_LISTENER_RULE,
    AWS_ELB_CLASSIC_LOAD_BALANCER,
    AWS_WAFV2_WEB_ACL,
    AWS_WAFV2_WEB_ACL_ASSOCIATION,
    AWS_CLOUDTRAIL_TRAIL,
    AWS_CLOUDTRAIL_EVENT_DATA_STORE,
    AWS_GUARDDUTY_DETECTOR,
    AWS_GUARDDUTY_PUBLISHING_DESTINATION,
    AWS_SECURITYHUB_ACCOUNT,
    AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
    AWS_SECURITYHUB_FINDING_AGGREGATOR,
    AWS_ECS_CLUSTER,
    AWS_ECS_SERVICE,
    AWS_ECS_TASK_DEFINITION,
    AWS_EKS_CLUSTER,
    AWS_EKS_NODE_GROUP,
    AWS_EKS_FARGATE_PROFILE,
    AWS_EKS_ADDON,
    AWS_ECR_REPOSITORY,
    AWS_ECR_REGISTRY_SCANNING_CONFIG,
    AWS_EVENTBRIDGE_EVENT_BUS,
    AWS_EVENTBRIDGE_RULE,
    AWS_EVENTBRIDGE_TARGET,
    AWS_EVENTBRIDGE_ARCHIVE,
    AWS_SQS_QUEUE,
    AWS_SNS_TOPIC,
    AWS_SNS_SUBSCRIPTION,
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
    AWS_CLOUDWATCH_METRIC_ALARM,
    AWS_CLOUDWATCH_COMPOSITE_ALARM,
    AWS_CLOUDWATCH_DASHBOARD,
    AWS_CLOUDWATCH_LOG_GROUP,
    AWS_CLOUDWATCH_METRIC_FILTER,
    AWS_CLOUDWATCH_SUBSCRIPTION_FILTER,
    AWS_CLOUDWATCH_METRIC_STREAM,
    AWS_CLOUDWATCH_ANOMALY_DETECTOR,
)

logger = logging.getLogger(__name__)

# AWS error codes that indicate invalid/revoked credentials (401 equivalent)
_AUTH_ERROR_CODES = frozenset({
    "InvalidClientTokenId",
    "AuthFailure",
    "SignatureDoesNotMatch",
    "InvalidSignatureException",
    "TokenRefreshRequired",
    "ExpiredTokenException",
    "InvalidAccessKeyId",
    "MissingAuthenticationToken",
})

# AWS error codes that indicate permissions missing but creds valid (403 equivalent)
_ACCESS_DENIED_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
})

# AWS error codes for throttling/rate limiting
_THROTTLE_CODES = frozenset({
    "Throttling",
    "ThrottlingException",
    "RequestThrottled",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "TransactionInProgressException",
    "SlowDown",
})


# ── S3-specific "not found" error codes ──────────────────────────────────────
# These codes indicate a configuration is absent (safe state), not an error.
# Used by _fetch_bucket_* helpers to distinguish "not configured" from failures.
_S3_NOT_CONFIGURED_CODES: frozenset[str] = frozenset({
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchLifecycleConfiguration",
    "NoSuchTagSet",
})

# ACL group URIs for public access detection
_ACL_ALL_USERS_URI         = "http://acs.amazonaws.com/groups/global/AllUsers"
_ACL_AUTH_USERS_URI        = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_ACL_READ_PERMISSIONS      = frozenset({"READ", "FULL_CONTROL"})
_ACL_WRITE_PERMISSIONS     = frozenset({"WRITE", "FULL_CONTROL"})


# ── M38: Security Group / Network helpers ────────────────────────────────────

# Port sets used for categorising security group rules.
_SG_ADMIN_PORTS: frozenset[int] = frozenset({22, 3389, 5985, 5986})
_SG_DATABASE_PORTS: frozenset[int] = frozenset({
    5432, 3306, 1433, 1521, 27017, 6379,
    9200, 9300, 11211, 9042, 9092,
})
_SG_WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})


def _cidr_is_public(cidr: str) -> bool:
    """Return True if *cidr* represents unrestricted public internet access.

    Only the canonical "any" CIDRs qualify:
    - 0.0.0.0/0  → all IPv4 addresses
    - ::/0        → all IPv6 addresses

    RFC-1918 private ranges and smaller public prefixes are NOT considered
    public for risk-classification purposes.
    """
    return cidr in ("0.0.0.0/0", "::/0")


def _has_port_in_range(
    port: int,
    from_port: int | None,
    to_port: int | None,
    protocol: str,
) -> bool:
    """Return True if *port* is covered by the permission's port range.

    Protocol "-1" means all-traffic: every port is included.
    None ports (e.g. ICMP rules) are treated as not covering *port*.
    """
    if protocol == "-1":
        return True
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _port_category(
    from_port: int | None,
    to_port: int | None,
    protocol: str,
) -> str:
    """Classify the port range into a security-relevant category.

    Returns one of: "all", "admin", "database", "web", "other".

    "all" is returned for protocol "-1" (all-traffic rules) OR for a TCP/UDP
    rule whose port range spans the entire port space (0/1–65535). The wide-range
    check runs BEFORE the admin/database/web sentinel checks: a range such as
    1–65535 covers admin ports too, so it must classify as the more severe
    "all" category rather than being mislabeled "admin". Only a genuinely full
    range (or protocol "-1") qualifies as "all" — narrow admin/db ranges do not.
    Admin, database, and web categories are then detected by checking whether
    any sentinel port from the respective set falls within [from_port, to_port].
    """
    if protocol == "-1":
        return "all"
    if from_port is None or to_port is None:
        return "other"
    # Full-range TCP/UDP rule (e.g. 0-65535 or 1-65535) → "all" (most severe).
    # Checked first so a wide range that also covers admin/db ports is not
    # mislabeled as the lower-severity "admin"/"database" category.
    if from_port <= 1 and to_port >= 65535:
        return "all"
    for p in _SG_ADMIN_PORTS:
        if from_port <= p <= to_port:
            return "admin"
    for p in _SG_DATABASE_PORTS:
        if from_port <= p <= to_port:
            return "database"
    for p in _SG_WEB_PORTS:
        if from_port <= p <= to_port:
            return "web"
    return "other"


def _sg_rule_stable_id(
    region: str,
    group_id: str,
    direction: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidr: str,
) -> str:
    """Compute a deterministic 12-character hex ID for a security group rule.

    The ID is stable across syncs as long as the structural properties of the
    rule (direction, protocol, ports, CIDR) do not change.  Description is
    intentionally excluded so description-only changes are tracked as field
    modifications rather than remove+add events.

    Returns a 12-hex-character string (48 bits of SHA-256).
    """
    parts = "|".join([
        region, group_id, direction, protocol,
        str(from_port) if from_port is not None else "",
        str(to_port) if to_port is not None else "",
        cidr,
    ])
    return hashlib.sha256(parts.encode()).hexdigest()[:12]


def _extract_tag_keys(tags: list[dict]) -> list[str] | None:
    """Return sorted tag key names from an AWS Tags list, or None if empty."""
    if not tags:
        return None
    keys = sorted(t["Key"] for t in tags if "Key" in t)
    return keys if keys else None


# ── M40: Route53 + CloudFront helpers ────────────────────────────────────────


def _hash_dns_values(values: list[str]) -> str:
    """Return a 16-hex-character SHA-256 of sorted DNS record values.

    Used for TXT and other record types to detect value changes without
    storing raw record data.  Sorted for stability across API response ordering.

    SECURITY: Raw DNS values (e.g. TXT record content) are never stored.
    """
    import hashlib
    canonical = "|".join(sorted(values))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _values_summary(values: list[str], max_items: int = 3, max_len: int = 80) -> list[str]:
    """Return a truncated summary list of DNS record values.

    Used for non-sensitive record types (A, AAAA, MX, NS, CNAME).
    TXT records use _hash_dns_values instead.

    Each value is truncated to max_len characters.  At most max_items values
    are returned; if there are more, the last entry is replaced with a count.
    """
    truncated = [v[:max_len] for v in values[:max_items]]
    if len(values) > max_items:
        truncated.append(f"... +{len(values) - max_items} more")
    return truncated


def _detect_routing_policy(rrset: dict) -> str:
    """Detect Route53 routing policy from a resource record set dict.

    Returns one of: simple, weighted, latency, failover, geolocation,
    geoproximity, multivalue, or simple (default fallback).
    """
    if "Weight" in rrset:
        return "weighted"
    if "Region" in rrset:
        return "latency"
    if "Failover" in rrset:
        return "failover"
    if "GeoLocation" in rrset:
        return "geolocation"
    if "GeoProximityLocation" in rrset:
        return "geoproximity"
    if rrset.get("MultiValueAnswer"):
        return "multivalue"
    return "simple"


def _classify_cf_origin_type(domain: str) -> str:
    """Classify a CloudFront origin domain as s3/custom/load_balancer/api_gateway/mediastore.

    Uses a best-effort heuristic on the domain name.
    """
    d = domain.lower()
    if ".s3." in d or d.endswith(".s3.amazonaws.com") or ".s3-" in d:
        return "s3"
    if "elb.amazonaws.com" in d or "alb.amazonaws.com" in d:
        return "load_balancer"
    if "execute-api" in d and "amazonaws.com" in d:
        return "api_gateway"
    if "mediastore" in d and "amazonaws.com" in d:
        return "mediastore"
    return "custom"


def _extract_dmarc_policy(txt_values: list[str]) -> str | None:
    """Extract the DMARC 'p=' policy tag from TXT record values.

    Searches all values for one that starts with "v=DMARC1" (case-insensitive).
    Returns "none", "quarantine", "reject", or "unknown" if found; None if
    no DMARC record is present.

    SECURITY: Raw TXT values are never stored; only the extracted policy tag.
    """
    for val in txt_values:
        stripped = val.strip().strip('"')
        if stripped.lower().startswith("v=dmarc1"):
            for part in stripped.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy_val = part[2:].strip().lower()
                    if policy_val in ("none", "quarantine", "reject"):
                        return policy_val
                    return "unknown"
            # v=DMARC1 found but no p= tag — treat as "unknown"
            return "unknown"
    return None


def _parse_bucket_policy_public(policy_json: str) -> bool:
    """Return True if the bucket policy contains a public principal.

    A public principal is defined as:
    - Principal: "*"
    - Principal: {"AWS": "*"}  or  {"AWS": ["*", ...]}

    Only Allow statements are checked. Deny overrides are not evaluated here
    because the authoritative public-exposure signal is policy_status_is_public
    from GetBucketPolicyStatus. This function provides a secondary conservative
    indicator when GetBucketPolicyStatus is unavailable.

    SECURITY: policy_json is parsed in memory only; it is never stored.
    """
    import json
    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, ValueError):
        return False

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "").upper() != "ALLOW":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_p = principal.get("AWS", [])
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            if isinstance(aws_p, list) and "*" in aws_p:
                return True
    return False


def _parse_principal_type(arn: str) -> str:
    """Extract principal type from an IAM ARN.

    Examples:
        arn:aws:iam::123456789012:user/alice          → "user"
        arn:aws:iam::123456789012:role/MyRole         → "role"
        arn:aws:sts::123456789012:assumed-role/R/sess → "assumed-role"
        arn:aws:iam::123456789012:root                → "root"
    """
    if not arn:
        return "unknown"
    parts = arn.split(":")
    if len(parts) < 6:
        return "unknown"
    resource = parts[5]  # e.g. "user/alice", "role/MyRole", "assumed-role/R/sess"
    resource_type = resource.split("/")[0].lower()
    return resource_type if resource_type else "unknown"


def _parse_partition(arn: str) -> str:
    """Extract partition from an IAM ARN (aws, aws-cn, aws-us-gov)."""
    if not arn:
        return "aws"
    parts = arn.split(":")
    return parts[1] if len(parts) >= 2 else "aws"


# ── M41: Secrets Manager + SSM helpers ───────────────────────────────────────


def _hash_kms_key_id(key_id: str) -> str:
    """Return a 12-character hex SHA-256 of a KMS key ID/ARN.

    Used to detect KMS key changes without storing the raw ARN.

    SECURITY: The raw key ID is never stored or returned.
    """
    return hashlib.sha256(key_id.encode("utf-8")).hexdigest()[:12]


# Sensitivity categories and their keyword patterns for secret names.
_SECRET_NAME_PATTERNS: dict[str, frozenset[str]] = {
    "secret":      frozenset({"secret", "secrets", "secretkey", "secret_key"}),
    "credential":  frozenset({"credential", "credentials", "cred", "creds", "passwd", "password", "pass"}),
    "api_key":     frozenset({"apikey", "api_key", "api-key", "token", "access_key", "accesskey"}),
    "auth":        frozenset({"auth", "oauth", "jwt", "cookie", "session", "sso", "saml", "oidc"}),
    "payment":     frozenset({"payment", "stripe", "paypal", "billing", "invoice", "card"}),
    "database":    frozenset({"db", "database", "rds", "postgres", "mysql", "mongo", "redis", "sql"}),
    "production":  frozenset({"prod", "production", "live"}),
    "config":      frozenset({"config", "configuration", "settings", "env", "environment"}),
}


def _classify_secret_name_sensitivity(name: str) -> str:
    """Return sensitivity category for a Secrets Manager secret name.

    Returns one of: secret, credential, api_key, auth, payment, database,
    production, config, none.

    SECURITY: The name is checked against known patterns; name itself is never
    stored in risk messages beyond what's already in record_name.
    """
    lower = name.lower()
    for category, patterns in _SECRET_NAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in lower:
                return category
    return "none"


# SSM parameter name patterns (same categories).
_SSM_NAME_PATTERNS: dict[str, frozenset[str]] = {
    "secret":      frozenset({"secret", "secrets", "secretkey", "secret_key"}),
    "credential":  frozenset({"credential", "credentials", "cred", "creds", "passwd", "password", "pass"}),
    "api_key":     frozenset({"apikey", "api_key", "api-key", "token", "access_key", "accesskey"}),
    "auth":        frozenset({"auth", "oauth", "jwt", "cookie", "session", "sso", "saml", "oidc"}),
    "payment":     frozenset({"payment", "stripe", "paypal", "billing", "invoice", "card"}),
    "database":    frozenset({"db", "database", "rds", "postgres", "mysql", "mongo", "redis", "sql"}),
    "production":  frozenset({"prod", "production", "live"}),
    "config":      frozenset({"config", "configuration", "settings", "env", "environment"}),
}


def _classify_ssm_name_sensitivity(name: str) -> str:
    """Return sensitivity category for an SSM parameter name.

    Returns one of: secret, credential, api_key, auth, payment, database,
    production, config, none.
    """
    lower = name.lower()
    for category, patterns in _SSM_NAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in lower:
                return category
    return "none"


def _summarize_iam_arn(arn: str | None) -> str | None:
    """Return a safe summary of an IAM ARN (no raw ARN stored).

    Returns a structured string like "user/alice", "role/LambdaRole",
    or None if the ARN is absent/invalid.

    SECURITY: The full ARN is never stored; only the resource component.
    """
    if not arn:
        return None
    try:
        # arn:aws:iam::account_id:user/alice  → "user/alice"
        parts = arn.split(":", 5)
        if len(parts) >= 6:
            return parts[5][:128]  # cap length
        return None
    except Exception:
        return None


def _analyze_secret_resource_policy(policy_json: str, account_id: str) -> dict:
    """Return a safe policy summary — no raw JSON stored.

    Analyzes a Secrets Manager resource policy for key risk signals:
    - Wildcard principal (*): any principal can access the secret
    - Cross-account principals: principals from other accounts
    - Service principals: AWS service access

    SECURITY: The raw policy JSON is never stored or returned.
    Only aggregate boolean/count signals are returned.
    """
    import json
    summary: dict = {
        "has_wildcard_principal": False,
        "cross_account_principal_count": 0,
        "service_principal_count": 0,
        "statement_count": 0,
        "allow_statement_count": 0,
        "deny_statement_count": 0,
    }
    try:
        policy = json.loads(policy_json)
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        summary["statement_count"] = len(statements)
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "").upper()
            if effect == "ALLOW":
                summary["allow_statement_count"] += 1
            elif effect == "DENY":
                summary["deny_statement_count"] += 1
            principal = stmt.get("Principal")
            if principal == "*" or principal == {"AWS": "*"}:
                summary["has_wildcard_principal"] = True
            elif isinstance(principal, dict):
                aws_p = principal.get("AWS", [])
                if isinstance(aws_p, str):
                    aws_p = [aws_p]
                if "*" in aws_p:
                    summary["has_wildcard_principal"] = True
                else:
                    for p in aws_p:
                        if isinstance(p, str) and account_id and account_id not in p:
                            summary["cross_account_principal_count"] += 1
                svc_p = principal.get("Service", [])
                if isinstance(svc_p, str):
                    svc_p = [svc_p]
                summary["service_principal_count"] += len(svc_p)
    except Exception:
        # Malformed policy — return empty summary; raw JSON is never stored
        pass
    return summary


def _summarize_rotation_rules(rotation_rules: dict) -> dict | None:
    """Return a safe summary of RotationRules dict.

    Extracts only numeric/boolean fields; never stores raw configuration.
    """
    if not rotation_rules:
        return None
    return {
        "automatically_after_days": rotation_rules.get("AutomaticallyAfterDays"),
        "duration": rotation_rules.get("Duration"),
        "schedule_expression_present": bool(rotation_rules.get("ScheduleExpression")),
    }


def _summarize_ssm_policies(policies: list) -> dict | None:
    """Return a safe summary of SSM Parameter Store parameter policies.

    Each policy has a Type (Expiration, ExpirationNotification, NoChangeNotification)
    and a Status.

    SECURITY: Raw policy content is never stored.
    """
    if not policies:
        return None
    counts: dict[str, int] = {}
    for p in policies:
        ptype = p.get("Type") or "Unknown"
        counts[ptype] = counts.get(ptype, 0) + 1
    return {"type_counts": counts, "total": len(policies)}


# ── M42: RDS helpers ─────────────────────────────────────────────────────────

# RDS name sensitivity categories — same structure as M41 helpers.
_RDS_NAME_PATTERNS: dict[str, frozenset[str]] = {
    "production":  frozenset({"prod", "production", "live"}),
    "credential":  frozenset({"credential", "credentials", "passwd", "password", "pass"}),
    "api_key":     frozenset({"apikey", "api_key", "api-key", "token", "access_key"}),
    "auth":        frozenset({"auth", "login", "oauth", "sso"}),
    "payment":     frozenset({"payment", "stripe", "paypal", "billing", "checkout", "invoice"}),
    "database":    frozenset({"db", "database", "rds", "postgres", "mysql", "mongo", "redis", "sql"}),
    "internal":    frozenset({"admin", "dashboard", "portal", "internal", "private", "backend", "worker"}),
    "config":      frozenset({"config", "settings", "environment", "env"}),
    "secure":      frozenset({"secure", "secrets", "secret"}),
    "app":         frozenset({"app", "api", "customer", "checkout"}),
}


def _classify_rds_name_sensitivity(name: str) -> str:
    """Return sensitivity category for an RDS DB instance/cluster identifier.

    Returns one of: production, credential, api_key, auth, payment, database,
    internal, config, secure, app, none.
    """
    lower = name.lower()
    for category, patterns in _RDS_NAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in lower:
                return category
    return "none"


def _rds_engine_major_version(engine_version: str) -> str:
    """Extract major version string from full engine version.

    Examples:
        "8.0.28"  → "8"
        "5.7.40"  → "5"
        "14.5"    → "14"
        "aurora-mysql8.0.23" → "8"
    """
    if not engine_version:
        return "unknown"
    # Strip common prefixes like "aurora-mysql", "aurora-postgresql"
    ver = engine_version.lower()
    for prefix in ("aurora-mysql", "aurora-postgresql", "aurora-"):
        if ver.startswith(prefix):
            ver = ver[len(prefix):]
            break
    # Take first numeric segment
    parts = ver.split(".")
    if parts and parts[0].isdigit():
        return parts[0]
    return engine_version.split(".")[0] if engine_version else "unknown"


def _rds_summarize_pending_modified(pending: dict) -> dict | None:
    """Return a safe summary of PendingModifiedValues.

    Only records the presence/absence of pending changes by field name.
    Raw values (e.g. pending MasterUserPassword) are NEVER stored.

    SECURITY: MasterUserPassword and other credential fields are explicitly
    excluded even if present in the API response.
    """
    if not pending:
        return None
    # Fields that must NEVER be included in the summary
    _FORBIDDEN = frozenset({
        "MasterUserPassword", "masterUserPassword",
        "Password", "password",
    })
    present_fields = [
        k for k in pending
        if k not in _FORBIDDEN and pending[k] is not None and pending[k] != []
    ]
    return {"pending_fields": sorted(present_fields), "count": len(present_fields)} if present_fields else None


def _rds_sorted_sg_ids(vpc_security_groups: list) -> list[str]:
    """Return a sorted list of VPC security group IDs from a DB security group list."""
    ids = []
    for sg in vpc_security_groups:
        sg_id = sg.get("VpcSecurityGroupId") or sg.get("vpc_security_group_id")
        if sg_id:
            ids.append(str(sg_id))
    return sorted(ids)


def _rds_sorted_param_group_names(param_groups: list, key: str = "DBParameterGroupName") -> list[str]:
    """Return sorted parameter group names from a list of parameter group dicts."""
    names = []
    for pg in param_groups:
        name = pg.get(key)
        if name:
            names.append(str(name))
    return sorted(names)


def _rds_sorted_option_group_names(option_groups: list) -> list[str]:
    """Return sorted option group names from a list of option group membership dicts."""
    names = []
    for og in option_groups:
        name = og.get("OptionGroupName")
        if name:
            names.append(str(name))
    return sorted(names)


# ── M43: Lambda + API Gateway helpers ────────────────────────────────────────

# Lambda/API Gateway name sensitivity categories and keywords.
_LAMBDA_NAME_PATTERNS: dict[str, frozenset[str]] = {
    "production":  frozenset({"prod", "production", "live"}),
    "payment":     frozenset({"payment", "payments", "checkout", "stripe", "billing", "invoice"}),
    "auth":        frozenset({"auth", "login", "oauth", "sso", "token", "session", "jwt"}),
    "admin":       frozenset({"admin", "dashboard", "portal"}),
    "database":    frozenset({"database", "db", "sql", "postgres", "mysql", "mongo", "redis"}),
    "internal":    frozenset({"internal", "private", "backend", "worker", "config"}),
    "secure":      frozenset({"secrets", "secret", "secure"}),
    "customer":    frozenset({"customer", "customers", "user", "users"}),
    "api":         frozenset({"api", "app"}),
}


def _classify_lambda_name_sensitivity(name: str) -> str:
    """Return sensitivity category for a Lambda function or API Gateway name.

    Returns one of: production, payment, auth, admin, database, internal,
    secure, customer, api, none.

    Same structure as _classify_rds_name_sensitivity.
    SECURITY: The name is checked against patterns; the raw name is already
    stored as the record name so this adds no new data exposure.
    """
    lower = name.lower()
    for category, patterns in _LAMBDA_NAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in lower:
                return category
    return "none"


# Sensitive environment variable key name patterns (lower-case substrings).
_SENSITIVE_ENV_KEY_PATTERNS: frozenset[str] = frozenset({
    "secret", "password", "passwd", "pass", "token", "key", "api_key", "apikey",
    "access_key", "auth", "credential", "cred", "private", "cert", "certificate",
    "jwt", "oauth", "stripe", "payment", "billing", "database_url", "db_url",
    "connection_string", "dsn",
})


def _lambda_env_key_info(env_vars: dict) -> tuple[list[str], int, int]:
    """Extract safe key info from Lambda env vars dict.

    Returns (sorted_key_names, key_count, sensitive_key_count).

    SECURITY: env_vars values are NEVER accessed or stored.
    Only key names are inspected.
    """
    if not env_vars:
        return [], 0, 0
    key_names = sorted(env_vars.keys())
    sensitive_count = 0
    for k in key_names:
        k_lower = k.lower()
        if any(pat in k_lower for pat in _SENSITIVE_ENV_KEY_PATTERNS):
            sensitive_count += 1
    return key_names, len(key_names), sensitive_count


def _lambda_event_source_type(arn: str) -> str:
    """Classify Lambda event source type from its ARN prefix.

    Returns one of: dynamodb, sqs, kinesis, msk, mq, documentdb, unknown.
    """
    if not arn:
        return "unknown"
    lower = arn.lower()
    if ":dynamodb:" in lower:
        return "dynamodb"
    if ":sqs:" in lower:
        return "sqs"
    if ":kinesis:" in lower:
        return "kinesis"
    if ":kafka:" in lower or ":msk:" in lower:
        return "msk"
    if ":mq:" in lower:
        return "mq"
    if ":docdb:" in lower or ":rds:" in lower:
        return "documentdb"
    return "unknown"


def _lambda_dlq_type(arn: str) -> str | None:
    """Classify DLQ target type from its ARN (SQS or SNS)."""
    if not arn:
        return None
    lower = arn.lower()
    if ":sqs:" in lower:
        return "sqs"
    if ":sns:" in lower:
        return "sns"
    return "other"


def _lambda_function_name_from_arn(arn: str) -> str:
    """Extract function name from a Lambda ARN.

    arn:aws:lambda:region:account:function:name → "name"
    Falls back to the full ARN if parsing fails.
    """
    if not arn:
        return ""
    parts = arn.split(":")
    if len(parts) >= 7:
        return parts[6]
    return arn.split(":")[-1]


def _apigw_policy_summary(policy_json: str, account_id: str) -> dict | None:
    """Return a safe summary of an API Gateway resource policy.

    Reuses the Secrets Manager policy analysis logic — same IAM structure.
    SECURITY: Raw policy JSON is never stored or returned.
    Only aggregate boolean/count signals are returned.
    """
    if not policy_json:
        return None
    return _analyze_secret_resource_policy(policy_json, account_id)


# ── M44: Load Balancer + WAF helpers ─────────────────────────────────────────

# Name sensitivity classification reuses the Lambda name classifier patterns.
# Sensitive categories include: production, credential, api_key, auth, payment,
# database, internal, config, secure, admin, customer.

def _classify_elb_name_sensitivity(name: str) -> str:
    """Return sensitivity category string for an ELB/WAF name.

    Reuses _classify_lambda_name_sensitivity — same pattern vocabulary.
    """
    return _classify_lambda_name_sensitivity(name)


def _elb_dns_name_suffix(dns_name: str) -> str | None:
    """Return a safe suffix of the DNS name (last 24 chars) for display.

    Full DNS name is never stored to avoid leaking internal topology.
    Returns None if the name is empty.
    """
    if not dns_name:
        return None
    # Return last segment that uniquely identifies the LB without full topology
    return dns_name[-24:] if len(dns_name) > 24 else dns_name


def _hash_elb_arn(arn: str) -> str | None:
    """Return 12-char SHA-256 hex prefix of an ARN.

    Re-uses _hash_kms_key_id convention — same 12-char prefix, same purpose.
    """
    return _hash_kms_key_id(arn) if arn else None


def _summarize_elbv2_attributes(attrs: list[dict]) -> dict:
    """Extract safe ELBv2 load balancer attribute values from the raw list.

    Raw attribute list format: [{"Key": "...", "Value": "..."}, ...]
    SECURITY: Only known safe fields are extracted by key name.
    Unknown attributes are counted but values never stored.
    """
    result: dict = {}
    for attr in attrs:
        k = attr.get("Key") or ""
        v = attr.get("Value") or ""
        if k == "deletion_protection.enabled":
            result["deletion_protection_enabled"] = v.lower() == "true"
        elif k == "access_logs.s3.enabled":
            result["access_logs_enabled"] = v.lower() == "true"
        elif k == "access_logs.s3.bucket":
            # Never store full bucket name — suffix only
            result["access_logs_bucket_suffix"] = v[-20:] if v else None
        elif k == "idle_timeout.timeout_seconds":
            try:
                result["idle_timeout_seconds"] = int(v)
            except (ValueError, TypeError):
                pass
        elif k == "routing.http2.enabled":
            result["routing_http2_enabled"] = v.lower() == "true"
        elif k == "routing.http.desync_mitigation_mode":
            result["desync_mitigation_mode"] = v  # safe enum: strictest/defensive/monitor
        elif k == "routing.http.drop_invalid_header_fields.enabled":
            result["drop_invalid_header_fields_enabled"] = v.lower() == "true"
        elif k == "routing.http.preserve_host_header.enabled":
            result["preserve_host_header_enabled"] = v.lower() == "true"
        elif k == "routing.http.xff_header_processing.mode":
            result["xff_header_processing_mode"] = v  # safe enum: append/preserve/remove
    return result


def _summarize_target_group_attributes(attrs: list[dict]) -> dict:
    """Extract safe target group attribute values.

    SECURITY: Only known safe fields are extracted. Values for unknown keys
    are never stored.
    """
    result: dict = {}
    for attr in attrs:
        k = attr.get("Key") or ""
        v = attr.get("Value") or ""
        if k == "deregistration_delay.timeout_seconds":
            try:
                result["deregistration_delay_seconds"] = int(v)
            except (ValueError, TypeError):
                pass
        elif k == "stickiness.enabled":
            result["stickiness_enabled"] = v.lower() == "true"
        elif k == "slow_start.duration_seconds":
            try:
                result["slow_start_duration_seconds"] = int(v)
            except (ValueError, TypeError):
                pass
    return result


def _summarize_listener_actions(actions: list[dict]) -> dict:
    """Return safe summaries of listener default actions.

    SECURITY: Target group ARNs are hashed. Redirect/fixed-response
    values (status codes, bodies, URIs) are summarised as booleans only.
    Never stores raw target URIs, headers, bodies, or query strings.
    """
    action_types: list[str] = []
    tg_hashes: list[str] = []
    auth_present = False
    redirect_present = False
    fixed_response_present = False

    for action in actions:
        atype = (action.get("Type") or "").lower()
        action_types.append(atype)
        if atype == "forward":
            # Single TG forward
            tg_arn = action.get("TargetGroupArn") or ""
            if tg_arn:
                h = _hash_elb_arn(tg_arn)
                if h:
                    tg_hashes.append(h)
            # Multi TG forward
            tg_config = action.get("ForwardConfig") or {}
            for tg in tg_config.get("TargetGroups") or []:
                tg_arn2 = tg.get("TargetGroupArn") or ""
                if tg_arn2:
                    h2 = _hash_elb_arn(tg_arn2)
                    if h2:
                        tg_hashes.append(h2)
        elif atype in ("authenticate-cognito", "authenticate-oidc"):
            auth_present = True
        elif atype == "redirect":
            redirect_present = True
        elif atype == "fixed-response":
            fixed_response_present = True

    return {
        "action_types":                   sorted(set(action_types)) or None,
        "target_group_arn_hashes":        sorted(set(tg_hashes)) or None,
        "auth_action_present":            auth_present,
        "redirect_action_present":        redirect_present,
        "fixed_response_action_present":  fixed_response_present,
    }


def _summarize_listener_rule_conditions(conditions: list[dict]) -> dict:
    """Return safe condition type presence flags for a listener rule.

    SECURITY: Condition VALUES (hostnames, paths, HTTP header values,
    source IPs, query string values) are NEVER stored — only field type
    presence booleans and counts are returned.
    """
    field_counts: dict[str, int] = {}
    host_header = False
    path_pattern = False
    source_ip = False
    http_header = False
    query_string = False

    for cond in conditions:
        field = (cond.get("Field") or "").lower()
        field_counts[field] = field_counts.get(field, 0) + 1
        if field == "host-header":
            host_header = True
        elif field == "path-pattern":
            path_pattern = True
        elif field == "source-ip":
            source_ip = True
        elif field == "http-header":
            http_header = True
        elif field == "query-string":
            query_string = True

    return {
        "condition_field_counts":         field_counts or None,
        "host_header_condition_present":  host_header,
        "path_pattern_condition_present": path_pattern,
        "source_ip_condition_present":    source_ip,
        "http_header_condition_present":  http_header,
        "query_string_condition_present": query_string,
    }


def _summarize_wafv2_rules(rules: list[dict]) -> dict:
    """Summarise WAFv2 Web ACL rules by count/type.

    SECURITY: Rule statements (byte match strings, regex, IP sets) are
    NEVER stored. GetSampledRequests is NEVER called.
    Only aggregate count/type signals are returned.
    """
    rule_count = len(rules)
    managed_count = 0
    custom_count = 0
    rate_based_count = 0
    allow_count = 0
    block_count = 0
    count_count = 0
    captcha_count = 0
    override_count_count = 0

    for rule in rules:
        stmt = rule.get("Statement") or {}
        action = rule.get("Action") or {}
        override_action = rule.get("OverrideAction") or {}

        # Classify rule type
        if "ManagedRuleGroupStatement" in stmt:
            managed_count += 1
        elif "RateBasedStatement" in stmt:
            rate_based_count += 1
        else:
            custom_count += 1

        # Classify terminal action
        if "Allow" in action:
            allow_count += 1
        elif "Block" in action:
            block_count += 1
        elif "Count" in action:
            count_count += 1
        elif "Captcha" in action or "Challenge" in action:
            captcha_count += 1

        # Count override-to-count (suppresses managed rule blocks)
        if "Count" in override_action:
            override_count_count += 1

    return {
        "rule_count":                   rule_count,
        "managed_rule_group_count":     managed_count,
        "custom_rule_count":            custom_count,
        "rate_based_rule_count":        rate_based_count,
        "allow_action_count":           allow_count,
        "block_action_count":           block_count,
        "count_action_count":           count_count,
        "captcha_challenge_action_count": captcha_count,
        "override_count_action_count":  override_count_count,
    }


# ── M46: ECS / EKS / ECR helpers ─────────────────────────────────────────────


def _classify_container_name_sensitivity(name: str) -> str:
    """Return sensitivity category for an ECS/EKS/ECR resource name.

    Reuses the Lambda name classifier — same pattern vocabulary covering:
    production, payment, auth, admin, database, internal, secure, customer,
    api, none.

    SECURITY: The raw name is already stored as record_name; this adds no
    new data exposure beyond what's already tracked.
    """
    return _classify_lambda_name_sensitivity(name)


def _ecs_env_key_info(env_list: list[dict]) -> tuple[list[str], int, int]:
    """Extract safe key info from an ECS container environment list.

    ECS env vars are represented as [{"name": KEY, "value": VALUE}, ...].

    Returns (sorted_key_names, key_count, sensitive_key_count).

    SECURITY: ``value`` fields are NEVER accessed or stored.  Only ``name``
    (the key name) is inspected.
    """
    if not env_list:
        return [], 0, 0
    key_names = sorted(
        item["name"]
        for item in env_list
        if isinstance(item, dict) and "name" in item
    )
    sensitive_count = sum(
        1
        for k in key_names
        if any(pat in k.lower() for pat in _SENSITIVE_ENV_KEY_PATTERNS)
    )
    return key_names, len(key_names), sensitive_count


def _ecs_secret_ref_count(secrets_list: list[dict]) -> int:
    """Return the number of ECS secret references (Secrets Manager / SSM).

    ECS secrets are represented as [{"name": ENV_KEY, "valueFrom": ARN}, ...].

    SECURITY: ``valueFrom`` ARNs and ``name`` env key names are NEVER stored
    as-is.  Only the count is returned.
    """
    return len(secrets_list) if secrets_list else 0


def _ecr_policy_is_public(policy_json: str, account_id: str) -> bool:
    """Return True if the ECR repository policy grants access beyond the account.

    Checks for:
    - Principal ``"*"`` (anonymous / any AWS principal)
    - Cross-account principal ARNs containing a different account ID

    SECURITY: Raw policy JSON is never stored.  Only the boolean result is
    returned.
    """
    if not policy_json:
        return False
    try:
        import json
        policy = json.loads(policy_json)
        for stmt in policy.get("Statement") or []:
            effect = (stmt.get("Effect") or "").upper()
            if effect != "ALLOW":
                continue
            principal = stmt.get("Principal")
            if principal == "*":
                return True
            if isinstance(principal, dict):
                for _key, val in principal.items():
                    if isinstance(val, str):
                        if val == "*":
                            return True
                        if account_id and account_id not in val:
                            return True
                    elif isinstance(val, list):
                        for v in val:
                            if v == "*":
                                return True
                            if account_id and account_id not in str(v):
                                return True
    except Exception:
        pass
    return False


def _eks_public_access_cidrs_open(cidrs: list[str]) -> bool:
    """Return True if the EKS public access CIDR list includes 0.0.0.0/0 or ::/0."""
    if not cidrs:
        return True  # No restriction = fully open by default
    return any(c in ("0.0.0.0/0", "::/0") for c in cidrs)


# ── M47: EventBridge / SQS / SNS helpers ─────────────────────────────────────

# Keyword patterns shared by all messaging resource name classifiers.
_MESSAGING_SENSITIVE_PATTERNS: frozenset[str] = frozenset({
    "prod", "production", "live",
    "payment", "payments", "billing", "invoice", "stripe",
    "auth", "authentication", "login", "credential",
    "admin", "critical", "pii", "customer", "user", "users",
    "financial", "order", "orders",
})


def _classify_messaging_name_sensitivity(name: str) -> str:
    """Return sensitivity category for an EventBridge/SQS/SNS resource name.

    Returns one of: production, payment, auth, admin, none.

    SECURITY: The raw name is already stored in the record; this only adds
    a sensitivity category derived from known pattern keywords.
    """
    lower = name.lower()
    if any(p in lower for p in ("prod", "production", "live")):
        return "production"
    if any(p in lower for p in ("payment", "payments", "billing", "invoice", "stripe", "financial", "order", "orders")):
        return "payment"
    if any(p in lower for p in ("auth", "authentication", "login", "credential")):
        return "auth"
    if any(p in lower for p in ("admin", "critical", "pii", "customer", "user", "users")):
        return "admin"
    return "none"


def _is_sensitive_messaging_resource(name: str) -> bool:
    """Return True if the resource name suggests production/sensitive context."""
    lower = name.lower()
    return any(p in lower for p in _MESSAGING_SENSITIVE_PATTERNS)


def _messaging_policy_is_public(policy_json: str, account_id: str) -> bool:
    """Return True if an AWS resource policy grants access beyond the account.

    Checks ALLOW statements for principal ``"*"`` or cross-account ARNs.
    Returns False on any parse failure (conservative, fail-closed).

    SECURITY: Raw policy JSON is NEVER stored.  Only the boolean result is
    returned and stored.
    """
    if not policy_json:
        return False
    try:
        import json as _json
        policy = _json.loads(policy_json)
        for stmt in policy.get("Statement") or []:
            effect = (stmt.get("Effect") or "").upper()
            if effect != "ALLOW":
                continue
            principal = stmt.get("Principal")
            if principal == "*":
                return True
            if isinstance(principal, dict):
                for _key, val in principal.items():
                    if isinstance(val, str):
                        if val == "*":
                            return True
                        if account_id and account_id not in val:
                            return True
                    elif isinstance(val, list):
                        for v in val:
                            if v == "*":
                                return True
                            if account_id and account_id not in str(v):
                                return True
    except Exception:
        pass
    return False


def _hash_arn(arn: str) -> str | None:
    """Return a 12-character hex SHA-256 of an ARN, or None if empty.

    SECURITY: Raw ARNs are never stored.  The hash detects ARN changes
    without exposing account IDs, resource names, or paths.
    """
    if not arn:
        return None
    return hashlib.sha256(arn.encode("utf-8")).hexdigest()[:12]


def _hash_endpoint(endpoint: str) -> str | None:
    """Return a 12-character hex SHA-256 of an SNS subscription endpoint.

    SECURITY: Raw endpoint values (email, phone, URL, queue ARN) are NEVER
    stored.  Only the hash is retained to detect endpoint changes.
    """
    if not endpoint:
        return None
    return hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:12]


def _classify_endpoint_type(endpoint: str, protocol: str) -> str:
    """Return a safe endpoint type string from a protocol and endpoint value.

    Returns one of: email, sms, http, https, sqs, lambda, firehose, application,
    arn_based, unknown.

    SECURITY: The raw endpoint value is never returned or stored.
    """
    p = (protocol or "").lower()
    if p in ("email", "email-json"):
        return "email"
    if p == "sms":
        return "sms"
    if p == "http":
        return "http"
    if p == "https":
        return "https"
    if p == "sqs":
        return "sqs"
    if p == "lambda":
        return "lambda"
    if p == "firehose":
        return "firehose"
    if p == "application":
        return "application"
    # ARN-based endpoints
    e = (endpoint or "").lower()
    if ":arn:" in e or e.startswith("arn:"):
        return "arn_based"
    return "unknown"


def _summarize_target_type(target_arn: str) -> str:
    """Classify an EventBridge target type from its ARN.

    Returns a safe type string such as: lambda, sqs, sns, kinesis, firehose,
    step_functions, ecs, api_gateway, events, logs, ssm, sagemaker, unknown.

    SECURITY: The raw ARN is never stored.
    """
    arn = (target_arn or "").lower()
    if ":lambda:" in arn or ":function:" in arn:
        return "lambda"
    if ":sqs:" in arn:
        return "sqs"
    if ":sns:" in arn:
        return "sns"
    if ":kinesis:" in arn:
        return "kinesis"
    if ":firehose:" in arn or ":deliverystream/" in arn:
        return "firehose"
    if ":states:" in arn or ":stateMachine:" in arn:
        return "step_functions"
    if ":ecs:" in arn:
        return "ecs"
    if ":execute-api:" in arn or ":apigateway:" in arn:
        return "api_gateway"
    if ":events:" in arn:
        return "events"
    if ":logs:" in arn:
        return "logs"
    if ":ssm:" in arn:
        return "ssm"
    if ":sagemaker:" in arn:
        return "sagemaker"
    return "unknown"


def _hash_event_pattern(pattern_json: str) -> str | None:
    """Return a 12-character SHA-256 hash of an EventBridge event pattern.

    SECURITY: Raw event pattern JSON is never stored.  The hash detects
    pattern changes without exposing event routing logic.
    """
    if not pattern_json:
        return None
    return hashlib.sha256(pattern_json.encode("utf-8")).hexdigest()[:12]


def _hash_filter_policy(policy_json: str) -> str | None:
    """Return a 12-character SHA-256 hash of an SNS filter policy.

    SECURITY: Raw filter policy JSON is never stored.  The hash detects
    policy changes without exposing filtering criteria.
    """
    if not policy_json:
        return None
    return hashlib.sha256(policy_json.encode("utf-8")).hexdigest()[:12]


def _summarize_redrive_allow_policy(raw_json: str) -> str | None:
    """Return a safe summary of an SQS RedriveAllowPolicy.

    Returns one of: "allowAll", "denyAll", "byQueue", or None on parse failure.

    SECURITY: Raw policy JSON is never stored.
    """
    if not raw_json:
        return None
    try:
        import json as _json
        pol = _json.loads(raw_json)
        permission = (pol.get("redrivePermission") or "").lower()
        if permission == "allowall":
            return "allowAll"
        if permission == "denyall":
            return "denyAll"
        if permission == "bysourcequeue":
            return "byQueue"
        return permission or None
    except Exception:
        return None


# ── M48: KMS / Backup / Organizations helpers ────────────────────────────────

_GOVERNANCE_SENSITIVE_PATTERNS: frozenset[str] = frozenset({
    "prod", "production", "live",
    "payment", "payments", "billing", "invoice", "stripe",
    "auth", "authentication", "login", "credential",
    "admin", "critical", "pii", "customer", "user", "users",
    "financial", "order", "orders",
    "backup", "backups", "restore", "recovery",
    "master", "root", "cmk", "compliance", "audit",
})


def _classify_governance_name_sensitivity(name: str) -> str:
    """Return sensitivity category for a KMS/Backup/Organizations resource name.

    Returns one of: production, payment, auth, admin, backup, none.
    """
    lower = name.lower()
    if any(p in lower for p in ("prod", "production", "live")):
        return "production"
    if any(p in lower for p in ("payment", "payments", "billing", "invoice", "stripe", "financial", "order", "orders")):
        return "payment"
    if any(p in lower for p in ("auth", "authentication", "login", "credential")):
        return "auth"
    if any(p in lower for p in ("backup", "backups", "restore", "recovery")):
        return "backup"
    if any(p in lower for p in ("admin", "critical", "pii", "customer", "user", "users", "master", "root", "cmk", "compliance", "audit")):
        return "admin"
    return "none"


def _is_sensitive_governance_resource(name: str) -> bool:
    """Return True if the resource name suggests a sensitive/production context."""
    lower = name.lower()
    return any(p in lower for p in _GOVERNANCE_SENSITIVE_PATTERNS)


def _hash_id(id_str: str) -> str | None:
    """Return a 12-character hex SHA-256 of an ID (key ID, org ID, policy ID, etc.).

    SECURITY: Raw IDs may be used as inputs to other operations; hashing
    prevents accidental enumeration while still detecting changes.
    """
    if not id_str:
        return None
    return hashlib.sha256(id_str.encode("utf-8")).hexdigest()[:12]


def _hash_email(email: str) -> str | None:
    """Return a 12-character hex SHA-256 of an email address.

    SECURITY: Raw account email addresses are never stored.
    """
    if not email:
        return None
    return hashlib.sha256(email.lower().encode("utf-8")).hexdigest()[:12]


def _kms_policy_is_public(policy_json: str, account_id: str) -> bool:
    """Return True if a KMS key policy grants access outside the account.

    Checks ALLOW statements for Principal="*" or cross-account ARNs.
    Returns False on parse failure (fail-closed).

    SECURITY: Raw policy JSON is NEVER stored.  Only the boolean result is returned.
    """
    # Reuse the messaging policy check logic
    return _messaging_policy_is_public(policy_json, account_id)


def _kms_policy_has_wildcard_admin(policy_json: str, account_id: str) -> bool:
    """Return True if a KMS key policy has a wildcard-action Allow for any principal.

    Detects overly broad KMS policies where Action is '*' or 'kms:*' in an
    Allow statement for a principal outside the account.

    SECURITY: Raw policy JSON is NEVER stored.  Only the boolean result is returned.
    """
    if not policy_json:
        return False
    try:
        import json as _json
        policy = _json.loads(policy_json)
        for stmt in policy.get("Statement") or []:
            effect = (stmt.get("Effect") or "").upper()
            if effect != "ALLOW":
                continue
            principal = stmt.get("Principal")
            # Determine if principal is external
            is_external = False
            if principal == "*":
                is_external = True
            elif isinstance(principal, dict):
                for _pkey, pval in principal.items():
                    vals = [pval] if isinstance(pval, str) else (pval if isinstance(pval, list) else [])
                    for v in vals:
                        sv = str(v)
                        if sv == "*" or (account_id and account_id not in sv):
                            is_external = True
                            break
                    if is_external:
                        break
            if not is_external:
                continue
            # Check for wildcard actions
            actions = stmt.get("Action") or []
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                a = str(action).lower()
                if a in ("*", "kms:*"):
                    return True
    except Exception:
        pass
    return False


def _summarize_scp_content(policy_json: str) -> dict:
    """Parse and summarize SCP content without storing raw JSON.

    Returns a dict with safe summary fields:
    - allow_statement_count
    - deny_statement_count
    - denied_action_count
    - denied_service_prefixes (sorted list of unique service prefixes)
    - wildcard_action_present (bool)
    - wildcard_resource_present (bool)
    - denies_full_admin_escape (bool)

    SECURITY: Raw SCP JSON is NEVER stored.  Only the summary dict is returned.
    """
    empty: dict = {
        "allow_statement_count": 0,
        "deny_statement_count": 0,
        "denied_action_count": 0,
        "denied_service_prefixes": [],
        "wildcard_action_present": False,
        "wildcard_resource_present": False,
        "denies_full_admin_escape": False,
    }
    if not policy_json:
        return empty
    try:
        import json as _json
        policy = _json.loads(policy_json)
        allow_count = 0
        deny_count = 0
        denied_actions: set[str] = set()
        denied_prefixes: set[str] = set()
        wildcard_action = False
        wildcard_resource = False
        denies_escape = False

        # Admin/escape action patterns to check
        _ADMIN_ESCAPE_PREFIXES = frozenset({
            "*", "iam", "sts", "organizations", "kms", "s3", "ec2", "cloudtrail",
        })
        _ADMIN_ESCAPE_ACTIONS = frozenset({
            "*", "iam:*", "sts:*", "organizations:*", "iam:createuser",
            "iam:createrolepolicy", "iam:attachrolepolicy", "iam:createrole",
            "iam:putrolepolicy", "iam:attachusergroup", "iam:addusertogroup",
        })

        for stmt in policy.get("Statement") or []:
            effect = (stmt.get("Effect") or "").upper()
            actions = stmt.get("Action") or []
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource") or []
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard actions across all effects
            for action in actions:
                a = str(action).lower()
                if "*" in a:
                    wildcard_action = True

            if effect == "ALLOW":
                allow_count += 1
            elif effect == "DENY":
                deny_count += 1
                for action in actions:
                    a = str(action).lower()
                    denied_actions.add(a)
                    if ":" in a:
                        prefix = a.split(":")[0]
                        denied_prefixes.add(prefix)
                    # Check if this deny covers admin-escape actions
                    for esc in _ADMIN_ESCAPE_ACTIONS:
                        if a == esc or a == "*":
                            denies_escape = True
                            break
                    if a.split(":")[0] in _ADMIN_ESCAPE_PREFIXES and a.endswith(":*"):
                        denies_escape = True
                for resource in resources:
                    if str(resource) == "*":
                        wildcard_resource = True

        return {
            "allow_statement_count": allow_count,
            "deny_statement_count": deny_count,
            "denied_action_count": len(denied_actions),
            "denied_service_prefixes": sorted(denied_prefixes),
            "wildcard_action_present": wildcard_action,
            "wildcard_resource_present": wildcard_resource,
            "denies_full_admin_escape": denies_escape,
        }
    except Exception:
        return empty


def _summarize_backup_rules(rules: list[dict]) -> dict:
    """Summarize AWS Backup plan rules without storing raw content.

    Returns a dict with safe summary fields.
    SECURITY: Raw rule content never stored.
    """
    if not rules:
        return {
            "rule_count": 0,
            "rule_names": [],
            "target_vault_names": [],
            "schedule_expression_present_count": 0,
            "continuous_backup_enabled_count": 0,
            "lifecycle_delete_after_days_min": None,
            "lifecycle_delete_after_days_max": None,
            "lifecycle_move_to_cold_after_days_min": None,
            "lifecycle_move_to_cold_after_days_max": None,
            "copy_action_count": 0,
        }
    rule_names: list[str] = []
    vault_names: list[str] = []
    sched_count = 0
    continuous_count = 0
    delete_days: list[int] = []
    cold_days: list[int] = []
    copy_count = 0

    for rule in rules:
        name = rule.get("RuleName") or ""
        if name:
            rule_names.append(name)
        vault = rule.get("TargetBackupVaultName") or ""
        if vault and vault not in vault_names:
            vault_names.append(vault)
        if rule.get("ScheduleExpression"):
            sched_count += 1
        if rule.get("EnableContinuousBackup"):
            continuous_count += 1
        lc = rule.get("Lifecycle") or {}
        dd = lc.get("DeleteAfterDays")
        ca = lc.get("MoveToColdStorageAfterDays")
        if dd is not None:
            try:
                delete_days.append(int(dd))
            except (TypeError, ValueError):
                pass
        if ca is not None:
            try:
                cold_days.append(int(ca))
            except (TypeError, ValueError):
                pass
        copy_count += len(rule.get("CopyActions") or [])

    return {
        "rule_count": len(rules),
        "rule_names": rule_names,
        "target_vault_names": sorted(set(vault_names)),
        "schedule_expression_present_count": sched_count,
        "continuous_backup_enabled_count": continuous_count,
        "lifecycle_delete_after_days_min": min(delete_days) if delete_days else None,
        "lifecycle_delete_after_days_max": max(delete_days) if delete_days else None,
        "lifecycle_move_to_cold_after_days_min": min(cold_days) if cold_days else None,
        "lifecycle_move_to_cold_after_days_max": max(cold_days) if cold_days else None,
        "copy_action_count": copy_count,
    }


def _summarize_backup_selection_resources(resources: list[str], conditions: dict) -> dict:
    """Summarize backup selection resources by type/count without storing raw ARNs.

    SECURITY: Raw resource ARNs are never stored.
    """
    type_counts: dict[str, int] = {}
    for r in resources:
        # Extract resource type from ARN pattern like arn:aws:ec2:*:*:instance/*
        parts = r.split(":")
        if len(parts) >= 3:
            svc = parts[2].lower() if len(parts) > 2 else "unknown"
            type_counts[svc] = type_counts.get(svc, 0) + 1
        else:
            type_counts["unknown"] = type_counts.get("unknown", 0) + 1
    tag_conditions = 0
    if isinstance(conditions, dict):
        for _k, v in conditions.items():
            if isinstance(v, list):
                tag_conditions += len(v)
    return {
        "resource_count": len(resources),
        "resource_type_counts": type_counts if type_counts else None,
        "condition_count": tag_conditions,
    }


# ── M39: IAM policy and trust analysis helpers ────────────────────────────────

# Services whose actions in a policy are considered sensitive for privilege
# escalation or data access risk assessment.
_IAM_SENSITIVE_SERVICES: frozenset[str] = frozenset({
    "iam", "sts", "s3", "ec2", "lambda", "cloudformation",
    "secretsmanager", "ssm", "kms", "organizations",
})

# IAM write action prefixes indicating privilege escalation risk.
# Only checked against "iam:" actions.
_IAM_WRITE_PREFIXES: frozenset[str] = frozenset({
    "create", "update", "delete", "put", "attach", "detach",
    "set", "add", "remove", "tag", "untag", "upload",
})

# Privilege escalation action patterns (lower-case action suffixes for iam:)
_PRIV_ESC_IAM_ACTIONS: frozenset[str] = frozenset({
    "createpolicy", "createpolicyversion", "setdefaultpolicyversion",
    "createrole", "updateassumerolepolicy",
    "attachrolepolicy", "attachuserpolicy", "attachgrouppolicy",
    "putrolepolicy", "putuserpolicy", "putgrouppolicy",
    "addusertogroup", "createloginprofile", "updateloginprofile",
    "createvirtualmfadevice", "enablemfadevice",
    "passrole",
})


def _analyze_policy_document(policy_json: str, account_id: str) -> dict:
    """Analyze an IAM policy document and return a safe summary.

    SECURITY: policy_json is parsed in memory only; it is NEVER stored or
    returned. Only the derived summary fields are returned.

    Args:
        policy_json: JSON string of the IAM policy document.
        account_id:  AWS account ID used to detect cross-account trust.

    Returns:
        A dict with safe summary fields — see inline comments for semantics.
    """
    import json
    import hashlib

    # Canonical hash of the raw document for change tracking (not the doc itself)
    doc_hash = hashlib.sha256(policy_json.encode("utf-8")).hexdigest()[:16]

    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, ValueError):
        return {
            "statement_count": 0,
            "action_count": 0,
            "resource_count": 0,
            "has_wildcard_action": False,
            "has_wildcard_resource": False,
            "has_not_action": False,
            "has_not_resource": False,
            "admin_access": False,
            "iam_write_actions": False,
            "sts_assume_role_actions": False,
            "pass_role_present": False,
            "privilege_escalation_actions": False,
            "sensitive_services_touched": [],
            "finding_codes": ["parse_error"],
            "policy_document_hash": doc_hash,
        }

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    action_set: set[str] = set()
    resource_set: set[str] = set()
    has_wildcard_action = False
    has_wildcard_resource = False
    has_not_action = False
    has_not_resource = False

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        # Only Allow statements grant permissions.  Deny statements restrict
        # access and must NOT contribute to grant-based findings such as
        # admin_access, iam_write_actions, sts_assume_role, pass_role, or
        # privilege_escalation_actions.  Counting Deny actions as grants would
        # produce false-positive findings (e.g. a policy that Denies iam:*
        # would incorrectly be flagged for iam_write_access).
        if stmt.get("Effect", "Allow").upper() != "ALLOW":
            continue
        # NotAction / NotResource in Allow statements are unusual and deserve
        # flagging — they grant everything *except* the listed actions/resources.
        if "NotAction" in stmt:
            has_not_action = True
        if "NotResource" in stmt:
            has_not_resource = True
        # Actions
        actions = stmt.get("Action") or stmt.get("NotAction") or []
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if isinstance(a, str):
                action_set.add(a.lower())
                if a == "*":
                    has_wildcard_action = True
        # Resources
        resources = stmt.get("Resource") or stmt.get("NotResource") or []
        if isinstance(resources, str):
            resources = [resources]
        for r in resources:
            if isinstance(r, str):
                resource_set.add(r)
                if r == "*":
                    has_wildcard_resource = True

    # Derive risk signals from collected actions
    admin_access = (
        has_wildcard_action and has_wildcard_resource
    ) or ("*" in action_set and "*" in resource_set)

    iam_write_actions = any(
        a.startswith("iam:") and any(a[4:].startswith(p) for p in _IAM_WRITE_PREFIXES)
        for a in action_set
    ) or ("iam:*" in action_set)

    sts_assume_role = any(
        a in ("sts:assumerole", "sts:assumerolewithaml", "sts:assumerolewithwebidentity", "sts:*")
        for a in action_set
    )

    pass_role = any(a in ("iam:passrole", "iam:*") for a in action_set)

    privilege_escalation = any(
        a in {f"iam:{x}" for x in _PRIV_ESC_IAM_ACTIONS}
        for a in action_set
    ) or iam_write_actions

    sensitive_services: list[str] = sorted({
        a.split(":")[0]
        for a in action_set
        if ":" in a and a.split(":")[0] in _IAM_SENSITIVE_SERVICES
    })

    # Build finding codes (stable, machine-readable)
    finding_codes: list[str] = []
    if admin_access:
        finding_codes.append("admin_access")
    if has_wildcard_action and not admin_access:
        finding_codes.append("wildcard_action")
    if has_wildcard_resource and not admin_access:
        finding_codes.append("wildcard_resource")
    if has_not_action:
        finding_codes.append("not_action")
    if has_not_resource:
        finding_codes.append("not_resource")
    if iam_write_actions:
        finding_codes.append("iam_write_access")
    if sts_assume_role:
        finding_codes.append("sts_assume_role")
    if pass_role:
        finding_codes.append("pass_role")
    if privilege_escalation and not admin_access:
        finding_codes.append("privilege_escalation_risk")

    return {
        "statement_count":              len(statements),
        "action_count":                 len(action_set),
        "resource_count":               len(resource_set),
        "has_wildcard_action":          has_wildcard_action,
        "has_wildcard_resource":        has_wildcard_resource,
        "has_not_action":               has_not_action,
        "has_not_resource":             has_not_resource,
        "admin_access":                 admin_access,
        "iam_write_actions":            iam_write_actions,
        "sts_assume_role_actions":      sts_assume_role,
        "pass_role_present":            pass_role,
        "privilege_escalation_actions": privilege_escalation,
        "sensitive_services_touched":   sensitive_services,
        "finding_codes":                finding_codes,
        "policy_document_hash":         doc_hash,
    }


def _analyze_trust_policy(trust_policy_dict: dict, account_id: str) -> dict:
    """Analyze a role's trust policy (AssumeRolePolicyDocument) safely.

    SECURITY: The trust policy dict is analyzed in memory only; it is NEVER
    stored or returned. Only the derived trust_summary fields are returned.

    Args:
        trust_policy_dict: Parsed trust policy dict (from GetRole response).
        account_id:        AWS account ID to detect external-account trust.

    Returns:
        A dict with safe trust summary fields.
    """
    statements = trust_policy_dict.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    principal_types: set[str] = set()
    aws_account_ids: set[str] = set()
    service_principals: set[str] = set()
    federated_count = 0
    has_wildcard_principal = False
    has_external_account = False
    has_root_account = False
    has_oidc_trust = False
    has_saml_trust = False
    has_external_id_condition = False
    has_mfa_condition = False
    condition_keys: set[str] = set()

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            has_wildcard_principal = True
            principal_types.add("*")
        elif isinstance(principal, dict):
            # AWS principals
            aws_p = principal.get("AWS", [])
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            for p in (aws_p if isinstance(aws_p, list) else []):
                if isinstance(p, str):
                    principal_types.add("AWS")
                    if p == "*":
                        has_wildcard_principal = True
                    elif ":root" in p:
                        has_root_account = True
                        # Extract account ID from root ARN
                        parts = p.split(":")
                        if len(parts) >= 5:
                            acct = parts[4]
                            if acct and acct != account_id:
                                has_external_account = True
                            aws_account_ids.add(acct)
                    else:
                        # Extract account ID from ARN
                        parts = p.split(":")
                        if len(parts) >= 5:
                            acct = parts[4]
                            if acct:
                                aws_account_ids.add(acct)
                                if acct != account_id:
                                    has_external_account = True
            # Service principals
            svc_p = principal.get("Service", [])
            if isinstance(svc_p, str):
                svc_p = [svc_p]
            for p in (svc_p if isinstance(svc_p, list) else []):
                if isinstance(p, str):
                    principal_types.add("Service")
                    service_principals.add(p)
            # Federated principals (OIDC/SAML)
            fed_p = principal.get("Federated", [])
            if isinstance(fed_p, str):
                fed_p = [fed_p]
            for p in (fed_p if isinstance(fed_p, list) else []):
                if isinstance(p, str):
                    principal_types.add("Federated")
                    federated_count += 1
                    if "oidc-provider" in p or "cognito-identity" in p:
                        has_oidc_trust = True
                    elif "saml-provider" in p:
                        has_saml_trust = True
        # Conditions
        conditions = stmt.get("Condition") or {}
        if isinstance(conditions, dict):
            for op, cond_map in conditions.items():
                if isinstance(cond_map, dict):
                    for key in cond_map:
                        condition_keys.add(key)
                        k_lower = key.lower()
                        if "externalid" in k_lower or "external-id" in k_lower:
                            has_external_id_condition = True
                        if "mfa" in k_lower or "multifactor" in k_lower:
                            has_mfa_condition = True

    return {
        "principal_types":          sorted(principal_types),
        "aws_principal_account_ids": sorted(aws_account_ids),
        "service_principals":       sorted(service_principals),
        "federated_principal_count": federated_count,
        "has_wildcard_principal":   has_wildcard_principal,
        "has_external_account_trust": has_external_account,
        "has_root_account_trust":   has_root_account,
        "has_oidc_trust":           has_oidc_trust,
        "has_saml_trust":           has_saml_trust,
        "has_external_id_condition": has_external_id_condition,
        "has_mfa_condition":        has_mfa_condition,
        "condition_keys":           sorted(condition_keys),
    }


def _stable_iam_attachment_id(
    principal_type: str, principal_id: str, policy_arn: str
) -> str:
    """Return a stable 16-hex record_id for a principal↔policy attachment."""
    import hashlib
    parts = f"{principal_type}|{principal_id}|{policy_arn}"
    return hashlib.sha256(parts.encode()).hexdigest()[:16]


def _stable_iam_inline_id(
    principal_type: str, principal_id: str, policy_name: str
) -> str:
    """Return a stable 16-hex record_id for an inline policy on a principal."""
    import hashlib
    parts = f"{principal_type}|{principal_id}|{policy_name}"
    return hashlib.sha256(parts.encode()).hexdigest()[:16]


def _stable_iam_idp_id(arn: str) -> str:
    """Return a stable 16-hex record_id for an OIDC/SAML identity provider."""
    import hashlib
    return hashlib.sha256(arn.encode()).hexdigest()[:16]


class AWSConnector(BaseConnector):
    """Read-only AWS connector for account/inventory metadata — M36.

    Supports AWS access key ID + secret access key authentication.
    Designed to be extended in future milestones (S3, Security Groups, IAM, etc.)
    by adding new methods that reuse _make_client() and _call_aws().
    """

    def _safe_key_id(self, credentials: dict) -> str:
        """Return a safe partial key ID for logging. NEVER logs the full key."""
        key_id = credentials.get("aws_access_key_id", "")
        if len(key_id) >= 4:
            return key_id[:4] + "***"
        return "***"

    def _default_region(self, credentials: dict) -> str:
        """Return the configured default region or us-east-1."""
        return credentials.get("aws_default_region") or "us-east-1"

    def _selected_regions(self, credentials: dict) -> list[str]:
        """Return the list of regions to monitor. Falls back to [default_region]."""
        regions = credentials.get("aws_selected_regions")
        if regions and isinstance(regions, list) and len(regions) > 0:
            return regions
        return [self._default_region(credentials)]

    def _make_client(self, service: str, credentials: dict, region: str | None = None) -> Any:
        """Create a boto3 client with explicit credentials.

        Extracted into its own method so tests can patch it cleanly without
        patching the entire boto3 module.

        SECURITY: aws_secret_access_key is never logged — it is passed directly
        to boto3 and is not stored anywhere in this class.
        """
        import boto3  # Local import so module is importable without boto3 installed
        region = region or self._default_region(credentials)
        # SECURITY: do not log credentials
        logger.debug(
            "aws._make_client  service=%s  region=%s  key_id=%s",
            service,
            region,
            self._safe_key_id(credentials),
        )
        return boto3.client(
            service,
            aws_access_key_id=credentials["aws_access_key_id"],
            aws_secret_access_key=credentials["aws_secret_access_key"],
            region_name=region,
        )

    def _call_aws(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Call an AWS API function and translate exceptions to connector errors.

        This is the single translation point for all AWS API calls. Any new
        method added in future milestones should wrap its boto3 calls here.

        Raises:
            AuthenticationError: Invalid or revoked credentials (AWS 401 equivalent).
            ConnectorError(status_code=403): Valid credentials but no permission.
            RateLimitError: AWS throttling / request limit exceeded.
            ConnectorError: Other AWS API errors (5xx, unexpected codes).
            NetworkError: Transport-level failure (no HTTP response received).
        """
        try:
            import botocore.exceptions  # noqa: F401 — ensure importable before calling fn
            return fn(*args, **kwargs)
        except Exception as exc:
            # Import botocore locally to avoid module-level dependency
            try:
                import botocore.exceptions as _bce
            except ImportError:
                raise ConnectorError(f"boto3/botocore not installed: {exc}") from exc

            if isinstance(exc, _bce.ClientError):
                error_code = exc.response["Error"]["Code"]
                error_message = exc.response["Error"]["Message"]

                if error_code in _AUTH_ERROR_CODES:
                    raise AuthenticationError(
                        f"AWS credentials are invalid or expired ({error_code}). "
                        "Verify the access key ID and secret access key are correct "
                        "and the IAM user has not been disabled or deleted.",
                        status_code=401,
                    ) from exc

                if error_code in _ACCESS_DENIED_CODES:
                    raise ConnectorError(
                        f"AWS access denied ({error_code}): {error_message}. "
                        "The IAM user or role lacks permission for this operation.",
                        status_code=403,
                    ) from exc

                if error_code in _THROTTLE_CODES:
                    raise RateLimitError(
                        f"AWS request throttled ({error_code}). "
                        "ConfigTrace will retry on the next scheduled sync."
                    ) from exc

                if error_code in {"ServiceUnavailable", "InternalError",
                                  "InternalErrorException", "ServiceUnavailableException"}:
                    raise ConnectorError(
                        f"AWS service temporarily unavailable ({error_code}).",
                        status_code=503,
                    ) from exc

                # Catch-all for other ClientErrors
                raise ConnectorError(
                    f"AWS API error ({error_code}): {error_message}",
                    status_code=None,
                ) from exc

            if isinstance(exc, _bce.NoCredentialsError):
                raise AuthenticationError(
                    "AWS credentials are missing or could not be loaded.",
                    status_code=401,
                ) from exc

            if isinstance(exc, _bce.PartialCredentialsError):
                raise AuthenticationError(
                    "AWS credentials are incomplete (missing access key ID or secret).",
                    status_code=401,
                ) from exc

            if isinstance(exc, (
                _bce.EndpointConnectionError,
                _bce.ConnectTimeoutError,
                _bce.ReadTimeoutError,
                _bce.ConnectionError,
            )):
                raise NetworkError(
                    f"Network error reaching AWS: {exc}"
                ) from exc

            # Unknown exception type — re-raise as-is
            raise

    # ── Public interface ───────────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate using STS GetCallerIdentity.

        STS GetCallerIdentity is the safest AWS validation call — it requires
        no IAM permissions beyond valid credentials and works for any principal
        type (IAM user, role, assumed role).

        Returns True on success. Raises AuthenticationError on invalid creds,
        ConnectorError on other API errors, NetworkError on transport failures.

        SECURITY: aws_secret_access_key is NEVER logged.
        """
        logger.info(
            "AWSConnector.validate_credentials  key_id=%s",
            self._safe_key_id(credentials),
        )
        client = self._make_client("sts", credentials)
        self._call_aws(client.get_caller_identity)
        logger.info(
            "AWSConnector.validate_credentials: success  key_id=%s",
            self._safe_key_id(credentials),
        )
        return True

    # ── Provider security alerts (M67.1) ──────────────────────────────────────
    #
    # GuardDuty / Access Analyzer are provider-ADJUDICATED security findings.
    # These methods fetch them for ingestion as Incident-Signal evidence. They do
    # NOT confirm breach/attacker/compromise — they surface provider-reported
    # findings for review. Errors are translated by ``_call_aws`` (403 →
    # ConnectorError(status_code=403) → caller treats as permission-limited).

    def list_guardduty_findings(
        self,
        credentials: dict,
        *,
        region: str | None = None,
        max_findings: int = 50,
    ) -> list[dict]:
        """Return recent GuardDuty findings (raw dicts) for the default region.

        Returns ``[]`` when no detector exists (GuardDuty not enabled). Region
        handling is intentionally simple: the integration default region only —
        this milestone does not scan every region.

        Raises (translated by ``_call_aws``): AuthenticationError (401),
        ConnectorError(403) on AccessDenied, RateLimitError, ConnectorError(503),
        NetworkError.
        """
        region = region or self._default_region(credentials)
        client = self._make_client("guardduty", credentials, region)

        detectors = self._call_aws(client.list_detectors).get("DetectorIds", [])
        if not detectors:
            return []  # GuardDuty not enabled in this region — not an error.
        detector_id = detectors[0]

        listed = self._call_aws(
            client.list_findings,
            DetectorId=detector_id,
            MaxResults=min(max_findings, 50),
        )
        finding_ids = listed.get("FindingIds", [])
        if not finding_ids:
            return []

        got = self._call_aws(
            client.get_findings, DetectorId=detector_id, FindingIds=finding_ids[:50]
        )
        findings = got.get("Findings", [])
        # Stamp the region/detector so the normalizer has them even if absent.
        for f in findings:
            if isinstance(f, dict):
                f.setdefault("Region", region)
                f.setdefault("_DetectorId", detector_id)
        return findings

    def list_access_analyzer_findings(
        self,
        credentials: dict,
        *,
        region: str | None = None,
        max_findings: int = 50,
    ) -> list[dict]:
        """Return IAM Access Analyzer findings (raw dicts) for the default region.

        Returns ``[]`` when no analyzer exists. Same error-translation as
        ``list_guardduty_findings``.
        """
        region = region or self._default_region(credentials)
        client = self._make_client("accessanalyzer", credentials, region)

        analyzers = self._call_aws(client.list_analyzers).get("analyzers", [])
        active = [a for a in analyzers if a.get("status") in (None, "ACTIVE")] or analyzers
        if not active:
            return []
        analyzer_arn = active[0].get("arn")
        if not analyzer_arn:
            return []

        listed = self._call_aws(
            client.list_findings,
            analyzerArn=analyzer_arn,
            maxResults=min(max_findings, 50),
        )
        findings = listed.get("findings", [])
        for f in findings:
            if isinstance(f, dict):
                f.setdefault("region", region)
                f.setdefault("_AnalyzerArn", analyzer_arn)
        return findings

    # ── Security Hub findings (M67.7) ──────────────────────────────────────────
    #
    # Security Hub aggregates provider-reported (ASFF) security findings across
    # AWS security services. These are provider-ADJUDICATED findings surfaced as
    # Incident-Signal evidence — they do NOT confirm breach/attacker/compromise.
    # Errors are translated by ``_call_aws`` (403 → ConnectorError(403) → caller
    # treats as permission-limited; "not enabled" surfaces as a non-fatal error).

    def list_security_hub_findings(
        self,
        credentials: dict,
        *,
        region: str | None = None,
        max_findings: int = 50,
        max_pages: int = 2,
    ) -> list[dict]:
        """Return recent ACTIVE Security Hub findings (raw ASFF dicts) for a region.

        Conservative: the integration default region only, active findings only,
        a small page cap. Returns ``[]`` when there are no active findings.

        Raises (translated by ``_call_aws``): AuthenticationError (401),
        ConnectorError(403) on AccessDenied, RateLimitError, ConnectorError(503),
        ConnectorError on "not subscribed"/other API errors, NetworkError.
        """
        region = region or self._default_region(credentials)
        client = self._make_client("securityhub", credentials, region)

        per_page = max(1, min(int(max_findings or 50), 100))
        pages_cap = max(1, min(int(max_pages or 1), 5))
        # Only currently-active findings (archived ones are historical noise).
        filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}

        findings: list[dict] = []
        next_token: str | None = None
        for _ in range(pages_cap):
            kwargs: dict[str, Any] = {"MaxResults": per_page, "Filters": filters}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = self._call_aws(client.get_findings, **kwargs)
            page = resp.get("Findings", []) or []
            for f in page:
                if isinstance(f, dict):
                    f.setdefault("_Region", region)
                    findings.append(f)
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return findings

    # ── CloudTrail management events (M67.5) ───────────────────────────────────
    #
    # CloudTrail ``LookupEvents`` returns MANAGEMENT (control-plane) events only —
    # data events (S3 object access, Lambda invokes, etc.) are NOT returned by
    # this API, so this milestone is structurally limited to management activity.
    # These are control-plane ACTIVITY events for review, not breach detection.
    # Errors are translated by ``_call_aws`` (403 → ConnectorError(403) →
    # caller treats as permission-limited).

    def lookup_cloudtrail_events(
        self,
        credentials: dict,
        *,
        region: str | None = None,
        lookback_hours: int = 24,
        max_pages: int = 2,
        page_size: int = 50,
    ) -> list[dict]:
        """Return recent CloudTrail management events (raw dicts) for one region.

        Conservative by design: management events only (the LookupEvents API does
        not return data events), the integration default region only, a small
        page limit, and a bounded recent time window. Returns ``[]`` when there is
        nothing in the window.

        Raises (translated by ``_call_aws``): AuthenticationError (401),
        ConnectorError(403) on AccessDenied, RateLimitError, ConnectorError(503),
        NetworkError.
        """
        from datetime import datetime, timedelta, timezone

        region = region or self._default_region(credentials)
        client = self._make_client("cloudtrail", credentials, region)

        # Bound the window and the work: clamp inputs to safe ranges.
        hours = max(1, min(int(lookback_hours or 24), 168))  # ≤ 7 days
        pages_cap = max(1, min(int(max_pages or 1), 10))
        per_page = max(1, min(int(page_size or 50), 50))     # LookupEvents max = 50

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        events: list[dict] = []
        next_token: str | None = None
        for _ in range(pages_cap):
            kwargs: dict[str, Any] = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": per_page,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = self._call_aws(client.lookup_events, **kwargs)
            page = resp.get("Events", []) or []
            for e in page:
                if isinstance(e, dict):
                    e.setdefault("_Region", region)
                    events.append(e)
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return events

    # ── S3 CloudTrail data-event trail logs (M67.8) ────────────────────────────
    #
    # CloudTrail ``LookupEvents`` does NOT return S3 object-level DATA events —
    # those are only delivered to a configured trail's S3 bucket. This milestone
    # ingests a BOUNDED set of those trail-log objects (gzipped CloudTrail JSON)
    # so the caller can extract S3 data events. These are object-level ACTIVITY
    # events for review, not breach detection. Everything is capped: a small
    # file count, a per-object byte cap, and prefix filtering.

    def list_cloudtrail_log_objects(
        self,
        credentials: dict,
        *,
        bucket: str,
        prefix: str | None = None,
        max_files: int = 20,
        region: str | None = None,
    ) -> list[str]:
        """List up to ``max_files`` CloudTrail trail-log object keys in a bucket.

        Bounded by design: never an unbounded bucket scan. Returns the keys of
        gzipped/JSON log objects under the (optional) prefix. ``[]`` if empty.

        Raises (translated by ``_call_aws``): AuthenticationError (401),
        ConnectorError(403) on AccessDenied, ConnectorError(404)-style on missing
        bucket, RateLimitError, NetworkError.
        """
        region = region or self._default_region(credentials)
        client = self._make_client("s3", credentials, region)

        cap = max(1, min(int(max_files or 20), 200))
        keys: list[str] = []
        token: str | None = None
        # At most a few list pages — bounded by ``cap``.
        for _ in range(10):
            kwargs: dict[str, Any] = {"Bucket": bucket, "MaxKeys": min(cap, 1000)}
            if prefix:
                kwargs["Prefix"] = prefix
            if token:
                kwargs["ContinuationToken"] = token
            resp = self._call_aws(client.list_objects_v2, **kwargs)
            for obj in resp.get("Contents", []) or []:
                k = obj.get("Key")
                # Accept gzipped/plaintext log objects: CloudTrail (.json.gz),
                # VPC Flow Logs (.log.gz / .log), and generic .json/.txt logs.
                if isinstance(k, str) and (
                    k.endswith(".json.gz") or k.endswith(".gz")
                    or k.endswith(".json") or k.endswith(".log") or k.endswith(".txt")
                ):
                    keys.append(k)
                    if len(keys) >= cap:
                        return keys
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
            if not token:
                break
        return keys[:cap]

    def read_cloudtrail_log_object(
        self,
        credentials: dict,
        *,
        bucket: str,
        key: str,
        region: str | None = None,
        max_bytes: int = 5_000_000,
    ) -> bytes:
        """Return up to ``max_bytes`` of a single trail-log object's raw bytes.

        The caller is responsible for gzip-decompressing and JSON-parsing; this
        method only performs the bounded S3 read. Same error translation as
        ``list_cloudtrail_log_objects``.
        """
        region = region or self._default_region(credentials)
        client = self._make_client("s3", credentials, region)
        cap = max(1, min(int(max_bytes or 5_000_000), 25_000_000))

        resp = self._call_aws(client.get_object, Bucket=bucket, Key=key)
        body = resp.get("Body") if isinstance(resp, dict) else None
        if body is None:
            return b""
        # boto3 returns a StreamingBody with .read(amt); tolerate raw bytes too.
        if hasattr(body, "read"):
            raw = body.read(cap)
        else:
            raw = body
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw[:cap])
        return b""

    # ── Generic S3 log-object helpers (M67.10) ─────────────────────────────────
    #
    # Thin, provider-neutral aliases over the bounded S3 log readers above so any
    # S3-delivered log source (CloudTrail, VPC Flow Logs, …) can reuse the same
    # bounded list/read logic without duplicating it.

    def list_log_objects(
        self,
        credentials: dict,
        *,
        bucket: str,
        prefix: str | None = None,
        max_files: int = 20,
        region: str | None = None,
    ) -> list[str]:
        """List up to ``max_files`` log object keys in a bucket (bounded)."""
        return self.list_cloudtrail_log_objects(
            credentials, bucket=bucket, prefix=prefix,
            max_files=max_files, region=region,
        )

    def read_log_object_bytes(
        self,
        credentials: dict,
        *,
        bucket: str,
        key: str,
        region: str | None = None,
        max_bytes: int = 5_000_000,
    ) -> bytes:
        """Return up to ``max_bytes`` of a single log object's raw bytes."""
        return self.read_cloudtrail_log_object(
            credentials, bucket=bucket, key=key, region=region, max_bytes=max_bytes,
        )

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all AWS account/inventory, S3, network, IAM, and secrets records.

        Returns a flat list of normalized records:
        - 1 × aws_account_identity  (M36)
        - N × aws_region            (M36, one per selected region)
        - M × aws_s3_bucket         (M37, one per visible S3 bucket)
        - P × aws_security_group    (M38, one per SG per selected region)
        - Q × aws_security_group_rule (M38, one per flattened rule)
        - R × aws_vpc / aws_subnet / aws_route_table / aws_internet_gateway / aws_network_acl
        - 1 × aws_iam_account_summary (M39)
        - U × aws_iam_user          (M39, one per IAM user)
        - V × aws_iam_access_key    (M39, one per access key)
        - W × aws_iam_group         (M39, one per IAM group)
        - X × aws_iam_role          (M39, one per IAM role)
        - Y × aws_iam_policy        (M39, one per customer-managed policy)
        - Z × aws_iam_policy_attachment (M39, one per principal↔policy link)
        - ZZ × aws_iam_inline_policy (M39, one per inline policy per principal)
        - ZZZ × aws_iam_identity_provider (M39, OIDC/SAML providers)
        - ZZZ4 × aws_route53_hosted_zone (M40, one per hosted zone)
        - ZZZ5 × aws_route53_record  (M40, one per resource record set)
        - ZZZ6 × aws_cloudfront_distribution (M40, one per distribution)
        - A × aws_secretsmanager_secret (M41, one per secret per region)
        - B × aws_ssm_parameter      (M41, one per SSM parameter per region)
        - 1 × aws_service_inventory (last — reflects all active surfaces)

        All resources use fail-soft behavior for optional endpoints.
        The account identity is the only required call.

        SECURITY: Credentials are never included in returned records.
                  Raw policy documents are NEVER stored.
                  Secret values are NEVER fetched or stored.
                  SSM parameter values are NEVER fetched or stored.
                  GetSecretValue is NEVER called.
                  GetParameter / GetParameters / GetParameterHistory are NEVER called.
                  No write operations are performed.  No resource mutations.
        """
        logger.info(
            "AWSConnector.fetch: starting  key_id=%s",
            self._safe_key_id(credentials),
        )

        records: list[dict] = []

        # 1. Account identity (required — also confirms credentials are valid)
        account_record = self._fetch_account_identity(credentials)
        records.append(account_record)
        logger.info(
            "AWSConnector.fetch: account_identity fetched  account_id=%s",
            account_record.get("account_id", ""),
        )

        # 2. Regions (optional — fails soft on 403)
        region_records = self._fetch_regions(credentials)
        records.extend(region_records)
        logger.info(
            "AWSConnector.fetch: regions fetched  count=%d",
            len(region_records),
        )

        # 3. S3 buckets (optional — fails soft on 403)
        s3_records = self._fetch_s3_buckets(credentials)
        records.extend(s3_records)
        logger.info(
            "AWSConnector.fetch: s3_buckets fetched  count=%d",
            len(s3_records),
        )

        # 4. Network resources — security groups, VPCs, route tables, etc. (M38)
        network_records = self._fetch_network_resources(credentials)
        records.extend(network_records)
        logger.info(
            "AWSConnector.fetch: network_resources fetched  count=%d",
            len(network_records),
        )

        # 5. IAM resources — users, groups, roles, policies, providers (M39)
        # IAM is global; all data fetched once per account.
        # Fail-soft: if IAM permissions are absent, returns empty list.
        account_id: str = account_record.get("account_id", "")
        iam_records = self._fetch_iam_resources(credentials, account_id)
        records.extend(iam_records)
        logger.info(
            "AWSConnector.fetch: iam_resources fetched  count=%d",
            len(iam_records),
        )

        # 6. Route53 DNS resources (M40) — global; fetched once per account.
        route53_records = self._fetch_route53_resources(credentials, account_id)
        records.extend(route53_records)
        logger.info(
            "AWSConnector.fetch: route53_resources fetched  count=%d",
            len(route53_records),
        )

        # 7. CloudFront CDN resources (M40) — global; fetched once per account.
        cloudfront_records = self._fetch_cloudfront_resources(credentials, account_id)
        records.extend(cloudfront_records)
        logger.info(
            "AWSConnector.fetch: cloudfront_resources fetched  count=%d",
            len(cloudfront_records),
        )

        # 8. Secrets Manager secrets (M41) — regional; metadata only.
        #    SECURITY: GetSecretValue is NEVER called.
        secrets_records = self._fetch_secrets_resources(credentials, account_id)
        records.extend(secrets_records)
        logger.info(
            "AWSConnector.fetch: secrets_resources fetched  count=%d",
            len(secrets_records),
        )

        # 9. SSM parameters (M41) — regional; metadata only.
        #    SECURITY: GetParameter / GetParameters / GetParameterHistory are NEVER called.
        ssm_records = self._fetch_ssm_resources(credentials, account_id)
        records.extend(ssm_records)
        logger.info(
            "AWSConnector.fetch: ssm_resources fetched  count=%d",
            len(ssm_records),
        )

        # 11. RDS database resources (M42) — regional; metadata only.
        #     SECURITY: No DB connections, no passwords, no database content accessed.
        #     DownloadDBLogFilePortion and DownloadCompleteDBLogFile are NEVER called.
        rds_records = self._fetch_rds_resources(credentials, account_id)
        records.extend(rds_records)
        logger.info(
            "AWSConnector.fetch: rds_resources fetched  count=%d",
            len(rds_records),
        )

        # 12. Lambda functions, aliases, event source mappings, function URLs (M43).
        #     SECURITY: Function code is NEVER accessed.  GetFunction is NOT called.
        #     Environment variable values are NEVER stored — keys only.
        #     lambda:InvokeFunction is NEVER called.
        lambda_records = self._fetch_lambda_resources(credentials, account_id)
        records.extend(lambda_records)
        logger.info(
            "AWSConnector.fetch: lambda_resources fetched  count=%d",
            len(lambda_records),
        )

        # 13. API Gateway REST APIs + stages (M43) — regional; metadata only.
        #     SECURITY: No request/response bodies, logs, or API traffic is read.
        #     Stage variable values are NEVER stored — keys only.
        apigw_records = self._fetch_apigateway_resources(credentials, account_id)
        records.extend(apigw_records)
        logger.info(
            "AWSConnector.fetch: apigateway_resources fetched  count=%d",
            len(apigw_records),
        )

        # 14. API Gateway V2 (HTTP/WebSocket) APIs + stages (M43) — regional.
        #     SECURITY: Same guarantees as REST API Gateway above.
        apigwv2_records = self._fetch_apigatewayv2_resources(credentials, account_id)
        records.extend(apigwv2_records)
        logger.info(
            "AWSConnector.fetch: apigatewayv2_resources fetched  count=%d",
            len(apigwv2_records),
        )

        # 15. ELBv2 load balancers, listeners, rules, target groups (M44) — regional.
        #     SECURITY: Access log objects NEVER read. Request/response traffic NEVER accessed.
        elbv2_records = self._fetch_elbv2_resources(credentials, account_id)
        records.extend(elbv2_records)
        logger.info(
            "AWSConnector.fetch: elbv2_resources fetched  count=%d",
            len(elbv2_records),
        )

        # 16. Classic ELB load balancers (M44) — regional; metadata only.
        #     SECURITY: Access log objects NEVER read.
        elb_classic_records = self._fetch_elb_classic_resources(credentials, account_id)
        records.extend(elb_classic_records)
        logger.info(
            "AWSConnector.fetch: elb_classic_resources fetched  count=%d",
            len(elb_classic_records),
        )

        # 17. WAFv2 REGIONAL Web ACLs (M44) — regional; metadata only.
        #     SECURITY: GetSampledRequests NEVER called. Rule statement values NEVER stored.
        wafv2_records = self._fetch_wafv2_resources(credentials, account_id)
        records.extend(wafv2_records)
        logger.info(
            "AWSConnector.fetch: wafv2_resources fetched  count=%d",
            len(wafv2_records),
        )

        # 18. CloudTrail trails + event data stores (M45) — trail metadata only.
        #     SECURITY: LookupEvents NEVER called. S3 log objects NEVER read.
        #     Event payloads, request params, user identity data NEVER stored.
        cloudtrail_records = self._fetch_cloudtrail_resources(credentials, account_id)
        records.extend(cloudtrail_records)
        logger.info(
            "AWSConnector.fetch: cloudtrail_resources fetched  count=%d",
            len(cloudtrail_records),
        )

        # 19. GuardDuty detectors (M45) — posture metadata only.
        #     SECURITY: GetFindings NEVER called. Finding details NEVER accessed or stored.
        guardduty_records = self._fetch_guardduty_resources(credentials, account_id)
        records.extend(guardduty_records)
        logger.info(
            "AWSConnector.fetch: guardduty_resources fetched  count=%d",
            len(guardduty_records),
        )

        # 20. Security Hub account posture (M45) — hub/standards metadata only.
        #     SECURITY: GetFindings NEVER called. Finding details NEVER accessed or stored.
        securityhub_records = self._fetch_securityhub_resources(credentials, account_id)
        records.extend(securityhub_records)
        logger.info(
            "AWSConnector.fetch: securityhub_resources fetched  count=%d",
            len(securityhub_records),
        )

        # 21. ECS clusters, services, task definitions (M46) — posture metadata only.
        #     SECURITY: logs:GetLogEvents NEVER called. Task/container logs NEVER read.
        #     Environment variable values NEVER stored. Secret values NEVER accessed.
        ecs_records = self._fetch_ecs_resources(credentials, account_id)
        records.extend(ecs_records)
        logger.info(
            "AWSConnector.fetch: ecs_resources fetched  count=%d",
            len(ecs_records),
        )

        # 22. EKS clusters, node groups, Fargate profiles, add-ons (M46).
        #     SECURITY: Kubernetes API NEVER called. Pods, Secrets, ConfigMaps NEVER read.
        eks_records = self._fetch_eks_resources(credentials, account_id)
        records.extend(eks_records)
        logger.info(
            "AWSConnector.fetch: eks_resources fetched  count=%d",
            len(eks_records),
        )

        # 23. ECR repositories + registry scanning config (M46).
        #     SECURITY: Images NEVER pulled. ecr:GetAuthorizationToken NEVER called.
        #     Image layers and manifests NEVER accessed.
        ecr_records = self._fetch_ecr_resources(credentials, account_id)
        records.extend(ecr_records)
        logger.info(
            "AWSConnector.fetch: ecr_resources fetched  count=%d",
            len(ecr_records),
        )

        # 24. EventBridge event buses, rules, targets, archives (M47).
        #     SECURITY: events:PutEvents NEVER called. Event payloads NEVER read or stored.
        #     Only bus/rule/target/archive configuration metadata is collected.
        eventbridge_records = self._fetch_eventbridge_resources(credentials, account_id)
        records.extend(eventbridge_records)
        logger.info(
            "AWSConnector.fetch: eventbridge_resources fetched  count=%d",
            len(eventbridge_records),
        )

        # 25. SQS queues (M47).
        #     SECURITY: sqs:ReceiveMessage/SendMessage/DeleteMessage/PurgeQueue NEVER called.
        #     Message bodies and queue contents NEVER read or stored.
        sqs_records = self._fetch_sqs_resources(credentials, account_id)
        records.extend(sqs_records)
        logger.info(
            "AWSConnector.fetch: sqs_resources fetched  count=%d",
            len(sqs_records),
        )

        # 26. SNS topics and subscriptions (M47).
        #     SECURITY: sns:Publish NEVER called. Notification contents NEVER read.
        #     Subscription endpoints hashed only; raw values NEVER stored.
        sns_records = self._fetch_sns_resources(credentials, account_id)
        records.extend(sns_records)
        logger.info(
            "AWSConnector.fetch: sns_resources fetched  count=%d",
            len(sns_records),
        )

        # 27. KMS keys and aliases (M48).
        #     SECURITY: kms:Decrypt/Encrypt/GenerateDataKey and ALL cryptographic
        #     operations NEVER called.  Only key configuration posture collected.
        kms_records = self._fetch_kms_resources(credentials, account_id)
        records.extend(kms_records)
        logger.info(
            "AWSConnector.fetch: kms_resources fetched  count=%d",
            len(kms_records),
        )

        # 28. AWS Backup vaults, plans, selections, recovery points (M48).
        #     SECURITY: backup:StartBackupJob/StartRestoreJob/DeleteRecoveryPoint NEVER called.
        #     Backup contents and protected resource data NEVER read.
        backup_records = self._fetch_backup_resources(credentials, account_id)
        records.extend(backup_records)
        logger.info(
            "AWSConnector.fetch: backup_resources fetched  count=%d",
            len(backup_records),
        )

        # 29. AWS Organizations structure and SCPs (M48).
        #     SECURITY: Organizations/SCP write/mutate operations NEVER called.
        #     SCPs never created, attached, detached, or deleted.
        organizations_records = self._fetch_organizations_resources(credentials, account_id)
        records.extend(organizations_records)
        logger.info(
            "AWSConnector.fetch: organizations_resources fetched  count=%d",
            len(organizations_records),
        )

        # 30. CloudWatch metric alarms, composite alarms, dashboards, metric streams,
        #     and anomaly detectors (M49).
        #     SECURITY: cloudwatch:GetMetricData, cloudwatch:GetMetricStatistics,
        #     and ALL metric datapoint read operations NEVER called.
        #     Alarm evaluation history NEVER read.
        cloudwatch_records = self._fetch_cloudwatch_resources(credentials, account_id)
        records.extend(cloudwatch_records)
        logger.info(
            "AWSConnector.fetch: cloudwatch_resources fetched  count=%d",
            len(cloudwatch_records),
        )

        # 31. CloudWatch Logs log groups, metric filters, subscription filters (M49).
        #     SECURITY: logs:GetLogEvents, logs:FilterLogEvents, logs:StartQuery,
        #     logs:GetQueryResults NEVER called. Log event contents NEVER accessed.
        cloudwatch_logs_records = self._fetch_cloudwatch_logs_resources(credentials, account_id)
        records.extend(cloudwatch_logs_records)
        logger.info(
            "AWSConnector.fetch: cloudwatch_logs_resources fetched  count=%d",
            len(cloudwatch_logs_records),
        )

        # 10. Service inventory (always last — reflects all active surfaces)
        sg_count = sum(
            1 for r in network_records
            if r.get("record_type") == AWS_SECURITY_GROUP
        )
        vpc_count = sum(
            1 for r in network_records
            if r.get("record_type") == AWS_VPC
        )
        iam_user_count = sum(
            1 for r in iam_records
            if r.get("record_type") == AWS_IAM_USER
        )
        iam_role_count = sum(
            1 for r in iam_records
            if r.get("record_type") == AWS_IAM_ROLE
        )
        route53_zone_count = sum(
            1 for r in route53_records
            if r.get("record_type") == AWS_ROUTE53_HOSTED_ZONE
        )
        cloudfront_dist_count = sum(
            1 for r in cloudfront_records
            if r.get("record_type") == AWS_CLOUDFRONT_DISTRIBUTION
        )
        secrets_count = sum(
            1 for r in secrets_records
            if r.get("record_type") == AWS_SECRETSMANAGER_SECRET
        )
        ssm_parameter_count = sum(
            1 for r in ssm_records
            if r.get("record_type") == AWS_SSM_PARAMETER
        )
        rds_instance_count = sum(
            1 for r in rds_records
            if r.get("record_type") == AWS_RDS_DB_INSTANCE
        )
        rds_cluster_count = sum(
            1 for r in rds_records
            if r.get("record_type") == AWS_RDS_DB_CLUSTER
        )
        lambda_function_count = sum(
            1 for r in lambda_records
            if r.get("record_type") == AWS_LAMBDA_FUNCTION
        )
        apigw_rest_api_count = sum(
            1 for r in apigw_records
            if r.get("record_type") == AWS_APIGATEWAY_REST_API
        )
        apigwv2_api_count = sum(
            1 for r in apigwv2_records
            if r.get("record_type") == AWS_APIGATEWAYV2_API
        )
        elbv2_lb_count = sum(
            1 for r in elbv2_records
            if r.get("record_type") == AWS_ELBV2_LOAD_BALANCER
        )
        elb_classic_count = sum(
            1 for r in elb_classic_records
            if r.get("record_type") == AWS_ELB_CLASSIC_LOAD_BALANCER
        )
        wafv2_acl_count = sum(
            1 for r in wafv2_records
            if r.get("record_type") == AWS_WAFV2_WEB_ACL
        )
        cloudtrail_trail_count = sum(
            1 for r in cloudtrail_records
            if r.get("record_type") == AWS_CLOUDTRAIL_TRAIL
        )
        guardduty_detector_count = sum(
            1 for r in guardduty_records
            if r.get("record_type") == AWS_GUARDDUTY_DETECTOR
        )
        securityhub_hub_count = sum(
            1 for r in securityhub_records
            if r.get("record_type") == AWS_SECURITYHUB_ACCOUNT
        )
        ecs_cluster_count = sum(
            1 for r in ecs_records
            if r.get("record_type") == AWS_ECS_CLUSTER
        )
        eks_cluster_count = sum(
            1 for r in eks_records
            if r.get("record_type") == AWS_EKS_CLUSTER
        )
        ecr_repository_count = sum(
            1 for r in ecr_records
            if r.get("record_type") == AWS_ECR_REPOSITORY
        )
        eventbridge_bus_count = sum(
            1 for r in eventbridge_records
            if r.get("record_type") == AWS_EVENTBRIDGE_EVENT_BUS
        )
        sqs_queue_count = sum(
            1 for r in sqs_records
            if r.get("record_type") == AWS_SQS_QUEUE
        )
        sns_topic_count = sum(
            1 for r in sns_records
            if r.get("record_type") == AWS_SNS_TOPIC
        )
        kms_key_count = sum(
            1 for r in kms_records
            if r.get("record_type") == AWS_KMS_KEY
        )
        backup_vault_count = sum(
            1 for r in backup_records
            if r.get("record_type") == AWS_BACKUP_VAULT
        )
        org_account_count = sum(
            1 for r in organizations_records
            if r.get("record_type") == AWS_ORGANIZATIONS_ACCOUNT
        )
        cloudwatch_alarm_count = sum(
            1 for r in cloudwatch_records
            if r.get("record_type") == AWS_CLOUDWATCH_METRIC_ALARM
        )
        cloudwatch_log_group_count = sum(
            1 for r in cloudwatch_logs_records
            if r.get("record_type") == AWS_CLOUDWATCH_LOG_GROUP
        )
        inventory_record = self._fetch_service_inventory(
            credentials,
            s3_count=len(s3_records),
            security_group_count=sg_count,
            vpc_count=vpc_count,
            iam_user_count=iam_user_count,
            iam_role_count=iam_role_count,
            route53_zone_count=route53_zone_count,
            cloudfront_distribution_count=cloudfront_dist_count,
            secrets_count=secrets_count,
            ssm_parameter_count=ssm_parameter_count,
            rds_instance_count=rds_instance_count,
            rds_cluster_count=rds_cluster_count,
            lambda_function_count=lambda_function_count,
            apigw_rest_api_count=apigw_rest_api_count,
            apigwv2_api_count=apigwv2_api_count,
            elbv2_lb_count=elbv2_lb_count,
            elb_classic_count=elb_classic_count,
            wafv2_acl_count=wafv2_acl_count,
            cloudtrail_trail_count=cloudtrail_trail_count,
            guardduty_detector_count=guardduty_detector_count,
            securityhub_hub_count=securityhub_hub_count,
            ecs_cluster_count=ecs_cluster_count,
            eks_cluster_count=eks_cluster_count,
            ecr_repository_count=ecr_repository_count,
            eventbridge_bus_count=eventbridge_bus_count,
            sqs_queue_count=sqs_queue_count,
            sns_topic_count=sns_topic_count,
            kms_key_count=kms_key_count,
            backup_vault_count=backup_vault_count,
            org_account_count=org_account_count,
            cloudwatch_alarm_count=cloudwatch_alarm_count,
            cloudwatch_log_group_count=cloudwatch_log_group_count,
        )
        records.append(inventory_record)

        logger.info(
            "AWSConnector.fetch: complete  total_records=%d",
            len(records),
        )
        return records

    # ── Fetch helpers ──────────────────────────────────────────────────────────

    def _fetch_account_identity(self, credentials: dict) -> dict:
        """Fetch account identity via STS GetCallerIdentity and normalize.

        SECURITY: Does not log ARN or account ID in full in any sensitive context.
        The account ID is used as the resource identifier and stored in metadata.
        """
        client = self._make_client("sts", credentials)
        response = self._call_aws(client.get_caller_identity)

        account_id: str = response.get("Account", "")
        arn: str = response.get("Arn", "")

        principal_type = _parse_principal_type(arn)
        partition = _parse_partition(arn)
        selected = self._selected_regions(credentials)
        default_region = self._default_region(credentials)

        return {
            "record_type":      AWS_ACCOUNT_IDENTITY,
            "record_id":        account_id,
            "name":             f"AWS Account {account_id}",
            # Account identity
            "account_id":       account_id,
            "principal_arn":    arn,          # full ARN — safe (not a secret)
            "principal_type":   principal_type,
            "partition":        partition,
            # Region configuration
            "default_region":   default_region,
            "selected_regions": selected,
        }

    def _fetch_regions(self, credentials: dict) -> list[dict]:
        """Fetch enabled regions from EC2 DescribeRegions and normalize.

        Returns one record per selected region.

        Fail-soft: if ec2:DescribeRegions is not permitted (403 / AccessDenied),
        this method returns records for the user-configured selected_regions
        without opt_in_status from AWS (uses "unknown" as fallback).
        """
        selected = self._selected_regions(credentials)
        region = self._default_region(credentials)

        try:
            client = self._make_client("ec2", credentials, region=region)
            response = self._call_aws(
                client.describe_regions,
                AllRegions=False,
                Filters=[
                    {
                        "Name": "opt-in-status",
                        "Values": ["opt-in-not-required", "opted-in"],
                    }
                ],
            )
            discovered: dict[str, dict] = {
                r["RegionName"]: r for r in response.get("Regions", [])
            }
            source = "discovered"
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "aws: ec2:DescribeRegions not permitted — "
                    "using user-selected regions without opt-in metadata"
                )
                discovered = {}
                source = "selected"
            else:
                raise

        records = []
        for region_name in selected:
            raw = discovered.get(region_name, {})
            records.append({
                "record_type":   AWS_REGION,
                "record_id":     region_name,
                "name":          region_name,
                "region_name":   region_name,
                "opt_in_status": raw.get("OptInStatus", "unknown"),
                "enabled":       True,
                "source":        source,
            })
        return records

    def _fetch_service_inventory(
        self,
        credentials: dict,
        s3_count: int = 0,
        security_group_count: int = 0,
        vpc_count: int = 0,
        iam_user_count: int = 0,
        iam_role_count: int = 0,
        route53_zone_count: int = 0,
        cloudfront_distribution_count: int = 0,
        secrets_count: int = 0,
        ssm_parameter_count: int = 0,
        rds_instance_count: int = 0,
        rds_cluster_count: int = 0,
        lambda_function_count: int = 0,
        apigw_rest_api_count: int = 0,
        apigwv2_api_count: int = 0,
        elbv2_lb_count: int = 0,
        elb_classic_count: int = 0,
        wafv2_acl_count: int = 0,
        cloudtrail_trail_count: int = 0,
        guardduty_detector_count: int = 0,
        securityhub_hub_count: int = 0,
        ecs_cluster_count: int = 0,
        eks_cluster_count: int = 0,
        ecr_repository_count: int = 0,
        eventbridge_bus_count: int = 0,
        sqs_queue_count: int = 0,
        sns_topic_count: int = 0,
        kms_key_count: int = 0,
        backup_vault_count: int = 0,
        org_account_count: int = 0,
        cloudwatch_alarm_count: int = 0,
        cloudwatch_log_group_count: int = 0,
    ) -> dict:
        """Return a service inventory record reflecting active monitored surfaces."""
        selected = self._selected_regions(credentials)
        return {
            "record_type":                    AWS_SERVICE_INVENTORY,
            "record_id":                      "service_inventory",
            "name":                           "AWS Service Inventory",
            "selected_regions":               selected,
            "enabled_surfaces":               [
                "account_inventory", "s3", "security_groups", "vpc",
                "iam", "route53", "cloudfront", "secrets_manager", "ssm",
                "rds", "lambda", "api_gateway", "load_balancers", "waf",
                "cloudtrail", "guardduty", "security_hub",
                "ecs", "eks", "ecr",
                "eventbridge", "sqs", "sns",
                "kms", "backup", "organizations",
                "cloudwatch", "cloudwatch_logs",
            ],
            "s3_bucket_count":                s3_count,
            "security_group_count":           security_group_count,
            "vpc_count":                      vpc_count,
            "iam_user_count":                 iam_user_count,
            "iam_role_count":                 iam_role_count,
            "route53_zone_count":             route53_zone_count,
            "cloudfront_distribution_count":  cloudfront_distribution_count,
            "secrets_count":                  secrets_count,
            "ssm_parameter_count":            ssm_parameter_count,
            "rds_instance_count":             rds_instance_count,
            "rds_cluster_count":              rds_cluster_count,
            "lambda_function_count":          lambda_function_count,
            "apigw_rest_api_count":           apigw_rest_api_count,
            "apigwv2_api_count":              apigwv2_api_count,
            "elbv2_lb_count":                 elbv2_lb_count,
            "elb_classic_count":              elb_classic_count,
            "wafv2_acl_count":                wafv2_acl_count,
            "cloudtrail_trail_count":         cloudtrail_trail_count,
            "guardduty_detector_count":       guardduty_detector_count,
            "securityhub_hub_count":          securityhub_hub_count,
            "ecs_cluster_count":              ecs_cluster_count,
            "eks_cluster_count":              eks_cluster_count,
            "ecr_repository_count":           ecr_repository_count,
            "eventbridge_bus_count":          eventbridge_bus_count,
            "sqs_queue_count":                sqs_queue_count,
            "sns_topic_count":                sns_topic_count,
            "kms_key_count":                  kms_key_count,
            "backup_vault_count":             backup_vault_count,
            "org_account_count":              org_account_count,
            "cloudwatch_alarm_count":         cloudwatch_alarm_count,
            "cloudwatch_log_group_count":     cloudwatch_log_group_count,
            "future_surfaces":                [],
        }

    def get_account_id(self, credentials: dict) -> str:
        """Return the AWS account ID for the given credentials.

        Used by integration_service to get the stable identifier before creating
        the Resource row. Calls STS GetCallerIdentity.

        SECURITY: aws_secret_access_key is never logged.
        """
        client = self._make_client("sts", credentials)
        response = self._call_aws(client.get_caller_identity)
        return response.get("Account", "")

    # ── S3 fetch methods (M37) ─────────────────────────────────────────────────

    def _fetch_s3_buckets(self, credentials: dict) -> list[dict]:
        """List all S3 buckets and fetch configuration for each.

        Returns one aws_s3_bucket record per bucket. Fail-soft on 403:
        if s3:ListAllMyBuckets is denied, returns an empty list so the rest
        of the sync still succeeds.

        Per-bucket optional field failures (e.g. missing GetBucketPolicy
        permission) are recorded in config_fetch_warnings on the record,
        not propagated as integration-level failures.

        SECURITY:
        - Object contents and object keys are NEVER fetched.
        - Raw bucket policy text is NEVER stored; only policy_hash + parsed fields.
        - aws credentials are never placed in any returned record.
        """
        # Use us-east-1 as the signing region for the global S3 endpoint.
        # boto3 automatically handles routing to bucket-specific regions.
        client = self._make_client("s3", credentials, region="us-east-1")

        try:
            response = self._call_aws(client.list_buckets)
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "aws: s3:ListAllMyBuckets not permitted — "
                    "skipping S3 monitoring for this sync"
                )
                return []
            raise

        buckets = response.get("Buckets") or []
        records: list[dict] = []
        for bucket in buckets:
            bucket_name: str = bucket.get("Name") or ""
            if not bucket_name:
                continue
            creation_date = bucket.get("CreationDate")
            try:
                record = self._fetch_bucket_config(
                    client, bucket_name, creation_date, credentials
                )
                records.append(record)
            except Exception:
                # Belt-and-suspenders: a single bad bucket must never abort
                # the full sync. Log and continue.
                logger.warning(
                    "aws: failed to fetch config for bucket %r — skipping",
                    bucket_name,
                    exc_info=True,
                )

        logger.debug(
            "aws._fetch_s3_buckets: fetched %d bucket record(s)  key_id=%s",
            len(records),
            self._safe_key_id(credentials),
        )
        return records

    def _fetch_bucket_config(
        self,
        client: Any,
        bucket_name: str,
        creation_date: Any,
        credentials: dict,
    ) -> dict:
        """Assemble a complete aws_s3_bucket record for one bucket.

        Each optional sub-helper is wrapped with a fail-soft handler so that
        an unexpected exception (e.g. wrong boto3 method name, API shape change,
        network hiccup on a single field) adds a ``*_error`` entry to
        ``config_fetch_warnings`` and returns None-valued fallback fields
        instead of skipping the bucket entirely.

        Expected permission errors (403) and "not configured" states
        (NoSuch*) are handled inside each sub-helper before they reach here.

        SECURITY: credentials are only forwarded to _make_client for regional
        clients; they are never placed in the returned record.
        """
        warnings: list[str] = []

        # ── Bucket region ──────────────────────────────────────────────────────
        bucket_region = self._fetch_bucket_region(client, bucket_name)

        # ── Creation date (immutable, stored for context only) ─────────────────
        creation_date_str: str | None = None
        if creation_date is not None:
            try:
                creation_date_str = creation_date.isoformat()
            except AttributeError:
                creation_date_str = str(creation_date)

        # ── Fail-soft wrapper ──────────────────────────────────────────────────
        # Calls fn(); on any unexpected exception logs a warning, appends
        # ``warning_key + "_error"`` to the shared warnings list, and returns
        # fallback so the caller always gets a usable dict.
        def _safe(fn: Any, fallback: dict, warning_key: str) -> dict:
            try:
                return fn()
            except Exception:
                logger.warning(
                    "aws._fetch_bucket_config: unexpected error fetching %s "
                    "for bucket %r — using safe fallback",
                    warning_key, bucket_name, exc_info=True,
                )
                warnings.append(warning_key + "_error")
                return fallback

        # ── Per-field config (all optional / fail-soft) ────────────────────────
        bpa = _safe(
            lambda: self._fetch_bucket_public_access_block(client, bucket_name, warnings),
            {
                "block_public_acls":              None,
                "ignore_public_acls":             None,
                "block_public_policy":            None,
                "restrict_public_buckets":        None,
                "public_access_block_configured": None,
            },
            "s3_public_access_block",
        )
        policy_info = _safe(
            lambda: self._fetch_bucket_policy_info(client, bucket_name, warnings),
            {"policy_present": None, "policy_hash": None, "public_principals_detected": None},
            "s3_policy",
        )
        policy_stat = _safe(
            lambda: self._fetch_bucket_policy_status(client, bucket_name, warnings),
            {"policy_status_is_public": None},
            "s3_policy_status",
        )
        acl_info = _safe(
            lambda: self._fetch_bucket_acl(client, bucket_name, warnings),
            {
                "acl_all_users_read":             None,
                "acl_all_users_write":            None,
                "acl_authenticated_users_read":   None,
                "acl_authenticated_users_write":  None,
            },
            "s3_acl",
        )
        enc_info = _safe(
            lambda: self._fetch_bucket_encryption(client, bucket_name, warnings),
            {"encryption_enabled": None, "encryption_algorithm": None, "bucket_key_enabled": None},
            "s3_encryption",
        )
        ver_info = _safe(
            lambda: self._fetch_bucket_versioning(client, bucket_name, warnings),
            {"versioning_status": None, "mfa_delete_status": None},
            "s3_versioning",
        )
        log_info = _safe(
            lambda: self._fetch_bucket_logging(client, bucket_name, warnings),
            {"logging_enabled": None, "logging_target_bucket": None},
            "s3_logging",
        )
        lifecycle = _safe(
            lambda: self._fetch_bucket_lifecycle(client, bucket_name, warnings),
            {"lifecycle_rule_count": None},
            "s3_lifecycle",
        )
        tag_info = _safe(
            lambda: self._fetch_bucket_tags(client, bucket_name, warnings),
            {"tag_keys": None},
            "s3_tagging",
        )

        record: dict[str, Any] = {
            "record_type":   AWS_S3_BUCKET,
            "record_id":     bucket_name,    # stable key used by diff_service
            "name":          bucket_name,
            "bucket_name":   bucket_name,
            "bucket_region": bucket_region,
            "creation_date": creation_date_str,
        }
        record.update(bpa)
        record.update(policy_info)
        record.update(policy_stat)
        record.update(acl_info)
        record.update(enc_info)
        record.update(ver_info)
        record.update(log_info)
        record.update(lifecycle)
        record.update(tag_info)
        record["config_fetch_warnings"] = sorted(warnings)

        return record

    def _fetch_bucket_region(self, client: Any, bucket_name: str) -> str:
        """Return the bucket's AWS region.

        GetBucketLocation returns None (or "") for us-east-1 buckets.
        All other regions are returned as-is.
        """
        try:
            response = self._call_aws(
                client.get_bucket_location, Bucket=bucket_name
            )
            location = response.get("LocationConstraint")
            return location if location else "us-east-1"
        except ConnectorError:
            logger.debug(
                "aws: could not determine region for bucket %r", bucket_name
            )
            return "unknown"

    def _fetch_bucket_public_access_block(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch Block Public Access (BPA) configuration.

        Returns a dict with block_public_acls, ignore_public_acls,
        block_public_policy, restrict_public_buckets, and the boolean
        public_access_block_configured (False when BPA is not set at all).

        NoSuchPublicAccessBlockConfiguration → all fields False, configured=False.
        403 → all fields None (unavailable), warning added.
        """
        try:
            response = self._call_aws(
                client.get_public_access_block, Bucket=bucket_name
            )
            cfg = response.get("PublicAccessBlockConfiguration") or {}
            return {
                "block_public_acls":         cfg.get("BlockPublicAcls",         False),
                "ignore_public_acls":        cfg.get("IgnorePublicAcls",        False),
                "block_public_policy":       cfg.get("BlockPublicPolicy",       False),
                "restrict_public_buckets":   cfg.get("RestrictPublicBuckets",   False),
                "public_access_block_configured": True,
            }
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchPublicAccessBlockConfiguration" in msg:
                # BPA not set — this is a legitimate "not configured" state
                return {
                    "block_public_acls":         False,
                    "ignore_public_acls":        False,
                    "block_public_policy":       False,
                    "restrict_public_buckets":   False,
                    "public_access_block_configured": False,
                }
            if exc.status_code == 403:
                warnings.append("s3_public_access_block_unavailable")
                return {
                    "block_public_acls":         None,
                    "ignore_public_acls":        None,
                    "block_public_policy":       None,
                    "restrict_public_buckets":   None,
                    "public_access_block_configured": None,
                }
            raise

    def _fetch_bucket_policy_info(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch bucket policy and derive public-principal presence.

        SECURITY: Raw policy text is NEVER stored. Only a short SHA-256
        prefix (policy_hash) and the boolean public_principals_detected are
        recorded.

        NoSuchBucketPolicy → policy_present=False, hash/public detection omitted.
        403 → policy_present=None (unavailable), warning added.
        """
        import hashlib
        try:
            response = self._call_aws(
                client.get_bucket_policy, Bucket=bucket_name
            )
            policy_json: str = response.get("Policy") or ""
            policy_hash = hashlib.sha256(policy_json.encode()).hexdigest()[:16]
            public_principals = _parse_bucket_policy_public(policy_json)
            return {
                "policy_present":            True,
                "policy_hash":               policy_hash,
                "public_principals_detected": public_principals,
            }
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchBucketPolicy" in msg:
                return {
                    "policy_present":            False,
                    "policy_hash":               None,
                    "public_principals_detected": False,
                }
            if exc.status_code == 403:
                warnings.append("s3_policy_unavailable")
                return {
                    "policy_present":            None,
                    "policy_hash":               None,
                    "public_principals_detected": None,
                }
            raise

    def _fetch_bucket_policy_status(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch AWS's computed public-policy status for the bucket.

        GetBucketPolicyStatus asks AWS whether the bucket policy makes the
        bucket public. This is the authoritative signal for public-policy
        exposure (more reliable than our own policy parsing).

        403 or no policy → policy_status_is_public=None (unavailable).
        """
        try:
            response = self._call_aws(
                client.get_bucket_policy_status, Bucket=bucket_name
            )
            status = response.get("PolicyStatus") or {}
            return {
                "policy_status_is_public": status.get("IsPublic"),
            }
        except ConnectorError as exc:
            msg = str(exc)
            # "NoSuchBucketPolicy" or "NoSuchPublicAccessBlockConfiguration"
            # can also appear here for buckets without policies
            if exc.status_code == 403 or "NoSuchBucketPolicy" in msg:
                if exc.status_code == 403:
                    warnings.append("s3_policy_status_unavailable")
                return {"policy_status_is_public": None}
            raise

    def _fetch_bucket_acl(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch ACL and detect public grants for AllUsers and AuthenticatedUsers.

        Returns boolean fields for read/write access to each public group.
        403 → all fields None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_acl, Bucket=bucket_name
            )
            grants = response.get("Grants") or []
            au_read = au_write = False
            auu_read = auu_write = False
            for grant in grants:
                grantee = grant.get("Grantee") or {}
                uri = grantee.get("URI") or ""
                perm = grant.get("Permission") or ""
                if uri == _ACL_ALL_USERS_URI:
                    if perm in _ACL_READ_PERMISSIONS:
                        au_read = True
                    if perm in _ACL_WRITE_PERMISSIONS:
                        au_write = True
                elif uri == _ACL_AUTH_USERS_URI:
                    if perm in _ACL_READ_PERMISSIONS:
                        auu_read = True
                    if perm in _ACL_WRITE_PERMISSIONS:
                        auu_write = True
            return {
                "acl_all_users_read":             au_read,
                "acl_all_users_write":            au_write,
                "acl_authenticated_users_read":   auu_read,
                "acl_authenticated_users_write":  auu_write,
            }
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append("s3_acl_unavailable")
                return {
                    "acl_all_users_read":             None,
                    "acl_all_users_write":            None,
                    "acl_authenticated_users_read":   None,
                    "acl_authenticated_users_write":  None,
                }
            raise

    def _fetch_bucket_encryption(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch server-side encryption configuration.

        Returns encryption_enabled=True with algorithm/bucket_key details,
        or encryption_enabled=False if not configured.
        403 → encryption_enabled=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_encryption, Bucket=bucket_name
            )
            sse_cfg = response.get("ServerSideEncryptionConfiguration") or {}
            rules = sse_cfg.get("Rules") or []
            if rules:
                rule = rules[0]
                default = rule.get("ApplyServerSideEncryptionByDefault") or {}
                return {
                    "encryption_enabled":    True,
                    "encryption_algorithm":  default.get("SSEAlgorithm"),
                    "bucket_key_enabled":    rule.get("BucketKeyEnabled"),
                }
            return {
                "encryption_enabled":    True,
                "encryption_algorithm":  None,
                "bucket_key_enabled":    None,
            }
        except ConnectorError as exc:
            msg = str(exc)
            if "ServerSideEncryptionConfigurationNotFoundError" in msg:
                return {
                    "encryption_enabled":    False,
                    "encryption_algorithm":  None,
                    "bucket_key_enabled":    None,
                }
            if exc.status_code == 403:
                warnings.append("s3_encryption_unavailable")
                return {
                    "encryption_enabled":    None,
                    "encryption_algorithm":  None,
                    "bucket_key_enabled":    None,
                }
            raise

    def _fetch_bucket_versioning(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch versioning and MFA-delete status.

        Versioning status:
            "Enabled"   → versioning_status = "enabled"
            "Suspended"  → versioning_status = "suspended"
            "" / absent  → versioning_status = "disabled"

        MFA delete:
            "Enabled"   → mfa_delete_status = "enabled"
            "Disabled"  → mfa_delete_status = "disabled"
            absent      → mfa_delete_status = None

        403 → both fields None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_versioning, Bucket=bucket_name
            )
            raw_status = response.get("Status") or ""
            raw_mfa = response.get("MFADelete") or ""
            versioning_status = (
                "enabled"   if raw_status == "Enabled"
                else "suspended" if raw_status == "Suspended"
                else "disabled"
            )
            mfa_delete_status = (
                raw_mfa.lower()
                if raw_mfa.lower() in ("enabled", "disabled")
                else None
            )
            return {
                "versioning_status":   versioning_status,
                "mfa_delete_status":   mfa_delete_status,
            }
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append("s3_versioning_unavailable")
                return {
                    "versioning_status":   None,
                    "mfa_delete_status":   None,
                }
            raise

    def _fetch_bucket_logging(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch server access logging configuration.

        Returns logging_enabled=True with target bucket if enabled,
        or logging_enabled=False if not configured (empty response).
        403 → logging_enabled=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_logging, Bucket=bucket_name
            )
            logging_cfg = response.get("LoggingEnabled")
            if logging_cfg:
                return {
                    "logging_enabled":        True,
                    "logging_target_bucket":  logging_cfg.get("TargetBucket"),
                }
            return {
                "logging_enabled":        False,
                "logging_target_bucket":  None,
            }
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append("s3_logging_unavailable")
                return {
                    "logging_enabled":        None,
                    "logging_target_bucket":  None,
                }
            raise

    def _fetch_bucket_lifecycle(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch lifecycle rule count.

        Returns lifecycle_rule_count=N, or 0 if no rules configured.
        403 → lifecycle_rule_count=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_lifecycle_configuration, Bucket=bucket_name
            )
            rules = response.get("Rules") or []
            return {"lifecycle_rule_count": len(rules)}
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchLifecycleConfiguration" in msg:
                return {"lifecycle_rule_count": 0}
            if exc.status_code == 403:
                warnings.append("s3_lifecycle_unavailable")
                return {"lifecycle_rule_count": None}
            raise

    def _fetch_bucket_tags(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch bucket tag keys (not values — values may be sensitive).

        Returns tag_keys as a sorted list of key strings, or None if no tags.
        403 → tag_keys=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_tagging, Bucket=bucket_name
            )
            tag_set = response.get("TagSet") or []
            keys = sorted(tag["Key"] for tag in tag_set if "Key" in tag)
            return {"tag_keys": keys if keys else None}
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchTagSet" in msg:
                return {"tag_keys": None}
            if exc.status_code == 403:
                warnings.append("s3_tagging_unavailable")
                return {"tag_keys": None}
            raise

    # ── Network resources (M38) ───────────────────────────────────────────────

    def _fetch_network_resources(self, credentials: dict) -> list[dict]:
        """Fetch security groups and VPC network resources across selected regions.

        Returns a flat list of records covering all selected regions:
        - aws_security_group / aws_security_group_rule (M38)
        - aws_vpc / aws_subnet / aws_route_table
        - aws_internet_gateway / aws_network_acl

        Fail-soft design:
        - If creating an EC2 client for a region fails, that region is skipped.
        - Per-API failures within a region (e.g. DescribeSecurityGroups 403)
          are caught individually so other APIs in the same region still run.
        - Unexpected exceptions per API are also caught and logged.

        SECURITY: No write operations.  No resource mutations.  Credentials
        are only forwarded to _make_client; they are never placed in records.
        """
        regions = self._selected_regions(credentials)
        records: list[dict] = []

        for region in regions:
            try:
                client = self._make_client("ec2", credentials, region=region)
            except Exception:
                logger.warning(
                    "aws.network: failed to create EC2 client for region %s — skipping",
                    region,
                    exc_info=True,
                )
                continue

            for fetch_fn, api_name in [
                (self._fetch_security_groups,  "DescribeSecurityGroups"),
                (self._fetch_vpcs,             "DescribeVpcs"),
                (self._fetch_igws,             "DescribeInternetGateways"),
                (self._fetch_route_tables,     "DescribeRouteTables"),
                (self._fetch_subnets,          "DescribeSubnets"),
                (self._fetch_network_acls,     "DescribeNetworkAcls"),
            ]:
                try:
                    sub_records = fetch_fn(client, region)
                    records.extend(sub_records)
                    logger.debug(
                        "aws.network: %s in %s → %d record(s)",
                        api_name, region, len(sub_records),
                    )
                except ConnectorError as exc:
                    fc = classify_aws_ec2_failure(api_name, exc)
                    if exc.status_code == 403:
                        logger.info(
                            "aws: %s [%s] not permitted in %s — %s",
                            api_name, fc.error_code, region, fc.recommended_action,
                        )
                    else:
                        logger.warning(
                            "aws: %s [%s] failed in %s — %s",
                            api_name, fc.error_code, region, fc.recommended_action,
                            exc_info=True,
                        )
                except Exception as exc:
                    fc = classify_aws_ec2_failure(api_name, exc)
                    logger.warning(
                        "aws: %s [%s] unexpected error in %s — skipping",
                        api_name, fc.error_code, region,
                        exc_info=True,
                    )

        return records

    # ── Security groups ───────────────────────────────────────────────────────

    def _make_sg_rule(
        self,
        group_id: str,
        region: str,
        direction: str,
        protocol: str,
        from_port: int | None,
        to_port: int | None,
        cidr: str,
        description: str,
    ) -> dict:
        """Build one aws_security_group_rule record.

        The ``record_id`` encodes the structural properties of the rule so it
        is stable across syncs.  Description is NOT part of the stable ID —
        description changes are tracked as field-level modifications, not
        remove+add events.

        CIDR is one of:
        - IPv4 CIDR string (e.g. "0.0.0.0/0", "10.0.0.0/8")
        - IPv6 CIDR string (e.g. "::/0", "2001:db8::/32")
        - Group reference (e.g. "group:123456789012/sg-abcdef")
        """
        rule_hash = _sg_rule_stable_id(
            region, group_id, direction, protocol, from_port, to_port, cidr
        )
        is_public = _cidr_is_public(cidr)
        port_cat = _port_category(from_port, to_port, protocol)

        # Classify CIDR type
        if cidr.startswith("group:"):
            cidr_ipv4 = None
            cidr_ipv6 = None
            ref_group_id: str | None = cidr[len("group:"):]
        elif ":" in cidr:
            cidr_ipv4 = None
            cidr_ipv6 = cidr
            ref_group_id = None
        else:
            cidr_ipv4 = cidr
            cidr_ipv6 = None
            ref_group_id = None

        # Human-readable name for display / record_identifier
        port_label = (
            "all" if protocol == "-1"
            else str(from_port) if from_port == to_port and from_port is not None
            else f"{from_port}-{to_port}" if from_port is not None
            else "?"
        )
        name = f"{direction} {protocol} {port_label} {cidr}"

        return {
            "record_type":         AWS_SECURITY_GROUP_RULE,
            "record_id":           f"{region}/{group_id}/{rule_hash}",
            "name":                name,
            "rule_hash":           rule_hash,
            "group_id":            group_id,
            "region":              region,
            "direction":           direction,
            "protocol":            protocol,
            "from_port":           from_port,
            "to_port":             to_port,
            "cidr_ipv4":           cidr_ipv4,
            "cidr_ipv6":           cidr_ipv6,
            "referenced_group_id": ref_group_id,
            "is_public":           is_public,
            "port_category":       port_cat,
            "description":         description,
        }

    def _flatten_permission(
        self,
        group_id: str,
        region: str,
        direction: str,
        permission: dict,
    ) -> list[dict]:
        """Flatten a single IpPermission dict into individual rule records.

        One rule record is created per:
        - IPv4 CIDR in IpRanges
        - IPv6 CIDR in Ipv6Ranges
        - Referenced security group in UserIdGroupPairs

        For permissions with no CIDRs or group pairs (unusual edge case),
        an empty list is returned.
        """
        protocol: str = permission.get("IpProtocol") or "-1"
        from_port: int | None = permission.get("FromPort")
        to_port: int | None = permission.get("ToPort")

        rules: list[dict] = []

        # IPv4 CIDRs
        for ip_range in (permission.get("IpRanges") or []):
            cidr = ip_range.get("CidrIp") or ""
            desc = ip_range.get("Description") or ""
            if cidr:
                rules.append(
                    self._make_sg_rule(
                        group_id, region, direction,
                        protocol, from_port, to_port, cidr, desc,
                    )
                )

        # IPv6 CIDRs
        for ip_range in (permission.get("Ipv6Ranges") or []):
            cidr = ip_range.get("CidrIpv6") or ""
            desc = ip_range.get("Description") or ""
            if cidr:
                rules.append(
                    self._make_sg_rule(
                        group_id, region, direction,
                        protocol, from_port, to_port, cidr, desc,
                    )
                )

        # Security group references
        for pair in (permission.get("UserIdGroupPairs") or []):
            ref_gid = pair.get("GroupId") or ""
            ref_uid = pair.get("UserId") or ""
            desc = pair.get("Description") or ""
            if ref_gid:
                cidr = f"group:{ref_uid}/{ref_gid}" if ref_uid else f"group:{ref_gid}"
                rules.append(
                    self._make_sg_rule(
                        group_id, region, direction,
                        protocol, from_port, to_port, cidr, desc,
                    )
                )

        return rules

    def _fetch_security_groups(self, client: Any, region: str) -> list[dict]:
        """Fetch all EC2 security groups in *region* and normalize to records.

        Returns aws_security_group records (one per group) followed by
        aws_security_group_rule records (one per flattened rule).

        Handles pagination via NextToken.

        SECURITY: No write operations.  Group rules are read-only metadata.
        """
        # ── Paginate DescribeSecurityGroups ───────────────────────────────────
        groups: list[dict] = []
        kwargs: dict = {}
        while True:
            response = self._call_aws(client.describe_security_groups, **kwargs)
            groups.extend(response.get("SecurityGroups") or [])
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        sg_records: list[dict] = []
        rule_records: list[dict] = []

        for group in groups:
            group_id: str = group.get("GroupId") or ""
            if not group_id:
                continue

            group_name: str = group.get("GroupName") or ""
            description: str = group.get("Description") or ""
            vpc_id: str | None = group.get("VpcId") or None
            owner_id: str = group.get("OwnerId") or ""
            tag_keys = _extract_tag_keys(group.get("Tags") or [])

            # ── Flatten all inbound rules ─────────────────────────────────────
            inbound_rules: list[dict] = []
            for perm in (group.get("IpPermissions") or []):
                inbound_rules.extend(
                    self._flatten_permission(group_id, region, "ingress", perm)
                )

            # ── Flatten all outbound rules ────────────────────────────────────
            outbound_rules: list[dict] = []
            for perm in (group.get("IpPermissionsEgress") or []):
                outbound_rules.extend(
                    self._flatten_permission(group_id, region, "egress", perm)
                )

            rule_records.extend(inbound_rules)
            rule_records.extend(outbound_rules)

            # ── Compute aggregate posture fields ──────────────────────────────
            # These allow diff tracking at the group level without scanning all
            # individual rule records.
            has_public_inbound = any(
                r["is_public"] for r in inbound_rules
            )
            has_public_ssh = any(
                r["is_public"]
                and _has_port_in_range(22, r["from_port"], r["to_port"], r["protocol"])
                for r in inbound_rules
            )
            has_public_rdp = any(
                r["is_public"]
                and _has_port_in_range(3389, r["from_port"], r["to_port"], r["protocol"])
                for r in inbound_rules
            )
            has_public_database_port = any(
                r["is_public"] and r["port_category"] == "database"
                for r in inbound_rules
            )

            sg_records.append({
                "record_type":             AWS_SECURITY_GROUP,
                "record_id":               f"{region}/{group_id}",
                "name":                    f"{group_name} ({group_id})",
                "group_id":                group_id,
                "group_name":              group_name,
                "description":             description,
                "vpc_id":                  vpc_id,
                "region":                  region,
                "owner_id":                owner_id,
                "inbound_rule_count":      len(inbound_rules),
                "outbound_rule_count":     len(outbound_rules),
                "has_public_inbound":      has_public_inbound,
                "has_public_ssh":          has_public_ssh,
                "has_public_rdp":          has_public_rdp,
                "has_public_database_port": has_public_database_port,
                "tag_keys":                tag_keys,
            })

        # SG records first, then rule records (stable ordering)
        return sg_records + rule_records

    # ── VPCs ──────────────────────────────────────────────────────────────────

    def _fetch_vpcs(self, client: Any, region: str) -> list[dict]:
        """Fetch all VPCs in *region* and normalize.

        Handles pagination via NextToken.
        """
        vpcs: list[dict] = []
        kwargs: dict = {}
        while True:
            response = self._call_aws(client.describe_vpcs, **kwargs)
            vpcs.extend(response.get("Vpcs") or [])
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        records: list[dict] = []
        for vpc in vpcs:
            vpc_id: str = vpc.get("VpcId") or ""
            if not vpc_id:
                continue
            records.append({
                "record_type":       AWS_VPC,
                "record_id":         f"{region}/{vpc_id}",
                "name":              vpc_id,
                "vpc_id":            vpc_id,
                "region":            region,
                "cidr_block":        vpc.get("CidrBlock") or "",
                "state":             vpc.get("State") or "",
                "is_default":        bool(vpc.get("IsDefault")),
                "dhcp_options_id":   vpc.get("DhcpOptionsId") or None,
                "instance_tenancy":  vpc.get("InstanceTenancy") or "default",
                "tag_keys":          _extract_tag_keys(vpc.get("Tags") or []),
            })
        return records

    # ── Internet Gateways ─────────────────────────────────────────────────────

    def _fetch_igws(self, client: Any, region: str) -> list[dict]:
        """Fetch all Internet Gateways in *region* and normalize.

        An IGW is considered "attached" when Attachments contains an entry with
        State "available" or "attached".  attached_vpc_id is the VPC it is
        attached to, or None if detached.

        Handles pagination via NextToken.
        """
        igws: list[dict] = []
        kwargs: dict = {}
        while True:
            response = self._call_aws(client.describe_internet_gateways, **kwargs)
            igws.extend(response.get("InternetGateways") or [])
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        records: list[dict] = []
        for igw in igws:
            igw_id: str = igw.get("InternetGatewayId") or ""
            if not igw_id:
                continue
            attachments = igw.get("Attachments") or []
            # Find the first VPC attachment that is available/attached
            attached_vpc_id: str | None = None
            state: str = "detached"
            for att in attachments:
                att_state = (att.get("State") or "").lower()
                if att_state in ("available", "attached"):
                    attached_vpc_id = att.get("VpcId") or None
                    state = att_state
                    break
                elif att_state:
                    state = att_state

            records.append({
                "record_type":      AWS_INTERNET_GATEWAY,
                "record_id":        f"{region}/{igw_id}",
                "name":             igw_id,
                "igw_id":           igw_id,
                "region":           region,
                "state":            state,
                "attached_vpc_id":  attached_vpc_id,
                "tag_keys":         _extract_tag_keys(igw.get("Tags") or []),
            })
        return records

    # ── Route tables ──────────────────────────────────────────────────────────

    def _fetch_route_tables(self, client: Any, region: str) -> list[dict]:
        """Fetch all route tables in *region* and normalize.

        Key derived field: ``has_igw_route`` — True when any route in this
        table points to an Internet Gateway (GatewayId starts with "igw-").
        This is the primary risk signal for internet-facing routing.

        Handles pagination via NextToken.
        """
        rts: list[dict] = []
        kwargs: dict = {}
        while True:
            response = self._call_aws(client.describe_route_tables, **kwargs)
            rts.extend(response.get("RouteTables") or [])
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        records: list[dict] = []
        for rt in rts:
            rt_id: str = rt.get("RouteTableId") or ""
            if not rt_id:
                continue
            vpc_id: str = rt.get("VpcId") or ""

            # Determine if this is the main route table
            associations = rt.get("Associations") or []
            is_main = any(a.get("Main") for a in associations)

            # Collect associated subnet IDs
            associated_subnet_ids: list[str] = sorted(
                a["SubnetId"]
                for a in associations
                if a.get("SubnetId")
            )

            # Check for IGW route
            routes = rt.get("Routes") or []
            igw_route = next(
                (
                    r for r in routes
                    if (r.get("GatewayId") or "").startswith("igw-")
                    and r.get("State") != "blackhole"
                ),
                None,
            )
            has_igw_route = igw_route is not None
            igw_id: str | None = igw_route["GatewayId"] if igw_route else None

            records.append({
                "record_type":           AWS_ROUTE_TABLE,
                "record_id":             f"{region}/{rt_id}",
                "name":                  rt_id,
                "route_table_id":        rt_id,
                "region":                region,
                "vpc_id":                vpc_id,
                "is_main":               is_main,
                "has_igw_route":         has_igw_route,
                "igw_id":                igw_id,
                "route_count":           len(routes),
                "associated_subnet_ids": associated_subnet_ids,
                "tag_keys":              _extract_tag_keys(rt.get("Tags") or []),
            })
        return records

    # ── Subnets ───────────────────────────────────────────────────────────────

    def _fetch_subnets(self, client: Any, region: str) -> list[dict]:
        """Fetch all subnets in *region* and normalize.

        Key field: ``map_public_ip_on_launch`` — when True, instances launched
        in this subnet automatically receive a public IPv4 address.

        Handles pagination via NextToken.
        """
        subnets: list[dict] = []
        kwargs: dict = {}
        while True:
            response = self._call_aws(client.describe_subnets, **kwargs)
            subnets.extend(response.get("Subnets") or [])
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        records: list[dict] = []
        for subnet in subnets:
            subnet_id: str = subnet.get("SubnetId") or ""
            if not subnet_id:
                continue
            records.append({
                "record_type":              AWS_SUBNET,
                "record_id":               f"{region}/{subnet_id}",
                "name":                    subnet_id,
                "subnet_id":               subnet_id,
                "region":                  region,
                "vpc_id":                  subnet.get("VpcId") or "",
                "cidr_block":              subnet.get("CidrBlock") or "",
                "availability_zone":       subnet.get("AvailabilityZone") or "",
                "state":                   subnet.get("State") or "",
                "available_ip_count":      subnet.get("AvailableIpAddressCount"),
                "map_public_ip_on_launch": bool(subnet.get("MapPublicIpOnLaunch")),
                "is_default":              bool(subnet.get("DefaultForAz")),
                "tag_keys":                _extract_tag_keys(subnet.get("Tags") or []),
            })
        return records

    # ── Network ACLs ──────────────────────────────────────────────────────────

    def _fetch_network_acls(self, client: Any, region: str) -> list[dict]:
        """Fetch all Network ACLs in *region* and normalize.

        Derived fields:
        - ``inbound_allow_all_count``  — # inbound ALLOW entries covering
          0.0.0.0/0 or ::/0 (any protocol)
        - ``outbound_allow_all_count`` — same for outbound entries

        These counts detect NACL configurations that effectively allow all
        internet traffic past the network layer.

        Handles pagination via NextToken.
        """
        acls: list[dict] = []
        kwargs: dict = {}
        while True:
            response = self._call_aws(client.describe_network_acls, **kwargs)
            acls.extend(response.get("NetworkAcls") or [])
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        records: list[dict] = []
        for acl in acls:
            acl_id: str = acl.get("NetworkAclId") or ""
            if not acl_id:
                continue
            entries = acl.get("Entries") or []

            def _is_allow_all(entry: dict, egress: bool) -> bool:
                if bool(entry.get("Egress")) != egress:
                    return False
                if (entry.get("RuleAction") or "").lower() != "allow":
                    return False
                cidr4 = entry.get("CidrBlock") or ""
                cidr6 = entry.get("Ipv6CidrBlock") or ""
                return cidr4 == "0.0.0.0/0" or cidr6 == "::/0"

            inbound_allow_all = sum(1 for e in entries if _is_allow_all(e, egress=False))
            outbound_allow_all = sum(1 for e in entries if _is_allow_all(e, egress=True))

            records.append({
                "record_type":              AWS_NETWORK_ACL,
                "record_id":               f"{region}/{acl_id}",
                "name":                    acl_id,
                "nacl_id":                 acl_id,
                "region":                  region,
                "vpc_id":                  acl.get("VpcId") or "",
                "is_default":              bool(acl.get("IsDefault")),
                "inbound_allow_all_count": inbound_allow_all,
                "outbound_allow_all_count": outbound_allow_all,
                "rule_count":              len(entries),
                "tag_keys":                _extract_tag_keys(acl.get("Tags") or []),
            })
        return records

    # ── IAM fetch methods (M39) ───────────────────────────────────────────────

    def _paginate_iam(self, method: Any, result_key: str, **kwargs: Any) -> list:
        """Paginate an IAM API call using IsTruncated/Marker style.

        IAM uses a different pagination style from EC2/S3 (IsTruncated + Marker
        instead of NextToken). This helper wraps the pattern so sub-methods
        stay clean.

        Args:
            method:     The boto3 IAM client method to call (e.g. client.list_users).
            result_key: The key in the response dict that contains the result list.
            **kwargs:   Additional keyword arguments forwarded to the method.

        Returns:
            A flat list of all items across all pages.
        """
        results: list = []
        while True:
            response = self._call_aws(method, **kwargs)
            results.extend(response.get(result_key) or [])
            if not response.get("IsTruncated"):
                break
            kwargs["Marker"] = response["Marker"]
        return results

    def _fetch_iam_resources(self, credentials: dict, account_id: str) -> list[dict]:
        """Fetch all IAM resources for the account. Fail-soft on 403.

        IAM is a global service — data is fetched once per account using a
        single client pointed at us-east-1. No per-region iteration needed.

        Returns a flat list of IAM records:
        - 0 or 1  × aws_iam_account_summary
        - 0 or N  × aws_iam_user
        - 0 or N  × aws_iam_access_key
        - 0 or N  × aws_iam_group
        - 0 or N  × aws_iam_role
        - 0 or N  × aws_iam_policy
        - 0 or N  × aws_iam_policy_attachment
        - 0 or N  × aws_iam_inline_policy
        - 0 or N  × aws_iam_identity_provider

        SECURITY: Raw policy documents are NEVER stored. Credentials are never
        placed in returned records. No write operations are performed.
        """
        # IAM is global — always use us-east-1 as the signing region.
        try:
            client = self._make_client("iam", credentials, region="us-east-1")
        except Exception:
            logger.warning(
                "aws: failed to create IAM client — skipping IAM monitoring",
                exc_info=True,
            )
            return []

        records: list[dict] = []
        config_fetch_warnings: list[str] = []

        # ── Account summary + password policy ────────────────────────────────
        try:
            summary_record = self._fetch_iam_account_summary(client, account_id)
            if summary_record:
                records.append(summary_record)
        except Exception as exc:
            fc = classify_aws_iam_failure("GetAccountSummary", exc)
            logger.warning(
                "aws: IAM account summary unavailable  error_code=%s",
                fc.error_code,
            )
            config_fetch_warnings.append("iam_account_summary_error")

        # ── Users (with access keys, MFA, policies) ──────────────────────────
        user_records: list[dict] = []
        key_records: list[dict] = []
        user_attachments: list[dict] = []
        user_inlines: list[dict] = []
        try:
            user_records, key_records, user_attachments, user_inlines = (
                self._fetch_iam_users(client, account_id)
            )
            records.extend(user_records)
            records.extend(key_records)
        except Exception as exc:
            fc = classify_aws_iam_failure("ListUsers", exc)
            logger.warning(
                "aws: IAM users unavailable  error_code=%s",
                fc.error_code,
            )
            config_fetch_warnings.append("iam_users_error")

        # ── Groups (with members, policies) ──────────────────────────────────
        group_records: list[dict] = []
        group_attachments: list[dict] = []
        group_inlines: list[dict] = []
        try:
            group_records, group_attachments, group_inlines = (
                self._fetch_iam_groups(client, account_id)
            )
            records.extend(group_records)
        except Exception as exc:
            fc = classify_aws_iam_failure("ListGroups", exc)
            logger.warning(
                "aws: IAM groups unavailable  error_code=%s",
                fc.error_code,
            )
            config_fetch_warnings.append("iam_groups_error")

        # ── Roles (with trust policy, attached/inline policies) ───────────────
        role_records: list[dict] = []
        role_attachments: list[dict] = []
        role_inlines: list[dict] = []
        try:
            role_records, role_attachments, role_inlines = (
                self._fetch_iam_roles(client, account_id)
            )
            records.extend(role_records)
        except Exception as exc:
            fc = classify_aws_iam_failure("ListRoles", exc)
            logger.warning(
                "aws: IAM roles unavailable  error_code=%s",
                fc.error_code,
            )
            config_fetch_warnings.append("iam_roles_error")

        # ── Customer-managed policies ─────────────────────────────────────────
        try:
            policy_records = self._fetch_iam_policies(client, account_id)
            records.extend(policy_records)
        except Exception as exc:
            fc = classify_aws_iam_failure("ListPolicies", exc)
            logger.warning(
                "aws: IAM policies unavailable  error_code=%s",
                fc.error_code,
            )
            config_fetch_warnings.append("iam_policies_error")

        # ── Policy attachments (gathered from user/group/role fetch) ──────────
        all_attachments = user_attachments + group_attachments + role_attachments
        records.extend(all_attachments)

        # ── Inline policies (gathered from user/group/role fetch) ─────────────
        all_inlines = user_inlines + group_inlines + role_inlines
        records.extend(all_inlines)

        # ── OIDC / SAML identity providers ───────────────────────────────────
        try:
            idp_records = self._fetch_iam_identity_providers(client, account_id)
            records.extend(idp_records)
        except Exception as exc:
            fc = classify_aws_iam_failure("ListOpenIDConnectProviders", exc)
            logger.warning(
                "aws: IAM identity providers unavailable  error_code=%s",
                fc.error_code,
            )
            config_fetch_warnings.append("iam_idp_error")

        if config_fetch_warnings:
            logger.info(
                "aws: IAM fetch completed with warnings  warnings=%s",
                config_fetch_warnings,
            )

        logger.debug(
            "aws._fetch_iam_resources: fetched %d IAM record(s)  "
            "users=%d keys=%d groups=%d roles=%d attachments=%d inlines=%d",
            len(records),
            len(user_records),
            len(key_records),
            len(group_records),
            len(role_records),
            len(all_attachments),
            len(all_inlines),
        )
        return records

    def _fetch_iam_account_summary(self, client: Any, account_id: str) -> dict | None:
        """Fetch IAM account summary and password policy.

        Calls GetAccountSummary and GetAccountPasswordPolicy and combines them
        into a single aws_iam_account_summary record.

        Returns None if both calls fail (already logged by caller).
        """
        # ── Account summary ───────────────────────────────────────────────────
        try:
            summary_resp = self._call_aws(client.get_account_summary)
            summary_map: dict = summary_resp.get("SummaryMap") or {}
        except Exception as exc:
            fc = classify_aws_iam_failure("GetAccountSummary", exc)
            logger.warning(
                "aws: GetAccountSummary failed  error_code=%s",
                fc.error_code,
            )
            summary_map = {}

        user_count    = summary_map.get("Users", 0)
        group_count   = summary_map.get("Groups", 0)
        role_count    = summary_map.get("Roles", 0)
        policy_count  = summary_map.get("Policies", 0)
        # AccountMFAEnabled: 0 or 1
        mfa_root      = summary_map.get("AccountMFAEnabled", 0) == 1
        # AccountAccessKeysPresent: 0 or 1
        root_keys     = summary_map.get("AccountAccessKeysPresent", 0) >= 1

        # ── Password policy ───────────────────────────────────────────────────
        password_policy_present = False
        pw_min_length: int | None = None
        pw_req_symbols: bool | None = None
        pw_req_numbers: bool | None = None
        pw_req_upper: bool | None = None
        pw_req_lower: bool | None = None
        pw_max_age: int | None = None
        pw_reuse: int | None = None
        pw_hard_expiry: bool | None = None

        try:
            pp_resp = self._call_aws(client.get_account_password_policy)
            pp = pp_resp.get("PasswordPolicy") or {}
            if pp:
                password_policy_present = True
                pw_min_length  = pp.get("MinimumPasswordLength")
                pw_req_symbols = pp.get("RequireSymbols")
                pw_req_numbers = pp.get("RequireNumbers")
                pw_req_upper   = pp.get("RequireUppercaseCharacters")
                pw_req_lower   = pp.get("RequireLowercaseCharacters")
                pw_max_age     = pp.get("MaxPasswordAge")
                pw_reuse       = pp.get("PasswordReusePrevention")
                pw_hard_expiry = pp.get("HardExpiry")
        except Exception as exc:
            # NoSuchEntity (404) means no policy — that is a valid state.
            try:
                import botocore.exceptions as _bce
                if isinstance(exc.__cause__, _bce.ClientError):
                    code = exc.__cause__.response["Error"]["Code"]
                    if code == "NoSuchEntity":
                        password_policy_present = False
                    else:
                        logger.warning(
                            "aws: GetAccountPasswordPolicy failed  error=%s",
                            code,
                        )
                else:
                    logger.warning(
                        "aws: GetAccountPasswordPolicy failed",
                        exc_info=True,
                    )
            except Exception:
                logger.warning(
                    "aws: GetAccountPasswordPolicy failed",
                    exc_info=True,
                )

        return {
            "record_type":              AWS_IAM_ACCOUNT_SUMMARY,
            "record_id":                f"{account_id}/iam_account_summary",
            "external_id":              f"{account_id}/iam_account_summary",
            "name":                     "IAM Account Summary",
            "user_count":               user_count,
            "group_count":              group_count,
            "role_count":               role_count,
            "policy_count":             policy_count,
            "mfa_enabled_for_root":     mfa_root,
            "root_access_keys_present": root_keys,
            "password_policy_present":  password_policy_present,
            "password_min_length":      pw_min_length,
            "password_requires_symbols": pw_req_symbols,
            "password_requires_numbers": pw_req_numbers,
            "password_requires_uppercase": pw_req_upper,
            "password_requires_lowercase": pw_req_lower,
            "password_max_age":         pw_max_age,
            "password_reuse_prevention": pw_reuse,
            "password_hard_expiry":     pw_hard_expiry,
        }

    def _fetch_iam_users(
        self,
        client: Any,
        account_id: str,
    ) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
        """Fetch all IAM users with access keys, MFA devices, and policies.

        Returns a 4-tuple of:
        - user_records:       list of aws_iam_user dicts
        - key_records:        list of aws_iam_access_key dicts
        - attachment_records: list of aws_iam_policy_attachment dicts (managed)
        - inline_records:     list of aws_iam_inline_policy dicts

        SECURITY: Secret access keys are NEVER fetched or stored. Only the
        access key ID (public identifier, AKIA...) and metadata are stored.
        Inline policy documents are analyzed in memory; only policy_summary
        is stored.
        """
        import urllib.parse

        users = self._paginate_iam(client.list_users, "Users")
        user_records: list[dict] = []
        key_records: list[dict] = []
        attachment_records: list[dict] = []
        inline_records: list[dict] = []

        for user in users:
            username: str = user.get("UserName") or ""
            user_id: str  = user.get("UserId") or ""
            arn: str       = user.get("Arn") or ""
            path: str      = user.get("Path") or "/"
            tags_raw       = user.get("Tags") or []

            if not user_id or not username:
                continue

            # ── Access keys (metadata only — never the secret) ────────────────
            active_keys = 0
            inactive_keys = 0
            last_used_age: int | None = None
            try:
                access_keys = self._paginate_iam(
                    client.list_access_keys, "AccessKeyMetadata",
                    UserName=username,
                )
                for ak in access_keys:
                    ak_id: str    = ak.get("AccessKeyId") or ""
                    ak_status: str = ak.get("Status") or "Inactive"
                    if ak_status == "Active":
                        active_keys += 1
                    else:
                        inactive_keys += 1

                    # Fetch last-used metadata (fail-soft)
                    last_used_svc: str | None = None
                    last_used_region: str | None = None
                    key_age: int | None = None
                    try:
                        lu_resp = self._call_aws(
                            client.get_access_key_last_used, AccessKeyId=ak_id
                        )
                        lu = lu_resp.get("AccessKeyLastUsed") or {}
                        if lu.get("LastUsedDate"):
                            from datetime import datetime, timezone
                            lu_date = lu["LastUsedDate"]
                            if hasattr(lu_date, "tzinfo"):
                                now = datetime.now(timezone.utc)
                                delta = now - lu_date.astimezone(timezone.utc)
                                key_age = delta.days
                                if last_used_age is None or key_age < last_used_age:
                                    last_used_age = key_age
                        last_used_svc    = lu.get("ServiceName") or None
                        last_used_region = lu.get("Region") or None
                    except Exception:
                        pass  # last-used is optional

                    key_records.append({
                        "record_type":      AWS_IAM_ACCESS_KEY,
                        "record_id":        ak_id,
                        "external_id":      ak_id,
                        "name":             ak_id,
                        "access_key_id":    ak_id,
                        "username":         username,
                        "user_id":          user_id,
                        "status":           ak_status,
                        "last_used_age_days": key_age,
                        "last_used_service":  last_used_svc,
                        "last_used_region":   last_used_region,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListAccessKeys", exc)
                logger.warning(
                    "aws: ListAccessKeys failed for user  error_code=%s",
                    fc.error_code,
                )

            # ── MFA devices ───────────────────────────────────────────────────
            mfa_count = 0
            try:
                mfa_devices = self._paginate_iam(
                    client.list_mfa_devices, "MFADevices",
                    UserName=username,
                )
                mfa_count = len(mfa_devices)
            except Exception:
                pass  # MFA count is optional

            # ── Groups for this user ──────────────────────────────────────────
            user_group_count = 0
            try:
                groups_for_user = self._paginate_iam(
                    client.list_groups_for_user, "Groups",
                    UserName=username,
                )
                user_group_count = len(groups_for_user)
            except Exception:
                pass  # group count is optional

            # ── Attached managed policies ─────────────────────────────────────
            attached_count = 0
            try:
                attached = self._paginate_iam(
                    client.list_attached_user_policies, "AttachedPolicies",
                    UserName=username,
                )
                attached_count = len(attached)
                for ap in attached:
                    p_arn  = ap.get("PolicyArn") or ""
                    p_name = ap.get("PolicyName") or p_arn.split("/")[-1]
                    if not p_arn:
                        continue
                    attachment_records.append({
                        "record_type":    AWS_IAM_POLICY_ATTACHMENT,
                        "record_id":      _stable_iam_attachment_id("user", user_id, p_arn),
                        "external_id":    _stable_iam_attachment_id("user", user_id, p_arn),
                        "name":           f"{p_name} → {username}",
                        "principal_type": "user",
                        "principal_id":   user_id,
                        "principal_name": username,
                        "principal_arn":  arn,
                        "policy_arn":     p_arn,
                        "policy_name":    p_name,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListAttachedUserPolicies", exc)
                logger.warning(
                    "aws: ListAttachedUserPolicies failed  error_code=%s",
                    fc.error_code,
                )

            # ── Inline policies ───────────────────────────────────────────────
            inline_count = 0
            try:
                inline_names = self._paginate_iam(
                    client.list_user_policies, "PolicyNames",
                    UserName=username,
                )
                inline_count = len(inline_names)
                for policy_name in inline_names:
                    policy_summary: dict = {}
                    try:
                        gp_resp = self._call_aws(
                            client.get_user_policy,
                            UserName=username,
                            PolicyName=policy_name,
                        )
                        doc_raw = gp_resp.get("PolicyDocument") or "{}"
                        # Policy documents from GetUserPolicy may be URL-encoded
                        if "%" in doc_raw:
                            doc_raw = urllib.parse.unquote(doc_raw)
                        # SECURITY: analyze in memory; never store raw doc
                        policy_summary = _analyze_policy_document(doc_raw, account_id)
                    except Exception:
                        pass  # policy summary is optional

                    inline_records.append({
                        "record_type":    AWS_IAM_INLINE_POLICY,
                        "record_id":      _stable_iam_inline_id("user", user_id, policy_name),
                        "external_id":    _stable_iam_inline_id("user", user_id, policy_name),
                        "name":           f"{policy_name} (inline on {username})",
                        "principal_type": "user",
                        "principal_id":   user_id,
                        "principal_name": username,
                        "principal_arn":  arn,
                        "policy_name":    policy_name,
                        "policy_summary": policy_summary,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListUserPolicies", exc)
                logger.warning(
                    "aws: ListUserPolicies failed  error_code=%s",
                    fc.error_code,
                )

            user_records.append({
                "record_type":          AWS_IAM_USER,
                "record_id":            user_id,
                "external_id":          user_id,
                "name":                 username,
                "username":             username,
                "user_id":              user_id,
                "path":                 path,
                "arn":                  arn,
                "mfa_enabled":          mfa_count > 0,
                "mfa_device_count":     mfa_count,
                "active_key_count":     active_keys,
                "inactive_key_count":   inactive_keys,
                "last_key_used_age_days": last_used_age,
                "group_count":          user_group_count,
                "attached_policy_count": attached_count,
                "inline_policy_count":  inline_count,
                "tag_keys":             _extract_tag_keys(tags_raw),
            })

        return user_records, key_records, attachment_records, inline_records

    def _fetch_iam_groups(
        self,
        client: Any,
        account_id: str,
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Fetch all IAM groups with member counts and policies.

        Returns a 3-tuple of:
        - group_records:      list of aws_iam_group dicts
        - attachment_records: list of aws_iam_policy_attachment dicts
        - inline_records:     list of aws_iam_inline_policy dicts
        """
        import urllib.parse

        groups = self._paginate_iam(client.list_groups, "Groups")
        group_records: list[dict] = []
        attachment_records: list[dict] = []
        inline_records: list[dict] = []

        for group in groups:
            group_name: str = group.get("GroupName") or ""
            group_id: str   = group.get("GroupId") or ""
            arn: str         = group.get("Arn") or ""
            path: str        = group.get("Path") or "/"

            if not group_id or not group_name:
                continue

            # ── Group members ─────────────────────────────────────────────────
            member_count = 0
            try:
                grp_resp = self._call_aws(
                    client.get_group, GroupName=group_name
                )
                members = grp_resp.get("Users") or []
                member_count = len(members)
                # Handle pagination for large groups
                while grp_resp.get("IsTruncated"):
                    grp_resp = self._call_aws(
                        client.get_group,
                        GroupName=group_name,
                        Marker=grp_resp["Marker"],
                    )
                    member_count += len(grp_resp.get("Users") or [])
            except Exception:
                pass  # member count is optional

            # ── Attached managed policies ─────────────────────────────────────
            attached_count = 0
            try:
                attached = self._paginate_iam(
                    client.list_attached_group_policies, "AttachedPolicies",
                    GroupName=group_name,
                )
                attached_count = len(attached)
                for ap in attached:
                    p_arn  = ap.get("PolicyArn") or ""
                    p_name = ap.get("PolicyName") or p_arn.split("/")[-1]
                    if not p_arn:
                        continue
                    attachment_records.append({
                        "record_type":    AWS_IAM_POLICY_ATTACHMENT,
                        "record_id":      _stable_iam_attachment_id("group", group_id, p_arn),
                        "external_id":    _stable_iam_attachment_id("group", group_id, p_arn),
                        "name":           f"{p_name} → {group_name}",
                        "principal_type": "group",
                        "principal_id":   group_id,
                        "principal_name": group_name,
                        "principal_arn":  arn,
                        "policy_arn":     p_arn,
                        "policy_name":    p_name,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListAttachedGroupPolicies", exc)
                logger.warning(
                    "aws: ListAttachedGroupPolicies failed  error_code=%s",
                    fc.error_code,
                )

            # ── Inline policies ───────────────────────────────────────────────
            inline_count = 0
            try:
                inline_names = self._paginate_iam(
                    client.list_group_policies, "PolicyNames",
                    GroupName=group_name,
                )
                inline_count = len(inline_names)
                for policy_name in inline_names:
                    policy_summary: dict = {}
                    try:
                        gp_resp = self._call_aws(
                            client.get_group_policy,
                            GroupName=group_name,
                            PolicyName=policy_name,
                        )
                        doc_raw = gp_resp.get("PolicyDocument") or "{}"
                        if "%" in doc_raw:
                            doc_raw = urllib.parse.unquote(doc_raw)
                        policy_summary = _analyze_policy_document(doc_raw, account_id)
                    except Exception:
                        pass

                    inline_records.append({
                        "record_type":    AWS_IAM_INLINE_POLICY,
                        "record_id":      _stable_iam_inline_id("group", group_id, policy_name),
                        "external_id":    _stable_iam_inline_id("group", group_id, policy_name),
                        "name":           f"{policy_name} (inline on {group_name})",
                        "principal_type": "group",
                        "principal_id":   group_id,
                        "principal_name": group_name,
                        "principal_arn":  arn,
                        "policy_name":    policy_name,
                        "policy_summary": policy_summary,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListGroupPolicies", exc)
                logger.warning(
                    "aws: ListGroupPolicies failed  error_code=%s",
                    fc.error_code,
                )

            group_records.append({
                "record_type":           AWS_IAM_GROUP,
                "record_id":             group_id,
                "external_id":           group_id,
                "name":                  group_name,
                "group_name":            group_name,
                "group_id":              group_id,
                "path":                  path,
                "arn":                   arn,
                "member_count":          member_count,
                "attached_policy_count": attached_count,
                "inline_policy_count":   inline_count,
            })

        return group_records, attachment_records, inline_records

    def _fetch_iam_roles(
        self,
        client: Any,
        account_id: str,
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Fetch all IAM roles with trust policy summary and policies.

        Returns a 3-tuple of:
        - role_records:       list of aws_iam_role dicts
        - attachment_records: list of aws_iam_policy_attachment dicts
        - inline_records:     list of aws_iam_inline_policy dicts

        SECURITY: Trust policy documents are analyzed in memory only; only
        the safe trust_summary dict is stored. Raw documents are never stored.
        Inline policy documents likewise produce only policy_summary.
        """
        import urllib.parse

        roles = self._paginate_iam(client.list_roles, "Roles")
        role_records: list[dict] = []
        attachment_records: list[dict] = []
        inline_records: list[dict] = []

        for role in roles:
            role_name: str = role.get("RoleName") or ""
            role_id: str   = role.get("RoleId") or ""
            arn: str        = role.get("Arn") or ""
            path: str       = role.get("Path") or "/"
            max_session     = role.get("MaxSessionDuration") or 3600
            tags_raw        = role.get("Tags") or []
            trust_doc       = role.get("AssumeRolePolicyDocument") or {}

            if not role_id or not role_name:
                continue

            # ── Trust policy analysis (in memory — never stored raw) ──────────
            trust_summary: dict = {}
            try:
                if isinstance(trust_doc, str):
                    import json
                    if "%" in trust_doc:
                        trust_doc = urllib.parse.unquote(trust_doc)
                    trust_doc = json.loads(trust_doc)
                trust_summary = _analyze_trust_policy(trust_doc, account_id)
            except Exception:
                logger.warning(
                    "aws: failed to analyze trust policy for role %r",
                    role_name,
                    exc_info=True,
                )

            # ── Attached managed policies ─────────────────────────────────────
            attached_count = 0
            try:
                attached = self._paginate_iam(
                    client.list_attached_role_policies, "AttachedPolicies",
                    RoleName=role_name,
                )
                attached_count = len(attached)
                for ap in attached:
                    p_arn  = ap.get("PolicyArn") or ""
                    p_name = ap.get("PolicyName") or p_arn.split("/")[-1]
                    if not p_arn:
                        continue
                    attachment_records.append({
                        "record_type":    AWS_IAM_POLICY_ATTACHMENT,
                        "record_id":      _stable_iam_attachment_id("role", role_id, p_arn),
                        "external_id":    _stable_iam_attachment_id("role", role_id, p_arn),
                        "name":           f"{p_name} → {role_name}",
                        "principal_type": "role",
                        "principal_id":   role_id,
                        "principal_name": role_name,
                        "principal_arn":  arn,
                        "policy_arn":     p_arn,
                        "policy_name":    p_name,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListAttachedRolePolicies", exc)
                logger.warning(
                    "aws: ListAttachedRolePolicies failed  error_code=%s",
                    fc.error_code,
                )

            # ── Inline policies ───────────────────────────────────────────────
            inline_count = 0
            try:
                inline_names = self._paginate_iam(
                    client.list_role_policies, "PolicyNames",
                    RoleName=role_name,
                )
                inline_count = len(inline_names)
                for policy_name in inline_names:
                    policy_summary: dict = {}
                    try:
                        gp_resp = self._call_aws(
                            client.get_role_policy,
                            RoleName=role_name,
                            PolicyName=policy_name,
                        )
                        doc_raw = gp_resp.get("PolicyDocument") or "{}"
                        if "%" in doc_raw:
                            doc_raw = urllib.parse.unquote(doc_raw)
                        policy_summary = _analyze_policy_document(doc_raw, account_id)
                    except Exception:
                        pass

                    inline_records.append({
                        "record_type":    AWS_IAM_INLINE_POLICY,
                        "record_id":      _stable_iam_inline_id("role", role_id, policy_name),
                        "external_id":    _stable_iam_inline_id("role", role_id, policy_name),
                        "name":           f"{policy_name} (inline on {role_name})",
                        "principal_type": "role",
                        "principal_id":   role_id,
                        "principal_name": role_name,
                        "principal_arn":  arn,
                        "policy_name":    policy_name,
                        "policy_summary": policy_summary,
                    })
            except Exception as exc:
                fc = classify_aws_iam_failure("ListRolePolicies", exc)
                logger.warning(
                    "aws: ListRolePolicies failed  error_code=%s",
                    fc.error_code,
                )

            role_records.append({
                "record_type":           AWS_IAM_ROLE,
                "record_id":             role_id,
                "external_id":           role_id,
                "name":                  role_name,
                "role_name":             role_name,
                "role_id":               role_id,
                "path":                  path,
                "arn":                   arn,
                "max_session_duration":  max_session,
                "attached_policy_count": attached_count,
                "inline_policy_count":   inline_count,
                "tag_keys":              _extract_tag_keys(tags_raw),
                "trust_summary":         trust_summary,
            })

        return role_records, attachment_records, inline_records

    def _fetch_iam_policies(self, client: Any, account_id: str) -> list[dict]:
        """Fetch all customer-managed IAM policies with their default version summary.

        Only Scope="Local" (customer-managed) policies are fetched.
        AWS-managed policies are excluded to reduce noise.

        SECURITY: Policy documents are analyzed in memory only; only the
        safe policy_summary dict is stored. Raw documents are never stored.
        """
        import urllib.parse

        policies = self._paginate_iam(
            client.list_policies, "Policies",
            Scope="Local",
            OnlyAttached=False,
        )
        records: list[dict] = []

        for policy in policies:
            policy_name: str = policy.get("PolicyName") or ""
            policy_id: str   = policy.get("PolicyId") or ""
            policy_arn: str  = policy.get("Arn") or ""
            path: str         = policy.get("Path") or "/"
            attachment_count  = policy.get("AttachmentCount") or 0
            is_attachable     = bool(policy.get("IsAttachable", True))
            default_version   = policy.get("DefaultVersionId") or ""
            version_count     = policy.get("PolicyVersionList") or None

            if not policy_id or not policy_arn:
                continue

            # ── Fetch default version document (never stored raw) ─────────────
            policy_summary: dict = {}
            pv_count = 1
            try:
                versions_resp = self._call_aws(
                    client.list_policy_versions, PolicyArn=policy_arn
                )
                versions = versions_resp.get("Versions") or []
                pv_count = len(versions)
                # Fetch the default version document (in memory only)
                if default_version:
                    doc_resp = self._call_aws(
                        client.get_policy_version,
                        PolicyArn=policy_arn,
                        VersionId=default_version,
                    )
                    pv = doc_resp.get("PolicyVersion") or {}
                    doc = pv.get("Document") or "{}"
                    if isinstance(doc, str):
                        if "%" in doc:
                            doc = urllib.parse.unquote(doc)
                    else:
                        import json
                        doc = json.dumps(doc)
                    # SECURITY: analyze in memory; never store raw doc
                    policy_summary = _analyze_policy_document(doc, account_id)
            except Exception as exc:
                fc = classify_aws_iam_failure("GetPolicyVersion", exc)
                logger.warning(
                    "aws: policy version fetch failed  policy=%r  error_code=%s",
                    policy_name,
                    fc.error_code,
                )

            records.append({
                "record_type":      AWS_IAM_POLICY,
                "record_id":        policy_id,
                "external_id":      policy_id,
                "name":             policy_name,
                "policy_name":      policy_name,
                "policy_id":        policy_id,
                "arn":              policy_arn,
                "path":             path,
                "attachment_count": attachment_count,
                "is_attachable":    is_attachable,
                "version_count":    pv_count,
                "policy_summary":   policy_summary,
            })

        return records

    def _fetch_iam_identity_providers(self, client: Any, account_id: str) -> list[dict]:
        """Fetch OIDC and SAML identity providers registered in the account.

        Returns one aws_iam_identity_provider record per OIDC/SAML provider.
        """
        records: list[dict] = []

        # ── OIDC providers ────────────────────────────────────────────────────
        try:
            oidc_resp = self._call_aws(client.list_open_id_connect_providers)
            oidc_list = oidc_resp.get("OpenIDConnectProviderList") or []
            for item in oidc_list:
                arn = item.get("Arn") or ""
                if not arn:
                    continue
                client_count: int | None = None
                thumbprint_count: int | None = None
                try:
                    detail = self._call_aws(
                        client.get_open_id_connect_provider,
                        OpenIDConnectProviderArn=arn,
                    )
                    client_ids = detail.get("ClientIDList") or []
                    thumbprints = detail.get("ThumbprintList") or []
                    client_count = len(client_ids)
                    thumbprint_count = len(thumbprints)
                    # URL is stored in safe form (not a credential)
                    oidc_url: str | None = detail.get("Url") or None
                except Exception:
                    oidc_url = None

                stable_id = _stable_iam_idp_id(arn)
                # Extract a short name from the ARN (last component)
                display_name = arn.split("/")[-1] or arn
                records.append({
                    "record_type":          AWS_IAM_IDENTITY_PROVIDER,
                    "record_id":            stable_id,
                    "external_id":          stable_id,
                    "name":                 display_name,
                    "arn":                  arn,
                    "provider_type":        "oidc",
                    "oidc_url":             oidc_url,
                    "oidc_client_id_count": client_count,
                    "oidc_thumbprint_count": thumbprint_count,
                    "saml_valid_until":     None,
                    "saml_provider_name":   None,
                })
        except Exception as exc:
            fc = classify_aws_iam_failure("ListOpenIDConnectProviders", exc)
            logger.warning(
                "aws: OIDC provider listing failed  error_code=%s",
                fc.error_code,
            )

        # ── SAML providers ────────────────────────────────────────────────────
        try:
            saml_resp = self._call_aws(client.list_saml_providers)
            saml_list = saml_resp.get("SAMLProviderList") or []
            for item in saml_list:
                arn = item.get("Arn") or ""
                if not arn:
                    continue
                valid_until: str | None = None
                try:
                    detail = self._call_aws(
                        client.get_saml_provider,
                        SAMLProviderArn=arn,
                    )
                    vu = detail.get("ValidUntil")
                    if vu and hasattr(vu, "isoformat"):
                        valid_until = vu.isoformat()
                    elif vu:
                        valid_until = str(vu)
                    # SECURITY: SAMLMetadataDocument is NEVER stored
                except Exception:
                    pass

                stable_id = _stable_iam_idp_id(arn)
                # Extract a short name from the ARN (last component)
                display_name = arn.split("/")[-1] or arn
                records.append({
                    "record_type":          AWS_IAM_IDENTITY_PROVIDER,
                    "record_id":            stable_id,
                    "external_id":          stable_id,
                    "name":                 display_name,
                    "arn":                  arn,
                    "provider_type":        "saml",
                    "oidc_url":             None,
                    "oidc_client_id_count": None,
                    "oidc_thumbprint_count": None,
                    "saml_valid_until":     valid_until,
                    "saml_provider_name":   display_name,
                })
        except Exception as exc:
            fc = classify_aws_iam_failure("ListSAMLProviders", exc)
            logger.warning(
                "aws: SAML provider listing failed  error_code=%s",
                fc.error_code,
            )

        return records

    # ── M40: Route53 DNS fetch methods ────────────────────────────────────────

    def _fetch_route53_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch Route53 hosted zones and their resource record sets.

        Route53 is a global service — a single us-east-1 client covers all
        hosted zones regardless of the selected_regions list.

        Fail-soft: if route53:ListHostedZones is denied (403), logs a warning
        and returns an empty list so the rest of the sync still succeeds.

        SECURITY: Raw TXT record values are NEVER stored — only value_hash.
        """
        client = self._make_client("route53", credentials, region="us-east-1")
        try:
            zones = self._fetch_hosted_zones(client, account_id)
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "aws: route53:ListHostedZones not permitted — "
                    "skipping Route53 monitoring for this sync  "
                    "error_code=%s",
                    classify_aws_route53_failure("ListHostedZones", exc).error_code,
                )
                return []
            fc = classify_aws_route53_failure("ListHostedZones", exc)
            logger.warning(
                "aws: Route53 hosted zones unavailable  error_code=%s",
                fc.error_code,
            )
            return []
        except Exception as exc:
            fc = classify_aws_route53_failure("ListHostedZones", exc)
            logger.warning(
                "aws: Route53 listing failed  error_code=%s",
                fc.error_code,
            )
            return []

        records: list[dict] = list(zones)
        for zone in zones:
            zone_id = zone.get("_zone_id") or ""
            zone_name = zone.get("name") or ""
            if not zone_id:
                continue
            try:
                rrs_records = self._fetch_zone_records(
                    client, zone_id, zone_name, account_id
                )
                records.extend(rrs_records)
            except Exception as exc:
                fc = classify_aws_route53_failure("ListResourceRecordSets", exc)
                logger.warning(
                    "aws: Route53 record set listing failed  zone_id=%s  error_code=%s",
                    zone_id,
                    fc.error_code,
                )
                # Mark zone with fetch warning and continue
                zone["config_fetch_warnings"] = (
                    zone.get("config_fetch_warnings") or []
                ) + [f"records_unavailable:{fc.error_code}"]

        # Strip internal helper fields before returning
        for zone in zones:
            zone.pop("_zone_id", None)

        return records

    def _fetch_hosted_zones(self, client: Any, account_id: str) -> list[dict]:
        """Fetch all hosted zones via ListHostedZones (paginated).

        Returns one aws_route53_hosted_zone record per zone.
        """
        records: list[dict] = []
        kwargs: dict[str, Any] = {}

        while True:
            resp = self._call_aws(client.list_hosted_zones, **kwargs)
            zones = resp.get("HostedZones") or []
            for zone in zones:
                zone_id_full: str = zone.get("Id") or ""
                # Strip /hostedzone/ prefix → bare zone ID
                zone_id = zone_id_full.split("/")[-1] if zone_id_full else ""
                if not zone_id:
                    continue
                zone_name: str = (zone.get("Name") or "").rstrip(".")
                config = zone.get("Config") or {}
                private_zone: bool = bool(config.get("PrivateZone", False))
                comment: str | None = config.get("Comment") or None
                rrs_count: int | None = zone.get("ResourceRecordSetCount")

                # Stable record ID: account_id/zone_id (zone IDs are globally unique)
                stable_id = f"{account_id}/{zone_id}"

                records.append({
                    "record_type":               AWS_ROUTE53_HOSTED_ZONE,
                    "record_id":                  stable_id,
                    "external_id":               stable_id,
                    "name":                      zone_name,
                    "zone_id":                   zone_id,
                    "zone_type":                 "private" if private_zone else "public",
                    "private_zone":              private_zone,
                    "resource_record_set_count": rrs_count,
                    "linked_vpc_count":          None,   # not in list response
                    "comment":                   comment,
                    "name_servers":              None,   # fetched separately if needed
                    "tag_keys":                  None,
                    "config_fetch_warnings":     None,
                    # Internal helper — stripped before returning
                    "_zone_id":                  zone_id,
                })

            if resp.get("IsTruncated"):
                kwargs = {"Marker": resp.get("NextMarker", "")}
            else:
                break

        return records

    def _fetch_zone_records(
        self,
        client: Any,
        zone_id: str,
        zone_name: str,
        account_id: str,
    ) -> list[dict]:
        """Fetch resource record sets for a single hosted zone (paginated).

        Returns one aws_route53_record record per resource record set.

        SECURITY: TXT record values are hashed (value_hash); raw values are
        never stored.  For DMARC TXT records, only the p= policy tag is
        extracted and stored (dmarc_policy).
        """
        records: list[dict] = []
        kwargs: dict[str, Any] = {"HostedZoneId": zone_id}

        while True:
            resp = self._call_aws(
                client.list_resource_record_sets,
                **kwargs,
            )
            rrsets = resp.get("ResourceRecordSets") or []
            for rrset in rrsets:
                record_name: str = (rrset.get("Name") or "").rstrip(".")
                record_type: str = rrset.get("Type") or ""
                set_identifier: str | None = rrset.get("SetIdentifier") or None
                ttl: int | None = rrset.get("TTL")

                # Stable ID: account_id/zone_id/name/type[/set_identifier]
                name_norm = record_name.lower().rstrip(".")
                id_parts = [account_id, zone_id, name_norm, record_type.upper()]
                if set_identifier:
                    id_parts.append(set_identifier)
                stable_id = "/".join(id_parts)

                # Routing policy detection
                routing_policy = _detect_routing_policy(rrset)
                weight: int | None = rrset.get("Weight")
                region: str | None = rrset.get("Region")
                failover: str | None = rrset.get("Failover")
                geo_loc = rrset.get("GeoLocation")
                geo_location_summary: str | None = None
                if isinstance(geo_loc, dict):
                    geo_parts = []
                    if geo_loc.get("ContinentCode"):
                        geo_parts.append(f"continent={geo_loc['ContinentCode']}")
                    if geo_loc.get("CountryCode"):
                        geo_parts.append(f"country={geo_loc['CountryCode']}")
                    if geo_loc.get("SubdivisionCode"):
                        geo_parts.append(f"subdivision={geo_loc['SubdivisionCode']}")
                    geo_location_summary = ",".join(geo_parts) or None

                health_check_id: str | None = rrset.get("HealthCheckId") or None

                # Alias vs value records
                alias_target = rrset.get("AliasTarget") or {}
                alias_dns_name: str | None = None
                alias_hz_id: str | None = None
                evaluate_target_health: bool | None = None
                value_hash: str | None = None

                if alias_target:
                    alias_dns_name = (alias_target.get("DNSName") or "").rstrip(".")
                    alias_hz_id = alias_target.get("HostedZoneId") or None
                    evaluate_target_health = alias_target.get("EvaluateTargetHealth")
                else:
                    # Extract raw values (NEVER stored for TXT)
                    raw_values = [
                        rr.get("Value", "")
                        for rr in (rrset.get("ResourceRecords") or [])
                        if rr.get("Value")
                    ]
                    if raw_values:
                        value_hash = _hash_dns_values(raw_values)

                # DMARC policy extraction (TXT records only)
                dmarc_policy: str | None = None
                if record_type == "TXT" and not alias_target:
                    raw_values_for_dmarc = [
                        rr.get("Value", "")
                        for rr in (rrset.get("ResourceRecords") or [])
                        if rr.get("Value")
                    ]
                    if record_name.lower().startswith("_dmarc"):
                        dmarc_policy = _extract_dmarc_policy(raw_values_for_dmarc)

                records.append({
                    "record_type":          AWS_ROUTE53_RECORD,
                    "record_id":            stable_id,
                    "external_id":          stable_id,
                    "name":                 f"{record_type} {record_name}",
                    "zone_id":              zone_id,
                    "zone_name":            zone_name,
                    "record_name":          record_name,
                    "dns_record_type":      record_type,
                    "set_identifier":       set_identifier,
                    "ttl":                  ttl,
                    "value_hash":           value_hash,
                    "alias_target_dns_name": alias_dns_name,
                    "alias_hosted_zone_id":  alias_hz_id,
                    "evaluate_target_health": evaluate_target_health,
                    "routing_policy":       routing_policy,
                    "weight":               weight,
                    "region":               region,
                    "failover":             failover,
                    "geo_location_summary": geo_location_summary,
                    "health_check_id":      health_check_id,
                    "dmarc_policy":         dmarc_policy,
                    "config_fetch_warnings": None,
                })

            if resp.get("IsTruncated"):
                kwargs = {
                    "HostedZoneId":        zone_id,
                    "StartRecordName":     resp.get("NextRecordName", ""),
                    "StartRecordType":     resp.get("NextRecordType", ""),
                }
                if resp.get("NextRecordIdentifier"):
                    kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]
            else:
                break

        return records

    # ── M40: CloudFront CDN fetch methods ─────────────────────────────────────

    def _fetch_cloudfront_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch CloudFront distribution configuration records.

        CloudFront is a global service — a single us-east-1 client covers all
        distributions regardless of the selected_regions list.

        Fail-soft: if cloudfront:ListDistributions is denied (403), logs a
        warning and returns an empty list.

        SECURITY: No distribution content or user data is fetched.
                  Only configuration metadata is stored.
        """
        client = self._make_client("cloudfront", credentials, region="us-east-1")
        try:
            return self._fetch_distributions(client, account_id)
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "aws: cloudfront:ListDistributions not permitted — "
                    "skipping CloudFront monitoring for this sync  "
                    "error_code=%s",
                    classify_aws_cloudfront_failure("ListDistributions", exc).error_code,
                )
                return []
            fc = classify_aws_cloudfront_failure("ListDistributions", exc)
            logger.warning(
                "aws: CloudFront distribution listing failed  error_code=%s",
                fc.error_code,
            )
            return []
        except Exception as exc:
            fc = classify_aws_cloudfront_failure("ListDistributions", exc)
            logger.warning(
                "aws: CloudFront fetch failed  error_code=%s",
                fc.error_code,
            )
            return []

    def _fetch_distributions(self, client: Any, account_id: str) -> list[dict]:
        """Fetch all CloudFront distributions via ListDistributions (paginated).

        Returns one aws_cloudfront_distribution record per distribution.
        """
        records: list[dict] = []
        kwargs: dict[str, Any] = {}

        while True:
            resp = self._call_aws(client.list_distributions, **kwargs)
            dist_list = (resp.get("DistributionList") or {})
            items = dist_list.get("Items") or []

            for item in items:
                dist_id: str = item.get("Id") or ""
                if not dist_id:
                    continue

                domain_name: str = item.get("DomainName") or ""
                enabled: bool = bool(item.get("Enabled", False))
                status: str = item.get("Status") or "unknown"
                last_modified = item.get("LastModifiedTime")

                # Aliases
                aliases_obj = item.get("Aliases") or {}
                aliases: list[str] = aliases_obj.get("Items") or []
                alias_count: int = aliases_obj.get("Quantity") or len(aliases)

                # Origins
                origins_obj = item.get("Origins") or {}
                origin_items = origins_obj.get("Items") or []
                origin_count: int = origins_obj.get("Quantity") or len(origin_items)
                origins_summary: list[dict] = []
                for orig in origin_items[:5]:  # cap at 5 for storage
                    orig_domain = orig.get("DomainName") or ""
                    origins_summary.append({
                        "id":            orig.get("Id") or "",
                        "domain":        orig_domain,
                        "origin_type":   _classify_cf_origin_type(orig_domain),
                        "path":          orig.get("OriginPath") or "",
                    })

                # Default cache behavior
                dcb = item.get("DefaultCacheBehavior") or {}
                viewer_protocol_policy: str = dcb.get("ViewerProtocolPolicy") or "unknown"
                default_cache_behavior_summary: dict = {
                    "viewer_protocol_policy": viewer_protocol_policy,
                    "compress":               dcb.get("Compress", False),
                    "cached_methods":         (
                        (dcb.get("AllowedMethods") or {}).get("CachedMethods", {}).get("Items") or []
                    ),
                }

                # Ordered cache behaviors
                ocb_obj = item.get("CacheBehaviors") or {}
                ocb_items = ocb_obj.get("Items") or []
                ordered_cache_behavior_count: int = ocb_obj.get("Quantity") or len(ocb_items)
                ordered_cache_behaviors_summary: list[dict] = [
                    {
                        "path_pattern":           b.get("PathPattern") or "",
                        "viewer_protocol_policy": b.get("ViewerProtocolPolicy") or "unknown",
                    }
                    for b in ocb_items[:5]  # cap at 5
                ]

                # Viewer certificate
                cert = item.get("ViewerCertificate") or {}
                viewer_certificate_summary: dict = {
                    "cloudfront_default_certificate": cert.get("CloudFrontDefaultCertificate", False),
                    "minimum_protocol_version":       cert.get("MinimumProtocolVersion") or "unknown",
                    "ssl_support_method":             cert.get("SSLSupportMethod") or "unknown",
                    "certificate_source":             cert.get("CertificateSource") or "unknown",
                }

                # WAF
                web_acl_id: str | None = item.get("WebACLId") or None

                # Price class, HTTP version, IPv6
                price_class: str = item.get("PriceClass") or "unknown"
                http_version: str = item.get("HttpVersion") or "unknown"
                ipv6_enabled: bool = bool(item.get("IsIPV6Enabled", False))

                # Default root object
                default_root_object: str | None = item.get("DefaultRootObject") or None

                # Logging (not in summary list — would need GetDistributionConfig)
                # We use what's available in the list response
                logging_enabled: bool | None = None
                logging_bucket_domain: str | None = None

                # Custom error responses
                custom_error_obj = item.get("CustomErrorResponses") or {}
                custom_error_response_count: int = (
                    custom_error_obj.get("Quantity") or
                    len(custom_error_obj.get("Items") or [])
                )

                # Geo restrictions
                restrictions_obj = (item.get("Restrictions") or {}).get("GeoRestriction") or {}
                restrictions_summary: dict | None = None
                if restrictions_obj:
                    restrictions_summary = {
                        "restriction_type": restrictions_obj.get("RestrictionType") or "none",
                        "quantity":         restrictions_obj.get("Quantity") or 0,
                    }

                # Stable ID: account_id/dist_id
                stable_id = f"{account_id}/{dist_id}"

                records.append({
                    "record_type":                    AWS_CLOUDFRONT_DISTRIBUTION,
                    "record_id":                      stable_id,
                    "external_id":                    stable_id,
                    "name":                           domain_name or dist_id,
                    "distribution_id":                dist_id,
                    "domain_name":                    domain_name,
                    "enabled":                        enabled,
                    "status":                         status,
                    "aliases":                        aliases or None,
                    "alias_count":                    alias_count,
                    "default_root_object":            default_root_object,
                    "price_class":                    price_class,
                    "http_version":                   http_version,
                    "ipv6_enabled":                   ipv6_enabled,
                    "web_acl_id":                     web_acl_id,
                    "viewer_certificate_summary":     viewer_certificate_summary,
                    "origin_count":                   origin_count,
                    "origins_summary":                origins_summary or None,
                    "default_cache_behavior_summary": default_cache_behavior_summary,
                    "ordered_cache_behavior_count":   ordered_cache_behavior_count,
                    "ordered_cache_behaviors_summary": ordered_cache_behaviors_summary or None,
                    "logging_enabled":                logging_enabled,
                    "logging_bucket_domain":          logging_bucket_domain,
                    "custom_error_response_count":    custom_error_response_count,
                    "restrictions_summary":           restrictions_summary,
                    "tag_keys":                       None,
                    "config_fetch_warnings":          None,
                })

            if dist_list.get("IsTruncated"):
                kwargs = {"Marker": dist_list.get("NextMarker", "")}
            else:
                break

        return records

    # ── M41: Secrets Manager fetch methods ────────────────────────────────────

    def _fetch_secrets_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch Secrets Manager secret metadata across all selected regions.

        Iterates over each selected region, calling ``_fetch_secrets_in_region``.
        Fail-soft: per-region failures are logged but do not abort the sync.

        SECURITY: GetSecretValue is NEVER called.  Secret values are never
        fetched, stored, logged, or returned in any form.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("secretsmanager", credentials, region=region)
                region_records = self._fetch_secrets_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: secrets fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except ConnectorError as exc:
                fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
                logger.warning(
                    "aws: secrets fetch failed  region=%s  code=%s  action=%s",
                    region, fc.error_code, fc.recommended_action,
                )
            except Exception:
                logger.warning(
                    "aws: secrets fetch failed  region=%s  (unexpected error)",
                    region,
                )

        return all_records

    def _fetch_secrets_in_region(
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize Secrets Manager secrets in a single region.

        Calls:
          - ListSecrets (paginated) — discovers all secrets
          - GetResourcePolicy (per secret, optional) — resource policy metadata
          - ListSecretVersionIds (per secret, optional) — version count signals

        SECURITY:
          - GetSecretValue is NEVER called.
          - Secret values are NEVER fetched, stored, or logged.
          - Raw resource policy JSON is parsed in memory only; never stored.
          - KMS key IDs are hashed; raw ARNs are never stored.
        """
        records: list[dict] = []
        kwargs: dict = {"MaxResults": 100, "SortOrder": "asc"}

        while True:
            try:
                response = self._call_aws(client.list_secrets, **kwargs)
            except ConnectorError as exc:
                fc = classify_aws_secretsmanager_failure("ListSecrets", exc)
                logger.warning(
                    "aws: ListSecrets failed  region=%s  code=%s",
                    region, fc.error_code,
                )
                break

            secret_list = response.get("SecretList") or []
            for secret in secret_list:
                name: str = secret.get("Name") or ""
                arn: str = secret.get("ARN") or ""
                description: str | None = secret.get("Description")
                kms_key_id: str | None = secret.get("KmsKeyId")
                rotation_enabled: bool = bool(secret.get("RotationEnabled", False))
                rotation_lambda_arn: str | None = secret.get("RotationLambdaARN")
                rotation_rules: dict | None = secret.get("RotationRules")
                last_changed_date = secret.get("LastChangedDate")
                last_accessed_date = secret.get("LastAccessedDate")
                created_date = secret.get("CreatedDate")
                deleted_date = secret.get("DeletedDate")
                owning_service: str | None = secret.get("OwningService")
                primary_region: str | None = secret.get("PrimaryRegion")
                replica_statuses: list = secret.get("ReplicationStatus") or []
                tags: list = secret.get("Tags") or []
                tag_keys: list[str] | None = sorted({t["Key"] for t in tags if "Key" in t}) or None

                warnings: list[str] = []

                # Resource policy — optional
                has_resource_policy = False
                policy_summary: dict | None = None
                try:
                    policy_response = self._call_aws(
                        client.get_resource_policy,
                        SecretId=arn,
                    )
                    raw_policy = policy_response.get("ResourcePolicy")
                    if raw_policy:
                        has_resource_policy = True
                        # SECURITY: raw_policy is analyzed in memory; never stored
                        policy_summary = _analyze_secret_resource_policy(
                            raw_policy, account_id
                        )
                except ConnectorError as exc:
                    fc = classify_aws_secretsmanager_failure("GetResourcePolicy", exc)
                    if fc.error_code != "aws_secretsmanager_policy_unavailable":
                        # Access denied — note it
                        warnings.append(f"GetResourcePolicy: {fc.error_code}")
                    # ResourceNotFoundException means no policy — that's fine
                except Exception:
                    warnings.append("GetResourcePolicy: unexpected error")

                # Version IDs — optional, for version count signals
                version_count = 0
                active_version_count = 0
                deprecated_version_count = 0
                try:
                    versions_response = self._call_aws(
                        client.list_secret_version_ids,
                        SecretId=arn,
                        IncludeDeprecated=True,
                    )
                    version_items = versions_response.get("Versions") or []
                    version_count = len(version_items)
                    for v in version_items:
                        stages = v.get("VersionStages") or []
                        if "AWSCURRENT" in stages or "AWSPENDING" in stages:
                            active_version_count += 1
                        elif not stages or stages == ["AWSDEPRECATED"]:
                            deprecated_version_count += 1
                except ConnectorError as exc:
                    fc = classify_aws_secretsmanager_failure(
                        "ListSecretVersionIds", exc
                    )
                    warnings.append(f"ListSecretVersionIds: {fc.error_code}")
                except Exception:
                    warnings.append("ListSecretVersionIds: unexpected error")

                # Date normalization — store as ISO strings, not raw datetime
                def _iso(dt: Any) -> str | None:
                    if dt is None:
                        return None
                    try:
                        return dt.isoformat()
                    except AttributeError:
                        return str(dt)

                stable_id = f"{account_id}/{region}/{name}"

                records.append({
                    "record_type":              AWS_SECRETSMANAGER_SECRET,
                    "record_id":                stable_id,
                    "external_id":              stable_id,
                    "name":                     name,
                    "account_id":               account_id,
                    "region":                   region,
                    "arn":                      arn,
                    "description_present":      bool(description),
                    "kms_key_id_present":       bool(kms_key_id),
                    "kms_key_id_hash":          _hash_kms_key_id(kms_key_id) if kms_key_id else None,
                    "rotation_enabled":         rotation_enabled,
                    "rotation_lambda_arn_present": bool(rotation_lambda_arn),
                    "rotation_rules_summary":   _summarize_rotation_rules(rotation_rules or {}),
                    "last_changed_date":        _iso(last_changed_date),
                    "last_accessed_date":       _iso(last_accessed_date),
                    "created_date":             _iso(created_date),
                    "deleted_date":             _iso(deleted_date),
                    "owning_service":           owning_service,
                    "primary_region":           primary_region,
                    "replica_region_count":     len(replica_statuses),
                    "replica_regions":          [r.get("Region") for r in replica_statuses] or None,
                    "version_count":            version_count,
                    "active_version_count":     active_version_count,
                    "deprecated_version_count": deprecated_version_count,
                    "has_resource_policy":      has_resource_policy,
                    "policy_summary":           policy_summary,
                    "tag_keys":                 tag_keys,
                    "sensitive_name_category":  _classify_secret_name_sensitivity(name),
                    "config_fetch_warnings":    warnings or None,
                })

            next_token = response.get("NextToken")
            if next_token:
                kwargs["NextToken"] = next_token
            else:
                break

        return records

    # ── M41: SSM Parameter Store fetch methods ────────────────────────────────

    def _fetch_ssm_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch SSM Parameter Store metadata across all selected regions.

        Iterates over each selected region, calling ``_fetch_ssm_in_region``.
        Fail-soft: per-region failures are logged but do not abort the sync.

        SECURITY: GetParameter, GetParameters, and GetParameterHistory are
        NEVER called.  Parameter values are never fetched, stored, or logged.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("ssm", credentials, region=region)
                region_records = self._fetch_ssm_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: ssm fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except ConnectorError as exc:
                fc = classify_aws_ssm_failure("DescribeParameters", exc)
                logger.warning(
                    "aws: ssm fetch failed  region=%s  code=%s  action=%s",
                    region, fc.error_code, fc.recommended_action,
                )
            except Exception:
                logger.warning(
                    "aws: ssm fetch failed  region=%s  (unexpected error)",
                    region,
                )

        return all_records

    def _fetch_ssm_in_region(
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize SSM parameters in a single region.

        Calls:
          - DescribeParameters (paginated) — discovers all parameters + metadata
          - ListTagsForResource (per parameter, optional) — tag keys

        SECURITY:
          - GetParameter, GetParameters, and GetParameterHistory are NEVER called.
          - Parameter values are NEVER fetched, stored, or logged.
          - KMS key IDs are hashed; raw ARNs are never stored.
          - LastModifiedUser ARN is summarized, not stored in full.
        """
        records: list[dict] = []
        kwargs: dict = {"MaxResults": 50}

        while True:
            try:
                response = self._call_aws(client.describe_parameters, **kwargs)
            except ConnectorError as exc:
                fc = classify_aws_ssm_failure("DescribeParameters", exc)
                logger.warning(
                    "aws: DescribeParameters failed  region=%s  code=%s",
                    region, fc.error_code,
                )
                break

            param_list = response.get("Parameters") or []
            for param in param_list:
                name: str = param.get("Name") or ""
                param_type: str = param.get("Type") or "String"
                tier: str = param.get("Tier") or "Standard"
                data_type: str = param.get("DataType") or "text"
                key_id: str | None = param.get("KeyId")
                version: int = param.get("Version") or 0
                last_modified_date = param.get("LastModifiedDate")
                last_modified_user: str | None = param.get("LastModifiedUser")
                allowed_pattern: str | None = param.get("AllowedPattern")
                policies: list = param.get("Policies") or []

                warnings: list[str] = []

                # Tags — optional
                tag_keys: list[str] | None = None
                try:
                    tags_response = self._call_aws(
                        client.list_tags_for_resource,
                        ResourceType="Parameter",
                        ResourceId=name,
                    )
                    tag_list = tags_response.get("TagList") or []
                    tag_keys = sorted({t["Key"] for t in tag_list if "Key" in t}) or None
                except ConnectorError as exc:
                    fc = classify_aws_ssm_failure("ListTagsForResource", exc)
                    warnings.append(f"ListTagsForResource: {fc.error_code}")
                except Exception:
                    warnings.append("ListTagsForResource: unexpected error")

                # Path analysis — safe metadata, no value access
                path_parts = name.strip("/").split("/")
                path_depth = len(path_parts)
                # Store only the first two path components as prefix (no values)
                path_prefix = "/" + "/".join(path_parts[:2]) if path_depth > 1 else "/"

                # Date normalization
                def _iso(dt: Any) -> str | None:
                    if dt is None:
                        return None
                    try:
                        return dt.isoformat()
                    except AttributeError:
                        return str(dt)

                stable_id = f"{account_id}/{region}/{name}"

                records.append({
                    "record_type":              AWS_SSM_PARAMETER,
                    "record_id":                stable_id,
                    "external_id":              stable_id,
                    "name":                     name,
                    "account_id":               account_id,
                    "region":                   region,
                    "parameter_type":           param_type,
                    "tier":                     tier,
                    "data_type":                data_type,
                    "key_id_present":           bool(key_id),
                    "key_id_hash":              _hash_kms_key_id(key_id) if key_id else None,
                    "version":                  version,
                    "last_modified_date":       _iso(last_modified_date),
                    "last_modified_user_summary": _summarize_iam_arn(last_modified_user),
                    "allowed_pattern_present":  bool(allowed_pattern),
                    "policy_count":             len(policies),
                    "policies_summary":         _summarize_ssm_policies(policies),
                    "tag_keys":                 tag_keys,
                    "path_depth":               path_depth,
                    "path_prefix":              path_prefix,
                    "sensitive_name_category":  _classify_ssm_name_sensitivity(name),
                    "config_fetch_warnings":    warnings or None,
                })

            next_token = response.get("NextToken")
            if next_token:
                kwargs["NextToken"] = next_token
            else:
                break

        return records

    # ── M42: RDS fetch methods ────────────────────────────────────────────────

    def _fetch_rds_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch RDS database resource metadata across all selected regions.

        Iterates over each selected region, calling ``_fetch_rds_in_region``.
        Fail-soft: per-region failures are logged but do not abort the sync.

        SECURITY:
        - No database connections are made.
        - No database content, passwords, or credentials are read.
        - DownloadDBLogFilePortion and DownloadCompleteDBLogFile are NEVER called.
        - Only metadata-level Describe* APIs are used.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("rds", credentials, region=region)
                region_records = self._fetch_rds_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: rds fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except ConnectorError as exc:
                fc = classify_aws_rds_failure("DescribeDBInstances", exc)
                logger.warning(
                    "aws: rds fetch failed  region=%s  code=%s  action=%s",
                    region, fc.error_code, fc.recommended_action,
                )
            except Exception:
                logger.warning(
                    "aws: rds fetch failed  region=%s  (unexpected error)",
                    region,
                )

        return all_records

    def _fetch_rds_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize RDS resources in a single region.

        Calls (fail-soft per API):
          - DescribeDBInstances (paginated)
          - DescribeDBClusters (paginated)
          - DescribeDBSubnetGroups (paginated)
          - DescribeDBSnapshots (paginated, manual snapshots only)
          - DescribeDBClusterSnapshots (paginated, manual snapshots only)

        SECURITY:
          - No DB connections are made.
          - No passwords, credentials, or database content are accessed.
          - MasterUserPassword is explicitly excluded from pending change summaries.
          - KMS key IDs are hashed; raw ARNs are never stored.
          - DownloadDBLogFilePortion / DownloadCompleteDBLogFile are NEVER called.
        """
        records: list[dict] = []

        def _iso(dt: Any) -> str | None:
            if dt is None:
                return None
            try:
                return dt.isoformat()
            except AttributeError:
                return str(dt)

        # ── DescribeDBInstances ───────────────────────────────────────────────
        try:
            inst_kwargs: dict = {"MaxRecords": 100}
            while True:
                try:
                    response = self._call_aws(client.describe_db_instances, **inst_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_rds_failure("DescribeDBInstances", exc)
                    logger.warning(
                        "aws: DescribeDBInstances failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for db in response.get("DBInstances") or []:
                    db_id: str = db.get("DBInstanceIdentifier") or ""
                    if not db_id:
                        continue

                    engine: str = db.get("Engine") or ""
                    engine_version: str = db.get("EngineVersion") or ""
                    kms_key_id: str | None = db.get("KmsKeyId")
                    performance_insights_kms: str | None = db.get("PerformanceInsightsKMSKeyId")
                    ca_cert: str | None = db.get("CACertificateIdentifier")
                    az: str | None = db.get("AvailabilityZone")
                    multi_az: bool = bool(db.get("MultiAZ", False))
                    secondary_az: str | None = db.get("SecondaryAvailabilityZone")
                    endpoint = db.get("Endpoint") or {}
                    publicly_accessible: bool = bool(db.get("PubliclyAccessible", False))
                    storage_encrypted: bool = bool(db.get("StorageEncrypted", False))
                    iam_auth_enabled: bool = bool(db.get("IAMDatabaseAuthenticationEnabled", False))
                    deletion_protection: bool = bool(db.get("DeletionProtection", False))
                    auto_minor_version_upgrade: bool = bool(db.get("AutoMinorVersionUpgrade", False))
                    copy_tags_to_snapshot: bool = bool(db.get("CopyTagsToSnapshot", False))
                    performance_insights_enabled: bool = bool(db.get("PerformanceInsightsEnabled", False))
                    enhanced_monitoring_interval: int = int(db.get("MonitoringInterval") or 0)
                    backup_retention_period: int = int(db.get("BackupRetentionPeriod") or 0)
                    preferred_backup_window: str | None = db.get("PreferredBackupWindow")
                    preferred_maintenance_window: str | None = db.get("PreferredMaintenanceWindow")
                    db_instance_class: str | None = db.get("DBInstanceClass")
                    db_instance_status: str | None = db.get("DBInstanceStatus")
                    db_name_present: bool = bool(db.get("DBName"))
                    allocated_storage: int = int(db.get("AllocatedStorage") or 0)
                    storage_type: str | None = db.get("StorageType")
                    license_model: str | None = db.get("LicenseModel")
                    read_replica_source: str | None = db.get("ReadReplicaSourceDBInstanceIdentifier")
                    read_replica_identifiers: list = db.get("ReadReplicaDBInstanceIdentifiers") or []
                    cluster_id: str | None = db.get("DBClusterIdentifier")
                    db_subnet_group = db.get("DBSubnetGroup") or {}
                    vpc_id: str | None = db_subnet_group.get("VpcId")
                    db_subnet_group_name: str | None = db_subnet_group.get("DBSubnetGroupName")
                    db_subnet_group_status: str | None = db_subnet_group.get("SubnetGroupStatus")
                    port: int | None = endpoint.get("Port")
                    hosted_zone_id: str | None = endpoint.get("HostedZoneId")
                    tags: list = db.get("TagList") or []
                    tag_keys: list[str] | None = sorted({t["Key"] for t in tags if "Key" in t}) or None
                    sg_ids = _rds_sorted_sg_ids(db.get("VpcSecurityGroups") or [])
                    param_group_names = _rds_sorted_param_group_names(
                        db.get("DBParameterGroups") or []
                    )
                    option_group_names = _rds_sorted_option_group_names(
                        db.get("OptionGroupMemberships") or []
                    )
                    pending_summary = _rds_summarize_pending_modified(
                        db.get("PendingModifiedValues") or {}
                    )
                    latest_restore_time = db.get("LatestRestorableTime")
                    processor_features: list = db.get("ProcessorFeatures") or []

                    stable_id = f"{account_id}/{region}/{db_id}"
                    records.append({
                        "record_type":                          AWS_RDS_DB_INSTANCE,
                        "record_id":                            stable_id,
                        "external_id":                          stable_id,
                        "name":                                 db_id,
                        "account_id":                           account_id,
                        "region":                               region,
                        "db_instance_identifier":               db_id,
                        "db_instance_class":                    db_instance_class,
                        "db_instance_status":                   db_instance_status,
                        "engine":                               engine,
                        "engine_version":                       engine_version,
                        "engine_major_version":                 _rds_engine_major_version(engine_version),
                        "db_name_present":                      db_name_present,
                        # ── tracked by diff_service ───────────────────────────
                        "allocated_storage":                    allocated_storage,          # was allocated_storage_gib
                        "storage_type":                         storage_type,
                        "storage_encrypted":                    storage_encrypted,
                        "kms_key_id_present":                   bool(kms_key_id),
                        "kms_key_id_hash":                      _hash_kms_key_id(kms_key_id) if kms_key_id else None,
                        "publicly_accessible":                  publicly_accessible,
                        "multi_az":                             multi_az,
                        "availability_zone":                    az,
                        "secondary_availability_zone_present":  bool(secondary_az),         # bool, not raw AZ name
                        "vpc_id":                               vpc_id,
                        "db_subnet_group_name":                 db_subnet_group_name,
                        "db_subnet_group_status":               db_subnet_group_status,
                        "vpc_security_group_ids":               sg_ids or None,
                        "endpoint_port":                        port,
                        "endpoint_hosted_zone_id":              hosted_zone_id,
                        "backup_retention_period":              backup_retention_period,
                        "preferred_backup_window":              preferred_backup_window,
                        "preferred_maintenance_window":         preferred_maintenance_window,
                        "latest_restorable_time":               _iso(latest_restore_time),
                        "auto_minor_version_upgrade":           auto_minor_version_upgrade,
                        "copy_tags_to_snapshot":                copy_tags_to_snapshot,
                        "deletion_protection":                  deletion_protection,
                        "iam_database_authentication_enabled":  iam_auth_enabled,
                        "performance_insights_enabled":         performance_insights_enabled,
                        "performance_insights_kms_key_id_present": bool(performance_insights_kms),  # was performance_insights_kms_key_present
                        "monitoring_interval":                  enhanced_monitoring_interval,       # was enhanced_monitoring_interval
                        "ca_certificate_identifier":            ca_cert,
                        "license_model":                        license_model,
                        "parameter_group_names":                param_group_names or None,          # was db_parameter_group_names
                        "option_group_names":                   option_group_names or None,
                        "read_replica_source_present":          bool(read_replica_source),          # bool presence, not raw ID
                        "read_replica_count":                   len(read_replica_identifiers),
                        "db_cluster_identifier":                cluster_id,
                        "processor_feature_count":              len(processor_features),
                        "pending_modified_values_summary":      pending_summary,
                        "tag_keys":                             tag_keys,
                        "sensitive_name_category":              _classify_rds_name_sensitivity(db_id),
                        "config_fetch_warnings":                None,
                    })

                marker = response.get("Marker")
                if marker:
                    inst_kwargs["Marker"] = marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeDBInstances unexpected error  region=%s",
                region, exc_info=True,
            )

        # ── DescribeDBClusters ────────────────────────────────────────────────
        try:
            cl_kwargs: dict = {"MaxRecords": 100}
            while True:
                try:
                    response = self._call_aws(client.describe_db_clusters, **cl_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_rds_failure("DescribeDBClusters", exc)
                    logger.warning(
                        "aws: DescribeDBClusters failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for cluster in response.get("DBClusters") or []:
                    cluster_id: str = cluster.get("DBClusterIdentifier") or ""
                    if not cluster_id:
                        continue

                    engine: str = cluster.get("Engine") or ""
                    engine_version: str = cluster.get("EngineVersion") or ""
                    engine_mode: str | None = cluster.get("EngineMode")
                    status: str | None = cluster.get("Status")
                    kms_key_id: str | None = cluster.get("KmsKeyId")
                    storage_encrypted: bool = bool(cluster.get("StorageEncrypted", False))
                    iam_auth_enabled: bool = bool(cluster.get("IAMDatabaseAuthenticationEnabled", False))
                    deletion_protection: bool = bool(cluster.get("DeletionProtection", False))
                    multi_az: bool = bool(cluster.get("MultiAZ", False))
                    backup_retention_period: int = int(cluster.get("BackupRetentionPeriod") or 0)
                    preferred_backup_window: str | None = cluster.get("PreferredBackupWindow")
                    preferred_maintenance_window: str | None = cluster.get("PreferredMaintenanceWindow")
                    publicly_accessible: bool = bool(cluster.get("PubliclyAccessible", False))
                    copy_tags_to_snapshot: bool = bool(cluster.get("CopyTagsToSnapshot", False))
                    performance_insights_enabled: bool = bool(cluster.get("PerformanceInsightsEnabled", False))
                    performance_insights_kms: str | None = cluster.get("PerformanceInsightsKMSKeyId")
                    port: int | None = cluster.get("Port")
                    subnet_group_name: str | None = cluster.get("DBSubnetGroup")
                    az_list: list[str] = sorted(cluster.get("AvailabilityZones") or [])
                    member_instances: list = cluster.get("DBClusterMembers") or []
                    db_cluster_members_count: int = len(member_instances)
                    writer_count: int = sum(
                        1 for m in member_instances if m.get("IsClusterWriter")
                    )
                    reader_count: int = db_cluster_members_count - writer_count
                    sg_ids = _rds_sorted_sg_ids(cluster.get("VpcSecurityGroups") or [])
                    vpc_security_group_count: int = len(sg_ids) if sg_ids else 0
                    db_cluster_parameter_group: str | None = cluster.get("DBClusterParameterGroup")
                    custom_endpoints: list = cluster.get("CustomEndpoints") or []
                    cloudwatch_logs_exports: list = cluster.get("EnabledCloudwatchLogsExports") or []
                    tags: list = cluster.get("TagList") or []
                    tag_keys: list[str] | None = sorted({t["Key"] for t in tags if "Key" in t}) or None
                    latest_restore_time = cluster.get("LatestRestorableTime")
                    # data-minimization: presence booleans only — no raw hostnames/names
                    endpoint_present: bool = bool(cluster.get("Endpoint"))
                    reader_endpoint_present: bool = bool(cluster.get("ReaderEndpoint"))
                    hosted_zone_id_present: bool = bool(cluster.get("HostedZoneId"))
                    database_name_present: bool = bool(cluster.get("DatabaseName"))
                    master_username_present: bool = bool(cluster.get("MasterUsername"))

                    stable_id = f"{account_id}/{region}/{cluster_id}"
                    records.append({
                        "record_type":                          AWS_RDS_DB_CLUSTER,
                        "record_id":                            stable_id,
                        "external_id":                          stable_id,
                        "name":                                 cluster_id,
                        "account_id":                           account_id,
                        "region":                               region,
                        "db_cluster_identifier":                cluster_id,
                        "status":                               status,
                        "engine":                               engine,
                        "engine_version":                       engine_version,
                        "engine_major_version":                 _rds_engine_major_version(engine_version),
                        "engine_mode":                          engine_mode,
                        "storage_encrypted":                    storage_encrypted,
                        "kms_key_id_present":                   bool(kms_key_id),
                        "kms_key_id_hash":                      _hash_kms_key_id(kms_key_id) if kms_key_id else None,
                        "backup_retention_period":              backup_retention_period,
                        "preferred_backup_window":              preferred_backup_window,
                        "preferred_maintenance_window":         preferred_maintenance_window,
                        "multi_az":                             multi_az,
                        "availability_zone_count":              len(az_list),
                        "db_cluster_members_count":             db_cluster_members_count,
                        "writer_count":                         writer_count,
                        "reader_count":                         reader_count,
                        "db_subnet_group_name":                 subnet_group_name,
                        "vpc_security_group_ids":               sg_ids or None,
                        "vpc_security_group_count":             vpc_security_group_count,
                        "port":                                 port,
                        "publicly_accessible":                  publicly_accessible,
                        "endpoint_present":                     endpoint_present,
                        "reader_endpoint_present":              reader_endpoint_present,
                        "custom_endpoints_count":               len(custom_endpoints),
                        "hosted_zone_id_present":               hosted_zone_id_present,
                        "database_name_present":                database_name_present,
                        "master_username_present":              master_username_present,
                        "iam_database_authentication_enabled":  iam_auth_enabled,
                        "deletion_protection":                  deletion_protection,
                        "copy_tags_to_snapshot":                copy_tags_to_snapshot,
                        "db_cluster_parameter_group":           db_cluster_parameter_group,
                        "enabled_cloudwatch_logs_exports":      cloudwatch_logs_exports or None,
                        "performance_insights_enabled":         performance_insights_enabled,
                        "performance_insights_kms_key_id_present": bool(performance_insights_kms),
                        "latest_restorable_time":               _iso(latest_restore_time),
                        "tag_keys":                             tag_keys,
                        "sensitive_name_category":              _classify_rds_name_sensitivity(cluster_id),
                        "config_fetch_warnings":                None,
                    })

                marker = response.get("Marker")
                if marker:
                    cl_kwargs["Marker"] = marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeDBClusters unexpected error  region=%s",
                region, exc_info=True,
            )

        # ── DescribeDBSubnetGroups ────────────────────────────────────────────
        try:
            sg_kwargs: dict = {"MaxRecords": 100}
            while True:
                try:
                    response = self._call_aws(client.describe_db_subnet_groups, **sg_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_rds_failure("DescribeDBSubnetGroups", exc)
                    logger.warning(
                        "aws: DescribeDBSubnetGroups failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for sng in response.get("DBSubnetGroups") or []:
                    group_name: str = sng.get("DBSubnetGroupName") or ""
                    if not group_name:
                        continue
                    vpc_id: str | None = sng.get("VpcId")
                    status: str | None = sng.get("SubnetGroupStatus")
                    subnets: list = sng.get("Subnets") or []
                    subnet_ids = sorted(
                        s.get("SubnetIdentifier") or ""
                        for s in subnets if s.get("SubnetIdentifier")
                    )
                    subnet_azs = sorted({
                        (s.get("SubnetAvailabilityZone") or {}).get("Name") or ""
                        for s in subnets
                        if (s.get("SubnetAvailabilityZone") or {}).get("Name")
                    })
                    tags: list = sng.get("TagList") or []
                    tag_keys: list[str] | None = sorted({t["Key"] for t in tags if "Key" in t}) or None

                    stable_id = f"{account_id}/{region}/{group_name}"
                    records.append({
                        "record_type":                  AWS_RDS_DB_SUBNET_GROUP,
                        "record_id":                    stable_id,
                        "external_id":                  stable_id,
                        "name":                         group_name,
                        "account_id":                   account_id,
                        "region":                       region,
                        "vpc_id":                       vpc_id,
                        "subnet_count":                 len(subnets),
                        "subnet_ids":                   subnet_ids or None,
                        "subnet_availability_zones":    subnet_azs or None,
                        "status":                       status,
                        "tag_keys":                     tag_keys,
                        "config_fetch_warnings":        None,
                    })

                marker = response.get("Marker")
                if marker:
                    sg_kwargs["Marker"] = marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeDBSubnetGroups unexpected error  region=%s",
                region, exc_info=True,
            )

        # ── DescribeDBSnapshots (manual only) ─────────────────────────────────
        try:
            snap_kwargs: dict = {"MaxRecords": 100, "SnapshotType": "manual"}
            while True:
                try:
                    response = self._call_aws(client.describe_db_snapshots, **snap_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_rds_failure("DescribeDBSnapshots", exc)
                    logger.warning(
                        "aws: DescribeDBSnapshots failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for snap in response.get("DBSnapshots") or []:
                    snap_id: str = snap.get("DBSnapshotIdentifier") or ""
                    if not snap_id:
                        continue
                    db_instance_id: str | None = snap.get("DBInstanceIdentifier")
                    engine: str = snap.get("Engine") or ""
                    engine_version: str = snap.get("EngineVersion") or ""
                    status: str | None = snap.get("Status")
                    snapshot_type: str | None = snap.get("SnapshotType")
                    storage_encrypted: bool = bool(snap.get("Encrypted", False))
                    kms_key_id: str | None = snap.get("KmsKeyId")
                    publicly_accessible: bool = snapshot_type == "public"
                    allocated_storage: int = int(snap.get("AllocatedStorage") or 0)
                    az: str | None = snap.get("AvailabilityZone")
                    vpc_id: str | None = snap.get("VpcId")
                    license_model: str | None = snap.get("LicenseModel")
                    snapshot_create_time = snap.get("SnapshotCreateTime")
                    instance_create_time = snap.get("InstanceCreateTime")
                    tags: list = snap.get("TagList") or []
                    tag_keys: list[str] | None = sorted({t["Key"] for t in tags if "Key" in t}) or None

                    stable_id = f"{account_id}/{region}/{snap_id}"
                    records.append({
                        "record_type":              AWS_RDS_DB_SNAPSHOT,
                        "record_id":                stable_id,
                        "external_id":              stable_id,
                        "name":                     snap_id,
                        "account_id":               account_id,
                        "region":                   region,
                        "db_snapshot_identifier":   snap_id,
                        "db_instance_identifier":   db_instance_id,
                        "engine":                   engine,
                        "engine_version":           engine_version,
                        "status":                   status,
                        "snapshot_type":            snapshot_type,
                        "storage_encrypted":        storage_encrypted,
                        "kms_key_id_present":       bool(kms_key_id),
                        "kms_key_id_hash":          _hash_kms_key_id(kms_key_id) if kms_key_id else None,
                        "publicly_accessible":      publicly_accessible,
                        "allocated_storage_gib":    allocated_storage,
                        "availability_zone":        az,
                        "vpc_id":                   vpc_id,
                        "license_model":            license_model,
                        "snapshot_create_time":     _iso(snapshot_create_time),
                        "instance_create_time":     _iso(instance_create_time),
                        "tag_keys":                 tag_keys,
                        "config_fetch_warnings":    None,
                    })

                marker = response.get("Marker")
                if marker:
                    snap_kwargs["Marker"] = marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeDBSnapshots unexpected error  region=%s",
                region, exc_info=True,
            )

        # ── DescribeDBClusterSnapshots (manual only) ──────────────────────────
        try:
            csnap_kwargs: dict = {"MaxRecords": 100, "SnapshotType": "manual"}
            while True:
                try:
                    response = self._call_aws(client.describe_db_cluster_snapshots, **csnap_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_rds_failure("DescribeDBClusterSnapshots", exc)
                    logger.warning(
                        "aws: DescribeDBClusterSnapshots failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for snap in response.get("DBClusterSnapshots") or []:
                    snap_id: str = snap.get("DBClusterSnapshotIdentifier") or ""
                    if not snap_id:
                        continue
                    cluster_id: str | None = snap.get("DBClusterIdentifier")
                    engine: str = snap.get("Engine") or ""
                    engine_version: str = snap.get("EngineVersion") or ""
                    status: str | None = snap.get("Status")
                    snapshot_type: str | None = snap.get("SnapshotType")
                    storage_encrypted: bool = bool(snap.get("StorageEncrypted", False))
                    kms_key_id: str | None = snap.get("KmsKeyId")
                    publicly_accessible: bool = snapshot_type == "public"
                    allocated_storage: int = int(snap.get("AllocatedStorage") or 0)
                    vpc_id: str | None = snap.get("VpcId")
                    az_list: list[str] = sorted(snap.get("AvailabilityZones") or [])
                    cluster_create_time = snap.get("ClusterCreateTime")
                    snapshot_create_time = snap.get("SnapshotCreateTime")
                    iam_auth_enabled: bool = bool(snap.get("IAMDatabaseAuthenticationEnabled", False))
                    tags: list = snap.get("TagList") or []
                    tag_keys: list[str] | None = sorted({t["Key"] for t in tags if "Key" in t}) or None

                    stable_id = f"{account_id}/{region}/{snap_id}"
                    records.append({
                        "record_type":                          AWS_RDS_DB_CLUSTER_SNAPSHOT,
                        "record_id":                            stable_id,
                        "external_id":                          stable_id,
                        "name":                                 snap_id,
                        "account_id":                           account_id,
                        "region":                               region,
                        "db_cluster_snapshot_identifier":       snap_id,
                        "db_cluster_identifier":                cluster_id,
                        "engine":                               engine,
                        "engine_version":                       engine_version,
                        "status":                               status,
                        "snapshot_type":                        snapshot_type,
                        "storage_encrypted":                    storage_encrypted,
                        "kms_key_id_present":                   bool(kms_key_id),
                        "kms_key_id_hash":                      _hash_kms_key_id(kms_key_id) if kms_key_id else None,
                        "publicly_accessible":                  publicly_accessible,
                        "allocated_storage_gib":                allocated_storage,
                        "vpc_id":                               vpc_id,
                        "availability_zones":                   az_list or None,
                        "iam_database_authentication_enabled":  iam_auth_enabled,
                        "snapshot_create_time":                 _iso(snapshot_create_time),
                        "cluster_create_time":                  _iso(cluster_create_time),
                        "tag_keys":                             tag_keys,
                        "config_fetch_warnings":                None,
                    })

                marker = response.get("Marker")
                if marker:
                    csnap_kwargs["Marker"] = marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeDBClusterSnapshots unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M43: Lambda fetch methods ─────────────────────────────────────────────

    def _fetch_lambda_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch Lambda metadata across all selected regions.

        SECURITY:
        - lambda:GetFunction is NEVER called (avoids Code.Location signed URLs).
        - lambda:InvokeFunction is NEVER called.
        - Function code and deployment packages are NEVER accessed or stored.
        - Environment variable values are NEVER stored (keys only).
        - Role/KMS/layer/event-source ARNs are hashed, never stored raw.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("lambda", credentials, region=region)
                region_records = self._fetch_lambda_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: lambda fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except ConnectorError as exc:
                fc = classify_aws_lambda_failure("ListFunctions", exc)
                logger.warning(
                    "aws: lambda fetch failed  region=%s  code=%s",
                    region, fc.error_code,
                )
            except Exception:
                logger.warning(
                    "aws: lambda fetch failed  region=%s  (unexpected error)",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_lambda_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize Lambda resources in a single region.

        Calls (fail-soft per API):
          - ListFunctions (paginated) → aws_lambda_function records
          - ListAliases per function → aws_lambda_alias records
          - ListFunctionUrlConfigs per function → aws_lambda_function_url records
          - ListEventSourceMappings → aws_lambda_event_source_mapping records

        SECURITY:
        - GetFunction is NEVER called.
        - InvokeFunction is NEVER called.
        - Function code/packages are NEVER accessed.
        - Environment variable values are NEVER stored.
        - Role, KMS, and layer ARNs are hashed before storage.
        """
        records: list[dict] = []
        # Maps function_name → function_arn for per-function calls below.
        fn_name_to_arn: dict[str, str] = {}

        # ── ListFunctions (paginated) ─────────────────────────────────────────
        try:
            lf_kwargs: dict = {}
            while True:
                try:
                    response = self._call_aws(client.list_functions, **lf_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_lambda_failure("ListFunctions", exc)
                    logger.warning(
                        "aws: ListFunctions failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for fn in response.get("Functions") or []:
                    fn_name: str = fn.get("FunctionName") or ""
                    fn_arn: str = fn.get("FunctionArn") or ""
                    if not fn_name:
                        continue

                    fn_name_to_arn[fn_name] = fn_arn

                    runtime: str = fn.get("Runtime") or ""
                    handler_present: bool = bool(fn.get("Handler"))
                    package_type: str = fn.get("PackageType") or "Zip"
                    architectures: list[str] = sorted(
                        fn.get("Architectures") or ["x86_64"]
                    )
                    memory_size: int | None = fn.get("MemorySize")
                    timeout: int | None = fn.get("Timeout")
                    code_size: int | None = fn.get("CodeSize")
                    last_modified: str | None = fn.get("LastModified")
                    version: str = fn.get("Version") or "$LATEST"

                    # Role ARN — hash only; NEVER store raw
                    role_arn: str = fn.get("Role") or ""
                    role_arn_present: bool = bool(role_arn)
                    role_arn_hash: str | None = _hash_kms_key_id(role_arn) if role_arn else None

                    # KMS key ARN — hash only
                    kms_key_arn: str = fn.get("KMSKeyArn") or ""
                    kms_key_arn_present: bool = bool(kms_key_arn)
                    kms_key_arn_hash: str | None = (
                        _hash_kms_key_id(kms_key_arn) if kms_key_arn else None
                    )

                    # Ephemeral storage
                    eph_storage: dict = fn.get("EphemeralStorage") or {}
                    ephemeral_storage_size: int | None = eph_storage.get("Size")

                    # Environment variables — SECURITY: keys only, NEVER values
                    env_config: dict = fn.get("Environment") or {}
                    env_vars: dict = env_config.get("Variables") or {}
                    env_key_names, env_key_count, env_sensitive_count = (
                        _lambda_env_key_info(env_vars)
                    )

                    # VPC config
                    vpc_config: dict = fn.get("VpcConfig") or {}
                    subnet_ids: list[str] = sorted(
                        vpc_config.get("SubnetIds") or []
                    )
                    sg_ids_lambda: list[str] = sorted(
                        vpc_config.get("SecurityGroupIds") or []
                    )
                    vpc_config_present: bool = bool(subnet_ids or sg_ids_lambda)
                    subnet_count: int = len(subnet_ids)
                    security_group_count: int = len(sg_ids_lambda)

                    # Tracing
                    tracing_config: dict = fn.get("TracingConfig") or {}
                    tracing_mode: str = tracing_config.get("Mode") or "PassThrough"

                    # Dead letter config
                    dlq_config: dict = fn.get("DeadLetterConfig") or {}
                    dlq_arn: str = dlq_config.get("TargetArn") or ""
                    dlq_present: bool = bool(dlq_arn)
                    dlq_type: str | None = _lambda_dlq_type(dlq_arn) if dlq_arn else None

                    # Layers — hash each ARN
                    layers: list = fn.get("Layers") or []
                    layers_count: int = len(layers)
                    layer_arn_hashes: list[str] = [
                        _hash_kms_key_id(la.get("Arn") or "")
                        for la in layers if la.get("Arn")
                    ]

                    # SnapStart
                    snap_start: dict = fn.get("SnapStart") or {}
                    snap_start_apply_on: str | None = snap_start.get("ApplyOn")

                    # Tags — Lambda tags are a plain dict {key: value}; extract key names only.
                    # ListFunctions does not officially return Tags, but handle them if present
                    # (e.g. from mock data, custom SDKs, or future API changes).
                    raw_tags_fn: dict = fn.get("Tags") or {}
                    tag_keys_fn: list[str] | None = sorted(raw_tags_fn.keys()) or None

                    sensitive_category: str = _classify_lambda_name_sensitivity(fn_name)

                    stable_id = f"{account_id}/{region}/{fn_arn}"
                    records.append({
                        "record_type":                      AWS_LAMBDA_FUNCTION,
                        "record_id":                        stable_id,
                        "external_id":                      stable_id,
                        "name":                             fn_name,
                        "account_id":                       account_id,
                        "region":                           region,
                        "function_name":                    fn_name,
                        "function_arn":                     fn_arn,
                        "runtime":                          runtime,
                        "handler_present":                  handler_present,
                        "package_type":                     package_type,
                        "architectures":                    architectures,
                        "memory_size":                      memory_size,
                        "timeout":                          timeout,
                        "ephemeral_storage_size":           ephemeral_storage_size,
                        "code_size":                        code_size,
                        "last_modified":                    last_modified,
                        "version":                          version,
                        "role_arn_present":                 role_arn_present,
                        "role_arn_hash":                    role_arn_hash,
                        "kms_key_arn_present":              kms_key_arn_present,
                        "kms_key_arn_hash":                 kms_key_arn_hash,
                        "environment_key_count":            env_key_count,
                        "environment_key_names":            env_key_names or None,
                        "environment_sensitive_key_count":  env_sensitive_count,
                        "vpc_config_present":               vpc_config_present,
                        "subnet_ids":                       subnet_ids or None,
                        "subnet_count":                     subnet_count,
                        "security_group_ids":               sg_ids_lambda or None,
                        "security_group_count":             security_group_count,
                        "tracing_mode":                     tracing_mode,
                        "dead_letter_target_present":       dlq_present,
                        "dead_letter_target_type":          dlq_type,
                        "layers_count":                     layers_count,
                        "layer_arn_hashes":                 layer_arn_hashes or None,
                        "reserved_concurrent_executions":   fn.get("ReservedConcurrentExecutions"),
                        "snap_start_apply_on":              snap_start_apply_on,
                        "tag_keys":                         tag_keys_fn,
                        "sensitive_name_category":          sensitive_category,
                        "config_fetch_warnings":            None,
                    })

                next_marker = response.get("NextMarker")
                if next_marker:
                    lf_kwargs["Marker"] = next_marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: ListFunctions unexpected error  region=%s",
                region, exc_info=True,
            )

        # ── ListAliases per function ──────────────────────────────────────────
        for fn_name, fn_arn in fn_name_to_arn.items():
            try:
                la_kwargs: dict = {"FunctionName": fn_name}
                while True:
                    try:
                        response = self._call_aws(client.list_aliases, **la_kwargs)
                    except ConnectorError as exc:
                        fc = classify_aws_lambda_failure("ListAliases", exc)
                        logger.warning(
                            "aws: ListAliases failed  region=%s  fn=%s  code=%s",
                            region, fn_name, fc.error_code,
                        )
                        break

                    for alias in response.get("Aliases") or []:
                        alias_name: str = alias.get("Name") or ""
                        if not alias_name:
                            continue
                        alias_arn: str = alias.get("AliasArn") or ""
                        fn_version_alias: str = alias.get("FunctionVersion") or ""
                        routing: dict = alias.get("RoutingConfig") or {}
                        add_versions: dict = routing.get("AdditionalVersionWeights") or {}
                        routing_config_present: bool = bool(add_versions)
                        additional_version_weights_count: int = len(add_versions)
                        additional_version_weights_summary: dict | None = (
                            {
                                "version_count": len(add_versions),
                                "versions": sorted(add_versions.keys())[:5],
                            }
                            if add_versions else None
                        )
                        description_present: bool = bool(alias.get("Description"))

                        alias_stable_id = f"{account_id}/{region}/{alias_arn}"
                        records.append({
                            "record_type":                          AWS_LAMBDA_ALIAS,
                            "record_id":                            alias_stable_id,
                            "external_id":                          alias_stable_id,
                            "name":                                 f"{fn_name}/{alias_name}",
                            "account_id":                           account_id,
                            "region":                               region,
                            "function_name":                        fn_name,
                            "function_arn":                         fn_arn,
                            "alias_name":                           alias_name,
                            "alias_arn":                            alias_arn,
                            "function_version":                     fn_version_alias,
                            "routing_config_present":               routing_config_present,
                            "additional_version_weights_count":     additional_version_weights_count,
                            "additional_version_weights_summary":   additional_version_weights_summary,
                            "description_present":                  description_present,
                            "config_fetch_warnings":                None,
                        })

                    next_marker_alias = response.get("NextMarker")
                    if next_marker_alias:
                        la_kwargs["Marker"] = next_marker_alias
                    else:
                        break
            except Exception:
                logger.warning(
                    "aws: ListAliases unexpected error  region=%s  fn=%s",
                    region, fn_name, exc_info=True,
                )

        # ── ListFunctionUrlConfigs per function ───────────────────────────────
        for fn_name, fn_arn in fn_name_to_arn.items():
            try:
                url_kwargs: dict = {"FunctionName": fn_name}
                while True:
                    try:
                        response = self._call_aws(
                            client.list_function_url_configs, **url_kwargs
                        )
                    except ConnectorError as exc:
                        fc = classify_aws_lambda_failure("ListFunctionUrlConfigs", exc)
                        logger.warning(
                            "aws: ListFunctionUrlConfigs failed  region=%s  fn=%s  code=%s",
                            region, fn_name, fc.error_code,
                        )
                        break

                    for url_cfg in response.get("FunctionUrlConfigs") or []:
                        url_fn_arn: str = url_cfg.get("FunctionArn") or fn_arn
                        fn_url: str = url_cfg.get("FunctionUrl") or ""
                        auth_type_url: str = url_cfg.get("AuthType") or ""
                        invoke_mode: str = url_cfg.get("InvokeMode") or "BUFFERED"

                        # SECURITY: hash the URL, never store raw endpoint
                        fn_url_hash: str | None = (
                            _hash_kms_key_id(fn_url) if fn_url else None
                        )

                        # CORS config — summarize safely
                        cors_cfg: dict = url_cfg.get("Cors") or {}
                        cors_present: bool = bool(cors_cfg)
                        cors_allow_credentials: bool | None = (
                            cors_cfg.get("AllowCredentials") if cors_cfg else None
                        )
                        cors_origins: list = cors_cfg.get("AllowOrigins") or []
                        cors_wildcard_origin_present: bool = any(
                            o == "*" for o in cors_origins
                        )
                        cors_allow_origins_count: int = len(cors_origins)
                        cors_allow_methods: list[str] | None = (
                            sorted(cors_cfg.get("AllowMethods") or []) or None
                        )

                        url_stable_id = f"{account_id}/{region}/{fn_name}/url"
                        records.append({
                            "record_type":                  AWS_LAMBDA_FUNCTION_URL,
                            "record_id":                    url_stable_id,
                            "external_id":                  url_stable_id,
                            "name":                         fn_name,
                            "account_id":                   account_id,
                            "region":                       region,
                            "function_name":                fn_name,
                            "function_arn":                 url_fn_arn,
                            "function_url_hash":            fn_url_hash,
                            "auth_type":                    auth_type_url,
                            "invoke_mode":                  invoke_mode,
                            "cors_present":                 cors_present,
                            "cors_allow_credentials":       cors_allow_credentials,
                            "cors_wildcard_origin_present": cors_wildcard_origin_present,
                            "cors_allow_origins_count":     cors_allow_origins_count,
                            "cors_allow_methods":           cors_allow_methods,
                            "config_fetch_warnings":        None,
                        })

                    next_marker_url = response.get("NextMarker")
                    if next_marker_url:
                        url_kwargs["Marker"] = next_marker_url
                    else:
                        break
            except Exception:
                logger.warning(
                    "aws: ListFunctionUrlConfigs unexpected error  region=%s  fn=%s",
                    region, fn_name, exc_info=True,
                )

        # ── ListEventSourceMappings (all in region) ───────────────────────────
        try:
            esm_kwargs: dict = {}
            while True:
                try:
                    response = self._call_aws(
                        client.list_event_source_mappings, **esm_kwargs
                    )
                except ConnectorError as exc:
                    fc = classify_aws_lambda_failure("ListEventSourceMappings", exc)
                    logger.warning(
                        "aws: ListEventSourceMappings failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for mapping in response.get("EventSourceMappings") or []:
                    esm_uuid: str = mapping.get("UUID") or ""
                    if not esm_uuid:
                        continue

                    esm_fn_arn: str = mapping.get("FunctionArn") or ""
                    esm_fn_name: str = _lambda_function_name_from_arn(esm_fn_arn)

                    # Event source ARN — hash, never store raw
                    event_source_arn: str = mapping.get("EventSourceArn") or ""
                    esm_arn_present: bool = bool(event_source_arn)
                    esm_arn_hash: str | None = (
                        _hash_kms_key_id(event_source_arn) if event_source_arn else None
                    )
                    esm_type: str = _lambda_event_source_type(event_source_arn)

                    esm_state: str = mapping.get("State") or ""
                    esm_enabled: bool = esm_state.upper() not in (
                        "DISABLED", "DISABLING", "DISABLED_WITH_FAILED_CONCURRENT_EXECUTIONS"
                    )

                    batch_size: int | None = mapping.get("BatchSize")
                    max_batch_window: int | None = mapping.get(
                        "MaximumBatchingWindowInSeconds"
                    )
                    starting_position: str | None = mapping.get("StartingPosition")

                    # Filter criteria — presence only, never store raw expressions
                    filter_criteria: dict | None = mapping.get("FilterCriteria")
                    filter_criteria_present: bool = bool(
                        filter_criteria
                        and filter_criteria.get("Filters")
                    )

                    # Destination config — presence only
                    dest_config: dict = mapping.get("DestinationConfig") or {}
                    destination_config_present: bool = bool(
                        dest_config.get("OnSuccess") or dest_config.get("OnFailure")
                    )

                    fn_response_types: list[str] | None = (
                        sorted(mapping.get("FunctionResponseTypes") or []) or None
                    )

                    esm_stable_id = f"{account_id}/{region}/{esm_uuid}"
                    esm_display = (
                        f"{esm_fn_name}/{esm_uuid[:8]}" if esm_fn_name else esm_uuid[:8]
                    )
                    records.append({
                        "record_type":                  AWS_LAMBDA_EVENT_SOURCE_MAPPING,
                        "record_id":                    esm_stable_id,
                        "external_id":                  esm_stable_id,
                        "name":                         esm_display,
                        "account_id":                   account_id,
                        "region":                       region,
                        "uuid":                         esm_uuid,
                        "function_name":                esm_fn_name,
                        "event_source_arn_present":     esm_arn_present,
                        "event_source_arn_hash":        esm_arn_hash,
                        "event_source_type":            esm_type,
                        "state":                        esm_state,
                        "enabled":                      esm_enabled,
                        "batch_size":                   batch_size,
                        "maximum_batching_window_seconds": max_batch_window,
                        "starting_position":            starting_position,
                        "filter_criteria_present":      filter_criteria_present,
                        "destination_config_present":   destination_config_present,
                        "function_response_types":      fn_response_types,
                        "config_fetch_warnings":        None,
                    })

                next_marker_esm = response.get("NextMarker")
                if next_marker_esm:
                    esm_kwargs["Marker"] = next_marker_esm
                else:
                    break
        except Exception:
            logger.warning(
                "aws: ListEventSourceMappings unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M43: API Gateway REST fetch methods ───────────────────────────────────

    def _fetch_apigateway_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch API Gateway REST API metadata across all selected regions.

        SECURITY:
        - No request/response bodies, logs, or API traffic is ever read.
        - Stage variable values are NEVER stored (keys only).
        - Integration URIs are NEVER stored (type counts only).
        - Resource policies are summarized (no raw JSON stored).
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("apigateway", credentials, region=region)
                region_records = self._fetch_apigateway_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: apigateway fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except ConnectorError as exc:
                fc = classify_aws_apigateway_failure("GetRestApis", exc)
                logger.warning(
                    "aws: apigateway fetch failed  region=%s  code=%s",
                    region, fc.error_code,
                )
            except Exception:
                logger.warning(
                    "aws: apigateway fetch failed  region=%s  (unexpected error)",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_apigateway_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize API Gateway REST resources in a single region.

        Calls (fail-soft per API):
          - GetRestApis (paginated)
          - GetAuthorizers per REST API
          - GetResources per REST API (with embedded methods for auth/integration counts)
          - GetStages per REST API

        SECURITY:
        - No request/response bodies or logs are read.
        - Integration URIs are never stored (type counts only).
        - Stage variable values are never stored (keys only).
        - Resource policies are summarized; raw JSON never stored.
        """
        records: list[dict] = []

        try:
            gra_kwargs: dict = {}
            while True:
                try:
                    response = self._call_aws(client.get_rest_apis, **gra_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_apigateway_failure("GetRestApis", exc)
                    logger.warning(
                        "aws: GetRestApis failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for api in response.get("items") or []:
                    api_id: str = api.get("id") or ""
                    if not api_id:
                        continue

                    api_name: str = api.get("name") or ""
                    description_present: bool = bool(api.get("description"))

                    endpoint_config: dict = api.get("endpointConfiguration") or {}
                    endpoint_types: list[str] = sorted(
                        endpoint_config.get("types") or []
                    )

                    disable_execute: bool = bool(
                        api.get("disableExecuteApiEndpoint", False)
                    )
                    min_compression_size: int | None = api.get("minimumCompressionSize")
                    api_key_source: str = api.get("apiKeySource") or "HEADER"
                    binary_media_types: list = api.get("binaryMediaTypes") or []
                    binary_media_types_count: int = len(binary_media_types)

                    # Resource policy — summarize safely, never store raw JSON
                    policy_raw: str | None = api.get("policy")
                    if policy_raw:
                        try:
                            from urllib.parse import unquote
                            policy_raw = unquote(policy_raw)
                        except Exception:
                            pass
                        policy_summary: dict | None = _apigw_policy_summary(
                            policy_raw, account_id
                        )
                    else:
                        policy_summary = None

                    # Tags — keys only
                    tags: dict = api.get("tags") or {}
                    tag_keys_api: list[str] | None = sorted(tags.keys()) or None

                    sensitive_cat: str = _classify_lambda_name_sensitivity(api_name)

                    # ── Get authorizers (fail-soft) ───────────────────────────
                    authorizer_count: int = 0
                    try:
                        auth_resp = self._call_aws(
                            client.get_authorizers, restApiId=api_id
                        )
                        authorizer_count = len(auth_resp.get("items") or [])
                    except Exception:
                        logger.debug(
                            "aws: GetAuthorizers failed  region=%s  api_id=%s",
                            region, api_id,
                        )

                    # ── Get resources + methods (fail-soft) ───────────────────
                    resource_count: int = 0
                    method_count: int = 0
                    unauthenticated_method_count: int = 0
                    integration_type_counts: dict[str, int] = {}
                    try:
                        res_kwargs: dict = {
                            "restApiId": api_id,
                            "embed": ["methods"],
                        }
                        while True:
                            res_resp = self._call_aws(
                                client.get_resources, **res_kwargs
                            )
                            for res in res_resp.get("items") or []:
                                resource_count += 1
                                methods: dict = res.get("resourceMethods") or {}
                                for _mname, mcfg in methods.items():
                                    method_count += 1
                                    auth_type_m: str = (mcfg or {}).get(
                                        "authorizationType", "NONE"
                                    )
                                    if str(auth_type_m).upper() == "NONE":
                                        unauthenticated_method_count += 1
                                    # Integration type — NEVER store URI
                                    integration: dict = (mcfg or {}).get(
                                        "methodIntegration"
                                    ) or {}
                                    int_type: str = (
                                        integration.get("type") or "UNKNOWN"
                                    ).upper()
                                    integration_type_counts[int_type] = (
                                        integration_type_counts.get(int_type, 0) + 1
                                    )
                            position = res_resp.get("position")
                            if position:
                                res_kwargs["position"] = position
                            else:
                                break
                    except Exception:
                        logger.debug(
                            "aws: GetResources failed  region=%s  api_id=%s",
                            region, api_id,
                        )

                    api_stable_id = f"{account_id}/{region}/{api_id}"
                    records.append({
                        "record_type":                  AWS_APIGATEWAY_REST_API,
                        "record_id":                    api_stable_id,
                        "external_id":                  api_stable_id,
                        "name":                         api_name,
                        "account_id":                   account_id,
                        "region":                       region,
                        "api_id":                       api_id,
                        "description_present":          description_present,
                        "endpoint_configuration_types": endpoint_types,
                        "disable_execute_api_endpoint": disable_execute,
                        "minimum_compression_size":     min_compression_size,
                        "api_key_source":               api_key_source,
                        "binary_media_types_count":     binary_media_types_count,
                        "policy_summary":               policy_summary,
                        "authorizer_count":             authorizer_count,
                        "resource_count":               resource_count,
                        "method_count":                 method_count,
                        "unauthenticated_method_count": unauthenticated_method_count,
                        "integration_type_counts":      integration_type_counts or None,
                        "tag_keys":                     tag_keys_api,
                        "sensitive_name_category":      sensitive_cat,
                        "config_fetch_warnings":        None,
                    })

                    # ── Get stages (fail-soft) ────────────────────────────────
                    try:
                        stages_resp = self._call_aws(
                            client.get_stages, restApiId=api_id
                        )
                        for stage in stages_resp.get("item") or []:
                            sn: str = stage.get("stageName") or ""
                            if not sn:
                                continue

                            dep_id: str = stage.get("deploymentId") or ""
                            dep_id_present: bool = bool(dep_id)
                            dep_id_hash: str | None = (
                                _hash_kms_key_id(dep_id) if dep_id else None
                            )

                            cache_enabled: bool = bool(
                                stage.get("cacheClusterEnabled", False)
                            )
                            cache_size: str | None = stage.get("cacheClusterSize")

                            tracing_enabled: bool = bool(
                                stage.get("tracingEnabled", False)
                            )

                            access_log_settings: dict = (
                                stage.get("accessLogSettings") or {}
                            )
                            access_logging_enabled: bool = bool(
                                access_log_settings.get("destinationArn")
                            )

                            method_settings: dict = stage.get("methodSettings") or {}
                            metrics_enabled_count: int = sum(
                                1
                                for ms in method_settings.values()
                                if (ms or {}).get("metricsEnabled", False)
                            )
                            logging_level_counts: dict[str, int] = {}
                            for ms in method_settings.values():
                                lvl: str = (ms or {}).get("loggingLevel") or "OFF"
                                logging_level_counts[lvl] = (
                                    logging_level_counts.get(lvl, 0) + 1
                                )

                            throttling_present: bool = any(
                                (ms or {}).get("throttlingBurstLimit")
                                or (ms or {}).get("throttlingRateLimit")
                                for ms in method_settings.values()
                            )

                            # Stage variables — keys only, NEVER values
                            stage_vars: dict = stage.get("variables") or {}
                            vars_key_count: int = len(stage_vars)
                            vars_key_names: list[str] | None = (
                                sorted(stage_vars.keys()) or None
                            )

                            canary_settings_present: bool = bool(
                                stage.get("canarySettings")
                            )
                            web_acl_arn_present: bool = bool(
                                stage.get("webAclArn")
                            )

                            stage_stable_id = (
                                f"{account_id}/{region}/{api_id}/{sn}"
                            )
                            records.append({
                                "record_type":              AWS_APIGATEWAY_REST_STAGE,
                                "record_id":                stage_stable_id,
                                "external_id":              stage_stable_id,
                                "name":                     f"{api_name}/{sn}",
                                "account_id":               account_id,
                                "region":                   region,
                                "api_id":                   api_id,
                                "stage_name":               sn,
                                "deployment_id_present":    dep_id_present,
                                "deployment_id_hash":       dep_id_hash,
                                "cache_cluster_enabled":    cache_enabled,
                                "cache_cluster_size":       cache_size,
                                "tracing_enabled":          tracing_enabled,
                                "access_logging_enabled":   access_logging_enabled,
                                "metrics_enabled_count":    metrics_enabled_count,
                                "logging_level_summary":    logging_level_counts or None,
                                "throttling_present":       throttling_present,
                                "variables_key_count":      vars_key_count,
                                "variables_key_names":      vars_key_names,
                                "canary_settings_present":  canary_settings_present,
                                "web_acl_arn_present":      web_acl_arn_present,
                                "config_fetch_warnings":    None,
                            })
                    except Exception:
                        logger.debug(
                            "aws: GetStages failed  region=%s  api_id=%s",
                            region, api_id,
                        )

                position = response.get("position")
                if position:
                    gra_kwargs["position"] = position
                else:
                    break
        except Exception:
            logger.warning(
                "aws: GetRestApis unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M43: API Gateway V2 fetch methods ────────────────────────────────────

    def _fetch_apigatewayv2_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch API Gateway V2 (HTTP/WebSocket) metadata across all selected regions.

        SECURITY: Same guarantees as _fetch_apigateway_resources.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("apigatewayv2", credentials, region=region)
                region_records = self._fetch_apigatewayv2_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: apigatewayv2 fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except ConnectorError as exc:
                fc = classify_aws_apigateway_failure("GetApis", exc)
                logger.warning(
                    "aws: apigatewayv2 fetch failed  region=%s  code=%s",
                    region, fc.error_code,
                )
            except Exception:
                logger.warning(
                    "aws: apigatewayv2 fetch failed  region=%s  (unexpected error)",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_apigatewayv2_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize API Gateway V2 resources in a single region.

        Calls (fail-soft per API):
          - GetApis (paginated)
          - GetRoutes per API (unauthenticated route count)
          - GetAuthorizers per API
          - GetIntegrations per API (type count summary only)
          - GetStages per API

        SECURITY:
        - Integration URIs are NEVER stored (type counts only).
        - Stage variable values are NEVER stored (keys only).
        - CORS origins are NEVER stored raw (wildcard detection + count only).
        """
        records: list[dict] = []

        try:
            ga_kwargs: dict = {}
            while True:
                try:
                    response = self._call_aws(client.get_apis, **ga_kwargs)
                except ConnectorError as exc:
                    fc = classify_aws_apigateway_failure("GetApis", exc)
                    logger.warning(
                        "aws: GetApis (v2) failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for api in response.get("Items") or []:
                    api_id_v2: str = api.get("ApiId") or ""
                    if not api_id_v2:
                        continue

                    api_name_v2: str = api.get("Name") or ""
                    protocol_type: str = api.get("ProtocolType") or ""

                    api_endpoint_v2: str = api.get("ApiEndpoint") or ""
                    api_endpoint_present: bool = bool(api_endpoint_v2)

                    rse: str = api.get("RouteSelectionExpression") or ""
                    rse_present: bool = bool(rse)

                    disable_execute_v2: bool = bool(
                        api.get("DisableExecuteApiEndpoint", False)
                    )

                    # CORS — summarize, never store raw origins
                    cors_v2: dict = api.get("CorsConfiguration") or {}
                    cors_present_v2: bool = bool(cors_v2)
                    cors_allow_credentials_v2: bool | None = (
                        cors_v2.get("AllowCredentials") if cors_v2 else None
                    )
                    cors_origins_v2: list = cors_v2.get("AllowOrigins") or []
                    cors_wildcard_v2: bool = any(o == "*" for o in cors_origins_v2)

                    # Tags — keys only
                    tags_v2: dict = api.get("Tags") or {}
                    tag_keys_v2: list[str] | None = sorted(tags_v2.keys()) or None

                    sensitive_cat_v2: str = _classify_lambda_name_sensitivity(
                        api_name_v2
                    )

                    # ── Get routes (fail-soft) ────────────────────────────────
                    route_count: int = 0
                    unauthenticated_route_count: int = 0
                    try:
                        gr_kwargs: dict = {"ApiId": api_id_v2}
                        while True:
                            gr_resp = self._call_aws(
                                client.get_routes, **gr_kwargs
                            )
                            for route in gr_resp.get("Items") or []:
                                route_count += 1
                                auth_type_r: str = (
                                    route.get("AuthorizationType") or "NONE"
                                ).upper()
                                if auth_type_r == "NONE":
                                    unauthenticated_route_count += 1
                            next_token_r = gr_resp.get("NextToken")
                            if next_token_r:
                                gr_kwargs["NextToken"] = next_token_r
                            else:
                                break
                    except Exception:
                        logger.debug(
                            "aws: GetRoutes (v2) failed  region=%s  api_id=%s",
                            region, api_id_v2,
                        )

                    # ── Get authorizers (fail-soft) ───────────────────────────
                    authorizer_count_v2: int = 0
                    try:
                        ga2_resp = self._call_aws(
                            client.get_authorizers, ApiId=api_id_v2
                        )
                        authorizer_count_v2 = len(ga2_resp.get("Items") or [])
                    except Exception:
                        logger.debug(
                            "aws: GetAuthorizers (v2) failed  region=%s  api_id=%s",
                            region, api_id_v2,
                        )

                    # ── Get integrations (fail-soft) — type counts only ───────
                    integration_type_counts_v2: dict[str, int] = {}
                    try:
                        gi_kwargs: dict = {"ApiId": api_id_v2}
                        while True:
                            gi_resp = self._call_aws(
                                client.get_integrations, **gi_kwargs
                            )
                            for intg in gi_resp.get("Items") or []:
                                # NEVER store IntegrationUri — type only
                                it: str = (
                                    intg.get("IntegrationType") or "UNKNOWN"
                                ).upper()
                                integration_type_counts_v2[it] = (
                                    integration_type_counts_v2.get(it, 0) + 1
                                )
                            next_token_i = gi_resp.get("NextToken")
                            if next_token_i:
                                gi_kwargs["NextToken"] = next_token_i
                            else:
                                break
                    except Exception:
                        logger.debug(
                            "aws: GetIntegrations (v2) failed  region=%s  api_id=%s",
                            region, api_id_v2,
                        )

                    api_stable_id_v2 = f"{account_id}/{region}/{api_id_v2}"
                    records.append({
                        "record_type":                      AWS_APIGATEWAYV2_API,
                        "record_id":                        api_stable_id_v2,
                        "external_id":                      api_stable_id_v2,
                        "name":                             api_name_v2,
                        "account_id":                       account_id,
                        "region":                           region,
                        "api_id":                           api_id_v2,
                        "protocol_type":                    protocol_type,
                        "api_endpoint_present":             api_endpoint_present,
                        "route_selection_expression_present": rse_present,
                        "disable_execute_api_endpoint":     disable_execute_v2,
                        "cors_present":                     cors_present_v2,
                        "cors_allow_credentials":           cors_allow_credentials_v2,
                        "cors_wildcard_origin_present":     cors_wildcard_v2,
                        "route_count":                      route_count,
                        "unauthenticated_route_count":      unauthenticated_route_count,
                        "authorizer_count":                 authorizer_count_v2,
                        "integration_type_counts":          integration_type_counts_v2 or None,
                        "tag_keys":                         tag_keys_v2,
                        "sensitive_name_category":          sensitive_cat_v2,
                        "config_fetch_warnings":            None,
                    })

                    # ── Get stages (fail-soft) ────────────────────────────────
                    try:
                        gs_kwargs: dict = {"ApiId": api_id_v2}
                        while True:
                            gs_resp = self._call_aws(
                                client.get_stages, **gs_kwargs
                            )
                            for stage_v2 in gs_resp.get("Items") or []:
                                sn_v2: str = stage_v2.get("StageName") or ""
                                if not sn_v2:
                                    continue

                                dep_id_v2: str = stage_v2.get("DeploymentId") or ""
                                dep_id_present_v2: bool = bool(dep_id_v2)
                                dep_id_hash_v2: str | None = (
                                    _hash_kms_key_id(dep_id_v2) if dep_id_v2 else None
                                )

                                auto_deploy: bool = bool(
                                    stage_v2.get("AutoDeploy", False)
                                )

                                access_log_v2: dict = (
                                    stage_v2.get("AccessLogSettings") or {}
                                )
                                access_logging_enabled_v2: bool = bool(
                                    access_log_v2.get("DestinationArn")
                                )

                                drs: dict = (
                                    stage_v2.get("DefaultRouteSettings") or {}
                                )
                                detailed_metrics_enabled: bool = bool(
                                    drs.get("DetailedMetricsEnabled", False)
                                )
                                drs_summary: dict | None = (
                                    {
                                        "data_trace_enabled": drs.get("DataTraceEnabled"),
                                        "logging_level": drs.get("LoggingLevel"),
                                        "throttling_burst_limit_present": bool(
                                            drs.get("ThrottlingBurstLimit")
                                        ),
                                        "throttling_rate_limit_present": bool(
                                            drs.get("ThrottlingRateLimit")
                                        ),
                                    }
                                    if drs else None
                                )

                                # Stage variables — keys only, NEVER values
                                sv_v2: dict = stage_v2.get("StageVariables") or {}
                                sv_key_count: int = len(sv_v2)
                                sv_key_names: list[str] | None = (
                                    sorted(sv_v2.keys()) or None
                                )

                                stage_stable_id_v2 = (
                                    f"{account_id}/{region}/{api_id_v2}/{sn_v2}"
                                )
                                records.append({
                                    "record_type":                      AWS_APIGATEWAYV2_STAGE,
                                    "record_id":                        stage_stable_id_v2,
                                    "external_id":                      stage_stable_id_v2,
                                    "name":                             f"{api_name_v2}/{sn_v2}",
                                    "account_id":                       account_id,
                                    "region":                           region,
                                    "api_id":                           api_id_v2,
                                    "stage_name":                       sn_v2,
                                    "deployment_id_present":            dep_id_present_v2,
                                    "deployment_id_hash":               dep_id_hash_v2,
                                    "auto_deploy":                      auto_deploy,
                                    "access_logging_enabled":           access_logging_enabled_v2,
                                    "detailed_metrics_enabled":         detailed_metrics_enabled,
                                    "default_route_settings_summary":   drs_summary,
                                    "stage_variables_key_count":        sv_key_count,
                                    "stage_variables_key_names":        sv_key_names,
                                    "config_fetch_warnings":            None,
                                })
                            next_token_s = gs_resp.get("NextToken")
                            if next_token_s:
                                gs_kwargs["NextToken"] = next_token_s
                            else:
                                break
                    except Exception:
                        logger.debug(
                            "aws: GetStages (v2) failed  region=%s  api_id=%s",
                            region, api_id_v2,
                        )

                next_token_api = response.get("NextToken")
                if next_token_api:
                    ga_kwargs["NextToken"] = next_token_api
                else:
                    break
        except Exception:
            logger.warning(
                "aws: GetApis (v2) unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M44: ELBv2 fetch methods ───────────────────────────────────────────────

    def _fetch_elbv2_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch ELBv2 metadata across all selected regions.

        SECURITY:
        - Access log objects are NEVER read.
        - Request/response traffic is NEVER accessed.
        - elasticloadbalancing:RegisterTargets / DeregisterTargets NEVER called.
        - Only configuration metadata is collected.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("elbv2", credentials, region=region)
                region_records = self._fetch_elbv2_in_region(client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: elbv2 fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: elbv2 fetch failed  region=%s  (unexpected error)",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_elbv2_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize ELBv2 resources in a single region.

        Calls (fail-soft per API):
          - DescribeLoadBalancers (paginated) → aws_elbv2_load_balancer records
          - DescribeLoadBalancerAttributes per LB → attribute fields
          - DescribeTags per batch → tag_keys (keys only, never values)
          - DescribeListeners per LB → aws_elbv2_listener records
          - DescribeRules per listener → aws_elbv2_listener_rule records
          - DescribeTargetGroups (paginated) → aws_elbv2_target_group records
          - DescribeTargetGroupAttributes per TG → attribute fields
          - DescribeTargetHealth per TG → healthy/unhealthy counts only

        SECURITY:
        - Access log objects NEVER read.
        - Request/response bodies NEVER accessed.
        - Only metadata counts from DescribeTargetHealth (healthy/unhealthy count).
        """
        records: list[dict] = []
        # Maps lb_arn → lb_name for listener records
        lb_arn_to_name: dict[str, str] = {}

        # ── DescribeLoadBalancers (paginated) ─────────────────────────────────
        try:
            dlb_kwargs: dict = {}
            while True:
                try:
                    response = self._call_aws(client.describe_load_balancers, **dlb_kwargs)
                except Exception as exc:
                    fc = classify_aws_elbv2_failure("DescribeLoadBalancers", exc)
                    logger.warning(
                        "aws: DescribeLoadBalancers failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for lb in response.get("LoadBalancers") or []:
                    lb_arn: str = lb.get("LoadBalancerArn") or ""
                    lb_name: str = lb.get("LoadBalancerName") or ""
                    if not lb_arn:
                        continue

                    lb_arn_to_name[lb_arn] = lb_name

                    lb_type: str = lb.get("Type") or ""
                    scheme: str = lb.get("Scheme") or ""
                    state_code: str = (lb.get("State") or {}).get("Code") or ""
                    dns_name: str = lb.get("DNSName") or ""
                    vpc_id: str = lb.get("VpcId") or ""
                    ip_type: str = lb.get("IpAddressType") or ""
                    hosted_zone_id: str = lb.get("CanonicalHostedZoneId") or ""

                    # AZs + subnets
                    az_list = lb.get("AvailabilityZones") or []
                    az_count: int = len(az_list)
                    subnet_ids: list[str] = sorted(
                        az.get("SubnetId") or "" for az in az_list if az.get("SubnetId")
                    )
                    subnet_count: int = len(subnet_ids)

                    # Security groups (ALBs only; NLBs/GLBs have none)
                    sg_ids: list[str] = sorted(lb.get("SecurityGroups") or [])
                    sg_count: int = len(sg_ids)

                    sensitive_cat = _classify_elb_name_sensitivity(lb_name)

                    # Fetch attributes (fail-soft)
                    attr_data: dict = {}
                    try:
                        attr_resp = self._call_aws(
                            client.describe_load_balancer_attributes,
                            LoadBalancerArn=lb_arn,
                        )
                        attr_data = _summarize_elbv2_attributes(
                            attr_resp.get("Attributes") or []
                        )
                    except Exception as exc:
                        fc = classify_aws_elbv2_failure("DescribeLoadBalancerAttributes", exc)
                        logger.debug(
                            "aws: DescribeLoadBalancerAttributes failed  region=%s  lb=%s  code=%s",
                            region, lb_name, fc.error_code,
                        )

                    # Fetch tags (fail-soft) — keys only, never values
                    tag_keys: list[str] | None = None
                    try:
                        tags_resp = self._call_aws(
                            client.describe_tags,
                            ResourceArns=[lb_arn],
                        )
                        for tag_desc in tags_resp.get("TagDescriptions") or []:
                            if tag_desc.get("ResourceArn") == lb_arn:
                                raw_tags = tag_desc.get("Tags") or []
                                keys = sorted(t["Key"] for t in raw_tags if "Key" in t)
                                tag_keys = keys or None
                    except Exception:
                        pass  # Tags are best-effort

                    stable_id = f"{account_id}/{region}/{lb_arn}"
                    records.append({
                        "record_type":                   AWS_ELBV2_LOAD_BALANCER,
                        "record_id":                     stable_id,
                        "external_id":                   stable_id,
                        "name":                          lb_name,
                        "account_id":                    account_id,
                        "region":                        region,
                        "lb_arn":                        lb_arn,
                        "type":                          lb_type,
                        "scheme":                        scheme,
                        "state":                         state_code,
                        "dns_name_hash":                 _hash_elb_arn(dns_name) if dns_name else None,
                        "hosted_zone_id_present":        bool(hosted_zone_id),
                        "vpc_id":                        vpc_id or None,
                        "availability_zone_count":       az_count,
                        "subnet_ids":                    subnet_ids or None,
                        "subnet_count":                  subnet_count,
                        "security_group_ids":            sg_ids or None,
                        "security_group_count":          sg_count,
                        "ip_address_type":               ip_type or None,
                        "deletion_protection_enabled":   attr_data.get("deletion_protection_enabled"),
                        "access_logs_enabled":           attr_data.get("access_logs_enabled"),
                        "access_logs_bucket_suffix":     attr_data.get("access_logs_bucket_suffix"),
                        "idle_timeout_seconds":          attr_data.get("idle_timeout_seconds"),
                        "routing_http2_enabled":         attr_data.get("routing_http2_enabled"),
                        "desync_mitigation_mode":        attr_data.get("desync_mitigation_mode"),
                        "drop_invalid_header_fields_enabled": attr_data.get("drop_invalid_header_fields_enabled"),
                        "preserve_host_header_enabled":  attr_data.get("preserve_host_header_enabled"),
                        "xff_header_processing_mode":    attr_data.get("xff_header_processing_mode"),
                        "tag_keys":                      tag_keys,
                        "sensitive_name_category":       sensitive_cat,
                        "config_fetch_warnings":         None,
                    })

                next_marker = response.get("NextMarker")
                if next_marker:
                    dlb_kwargs["Marker"] = next_marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeLoadBalancers unexpected error  region=%s",
                region, exc_info=True,
            )

        # ── DescribeListeners + DescribeRules per LB ──────────────────────────
        for lb_arn, lb_name in lb_arn_to_name.items():
            try:
                dl_kwargs: dict = {"LoadBalancerArn": lb_arn}
                while True:
                    try:
                        listener_resp = self._call_aws(
                            client.describe_listeners, **dl_kwargs
                        )
                    except Exception as exc:
                        fc = classify_aws_elbv2_failure("DescribeListeners", exc)
                        logger.debug(
                            "aws: DescribeListeners failed  region=%s  lb=%s  code=%s",
                            region, lb_name, fc.error_code,
                        )
                        break

                    for lst in listener_resp.get("Listeners") or []:
                        lst_arn: str = lst.get("ListenerArn") or ""
                        if not lst_arn:
                            continue

                        port: int | None = lst.get("Port")
                        protocol: str = lst.get("Protocol") or ""
                        ssl_policy: str | None = lst.get("SslPolicy") or None

                        # Certificate count (never store raw cert ARNs)
                        certs = lst.get("Certificates") or []
                        cert_count: int = len(certs)

                        # Summarize default actions
                        default_actions = lst.get("DefaultActions") or []
                        action_summary = _summarize_listener_actions(default_actions)

                        lst_stable_id = f"{account_id}/{region}/{lst_arn}"
                        records.append({
                            "record_type":                   AWS_ELBV2_LISTENER,
                            "record_id":                     lst_stable_id,
                            "external_id":                   lst_stable_id,
                            "name":                          f"{lb_name}:{port or '?'}/{protocol}",
                            "account_id":                    account_id,
                            "region":                        region,
                            "listener_arn":                  lst_arn,
                            "load_balancer_name":            lb_name,
                            "load_balancer_arn_hash":        _hash_elb_arn(lb_arn),
                            "port":                          port,
                            "protocol":                      protocol,
                            "ssl_policy":                    ssl_policy,
                            "certificate_count":             cert_count,
                            "default_action_types":          action_summary["action_types"],
                            "default_target_group_arn_hashes": action_summary["target_group_arn_hashes"],
                            "auth_action_present":           action_summary["auth_action_present"],
                            "redirect_action_present":       action_summary["redirect_action_present"],
                            "fixed_response_action_present": action_summary["fixed_response_action_present"],
                            "config_fetch_warnings":         None,
                        })

                        # Fetch rules for this listener (fail-soft)
                        try:
                            dr_kwargs: dict = {"ListenerArn": lst_arn}
                            while True:
                                rules_resp = self._call_aws(
                                    client.describe_rules, **dr_kwargs
                                )
                                for rule in rules_resp.get("Rules") or []:
                                    rule_arn: str = rule.get("RuleArn") or ""
                                    if not rule_arn:
                                        continue

                                    priority: str = str(rule.get("Priority") or "")
                                    is_default: bool = priority.lower() == "default"

                                    cond_summary = _summarize_listener_rule_conditions(
                                        rule.get("Conditions") or []
                                    )
                                    rule_action_summary = _summarize_listener_actions(
                                        rule.get("Actions") or []
                                    )

                                    rule_stable_id = f"{account_id}/{region}/{rule_arn}"
                                    records.append({
                                        "record_type":                   AWS_ELBV2_LISTENER_RULE,
                                        "record_id":                     rule_stable_id,
                                        "external_id":                   rule_stable_id,
                                        "name":                          f"{lb_name}/{protocol}/rule-{priority}",
                                        "account_id":                    account_id,
                                        "region":                        region,
                                        "rule_arn":                      rule_arn,
                                        "listener_arn_hash":             _hash_elb_arn(lst_arn),
                                        "load_balancer_name":            lb_name,
                                        "priority":                      priority,
                                        "is_default":                    is_default,
                                        "condition_field_counts":        cond_summary["condition_field_counts"],
                                        "host_header_condition_present": cond_summary["host_header_condition_present"],
                                        "path_pattern_condition_present": cond_summary["path_pattern_condition_present"],
                                        "source_ip_condition_present":   cond_summary["source_ip_condition_present"],
                                        "http_header_condition_present": cond_summary["http_header_condition_present"],
                                        "query_string_condition_present": cond_summary["query_string_condition_present"],
                                        "action_types":                  rule_action_summary["action_types"],
                                        "target_group_arn_hashes":       rule_action_summary["target_group_arn_hashes"],
                                        "auth_action_present":           rule_action_summary["auth_action_present"],
                                        "redirect_action_present":       rule_action_summary["redirect_action_present"],
                                        "fixed_response_action_present": rule_action_summary["fixed_response_action_present"],
                                        "config_fetch_warnings":         None,
                                    })

                                next_rules_marker = rules_resp.get("NextMarker")
                                if next_rules_marker:
                                    dr_kwargs["Marker"] = next_rules_marker
                                else:
                                    break
                        except Exception as exc:
                            fc = classify_aws_elbv2_failure("DescribeRules", exc)
                            logger.debug(
                                "aws: DescribeRules failed  region=%s  lb=%s  lst=%s  code=%s",
                                region, lb_name, lst_arn, fc.error_code,
                            )

                    next_lst_marker = listener_resp.get("NextMarker")
                    if next_lst_marker:
                        dl_kwargs["Marker"] = next_lst_marker
                    else:
                        break
            except Exception:
                logger.debug(
                    "aws: Listeners fetch unexpected error  region=%s  lb=%s",
                    region, lb_name, exc_info=True,
                )

        # ── DescribeTargetGroups (paginated) ──────────────────────────────────
        try:
            dtg_kwargs: dict = {}
            while True:
                try:
                    tg_response = self._call_aws(
                        client.describe_target_groups, **dtg_kwargs
                    )
                except Exception as exc:
                    fc = classify_aws_elbv2_failure("DescribeTargetGroups", exc)
                    logger.warning(
                        "aws: DescribeTargetGroups failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for tg in tg_response.get("TargetGroups") or []:
                    tg_arn: str = tg.get("TargetGroupArn") or ""
                    tg_name: str = tg.get("TargetGroupName") or ""
                    if not tg_arn:
                        continue

                    tg_protocol: str = tg.get("Protocol") or ""
                    tg_port: int | None = tg.get("Port")
                    tg_proto_ver: str = tg.get("ProtocolVersion") or ""
                    tg_type: str = tg.get("TargetType") or ""
                    tg_vpc: str = tg.get("VpcId") or ""

                    hc = tg.get("HealthCheckEnabled") if tg.get("HealthCheckEnabled") is not None else True
                    hc_protocol: str = tg.get("HealthCheckProtocol") or ""
                    hc_port: str = tg.get("HealthCheckPort") or ""
                    hc_path: str = tg.get("HealthCheckPath") or ""
                    hc_interval: int | None = tg.get("HealthCheckIntervalSeconds")
                    hc_timeout: int | None = tg.get("HealthCheckTimeoutSeconds")
                    healthy_t: int | None = tg.get("HealthyThresholdCount")
                    unhealthy_t: int | None = tg.get("UnhealthyThresholdCount")

                    # Matcher: only the summary value (e.g. "200-299"), not raw
                    matcher = tg.get("Matcher") or {}
                    matcher_summary: str | None = (
                        matcher.get("HttpCode") or matcher.get("GrpcCode") or None
                    )

                    lb_arns = tg.get("LoadBalancerArns") or []
                    lb_arn_count = len(lb_arns)

                    tg_sensitive_cat = _classify_elb_name_sensitivity(tg_name)

                    # Fetch target group attributes (fail-soft)
                    tg_attr_data: dict = {}
                    try:
                        tga_resp = self._call_aws(
                            client.describe_target_group_attributes,
                            TargetGroupArn=tg_arn,
                        )
                        tg_attr_data = _summarize_target_group_attributes(
                            tga_resp.get("Attributes") or []
                        )
                    except Exception:
                        pass

                    # Fetch target health — count only, no target IDs or IPs
                    target_count: int = 0
                    healthy_count: int = 0
                    unhealthy_count: int = 0
                    try:
                        health_resp = self._call_aws(
                            client.describe_target_health,
                            TargetGroupArn=tg_arn,
                        )
                        health_descs = health_resp.get("TargetHealthDescriptions") or []
                        target_count = len(health_descs)
                        for h in health_descs:
                            state = (h.get("TargetHealth") or {}).get("State") or ""
                            if state == "healthy":
                                healthy_count += 1
                            elif state in ("unhealthy", "draining", "unavailable"):
                                unhealthy_count += 1
                    except Exception as exc:
                        fc = classify_aws_elbv2_failure("DescribeTargetHealth", exc)
                        logger.debug(
                            "aws: DescribeTargetHealth failed  region=%s  tg=%s  code=%s",
                            region, tg_name, fc.error_code,
                        )

                    # Tags (fail-soft)
                    tg_tag_keys: list[str] | None = None
                    try:
                        tg_tags_resp = self._call_aws(
                            client.describe_tags, ResourceArns=[tg_arn]
                        )
                        for td in tg_tags_resp.get("TagDescriptions") or []:
                            if td.get("ResourceArn") == tg_arn:
                                raw = td.get("Tags") or []
                                tg_tag_keys = sorted(t["Key"] for t in raw if "Key" in t) or None
                    except Exception:
                        pass

                    tg_stable_id = f"{account_id}/{region}/{tg_arn}"
                    records.append({
                        "record_type":                  AWS_ELBV2_TARGET_GROUP,
                        "record_id":                    tg_stable_id,
                        "external_id":                  tg_stable_id,
                        "name":                         tg_name,
                        "account_id":                   account_id,
                        "region":                       region,
                        "tg_arn":                       tg_arn,
                        "protocol":                     tg_protocol or None,
                        "port":                         tg_port,
                        "protocol_version":             tg_proto_ver or None,
                        "target_type":                  tg_type or None,
                        "vpc_id":                       tg_vpc or None,
                        "health_check_enabled":         hc,
                        "health_check_protocol":        hc_protocol or None,
                        "health_check_port":            hc_port or None,
                        "health_check_path_present":    bool(hc_path),
                        "health_check_interval_seconds": hc_interval,
                        "health_check_timeout_seconds": hc_timeout,
                        "healthy_threshold_count":      healthy_t,
                        "unhealthy_threshold_count":    unhealthy_t,
                        "matcher_summary":              matcher_summary,
                        "load_balancer_arn_count":      lb_arn_count,
                        "target_count":                 target_count,
                        "healthy_target_count":         healthy_count,
                        "unhealthy_target_count":       unhealthy_count,
                        "deregistration_delay_seconds": tg_attr_data.get("deregistration_delay_seconds"),
                        "stickiness_enabled":           tg_attr_data.get("stickiness_enabled"),
                        "slow_start_duration_seconds":  tg_attr_data.get("slow_start_duration_seconds"),
                        "tag_keys":                     tg_tag_keys,
                        "sensitive_name_category":      tg_sensitive_cat,
                        "config_fetch_warnings":        None,
                    })

                next_tg_marker = tg_response.get("NextMarker")
                if next_tg_marker:
                    dtg_kwargs["Marker"] = next_tg_marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: DescribeTargetGroups unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M44: Classic ELB fetch methods ────────────────────────────────────────

    def _fetch_elb_classic_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch Classic ELB metadata across all selected regions.

        SECURITY:
        - Access log objects are NEVER read.
        - Request/response traffic is NEVER accessed.
        - elasticloadbalancing:RegisterInstancesWithLoadBalancer NEVER called.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                client = self._make_client("elb", credentials, region=region)
                region_records = self._fetch_elb_classic_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: elb_classic fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: elb_classic fetch failed  region=%s  (unexpected error)",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_elb_classic_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize Classic ELB resources in a single region.

        SECURITY:
        - Access log objects NEVER read.
        - Request/response traffic NEVER accessed.
        - DNS name is hashed, never stored raw.
        - Tag values never stored (keys only).
        """
        records: list[dict] = []

        try:
            dlb_kwargs: dict = {}
            while True:
                try:
                    response = self._call_aws(
                        client.describe_load_balancers, **dlb_kwargs
                    )
                except Exception as exc:
                    fc = classify_aws_elb_classic_failure("DescribeLoadBalancers", exc)
                    logger.warning(
                        "aws: Classic DescribeLoadBalancers failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for lb in response.get("LoadBalancerDescriptions") or []:
                    lb_name: str = lb.get("LoadBalancerName") or ""
                    if not lb_name:
                        continue

                    dns_name: str = lb.get("DNSName") or ""
                    scheme: str = lb.get("Scheme") or ""
                    vpc_id: str = lb.get("VPCId") or ""

                    # Subnets + AZs
                    subnet_ids: list[str] = sorted(lb.get("Subnets") or [])
                    az_list = lb.get("AvailabilityZones") or []
                    az_count: int = len(az_list)

                    # Security groups
                    sg_ids: list[str] = sorted(lb.get("SecurityGroups") or [])

                    # Listeners — protocol names only (never port contents)
                    listeners = lb.get("ListenerDescriptions") or []
                    listener_count: int = len(listeners)
                    listener_protocols: list[str] = sorted(set(
                        ld.get("Listener", {}).get("Protocol") or ""
                        for ld in listeners
                        if ld.get("Listener", {}).get("Protocol")
                    ))

                    # Instance count (no IPs or IDs stored)
                    instances = lb.get("Instances") or []
                    instance_count: int = len(instances)

                    sensitive_cat = _classify_elb_name_sensitivity(lb_name)

                    # Fetch attributes (fail-soft)
                    cross_zone: bool | None = None
                    access_logs: bool | None = None
                    conn_draining: bool | None = None
                    idle_timeout: int | None = None
                    try:
                        attr_resp = self._call_aws(
                            client.describe_load_balancer_attributes,
                            LoadBalancerName=lb_name,
                        )
                        attrs = attr_resp.get("LoadBalancerAttributes") or {}
                        czlb = attrs.get("CrossZoneLoadBalancing") or {}
                        cross_zone = czlb.get("Enabled")
                        al = attrs.get("AccessLog") or {}
                        access_logs = al.get("Enabled")
                        cd = attrs.get("ConnectionDraining") or {}
                        conn_draining = cd.get("Enabled")
                        ci = attrs.get("ConnectionSettings") or {}
                        idle_timeout = ci.get("IdleTimeout")
                    except Exception:
                        pass

                    # Instance health — count only
                    healthy_inst: int = 0
                    unhealthy_inst: int = 0
                    try:
                        health_resp = self._call_aws(
                            client.describe_instance_health,
                            LoadBalancerName=lb_name,
                        )
                        for inst_state in health_resp.get("InstanceStates") or []:
                            if inst_state.get("State") == "InService":
                                healthy_inst += 1
                            else:
                                unhealthy_inst += 1
                    except Exception:
                        pass

                    # Tags (fail-soft) — keys only, never values
                    tag_keys: list[str] | None = None
                    try:
                        tags_resp = self._call_aws(
                            client.describe_tags, LoadBalancerNames=[lb_name]
                        )
                        for td in tags_resp.get("TagDescriptions") or []:
                            if td.get("LoadBalancerName") == lb_name:
                                raw = td.get("Tags") or []
                                tag_keys = sorted(t["Key"] for t in raw if "Key" in t) or None
                    except Exception:
                        pass

                    stable_id = f"{account_id}/{region}/{lb_name}"
                    records.append({
                        "record_type":                    AWS_ELB_CLASSIC_LOAD_BALANCER,
                        "record_id":                      stable_id,
                        "external_id":                    stable_id,
                        "name":                           lb_name,
                        "account_id":                     account_id,
                        "region":                         region,
                        "scheme":                         scheme or None,
                        "dns_name_hash":                  _hash_elb_arn(dns_name) if dns_name else None,
                        "vpc_id":                         vpc_id or None,
                        "subnet_ids":                     subnet_ids or None,
                        "security_group_ids":             sg_ids or None,
                        "listener_count":                 listener_count,
                        "listener_protocols":             listener_protocols or None,
                        "availability_zone_count":        az_count,
                        "instance_count":                 instance_count,
                        "healthy_instance_count":         healthy_inst,
                        "unhealthy_instance_count":       unhealthy_inst,
                        "cross_zone_load_balancing_enabled": cross_zone,
                        "access_logs_enabled":            access_logs,
                        "connection_draining_enabled":    conn_draining,
                        "idle_timeout_seconds":           idle_timeout,
                        "tag_keys":                       tag_keys,
                        "sensitive_name_category":        sensitive_cat,
                        "config_fetch_warnings":          None,
                    })

                next_marker = response.get("NextPageToken")
                if next_marker:
                    dlb_kwargs["Marker"] = next_marker
                else:
                    break
        except Exception:
            logger.warning(
                "aws: Classic DescribeLoadBalancers unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M44: WAFv2 fetch methods ──────────────────────────────────────────────

    def _fetch_wafv2_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch WAFv2 REGIONAL and CLOUDFRONT Web ACL metadata.

        Two scopes are fetched (M57.7 security-edge extension):

        * REGIONAL — one pass per selected region (existing M44 behaviour).
        * CLOUDFRONT — a single global pass against us-east-1, covering WAFs
          attached to CloudFront distributions.  This scope requires the
          wafv2 client to target us-east-1 regardless of the selected regions.

        SECURITY:
        - GetSampledRequests is NEVER called.
        - Request/response traffic and sampled request bodies NEVER accessed.
        - Only Web ACL configuration metadata (counts, default action, rules
          by type) is collected.
        - Rule statement values (byte match strings, regex patterns, IP sets)
          are NEVER stored — only aggregate type counts.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                waf_client = self._make_client("wafv2", credentials, region=region)
                region_records = self._fetch_wafv2_in_region(
                    waf_client, account_id, region, scope="REGIONAL"
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: wafv2 fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: wafv2 fetch failed  region=%s  (unexpected error)",
                    region, exc_info=True,
                )

        # M57.7: CLOUDFRONT-scope WAFs — global, requires us-east-1 client.
        # Fail-soft: if the API is not permitted (e.g. no wafv2:ListWebACLs for
        # CLOUDFRONT scope), we log a warning and continue.
        try:
            cf_waf_client = self._make_client("wafv2", credentials, region="us-east-1")
            cf_records = self._fetch_wafv2_in_region(
                cf_waf_client, account_id, "us-east-1", scope="CLOUDFRONT"
            )
            all_records.extend(cf_records)
            logger.debug(
                "aws: wafv2 cloudfront-scope fetched  count=%d",
                len(cf_records),
            )
        except Exception:
            logger.warning(
                "aws: wafv2 cloudfront-scope fetch failed  (unexpected error)",
                exc_info=True,
            )

        return all_records

    def _fetch_wafv2_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
        scope: str = "REGIONAL",
    ) -> list[dict]:
        """Fetch and normalize WAFv2 Web ACLs in a single region/scope.

        SECURITY:
        - GetSampledRequests NEVER called.
        - Sampled request bodies/headers/URIs NEVER accessed.
        - Rule statement values (regexes, byte strings, IPs) NEVER stored.
        - Tag values NEVER stored — only key names collected.
        """
        records: list[dict] = []

        # ── ListWebACLs (paginated) ────────────────────────────────────────────
        try:
            lwa_kwargs: dict = {"Scope": scope}
            while True:
                try:
                    list_resp = self._call_aws(client.list_web_acls, **lwa_kwargs)
                except Exception as exc:
                    fc = classify_aws_wafv2_failure("ListWebACLs", exc)
                    logger.warning(
                        "aws: ListWebACLs failed  region=%s  scope=%s  code=%s",
                        region, scope, fc.error_code,
                    )
                    break

                for acl_summary in list_resp.get("WebACLs") or []:
                    acl_name: str = acl_summary.get("Name") or ""
                    acl_id: str = acl_summary.get("Id") or ""
                    acl_arn: str = acl_summary.get("ARN") or ""
                    if not acl_id:
                        continue

                    sensitive_cat = _classify_elb_name_sensitivity(acl_name)

                    # GetWebACL for full rule details (fail-soft)
                    rule_summary: dict = {
                        "rule_count": 0,
                        "managed_rule_group_count": 0,
                        "custom_rule_count": 0,
                        "rate_based_rule_count": 0,
                        "allow_action_count": 0,
                        "block_action_count": 0,
                        "count_action_count": 0,
                        "captcha_challenge_action_count": 0,
                        "override_count_action_count": 0,
                    }
                    default_action: str = "unknown"
                    description_present: bool = False
                    try:
                        get_resp = self._call_aws(
                            client.get_web_acl,
                            Name=acl_name,
                            Scope=scope,
                            Id=acl_id,
                        )
                        acl_detail = get_resp.get("WebACL") or {}
                        description_present = bool(acl_detail.get("Description"))
                        default_action_raw = acl_detail.get("DefaultAction") or {}
                        if "Allow" in default_action_raw:
                            default_action = "allow"
                        elif "Block" in default_action_raw:
                            default_action = "block"
                        else:
                            default_action = "other"
                        rules = acl_detail.get("Rules") or []
                        rule_summary = _summarize_wafv2_rules(rules)
                    except Exception as exc:
                        fc = classify_aws_wafv2_failure("GetWebACL", exc)
                        logger.debug(
                            "aws: GetWebACL failed  region=%s  acl=%s  code=%s",
                            region, acl_name, fc.error_code,
                        )

                    # GetLoggingConfiguration — only check if logging is enabled
                    logging_enabled: bool = False
                    try:
                        log_resp = self._call_aws(
                            client.get_logging_configuration,
                            ResourceArn=acl_arn,
                        )
                        logging_enabled = bool(
                            log_resp.get("LoggingConfiguration") or {}
                        )
                    except Exception:
                        # Not configured or no permission → logging disabled or unknown
                        pass

                    # ListResourcesForWebACL — count + hash only, never raw ARNs
                    assoc_resource_arns: list[str] = []
                    try:
                        lr_resp = self._call_aws(
                            client.list_resources_for_web_acl,
                            WebACLArn=acl_arn,
                        )
                        assoc_resource_arns = lr_resp.get("ResourceArns") or []
                    except Exception as exc:
                        fc = classify_aws_wafv2_failure("ListResourcesForWebACL", exc)
                        logger.debug(
                            "aws: ListResourcesForWebACL failed  region=%s  acl=%s  code=%s",
                            region, acl_name, fc.error_code,
                        )

                    assoc_count = len(assoc_resource_arns)
                    assoc_hashes = sorted(
                        _hash_elb_arn(r) for r in assoc_resource_arns if r
                    )

                    # Tags (fail-soft) — keys only, never values
                    waf_tag_keys: list[str] | None = None
                    if acl_arn:
                        try:
                            tags_resp = self._call_aws(
                                client.list_tags_for_resource,
                                ResourceARN=acl_arn,
                            )
                            tag_list = (
                                (tags_resp.get("TagInfoForResource") or {}).get("TagList") or []
                            )
                            waf_tag_keys = sorted(t["Key"] for t in tag_list if "Key" in t) or None
                        except Exception:
                            pass

                    acl_stable_id = f"{account_id}/{region}/{scope}/{acl_arn or acl_id}"
                    records.append({
                        "record_type":                    AWS_WAFV2_WEB_ACL,
                        "record_id":                      acl_stable_id,
                        "external_id":                    acl_stable_id,
                        "name":                           acl_name,
                        "account_id":                     account_id,
                        "region":                         region,
                        "scope":                          scope,
                        "acl_id":                         acl_id,
                        "acl_arn":                        acl_arn,
                        "description_present":            description_present,
                        "default_action":                 default_action,
                        "rule_count":                     rule_summary["rule_count"],
                        "managed_rule_group_count":       rule_summary["managed_rule_group_count"],
                        "custom_rule_count":              rule_summary["custom_rule_count"],
                        "rate_based_rule_count":          rule_summary["rate_based_rule_count"],
                        "allow_action_count":             rule_summary["allow_action_count"],
                        "block_action_count":             rule_summary["block_action_count"],
                        "count_action_count":             rule_summary["count_action_count"],
                        "captcha_challenge_action_count": rule_summary["captcha_challenge_action_count"],
                        "override_count_action_count":    rule_summary["override_count_action_count"],
                        "logging_enabled":                logging_enabled,
                        "associated_resource_count":      assoc_count,
                        "associated_resource_arn_hashes": assoc_hashes or None,
                        "tag_keys":                       waf_tag_keys,
                        "sensitive_name_category":        sensitive_cat,
                        "config_fetch_warnings":          None,
                    })

                    # Create association records
                    for res_arn in assoc_resource_arns:
                        if not res_arn:
                            continue
                        # Determine resource type from ARN prefix
                        res_type = "unknown"
                        if ":elasticloadbalancing:" in res_arn and "loadbalancer/" in res_arn.lower():
                            res_type = "alb"
                        elif ":apigateway:" in res_arn or "/restapis/" in res_arn:
                            res_type = "apigateway"
                        elif ":cloudfront:" in res_arn:
                            res_type = "cloudfront"
                        elif ":appsync:" in res_arn:
                            res_type = "appsync"
                        elif ":cognito-idp:" in res_arn:
                            res_type = "cognito_user_pool"

                        acl_key = _hash_elb_arn(acl_arn) or acl_id
                        assoc_stable_id = (
                            f"{account_id}/{region}/{scope}/{acl_key}/"
                            f"{_hash_elb_arn(res_arn)}"
                        )
                        records.append({
                            "record_type":           AWS_WAFV2_WEB_ACL_ASSOCIATION,
                            "record_id":             assoc_stable_id,
                            "external_id":           assoc_stable_id,
                            "name":                  f"{acl_name} → {res_type}",
                            "account_id":            account_id,
                            "region":                region,
                            "web_acl_name":          acl_name,
                            "web_acl_arn_hash":      _hash_elb_arn(acl_arn),
                            "resource_arn_hash":     _hash_elb_arn(res_arn),
                            "resource_type":         res_type,
                            "scope":                 scope,
                            "config_fetch_warnings": None,
                        })

                next_waf_token = list_resp.get("NextMarker")
                if next_waf_token:
                    lwa_kwargs["NextMarker"] = next_waf_token
                else:
                    break
        except Exception:
            logger.warning(
                "aws: WAFv2 ListWebACLs unexpected error  region=%s  scope=%s",
                region, scope, exc_info=True,
            )

        return records

    # ── M45: CloudTrail helpers ────────────────────────────────────────────────

    @staticmethod
    def _summarize_cloudtrail_event_selectors(selectors: list[dict]) -> dict:
        """Extract aggregate metadata from GetEventSelectors response.

        SECURITY: Selector condition values (prefixes, field values) NEVER stored.
        Only type/count metadata is retained.
        """
        read_write_type = "All"
        include_management = True
        exclude_count = 0
        data_resource_type_counts: dict[str, int] = {}

        for sel in selectors:
            rw = sel.get("ReadWriteType") or "All"
            read_write_type = rw
            include_management = bool(sel.get("IncludeManagementEvents", True))
            for exc_src in sel.get("ExcludeManagementEventSources") or []:
                if exc_src:
                    exclude_count += 1
            for dr in sel.get("DataResources") or []:
                dr_type: str = dr.get("Type") or "unknown"
                data_resource_type_counts[dr_type] = (
                    data_resource_type_counts.get(dr_type, 0) + 1
                )

        return {
            "read_write_type":                        read_write_type,
            "include_management_events":              include_management,
            "data_resource_type_counts":              data_resource_type_counts or None,
            "exclude_management_event_sources_count": exclude_count,
        }

    @staticmethod
    def _summarize_cloudtrail_advanced_event_selectors(
        adv_selectors: list[dict],
    ) -> dict:
        """Extract aggregate metadata from AdvancedEventSelectors.

        SECURITY: FieldSelector values NEVER stored. Only type/count info.
        """
        read_write_type = "All"
        include_management = True
        exclude_count = 0

        for sel in adv_selectors:
            for fs in sel.get("FieldSelectors") or []:
                field = (fs.get("Field") or "").lower()
                if field == "readwritetype":
                    vals = fs.get("Equals") or []
                    if vals:
                        read_write_type = vals[0]
                elif field == "managementevent":
                    vals = fs.get("Equals") or []
                    if "false" in [str(v).lower() for v in vals]:
                        include_management = False

        return {
            "read_write_type":                        read_write_type,
            "include_management_events":              include_management,
            "data_resource_type_counts":              None,
            "exclude_management_event_sources_count": exclude_count,
        }

    @staticmethod
    def _summarize_cloudtrail_insight_selectors(selectors: list[dict]) -> dict:
        """Extract insight selector metadata.

        SECURITY: No event content is accessed or stored.
        """
        types = sorted({
            sel.get("InsightType") or "unknown"
            for sel in selectors
            if sel.get("InsightType")
        })
        return {
            "insight_selector_count": len(selectors),
            "insight_selector_types": types if types else None,
        }

    # ── M45: CloudTrail fetch methods ─────────────────────────────────────────

    def _fetch_cloudtrail_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch CloudTrail trail posture and event data stores across all regions.

        SECURITY:
        - LookupEvents is NEVER called.
        - S3 log objects are NEVER accessed.
        - Event payloads, request parameters, user identity data,
          source IPs NEVER stored.
        - Only posture/configuration metadata is collected:
          multi-region enabled, logging status, validation enabled,
          KMS presence (hashed), event selector type counts.
        - cloudtrail:LookupEvents NOT requested in IAM permissions.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []
        seen_trail_arns: set[str] = set()

        # Fetch all trails from primary region with includeShadowTrails=True
        # for a deduplicated account-wide view. Use home_region clients for
        # status and selectors.
        primary_region = selected_regions[0] if selected_regions else "us-east-1"
        try:
            primary_client = self._make_client(
                "cloudtrail", credentials, region=primary_region
            )
            try:
                describe_resp = self._call_aws(
                    primary_client.describe_trails,
                    includeShadowTrails=True,
                )
            except Exception as exc:
                fc = classify_aws_cloudtrail_failure("DescribeTrails", exc)
                logger.warning(
                    "aws: DescribeTrails failed  region=%s  code=%s",
                    primary_region, fc.error_code,
                )
                describe_resp = {}

            trails = describe_resp.get("trailList") or []

            for trail in trails:
                trail_arn: str = trail.get("TrailARN") or ""
                if not trail_arn or trail_arn in seen_trail_arns:
                    continue
                seen_trail_arns.add(trail_arn)

                home_region: str = trail.get("HomeRegion") or primary_region
                # Include multi-region trails regardless of home_region;
                # include single-region trails only if home_region is selected.
                if home_region not in selected_regions:
                    if not trail.get("IsMultiRegionTrail"):
                        continue

                trail_record = self._fetch_cloudtrail_trail_detail(
                    credentials, trail, account_id, home_region
                )
                all_records.append(trail_record)

        except Exception:
            logger.warning(
                "aws: CloudTrail describe_trails unexpected error  region=%s",
                primary_region, exc_info=True,
            )

        # Fetch event data stores per region
        for region in selected_regions:
            try:
                ct_client = self._make_client("cloudtrail", credentials, region=region)
                eds_records = self._fetch_cloudtrail_event_data_stores_in_region(
                    ct_client, account_id, region
                )
                all_records.extend(eds_records)
            except Exception:
                logger.warning(
                    "aws: CloudTrail event data stores unexpected error  region=%s",
                    region, exc_info=True,
                )

        logger.debug(
            "aws._fetch_cloudtrail_resources: fetched %d record(s)  account=%s",
            len(all_records), account_id,
        )
        return all_records

    def _fetch_cloudtrail_trail_detail(  # noqa: C901
        self,
        credentials: dict,
        trail: dict,
        account_id: str,
        home_region: str,
    ) -> dict:
        """Fetch and normalize a single CloudTrail trail posture record.

        SECURITY:
        - LookupEvents NEVER called.
        - S3 log objects NEVER read.
        - Event payloads, request parameters, user identity data NEVER stored.
        - GetTrailStatus: only is_logging + latest error presence (boolean) stored.
        - GetEventSelectors: only type/count aggregates stored.
        - GetInsightSelectors: only count + type names stored.
        - Tag values NEVER stored — only key names.
        """
        trail_arn: str = trail.get("TrailARN") or ""
        trail_name: str = trail.get("Name") or ""
        is_multi: bool = bool(trail.get("IsMultiRegionTrail"))
        is_org: bool = bool(trail.get("IsOrganizationTrail"))
        include_global: bool = bool(trail.get("IncludeGlobalServiceEvents"))
        log_validation: bool = bool(trail.get("LogFileValidationEnabled"))
        s3_bucket: str = trail.get("S3BucketName") or ""
        sns_topic: str = trail.get("SNSTopicARN") or trail.get("SNSTopicName") or ""
        kms_key_id: str = trail.get("KMSKeyId") or ""
        cw_log_grp: str = trail.get("CloudWatchLogsLogGroupArn") or ""

        warnings: list[str] = []

        # Use home_region client for status and selectors (trail lives there)
        try:
            home_client = self._make_client(
                "cloudtrail", credentials, region=home_region
            )
        except Exception:
            logger.warning(
                "aws: CloudTrail could not create client  home_region=%s",
                home_region, exc_info=True,
            )
            home_client = None

        # GetTrailStatus — logging status and error presence only
        is_logging: bool = False
        latest_delivery_error_present: bool = False
        latest_notification_error_present: bool = False
        if home_client is not None:
            try:
                status_resp = self._call_aws(
                    home_client.get_trail_status,
                    Name=trail_arn,
                )
                is_logging = bool(status_resp.get("IsLogging"))
                # SECURITY: boolean presence only — not the actual error text
                latest_delivery_error_present = bool(
                    status_resp.get("LatestDeliveryError")
                )
                latest_notification_error_present = bool(
                    status_resp.get("LatestNotificationError")
                )
            except Exception as exc:
                fc = classify_aws_cloudtrail_failure("GetTrailStatus", exc)
                warnings.append(f"GetTrailStatus: {fc.error_code}")

        # GetEventSelectors — aggregate counts only
        sel_summary: dict = {
            "management_events_enabled":              True,
            "read_write_type":                        "All",
            "include_management_events":              True,
            "data_resource_type_counts":              None,
            "exclude_management_event_sources_count": 0,
            "has_custom_event_selectors":             False,
        }
        if home_client is not None:
            try:
                sel_resp = self._call_aws(
                    home_client.get_event_selectors,
                    TrailName=trail_arn,
                )
                adv = sel_resp.get("AdvancedEventSelectors") or []
                basic = sel_resp.get("EventSelectors") or []
                if adv:
                    parsed = self._summarize_cloudtrail_advanced_event_selectors(adv)
                    sel_summary.update(parsed)
                    sel_summary["has_custom_event_selectors"] = True
                elif basic:
                    parsed = self._summarize_cloudtrail_event_selectors(basic)
                    sel_summary.update(parsed)
                    sel_summary["has_custom_event_selectors"] = True
                sel_summary["management_events_enabled"] = sel_summary.get(
                    "include_management_events", True
                )
            except Exception as exc:
                fc = classify_aws_cloudtrail_failure("GetEventSelectors", exc)
                warnings.append(f"GetEventSelectors: {fc.error_code}")

        # GetInsightSelectors — count + type names only
        insight_summary: dict = {
            "insight_selector_count": 0,
            "insight_selector_types": None,
        }
        if home_client is not None:
            try:
                ins_resp = self._call_aws(
                    home_client.get_insight_selectors,
                    TrailName=trail_arn,
                )
                raw_ins = ins_resp.get("InsightSelectors") or []
                insight_summary = self._summarize_cloudtrail_insight_selectors(raw_ins)
            except Exception as exc:
                code = getattr(
                    getattr(exc, "response", {}), "get", lambda *a: {}
                )("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
                if not code:
                    # Try botocore-style exception
                    try:
                        code = exc.response.get("Error", {}).get("Code", "")  # type: ignore[union-attr]
                    except Exception:
                        code = ""
                if code == "InsightNotEnabledException":
                    pass  # Normal — insights not configured
                else:
                    fc = classify_aws_cloudtrail_failure("GetInsightSelectors", exc)
                    warnings.append(f"GetInsightSelectors: {fc.error_code}")

        # Tags — key names only (values NEVER stored)
        tag_keys: list[str] | None = None
        if home_client is not None:
            try:
                tag_resp = self._call_aws(
                    home_client.list_tags,
                    ResourceIdList=[trail_arn],
                )
                for tag_list in tag_resp.get("ResourceTagList") or []:
                    raw_tags = tag_list.get("TagsList") or []
                    tag_keys = _extract_tag_keys(raw_tags)
                    break
            except Exception as exc:
                fc = classify_aws_cloudtrail_failure("ListTags", exc)
                warnings.append(f"ListTags: {fc.error_code}")

        stable_id = f"{account_id}/{home_region}/{_hash_kms_key_id(trail_arn)}"

        return {
            "record_type":              AWS_CLOUDTRAIL_TRAIL,
            "record_id":                stable_id,
            "external_id":              stable_id,
            "name":                     trail_name,
            "account_id":               account_id,
            "home_region":              home_region,
            "is_multi_region_trail":    is_multi,
            "include_global_service_events":  include_global,
            "is_organization_trail":    is_org,
            "log_file_validation_enabled":    log_validation,
            "kms_key_id_present":       bool(kms_key_id),
            "kms_key_id_hash":          _hash_kms_key_id(kms_key_id) if kms_key_id else None,
            "s3_bucket_name_hash":      _hash_kms_key_id(s3_bucket) if s3_bucket else None,
            "sns_topic_name_present":   bool(sns_topic),
            "cloud_watch_logs_enabled": bool(cw_log_grp),
            "has_custom_event_selectors":     sel_summary.get("has_custom_event_selectors", False),
            "is_logging":               is_logging,
            "latest_delivery_error_present":      latest_delivery_error_present,
            "latest_notification_error_present":  latest_notification_error_present,
            "management_events_enabled":          sel_summary.get("management_events_enabled", True),
            "read_write_type":                    sel_summary.get("read_write_type", "All"),
            "include_management_events":          sel_summary.get("include_management_events", True),
            "data_resource_type_counts":          sel_summary.get("data_resource_type_counts"),
            "exclude_management_event_sources_count": sel_summary.get(
                "exclude_management_event_sources_count", 0
            ),
            "insight_selector_count":  insight_summary.get("insight_selector_count", 0),
            "insight_selector_types":  insight_summary.get("insight_selector_types"),
            "tag_keys":                tag_keys,
            "config_fetch_warnings":   warnings if warnings else None,
        }

    def _fetch_cloudtrail_event_data_stores_in_region(
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch CloudTrail Event Data Store metadata in a single region.

        SECURITY:
        - Event records NEVER accessed.
        - Only posture/config metadata stored.
        - Advanced event selector values NEVER stored.
        - Tag values NEVER stored.
        """
        records: list[dict] = []

        try:
            kwargs: dict = {}
            while True:
                try:
                    resp = self._call_aws(client.list_event_data_stores, **kwargs)
                except Exception as exc:
                    fc = classify_aws_cloudtrail_failure("ListEventDataStores", exc)
                    logger.warning(
                        "aws: ListEventDataStores failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break

                for eds in resp.get("EventDataStores") or []:
                    eds_arn: str = eds.get("EventDataStoreArn") or ""
                    if not eds_arn:
                        continue

                    eds_name: str = eds.get("Name") or ""
                    status: str = eds.get("Status") or "UNKNOWN"
                    term_protection: bool = bool(eds.get("TerminationProtectionEnabled"))
                    multi_region: bool = bool(eds.get("MultiRegionEnabled"))
                    org_enabled: bool = bool(eds.get("OrganizationEnabled"))
                    retention: int | None = eds.get("RetentionPeriod")
                    billing_mode: str = (
                        eds.get("BillingMode") or "EXTENDABLE_RETENTION_PRICING"
                    )
                    kms_key_id: str = eds.get("KmsKeyId") or ""
                    # Advanced event selectors — count only; values NEVER stored
                    adv_sel_count = len(eds.get("AdvancedEventSelectors") or [])

                    # GetEventDataStore for tags (fail-soft)
                    tag_keys: list[str] | None = None
                    eds_warnings: list[str] = []
                    try:
                        get_resp = self._call_aws(
                            client.get_event_data_store,
                            EventDataStore=eds_arn,
                        )
                        raw_tags = get_resp.get("Tags") or []
                        tag_keys = _extract_tag_keys(raw_tags)
                    except Exception as exc:
                        fc = classify_aws_cloudtrail_failure("GetEventDataStore", exc)
                        eds_warnings.append(f"GetEventDataStore: {fc.error_code}")

                    stable_id = (
                        f"{account_id}/{region}/{_hash_kms_key_id(eds_arn)}"
                    )
                    records.append({
                        "record_type":                      AWS_CLOUDTRAIL_EVENT_DATA_STORE,
                        "record_id":                        stable_id,
                        "external_id":                      stable_id,
                        "name":                             eds_name,
                        "account_id":                       account_id,
                        "region":                           region,
                        "status":                           status,
                        "termination_protection_enabled":   term_protection,
                        "multi_region_enabled":             multi_region,
                        "organization_enabled":             org_enabled,
                        "retention_period":                 retention,
                        "advanced_event_selector_count":    adv_sel_count,
                        "kms_key_id_present":               bool(kms_key_id),
                        "billing_mode":                     billing_mode,
                        "tag_keys":                         tag_keys,
                        "config_fetch_warnings":            eds_warnings if eds_warnings else None,
                    })

                next_token = resp.get("NextToken")
                if next_token:
                    kwargs["NextToken"] = next_token
                else:
                    break

        except Exception:
            logger.warning(
                "aws: CloudTrail event data store unexpected error  region=%s",
                region, exc_info=True,
            )

        return records

    # ── M45: GuardDuty fetch methods ──────────────────────────────────────────

    @staticmethod
    def _summarize_guardduty_features(features: list[dict]) -> dict:
        """Extract GuardDuty feature enable/disable status.

        SECURITY: Feature configuration details and finding data NEVER stored.
        Only presence/enabled booleans per feature.
        """
        result: dict[str, bool] = {}
        for feat in features:
            name: str = (feat.get("Name") or "").lower()
            status: str = (feat.get("Status") or "").upper()
            enabled = status == "ENABLED"
            if name in {"s3_logs", "s3logs"}:
                result["s3_logs_enabled"] = enabled
            elif name in {"eks_audit_logs", "eksauditlogs"}:
                result["eks_audit_logs_enabled"] = enabled
            elif name in {"malware_protection", "malwareprotection"}:
                result["malware_protection_enabled"] = enabled
            elif name in {"rds_login_events", "rdsloginevents"}:
                result["rds_login_events_enabled"] = enabled
            elif name in {"lambda_network_logs", "lambdanetworklogs"}:
                result["lambda_network_logs_enabled"] = enabled
            elif name in {"runtime_monitoring", "runtimemonitoring"}:
                result["runtime_monitoring_enabled"] = enabled
            elif name in {"ebs_malware_protection", "ebsmalwareprotection"}:
                result["ebs_malware_protection_enabled"] = enabled
        return result

    def _fetch_guardduty_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch GuardDuty detector posture across all selected regions.

        SECURITY:
        - GetFindings NEVER called.
        - Finding details, severity, resources, remediation NEVER accessed.
        - Only detector posture (enabled, publishing frequency, feature flags)
          and aggregate member counts collected.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                gd_client = self._make_client("guardduty", credentials, region=region)
                region_records = self._fetch_guardduty_in_region(
                    gd_client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: guardduty fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: guardduty fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_guardduty_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize GuardDuty detectors in a single region.

        SECURITY:
        - GetFindings NEVER called.
        - Finding details NEVER accessed or stored.
        - Tag values NEVER stored.
        """
        records: list[dict] = []

        # ListDetectors
        detector_ids: list[str] = []
        try:
            kwargs: dict = {}
            while True:
                try:
                    resp = self._call_aws(client.list_detectors, **kwargs)
                except Exception as exc:
                    fc = classify_aws_guardduty_failure("ListDetectors", exc)
                    logger.warning(
                        "aws: ListDetectors failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break
                detector_ids.extend(resp.get("DetectorIds") or [])
                next_token = resp.get("NextToken")
                if next_token:
                    kwargs["NextToken"] = next_token
                else:
                    break
        except Exception:
            logger.warning(
                "aws: GuardDuty ListDetectors unexpected  region=%s",
                region, exc_info=True,
            )
            return records

        for detector_id in detector_ids:
            warnings: list[str] = []

            # GetDetector
            det: dict = {}
            try:
                det_resp = self._call_aws(client.get_detector, DetectorId=detector_id)
                det = det_resp
            except Exception as exc:
                fc = classify_aws_guardduty_failure("GetDetector", exc)
                warnings.append(f"GetDetector: {fc.error_code}")

            status: str = (det.get("Status") or "DISABLED").upper()
            freq: str = det.get("FindingPublishingFrequency") or "SIX_HOURS"

            # Features (newer API) vs DataSources (legacy) — handle both
            features_raw: list[dict] = det.get("Features") or []
            data_sources: dict = det.get("DataSources") or {}

            feature_flags: dict = {}
            if features_raw:
                feature_flags = self._summarize_guardduty_features(features_raw)
                feature_count = len(features_raw)
            else:
                # Legacy DataSources format
                s3_status = (
                    (data_sources.get("S3Logs") or {}).get("Status") or "DISABLED"
                ).upper()
                eks_status = (
                    (
                        (data_sources.get("Kubernetes") or {})
                        .get("AuditLogs") or {}
                    ).get("Status") or "DISABLED"
                ).upper()
                mal_ds = data_sources.get("MalwareProtection") or {}
                ebs_status = (
                    (
                        (mal_ds.get("ScanEc2InstanceWithFindings") or {})
                        .get("EbsVolumes") or {}
                    ).get("Status") or "DISABLED"
                ).upper()
                feature_flags = {
                    "s3_logs_enabled":           s3_status == "ENABLED",
                    "eks_audit_logs_enabled":    eks_status == "ENABLED",
                    "malware_protection_enabled": ebs_status == "ENABLED",
                    "rds_login_events_enabled":  False,
                    "lambda_network_logs_enabled": False,
                    "runtime_monitoring_enabled": False,
                    "ebs_malware_protection_enabled": False,
                }
                feature_count = sum(1 for v in feature_flags.values() if v)

            # Member counts (fail-soft)
            member_count = 0
            active_member_count = 0
            try:
                mem_resp = self._call_aws(
                    client.list_members,
                    DetectorId=detector_id,
                    OnlyAssociated="false",
                )
                members = mem_resp.get("Members") or []
                member_count = len(members)
                active_member_count = sum(
                    1 for m in members
                    if (m.get("RelationshipStatus") or "").upper() == "ENABLED"
                )
            except Exception as exc:
                fc = classify_aws_guardduty_failure("ListMembers", exc)
                warnings.append(f"ListMembers: {fc.error_code}")

            # Admin account presence (fail-soft)
            admin_account_present: bool = False
            try:
                admin_resp = self._call_aws(
                    client.get_administrator_account,
                    DetectorId=detector_id,
                )
                admin_info = admin_resp.get("Administrator") or {}
                admin_account_present = bool(admin_info.get("AccountId"))
            except Exception as exc:
                fc = classify_aws_guardduty_failure("GetAdministratorAccount", exc)
                if fc.error_code not in {
                    "aws_guardduty_access_denied",
                    "aws_guardduty_api_unavailable",
                }:
                    warnings.append(f"GetAdministratorAccount: {fc.error_code}")

            # Publishing destinations
            pub_dest_records: list[dict] = []
            try:
                dest_resp = self._call_aws(
                    client.list_publishing_destinations,
                    DetectorId=detector_id,
                )
                for dest in dest_resp.get("Destinations") or []:
                    dest_id: str = dest.get("DestinationId") or ""
                    if not dest_id:
                        continue
                    dest_type: str = dest.get("DestinationType") or "UNKNOWN"
                    dest_status: str = (dest.get("Status") or "UNKNOWN").upper()

                    dest_warnings: list[str] = []
                    kms_arn_present: bool = False
                    dest_arn_present: bool = False
                    try:
                        desc_resp = self._call_aws(
                            client.describe_publishing_destination,
                            DetectorId=detector_id,
                            DestinationId=dest_id,
                        )
                        dest_props = desc_resp.get("DestinationProperties") or {}
                        kms_arn_present = bool(dest_props.get("KmsKeyArn"))
                        dest_arn_present = bool(dest_props.get("DestinationArn"))
                    except Exception as exc:
                        fc = classify_aws_guardduty_failure(
                            "DescribePublishingDestination", exc
                        )
                        dest_warnings.append(
                            f"DescribePublishingDestination: {fc.error_code}"
                        )

                    dest_stable_id = (
                        f"{account_id}/{region}/{detector_id}/{dest_id}"
                    )
                    pub_dest_records.append({
                        "record_type":             AWS_GUARDDUTY_PUBLISHING_DESTINATION,
                        "record_id":               dest_stable_id,
                        "external_id":             dest_stable_id,
                        "name":                    f"guardduty-dest-{dest_id[:8]}",
                        "account_id":              account_id,
                        "region":                  region,
                        "destination_type":        dest_type,
                        "status":                  dest_status,
                        "kms_key_arn_present":     kms_arn_present,
                        "destination_arn_present": dest_arn_present,
                        "config_fetch_warnings":   dest_warnings if dest_warnings else None,
                    })
            except Exception as exc:
                fc = classify_aws_guardduty_failure("ListPublishingDestinations", exc)
                warnings.append(f"ListPublishingDestinations: {fc.error_code}")

            # Tags — key names only (values NEVER stored)
            tag_keys: list[str] | None = None
            try:
                det_arn = (
                    f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"
                )
                tag_resp = self._call_aws(
                    client.list_tags_for_resource,
                    ResourceArn=det_arn,
                )
                raw_tags = [
                    {"Key": k, "Value": v}
                    for k, v in (tag_resp.get("Tags") or {}).items()
                ]
                tag_keys = _extract_tag_keys(raw_tags)
            except Exception as exc:
                fc = classify_aws_guardduty_failure("ListTagsForResource", exc)
                warnings.append(f"ListTagsForResource: {fc.error_code}")

            stable_id = f"{account_id}/{region}/{detector_id}"
            det_record: dict = {
                "record_type":                    AWS_GUARDDUTY_DETECTOR,
                "record_id":                      stable_id,
                "external_id":                    stable_id,
                "name":                           f"guardduty-{region}-{detector_id[:8]}",
                "account_id":                     account_id,
                "region":                         region,
                "status":                         status,
                "finding_publishing_frequency":   freq,
                "s3_logs_enabled":                feature_flags.get("s3_logs_enabled", False),
                "eks_audit_logs_enabled":         feature_flags.get("eks_audit_logs_enabled", False),
                "malware_protection_enabled":     feature_flags.get("malware_protection_enabled", False),
                "rds_login_events_enabled":       feature_flags.get("rds_login_events_enabled", False),
                "lambda_network_logs_enabled":    feature_flags.get("lambda_network_logs_enabled", False),
                "runtime_monitoring_enabled":     feature_flags.get("runtime_monitoring_enabled", False),
                "ebs_malware_protection_enabled": feature_flags.get("ebs_malware_protection_enabled", False),
                "feature_count":                  feature_count,
                "member_count":                   member_count,
                "active_member_count":            active_member_count,
                "admin_account_present":          admin_account_present,
                "tag_keys":                       tag_keys,
                "config_fetch_warnings":          warnings if warnings else None,
            }
            records.append(det_record)
            records.extend(pub_dest_records)

        return records

    # ── M45: Security Hub fetch methods ───────────────────────────────────────

    @staticmethod
    def _securityhub_standard_name_from_arn(arn: str) -> str:
        """Extract a short human-readable standard name from a standards ARN.

        SECURITY: Only the ARN path segment is used to derive the name.
        No finding data or standard content is accessed.
        """
        arn_lower = arn.lower()
        if "cis" in arn_lower:
            return "CIS"
        if (
            "aws-foundational-security-best-practices" in arn_lower
            or "fsbp" in arn_lower
        ):
            return "FSBP"
        if "nist-800-53" in arn_lower or "nist800" in arn_lower:
            return "NIST-800-53"
        if "pci-dss" in arn_lower or "pcidss" in arn_lower:
            return "PCI-DSS"
        # Fallback: last meaningful path component
        parts = arn.rstrip("/").split("/")
        for p in reversed(parts):
            if p and not p.startswith("v") and p not in {"standards", "ruleset", "aws"}:
                return p[:32]
        return "unknown"

    def _fetch_securityhub_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch Security Hub posture across all selected regions.

        SECURITY:
        - GetFindings NEVER called.
        - Finding details, evidence, remediation NEVER accessed or stored.
        - Only hub posture (enabled, auto-enable controls, standards) collected.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                sh_client = self._make_client("securityhub", credentials, region=region)
                region_records = self._fetch_securityhub_in_region(
                    sh_client, account_id, region
                )
                all_records.extend(region_records)
                logger.debug(
                    "aws: securityhub fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: securityhub fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_securityhub_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize Security Hub posture in a single region.

        SECURITY:
        - GetFindings NEVER called.
        - Finding details NEVER accessed or stored.
        - Tag values NEVER stored — only key names.
        """
        records: list[dict] = []
        warnings: list[str] = []

        # DescribeHub — check if Security Hub is enabled
        hub_enabled: bool = False
        auto_enable_controls: bool = False
        control_finding_generator: str = "STANDARD_CONTROL"

        try:
            hub_resp = self._call_aws(client.describe_hub)
            hub_enabled = True
            auto_enable_controls = bool(hub_resp.get("AutoEnableControls"))
            control_finding_generator = (
                hub_resp.get("ControlFindingGenerator") or "STANDARD_CONTROL"
            )
        except Exception as exc:
            fc = classify_aws_securityhub_failure("DescribeHub", exc)
            if fc.error_code == "aws_securityhub_hub_unavailable":
                # Security Hub not enabled in this region — emit disabled record
                stable_id = f"{account_id}/{region}/securityhub"
                records.append({
                    "record_type":                  AWS_SECURITYHUB_ACCOUNT,
                    "record_id":                    stable_id,
                    "external_id":                  stable_id,
                    "name":                         f"securityhub-{region}",
                    "account_id":                   account_id,
                    "region":                       region,
                    "hub_enabled":                  False,
                    "auto_enable_controls":         False,
                    "control_finding_generator":    "STANDARD_CONTROL",
                    "enabled_standards_count":      0,
                    "enabled_products_count":       0,
                    "finding_aggregator_present":   False,
                    "tag_keys":                     None,
                    "config_fetch_warnings":        None,
                })
                return records
            warnings.append(f"DescribeHub: {fc.error_code}")

        # GetEnabledStandards — count + name summaries only
        standards_records: list[dict] = []
        enabled_standards_count = 0
        try:
            std_kwargs: dict = {}
            while True:
                try:
                    std_resp = self._call_aws(
                        client.get_enabled_standards, **std_kwargs
                    )
                except Exception as exc:
                    fc = classify_aws_securityhub_failure("GetEnabledStandards", exc)
                    warnings.append(f"GetEnabledStandards: {fc.error_code}")
                    break

                for sub in std_resp.get("StandardsSubscriptions") or []:
                    sub_arn: str = sub.get("StandardsSubscriptionArn") or ""
                    std_arn: str = sub.get("StandardsArn") or ""
                    status: str = (sub.get("StandardsStatus") or "INCOMPLETE").upper()
                    status_reason_obj = sub.get("StandardsStatusReason") or {}
                    status_reason: str = (
                        status_reason_obj.get("StatusReasonCode") or ""
                        if isinstance(status_reason_obj, dict)
                        else ""
                    )
                    std_name = self._securityhub_standard_name_from_arn(std_arn)
                    enabled_standards_count += 1

                    sub_stable_id = (
                        f"{account_id}/{region}/"
                        f"{_hash_kms_key_id(sub_arn) if sub_arn else std_name}"
                    )
                    standards_records.append({
                        "record_type":             AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
                        "record_id":               sub_stable_id,
                        "external_id":             sub_stable_id,
                        "name":                    f"securityhub-std-{std_name}",
                        "account_id":              account_id,
                        "region":                  region,
                        "standards_status":        status,
                        "standards_status_reason": status_reason or None,
                        "standards_name_summary":  std_name,
                        "config_fetch_warnings":   None,
                    })

                next_token = std_resp.get("NextToken")
                if next_token:
                    std_kwargs["NextToken"] = next_token
                else:
                    break
        except Exception:
            logger.warning(
                "aws: SecurityHub GetEnabledStandards unexpected  region=%s",
                region, exc_info=True,
            )

        # ListEnabledProductsForImport — count only (product ARNs NEVER stored)
        enabled_products_count = 0
        try:
            prod_kwargs: dict = {}
            while True:
                try:
                    prod_resp = self._call_aws(
                        client.list_enabled_products_for_import, **prod_kwargs
                    )
                except Exception as exc:
                    fc = classify_aws_securityhub_failure(
                        "ListEnabledProductsForImport", exc
                    )
                    warnings.append(f"ListEnabledProductsForImport: {fc.error_code}")
                    break
                enabled_products_count += len(
                    prod_resp.get("ProductSubscriptions") or []
                )
                next_token = prod_resp.get("NextToken")
                if next_token:
                    prod_kwargs["NextToken"] = next_token
                else:
                    break
        except Exception:
            pass  # Non-critical; fail-soft

        # ListFindingAggregators — presence only
        finding_aggregator_records: list[dict] = []
        finding_aggregator_present: bool = False
        try:
            agg_resp = self._call_aws(client.list_finding_aggregators)
            aggregators = agg_resp.get("FindingAggregators") or []
            finding_aggregator_present = bool(aggregators)

            for agg in aggregators:
                agg_arn: str = agg.get("FindingAggregatorArn") or ""
                if not agg_arn:
                    continue

                linking_mode: str = "UNKNOWN"
                specified_regions: list[str] = []
                agg_warnings: list[str] = []
                try:
                    get_agg_resp = self._call_aws(
                        client.get_finding_aggregator,
                        FindingAggregatorArn=agg_arn,
                    )
                    linking_mode = get_agg_resp.get("RegionLinkingMode") or "UNKNOWN"
                    # Region names are not PII; stored for drift detection only.
                    specified_regions = sorted(get_agg_resp.get("Regions") or [])
                except Exception as exc:
                    fc = classify_aws_securityhub_failure("GetFindingAggregator", exc)
                    agg_warnings.append(f"GetFindingAggregator: {fc.error_code}")

                agg_stable_id = (
                    f"{account_id}/{region}/{_hash_kms_key_id(agg_arn)}"
                )
                finding_aggregator_records.append({
                    "record_type":             AWS_SECURITYHUB_FINDING_AGGREGATOR,
                    "record_id":               agg_stable_id,
                    "external_id":             agg_stable_id,
                    "name":                    f"securityhub-aggregator-{region}",
                    "account_id":              account_id,
                    "region":                  region,
                    "linking_mode":            linking_mode,
                    "specified_regions_count": len(specified_regions),
                    "specified_regions":       specified_regions if specified_regions else None,
                    "config_fetch_warnings":   agg_warnings if agg_warnings else None,
                })

        except Exception as exc:
            fc = classify_aws_securityhub_failure("ListFindingAggregators", exc)
            if fc.error_code not in {
                "aws_securityhub_access_denied",
                "aws_securityhub_aggregator_unavailable",
            }:
                warnings.append(f"ListFindingAggregators: {fc.error_code}")

        # Tags — key names only (values NEVER stored)
        tag_keys: list[str] | None = None
        try:
            hub_arn = f"arn:aws:securityhub:{region}:{account_id}:hub/default"
            tag_resp = self._call_aws(
                client.list_tags_for_resource,
                ResourceArn=hub_arn,
            )
            raw_tags = [
                {"Key": k, "Value": v}
                for k, v in (tag_resp.get("Tags") or {}).items()
            ]
            tag_keys = _extract_tag_keys(raw_tags)
        except Exception as exc:
            fc = classify_aws_securityhub_failure("ListTagsForResource", exc)
            warnings.append(f"ListTagsForResource: {fc.error_code}")

        stable_id = f"{account_id}/{region}/securityhub"
        hub_record: dict = {
            "record_type":                  AWS_SECURITYHUB_ACCOUNT,
            "record_id":                    stable_id,
            "external_id":                  stable_id,
            "name":                         f"securityhub-{region}",
            "account_id":                   account_id,
            "region":                       region,
            "hub_enabled":                  hub_enabled,
            "auto_enable_controls":         auto_enable_controls,
            "control_finding_generator":    control_finding_generator,
            "enabled_standards_count":      enabled_standards_count,
            "enabled_products_count":       enabled_products_count,
            "finding_aggregator_present":   finding_aggregator_present,
            "tag_keys":                     tag_keys,
            "config_fetch_warnings":        warnings if warnings else None,
        }

        records.append(hub_record)
        records.extend(standards_records)
        records.extend(finding_aggregator_records)
        return records

    # ── M46: ECS fetch methods ─────────────────────────────────────────────────

    def _fetch_ecs_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch ECS cluster, service, and task definition posture across all regions.

        SECURITY:
        - logs:GetLogEvents NEVER called.
        - ECS task and container logs NEVER read.
        - Environment variable values NEVER stored — key names only.
        - Secret reference values and ARNs NEVER stored — count only.
        - No write operations performed.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                ecs_client = self._make_client("ecs", credentials, region=region)
                region_records = self._fetch_ecs_in_region(ecs_client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: ecs fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: ecs fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_ecs_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize ECS resources in a single region.

        SECURITY:
        - logs:GetLogEvents NEVER called.
        - Container log output NEVER accessed.
        - Environment variable values NEVER stored.
        - Secret values NEVER accessed.
        """
        records: list[dict] = []
        seen_task_def_arns: set[str] = set()

        # ── ListClusters (paginated) ──────────────────────────────────────────
        cluster_arns: list[str] = []
        try:
            kwargs: dict = {}
            while True:
                try:
                    resp = self._call_aws(client.list_clusters, **kwargs)
                except Exception as exc:
                    fc = classify_aws_ecs_failure("ListClusters", exc)
                    logger.warning(
                        "aws: ListClusters failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    return records
                cluster_arns.extend(resp.get("clusterArns") or [])
                next_token = resp.get("nextToken")
                if next_token:
                    kwargs["nextToken"] = next_token
                else:
                    break
        except Exception:
            logger.warning(
                "aws: ECS ListClusters unexpected  region=%s", region, exc_info=True,
            )
            return records

        if not cluster_arns:
            return records

        # ── DescribeClusters (batch up to 100) ────────────────────────────────
        cluster_details: list[dict] = []
        try:
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i:i + 100]
                try:
                    desc_resp = self._call_aws(
                        client.describe_clusters,
                        clusters=batch,
                        include=["SETTINGS", "STATISTICS", "TAGS"],
                    )
                    cluster_details.extend(desc_resp.get("clusters") or [])
                except Exception as exc:
                    fc = classify_aws_ecs_failure("DescribeClusters", exc)
                    logger.warning(
                        "aws: DescribeClusters failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
        except Exception:
            logger.warning(
                "aws: ECS DescribeClusters unexpected  region=%s", region, exc_info=True,
            )

        for cluster in cluster_details:
            cluster_arn: str = cluster.get("clusterArn") or ""
            cluster_name: str = cluster.get("clusterName") or ""
            if not cluster_arn:
                continue

            status: str = cluster.get("status") or "UNKNOWN"
            registered_container_instances: int = cluster.get(
                "registeredContainerInstancesCount", 0
            ) or 0
            running_tasks: int = cluster.get("runningTasksCount", 0) or 0
            pending_tasks: int = cluster.get("pendingTasksCount", 0) or 0
            active_services: int = cluster.get("activeServicesCount", 0) or 0

            # Capacity providers
            capacity_providers: list[str] = sorted(
                cluster.get("capacityProviders") or []
            )
            default_capacity_provider_strategy: list[dict] = (
                cluster.get("defaultCapacityProviderStrategy") or []
            )
            has_fargate_capacity: bool = any(
                cp in ("FARGATE", "FARGATE_SPOT")
                for cp in capacity_providers
            )

            # Settings (containerInsights, etc.)
            settings: list[dict] = cluster.get("settings") or []
            container_insights_enabled: bool = any(
                s.get("name") == "containerInsights" and s.get("value") == "enabled"
                for s in settings
            )

            # Tag keys only
            tag_keys = _extract_tag_keys(cluster.get("tags") or [])

            name_sensitivity = _classify_container_name_sensitivity(cluster_name)
            stable_id = f"{account_id}/{region}/{cluster_name}"
            records.append({
                "record_type":                       AWS_ECS_CLUSTER,
                "record_id":                         stable_id,
                "external_id":                       cluster_arn,
                "name":                              cluster_name,
                "account_id":                        account_id,
                "region":                            region,
                "status":                            status,
                "registered_container_instance_count": registered_container_instances,
                "running_tasks_count":               running_tasks,
                "pending_tasks_count":               pending_tasks,
                "active_services_count":             active_services,
                "capacity_providers":                capacity_providers if capacity_providers else None,
                "default_capacity_provider_strategy_count": len(default_capacity_provider_strategy),
                "has_fargate_capacity":              has_fargate_capacity,
                "container_insights_enabled":        container_insights_enabled,
                "name_sensitivity":                  name_sensitivity,
                "tag_keys":                          tag_keys,
            })

            # ── ListServices per cluster ──────────────────────────────────────
            service_arns: list[str] = []
            try:
                svc_kwargs: dict = {"cluster": cluster_arn}
                while True:
                    try:
                        svc_resp = self._call_aws(client.list_services, **svc_kwargs)
                    except Exception as exc:
                        fc = classify_aws_ecs_failure("ListServices", exc)
                        logger.warning(
                            "aws: ListServices failed  cluster=%s  code=%s",
                            cluster_name, fc.error_code,
                        )
                        break
                    service_arns.extend(svc_resp.get("serviceArns") or [])
                    next_token = svc_resp.get("nextToken")
                    if next_token:
                        svc_kwargs["nextToken"] = next_token
                    else:
                        break
            except Exception:
                logger.warning(
                    "aws: ECS ListServices unexpected  cluster=%s", cluster_name, exc_info=True,
                )

            if not service_arns:
                continue

            # ── DescribeServices (batch up to 10) ─────────────────────────────
            for i in range(0, len(service_arns), 10):
                batch_svc = service_arns[i:i + 10]
                try:
                    svc_desc_resp = self._call_aws(
                        client.describe_services,
                        cluster=cluster_arn,
                        services=batch_svc,
                        include=["TAGS"],
                    )
                    for svc in svc_desc_resp.get("services") or []:
                        svc_arn: str = svc.get("serviceArn") or ""
                        svc_name: str = svc.get("serviceName") or ""
                        if not svc_arn:
                            continue

                        launch_type: str = svc.get("launchType") or "EC2"
                        scheduling_strategy: str = (
                            svc.get("schedulingStrategy") or "REPLICA"
                        )
                        desired_count: int = svc.get("desiredCount", 0) or 0
                        running_count: int = svc.get("runningCount", 0) or 0
                        status_svc: str = svc.get("status") or "UNKNOWN"

                        # Network config
                        network_cfg: dict = svc.get("networkConfiguration") or {}
                        awsvpc_cfg: dict = (
                            network_cfg.get("awsvpcConfiguration") or {}
                        )
                        assign_public_ip: str = (
                            awsvpc_cfg.get("assignPublicIp") or "DISABLED"
                        )
                        has_public_ip: bool = assign_public_ip == "ENABLED"

                        # Load balancers
                        load_balancers: list[dict] = svc.get("loadBalancers") or []
                        lb_count: int = len(load_balancers)
                        lb_target_group_arns: list[str] = sorted(
                            _hash_kms_key_id(lb.get("targetGroupArn") or "x")
                            for lb in load_balancers
                            if lb.get("targetGroupArn")
                        )

                        # Task definition ARN — hashed
                        task_def_arn: str = svc.get("taskDefinition") or ""
                        task_def_arn_hash: str | None = (
                            _hash_kms_key_id(task_def_arn) if task_def_arn else None
                        )
                        # Track unique task def ARNs to fetch later
                        if task_def_arn and task_def_arn not in seen_task_def_arns:
                            seen_task_def_arns.add(task_def_arn)

                        # Deployments
                        deployments: list[dict] = svc.get("deployments") or []
                        deployment_config: dict = (
                            svc.get("deploymentConfiguration") or {}
                        )
                        circuit_breaker: dict = (
                            deployment_config.get("deploymentCircuitBreaker") or {}
                        )
                        circuit_breaker_enabled: bool = bool(
                            circuit_breaker.get("enable")
                        )
                        circuit_breaker_rollback: bool = bool(
                            circuit_breaker.get("rollback")
                        )

                        # Service connect
                        service_connect_cfg: dict = (
                            svc.get("serviceConnectConfiguration") or {}
                        )
                        service_connect_enabled: bool = bool(
                            service_connect_cfg.get("enabled")
                        )

                        # Tags
                        svc_tag_keys = _extract_tag_keys(svc.get("tags") or [])
                        svc_name_sensitivity = _classify_container_name_sensitivity(
                            svc_name
                        )

                        svc_stable_id = f"{account_id}/{region}/{cluster_name}/{svc_name}"
                        records.append({
                            "record_type":                  AWS_ECS_SERVICE,
                            "record_id":                    svc_stable_id,
                            "external_id":                  svc_arn,
                            "name":                         svc_name,
                            "account_id":                   account_id,
                            "region":                       region,
                            "cluster_name":                 cluster_name,
                            "status":                       status_svc,
                            "launch_type":                  launch_type,
                            "scheduling_strategy":          scheduling_strategy,
                            "desired_count":                desired_count,
                            "running_count":                running_count,
                            "has_public_ip":                has_public_ip,
                            "lb_count":                     lb_count,
                            "lb_target_group_arn_hashes":   lb_target_group_arns if lb_target_group_arns else None,
                            "task_definition_arn_hash":     task_def_arn_hash,
                            "deployment_count":             len(deployments),
                            "circuit_breaker_enabled":      circuit_breaker_enabled,
                            "circuit_breaker_rollback":     circuit_breaker_rollback,
                            "service_connect_enabled":      service_connect_enabled,
                            "name_sensitivity":             svc_name_sensitivity,
                            "tag_keys":                     svc_tag_keys,
                        })
                except Exception as exc:
                    fc = classify_aws_ecs_failure("DescribeServices", exc)
                    logger.warning(
                        "aws: DescribeServices failed  cluster=%s  code=%s",
                        cluster_name, fc.error_code,
                    )

        # ── DescribeTaskDefinition per unique revision ─────────────────────────
        for td_arn in seen_task_def_arns:
            try:
                td_resp = self._call_aws(
                    client.describe_task_definition,
                    taskDefinition=td_arn,
                    include=["TAGS"],
                )
                td: dict = td_resp.get("taskDefinition") or {}
                if not td:
                    continue

                td_family: str = td.get("family") or ""
                td_revision: int = td.get("revision") or 0
                td_status: str = td.get("status") or "UNKNOWN"
                td_network_mode: str = td.get("networkMode") or "bridge"
                td_requires_compat: list[str] = sorted(
                    td.get("requiresCompatibilities") or []
                )
                td_cpu: str | None = td.get("cpu")
                td_memory: str | None = td.get("memory")
                td_task_role_arn: str = td.get("taskRoleArn") or ""
                td_exec_role_arn: str = td.get("executionRoleArn") or ""
                td_task_role_hash: str | None = (
                    _hash_kms_key_id(td_task_role_arn) if td_task_role_arn else None
                )
                td_exec_role_hash: str | None = (
                    _hash_kms_key_id(td_exec_role_arn) if td_exec_role_arn else None
                )

                # Volumes (count + presence of sensitive types)
                volumes: list[dict] = td.get("volumes") or []
                volume_count: int = len(volumes)
                has_efs_volume: bool = any(
                    bool(v.get("efsVolumeConfiguration")) for v in volumes
                )

                # Container definitions — SECURITY: env values NEVER stored
                container_defs: list[dict] = td.get("containerDefinitions") or []
                container_count: int = len(container_defs)
                total_env_key_count: int = 0
                total_env_sensitive_count: int = 0
                total_secret_ref_count: int = 0
                has_privileged_container: bool = False
                has_readonly_root: bool = False  # track if ALL containers have it
                any_readonly_root: bool = False
                log_driver_types: set[str] = set()

                for cdef in container_defs:
                    # Env vars — keys only
                    env_list = cdef.get("environment") or []
                    _, ek_count, es_count = _ecs_env_key_info(env_list)
                    total_env_key_count += ek_count
                    total_env_sensitive_count += es_count

                    # Secret references — count only
                    secrets_list = cdef.get("secrets") or []
                    total_secret_ref_count += _ecs_secret_ref_count(secrets_list)

                    # Privileged container flag
                    if cdef.get("privileged"):
                        has_privileged_container = True

                    # Read-only root filesystem
                    if cdef.get("readonlyRootFilesystem"):
                        any_readonly_root = True

                    # Log driver (driver name only, not config options)
                    log_cfg: dict = cdef.get("logConfiguration") or {}
                    driver = log_cfg.get("logDriver") or ""
                    if driver:
                        log_driver_types.add(driver)

                td_tags = td_resp.get("tags") or []
                td_tag_keys = _extract_tag_keys(td_tags)
                td_name_sensitivity = _classify_container_name_sensitivity(td_family)

                td_stable_id = f"{account_id}/{region}/{td_family}:{td_revision}"
                records.append({
                    "record_type":                  AWS_ECS_TASK_DEFINITION,
                    "record_id":                    td_stable_id,
                    "external_id":                  td_arn,
                    "name":                         f"{td_family}:{td_revision}",
                    "account_id":                   account_id,
                    "region":                       region,
                    "family":                       td_family,
                    "revision":                     td_revision,
                    "status":                       td_status,
                    "network_mode":                 td_network_mode,
                    "requires_compatibilities":     td_requires_compat if td_requires_compat else None,
                    "cpu":                          td_cpu,
                    "memory":                       td_memory,
                    "task_role_arn_hash":           td_task_role_hash,
                    "execution_role_arn_hash":      td_exec_role_hash,
                    "container_count":              container_count,
                    "volume_count":                 volume_count,
                    "has_efs_volume":               has_efs_volume,
                    "env_key_count":                total_env_key_count,
                    "env_sensitive_key_count":      total_env_sensitive_count,
                    "secret_ref_count":             total_secret_ref_count,
                    "has_privileged_container":     has_privileged_container,
                    "any_readonly_root_filesystem": any_readonly_root,
                    "log_driver_types":             sorted(log_driver_types) if log_driver_types else None,
                    "name_sensitivity":             td_name_sensitivity,
                    "tag_keys":                     td_tag_keys,
                })
            except Exception as exc:
                fc = classify_aws_ecs_failure("DescribeTaskDefinition", exc)
                logger.warning(
                    "aws: DescribeTaskDefinition failed  arn=%s  code=%s",
                    td_arn[:40], fc.error_code,
                )

        return records

    # ── M46: EKS fetch methods ─────────────────────────────────────────────────

    def _fetch_eks_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch EKS cluster, node group, Fargate profile, and add-on posture.

        SECURITY:
        - Kubernetes API NEVER called.
        - Kubernetes pods, Secrets, ConfigMaps, events, logs NEVER accessed.
        - No write operations performed.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                eks_client = self._make_client("eks", credentials, region=region)
                region_records = self._fetch_eks_in_region(eks_client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: eks fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: eks fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_eks_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize EKS resources in a single region.

        SECURITY:
        - Kubernetes API NEVER called.
        - No pod, secret, configmap, or log data accessed.
        - Role and endpoint ARNs hashed before storage.
        """
        records: list[dict] = []

        # ── ListClusters (paginated) ──────────────────────────────────────────
        cluster_names: list[str] = []
        try:
            kwargs: dict = {}
            while True:
                try:
                    resp = self._call_aws(client.list_clusters, **kwargs)
                except Exception as exc:
                    fc = classify_aws_eks_failure("ListClusters", exc)
                    logger.warning(
                        "aws: EKS ListClusters failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    return records
                cluster_names.extend(resp.get("clusters") or [])
                next_token = resp.get("nextToken")
                if next_token:
                    kwargs["nextToken"] = next_token
                else:
                    break
        except Exception:
            logger.warning(
                "aws: EKS ListClusters unexpected  region=%s", region, exc_info=True,
            )
            return records

        for cluster_name in cluster_names:
            cluster_warnings: list[str] = []

            # ── DescribeCluster ───────────────────────────────────────────────
            cluster: dict = {}
            try:
                desc_resp = self._call_aws(client.describe_cluster, name=cluster_name)
                cluster = desc_resp.get("cluster") or {}
            except Exception as exc:
                fc = classify_aws_eks_failure("DescribeCluster", exc)
                cluster_warnings.append(f"DescribeCluster: {fc.error_code}")

            status_cluster: str = cluster.get("status") or "UNKNOWN"
            k8s_version: str = cluster.get("version") or "unknown"
            platform_version: str = cluster.get("platformVersion") or ""
            role_arn: str = cluster.get("roleArn") or ""
            role_arn_hash: str | None = (
                _hash_kms_key_id(role_arn) if role_arn else None
            )

            # Kubernetes network config
            k8s_network_cfg: dict = cluster.get("kubernetesNetworkConfig") or {}
            ip_family: str = k8s_network_cfg.get("ipFamily") or "ipv4"

            # Resources VPC config — SECURITY: store posture booleans, not subnet/SG IDs
            resources_vpc: dict = cluster.get("resourcesVpcConfig") or {}
            endpoint_public_access: bool = bool(
                resources_vpc.get("endpointPublicAccess", True)
            )
            endpoint_private_access: bool = bool(
                resources_vpc.get("endpointPrivateAccess", False)
            )
            public_access_cidrs: list[str] = sorted(
                resources_vpc.get("publicAccessCidrs") or []
            )
            public_access_fully_open: bool = (
                endpoint_public_access
                and _eks_public_access_cidrs_open(public_access_cidrs)
            )
            subnet_count: int = len(resources_vpc.get("subnetIds") or [])
            security_group_count: int = len(
                resources_vpc.get("securityGroupIds") or []
            )

            # Logging config
            logging_cfg: dict = cluster.get("logging") or {}
            enabled_log_types: list[str] = []
            for log_setup in logging_cfg.get("clusterLogging") or []:
                if log_setup.get("enabled"):
                    enabled_log_types.extend(log_setup.get("types") or [])
            enabled_log_types = sorted(set(enabled_log_types))
            has_audit_logging: bool = "audit" in enabled_log_types

            # Encryption config — KMS presence only
            encryption_configs: list[dict] = cluster.get("encryptionConfig") or []
            secrets_encryption_enabled: bool = any(
                "secrets" in (ec.get("resources") or [])
                for ec in encryption_configs
            )
            kms_key_hash: str | None = None
            for ec in encryption_configs:
                provider = ec.get("provider") or {}
                key_arn = provider.get("keyArn") or ""
                if key_arn:
                    kms_key_hash = _hash_kms_key_id(key_arn)
                    break

            # Add-ons and node groups will be added separately below
            name_sensitivity = _classify_container_name_sensitivity(cluster_name)
            tag_keys = _extract_tag_keys(
                [{"Key": k, "Value": v} for k, v in (cluster.get("tags") or {}).items()]
            )

            stable_id = f"{account_id}/{region}/{cluster_name}"
            records.append({
                "record_type":                    AWS_EKS_CLUSTER,
                "record_id":                      stable_id,
                "external_id":                    cluster.get("arn") or stable_id,
                "name":                           cluster_name,
                "account_id":                     account_id,
                "region":                         region,
                "status":                         status_cluster,
                "kubernetes_version":             k8s_version,
                "platform_version":               platform_version,
                "role_arn_hash":                  role_arn_hash,
                "endpoint_public_access":         endpoint_public_access,
                "endpoint_private_access":        endpoint_private_access,
                "public_access_fully_open":       public_access_fully_open,
                "public_access_cidrs_count":      len(public_access_cidrs),
                "subnet_count":                   subnet_count,
                "security_group_count":           security_group_count,
                "ip_family":                      ip_family,
                "enabled_log_types":              enabled_log_types if enabled_log_types else None,
                "has_audit_logging":              has_audit_logging,
                "secrets_encryption_enabled":     secrets_encryption_enabled,
                "kms_key_hash":                   kms_key_hash,
                "name_sensitivity":               name_sensitivity,
                "tag_keys":                       tag_keys,
                "config_fetch_warnings":          cluster_warnings if cluster_warnings else None,
            })

            # ── ListNodegroups ────────────────────────────────────────────────
            ng_names: list[str] = []
            try:
                ng_kwargs: dict = {"clusterName": cluster_name}
                while True:
                    try:
                        ng_resp = self._call_aws(client.list_nodegroups, **ng_kwargs)
                    except Exception as exc:
                        fc = classify_aws_eks_failure("ListNodegroups", exc)
                        logger.warning(
                            "aws: ListNodegroups failed  cluster=%s  code=%s",
                            cluster_name, fc.error_code,
                        )
                        break
                    ng_names.extend(ng_resp.get("nodegroups") or [])
                    next_token = ng_resp.get("nextToken")
                    if next_token:
                        ng_kwargs["nextToken"] = next_token
                    else:
                        break
            except Exception:
                logger.warning(
                    "aws: EKS ListNodegroups unexpected  cluster=%s",
                    cluster_name, exc_info=True,
                )

            for ng_name in ng_names:
                try:
                    ng_resp = self._call_aws(
                        client.describe_nodegroup,
                        clusterName=cluster_name,
                        nodegroupName=ng_name,
                    )
                    ng: dict = ng_resp.get("nodegroup") or {}

                    ng_status: str = ng.get("status") or "UNKNOWN"
                    ng_capacity_type: str = ng.get("capacityType") or "ON_DEMAND"
                    ng_ami_type: str = ng.get("amiType") or "AL2_x86_64"
                    ng_disk_size: int | None = ng.get("diskSize")
                    ng_instance_types: list[str] = sorted(
                        ng.get("instanceTypes") or []
                    )

                    # Scaling config
                    scaling: dict = ng.get("scalingConfig") or {}
                    ng_min_size: int | None = scaling.get("minSize")
                    ng_max_size: int | None = scaling.get("maxSize")
                    ng_desired_size: int | None = scaling.get("desiredSize")

                    # Node role
                    ng_role_arn: str = ng.get("nodeRole") or ""
                    ng_role_arn_hash: str | None = (
                        _hash_kms_key_id(ng_role_arn) if ng_role_arn else None
                    )

                    # Remote access
                    remote_access: dict = ng.get("remoteAccess") or {}
                    has_remote_access: bool = bool(
                        remote_access.get("ec2SshKey")
                    )
                    source_security_group_count: int = len(
                        remote_access.get("sourceSecurityGroups") or []
                    )
                    ssh_unrestricted: bool = (
                        has_remote_access and source_security_group_count == 0
                    )

                    # Tags
                    ng_tag_keys = _extract_tag_keys(
                        [
                            {"Key": k, "Value": v}
                            for k, v in (ng.get("tags") or {}).items()
                        ]
                    )

                    ng_stable_id = f"{account_id}/{region}/{cluster_name}/ng/{ng_name}"
                    records.append({
                        "record_type":                AWS_EKS_NODE_GROUP,
                        "record_id":                  ng_stable_id,
                        "external_id":                ng.get("nodegroupArn") or ng_stable_id,
                        "name":                       ng_name,
                        "account_id":                 account_id,
                        "region":                     region,
                        "cluster_name":               cluster_name,
                        "status":                     ng_status,
                        "capacity_type":              ng_capacity_type,
                        "ami_type":                   ng_ami_type,
                        "instance_types":             ng_instance_types if ng_instance_types else None,
                        "disk_size":                  ng_disk_size,
                        "min_size":                   ng_min_size,
                        "max_size":                   ng_max_size,
                        "desired_size":               ng_desired_size,
                        "node_role_arn_hash":         ng_role_arn_hash,
                        "has_remote_access":          has_remote_access,
                        "ssh_unrestricted":           ssh_unrestricted,
                        "source_security_group_count": source_security_group_count,
                        "tag_keys":                   ng_tag_keys,
                    })
                except Exception as exc:
                    fc = classify_aws_eks_failure("DescribeNodegroup", exc)
                    logger.warning(
                        "aws: DescribeNodegroup failed  cluster=%s  ng=%s  code=%s",
                        cluster_name, ng_name, fc.error_code,
                    )

            # ── ListFargateProfiles ───────────────────────────────────────────
            fp_names: list[str] = []
            try:
                fp_kwargs: dict = {"clusterName": cluster_name}
                while True:
                    try:
                        fp_resp = self._call_aws(client.list_fargate_profiles, **fp_kwargs)
                    except Exception as exc:
                        fc = classify_aws_eks_failure("ListFargateProfiles", exc)
                        logger.warning(
                            "aws: ListFargateProfiles failed  cluster=%s  code=%s",
                            cluster_name, fc.error_code,
                        )
                        break
                    fp_names.extend(fp_resp.get("fargateProfileNames") or [])
                    next_token = fp_resp.get("nextToken")
                    if next_token:
                        fp_kwargs["nextToken"] = next_token
                    else:
                        break
            except Exception:
                logger.warning(
                    "aws: EKS ListFargateProfiles unexpected  cluster=%s",
                    cluster_name, exc_info=True,
                )

            for fp_name in fp_names:
                try:
                    fp_desc_resp = self._call_aws(
                        client.describe_fargate_profile,
                        clusterName=cluster_name,
                        fargateProfileName=fp_name,
                    )
                    fp: dict = fp_desc_resp.get("fargateProfile") or {}

                    fp_status: str = fp.get("status") or "UNKNOWN"
                    fp_role_arn: str = fp.get("podExecutionRoleArn") or ""
                    fp_role_hash: str | None = (
                        _hash_kms_key_id(fp_role_arn) if fp_role_arn else None
                    )
                    # Selectors — store count and namespace names (not labels)
                    selectors: list[dict] = fp.get("selectors") or []
                    selector_count: int = len(selectors)
                    selector_namespaces: list[str] = sorted(
                        s.get("namespace") or ""
                        for s in selectors
                        if s.get("namespace")
                    )
                    fp_subnet_count: int = len(fp.get("subnets") or [])
                    fp_tag_keys = _extract_tag_keys(
                        [
                            {"Key": k, "Value": v}
                            for k, v in (fp.get("tags") or {}).items()
                        ]
                    )

                    fp_stable_id = f"{account_id}/{region}/{cluster_name}/fp/{fp_name}"
                    records.append({
                        "record_type":                 AWS_EKS_FARGATE_PROFILE,
                        "record_id":                   fp_stable_id,
                        "external_id":                 fp.get("fargateProfileArn") or fp_stable_id,
                        "name":                        fp_name,
                        "account_id":                  account_id,
                        "region":                      region,
                        "cluster_name":                cluster_name,
                        "status":                      fp_status,
                        "pod_execution_role_arn_hash": fp_role_hash,
                        "selector_count":              selector_count,
                        "selector_namespaces":         selector_namespaces if selector_namespaces else None,
                        "subnet_count":                fp_subnet_count,
                        "tag_keys":                    fp_tag_keys,
                    })
                except Exception as exc:
                    fc = classify_aws_eks_failure("DescribeFargateProfile", exc)
                    logger.warning(
                        "aws: DescribeFargateProfile failed  cluster=%s  fp=%s  code=%s",
                        cluster_name, fp_name, fc.error_code,
                    )

            # ── ListAddons ────────────────────────────────────────────────────
            addon_names: list[str] = []
            try:
                addon_kwargs: dict = {"clusterName": cluster_name}
                while True:
                    try:
                        addon_resp = self._call_aws(client.list_addons, **addon_kwargs)
                    except Exception as exc:
                        fc = classify_aws_eks_failure("ListAddons", exc)
                        logger.warning(
                            "aws: ListAddons failed  cluster=%s  code=%s",
                            cluster_name, fc.error_code,
                        )
                        break
                    addon_names.extend(addon_resp.get("addons") or [])
                    next_token = addon_resp.get("nextToken")
                    if next_token:
                        addon_kwargs["nextToken"] = next_token
                    else:
                        break
            except Exception:
                logger.warning(
                    "aws: EKS ListAddons unexpected  cluster=%s",
                    cluster_name, exc_info=True,
                )

            for addon_name in addon_names:
                try:
                    addon_desc_resp = self._call_aws(
                        client.describe_addon,
                        clusterName=cluster_name,
                        addonName=addon_name,
                    )
                    addon: dict = addon_desc_resp.get("addon") or {}

                    addon_status: str = addon.get("status") or "UNKNOWN"
                    addon_version: str = addon.get("addonVersion") or ""
                    addon_created_at: str = str(addon.get("createdAt") or "")
                    addon_modified_at: str = str(addon.get("modifiedAt") or "")
                    addon_role_arn: str = addon.get("serviceAccountRoleArn") or ""
                    addon_role_hash: str | None = (
                        _hash_kms_key_id(addon_role_arn) if addon_role_arn else None
                    )
                    addon_tag_keys = _extract_tag_keys(
                        [
                            {"Key": k, "Value": v}
                            for k, v in (addon.get("tags") or {}).items()
                        ]
                    )

                    addon_stable_id = (
                        f"{account_id}/{region}/{cluster_name}/addon/{addon_name}"
                    )
                    records.append({
                        "record_type":               AWS_EKS_ADDON,
                        "record_id":                 addon_stable_id,
                        "external_id":               addon.get("addonArn") or addon_stable_id,
                        "name":                      addon_name,
                        "account_id":                account_id,
                        "region":                    region,
                        "cluster_name":              cluster_name,
                        "status":                    addon_status,
                        "addon_version":             addon_version,
                        "service_account_role_hash": addon_role_hash,
                        "tag_keys":                  addon_tag_keys,
                    })
                except Exception as exc:
                    fc = classify_aws_eks_failure("DescribeAddon", exc)
                    logger.warning(
                        "aws: DescribeAddon failed  cluster=%s  addon=%s  code=%s",
                        cluster_name, addon_name, fc.error_code,
                    )

        return records

    # ── M46: ECR fetch methods ─────────────────────────────────────────────────

    def _fetch_ecr_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch ECR repository and registry scanning posture across all regions.

        SECURITY:
        - Images NEVER pulled.
        - Image layers and manifests NEVER accessed.
        - ecr:GetAuthorizationToken NEVER called.
        - Vulnerability scan findings NEVER ingested.
        - Raw repository policy JSON NEVER stored — only boolean summary.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                ecr_client = self._make_client("ecr", credentials, region=region)
                region_records = self._fetch_ecr_in_region(ecr_client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: ecr fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: ecr fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_ecr_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch and normalize ECR resources in a single region.

        SECURITY:
        - ecr:GetAuthorizationToken NEVER called.
        - Images, layers, manifests NEVER accessed.
        - Raw policy JSON NEVER stored — only boolean/count summary.
        - Tag values NEVER stored.
        """
        records: list[dict] = []

        # ── DescribeRepositories (paginated) ──────────────────────────────────
        repositories: list[dict] = []
        try:
            repo_kwargs: dict = {}
            while True:
                try:
                    resp = self._call_aws(client.describe_repositories, **repo_kwargs)
                except Exception as exc:
                    fc = classify_aws_ecr_failure("DescribeRepositories", exc)
                    logger.warning(
                        "aws: DescribeRepositories failed  region=%s  code=%s",
                        region, fc.error_code,
                    )
                    break
                repositories.extend(resp.get("repositories") or [])
                next_token = resp.get("nextToken")
                if next_token:
                    repo_kwargs["nextToken"] = next_token
                else:
                    break
        except Exception:
            logger.warning(
                "aws: ECR DescribeRepositories unexpected  region=%s",
                region, exc_info=True,
            )

        for repo in repositories:
            repo_arn: str = repo.get("repositoryArn") or ""
            repo_name: str = repo.get("repositoryName") or ""
            if not repo_arn:
                continue

            repo_warnings: list[str] = []

            # Basic metadata
            image_tag_mutability: str = repo.get("imageTagMutability") or "MUTABLE"
            tag_immutable: bool = image_tag_mutability == "IMMUTABLE"
            encryption_type: str = (
                (repo.get("encryptionConfiguration") or {}).get("encryptionType") or "AES256"
            )
            kms_key_id: str = (
                (repo.get("encryptionConfiguration") or {}).get("kmsKey") or ""
            )
            kms_key_hash: str | None = (
                _hash_kms_key_id(kms_key_id) if kms_key_id else None
            )

            # Image scanning config
            scan_cfg: dict = repo.get("imageScanningConfiguration") or {}
            scan_on_push: bool = bool(scan_cfg.get("scanOnPush", False))

            # Repository policy — SECURITY: raw JSON never stored
            policy_public: bool = False
            policy_present: bool = False
            try:
                policy_resp = self._call_aws(
                    client.get_repository_policy,
                    repositoryName=repo_name,
                )
                raw_policy: str = policy_resp.get("policyText") or ""
                if raw_policy:
                    policy_present = True
                    policy_public = _ecr_policy_is_public(raw_policy, account_id)
            except ConnectorError as exc:
                if exc.status_code == 400 or (
                    hasattr(exc, "aws_error_code")
                    and exc.aws_error_code == "RepositoryPolicyNotFoundException"
                ):
                    pass  # No policy — safe default
                else:
                    fc = classify_aws_ecr_failure("GetRepositoryPolicy", exc)
                    repo_warnings.append(f"GetRepositoryPolicy: {fc.error_code}")
            except Exception as exc:
                fc = classify_aws_ecr_failure("GetRepositoryPolicy", exc)
                repo_warnings.append(f"GetRepositoryPolicy: {fc.error_code}")

            # Lifecycle policy — presence + rule count only
            lifecycle_present: bool = False
            lifecycle_rule_count: int = 0
            try:
                lc_resp = self._call_aws(
                    client.get_lifecycle_policy,
                    repositoryName=repo_name,
                )
                lc_text: str = lc_resp.get("lifecyclePolicyText") or ""
                if lc_text:
                    lifecycle_present = True
                    try:
                        import json as _json
                        lc_parsed = _json.loads(lc_text)
                        lifecycle_rule_count = len(
                            lc_parsed.get("rules") or []
                        )
                    except Exception:
                        lifecycle_rule_count = 0
            except ConnectorError as exc:
                if exc.status_code == 400 or (
                    hasattr(exc, "aws_error_code")
                    and exc.aws_error_code == "LifecyclePolicyNotFoundException"
                ):
                    pass  # No lifecycle policy — safe default
                else:
                    fc = classify_aws_ecr_failure("GetLifecyclePolicy", exc)
                    repo_warnings.append(f"GetLifecyclePolicy: {fc.error_code}")
            except Exception as exc:
                fc = classify_aws_ecr_failure("GetLifecyclePolicy", exc)
                repo_warnings.append(f"GetLifecyclePolicy: {fc.error_code}")

            # Tags
            repo_tag_keys = _extract_tag_keys(repo.get("tags") or [])
            name_sensitivity = _classify_container_name_sensitivity(repo_name)

            repo_stable_id = f"{account_id}/{region}/{repo_name}"
            records.append({
                "record_type":            AWS_ECR_REPOSITORY,
                "record_id":              repo_stable_id,
                "external_id":            repo_arn,
                "name":                   repo_name,
                "account_id":             account_id,
                "region":                 region,
                "image_tag_mutability":   image_tag_mutability,
                "tag_immutable":          tag_immutable,
                "scan_on_push":           scan_on_push,
                "encryption_type":        encryption_type,
                "kms_key_hash":           kms_key_hash,
                "policy_present":         policy_present,
                "policy_is_public":       policy_public,
                "lifecycle_policy_present": lifecycle_present,
                "lifecycle_rule_count":   lifecycle_rule_count,
                "name_sensitivity":       name_sensitivity,
                "tag_keys":               repo_tag_keys,
                "config_fetch_warnings":  repo_warnings if repo_warnings else None,
            })

        # ── GetRegistryScanningConfiguration (one per region) ─────────────────
        try:
            scan_config_resp = self._call_aws(client.get_registry_scanning_configuration)
            scan_type: str = scan_config_resp.get("scanType") or "BASIC"
            scan_rules: list[dict] = scan_config_resp.get("rules") or []
            rule_count: int = len(scan_rules)
            # Summarize filters (repo filter strings are not PII)
            repo_filter_count: int = sum(
                len(rule.get("repositoryFilters") or []) for rule in scan_rules
            )
            scan_freq_types: list[str] = sorted(set(
                rule.get("scanFrequency") or "" for rule in scan_rules
                if rule.get("scanFrequency")
            ))

            scan_stable_id = f"{account_id}/{region}/ecr-registry-scanning"
            records.append({
                "record_type":           AWS_ECR_REGISTRY_SCANNING_CONFIG,
                "record_id":             scan_stable_id,
                "external_id":           scan_stable_id,
                "name":                  f"ecr-registry-scanning-{region}",
                "account_id":            account_id,
                "region":                region,
                "scan_type":             scan_type,
                "rule_count":            rule_count,
                "repo_filter_count":     repo_filter_count,
                "scan_frequency_types":  scan_freq_types if scan_freq_types else None,
            })
        except Exception as exc:
            fc = classify_aws_ecr_failure("GetRegistryScanningConfiguration", exc)
            logger.warning(
                "aws: GetRegistryScanningConfiguration failed  region=%s  code=%s",
                region, fc.error_code,
            )

        return records

    # ── M47: EventBridge fetch methods ────────────────────────────────────────

    def _fetch_eventbridge_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch EventBridge event buses, rules, targets, and archives across all regions.

        SECURITY:
        - events:PutEvents NEVER called.
        - EventBridge event payloads NEVER read or stored.
        - Only bus/rule/target/archive configuration posture metadata collected.
        - No write operations performed.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                eb_client = self._make_client("events", credentials, region=region)
                region_records = self._fetch_eventbridge_in_region(eb_client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: eventbridge fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: eventbridge fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_eventbridge_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch EventBridge buses, rules, targets, and archives for one region.

        SECURITY: event payloads are NEVER read. events:PutEvents NEVER called.
        """
        records: list[dict] = []

        # ── ListEventBuses (paginated) ─────────────────────────────────────────
        buses: list[dict] = []
        try:
            kwargs: dict = {}
            while True:
                response = self._call_aws(client.list_event_buses, **kwargs)
                buses.extend(response.get("EventBuses") or [])
                next_token = response.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except Exception as exc:
            fc = classify_aws_eventbridge_failure("ListEventBuses", exc)
            logger.warning(
                "aws: ListEventBuses failed  region=%s  code=%s",
                region, fc.error_code,
            )
            return records  # cannot proceed without bus list

        for bus in buses:
            bus_name: str = bus.get("Name") or "default"
            bus_arn: str = bus.get("Arn") or ""
            bus_warnings: list[str] = []

            # ── DescribeEventBus — policy details ──────────────────────────────
            policy_present = False
            policy_is_public = False
            try:
                desc = self._call_aws(client.describe_event_bus, Name=bus_name)
                raw_policy: str = desc.get("Policy") or ""
                if raw_policy:
                    policy_present = True
                    # SECURITY: raw policy JSON never stored, only boolean
                    policy_is_public = _messaging_policy_is_public(raw_policy, account_id)
            except Exception as exc:
                fc = classify_aws_eventbridge_failure("DescribeEventBus", exc)
                bus_warnings.append(f"DescribeEventBus: {fc.error_code}")

            # ── Tags — ListTagsForResource ─────────────────────────────────────
            tag_keys: list[str] | None = None
            if bus_arn:
                try:
                    tags_resp = self._call_aws(
                        client.list_tags_for_resource, ResourceARN=bus_arn
                    )
                    raw_tags = tags_resp.get("Tags") or []
                    tag_keys = sorted({t["Key"] for t in raw_tags if "Key" in t}) or None
                except Exception as exc:
                    fc = classify_aws_eventbridge_failure("ListTagsForResource", exc)
                    bus_warnings.append(f"ListTagsForResource: {fc.error_code}")

            name_sensitivity = _classify_messaging_name_sensitivity(bus_name)
            bus_stable_id = f"{account_id}/{region}/eventbridge-bus/{bus_name}"
            records.append({
                "record_type":              AWS_EVENTBRIDGE_EVENT_BUS,
                "record_id":               bus_stable_id,
                "external_id":             bus_arn,
                "name":                    bus_name,
                "account_id":              account_id,
                "region":                  region,
                "arn_hash":                _hash_arn(bus_arn),
                "policy_present":                  policy_present,
                "public_or_cross_account_policy":  policy_is_public,
                "name_sensitivity":                name_sensitivity,
                "tag_keys":                        tag_keys,
                "config_fetch_warnings":           bus_warnings if bus_warnings else None,
            })

            # ── ListRules per bus (paginated) ──────────────────────────────────
            rules: list[dict] = []
            try:
                kwargs = {"EventBusName": bus_name}
                while True:
                    response = self._call_aws(client.list_rules, **kwargs)
                    rules.extend(response.get("Rules") or [])
                    next_token = response.get("NextToken")
                    if not next_token:
                        break
                    kwargs["NextToken"] = next_token
            except Exception as exc:
                fc = classify_aws_eventbridge_failure("ListRules", exc)
                logger.warning(
                    "aws: ListRules failed  region=%s  bus=%s  code=%s",
                    region, bus_name, fc.error_code,
                )
                continue  # skip rules for this bus

            for rule in rules:
                rule_name: str = rule.get("Name") or ""
                rule_arn: str = rule.get("Arn") or ""
                rule_state: str = rule.get("State") or "UNKNOWN"
                schedule_expression: str = rule.get("ScheduleExpression") or ""
                event_pattern_raw: str = rule.get("EventPattern") or ""
                rule_warnings: list[str] = []

                # ── ListTargetsByRule (paginated) ──────────────────────────────
                targets: list[dict] = []
                try:
                    kwargs = {"Rule": rule_name, "EventBusName": bus_name}
                    while True:
                        response = self._call_aws(client.list_targets_by_rule, **kwargs)
                        targets.extend(response.get("Targets") or [])
                        next_token = response.get("NextToken")
                        if not next_token:
                            break
                        kwargs["NextToken"] = next_token
                except Exception as exc:
                    fc = classify_aws_eventbridge_failure("ListTargetsByRule", exc)
                    rule_warnings.append(f"ListTargetsByRule: {fc.error_code}")

                # Summarize target types (no raw ARNs stored)
                target_count = len(targets)
                target_type_counts: dict[str, int] = {}
                dlq_target_present = False
                retry_policy_present = False
                for tgt in targets:
                    ttype = _summarize_target_type(tgt.get("Arn") or "")
                    target_type_counts[ttype] = target_type_counts.get(ttype, 0) + 1
                    if tgt.get("DeadLetterConfig") and (tgt["DeadLetterConfig"].get("Arn")):
                        dlq_target_present = True
                    if tgt.get("RetryPolicy"):
                        retry_policy_present = True

                # Tags for rule
                rule_tag_keys: list[str] | None = None
                if rule_arn:
                    try:
                        tags_resp = self._call_aws(
                            client.list_tags_for_resource, ResourceARN=rule_arn
                        )
                        raw_tags = tags_resp.get("Tags") or []
                        rule_tag_keys = sorted({t["Key"] for t in raw_tags if "Key" in t}) or None
                    except Exception as exc:
                        fc = classify_aws_eventbridge_failure("ListTagsForResource", exc)
                        rule_warnings.append(f"ListTagsForResource: {fc.error_code}")

                rule_name_sensitivity = _classify_messaging_name_sensitivity(rule_name)
                rule_stable_id = f"{account_id}/{region}/eventbridge-rule/{bus_name}/{rule_name}"
                records.append({
                    "record_type":              AWS_EVENTBRIDGE_RULE,
                    "record_id":               rule_stable_id,
                    "external_id":             rule_arn,
                    "name":                    rule_name,
                    "account_id":              account_id,
                    "region":                  region,
                    "event_bus_name":          bus_name,
                    "arn_hash":                _hash_arn(rule_arn),
                    "state":                   rule_state,
                    "schedule_expression_present": bool(schedule_expression),
                    "event_pattern_present":   bool(event_pattern_raw),
                    # SECURITY: raw event pattern never stored — hash only
                    "event_pattern_hash":      _hash_event_pattern(event_pattern_raw),
                    "target_count":            target_count,
                    "target_type_counts":      target_type_counts if target_type_counts else None,
                    "dlq_target_present":      dlq_target_present,
                    "retry_policy_present":    retry_policy_present,
                    "name_sensitivity":        rule_name_sensitivity,
                    "tag_keys":                rule_tag_keys,
                    "config_fetch_warnings":   rule_warnings if rule_warnings else None,
                })

                # ── Target records ─────────────────────────────────────────────
                for tgt in targets:
                    tgt_id: str = tgt.get("Id") or ""
                    tgt_arn: str = tgt.get("Arn") or ""
                    tgt_id_hash = _hash_arn(tgt_id) or _hash_arn(tgt_arn) or "unknown"
                    tgt_role_arn: str = tgt.get("RoleArn") or ""
                    dlq_arn: str = (tgt.get("DeadLetterConfig") or {}).get("Arn") or ""
                    retry_cfg = tgt.get("RetryPolicy") or {}
                    input_transformer = tgt.get("InputTransformer")
                    input_path = tgt.get("InputPath")
                    raw_input = tgt.get("Input")

                    tgt_stable_id = (
                        f"{account_id}/{region}/eventbridge-target"
                        f"/{bus_name}/{rule_name}/{tgt_id_hash}"
                    )
                    records.append({
                        "record_type":              AWS_EVENTBRIDGE_TARGET,
                        "record_id":               tgt_stable_id,
                        "external_id":             tgt_stable_id,
                        "name":                    f"target-{tgt_id_hash}",
                        "account_id":              account_id,
                        "region":                  region,
                        "event_bus_name":          bus_name,
                        "rule_name":               rule_name,
                        "target_id_hash":          tgt_id_hash,
                        # SECURITY: raw ARN never stored
                        "target_arn_hash":         _hash_arn(tgt_arn),
                        "target_type":             _summarize_target_type(tgt_arn),
                        "role_arn_present":        bool(tgt_role_arn),
                        "role_arn_hash":           _hash_arn(tgt_role_arn),
                        "dead_letter_config_present": bool(dlq_arn),
                        "dead_letter_arn_hash":    _hash_arn(dlq_arn),
                        "retry_policy_present":    bool(retry_cfg),
                        "retry_max_event_age_seconds": retry_cfg.get("MaximumEventAgeInSeconds"),
                        "retry_max_attempts":      retry_cfg.get("MaximumRetryAttempts"),
                        "input_transformer_present": bool(input_transformer),
                        "input_path_present":      bool(input_path),
                        # SECURITY: raw input/payload never stored — boolean only
                        "input_present":           bool(raw_input),
                        "config_fetch_warnings":   None,
                    })

        # ── ListArchives (paginated) ───────────────────────────────────────────
        try:
            archives: list[dict] = []
            kwargs = {}
            while True:
                response = self._call_aws(client.list_archives, **kwargs)
                archives.extend(response.get("Archives") or [])
                next_token = response.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token

            for archive in archives:
                archive_name: str = archive.get("ArchiveName") or ""
                archive_arn: str = archive.get("ArchiveArn") or ""
                event_source_arn: str = archive.get("EventSourceArn") or ""
                archive_state: str = archive.get("State") or "UNKNOWN"
                retention_days: int | None = archive.get("RetentionDays")
                event_count: int | None = archive.get("EventCount")
                size_bytes: int | None = archive.get("SizeBytes")

                archive_stable_id = f"{account_id}/{region}/eventbridge-archive/{archive_name}"
                records.append({
                    "record_type":              AWS_EVENTBRIDGE_ARCHIVE,
                    "record_id":               archive_stable_id,
                    "external_id":             archive_arn,
                    "name":                    archive_name,
                    "account_id":              account_id,
                    "region":                  region,
                    "arn_hash":                _hash_arn(archive_arn),
                    # SECURITY: event source ARN hashed, not stored raw
                    "event_source_arn_hash":   _hash_arn(event_source_arn),
                    "state":                   archive_state,
                    "retention_days":          retention_days,
                    "event_count":             event_count,
                    "size_bytes":              size_bytes,
                    "config_fetch_warnings":   None,
                })
        except Exception as exc:
            fc = classify_aws_eventbridge_failure("ListArchives", exc)
            logger.warning(
                "aws: ListArchives failed  region=%s  code=%s",
                region, fc.error_code,
            )

        return records

    # ── M47: SQS fetch methods ────────────────────────────────────────────────

    def _fetch_sqs_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch SQS queue configuration posture across all regions.

        SECURITY:
        - sqs:ReceiveMessage NEVER called.
        - sqs:SendMessage NEVER called.
        - sqs:DeleteMessage NEVER called.
        - sqs:PurgeQueue NEVER called.
        - Message bodies and queue contents NEVER read or stored.
        - Only queue configuration metadata is collected.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                sqs_client = self._make_client("sqs", credentials, region=region)
                region_records = self._fetch_sqs_in_region(sqs_client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: sqs fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: sqs fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_sqs_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch SQS queues for one region.

        SECURITY: message bodies NEVER read. ReceiveMessage/SendMessage/DeleteMessage/PurgeQueue NEVER called.
        """
        records: list[dict] = []

        # ── ListQueues (paginated) ─────────────────────────────────────────────
        queue_urls: list[str] = []
        try:
            kwargs: dict = {}
            while True:
                response = self._call_aws(client.list_queues, **kwargs)
                queue_urls.extend(response.get("QueueUrls") or [])
                next_token = response.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except Exception as exc:
            fc = classify_aws_sqs_failure("ListQueues", exc)
            logger.warning(
                "aws: ListQueues failed  region=%s  code=%s",
                region, fc.error_code,
            )
            return records

        for queue_url in queue_urls:
            queue_warnings: list[str] = []

            # Extract queue name from URL (last path segment)
            queue_name = queue_url.rstrip("/").rsplit("/", 1)[-1]

            # ── GetQueueAttributes ─────────────────────────────────────────────
            attrs: dict = {}
            try:
                resp = self._call_aws(
                    client.get_queue_attributes,
                    QueueUrl=queue_url,
                    AttributeNames=["All"],
                )
                attrs = resp.get("Attributes") or {}
            except Exception as exc:
                fc = classify_aws_sqs_failure("GetQueueAttributes", exc)
                queue_warnings.append(f"GetQueueAttributes: {fc.error_code}")

            # Safe attribute extraction — never read MessageBody
            queue_arn = attrs.get("QueueArn") or ""
            fifo_queue = attrs.get("FifoQueue", "false").lower() == "true"
            content_based_dedup = attrs.get("ContentBasedDeduplication", "false").lower() == "true"
            sqs_managed_sse = attrs.get("SqsManagedSseEnabled", "false").lower() == "true"
            kms_key_raw = attrs.get("KmsMasterKeyId") or ""
            kms_key_present = bool(kms_key_raw)
            kms_key_hash = _hash_arn(kms_key_raw) if kms_key_raw else None

            def _safe_int(val: str | None) -> int | None:
                try:
                    return int(val) if val is not None else None
                except (ValueError, TypeError):
                    return None

            visibility_timeout = _safe_int(attrs.get("VisibilityTimeout"))
            message_retention = _safe_int(attrs.get("MessageRetentionPeriod"))
            delay_seconds = _safe_int(attrs.get("DelaySeconds"))
            max_message_size = _safe_int(attrs.get("MaximumMessageSize"))
            receive_wait_time = _safe_int(attrs.get("ReceiveMessageWaitTimeSeconds"))
            approx_msgs = _safe_int(attrs.get("ApproximateNumberOfMessages"))
            approx_msgs_not_visible = _safe_int(attrs.get("ApproximateNumberOfMessagesNotVisible"))
            approx_msgs_delayed = _safe_int(attrs.get("ApproximateNumberOfMessagesDelayed"))

            # Redrive policy — parse JSON, store only structural metadata
            redrive_raw = attrs.get("RedrivePolicy") or ""
            redrive_present = bool(redrive_raw)
            dlq_arn_hash: str | None = None
            max_receive_count: int | None = None
            if redrive_raw:
                try:
                    import json as _json
                    rdp = _json.loads(redrive_raw)
                    dlq_arn_hash = _hash_arn(rdp.get("deadLetterTargetArn") or "")
                    max_receive_count = _safe_int(str(rdp.get("maxReceiveCount") or ""))
                except Exception:
                    queue_warnings.append("RedrivePolicy: parse error")

            # Redrive allow policy
            redrive_allow_raw = attrs.get("RedriveAllowPolicy") or ""
            redrive_allow_summary = _summarize_redrive_allow_policy(redrive_allow_raw)

            # Queue policy — parse for public access, never store raw
            policy_raw = attrs.get("Policy") or ""
            policy_present = bool(policy_raw)
            policy_is_public = False
            if policy_raw:
                # SECURITY: raw policy JSON never stored
                policy_is_public = _messaging_policy_is_public(policy_raw, account_id)

            # ── ListQueueTags ──────────────────────────────────────────────────
            tag_keys: list[str] | None = None
            try:
                tags_resp = self._call_aws(client.list_queue_tags, QueueUrl=queue_url)
                # SECURITY: tag values never stored — keys only
                raw_tags = tags_resp.get("Tags") or {}
                tag_keys = sorted(raw_tags.keys()) or None
            except Exception as exc:
                fc = classify_aws_sqs_failure("ListQueueTags", exc)
                queue_warnings.append(f"ListQueueTags: {fc.error_code}")

            name_sensitivity = _classify_messaging_name_sensitivity(queue_name)
            queue_stable_id = f"{account_id}/{region}/sqs/{queue_name}"
            records.append({
                "record_type":                          AWS_SQS_QUEUE,
                "record_id":                            queue_stable_id,
                "external_id":                          queue_stable_id,
                "name":                                 queue_name,
                "account_id":                           account_id,
                "region":                               region,
                # SECURITY: raw URL and ARN never stored as-is — hashed
                "queue_url_hash":                       _hash_endpoint(queue_url),
                "queue_arn_hash":                       _hash_arn(queue_arn),
                "fifo_queue":                           fifo_queue,
                "content_based_deduplication":          content_based_dedup,
                "sqs_managed_sse_enabled":              sqs_managed_sse,
                "kms_master_key_id_present":            kms_key_present,
                "kms_master_key_id_hash":               kms_key_hash,
                "visibility_timeout":                   visibility_timeout,
                "message_retention_period":             message_retention,
                "delay_seconds":                        delay_seconds,
                "maximum_message_size":                 max_message_size,
                "long_polling_wait_time_seconds":        receive_wait_time,
                "redrive_policy_present":               redrive_present,
                "dead_letter_target_arn_hash":          dlq_arn_hash,
                "max_receive_count":                    max_receive_count,
                "redrive_allow_policy_summary":         redrive_allow_summary,
                "policy_present":                       policy_present,
                "public_or_cross_account_policy":       policy_is_public,
                "approximate_number_of_messages":       approx_msgs,
                "approximate_number_of_messages_not_visible": approx_msgs_not_visible,
                "approximate_number_of_messages_delayed": approx_msgs_delayed,
                "name_sensitivity":                     name_sensitivity,
                "tag_keys":                             tag_keys,
                "config_fetch_warnings":                queue_warnings if queue_warnings else None,
            })

        return records

    # ── M47: SNS fetch methods ────────────────────────────────────────────────

    def _fetch_sns_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch SNS topic and subscription configuration posture across all regions.

        SECURITY:
        - sns:Publish NEVER called.
        - Notification contents and message bodies NEVER read or stored.
        - Subscription endpoints are hashed; raw email/phone/URL NEVER stored.
        - Only topic and subscription configuration metadata is collected.
        """
        selected_regions = self._selected_regions(credentials)
        all_records: list[dict] = []

        for region in selected_regions:
            try:
                sns_client = self._make_client("sns", credentials, region=region)
                region_records = self._fetch_sns_in_region(sns_client, account_id, region)
                all_records.extend(region_records)
                logger.debug(
                    "aws: sns fetched  region=%s  count=%d",
                    region, len(region_records),
                )
            except Exception:
                logger.warning(
                    "aws: sns fetch unexpected error  region=%s",
                    region, exc_info=True,
                )

        return all_records

    def _fetch_sns_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch SNS topics and subscriptions for one region.

        SECURITY: sns:Publish NEVER called. Notification contents NEVER read.
        Raw subscription endpoints NEVER stored — hashed only.
        """
        records: list[dict] = []

        # ── ListTopics (paginated) ─────────────────────────────────────────────
        topic_arns: list[str] = []
        try:
            kwargs: dict = {}
            while True:
                response = self._call_aws(client.list_topics, **kwargs)
                for t in response.get("Topics") or []:
                    arn = t.get("TopicArn") or ""
                    if arn:
                        topic_arns.append(arn)
                next_token = response.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except Exception as exc:
            fc = classify_aws_sns_failure("ListTopics", exc)
            logger.warning(
                "aws: ListTopics failed  region=%s  code=%s",
                region, fc.error_code,
            )
            return records

        for topic_arn in topic_arns:
            topic_warnings: list[str] = []

            # Extract topic name from ARN (last segment)
            topic_name = topic_arn.rsplit(":", 1)[-1] if ":" in topic_arn else topic_arn

            # ── GetTopicAttributes ─────────────────────────────────────────────
            attrs: dict = {}
            try:
                resp = self._call_aws(client.get_topic_attributes, TopicArn=topic_arn)
                attrs = resp.get("Attributes") or {}
            except Exception as exc:
                fc = classify_aws_sns_failure("GetTopicAttributes", exc)
                topic_warnings.append(f"GetTopicAttributes: {fc.error_code}")

            # FIFO / dedup
            fifo_topic = (attrs.get("FifoTopic") or "false").lower() == "true"
            content_based_dedup = (attrs.get("ContentBasedDeduplication") or "false").lower() == "true"

            # KMS
            kms_key_raw = attrs.get("KmsMasterKeyId") or ""
            kms_key_present = bool(kms_key_raw)
            kms_key_hash = _hash_arn(kms_key_raw) if kms_key_raw else None

            # Delivery / policy — presence only, never raw
            delivery_policy_present = bool(attrs.get("DeliveryPolicy"))
            effective_delivery_policy_present = bool(attrs.get("EffectiveDeliveryPolicy"))

            # Topic policy — parse for public access, never store raw
            policy_raw = attrs.get("Policy") or ""
            policy_present = bool(policy_raw)
            policy_is_public = False
            if policy_raw:
                # SECURITY: raw policy JSON never stored
                policy_is_public = _messaging_policy_is_public(policy_raw, account_id)

            # Subscription counts
            def _safe_int(v: str | None) -> int:
                try:
                    return int(v or 0)
                except (ValueError, TypeError):
                    return 0

            confirmed_count = _safe_int(attrs.get("SubscriptionsConfirmed"))
            pending_count = _safe_int(attrs.get("SubscriptionsPending"))
            deleted_count = _safe_int(attrs.get("SubscriptionsDeleted"))
            subscription_count = confirmed_count + pending_count

            # ── Tags — ListTagsForResource ─────────────────────────────────────
            tag_keys: list[str] | None = None
            try:
                tags_resp = self._call_aws(
                    client.list_tags_for_resource, ResourceArn=topic_arn
                )
                raw_tags = tags_resp.get("Tags") or []
                # SECURITY: tag values never stored — keys only
                tag_keys = sorted({t["Key"] for t in raw_tags if "Key" in t}) or None
            except Exception as exc:
                fc = classify_aws_sns_failure("ListTagsForResource", exc)
                topic_warnings.append(f"ListTagsForResource: {fc.error_code}")

            # ── ListSubscriptionsByTopic (paginated) ───────────────────────────
            subscriptions: list[dict] = []
            protocol_counts: dict[str, int] = {}
            try:
                kwargs = {"TopicArn": topic_arn}
                while True:
                    response = self._call_aws(client.list_subscriptions_by_topic, **kwargs)
                    for sub in response.get("Subscriptions") or []:
                        subscriptions.append(sub)
                        proto = (sub.get("Protocol") or "unknown").lower()
                        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
                    next_token = response.get("NextToken")
                    if not next_token:
                        break
                    kwargs["NextToken"] = next_token
            except Exception as exc:
                fc = classify_aws_sns_failure("ListSubscriptionsByTopic", exc)
                topic_warnings.append(f"ListSubscriptionsByTopic: {fc.error_code}")

            name_sensitivity = _classify_messaging_name_sensitivity(topic_name)
            topic_arn_hash = _hash_arn(topic_arn) or ""
            topic_stable_id = f"{account_id}/{region}/sns/{topic_arn_hash}"
            records.append({
                "record_type":                          AWS_SNS_TOPIC,
                "record_id":                            topic_stable_id,
                "external_id":                          topic_arn,
                "name":                                 topic_name,
                "account_id":                           account_id,
                "region":                               region,
                # SECURITY: raw ARN not stored as primary key — hash only
                "topic_arn_hash":                       topic_arn_hash,
                "fifo_topic":                           fifo_topic,
                "content_based_deduplication":          content_based_dedup,
                "kms_master_key_id_present":            kms_key_present,
                "kms_master_key_id_hash":               kms_key_hash,
                "delivery_policy_present":              delivery_policy_present,
                "effective_delivery_policy_present":    effective_delivery_policy_present,
                "policy_present":                       policy_present,
                "public_or_cross_account_policy":       policy_is_public,
                "subscription_count":                   subscription_count,
                "confirmed_subscription_count":         confirmed_count,
                "pending_subscription_count":           pending_count,
                "subscription_protocol_counts":         protocol_counts if protocol_counts else None,
                "name_sensitivity":                     name_sensitivity,
                "tag_keys":                             tag_keys,
                "config_fetch_warnings":                topic_warnings if topic_warnings else None,
            })

            # ── Subscription records ───────────────────────────────────────────
            for sub in subscriptions:
                sub_arn: str = sub.get("SubscriptionArn") or ""
                # Skip pending subscriptions that have no stable ARN yet
                if sub_arn in ("PendingConfirmation", "Deleted", ""):
                    continue

                protocol: str = (sub.get("Protocol") or "unknown").lower()
                endpoint_raw: str = sub.get("Endpoint") or ""

                # SECURITY: raw endpoint never stored — hash only
                endpoint_hash = _hash_endpoint(endpoint_raw)
                endpoint_type = _classify_endpoint_type(endpoint_raw, protocol)

                # ── GetSubscriptionAttributes (optional) ───────────────────────
                sub_attrs: dict = {}
                sub_warnings: list[str] = []
                try:
                    sub_resp = self._call_aws(
                        client.get_subscription_attributes, SubscriptionArn=sub_arn
                    )
                    sub_attrs = sub_resp.get("Attributes") or {}
                except Exception as exc:
                    fc = classify_aws_sns_failure("GetSubscriptionAttributes", exc)
                    sub_warnings.append(f"GetSubscriptionAttributes: {fc.error_code}")

                confirmation_was_authenticated = (
                    sub_attrs.get("ConfirmationWasAuthenticated") or "false"
                ).lower() == "true"
                pending_confirmation = (
                    sub_attrs.get("PendingConfirmation") or "false"
                ).lower() == "true"
                raw_message_delivery = (
                    sub_attrs.get("RawMessageDelivery") or "false"
                ).lower() == "true"

                filter_policy_raw = sub_attrs.get("FilterPolicy") or ""
                filter_policy_present = bool(filter_policy_raw)
                # SECURITY: raw filter policy never stored — hash only
                filter_policy_hash = _hash_filter_policy(filter_policy_raw)

                redrive_policy_present = bool(sub_attrs.get("RedrivePolicy"))
                delivery_policy_present = bool(sub_attrs.get("DeliveryPolicy"))

                sub_arn_hash = _hash_arn(sub_arn) or ""
                sub_stable_id = f"{account_id}/{region}/sns-sub/{sub_arn_hash}"
                records.append({
                    "record_type":                      AWS_SNS_SUBSCRIPTION,
                    "record_id":                        sub_stable_id,
                    "external_id":                      sub_arn,
                    "name":                             f"sub-{protocol}-{endpoint_hash or 'unknown'}",
                    "account_id":                       account_id,
                    "region":                           region,
                    "topic_arn_hash":                   topic_arn_hash,
                    "subscription_arn_hash":            sub_arn_hash,
                    "protocol":                         protocol,
                    # SECURITY: raw endpoint never stored
                    "endpoint_hash":                    endpoint_hash,
                    "endpoint_type":                    endpoint_type,
                    "confirmation_was_authenticated":   confirmation_was_authenticated,
                    "pending_confirmation":             pending_confirmation,
                    "raw_message_delivery":             raw_message_delivery,
                    "filter_policy_present":            filter_policy_present,
                    "filter_policy_hash":               filter_policy_hash,
                    "redrive_policy_present":           redrive_policy_present,
                    "delivery_policy_present":          delivery_policy_present,
                    "config_fetch_warnings":            sub_warnings if sub_warnings else None,
                })

        return records

    # ── M48: KMS fetch methods ────────────────────────────────────────────────

    def _fetch_kms_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch KMS key and alias configuration posture across all regions.

        SECURITY:
        - kms:Decrypt NEVER called.
        - kms:Encrypt NEVER called.
        - kms:GenerateDataKey NEVER called.
        - No cryptographic operations performed.
        - Only key configuration posture metadata is collected.
        """
        records: list[dict] = []
        selected = self._selected_regions(credentials)
        for region in selected:
            try:
                client = self._make_client("kms", credentials, region=region)
                region_records = self._fetch_kms_in_region(client, account_id, region)
                records.extend(region_records)
            except Exception as exc:
                fc = classify_aws_kms_failure("ListKeys", exc)
                logger.warning(
                    "aws: KMS region fetch failed  region=%s  code=%s",
                    region, fc.error_code,
                )
        return records

    def _fetch_kms_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch KMS keys and aliases for one region.

        SECURITY: Cryptographic APIs (Decrypt, Encrypt, GenerateDataKey,
        ReEncrypt, Sign, Verify) NEVER called.
        """
        import json as _json
        records: list[dict] = []

        # ── ListKeys (paginated) ───────────────────────────────────────────────
        key_entries: list[dict] = []
        try:
            kwargs: dict = {}
            while True:
                response = self._call_aws(client.list_keys, **kwargs)
                key_entries.extend(response.get("Keys") or [])
                next_token = response.get("NextMarker")
                if not next_token:
                    break
                kwargs["Marker"] = next_token
        except Exception as exc:
            fc = classify_aws_kms_failure("ListKeys", exc)
            logger.warning(
                "aws: ListKeys failed  region=%s  code=%s",
                region, fc.error_code,
            )
            return records

        for entry in key_entries:
            key_id: str = entry.get("KeyId") or ""
            key_arn: str = entry.get("KeyArn") or ""
            key_warnings: list[str] = []

            # ── DescribeKey ────────────────────────────────────────────────────
            key_meta: dict = {}
            try:
                desc_resp = self._call_aws(client.describe_key, KeyId=key_id)
                key_meta = (desc_resp.get("KeyMetadata") or {})
            except Exception as exc:
                fc = classify_aws_kms_failure("DescribeKey", exc)
                key_warnings.append(f"DescribeKey: {fc.error_code}")

            key_state: str = key_meta.get("KeyState") or "Unknown"
            enabled: bool = key_meta.get("Enabled", False)
            key_usage: str = key_meta.get("KeyUsage") or ""
            key_spec: str = key_meta.get("KeySpec") or key_meta.get("CustomerMasterKeySpec") or ""
            key_manager: str = key_meta.get("KeyManager") or ""
            origin: str = key_meta.get("Origin") or ""
            multi_region: bool = key_meta.get("MultiRegion", False)
            deletion_date_present: bool = bool(key_meta.get("DeletionDate"))
            valid_to_present: bool = bool(key_meta.get("ValidTo"))
            creation_date_present: bool = bool(key_meta.get("CreationDate"))

            # ── GetKeyRotationStatus ───────────────────────────────────────────
            rotation_enabled: bool | None = None
            # Only applicable to symmetric keys managed by AWS KMS
            if key_manager == "CUSTOMER" and origin == "AWS_KMS":
                try:
                    rot_resp = self._call_aws(client.get_key_rotation_status, KeyId=key_id)
                    rotation_enabled = rot_resp.get("KeyRotationEnabled", False)
                except Exception as exc:
                    fc = classify_aws_kms_failure("GetKeyRotationStatus", exc)
                    key_warnings.append(f"GetKeyRotationStatus: {fc.error_code}")

            # ── GetKeyPolicy ───────────────────────────────────────────────────
            policy_present = False
            policy_is_public = False
            wildcard_admin_policy = False
            try:
                pol_resp = self._call_aws(
                    client.get_key_policy, KeyId=key_id, PolicyName="default"
                )
                raw_policy: str = pol_resp.get("Policy") or ""
                if raw_policy:
                    policy_present = True
                    # SECURITY: raw policy never stored
                    policy_is_public = _kms_policy_is_public(raw_policy, account_id)
                    wildcard_admin_policy = _kms_policy_has_wildcard_admin(raw_policy, account_id)
            except Exception as exc:
                fc = classify_aws_kms_failure("GetKeyPolicy", exc)
                key_warnings.append(f"GetKeyPolicy: {fc.error_code}")

            # ── ListResourceTags — keys only ───────────────────────────────────
            tag_keys: list[str] | None = None
            try:
                tags_resp = self._call_aws(client.list_resource_tags, KeyId=key_id)
                raw_tags = tags_resp.get("Tags") or []
                # SECURITY: tag values never stored
                tag_keys = sorted({t["TagKey"] for t in raw_tags if "TagKey" in t}) or None
            except Exception as exc:
                fc = classify_aws_kms_failure("ListResourceTags", exc)
                key_warnings.append(f"ListResourceTags: {fc.error_code}")

            name_sensitivity = _classify_governance_name_sensitivity(key_id)
            key_id_hash = _hash_id(key_id) or "unknown"
            key_stable_id = f"{account_id}/{region}/kms/{key_id_hash}"
            records.append({
                "record_type":                AWS_KMS_KEY,
                "record_id":                  key_stable_id,
                "external_id":                key_stable_id,
                "name":                       f"kms-key-{key_id_hash}",
                "account_id":                 account_id,
                "region":                     region,
                # SECURITY: raw key ID and ARN never stored — hashed
                "key_id_hash":                key_id_hash,
                "key_arn_hash":               _hash_arn(key_arn),
                "key_state":                  key_state,
                "enabled":                    enabled,
                "key_usage":                  key_usage,
                "key_spec":                   key_spec,
                "key_manager":                key_manager,
                "origin":                     origin,
                "multi_region":               multi_region,
                "deletion_date_present":      deletion_date_present,
                "valid_to_present":           valid_to_present,
                "creation_date_present":      creation_date_present,
                "rotation_enabled":           rotation_enabled,
                "policy_present":             policy_present,
                "public_or_cross_account_policy": policy_is_public,
                "wildcard_admin_policy":      wildcard_admin_policy,
                "name_sensitivity":           name_sensitivity,
                "tag_keys":                   tag_keys,
                "config_fetch_warnings":      key_warnings if key_warnings else None,
            })

        # ── ListAliases (paginated) ────────────────────────────────────────────
        try:
            alias_kwargs: dict = {}
            while True:
                alias_resp = self._call_aws(client.list_aliases, **alias_kwargs)
                for alias in alias_resp.get("Aliases") or []:
                    alias_name: str = alias.get("AliasName") or ""
                    alias_arn: str = alias.get("AliasArn") or ""
                    target_key_id: str = alias.get("TargetKeyId") or ""

                    alias_stable_id = f"{account_id}/{region}/kms-alias/{alias_name}"
                    records.append({
                        "record_type":            AWS_KMS_ALIAS,
                        "record_id":              alias_stable_id,
                        "external_id":            alias_stable_id,
                        "name":                   alias_name,
                        "account_id":             account_id,
                        "region":                 region,
                        "alias_name":             alias_name,
                        "alias_arn_hash":         _hash_arn(alias_arn),
                        # SECURITY: raw target key ID not stored — hash only
                        "target_key_id_hash":     _hash_id(target_key_id),
                        "target_key_present":     bool(target_key_id),
                        "config_fetch_warnings":  None,
                    })
                next_marker = alias_resp.get("NextMarker")
                if not next_marker:
                    break
                alias_kwargs["Marker"] = next_marker
        except Exception as exc:
            fc = classify_aws_kms_failure("ListAliases", exc)
            logger.warning(
                "aws: ListAliases failed  region=%s  code=%s",
                region, fc.error_code,
            )

        return records

    # ── M48: Backup fetch methods ─────────────────────────────────────────────

    def _fetch_backup_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch AWS Backup vault, plan, selection, and recovery point posture.

        SECURITY:
        - backup:StartBackupJob NEVER called.
        - backup:StartRestoreJob NEVER called.
        - backup:DeleteRecoveryPoint NEVER called.
        - Backup contents and protected resource data NEVER read.
        - Only backup configuration posture metadata is collected.
        """
        records: list[dict] = []
        selected = self._selected_regions(credentials)
        for region in selected:
            try:
                client = self._make_client("backup", credentials, region=region)
                region_records = self._fetch_backup_in_region(client, account_id, region)
                records.extend(region_records)
            except Exception as exc:
                fc = classify_aws_backup_failure("ListBackupVaults", exc)
                logger.warning(
                    "aws: Backup region fetch failed  region=%s  code=%s",
                    region, fc.error_code,
                )
        return records

    def _fetch_backup_in_region(  # noqa: C901
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch AWS Backup configuration for one region.

        SECURITY: Backup restore, start, delete operations NEVER called.
        """
        records: list[dict] = []

        # ── ListBackupVaults (paginated) ───────────────────────────────────────
        vaults: list[dict] = []
        try:
            kwargs: dict = {}
            while True:
                response = self._call_aws(client.list_backup_vaults, **kwargs)
                vaults.extend(response.get("BackupVaultList") or [])
                next_token = response.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except Exception as exc:
            fc = classify_aws_backup_failure("ListBackupVaults", exc)
            logger.warning(
                "aws: ListBackupVaults failed  region=%s  code=%s",
                region, fc.error_code,
            )
            return records

        for vault in vaults:
            vault_name: str = vault.get("BackupVaultName") or ""
            vault_arn: str = vault.get("BackupVaultArn") or ""
            vault_warnings: list[str] = []

            # ── DescribeBackupVault — lock config ──────────────────────────────
            locked = False
            min_retention_days: int | None = None
            max_retention_days: int | None = None
            recovery_points_count: int | None = vault.get("NumberOfRecoveryPoints")
            backup_vault_lock_configuration_present = False
            encryption_key_arn: str = vault.get("EncryptionKeyArn") or ""
            try:
                desc = self._call_aws(client.describe_backup_vault, BackupVaultName=vault_name)
                encryption_key_arn = desc.get("EncryptionKeyArn") or encryption_key_arn
                recovery_points_count = desc.get("NumberOfRecoveryPoints") or recovery_points_count
                lock_cfg = desc.get("Locked")
                if lock_cfg is not None:
                    locked = bool(lock_cfg)
                min_ret = desc.get("MinRetentionDays")
                max_ret = desc.get("MaxRetentionDays")
                if min_ret is not None:
                    min_retention_days = int(min_ret)
                    backup_vault_lock_configuration_present = True
                if max_ret is not None:
                    max_retention_days = int(max_ret)
                    backup_vault_lock_configuration_present = True
            except Exception as exc:
                fc = classify_aws_backup_failure("DescribeBackupVault", exc)
                vault_warnings.append(f"DescribeBackupVault: {fc.error_code}")

            # ── ListTags — keys only ───────────────────────────────────────────
            tag_keys: list[str] | None = None
            if vault_arn:
                try:
                    tags_resp = self._call_aws(client.list_tags, ResourceArn=vault_arn)
                    raw_tags = tags_resp.get("Tags") or {}
                    # SECURITY: tag values never stored
                    tag_keys = sorted(raw_tags.keys()) or None
                except Exception as exc:
                    fc = classify_aws_backup_failure("ListTags", exc)
                    vault_warnings.append(f"ListTags: {fc.error_code}")

            name_sensitivity = _classify_governance_name_sensitivity(vault_name)
            vault_stable_id = f"{account_id}/{region}/backup-vault/{vault_name}"
            records.append({
                "record_type":                          AWS_BACKUP_VAULT,
                "record_id":                            vault_stable_id,
                "external_id":                          vault_stable_id,
                "name":                                 vault_name,
                "account_id":                           account_id,
                "region":                               region,
                "vault_arn_hash":                       _hash_arn(vault_arn),
                "encryption_key_arn_present":           bool(encryption_key_arn),
                "encryption_key_arn_hash":              _hash_arn(encryption_key_arn),
                "locked":                               locked,
                "min_retention_days":                   min_retention_days,
                "max_retention_days":                   max_retention_days,
                "recovery_points_count":                recovery_points_count,
                "backup_vault_lock_configuration_present": backup_vault_lock_configuration_present,
                "name_sensitivity":                     name_sensitivity,
                "tag_keys":                             tag_keys,
                "config_fetch_warnings":                vault_warnings if vault_warnings else None,
            })

            # ── ListRecoveryPointsByBackupVault (bounded — up to 100) ─────────
            try:
                rp_kwargs: dict = {"BackupVaultName": vault_name, "MaxResults": 100}
                rp_resp = self._call_aws(client.list_recovery_points_by_backup_vault, **rp_kwargs)
                for rp in rp_resp.get("RecoveryPoints") or []:
                    rp_arn: str = rp.get("RecoveryPointArn") or ""
                    resource_type: str = rp.get("ResourceType") or ""
                    status: str = rp.get("Status") or ""
                    rp_vault: str = rp.get("BackupVaultName") or vault_name
                    enc_key: str = rp.get("EncryptionKeyArn") or ""
                    size_bytes: int | None = rp.get("BackupSizeInBytes")

                    rp_arn_hash = _hash_arn(rp_arn) or "unknown"
                    rp_stable_id = f"{account_id}/{region}/backup-recovery-point/{rp_arn_hash}"
                    records.append({
                        "record_type":                      AWS_BACKUP_RECOVERY_POINT,
                        "record_id":                        rp_stable_id,
                        "external_id":                      rp_stable_id,
                        "name":                             f"rp-{rp_arn_hash}",
                        "account_id":                       account_id,
                        "region":                           region,
                        "recovery_point_arn_hash":          rp_arn_hash,
                        "backup_vault_name":                rp_vault,
                        "resource_type":                    resource_type,
                        "status":                           status,
                        "creation_date_present":            bool(rp.get("CreationDate")),
                        "completion_date_present":          bool(rp.get("CompletionDate")),
                        "lifecycle_present":                bool(rp.get("Lifecycle")),
                        "calculated_lifecycle_delete_at_present": bool(rp.get("CalculatedLifecycle")),
                        "encryption_key_arn_present":       bool(enc_key),
                        "encryption_key_arn_hash":          _hash_arn(enc_key),
                        "is_encrypted":                     rp.get("IsEncrypted", False),
                        "size_bytes":                       size_bytes,
                        "config_fetch_warnings":            None,
                    })
            except Exception as exc:
                fc = classify_aws_backup_failure("ListRecoveryPointsByBackupVault", exc)
                vault_warnings.append(f"ListRecoveryPoints: {fc.error_code}")

        # ── ListBackupPlans (paginated) ────────────────────────────────────────
        try:
            plan_kwargs: dict = {}
            while True:
                plan_list_resp = self._call_aws(client.list_backup_plans, **plan_kwargs)
                for plan_entry in plan_list_resp.get("BackupPlansList") or []:
                    plan_id: str = plan_entry.get("BackupPlanId") or ""
                    plan_arn: str = plan_entry.get("BackupPlanArn") or ""
                    version_id: str = plan_entry.get("VersionId") or ""
                    plan_warnings: list[str] = []

                    # ── GetBackupPlan ──────────────────────────────────────────
                    rules: list[dict] = []
                    plan_name: str = plan_entry.get("BackupPlanName") or ""
                    try:
                        plan_resp = self._call_aws(
                            client.get_backup_plan,
                            BackupPlanId=plan_id,
                        )
                        bp = plan_resp.get("BackupPlan") or {}
                        plan_name = bp.get("BackupPlanName") or plan_name
                        rules = bp.get("Rules") or []
                    except Exception as exc:
                        fc = classify_aws_backup_failure("GetBackupPlan", exc)
                        plan_warnings.append(f"GetBackupPlan: {fc.error_code}")

                    rule_summary = _summarize_backup_rules(rules)

                    # ── ListBackupSelections ───────────────────────────────────
                    selections: list[dict] = []
                    try:
                        sel_resp = self._call_aws(
                            client.list_backup_selections,
                            BackupPlanId=plan_id,
                        )
                        selections = sel_resp.get("BackupSelectionsList") or []
                    except Exception as exc:
                        fc = classify_aws_backup_failure("ListBackupSelections", exc)
                        plan_warnings.append(f"ListBackupSelections: {fc.error_code}")

                    plan_id_hash = _hash_id(plan_id) or "unknown"
                    plan_stable_id = f"{account_id}/{region}/backup-plan/{plan_id_hash}"
                    plan_name_sensitivity = _classify_governance_name_sensitivity(plan_name)
                    records.append({
                        "record_type":                          AWS_BACKUP_PLAN,
                        "record_id":                            plan_stable_id,
                        "external_id":                          plan_stable_id,
                        "name":                                 plan_name,
                        "account_id":                           account_id,
                        "region":                               region,
                        "backup_plan_id_hash":                  plan_id_hash,
                        "backup_plan_name":                     plan_name,
                        "version_id_hash":                      _hash_id(version_id),
                        "rule_count":                           rule_summary["rule_count"],
                        "rule_names":                           rule_summary["rule_names"],
                        "target_vault_names":                   rule_summary["target_vault_names"],
                        "schedule_expression_present_count":    rule_summary["schedule_expression_present_count"],
                        "continuous_backup_enabled_count":      rule_summary["continuous_backup_enabled_count"],
                        "lifecycle_delete_after_days_min":      rule_summary["lifecycle_delete_after_days_min"],
                        "lifecycle_delete_after_days_max":      rule_summary["lifecycle_delete_after_days_max"],
                        "lifecycle_move_to_cold_after_days_min": rule_summary["lifecycle_move_to_cold_after_days_min"],
                        "lifecycle_move_to_cold_after_days_max": rule_summary["lifecycle_move_to_cold_after_days_max"],
                        "copy_action_count":                    rule_summary["copy_action_count"],
                        "name_sensitivity":                     plan_name_sensitivity,
                        "config_fetch_warnings":                plan_warnings if plan_warnings else None,
                    })

                    # ── Backup selection records ───────────────────────────────
                    for sel_entry in selections:
                        sel_id: str = sel_entry.get("SelectionId") or ""
                        sel_name: str = sel_entry.get("SelectionName") or ""
                        sel_warnings: list[str] = []

                        # ── GetBackupSelection ─────────────────────────────────
                        resources: list[str] = []
                        conditions: dict = {}
                        iam_role_arn: str = ""
                        list_of_tags_count: int = 0
                        not_resources_count: int = 0
                        try:
                            sel_resp = self._call_aws(
                                client.get_backup_selection,
                                BackupPlanId=plan_id,
                                SelectionId=sel_id,
                            )
                            bs = sel_resp.get("BackupSelection") or {}
                            sel_name = bs.get("SelectionName") or sel_name
                            iam_role_arn = bs.get("IamRoleArn") or ""
                            resources = bs.get("Resources") or []
                            conditions = bs.get("Conditions") or {}
                            list_of_tags_count = len(bs.get("ListOfTags") or [])
                            not_resources_count = len(bs.get("NotResources") or [])
                        except Exception as exc:
                            fc = classify_aws_backup_failure("GetBackupSelection", exc)
                            sel_warnings.append(f"GetBackupSelection: {fc.error_code}")

                        res_summary = _summarize_backup_selection_resources(resources, conditions)
                        sel_id_hash = _hash_id(sel_id) or "unknown"
                        sel_stable_id = f"{account_id}/{region}/backup-selection/{plan_id_hash}/{sel_id_hash}"
                        records.append({
                            "record_type":            AWS_BACKUP_SELECTION,
                            "record_id":              sel_stable_id,
                            "external_id":            sel_stable_id,
                            "name":                   sel_name,
                            "account_id":             account_id,
                            "region":                 region,
                            "backup_plan_id_hash":    plan_id_hash,
                            "selection_id_hash":      sel_id_hash,
                            "selection_name":         sel_name,
                            "iam_role_arn_present":   bool(iam_role_arn),
                            # SECURITY: raw IAM role ARN not stored
                            "iam_role_arn_hash":      _hash_arn(iam_role_arn),
                            "resource_count":         res_summary["resource_count"],
                            "resource_type_counts":   res_summary["resource_type_counts"],
                            "condition_count":        res_summary["condition_count"],
                            "list_of_tags_count":     list_of_tags_count,
                            "not_resources_count":    not_resources_count,
                            "config_fetch_warnings":  sel_warnings if sel_warnings else None,
                        })

                next_plan_token = plan_list_resp.get("NextToken")
                if not next_plan_token:
                    break
                plan_kwargs["NextToken"] = next_plan_token
        except Exception as exc:
            fc = classify_aws_backup_failure("ListBackupPlans", exc)
            logger.warning(
                "aws: ListBackupPlans failed  region=%s  code=%s",
                region, fc.error_code,
            )

        return records

    # ── M48: Organizations fetch methods ─────────────────────────────────────

    def _fetch_organizations_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch AWS Organizations structure and SCP posture.

        Organizations is a global service — fetched once from us-east-1
        (or the default region), not per-region.

        SECURITY:
        - Organizations write/mutate APIs NEVER called.
        - SCPs never created, updated, deleted, attached, or detached.
        - Raw SCP policy JSON never stored — summary only.
        - Raw account email addresses never stored — hashed only.
        """
        region = self._default_region(credentials)
        try:
            client = self._make_client("organizations", credentials, region=region)
            return self._fetch_organizations_global(client, account_id)
        except Exception as exc:
            fc = classify_aws_organizations_failure("DescribeOrganization", exc)
            logger.warning(
                "aws: Organizations global fetch failed  code=%s",
                fc.error_code,
            )
            return []

    def _fetch_organizations_global(  # noqa: C901
        self,
        client: Any,
        account_id: str,
    ) -> list[dict]:
        """Fetch Organizations organization, accounts, OUs, and SCPs.

        SECURITY: All Organizations write operations NEVER called.
        Raw policy content never stored — summary only.
        """
        import json as _json
        records: list[dict] = []

        # ── DescribeOrganization ───────────────────────────────────────────────
        org_id: str = ""
        feature_set: str = ""
        master_account_id: str = ""
        policy_types: list[dict] = []
        root_count: int = 0
        account_count: int = 0
        ou_count: int = 0
        scp_count: int = 0
        org_warnings: list[str] = []

        try:
            org_resp = self._call_aws(client.describe_organization)
            org = org_resp.get("Organization") or {}
            org_id = org.get("Id") or ""
            feature_set = org.get("FeatureSet") or ""
            master_account_id = org.get("MasterAccountId") or ""
            policy_types = org.get("AvailablePolicyTypes") or []
        except Exception as exc:
            fc = classify_aws_organizations_failure("DescribeOrganization", exc)
            org_warnings.append(f"DescribeOrganization: {fc.error_code}")
            # Cannot proceed without org info — return warning record only
            return records

        # ── ListRoots ─────────────────────────────────────────────────────────
        roots: list[dict] = []
        try:
            roots_resp = self._call_aws(client.list_roots)
            roots = roots_resp.get("Roots") or []
            root_count = len(roots)
        except Exception as exc:
            fc = classify_aws_organizations_failure("ListRoots", exc)
            org_warnings.append(f"ListRoots: {fc.error_code}")

        # ── ListAccounts (paginated) ───────────────────────────────────────────
        accounts: list[dict] = []
        try:
            kwargs: dict = {}
            while True:
                acct_resp = self._call_aws(client.list_accounts, **kwargs)
                accounts.extend(acct_resp.get("Accounts") or [])
                next_token = acct_resp.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
            account_count = len(accounts)
        except Exception as exc:
            fc = classify_aws_organizations_failure("ListAccounts", exc)
            org_warnings.append(f"ListAccounts: {fc.error_code}")

        # ── ListPolicies for SERVICE_CONTROL_POLICY ───────────────────────────
        scps: list[dict] = []
        try:
            scp_kwargs: dict = {"Filter": "SERVICE_CONTROL_POLICY"}
            while True:
                scp_list_resp = self._call_aws(client.list_policies, **scp_kwargs)
                scps.extend(scp_list_resp.get("Policies") or [])
                next_token = scp_list_resp.get("NextToken")
                if not next_token:
                    break
                scp_kwargs["NextToken"] = next_token
            scp_count = len(scps)
        except Exception as exc:
            fc = classify_aws_organizations_failure("ListPolicies", exc)
            org_warnings.append(f"ListPolicies: {fc.error_code}")

        # Summarize policy types enabled
        policy_types_summary = [
            {"type": pt.get("Type", ""), "status": pt.get("Status", "")}
            for pt in policy_types
        ]

        org_id_hash = _hash_id(org_id) or "unknown"
        master_id_hash = _hash_id(master_account_id)
        org_stable_id = f"{account_id}/organizations/{org_id_hash}"
        records.append({
            "record_type":              AWS_ORGANIZATIONS_ORGANIZATION,
            "record_id":               org_stable_id,
            "external_id":             org_stable_id,
            "name":                    f"org-{org_id_hash}",
            "account_id":              account_id,
            "region":                  "global",
            # SECURITY: raw org ID and master account ID not stored — hashed
            "organization_id_hash":    org_id_hash,
            "management_account_id_hash": master_id_hash,
            "feature_set":             feature_set,
            "root_count":              root_count,
            "account_count":           account_count,
            "ou_count":                ou_count,  # updated below
            "scp_count":               scp_count,
            "policy_types_summary":    policy_types_summary,
            "config_fetch_warnings":   org_warnings if org_warnings else None,
        })

        # ── Account records ────────────────────────────────────────────────────
        for acct in accounts:
            acct_id: str = acct.get("Id") or ""
            acct_name: str = acct.get("Name") or ""
            acct_email: str = acct.get("Email") or ""
            acct_status: str = acct.get("Status") or ""
            joined_method: str = acct.get("JoinedMethod") or ""

            acct_id_hash = _hash_id(acct_id) or "unknown"
            acct_name_hash = _hash_id(acct_name)
            # SECURITY: raw email never stored — hash only
            acct_email_hash = _hash_email(acct_email)

            acct_stable_id = f"{account_id}/org-account/{acct_id_hash}"
            records.append({
                "record_type":              AWS_ORGANIZATIONS_ACCOUNT,
                "record_id":               acct_stable_id,
                "external_id":             acct_stable_id,
                "name":                    f"org-acct-{acct_id_hash}",
                "account_id":              account_id,
                "region":                  "global",
                "org_account_id_hash":     acct_id_hash,
                "account_name_hash":       acct_name_hash,
                # SECURITY: raw email never stored
                "account_email_hash":      acct_email_hash,
                "status":                  acct_status,
                "joined_method":           joined_method,
                "joined_timestamp_present": bool(acct.get("JoinedTimestamp")),
                "config_fetch_warnings":   None,
            })

        # ── OU records (from each root, one level deep + recursive) ───────────
        total_ou_count = 0
        for root in roots:
            root_id: str = root.get("Id") or ""
            root_ou_count = self._fetch_ou_children(
                client, account_id, root_id, root_id, records, depth=0, max_depth=5
            )
            total_ou_count += root_ou_count

        # Update org record ou_count
        for r in records:
            if r.get("record_type") == AWS_ORGANIZATIONS_ORGANIZATION:
                r["ou_count"] = total_ou_count

        # ── SCP records ────────────────────────────────────────────────────────
        for scp in scps:
            policy_id: str = scp.get("Id") or ""
            policy_name: str = scp.get("Name") or ""
            policy_arn: str = scp.get("Arn") or ""
            aws_managed: bool = scp.get("AwsManaged", False)
            description: str = scp.get("Description") or ""
            scp_warnings: list[str] = []

            # ── DescribePolicy — get content for summary ───────────────────────
            scp_summary: dict = {}
            try:
                desc_resp = self._call_aws(client.describe_policy, PolicyId=policy_id)
                policy_content_raw = (desc_resp.get("Policy") or {}).get("Content") or ""
                # SECURITY: raw policy JSON never stored — summary only
                scp_summary = _summarize_scp_content(policy_content_raw)
            except Exception as exc:
                fc = classify_aws_organizations_failure("DescribePolicy", exc)
                scp_warnings.append(f"DescribePolicy: {fc.error_code}")

            # ── ListTargetsForPolicy ───────────────────────────────────────────
            targets: list[dict] = []
            try:
                tgt_resp = self._call_aws(client.list_targets_for_policy, PolicyId=policy_id)
                targets = tgt_resp.get("Targets") or []
            except Exception as exc:
                fc = classify_aws_organizations_failure("ListTargetsForPolicy", exc)
                scp_warnings.append(f"ListTargetsForPolicy: {fc.error_code}")

            target_type_counts: dict[str, int] = {}
            for tgt in targets:
                ttype = (tgt.get("Type") or "UNKNOWN").upper()
                target_type_counts[ttype] = target_type_counts.get(ttype, 0) + 1

            policy_id_hash = _hash_id(policy_id) or "unknown"
            policy_name_sensitivity = _classify_governance_name_sensitivity(policy_name)
            scp_stable_id = f"{account_id}/org-scp/{policy_id_hash}"
            records.append({
                "record_type":              AWS_ORGANIZATIONS_SCP,
                "record_id":               scp_stable_id,
                "external_id":             scp_stable_id,
                "name":                    policy_name,
                "account_id":              account_id,
                "region":                  "global",
                "policy_id_hash":          policy_id_hash,
                "policy_name":             policy_name,
                "arn_hash":                _hash_arn(policy_arn),
                "aws_managed":             aws_managed,
                "description_present":     bool(description),
                # SCP content summary — raw JSON never stored
                "allow_statement_count":   scp_summary.get("allow_statement_count", 0),
                "deny_statement_count":    scp_summary.get("deny_statement_count", 0),
                "denied_action_count":     scp_summary.get("denied_action_count", 0),
                "denied_service_prefixes": scp_summary.get("denied_service_prefixes", []),
                "wildcard_action_present": scp_summary.get("wildcard_action_present", False),
                "wildcard_resource_present": scp_summary.get("wildcard_resource_present", False),
                "denies_full_admin_escape": scp_summary.get("denies_full_admin_escape", False),
                "attached_target_count":   len(targets),
                "attached_target_type_counts": target_type_counts if target_type_counts else None,
                "name_sensitivity":        policy_name_sensitivity,
                "config_fetch_warnings":   scp_warnings if scp_warnings else None,
            })

            # ── SCP attachment records ─────────────────────────────────────────
            for tgt in targets:
                tgt_id: str = tgt.get("TargetId") or ""
                tgt_name: str = tgt.get("Name") or ""
                tgt_type: str = (tgt.get("Type") or "UNKNOWN").upper()

                tgt_id_hash = _hash_id(tgt_id) or "unknown"
                tgt_name_hash = _hash_id(tgt_name)
                attachment_stable_id = f"{account_id}/org-scp-attachment/{policy_id_hash}/{tgt_id_hash}"
                records.append({
                    "record_type":          AWS_ORGANIZATIONS_SCP_ATTACHMENT,
                    "record_id":           attachment_stable_id,
                    "external_id":         attachment_stable_id,
                    "name":                f"scp-attach-{policy_id_hash}-{tgt_id_hash}",
                    "account_id":          account_id,
                    "region":              "global",
                    "policy_id_hash":      policy_id_hash,
                    "policy_name":         policy_name,
                    "target_id_hash":      tgt_id_hash,
                    "target_name_hash":    tgt_name_hash,
                    "target_type":         tgt_type,
                    "config_fetch_warnings": None,
                })

        return records

    def _fetch_ou_children(
        self,
        client: Any,
        account_id: str,
        parent_id: str,
        root_id: str,
        records: list[dict],
        depth: int = 0,
        max_depth: int = 5,
    ) -> int:
        """Recursively fetch OUs for a parent (root or OU), up to max_depth.

        Returns the total number of OUs found.
        """
        if depth >= max_depth:
            return 0
        total_ous = 0
        try:
            resp = self._call_aws(
                client.list_organizational_units_for_parent,
                ParentId=parent_id,
            )
            for ou in resp.get("OrganizationalUnits") or []:
                ou_id: str = ou.get("Id") or ""
                ou_name: str = ou.get("Name") or ""
                total_ous += 1

                # Count child accounts for this OU
                child_account_count = 0
                try:
                    children_resp = self._call_aws(
                        client.list_children,
                        ParentId=ou_id,
                        ChildType="ACCOUNT",
                    )
                    child_account_count = len(children_resp.get("Children") or [])
                except Exception:
                    pass

                # Count attached SCPs
                attached_scp_count = 0
                try:
                    pol_resp = self._call_aws(
                        client.list_policies_for_target,
                        TargetId=ou_id,
                        Filter="SERVICE_CONTROL_POLICY",
                    )
                    attached_scp_count = len(pol_resp.get("Policies") or [])
                except Exception:
                    pass

                ou_id_hash = _hash_id(ou_id) or "unknown"
                ou_name_hash = _hash_id(ou_name)
                parent_id_hash = _hash_id(parent_id)
                ou_stable_id = f"{account_id}/org-ou/{ou_id_hash}"

                # Count child OUs recursively
                child_ou_count = self._fetch_ou_children(
                    client, account_id, ou_id, root_id, records,
                    depth=depth + 1, max_depth=max_depth,
                )
                total_ous += child_ou_count

                records.append({
                    "record_type":           AWS_ORGANIZATIONS_OU,
                    "record_id":            ou_stable_id,
                    "external_id":          ou_stable_id,
                    "name":                 f"ou-{ou_id_hash}",
                    "account_id":           account_id,
                    "region":               "global",
                    "ou_id_hash":           ou_id_hash,
                    "ou_name_hash":         ou_name_hash,
                    "parent_id_hash":       parent_id_hash,
                    "child_ou_count":       child_ou_count,
                    "child_account_count":  child_account_count,
                    "attached_scp_count":   attached_scp_count,
                    "config_fetch_warnings": None,
                })
        except Exception as exc:
            fc = classify_aws_organizations_failure("ListOrganizationalUnitsForParent", exc)
            logger.warning(
                "aws: ListOrganizationalUnitsForParent failed  parent=%s  code=%s",
                parent_id, fc.error_code,
            )
        return total_ous

    # ── M49: CloudWatch Alarms + Observability Config helpers ─────────────────

    @staticmethod
    def _summarize_alarm_action_types(action_arns: list) -> dict:
        """Return a count-per-destination-type dict for a list of alarm action ARNs.

        SECURITY: Raw ARN values are NEVER stored. Only the destination type is
        extracted (e.g. "sns", "lambda", "ssm", "autoscaling", "ec2", "other").
        """
        counts: dict[str, int] = {}
        for arn in (action_arns or []):
            arn_str = str(arn)
            # Extract service prefix from ARN: arn:partition:service:...
            parts = arn_str.split(":")
            service = parts[2].lower() if len(parts) >= 3 else "other"
            # Normalize known service names
            if service in ("sns", "lambda", "ssm", "autoscaling", "ec2"):
                key = service
            elif service == "sqs":
                key = "sqs"
            else:
                key = "other"
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def _summarize_metric_dimensions(dimensions: list) -> list:
        """Return a sorted list of dimension key names only — values NEVER stored."""
        keys = []
        for d in (dimensions or []):
            k = d.get("Name") or "" if isinstance(d, dict) else ""
            if k:
                keys.append(k)
        return sorted(set(keys))

    @staticmethod
    def _hash_dashboard_body(body: str) -> str:
        """Return a 12-char SHA-256 hex digest of the dashboard JSON body.

        SECURITY: The raw body string is NEVER stored or logged.
        """
        import hashlib
        return hashlib.sha256((body or "").encode()).hexdigest()[:12]

    @staticmethod
    def _count_dashboard_widgets(body: str) -> tuple[int, dict]:
        """Parse dashboard body and return (widget_count, type_counts_dict).

        SECURITY: Widget content, metric names, query text, and any PII
        in widget definitions are NEVER stored. Only type names and counts
        are returned.
        """
        import json
        try:
            parsed = json.loads(body or "{}")
            widgets = parsed.get("widgets") or []
            type_counts: dict[str, int] = {}
            for w in widgets:
                wtype = (w.get("type") or "unknown") if isinstance(w, dict) else "unknown"
                type_counts[wtype] = type_counts.get(wtype, 0) + 1
            return len(widgets), type_counts
        except Exception:
            return 0, {}

    @staticmethod
    def _hash_filter_pattern(pattern: str) -> str:
        """Return a 12-char SHA-256 hex digest of a filter pattern string.

        SECURITY: The raw filter pattern is NEVER stored or logged.
        """
        import hashlib
        return hashlib.sha256((pattern or "").encode()).hexdigest()[:12]

    @staticmethod
    def _summarize_subscription_destination_type(arn: str) -> str:
        """Extract the destination type from a subscription filter destination ARN.

        SECURITY: Raw ARN value is NEVER stored; only the service type is returned.
        Returns one of: "lambda", "kinesis", "firehose", "opensearch", "other".
        """
        arn_str = str(arn or "")
        parts = arn_str.split(":")
        service = parts[2].lower() if len(parts) >= 3 else "other"
        if service == "lambda":
            return "lambda"
        if service == "kinesis":
            return "kinesis"
        if service == "firehose":
            return "firehose"
        if service == "es":
            return "opensearch"
        return "other"

    @staticmethod
    def _classify_observability_name_sensitivity(name: str) -> str:
        """Classify alarm/log-group name sensitivity level.

        Returns one of: "production", "payment", "auth", "security",
        "compliance", "alert", "none".
        """
        lower = (name or "").lower()
        if any(p in lower for p in ("prod", "production", "live")):
            return "production"
        if any(p in lower for p in ("payment", "payments", "billing", "invoice")):
            return "payment"
        if any(p in lower for p in ("auth", "authentication", "login", "credential")):
            return "auth"
        if any(p in lower for p in ("security", "pii", "customer", "user", "users")):
            return "security"
        if any(p in lower for p in ("compliance", "audit")):
            return "compliance"
        if any(p in lower for p in ("alert", "alarm", "error", "exception")):
            return "alert"
        return "none"

    # ── M49: CloudWatch fetch methods ──────────────────────────────────────────

    def _fetch_cloudwatch_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch CloudWatch metric alarms, composite alarms, dashboards,
        metric streams, and anomaly detectors across all selected regions.

        SECURITY:
        - cloudwatch:GetMetricData NEVER called — metric datapoints NEVER read.
        - cloudwatch:GetMetricStatistics NEVER called.
        - Alarm evaluation history NEVER read.
        - All alarm action ARNs are type-summarized; raw values NEVER stored.
        - Dashboard body stored as hash only; widget content NEVER stored.
        - Firehose ARNs stored as hashes only.
        """
        selected = self._selected_regions(credentials)
        all_records: list[dict] = []
        for region in selected:
            try:
                client = self._make_client("cloudwatch", credentials, region)
                region_records = self._fetch_cloudwatch_in_region(
                    client, account_id, region
                )
                all_records.extend(region_records)
            except Exception as exc:
                fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
                logger.warning(
                    "aws: cloudwatch region=%s  code=%s",
                    region, fc.error_code,
                )
        return all_records

    def _fetch_cloudwatch_in_region(  # noqa: C901
        self,
        client: object,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch all CloudWatch resources in one region.

        Returns records for metric alarms, composite alarms, dashboards,
        metric streams, and anomaly detectors.

        SECURITY: metric datapoints NEVER read; dashboard body hashed only;
        action ARNs type-summarized only; firehose ARNs hashed only.
        """
        records: list[dict] = []

        # ── Metric alarms ──────────────────────────────────────────────────────
        try:
            paginator_resp: list[dict] = []
            try:
                # Paginate through all metric alarms
                next_token = None
                while True:
                    kwargs: dict = {"AlarmTypes": ["MetricAlarm"]}
                    if next_token:
                        kwargs["NextToken"] = next_token
                    resp = self._call_aws(client.describe_alarms, **kwargs)
                    paginator_resp.extend(resp.get("MetricAlarms") or [])
                    next_token = resp.get("NextToken")
                    if not next_token:
                        break
            except Exception as exc:
                fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
                logger.warning(
                    "aws: DescribeAlarms(MetricAlarm) region=%s  code=%s",
                    region, fc.error_code,
                )

            for alarm in paginator_resp:
                alarm_name: str = alarm.get("AlarmName") or ""
                alarm_arn: str = alarm.get("AlarmArn") or ""
                alarm_arn_hash = _hash_id(alarm_arn)
                stable_id = f"{account_id}/cloudwatch-alarm/{region}/{alarm_arn_hash}"

                actions_enabled = alarm.get("ActionsEnabled")
                alarm_state = alarm.get("StateValue") or "INSUFFICIENT_DATA"
                comparison_op = alarm.get("ComparisonOperator") or ""
                threshold = alarm.get("Threshold")
                evaluation_periods = alarm.get("EvaluationPeriods")
                datapoints_to_alarm = alarm.get("DatapointsToAlarm")
                treat_missing = alarm.get("TreatMissingData") or "missing"
                statistic = alarm.get("Statistic") or ""
                extended_stat = alarm.get("ExtendedStatistic") or ""
                namespace = alarm.get("Namespace") or ""
                metric_name = alarm.get("MetricName") or ""
                dimensions = alarm.get("Dimensions") or []
                metrics = alarm.get("Metrics") or []

                alarm_actions = self._summarize_alarm_action_types(
                    alarm.get("AlarmActions") or []
                )
                ok_actions = self._summarize_alarm_action_types(
                    alarm.get("OKActions") or []
                )
                insuf_actions = self._summarize_alarm_action_types(
                    alarm.get("InsufficientDataActions") or []
                )
                alarm_action_count = sum(alarm_actions.values())
                ok_action_count = sum(ok_actions.values())
                insufficient_data_action_count = sum(insuf_actions.values())
                dimension_keys = self._summarize_metric_dimensions(dimensions)
                period = alarm.get("Period")
                name_sensitivity = self._classify_observability_name_sensitivity(alarm_name)

                # Tags — keys only; values NEVER stored
                tag_keys: list[str] = []
                try:
                    tag_resp = self._call_aws(
                        client.list_tags_for_resource,
                        ResourceARN=alarm_arn,
                    )
                    tag_keys = sorted(
                        t.get("Key") or ""
                        for t in (tag_resp.get("Tags") or [])
                        if t.get("Key")
                    )
                except Exception:
                    pass

                records.append({
                    "record_type":                          AWS_CLOUDWATCH_METRIC_ALARM,
                    "record_id":                            stable_id,
                    "external_id":                          stable_id,
                    "name":                                 alarm_name,
                    "account_id":                           account_id,
                    "region":                               region,
                    "alarm_arn_hash":                       alarm_arn_hash,
                    "alarm_state_value":                    alarm_state,
                    "alarm_state_reason_absent":            not bool(alarm.get("StateReason")),
                    "actions_enabled":                      actions_enabled,
                    "alarm_action_type_counts":             alarm_actions,
                    "alarm_action_count":                   alarm_action_count,
                    "ok_action_type_counts":                ok_actions,
                    "ok_action_count":                      ok_action_count,
                    "insufficient_data_action_type_counts": insuf_actions,
                    "insufficient_data_action_count":       insufficient_data_action_count,
                    "namespace":                            namespace,
                    "metric_name":                          metric_name,
                    "statistic":                            statistic,
                    "extended_statistic_present":           bool(extended_stat),
                    "period":                               period,
                    "comparison_operator":                  comparison_op,
                    "threshold":                            threshold,
                    "evaluation_periods":                   evaluation_periods,
                    "datapoints_to_alarm":                  datapoints_to_alarm,
                    "treat_missing_data":                   treat_missing,
                    "dimension_key_names":                  dimension_keys,
                    "metrics_present":                      bool(metrics),
                    "name_sensitivity":                     name_sensitivity,
                    "tag_keys":                             tag_keys,
                    "config_fetch_warnings":                None,
                })
        except Exception as exc:
            fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
            logger.warning(
                "aws: DescribeAlarms region=%s  code=%s", region, fc.error_code,
            )

        # ── Composite alarms ───────────────────────────────────────────────────
        try:
            composite_alarms: list[dict] = []
            next_token = None
            while True:
                kwargs = {"AlarmTypes": ["CompositeAlarm"]}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = self._call_aws(client.describe_alarms, **kwargs)
                composite_alarms.extend(resp.get("CompositeAlarms") or [])
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            for alarm in composite_alarms:
                alarm_name = alarm.get("AlarmName") or ""
                alarm_arn = alarm.get("AlarmArn") or ""
                alarm_arn_hash = _hash_id(alarm_arn)
                stable_id = f"{account_id}/cloudwatch-composite/{region}/{alarm_arn_hash}"

                rule = alarm.get("AlarmRule") or ""
                rule_hash = self._hash_filter_pattern(rule)
                # Count component alarms: split on " AND ", " OR ", " NOT "
                import re as _re
                components = _re.split(r"\b(?:AND|OR|NOT)\b", rule)
                rule_component_count = len([c for c in components if c.strip()])

                alarm_actions = self._summarize_alarm_action_types(
                    alarm.get("AlarmActions") or []
                )
                ok_actions = self._summarize_alarm_action_types(
                    alarm.get("OKActions") or []
                )
                insuf_actions = self._summarize_alarm_action_types(
                    alarm.get("InsufficientDataActions") or []
                )
                composite_alarm_action_count = sum(alarm_actions.values())
                composite_ok_action_count = sum(ok_actions.values())
                composite_insuf_action_count = sum(insuf_actions.values())
                name_sensitivity = self._classify_observability_name_sensitivity(alarm_name)

                tag_keys = []
                try:
                    tag_resp = self._call_aws(
                        client.list_tags_for_resource,
                        ResourceARN=alarm_arn,
                    )
                    tag_keys = sorted(
                        t.get("Key") or ""
                        for t in (tag_resp.get("Tags") or [])
                        if t.get("Key")
                    )
                except Exception:
                    pass

                records.append({
                    "record_type":                          AWS_CLOUDWATCH_COMPOSITE_ALARM,
                    "record_id":                            stable_id,
                    "external_id":                          stable_id,
                    "name":                                 alarm_name,
                    "account_id":                           account_id,
                    "region":                               region,
                    "alarm_arn_hash":                       alarm_arn_hash,
                    "alarm_state_value":                    alarm.get("StateValue") or "INSUFFICIENT_DATA",
                    "alarm_state_reason_absent":            not bool(alarm.get("StateReason")),
                    "actions_enabled":                      alarm.get("ActionsEnabled"),
                    "alarm_rule_present":                   bool(rule),
                    "alarm_rule_hash":                      rule_hash,
                    "alarm_rule_component_count":           rule_component_count,
                    "alarm_action_type_counts":             alarm_actions,
                    "alarm_action_count":                   composite_alarm_action_count,
                    "ok_action_type_counts":                ok_actions,
                    "ok_action_count":                      composite_ok_action_count,
                    "insufficient_data_action_type_counts": insuf_actions,
                    "insufficient_data_action_count":       composite_insuf_action_count,
                    "name_sensitivity":                     name_sensitivity,
                    "tag_keys":                             tag_keys,
                    "config_fetch_warnings":                None,
                })
        except Exception as exc:
            fc = classify_aws_cloudwatch_failure("DescribeAlarms", exc)
            logger.warning(
                "aws: DescribeAlarms(CompositeAlarm) region=%s  code=%s",
                region, fc.error_code,
            )

        # ── Dashboards ────────────────────────────────────────────────────────
        try:
            dashboard_list: list[dict] = []
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = self._call_aws(client.list_dashboards, **kwargs)
                dashboard_list.extend(resp.get("DashboardEntries") or [])
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            for dash in dashboard_list:
                dash_name: str = dash.get("DashboardName") or ""
                dash_arn: str = dash.get("DashboardArn") or ""
                dash_arn_hash = _hash_id(dash_arn)
                stable_id = f"{account_id}/cloudwatch-dashboard/{region}/{dash_arn_hash}"

                # Fetch body to hash it — never store the body itself
                body_hash = ""
                widget_count = 0
                widget_type_counts: dict = {}
                try:
                    body_resp = self._call_aws(
                        client.get_dashboard,
                        DashboardName=dash_name,
                    )
                    body = body_resp.get("DashboardBody") or ""
                    body_hash = self._hash_dashboard_body(body)
                    widget_count, widget_type_counts = self._count_dashboard_widgets(body)
                except Exception as exc:
                    fc = classify_aws_cloudwatch_failure("GetDashboard", exc)
                    logger.warning(
                        "aws: GetDashboard name=%s region=%s  code=%s",
                        dash_name, region, fc.error_code,
                    )

                records.append({
                    "record_type":          AWS_CLOUDWATCH_DASHBOARD,
                    "record_id":            stable_id,
                    "external_id":          stable_id,
                    "name":                 dash_name,
                    "account_id":           account_id,
                    "region":               region,
                    "dashboard_arn_hash":   dash_arn_hash,
                    "dashboard_body_hash":  body_hash,
                    "widget_count":         widget_count,
                    "widget_type_counts":   widget_type_counts,
                    "config_fetch_warnings": None,
                })
        except Exception as exc:
            fc = classify_aws_cloudwatch_failure("ListDashboards", exc)
            logger.warning(
                "aws: ListDashboards region=%s  code=%s", region, fc.error_code,
            )

        # ── Metric streams ─────────────────────────────────────────────────────
        try:
            stream_list: list[dict] = []
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = self._call_aws(client.list_metric_streams, **kwargs)
                stream_list.extend(resp.get("Entries") or [])
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            for entry in stream_list:
                stream_name: str = entry.get("Name") or ""
                stream_arn: str = entry.get("Arn") or ""
                stream_arn_hash = _hash_id(stream_arn)
                stable_id = f"{account_id}/cloudwatch-stream/{region}/{stream_arn_hash}"

                # Fetch detailed config
                firehose_arn_hash = ""
                include_count = 0
                exclude_count = 0
                output_format = ""
                state = entry.get("State") or ""
                stats_config_count = 0
                tag_keys_stream: list[str] = []

                role_arn_hash_stream = ""
                try:
                    detail = self._call_aws(
                        client.get_metric_stream,
                        Name=stream_name,
                    )
                    firehose_arn = detail.get("FirehoseArn") or ""
                    firehose_arn_hash = _hash_id(firehose_arn)
                    role_arn_stream = detail.get("RoleArn") or ""
                    role_arn_hash_stream = _hash_id(role_arn_stream) if role_arn_stream else ""
                    include_count = len(detail.get("IncludeFilters") or [])
                    exclude_count = len(detail.get("ExcludeFilters") or [])
                    output_format = detail.get("OutputFormat") or ""
                    state = detail.get("State") or state
                    stats_config_count = len(detail.get("StatisticsConfigurations") or [])

                    # Tags — keys only
                    tag_keys_stream = sorted(
                        t.get("Key") or ""
                        for t in (detail.get("Tags") or [])
                        if t.get("Key")
                    )
                except Exception as exc:
                    fc = classify_aws_cloudwatch_failure("GetMetricStream", exc)
                    logger.warning(
                        "aws: GetMetricStream name=%s region=%s  code=%s",
                        stream_name, region, fc.error_code,
                    )

                records.append({
                    "record_type":                      AWS_CLOUDWATCH_METRIC_STREAM,
                    "record_id":                        stable_id,
                    "external_id":                      stable_id,
                    "name":                             stream_name,
                    "account_id":                       account_id,
                    "region":                           region,
                    "stream_arn_hash":                  stream_arn_hash,
                    "state":                            state,
                    "output_format":                    output_format,
                    "firehose_arn_hash":                firehose_arn_hash,
                    "role_arn_hash":                    role_arn_hash_stream or None,
                    "include_filter_count":             include_count,
                    "exclude_filter_count":             exclude_count,
                    "statistics_configuration_count":   stats_config_count,
                    "tag_keys":                         tag_keys_stream,
                    "config_fetch_warnings":            None,
                })
        except Exception as exc:
            fc = classify_aws_cloudwatch_failure("ListMetricStreams", exc)
            logger.warning(
                "aws: ListMetricStreams region=%s  code=%s", region, fc.error_code,
            )

        # ── Anomaly detectors ──────────────────────────────────────────────────
        try:
            detector_list: list[dict] = []
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = self._call_aws(client.describe_anomaly_detectors, **kwargs)
                detector_list.extend(resp.get("AnomalyDetectors") or [])
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            for det in detector_list:
                # Handle both SingleMetricAnomalyDetector and MetricMathAnomalyDetector
                single = det.get("SingleMetricAnomalyDetector") or {}
                namespace = single.get("Namespace") or det.get("Namespace") or ""
                metric_name = single.get("MetricName") or det.get("MetricName") or ""
                stat = single.get("Stat") or det.get("Stat") or ""
                dimensions = single.get("Dimensions") or det.get("Dimensions") or []
                dimension_keys = self._summarize_metric_dimensions(dimensions)
                config = det.get("Configuration") or {}
                excluded_ranges = config.get("ExcludedTimeRanges") or []
                metric_tz = config.get("MetricTimezone") or ""
                state_val = det.get("StateValue") or ""

                det_name = f"{namespace}/{metric_name}/{stat}"
                det_hash = _hash_id(f"{account_id}/{region}/{namespace}/{metric_name}/{stat}")
                stable_id = f"{account_id}/cloudwatch-anomaly/{region}/{det_hash}"

                records.append({
                    "record_type":                              AWS_CLOUDWATCH_ANOMALY_DETECTOR,
                    "record_id":                                stable_id,
                    "external_id":                              stable_id,
                    "name":                                     det_name,
                    "account_id":                               account_id,
                    "region":                                   region,
                    "namespace":                                namespace,
                    "metric_name":                              metric_name,
                    "stat":                                     stat,
                    "dimension_key_names":                      dimension_keys,
                    "state":                                    state_val,
                    "configuration_excluded_time_ranges_count": len(excluded_ranges),
                    "configuration_metric_timezone_present":    bool(metric_tz),
                    "config_fetch_warnings":                    None,
                })
        except Exception as exc:
            fc = classify_aws_cloudwatch_failure("DescribeAnomalyDetectors", exc)
            logger.warning(
                "aws: DescribeAnomalyDetectors region=%s  code=%s", region, fc.error_code,
            )

        return records

    # ── M49: CloudWatch Logs fetch methods ─────────────────────────────────────

    def _fetch_cloudwatch_logs_resources(
        self,
        credentials: dict,
        account_id: str,
    ) -> list[dict]:
        """Fetch CloudWatch Logs log groups, metric filters, and subscription
        filters across all selected regions.

        SECURITY:
        - logs:GetLogEvents NEVER called — log event contents NEVER read.
        - logs:FilterLogEvents NEVER called.
        - logs:StartQuery NEVER called.
        - logs:GetQueryResults NEVER called.
        - Filter patterns stored as hashes only; raw values NEVER stored.
        - Destination ARNs stored as type summaries + hashes; raw values NEVER stored.
        - Log group names stored as hashes in stable IDs; display name is the name.
        """
        selected = self._selected_regions(credentials)
        all_records: list[dict] = []
        for region in selected:
            try:
                logs_client = self._make_client("logs", credentials, region)
                region_records = self._fetch_cloudwatch_logs_in_region(
                    logs_client, account_id, region
                )
                all_records.extend(region_records)
            except Exception as exc:
                fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
                logger.warning(
                    "aws: cloudwatch_logs region=%s  code=%s",
                    region, fc.error_code,
                )
        return all_records

    def _fetch_cloudwatch_logs_in_region(  # noqa: C901
        self,
        client: object,
        account_id: str,
        region: str,
    ) -> list[dict]:
        """Fetch all CloudWatch Logs resources in one region.

        Returns records for log groups, metric filters, and subscription filters.

        SECURITY: log events NEVER read; filter patterns hashed only;
        destination ARNs type-summarized + hashed only.
        """
        records: list[dict] = []

        # ── Log groups ─────────────────────────────────────────────────────────
        log_groups: list[dict] = []
        try:
            next_token = None
            while True:
                kwargs: dict = {}
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = self._call_aws(client.describe_log_groups, **kwargs)
                log_groups.extend(resp.get("logGroups") or [])
                next_token = resp.get("nextToken")
                if not next_token:
                    break
        except Exception as exc:
            fc = classify_aws_cloudwatch_logs_failure("DescribeLogGroups", exc)
            logger.warning(
                "aws: DescribeLogGroups region=%s  code=%s", region, fc.error_code,
            )

        for lg in log_groups:
            lg_name: str = lg.get("logGroupName") or ""
            lg_name_hash = _hash_id(lg_name)
            stable_id = f"{account_id}/cloudwatch-log-group/{region}/{lg_name_hash}"

            retention = lg.get("retentionInDays")
            kms_arn = lg.get("kmsKeyId") or ""
            kms_arn_hash = _hash_id(kms_arn) if kms_arn else ""
            stored_bytes = lg.get("storedBytes") or 0
            metric_filter_count = lg.get("metricFilterCount") or 0

            # Tags — keys only
            tag_keys: list[str] = []
            try:
                tag_resp = self._call_aws(
                    client.list_tags_log_group,
                    logGroupName=lg_name,
                )
                tag_keys = sorted(
                    k for k in (tag_resp.get("tags") or {}).keys() if k
                )
            except Exception:
                pass

            # Count subscription filters for this group
            sub_filter_count = 0
            try:
                sf_resp = self._call_aws(
                    client.describe_subscription_filters,
                    logGroupName=lg_name,
                )
                sub_filter_count = len(sf_resp.get("subscriptionFilters") or [])
            except Exception:
                pass

            name_sensitivity = self._classify_observability_name_sensitivity(lg_name)

            records.append({
                "record_type":                AWS_CLOUDWATCH_LOG_GROUP,
                "record_id":                  stable_id,
                "external_id":                stable_id,
                "name":                       lg_name,
                "account_id":                 account_id,
                "region":                     region,
                "log_group_name_hash":        lg_name_hash,
                "retention_in_days":          retention,
                "retention_configured":       retention is not None,
                "kms_key_id_present":         bool(kms_arn),
                "kms_key_id_hash":            kms_arn_hash or None,
                "stored_bytes":               stored_bytes,
                "metric_filter_count":        metric_filter_count,
                "subscription_filter_count":  sub_filter_count,
                "name_sensitivity":           name_sensitivity,
                "tag_keys":                   tag_keys,
                "config_fetch_warnings":      None,
            })

            # ── Metric filters for this log group ─────────────────────────────
            try:
                mf_resp = self._call_aws(
                    client.describe_metric_filters,
                    logGroupName=lg_name,
                )
                for mf in (mf_resp.get("metricFilters") or []):
                    filter_name: str = mf.get("filterName") or ""
                    filter_name_hash = _hash_id(filter_name)
                    mf_stable_id = (
                        f"{account_id}/cloudwatch-metric-filter/"
                        f"{region}/{lg_name_hash}/{filter_name_hash}"
                    )
                    pattern: str = mf.get("filterPattern") or ""
                    pattern_hash = self._hash_filter_pattern(pattern)
                    pattern_len = len(pattern)

                    transformations = mf.get("metricTransformations") or []
                    target_metric = transformations[0].get("metricName") if transformations else ""
                    target_ns = transformations[0].get("metricNamespace") if transformations else ""
                    has_default_value = any(
                        t.get("defaultValue") is not None for t in transformations
                    )
                    has_unit = any(t.get("unit") for t in transformations)

                    records.append({
                        "record_type":                  AWS_CLOUDWATCH_METRIC_FILTER,
                        "record_id":                    mf_stable_id,
                        "external_id":                  mf_stable_id,
                        "name":                         filter_name,
                        "account_id":                   account_id,
                        "region":                       region,
                        "log_group_name_hash":          lg_name_hash,
                        "filter_name_hash":             filter_name_hash,
                        "filter_pattern_present":       bool(pattern),
                        "filter_pattern_hash":          pattern_hash,
                        "filter_pattern_length":        pattern_len,
                        "metric_name":                  target_metric or "",
                        "metric_namespace":             target_ns or "",
                        "metric_transformation_count":  len(transformations),
                        "default_value_present":        has_default_value,
                        "unit_present":                 has_unit,
                        "config_fetch_warnings":        None,
                    })
            except Exception as exc:
                fc = classify_aws_cloudwatch_logs_failure("DescribeMetricFilters", exc)
                logger.warning(
                    "aws: DescribeMetricFilters log_group=%s region=%s  code=%s",
                    lg_name_hash, region, fc.error_code,
                )

            # ── Subscription filters for this log group ───────────────────────
            try:
                sf_full_resp = self._call_aws(
                    client.describe_subscription_filters,
                    logGroupName=lg_name,
                )
                for sf in (sf_full_resp.get("subscriptionFilters") or []):
                    sf_name: str = sf.get("filterName") or ""
                    sf_name_hash = _hash_id(sf_name)
                    sf_stable_id = (
                        f"{account_id}/cloudwatch-subscription-filter/"
                        f"{region}/{lg_name_hash}/{sf_name_hash}"
                    )
                    sf_pattern: str = sf.get("filterPattern") or ""
                    sf_pattern_hash = self._hash_filter_pattern(sf_pattern)

                    dest_arn: str = sf.get("destinationArn") or ""
                    dest_type = self._summarize_subscription_destination_type(dest_arn)
                    dest_arn_hash = _hash_id(dest_arn) if dest_arn else ""
                    distribution: str = sf.get("distribution") or ""
                    # Role ARN — hashed only; raw value NEVER stored
                    sf_role_arn: str = sf.get("roleArn") or sf.get("RoleArn") or ""
                    sf_role_arn_hash = _hash_id(sf_role_arn) if sf_role_arn else ""

                    records.append({
                        "record_type":              AWS_CLOUDWATCH_SUBSCRIPTION_FILTER,
                        "record_id":                sf_stable_id,
                        "external_id":              sf_stable_id,
                        "name":                     sf_name,
                        "account_id":               account_id,
                        "region":                   region,
                        "log_group_name_hash":      lg_name_hash,
                        "filter_name_hash":         sf_name_hash,
                        "filter_pattern_present":   bool(sf_pattern),
                        "filter_pattern_hash":      sf_pattern_hash,
                        "filter_pattern_length":    len(sf_pattern),
                        "destination_type":         dest_type,
                        "destination_arn_hash":     dest_arn_hash or None,
                        "role_arn_present":         bool(sf_role_arn),
                        "role_arn_hash":            sf_role_arn_hash or None,
                        "distribution":             distribution,
                        "config_fetch_warnings":    None,
                    })
            except Exception as exc:
                fc = classify_aws_cloudwatch_logs_failure("DescribeSubscriptionFilters", exc)
                logger.warning(
                    "aws: DescribeSubscriptionFilters log_group=%s region=%s  code=%s",
                    lg_name_hash, region, fc.error_code,
                )

        return records
