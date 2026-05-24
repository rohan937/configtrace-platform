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

    "all" is returned for protocol "-1" (all-traffic rules).
    Admin, database, and web categories are detected by checking whether
    any sentinel port from the respective set falls within [from_port, to_port].
    """
    if protocol == "-1":
        return "all"
    if from_port is None or to_port is None:
        return "other"
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
            "future_surfaces": [
                "rds", "lambda", "api_gateway", "load_balancers",
                "waf", "cloudtrail", "guardduty", "security_hub",
                "ecs", "eks", "ecr", "eventbridge", "sqs", "sns",
                "kms", "backup", "organizations", "cloudwatch",
            ],
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
