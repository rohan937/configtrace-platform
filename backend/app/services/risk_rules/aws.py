"""AWS risk classification rules — M36 + M37 + M38.

Entry point: classify_aws_change(change)

Risk levels for M36 (account/inventory changes)
------------------------------------------------------
high     — Account identity changed, principal ARN changed to a different
           principal, selected regions significantly reduced.
medium   — Selected regions changed, default region changed, new region added,
           principal type changed.
low      — Routine metadata, opt-in status, service inventory placeholder.

Risk levels for M37 (S3 exposure and storage configuration)
------------------------------------------------------
critical — Bucket becomes public (policy_status_is_public true), public WRITE
           ACL granted, public principal added to policy on sensitive bucket.
high     — Public READ ACL granted, Block Public Access control weakened on
           sensitive bucket, public principal added to policy on any bucket,
           encryption disabled, versioning disabled on sensitive bucket.
medium   — BPA weakened on non-sensitive bucket, encryption algorithm changed,
           versioning disabled on non-sensitive bucket, logging disabled on
           sensitive bucket, policy changed (hash), lifecycle rules decreased.
low      — Protection strengthened, encryption/versioning/logging enabled,
           routine lifecycle/tag/metadata changes, unmatched S3 field.

Sensitive bucket detection
--------------------------
Bucket names are checked for known production/sensitive keywords.
Any bucket name containing one of these patterns is treated as sensitive:
prod, production, live, app, api, customer, users, uploads, assets, media,
invoices, billing, payments, stripe, backup, backups, db, database, logs,
private, secrets, config, terraform, tfstate.
"""
from __future__ import annotations

from app.connectors.aws import (
    _cidr_is_public,
    _has_port_in_range,
    _port_category,
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
)

# ── Sensitive bucket pattern detection ───────────────────────────────────────

_SENSITIVE_BUCKET_PATTERNS: frozenset[str] = frozenset({
    "prod", "production", "live", "app", "api",
    "customer", "users", "uploads", "assets", "media",
    "invoices", "billing", "payments", "stripe",
    "backup", "backups", "db", "database",
    "logs", "private", "secrets",
    "config", "terraform", "tfstate",
})


def _is_sensitive_bucket(bucket_name: str) -> bool:
    """Return True if the bucket name suggests production/sensitive data."""
    name = bucket_name.lower()
    return any(pattern in name for pattern in _SENSITIVE_BUCKET_PATTERNS)


def _get(obj: object, field: str) -> object:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


# ── aws_account_identity ─────────────────────────────────────────────────────


def _classify_account_identity_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return (
            "low",
            "AWS account identity record was established for this integration.",
        )
    if ct == "removed":
        return (
            "high",
            "The AWS account identity record was removed. "
            "This may indicate the integration lost access to the AWS account.",
        )

    # modified
    if fp == "principal_arn":
        return (
            "high",
            "The AWS IAM principal (ARN) used by this integration changed. "
            "Verify that the new credentials belong to the intended read-only "
            "identity and not an unauthorized principal.",
        )
    if fp == "principal_type":
        return (
            "medium",
            "The AWS principal type changed (e.g. from user to assumed-role). "
            "Confirm this is an expected credential update.",
        )
    if fp == "account_id":
        return (
            "high",
            "The AWS account ID changed. This integration may be pointing at a "
            "different AWS account than expected.",
        )
    if fp == "selected_regions":
        return (
            "medium",
            "The selected AWS monitoring regions changed. "
            "ConfigTrace may now scan a different set of regions.",
        )
    if fp == "default_region":
        return (
            "medium",
            "The default AWS region changed. "
            "Future regional scans may start from a different region.",
        )
    if fp == "partition":
        return (
            "medium",
            "The AWS partition changed (e.g. aws → aws-cn). "
            "This is unusual and may indicate a misconfiguration.",
        )

    return (
        "low",
        f"AWS account identity metadata changed ({fp or 'unknown field'}).",
    )


# ── aws_region ───────────────────────────────────────────────────────────────


def _classify_region_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    record_id = _get(change, "record_identifier") or ""

    if ct == "removed":
        return (
            "high",
            f"AWS region {record_id!r} was removed from monitoring. "
            "ConfigTrace will no longer scan resources in this region.",
        )
    if ct == "added":
        return (
            "medium",
            f"AWS region {record_id!r} was added to monitoring. "
            "ConfigTrace will now include this region in future scans.",
        )
    if fp == "opt_in_status":
        return (
            "low",
            f"AWS region {record_id!r} opt-in status changed.",
        )
    if fp == "enabled":
        return (
            "medium",
            f"AWS region {record_id!r} enabled status changed.",
        )

    return (
        "low",
        f"AWS region {record_id!r} metadata changed.",
    )


# ── aws_service_inventory ────────────────────────────────────────────────────


def _classify_service_inventory_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in {"added", "removed"}:
        return (
            "low",
            "AWS service inventory record was updated.",
        )
    if fp == "selected_regions":
        return (
            "medium",
            "The AWS monitoring region list changed in the service inventory. "
            "ConfigTrace may now scan a different set of regions.",
        )
    if fp == "enabled_surfaces":
        return (
            "low",
            "The set of actively monitored AWS surfaces changed.",
        )

    return (
        "low",
        f"AWS service inventory metadata changed ({fp or 'unknown field'}).",
    )


# ── aws_s3_bucket ─────────────────────────────────────────────────────────────

# Human-readable names for Block Public Access fields used in risk messages.
_BPA_FIELD_LABELS: dict[str, str] = {
    "block_public_acls":       "Block Public ACLs",
    "ignore_public_acls":      "Ignore Public ACLs",
    "block_public_policy":     "Block Public Policy",
    "restrict_public_buckets": "Restrict Public Buckets",
}


def _classify_s3_change(change: object) -> tuple[str, str]:  # noqa: C901 (complexity OK — one big dispatch)
    """Classify a change to an aws_s3_bucket record.

    Dispatches on (field_path, change_type, new_value → prev_value direction,
    bucket sensitivity) to produce a specific risk level and explanation.

    Risk assignment philosophy:
    - Becoming public or losing protections → critical or high depending on
      field and bucket sensitivity.
    - Becoming less public or strengthening protections → low.
    - Configuration changes without clear public exposure → medium/low.
    - Unknown/unavailable data does not trigger critical by itself.
    """
    fp  = (_get(change, "field_path") or "").lower()
    ct  = (_get(change, "change_type") or "").lower()
    pm  = _get(change, "provider_metadata") or {}
    nv  = _get(change, "new_value")
    pv  = _get(change, "prev_value")

    # Bucket name comes from record_name (set at diff time) or record_id.
    bucket_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
    )
    sensitive = _is_sensitive_bucket(bucket_name)

    # ── Added / removed bucket ────────────────────────────────────────────────
    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        if nv_dict.get("acl_all_users_write"):
            return (
                "critical",
                f"S3 bucket {bucket_name!r} appeared with public WRITE access "
                "enabled via ACL. External users may be able to upload or "
                "modify objects immediately.",
            )
        if nv_dict.get("policy_status_is_public"):
            return (
                "high",
                f"S3 bucket {bucket_name!r} appeared and is already marked as "
                "publicly accessible by AWS. Verify access controls are intentional.",
            )
        if nv_dict.get("acl_all_users_read") or nv_dict.get("public_principals_detected"):
            return (
                "high",
                f"S3 bucket {bucket_name!r} appeared with public READ access "
                "or a public principal in its bucket policy.",
            )
        return (
            "low",
            f"S3 bucket {bucket_name!r} appeared in monitoring.",
        )

    if ct == "removed":
        return (
            "medium",
            f"S3 bucket {bucket_name!r} is no longer visible. "
            "It may have been deleted, renamed, or become inaccessible.",
        )

    # ── Modified field changes ────────────────────────────────────────────────

    # Public policy status — authoritative AWS signal
    if fp == "policy_status_is_public":
        if nv is True:
            return (
                "critical",
                f"S3 bucket {bucket_name!r} is now marked as publicly "
                "accessible by AWS. Objects may be readable by anyone on the "
                "internet without authentication. Review the bucket policy and "
                "Block Public Access settings immediately.",
            )
        if nv is False and pv is True:
            return (
                "low",
                f"S3 bucket {bucket_name!r} is no longer publicly accessible "
                "according to AWS policy status. Confirm access controls are "
                "correctly configured.",
            )
        return (
            "medium",
            f"S3 bucket {bucket_name!r} policy public status changed.",
        )

    # ACL public WRITE for AllUsers — critical at any sensitivity
    if fp == "acl_all_users_write":
        if nv is True:
            return (
                "critical",
                f"Public WRITE access was granted through an ACL on S3 bucket "
                f"{bucket_name!r}. External users may be able to upload or "
                "modify objects without authentication.",
            )
        if nv is False:
            return (
                "low",
                f"Public WRITE ACL was removed from S3 bucket {bucket_name!r}. "
                "This is a security improvement.",
            )
        # nv is None — GetBucketAcl permission removed; ACL status is unknown.
        # Do not claim the ACL was removed when we cannot confirm it.
        return (
            "low",
            f"Public WRITE ACL status for S3 bucket {bucket_name!r} is now "
            "unavailable. Verify ACL configuration if a read permission changed.",
        )

    # ACL public READ for AllUsers
    if fp == "acl_all_users_read":
        if nv is True:
            return (
                "high",
                f"S3 bucket {bucket_name!r} now allows public READ access via "
                "ACL. Objects may be readable by anyone on the internet without "
                "authentication. Check if this is intentional.",
            )
        if nv is False:
            return (
                "low",
                f"Public READ ACL was removed from S3 bucket {bucket_name!r}.",
            )
        # nv is None — ACL status unavailable; cannot confirm removal.
        return (
            "low",
            f"Public READ ACL status for S3 bucket {bucket_name!r} is now "
            "unavailable. Verify ACL configuration if a read permission changed.",
        )

    # ACL WRITE for authenticated AWS users (any AWS account)
    if fp == "acl_authenticated_users_write":
        if nv is True:
            return (
                "high",
                f"S3 bucket {bucket_name!r} now allows WRITE access for all "
                "authenticated AWS users via ACL. Any AWS account can modify "
                "or delete objects in this bucket.",
            )
        if nv is False:
            return (
                "low",
                f"AuthenticatedUsers WRITE ACL was removed from S3 bucket {bucket_name!r}.",
            )
        # nv is None — ACL status unavailable.
        return (
            "low",
            f"AuthenticatedUsers WRITE ACL status for S3 bucket {bucket_name!r} "
            "is now unavailable.",
        )

    # ACL READ for authenticated AWS users
    if fp == "acl_authenticated_users_read":
        if nv is True:
            return (
                "medium",
                f"S3 bucket {bucket_name!r} now allows READ access for all "
                "authenticated AWS users via ACL. Any AWS account can list and "
                "read objects in this bucket.",
            )
        if nv is False:
            return (
                "low",
                f"AuthenticatedUsers READ ACL was removed from S3 bucket {bucket_name!r}.",
            )
        # nv is None — ACL status unavailable.
        return (
            "low",
            f"AuthenticatedUsers READ ACL status for S3 bucket {bucket_name!r} "
            "is now unavailable.",
        )

    # Public principal in bucket policy
    if fp == "public_principals_detected":
        if nv is True and pv is not True:
            level = "critical" if sensitive else "high"
            return (
                level,
                f"The bucket policy for S3 bucket {bucket_name!r} now contains "
                "a public principal (* or all AWS accounts). This may allow "
                "unauthenticated or cross-account access to bucket contents. "
                "Review the policy immediately.",
            )
        if nv is False:
            return (
                "low",
                f"The bucket policy for S3 bucket {bucket_name!r} no longer "
                "contains a public principal.",
            )
        return (
            "medium",
            f"Public-principal detection changed for S3 bucket {bucket_name!r}.",
        )

    # Block Public Access fields weakened or strengthened
    if fp in _BPA_FIELD_LABELS:
        label = _BPA_FIELD_LABELS[fp]
        if nv is False and pv is True:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"'{label}' was disabled on S3 bucket {bucket_name!r}. "
                "Future bucket policies or ACLs may expose objects publicly. "
                "Verify this change was intentional and check current public "
                "access status.",
            )
        if nv is True and pv is False:
            return (
                "low",
                f"'{label}' was enabled on S3 bucket {bucket_name!r}. "
                "Public access protection strengthened.",
            )
        return (
            "low",
            f"Block Public Access setting '{label}' changed on S3 bucket {bucket_name!r}.",
        )

    # BPA configuration added or removed entirely
    if fp == "public_access_block_configured":
        if nv is False and pv is True:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Block Public Access configuration was removed from S3 bucket "
                f"{bucket_name!r}. The bucket now relies entirely on bucket "
                "policy and ACLs for access control. Check current exposure.",
            )
        if nv is True:
            return (
                "low",
                f"Block Public Access was configured on S3 bucket {bucket_name!r}.",
            )
        return (
            "medium",
            f"Block Public Access configuration changed on S3 bucket {bucket_name!r}.",
        )

    # Encryption disabled / enabled
    if fp == "encryption_enabled":
        if nv is False:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Default encryption was disabled on S3 bucket {bucket_name!r}. "
                "Newly stored objects may no longer be encrypted at rest by "
                "default. Verify encryption requirements for this bucket.",
            )
        if nv is True:
            return (
                "low",
                f"Default encryption was enabled on S3 bucket {bucket_name!r}. "
                "Objects will be encrypted at rest.",
            )
        return (
            "medium",
            f"Encryption status changed on S3 bucket {bucket_name!r}.",
        )

    if fp == "encryption_algorithm":
        return (
            "medium",
            f"Encryption algorithm changed on S3 bucket {bucket_name!r} "
            f"(was {pv!r}, now {nv!r}). Verify the new algorithm meets your "
            "compliance requirements.",
        )

    if fp == "bucket_key_enabled":
        if nv is False:
            return (
                "low",
                f"S3 Bucket Key was disabled on {bucket_name!r}. "
                "KMS API request costs may increase.",
            )
        return (
            "low",
            f"S3 Bucket Key was enabled on {bucket_name!r}. "
            "KMS API request costs may decrease.",
        )

    # Versioning status
    if fp == "versioning_status":
        # Guard: None means the field became unavailable (GetBucketVersioning
        # permission removed), not that versioning was actually disabled.
        # Treat unavailability as low — we cannot confirm a security regression.
        if nv is None:
            return (
                "low",
                f"Versioning status for S3 bucket {bucket_name!r} is now "
                "unavailable. A read permission may have been removed.",
            )
        nv_str = nv.lower() if isinstance(nv, str) else str(nv).lower()
        pv_str = str(pv).lower() if pv is not None else ""
        if nv_str in ("suspended", "disabled") and pv_str == "enabled":
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Versioning was {nv_str} on S3 bucket {bucket_name!r}. "
                "Recovery from accidental deletion or overwrite may be harder. "
                "Verify this change was intentional.",
            )
        if nv_str == "enabled":
            return (
                "low",
                f"Versioning was enabled on S3 bucket {bucket_name!r}. "
                "Objects can now be recovered from accidental deletion.",
            )
        return (
            "low",
            f"Versioning status changed on S3 bucket {bucket_name!r} "
            f"(was {pv!r}, now {nv!r}).",
        )

    if fp == "mfa_delete_status":
        if str(nv).lower() == "disabled" and str(pv).lower() == "enabled":
            return (
                "medium",
                f"MFA delete was disabled on S3 bucket {bucket_name!r}. "
                "Objects can now be permanently deleted without MFA confirmation.",
            )
        if str(nv).lower() == "enabled":
            return (
                "low",
                f"MFA delete was enabled on S3 bucket {bucket_name!r}.",
            )
        return (
            "low",
            f"MFA delete status changed on S3 bucket {bucket_name!r}.",
        )

    # Logging
    if fp == "logging_enabled":
        if nv is False:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"Server access logging was disabled on S3 bucket {bucket_name!r}. "
                "Access requests will no longer be recorded, which may affect "
                "audit trail and security incident investigation.",
            )
        if nv is True:
            return (
                "low",
                f"Server access logging was enabled on S3 bucket {bucket_name!r}. "
                "Access requests will now be recorded.",
            )
        return (
            "low",
            f"Logging status changed on S3 bucket {bucket_name!r}.",
        )

    if fp == "logging_target_bucket":
        return (
            "low",
            f"Log delivery target changed for S3 bucket {bucket_name!r} "
            f"(now: {nv!r}). Verify logs are still being collected.",
        )

    # Lifecycle rules
    if fp == "lifecycle_rule_count":
        if isinstance(nv, int) and isinstance(pv, int):
            if nv < pv:
                return (
                    "medium",
                    f"Lifecycle rules decreased from {pv} to {nv} on S3 bucket "
                    f"{bucket_name!r}. Data retention policies may have changed. "
                    "Verify expiration and transition rules are still correct.",
                )
            if nv > pv:
                return (
                    "low",
                    f"Lifecycle rules increased from {pv} to {nv} on S3 bucket "
                    f"{bucket_name!r}.",
                )
        return (
            "low",
            f"Lifecycle configuration changed on S3 bucket {bucket_name!r}.",
        )

    # Policy: present / absent
    if fp == "policy_present":
        if nv is True and pv is False:
            return (
                "medium",
                f"A bucket policy was added to S3 bucket {bucket_name!r}. "
                "Review the new policy for unintended public or cross-account "
                "access grants.",
            )
        if nv is False and pv is True:
            return (
                "low",
                f"The bucket policy was removed from S3 bucket {bucket_name!r}.",
            )
        return (
            "low",
            f"Bucket policy presence changed for S3 bucket {bucket_name!r}.",
        )

    # Policy text changed (hash changed, public status may not have changed)
    if fp == "policy_hash":
        return (
            "medium",
            f"The bucket policy text for S3 bucket {bucket_name!r} changed. "
            "Verify the updated policy does not grant unintended public or "
            "cross-account access.",
        )

    # Bucket region
    if fp == "bucket_region":
        return (
            "medium",
            f"The recorded region for S3 bucket {bucket_name!r} changed "
            f"(was {pv!r}, now {nv!r}). S3 bucket regions are immutable — "
            "this may indicate a configuration inconsistency.",
        )

    # Tag keys
    if fp == "tag_keys":
        return (
            "low",
            f"Tag keys changed on S3 bucket {bucket_name!r}. "
            "Tag-based access controls or cost allocation may be affected.",
        )

    # Fetch warnings changed (permission set changed)
    if fp == "config_fetch_warnings":
        return (
            "low",
            f"The set of S3 configuration fetch warnings changed for bucket "
            f"{bucket_name!r}. A permission may have been granted or revoked.",
        )

    # Default catch-all
    return (
        "low",
        f"S3 bucket {bucket_name!r} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ── M38: Security group helpers ───────────────────────────────────────────────


def _sg_group_name(change: object) -> str:
    """Return a human-readable group label from provider_metadata."""
    pm = _get(change, "provider_metadata") or {}
    record_id: str = pm.get("record_id") or ""
    record_name: str = pm.get("record_name") or ""
    if record_name:
        return record_name
    # record_id format: "{region}/{group_id}"
    parts = record_id.split("/")
    return parts[-1] if parts else "unknown"


def _sg_rule_context(rule: dict) -> tuple[str, str, str, int | None, int | None, str]:
    """Extract key rule properties from a full rule record dict."""
    group_id: str = rule.get("group_id") or "unknown"
    region: str = rule.get("region") or ""
    protocol: str = rule.get("protocol") or "-1"
    from_port: int | None = rule.get("from_port")
    to_port: int | None = rule.get("to_port")
    cidr: str = (
        rule.get("cidr_ipv4")
        or rule.get("cidr_ipv6")
        or (f"group:{rule['referenced_group_id']}" if rule.get("referenced_group_id") else "")
        or ""
    )
    return group_id, region, protocol, from_port, to_port, cidr


def _risk_for_public_ingress_rule(
    group_id: str,
    region: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidr: str,
    group_name: str = "",
) -> tuple[str, str]:
    """Return (risk_level, risk_reason) for a public ingress rule (added).

    Uses "may be reachable" hedging throughout — a SG rule allowing public
    access does not prove reachability without subnet/IGW/route-table context.

    Args:
        group_name: Human-readable security group name, used to detect
                    sensitive/production groups that warrant higher risk for
                    web traffic rules.  Defaults to empty string (non-sensitive).
    """
    port_cat = _port_category(from_port, to_port, protocol)
    port_str = (
        "all ports and protocols" if protocol == "-1"
        else f"port {from_port}" if from_port == to_port and from_port is not None
        else f"ports {from_port}–{to_port}" if from_port is not None
        else "unknown port"
    )

    if port_cat == "admin":
        # Identify specific admin service for the message
        if _has_port_in_range(22, from_port, to_port, protocol):
            admin_name = "SSH (port 22)"
        elif _has_port_in_range(3389, from_port, to_port, protocol):
            admin_name = "RDP (port 3389)"
        elif _has_port_in_range(5985, from_port, to_port, protocol) or _has_port_in_range(5986, from_port, to_port, protocol):
            admin_name = "WinRM"
        else:
            admin_name = f"admin access ({port_str})"

        return (
            "critical",
            f"An inbound {admin_name} rule was added to security group {group_id!r} "
            f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
            f"Instances attached to this security group may be reachable from the public "
            f"internet via {admin_name}. "
            f"Restrict the source CIDR to known trusted IP ranges.",
        )

    if port_cat == "database":
        return (
            "critical",
            f"An inbound database port rule was added to security group {group_id!r} "
            f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
            f"Database services may be reachable from the public internet. "
            f"Database ports should never be publicly accessible. "
            f"Restrict the source CIDR to application security groups only.",
        )

    if port_cat == "all":
        return (
            "critical",
            f"An inbound rule allowing ALL traffic was added to security group {group_id!r} "
            f"in {region or 'unknown region'} from {cidr or 'all sources'}. "
            f"All ports and protocols may be reachable from the public internet. "
            f"This is a significant network exposure. Remove or restrict this rule immediately.",
        )

    if port_cat == "web":
        # Sensitive groups (production, backend, internal, admin, etc.) warrant
        # a higher signal even for expected web ports — public web exposure on
        # those groups merits deliberate review.
        sensitive = _is_sensitive_principal(group_name)

        if _has_port_in_range(80, from_port, to_port, protocol) or _has_port_in_range(8080, from_port, to_port, protocol):
            level = "high" if sensitive else "medium"
            note = (
                f"HTTP on a sensitive or production-facing group should be "
                f"reviewed immediately. HTTPS (port 443) is preferred."
                if sensitive
                else f"Verify that public HTTP access is intentional for the "
                     f"attached resources. HTTPS (port 443) is preferred for web traffic."
            )
            return (
                level,
                f"An inbound HTTP rule ({port_str}) was added to security group {group_id!r} "
                f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
                f"{note}",
            )

        # HTTPS (443, 8443) — publicly expected for web services, but still
        # worth reviewing on sensitive groups.
        level = "high" if sensitive else "medium"
        note = (
            f"HTTPS on a sensitive or production-facing group should be reviewed "
            f"to confirm only the intended resources are reachable from the internet."
            if sensitive
            else f"HTTPS access from the internet is expected for public web services. "
                 f"Verify this group is attached to the appropriate resources."
        )
        return (
            level,
            f"An inbound HTTPS rule ({port_str}) was added to security group {group_id!r} "
            f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
            f"{note}",
        )

    # Other port with public CIDR
    return (
        "medium",
        f"An inbound rule for {port_str} was added to security group {group_id!r} "
        f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
        f"Verify that this public access is intentional.",
    )


# ── M38: aws_security_group_rule ──────────────────────────────────────────────


def _classify_security_group_rule_change(change: object) -> tuple[str, str]:
    """Classify changes to individual security group rules.

    Added rules:
      - Critical for public inbound SSH, RDP, database ports, or all-traffic.
      - High for public inbound HTTP/HTTPS on sensitive/production-named groups.
      - Medium for public inbound HTTP/HTTPS on non-sensitive groups, or other ports.
      - Low for private CIDRs, group references, or egress.
    Removed rules:
      - Always low (rule removed = less exposure or routine cleanup).
    Modified rules (description only):
      - Always low (description change, no security posture change).
    """
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    fp = (_get(change, "field_path") or "").lower()

    if ct == "added":
        rule = nv if isinstance(nv, dict) else {}
        group_id, region, protocol, from_port, to_port, cidr = _sg_rule_context(rule)
        direction: str = rule.get("direction") or ""
        is_public: bool = bool(rule.get("is_public"))

        if direction == "ingress" and is_public:
            # Extract the security group name from provider_metadata for
            # sensitive-group escalation on web port rules.
            pm = _get(change, "provider_metadata") or {}
            sg_name = (pm.get("record_name") or "") if isinstance(pm, dict) else ""
            return _risk_for_public_ingress_rule(
                group_id, region, protocol, from_port, to_port, cidr, sg_name
            )

        if direction == "ingress":
            ref_gid = rule.get("referenced_group_id")
            if ref_gid:
                return (
                    "low",
                    f"An inbound rule referencing security group {ref_gid!r} was added "
                    f"to {group_id!r}. Verify the referenced group's rules are appropriate.",
                )
            return (
                "low",
                f"An inbound rule was added to security group {group_id!r} "
                f"in {region or 'unknown region'} from a private or restricted CIDR.",
            )

        # Egress rules
        if direction == "egress":
            port_cat = _port_category(from_port, to_port, protocol)
            if is_public and port_cat == "all":
                # Default all-egress rule — very common and expected
                return (
                    "low",
                    f"A default all-traffic egress rule was added to security group "
                    f"{group_id!r}. This is standard EC2 default behaviour — all "
                    f"outbound traffic is allowed.",
                )
            return (
                "low",
                f"An egress rule was added to security group {group_id!r}.",
            )

        return ("low", f"A security group rule was added to {group_id!r}.")

    if ct == "removed":
        rule = pv if isinstance(pv, dict) else {}
        group_id, region, protocol, from_port, to_port, cidr = _sg_rule_context(rule)
        direction = rule.get("direction") or ""
        is_public = bool(rule.get("is_public"))
        port_cat = _port_category(from_port, to_port, protocol)

        if direction == "ingress" and is_public and port_cat in ("admin", "database", "all"):
            return (
                "low",
                f"A public-facing inbound {port_cat} rule was removed from security group "
                f"{group_id!r} in {region or 'unknown region'}. "
                f"Public exposure via {cidr or 'the previous CIDR'} has been reduced. "
                f"Verify the removal was intentional.",
            )
        return (
            "low",
            f"A security group rule was removed from {group_id!r}. "
            f"Network access may have changed.",
        )

    # Modified — only description can change in place
    if ct == "modified" and fp == "description":
        pm = _get(change, "provider_metadata") or {}
        rid = pm.get("record_id") or ""
        parts = rid.split("/")
        group_label = parts[1] if len(parts) >= 2 else "unknown"
        return (
            "low",
            f"A security group rule description was updated in group {group_label!r}.",
        )

    return ("low", "A security group rule changed.")


# ── M38: aws_security_group ───────────────────────────────────────────────────


def _classify_security_group_change(change: object) -> tuple[str, str]:
    """Classify changes to security group aggregate records.

    The aws_security_group record tracks group-level posture (has_public_ssh,
    has_public_rdp, has_public_database_port, has_public_inbound, rule counts).
    Individual rule risk is covered by _classify_security_group_rule_change.
    """
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    label = _sg_group_name(change)

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        if (
            nv_dict.get("has_public_ssh")
            or nv_dict.get("has_public_rdp")
            or nv_dict.get("has_public_database_port")
        ):
            return (
                "high",
                f"Security group {label!r} appeared with public-facing rules for "
                f"admin or database ports. Instances attached to this group may be "
                f"reachable from the public internet. Verify all rules are intentional.",
            )
        if nv_dict.get("has_public_inbound"):
            return (
                "medium",
                f"Security group {label!r} appeared with public inbound rules. "
                f"Verify the intended level of internet access.",
            )
        return ("low", f"Security group {label!r} appeared in monitoring.")

    if ct == "removed":
        return (
            "medium",
            f"Security group {label!r} was removed. "
            f"Instances that referenced this group may have their network access changed. "
            f"Verify the removal was intentional.",
        )

    # Modified field changes
    if fp == "has_public_ssh":
        if nv is True:
            return (
                "high",
                f"Security group {label!r} now has an inbound rule allowing SSH "
                f"(port 22) from the public internet (0.0.0.0/0 or ::/0). "
                f"Instances attached to this group may be reachable via SSH from any IP address.",
            )
        return (
            "low",
            f"Security group {label!r} no longer has a public SSH rule. "
            f"SSH exposure from the internet has been reduced.",
        )

    if fp == "has_public_rdp":
        if nv is True:
            return (
                "high",
                f"Security group {label!r} now has an inbound rule allowing RDP "
                f"(port 3389) from the public internet. "
                f"Windows instances attached to this group may be reachable via RDP.",
            )
        return (
            "low",
            f"Security group {label!r} no longer has a public RDP rule. "
            f"RDP exposure from the internet has been reduced.",
        )

    if fp == "has_public_database_port":
        if nv is True:
            return (
                "high",
                f"Security group {label!r} now has inbound rules allowing database "
                f"ports from the public internet. Database services may be reachable "
                f"from any IP address. Review and restrict access immediately.",
            )
        return (
            "low",
            f"Security group {label!r} no longer exposes database ports to the "
            f"public internet. Exposure reduced.",
        )

    if fp == "has_public_inbound":
        if nv is True:
            return (
                "medium",
                f"Security group {label!r} now has at least one inbound rule open to "
                f"the public internet. Verify the intended exposure.",
            )
        return (
            "low",
            f"Security group {label!r} no longer has public inbound rules. "
            f"Internet-facing exposure has been removed.",
        )

    if fp in ("inbound_rule_count", "outbound_rule_count"):
        direction_label = "inbound" if "inbound" in fp else "outbound"
        if isinstance(nv, int) and isinstance(pv, int):
            if nv < pv:
                return (
                    "medium",
                    f"Security group {label!r} {direction_label} rule count decreased "
                    f"from {pv} to {nv}. Rules may have been removed. "
                    f"Verify the intended network access.",
                )
            return (
                "low",
                f"Security group {label!r} {direction_label} rule count increased "
                f"from {pv} to {nv}.",
            )
        return ("low", f"Security group {label!r} rule count changed.")

    if fp == "description":
        return ("low", f"Security group {label!r} description was updated.")

    if fp == "group_name":
        return ("low", f"Security group was renamed to {nv!r}.")

    if fp == "vpc_id":
        return (
            "medium",
            f"Security group {label!r} VPC association changed "
            f"(was {pv!r}, now {nv!r}). Verify the group is in the intended VPC.",
        )

    if fp == "tag_keys":
        return ("low", f"Security group {label!r} tag keys changed.")

    return (
        "low",
        f"Security group {label!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── M38: aws_vpc ─────────────────────────────────────────────────────────────


def _classify_vpc_change(change: object) -> tuple[str, str]:
    """Classify changes to VPC records."""
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    rid = pm.get("record_id") or ""
    parts = rid.split("/")
    vpc_id = parts[-1] if parts else "unknown"

    if ct == "added":
        return ("low", f"VPC {vpc_id!r} appeared in monitoring.")
    if ct == "removed":
        return (
            "medium",
            f"VPC {vpc_id!r} is no longer visible. "
            f"It may have been deleted or become inaccessible.",
        )

    if fp == "state":
        if nv not in ("available",):
            return (
                "medium",
                f"VPC {vpc_id!r} state changed to {nv!r}. "
                f"Verify the VPC is operational.",
            )
        return ("low", f"VPC {vpc_id!r} state changed to {nv!r}.")

    if fp == "instance_tenancy":
        return (
            "medium",
            f"VPC {vpc_id!r} instance tenancy changed to {nv!r}. "
            f"Verify billing and compliance implications.",
        )

    if fp == "dhcp_options_id":
        return (
            "medium",
            f"DHCP options set changed for VPC {vpc_id!r} "
            f"(was {pv!r}, now {nv!r}). "
            f"DNS resolution and domain settings may be affected.",
        )

    if fp == "cidr_block":
        return (
            "medium",
            f"The primary CIDR block for VPC {vpc_id!r} changed "
            f"(was {pv!r}, now {nv!r}). Verify routing and subnet allocation.",
        )

    return ("low", f"VPC {vpc_id!r} metadata changed ({fp or 'unknown field'}).")


# ── M38: aws_subnet ───────────────────────────────────────────────────────────


def _classify_subnet_change(change: object) -> tuple[str, str]:
    """Classify changes to subnet records."""
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    rid = pm.get("record_id") or ""
    parts = rid.split("/")
    subnet_id = parts[-1] if parts else "unknown"

    if ct == "added":
        return ("low", f"Subnet {subnet_id!r} appeared in monitoring.")
    if ct == "removed":
        return ("low", f"Subnet {subnet_id!r} is no longer visible.")

    if fp == "map_public_ip_on_launch":
        if nv is True:
            return (
                "high",
                f"Auto-assign public IPv4 addresses was enabled on subnet {subnet_id!r}. "
                f"Instances launched in this subnet will automatically receive public IP "
                f"addresses. Verify that this is intentional and that security groups "
                f"appropriately restrict inbound access.",
            )
        if nv is False:
            return (
                "low",
                f"Auto-assign public IPv4 addresses was disabled on subnet {subnet_id!r}. "
                f"Instances launched here will no longer receive public IPs automatically.",
            )
        return (
            "medium",
            f"Subnet {subnet_id!r} public IP auto-assignment status changed.",
        )

    if fp == "state":
        return ("low", f"Subnet {subnet_id!r} state changed to {nv!r}.")

    if fp == "available_ip_count":
        return ("low", f"Available IP address count changed in subnet {subnet_id!r}.")

    return ("low", f"Subnet {subnet_id!r} configuration changed ({fp or 'unknown field'}).")


# ── M38: aws_route_table ──────────────────────────────────────────────────────


def _classify_route_table_change(change: object) -> tuple[str, str]:
    """Classify changes to route table records.

    has_igw_route is the primary risk signal: when True, resources associated
    with this route table may route traffic through an Internet Gateway.
    """
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    rid = pm.get("record_id") or ""
    parts = rid.split("/")
    rt_id = parts[-1] if parts else "unknown"

    if ct == "added":
        return ("low", f"Route table {rt_id!r} appeared in monitoring.")
    if ct == "removed":
        return ("low", f"Route table {rt_id!r} is no longer visible.")

    if fp == "has_igw_route":
        if nv is True:
            return (
                "high",
                f"Route table {rt_id!r} now has a route to an Internet Gateway. "
                f"Resources associated with this route table may now have internet "
                f"connectivity. Verify that security groups and Network ACLs are "
                f"configured to restrict inbound access appropriately.",
            )
        if nv is False:
            return (
                "low",
                f"The Internet Gateway route was removed from route table {rt_id!r}. "
                f"Internet connectivity for associated resources may have been removed.",
            )
        return ("medium", f"Route table {rt_id!r} IGW routing status changed.")

    if fp == "igw_id":
        return (
            "medium",
            f"Route table {rt_id!r} Internet Gateway reference changed "
            f"(was {pv!r}, now {nv!r}). Verify the new IGW is correct.",
        )

    if fp == "route_count":
        if isinstance(nv, int) and isinstance(pv, int):
            if nv < pv:
                return (
                    "medium",
                    f"Route count decreased in route table {rt_id!r} "
                    f"(was {pv}, now {nv}). Routes may have been removed.",
                )
            return (
                "low",
                f"Route count increased in route table {rt_id!r} "
                f"(was {pv}, now {nv}).",
            )
        return ("low", f"Route count changed in route table {rt_id!r}.")

    if fp == "associated_subnet_ids":
        return (
            "low",
            f"Subnet associations changed for route table {rt_id!r}.",
        )

    return (
        "low",
        f"Route table {rt_id!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── M38: aws_internet_gateway ─────────────────────────────────────────────────


def _classify_igw_change(change: object) -> tuple[str, str]:
    """Classify changes to Internet Gateway records."""
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    rid = pm.get("record_id") or ""
    parts = rid.split("/")
    igw_id = parts[-1] if parts else "unknown"

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        if nv_dict.get("attached_vpc_id"):
            return (
                "medium",
                f"Internet Gateway {igw_id!r} appeared already attached to VPC "
                f"{nv_dict['attached_vpc_id']!r}.",
            )
        return ("low", f"Internet Gateway {igw_id!r} appeared in monitoring.")

    if ct == "removed":
        return (
            "low",
            f"Internet Gateway {igw_id!r} is no longer visible. "
            f"It may have been deleted.",
        )

    if fp == "attached_vpc_id":
        if pv is None and nv is not None:
            return (
                "high",
                f"Internet Gateway {igw_id!r} was attached to VPC {nv!r}. "
                f"Resources in this VPC may now have internet connectivity. "
                f"Verify that route tables and security groups are configured to "
                f"restrict inbound access appropriately.",
            )
        if pv is not None and nv is None:
            return (
                "low",
                f"Internet Gateway {igw_id!r} was detached from VPC {pv!r}. "
                f"Internet connectivity for resources in this VPC has been removed.",
            )
        return (
            "medium",
            f"Internet Gateway {igw_id!r} VPC attachment changed "
            f"(was {pv!r}, now {nv!r}).",
        )

    if fp == "state":
        return ("low", f"Internet Gateway {igw_id!r} state changed to {nv!r}.")

    return (
        "low",
        f"Internet Gateway {igw_id!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── M38: aws_network_acl ──────────────────────────────────────────────────────


def _classify_network_acl_change(change: object) -> tuple[str, str]:
    """Classify changes to Network ACL records."""
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    rid = pm.get("record_id") or ""
    parts = rid.split("/")
    nacl_id = parts[-1] if parts else "unknown"

    if ct == "added":
        return ("low", f"Network ACL {nacl_id!r} appeared in monitoring.")
    if ct == "removed":
        return ("low", f"Network ACL {nacl_id!r} is no longer visible.")

    if fp == "inbound_allow_all_count":
        if isinstance(nv, int) and isinstance(pv, int):
            if nv > pv:
                return (
                    "medium",
                    f"The number of inbound ALLOW-all rules in Network ACL {nacl_id!r} "
                    f"increased from {pv} to {nv}. "
                    f"Verify the new rules are intentional and correctly scoped.",
                )
            if nv < pv:
                return (
                    "low",
                    f"Inbound ALLOW-all rules decreased in Network ACL {nacl_id!r} "
                    f"(was {pv}, now {nv}). Public access restriction improved.",
                )
        return (
            "medium",
            f"Inbound ALLOW-all rule count changed in Network ACL {nacl_id!r}.",
        )

    if fp == "outbound_allow_all_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return (
                "low",
                f"Outbound ALLOW-all rules increased in Network ACL {nacl_id!r}. "
                f"This is generally expected for standard configurations.",
            )
        return (
            "low",
            f"Outbound ALLOW-all rule count changed in Network ACL {nacl_id!r}.",
        )

    if fp == "rule_count":
        return (
            "low",
            f"Rule count changed in Network ACL {nacl_id!r} "
            f"(was {pv!r}, now {nv!r}).",
        )

    return (
        "low",
        f"Network ACL {nacl_id!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── M39: IAM risk classification ──────────────────────────────────────────────

# IAM principal names that suggest production/sensitive environments.
# Used to escalate risk when sensitive principals gain broad permissions.
_SENSITIVE_PRINCIPAL_PATTERNS: frozenset[str] = frozenset({
    "prod", "production", "live", "app", "api", "database", "db",
    "admin", "bastion", "deploy", "ci", "cd", "cicd",
    "release", "master", "main", "primary",
})


def _is_sensitive_principal(name: str) -> bool:
    """Return True if the principal name suggests a production/sensitive context."""
    n = name.lower()
    return any(p in n for p in _SENSITIVE_PRINCIPAL_PATTERNS)


def _policy_summary_finding_codes(policy_summary: object) -> list[str]:
    """Extract finding_codes from a policy_summary dict or object."""
    if isinstance(policy_summary, dict):
        codes = policy_summary.get("finding_codes")
        return codes if isinstance(codes, list) else []
    return []


def _policy_summary_admin(policy_summary: object) -> bool:
    """Return True if policy_summary indicates admin access."""
    if isinstance(policy_summary, dict):
        return bool(policy_summary.get("admin_access"))
    return False


def _policy_summary_priv_esc(policy_summary: object) -> bool:
    """Return True if policy_summary indicates privilege escalation risk."""
    if isinstance(policy_summary, dict):
        codes = policy_summary.get("finding_codes") or []
        return "privilege_escalation_risk" in codes or "iam_write_access" in codes
    return False


# ── aws_iam_account_summary ───────────────────────────────────────────────────


def _classify_iam_account_summary_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if ct == "added":
        return (
            "low",
            "IAM account summary record was established for this integration.",
        )
    if ct == "removed":
        return (
            "medium",
            "The IAM account summary record was removed. "
            "Verify the integration still has IAM read permissions.",
        )

    # ── Root security ─────────────────────────────────────────────────────────
    if fp == "mfa_enabled_for_root":
        if nv is False and pv is True:
            return (
                "critical",
                "MFA was disabled on the AWS root account. "
                "Root account access without MFA is a critical security risk. "
                "Re-enable MFA on the root account immediately.",
            )
        if nv is True:
            return (
                "low",
                "MFA was enabled on the AWS root account. "
                "This is a security improvement.",
            )
        return ("medium", "Root account MFA status changed.")

    if fp == "root_access_keys_present":
        if nv is True and pv is not True:
            return (
                "critical",
                "Root account access keys are now present. "
                "AWS best practice is to never create root access keys. "
                "Remove these keys from the root account immediately.",
            )
        if nv is False:
            return (
                "low",
                "Root account access keys were removed. "
                "This is a security improvement.",
            )
        return ("medium", "Root account access key status changed.")

    # ── Password policy ───────────────────────────────────────────────────────
    if fp == "password_policy_present":
        if nv is False and pv is True:
            return (
                "high",
                "The IAM account password policy was removed. "
                "Without a policy, there are no password complexity or rotation "
                "requirements for IAM users. Consider re-enabling a strong policy.",
            )
        if nv is True:
            return (
                "low",
                "An IAM account password policy was added.",
            )
        return ("medium", "Password policy presence changed.")

    if fp == "password_min_length":
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv < pv:
            return (
                "medium",
                f"IAM password minimum length decreased from {pv!r} to {nv!r}. "
                "A shorter minimum may weaken password security.",
            )
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv > pv:
            return (
                "low",
                f"IAM password minimum length increased from {pv!r} to {nv!r}.",
            )
        return ("low", f"IAM password minimum length changed ({pv!r} → {nv!r}).")

    if fp == "password_max_age":
        if nv is None and pv is not None:
            return (
                "medium",
                "IAM password expiration policy was removed. "
                "Passwords will no longer expire automatically.",
            )
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv > pv:
            return (
                "medium",
                f"IAM password maximum age increased from {pv!r} to {nv!r} days. "
                "Passwords will expire less frequently.",
            )
        return ("low", f"IAM password age policy changed ({pv!r} → {nv!r} days).")

    if fp in ("password_requires_symbols", "password_requires_numbers",
               "password_requires_uppercase", "password_requires_lowercase"):
        if nv is False and pv is True:
            return (
                "medium",
                f"IAM password complexity requirement '{fp}' was disabled. "
                "This may weaken password security for IAM users.",
            )
        if nv is True:
            return ("low", f"IAM password complexity requirement '{fp}' was enabled.")
        return ("low", f"IAM password complexity requirement '{fp}' changed.")

    if fp == "password_reuse_prevention":
        if nv is None and pv is not None:
            return (
                "medium",
                "IAM password reuse prevention was removed. "
                "Users may now reuse old passwords.",
            )
        return ("low", f"IAM password reuse prevention changed ({pv!r} → {nv!r}).")

    # ── Aggregate counts ──────────────────────────────────────────────────────
    if fp in ("user_count", "group_count", "role_count", "policy_count"):
        return (
            "low",
            f"IAM {fp.replace('_', ' ')} changed from {pv!r} to {nv!r}. "
            "Review the IAM users, groups, roles, or policies lists for details.",
        )

    return (
        "low",
        f"IAM account summary changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_user ──────────────────────────────────────────────────────────────


def _classify_iam_user_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    user_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )
    sensitive = _is_sensitive_principal(user_name)

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        if nv_dict.get("active_key_count", 0) > 0 and not nv_dict.get("mfa_enabled"):
            return (
                "high",
                f"IAM user {user_name!r} was created with active access keys "
                "and no MFA. Access keys without MFA may allow programmatic "
                "access without a second factor. Review this user's purpose.",
            )
        return (
            "low",
            f"IAM user {user_name!r} was created.",
        )

    if ct == "removed":
        level = "medium" if sensitive else "low"
        return (
            level,
            f"IAM user {user_name!r} was removed. "
            "Verify that any active credentials belonging to this user "
            "have been revoked.",
        )

    # ── MFA ───────────────────────────────────────────────────────────────────
    if fp == "mfa_enabled":
        if nv is False and pv is True:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"MFA was disabled for IAM user {user_name!r}. "
                "This user can now authenticate without a second factor. "
                "Verify this change was intentional.",
            )
        if nv is True:
            return (
                "low",
                f"MFA was enabled for IAM user {user_name!r}. "
                "This is a security improvement.",
            )
        return ("low", f"MFA status changed for IAM user {user_name!r}.")

    if fp == "mfa_device_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv < pv and nv == 0:
            return (
                "high" if sensitive else "medium",
                f"IAM user {user_name!r} no longer has any MFA devices. "
                "This user can authenticate without a second factor.",
            )
        return ("low", f"MFA device count changed for IAM user {user_name!r}.")

    # ── Access keys ───────────────────────────────────────────────────────────
    if fp == "active_key_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return (
                "medium",
                f"The number of active access keys for IAM user {user_name!r} "
                f"increased from {pv} to {nv}. "
                "Verify the new key was intentionally created.",
            )
        if isinstance(nv, int) and isinstance(pv, int) and nv < pv:
            return (
                "low",
                f"The number of active access keys for IAM user {user_name!r} "
                f"decreased from {pv} to {nv}.",
            )
        return ("low", f"Active access key count changed for IAM user {user_name!r}.")

    if fp == "inactive_key_count":
        return (
            "low",
            f"Inactive access key count changed for IAM user {user_name!r}. "
            "Consider removing unused inactive keys.",
        )

    if fp == "last_key_used_age_days":
        if isinstance(nv, int) and nv > 90:
            return (
                "low",
                f"IAM user {user_name!r} has not used any access key in "
                f"{nv} days. Consider rotating or deactivating stale keys.",
            )
        return ("low", f"Access key last-used age changed for IAM user {user_name!r}.")

    # ── Policy membership ─────────────────────────────────────────────────────
    if fp == "attached_policy_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"The number of managed policies attached to IAM user "
                f"{user_name!r} increased from {pv} to {nv}. "
                "Review the new policy attachments for permission changes.",
            )
        return ("low", f"Managed policy count changed for IAM user {user_name!r}.")

    if fp == "inline_policy_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"The number of inline policies on IAM user {user_name!r} "
                f"increased from {pv} to {nv}. "
                "Review new inline policies for broad permissions.",
            )
        return ("low", f"Inline policy count changed for IAM user {user_name!r}.")

    if fp == "group_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return (
                "low",
                f"IAM user {user_name!r} was added to more groups "
                f"({pv} → {nv}). Group membership may grant additional permissions.",
            )
        return ("low", f"Group membership count changed for IAM user {user_name!r}.")

    return (
        "low",
        f"IAM user {user_name!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_access_key ────────────────────────────────────────────────────────


def _classify_iam_access_key_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    record_id: str = (
        (pm.get("record_id") or pm.get("record_name") or "")
        if isinstance(pm, dict) else ""
    )

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        if (nv_dict.get("status") or "").lower() == "active":
            return (
                "medium",
                f"A new active IAM access key {record_id!r} was created. "
                "Verify this key was intentionally issued and belongs to the "
                "expected user.",
            )
        return (
            "low",
            f"IAM access key {record_id!r} appeared in monitoring.",
        )

    if ct == "removed":
        return (
            "low",
            f"IAM access key {record_id!r} was removed. "
            "If this key was active, ensure dependent services are updated.",
        )

    if fp == "status":
        nv_str = (nv or "").lower() if isinstance(nv, str) else ""
        pv_str = (pv or "").lower() if isinstance(pv, str) else ""
        if nv_str == "inactive" and pv_str == "active":
            return (
                "low",
                f"IAM access key {record_id!r} was deactivated. "
                "Services using this key will lose access.",
            )
        if nv_str == "active" and pv_str == "inactive":
            return (
                "medium",
                f"IAM access key {record_id!r} was re-activated. "
                "Verify this reactivation was intentional.",
            )
        return ("low", f"IAM access key {record_id!r} status changed.")

    if fp == "last_used_age_days":
        if isinstance(nv, int) and nv > 90:
            return (
                "low",
                f"IAM access key {record_id!r} has not been used in "
                f"{nv} days. Consider deactivating or removing stale keys.",
            )
        return ("low", f"IAM access key {record_id!r} last-used age changed.")

    return (
        "low",
        f"IAM access key {record_id!r} metadata changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_group ─────────────────────────────────────────────────────────────


def _classify_iam_group_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    group_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )
    sensitive = _is_sensitive_principal(group_name)

    if ct == "added":
        return ("low", f"IAM group {group_name!r} appeared in monitoring.")
    if ct == "removed":
        return (
            "low",
            f"IAM group {group_name!r} was removed. "
            "Users that were members may have lost associated permissions.",
        )

    if fp == "member_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"IAM group {group_name!r} membership increased from {pv} to {nv}. "
                "New members inherit all group permissions.",
            )
        return ("low", f"IAM group {group_name!r} membership changed ({pv!r} → {nv!r}).")

    if fp == "attached_policy_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"More managed policies were attached to IAM group {group_name!r} "
                f"({pv} → {nv}). All group members may have gained additional permissions.",
            )
        return ("low", f"Managed policy count changed for IAM group {group_name!r}.")

    if fp == "inline_policy_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"More inline policies were added to IAM group {group_name!r} "
                f"({pv} → {nv}). Review new inline policies for broad permissions.",
            )
        return ("low", f"Inline policy count changed for IAM group {group_name!r}.")

    return (
        "low",
        f"IAM group {group_name!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_role ──────────────────────────────────────────────────────────────


def _classify_iam_role_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    role_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )
    sensitive = _is_sensitive_principal(role_name)

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        ts = nv_dict.get("trust_summary") or {}
        if isinstance(ts, dict) and ts.get("has_external_account_trust"):
            return (
                "medium",
                f"IAM role {role_name!r} appeared with trust for an external AWS "
                "account. Verify that cross-account access is intentional.",
            )
        if isinstance(ts, dict) and ts.get("has_wildcard_principal"):
            return (
                "high",
                f"IAM role {role_name!r} appeared with a wildcard (*) trust principal. "
                "Any AWS principal may be able to assume this role.",
            )
        return ("low", f"IAM role {role_name!r} appeared in monitoring.")

    if ct == "removed":
        return (
            "medium" if sensitive else "low",
            f"IAM role {role_name!r} was removed. "
            "Services or principals that assumed this role will lose access.",
        )

    # ── Trust policy changes ──────────────────────────────────────────────────
    if fp == "trust_summary":
        prev_ts = pv if isinstance(pv, dict) else {}
        new_ts  = nv if isinstance(nv, dict) else {}

        # External account trust added
        if new_ts.get("has_external_account_trust") and not prev_ts.get("has_external_account_trust"):
            level = "high" if sensitive else "medium"
            return (
                level,
                f"IAM role {role_name!r} now trusts an external AWS account. "
                "Cross-account access could allow principals from another account "
                "to assume this role. Verify the trust relationship is intentional "
                "and uses appropriate conditions.",
            )
        # External account trust removed
        if prev_ts.get("has_external_account_trust") and not new_ts.get("has_external_account_trust"):
            return (
                "low",
                f"Cross-account trust was removed from IAM role {role_name!r}. "
                "External accounts can no longer assume this role.",
            )
        # Wildcard principal added
        if new_ts.get("has_wildcard_principal") and not prev_ts.get("has_wildcard_principal"):
            return (
                "critical",
                f"IAM role {role_name!r} trust policy now includes a wildcard (*) "
                "principal. Any AWS principal may be able to assume this role. "
                "Remove the wildcard and restrict trust to specific principals.",
            )
        # Wildcard principal removed
        if prev_ts.get("has_wildcard_principal") and not new_ts.get("has_wildcard_principal"):
            return (
                "low",
                f"Wildcard principal was removed from the trust policy of "
                f"IAM role {role_name!r}. This is a security improvement.",
            )
        # External ID condition removed
        if prev_ts.get("has_external_id_condition") and not new_ts.get("has_external_id_condition"):
            return (
                "high",
                f"The ExternalId condition was removed from IAM role {role_name!r} "
                "trust policy. Removing ExternalId on a cross-account role may allow "
                "'confused deputy' attacks. Verify this change is intentional.",
            )
        # MFA condition removed
        if prev_ts.get("has_mfa_condition") and not new_ts.get("has_mfa_condition"):
            return (
                "medium",
                f"The MFA condition was removed from IAM role {role_name!r} "
                "trust policy. Role assumption no longer requires MFA.",
            )
        # Service principals changed
        prev_svcs = set(prev_ts.get("service_principals") or [])
        new_svcs  = set(new_ts.get("service_principals") or [])
        if new_svcs - prev_svcs:
            added = sorted(new_svcs - prev_svcs)
            return (
                "medium",
                f"IAM role {role_name!r} trust policy now allows additional AWS "
                f"service principal(s): {added}. Verify this is intended.",
            )
        # Root account trust added
        if new_ts.get("has_root_account_trust") and not prev_ts.get("has_root_account_trust"):
            return (
                "high",
                f"IAM role {role_name!r} now trusts an AWS account root. "
                "Root trust grants broad assume-role capability to the root identity.",
            )
        return (
            "medium",
            f"IAM role {role_name!r} trust policy changed. "
            "Review the updated trust policy to confirm principals are expected.",
        )

    # ── Session duration ──────────────────────────────────────────────────────
    if fp == "max_session_duration":
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv > pv:
            nv_hrs = round(nv / 3600, 1)
            pv_hrs = round(pv / 3600, 1)
            level = "medium" if nv > 28800 else "low"  # > 8 hours is notable
            return (
                level,
                f"Maximum session duration for IAM role {role_name!r} increased "
                f"from {pv_hrs}h to {nv_hrs}h. Longer sessions may increase the "
                "window of exposure if a session token is compromised.",
            )
        return ("low", f"Maximum session duration changed for IAM role {role_name!r}.")

    # ── Policy counts ─────────────────────────────────────────────────────────
    if fp == "attached_policy_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"More managed policies were attached to IAM role {role_name!r} "
                f"({pv} → {nv}). The role may have gained additional permissions.",
            )
        return ("low", f"Managed policy count changed for IAM role {role_name!r}.")

    if fp == "inline_policy_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"More inline policies were added to IAM role {role_name!r} "
                f"({pv} → {nv}). Review new inline policies for broad permissions.",
            )
        return ("low", f"Inline policy count changed for IAM role {role_name!r}.")

    return (
        "low",
        f"IAM role {role_name!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_policy ────────────────────────────────────────────────────────────


def _classify_iam_policy_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    policy_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        ps = nv_dict.get("policy_summary") or {}
        if _policy_summary_admin(ps):
            return (
                "high",
                f"IAM managed policy {policy_name!r} was created with admin-level "
                "permissions (Action: *, Resource: *). If attached to a principal, "
                "this could allow full account access.",
            )
        return ("low", f"IAM managed policy {policy_name!r} was created.")

    if ct == "removed":
        return (
            "low",
            f"IAM managed policy {policy_name!r} was removed. "
            "Any principals that had this policy attached will have lost the "
            "permissions it granted.",
        )

    if fp == "policy_summary":
        prev_ps = pv if isinstance(pv, dict) else {}
        new_ps  = nv if isinstance(nv, dict) else {}

        prev_codes = set(prev_ps.get("finding_codes") or [])
        new_codes  = set(new_ps.get("finding_codes") or [])

        if "admin_access" in new_codes and "admin_access" not in prev_codes:
            return (
                "critical",
                f"IAM managed policy {policy_name!r} was updated to grant "
                "admin-level access (Action: *, Resource: *). Any principal with "
                "this policy could now take any action in the account.",
            )
        if "admin_access" in prev_codes and "admin_access" not in new_codes:
            return (
                "low",
                f"IAM managed policy {policy_name!r} no longer grants admin-level "
                "access. This is a security improvement.",
            )
        if "privilege_escalation_risk" in new_codes and "privilege_escalation_risk" not in prev_codes:
            return (
                "high",
                f"IAM managed policy {policy_name!r} was updated to include "
                "privilege escalation actions (e.g. iam:PassRole, iam:CreateRole). "
                "Principals with this policy could potentially escalate their privileges.",
            )
        if "iam_write_access" in new_codes and "iam_write_access" not in prev_codes:
            return (
                "high",
                f"IAM managed policy {policy_name!r} was updated to include "
                "IAM write actions. Principals with this policy could modify "
                "other IAM users, roles, or policies.",
            )
        if "sts_assume_role" in new_codes and "sts_assume_role" not in prev_codes:
            return (
                "medium",
                f"IAM managed policy {policy_name!r} now allows sts:AssumeRole. "
                "Principals with this policy may be able to assume other roles.",
            )
        if "wildcard_action" in new_codes and "wildcard_action" not in prev_codes:
            return (
                "medium",
                f"IAM managed policy {policy_name!r} was updated to include a "
                "wildcard action (*) on a service. Review the policy document for "
                "unintended broad access.",
            )
        # Policy hash changed but no new finding codes
        prev_hash = prev_ps.get("policy_document_hash") or ""
        new_hash  = new_ps.get("policy_document_hash") or ""
        if prev_hash != new_hash:
            return (
                "medium",
                f"IAM managed policy {policy_name!r} document was updated. "
                "Review the change to verify permissions are as expected.",
            )
        return (
            "low",
            f"IAM managed policy {policy_name!r} summary changed.",
        )

    if fp == "attachment_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return (
                "low",
                f"IAM managed policy {policy_name!r} is now attached to "
                f"{nv} principals (was {pv}). Policy changes will affect more principals.",
            )
        return ("low", f"IAM managed policy {policy_name!r} attachment count changed.")

    if fp == "version_count":
        return ("low", f"IAM managed policy {policy_name!r} version count changed.")

    return (
        "low",
        f"IAM managed policy {policy_name!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_policy_attachment ─────────────────────────────────────────────────


def _classify_iam_policy_attachment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    record_id: str = (
        (pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )

    def _extract_attachment(d: object) -> tuple[str, str, str]:
        """Return (principal_name, policy_name, principal_type) from dict."""
        if isinstance(d, dict):
            return (
                d.get("principal_name") or "",
                d.get("policy_name") or "",
                d.get("principal_type") or "",
            )
        return ("", "", "")

    if ct == "added":
        principal_name, policy_name, principal_type = _extract_attachment(nv)
        sensitive = _is_sensitive_principal(principal_name)
        # Classify known high-risk managed policies
        pn_lower = policy_name.lower()
        if pn_lower in ("administratoraccess", "administrator access"):
            return (
                "critical",
                f"AdministratorAccess policy was attached to {principal_type} "
                f"{principal_name!r}. This grants unrestricted access to all AWS "
                "services and resources.",
            )
        if "poweruser" in pn_lower or "fullaccess" in pn_lower:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Policy {policy_name!r} was attached to {principal_type} "
                f"{principal_name!r}. This may grant broad access to AWS services. "
                "Verify this attachment is intentional.",
            )
        if "iamfull" in pn_lower or "iam" in pn_lower and "write" in pn_lower:
            return (
                "high",
                f"IAM-related policy {policy_name!r} was attached to {principal_type} "
                f"{principal_name!r}. IAM permissions could allow privilege escalation.",
            )
        level = "medium" if sensitive else "low"
        return (
            level,
            f"Managed policy {policy_name!r} was attached to {principal_type} "
            f"{principal_name!r}. The principal has gained the permissions in this policy.",
        )

    if ct == "removed":
        principal_name, policy_name, principal_type = _extract_attachment(pv)
        sensitive = _is_sensitive_principal(principal_name)
        level = "medium" if sensitive else "low"
        return (
            level,
            f"Managed policy {policy_name!r} was removed from {principal_type} "
            f"{principal_name!r}. The principal has lost the permissions in this policy. "
            "Verify dependent services still have required access.",
        )

    # Modified (policy_name field changed — unusual structural change)
    return (
        "low",
        f"IAM policy attachment {record_id!r} configuration changed.",
    )


# ── aws_iam_inline_policy ─────────────────────────────────────────────────────


def _classify_iam_inline_policy_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    record_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )

    if ct == "added":
        nv_dict = nv if isinstance(nv, dict) else {}
        ps = nv_dict.get("policy_summary") or {}
        if _policy_summary_admin(ps):
            return (
                "critical",
                f"Inline policy {record_name!r} was added with admin-level "
                "permissions (Action: *, Resource: *). The attached principal "
                "may now be able to take any action in the account.",
            )
        if _policy_summary_priv_esc(ps):
            return (
                "high",
                f"Inline policy {record_name!r} was added with privilege "
                "escalation actions. Review the policy to confirm this is intended.",
            )
        return ("low", f"Inline policy {record_name!r} was added.")

    if ct == "removed":
        return (
            "low",
            f"Inline policy {record_name!r} was removed. "
            "The principal has lost any permissions it granted.",
        )

    if fp == "policy_summary":
        prev_ps = pv if isinstance(pv, dict) else {}
        new_ps  = nv if isinstance(nv, dict) else {}
        prev_codes = set(prev_ps.get("finding_codes") or [])
        new_codes  = set(new_ps.get("finding_codes") or [])

        if "admin_access" in new_codes and "admin_access" not in prev_codes:
            return (
                "critical",
                f"Inline policy {record_name!r} was updated to grant admin-level "
                "access. The principal could now take any action in the account.",
            )
        if "privilege_escalation_risk" in new_codes and "privilege_escalation_risk" not in prev_codes:
            return (
                "high",
                f"Inline policy {record_name!r} was updated to include privilege "
                "escalation actions. Review the policy document for unintended access.",
            )
        if "iam_write_access" in new_codes and "iam_write_access" not in prev_codes:
            return (
                "high",
                f"Inline policy {record_name!r} was updated to include IAM write "
                "actions. The principal may be able to modify other IAM entities.",
            )
        if "wildcard_action" in new_codes and "wildcard_action" not in prev_codes:
            return (
                "medium",
                f"Inline policy {record_name!r} was updated to include a wildcard "
                "action. Review the policy for unintended broad permissions.",
            )
        # Any other policy_summary change
        return (
            "medium",
            f"Inline policy {record_name!r} document was updated. "
            "Review the change to verify permissions are as expected.",
        )

    return (
        "low",
        f"Inline policy {record_name!r} configuration changed ({fp or 'unknown field'}).",
    )


# ── aws_iam_identity_provider ─────────────────────────────────────────────────


def _classify_iam_identity_provider_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")
    pm = _get(change, "provider_metadata") or {}
    provider_name: str = (
        (pm.get("record_name") or pm.get("record_id") or "")
        if isinstance(pm, dict) else ""
    )
    nv_dict = nv if isinstance(nv, dict) else {}
    provider_type = nv_dict.get("provider_type") or "identity"

    if ct == "added":
        return (
            "medium",
            f"{provider_type.upper()} identity provider {provider_name!r} was added. "
            "Federation grants external identities the ability to assume IAM roles. "
            "Verify this provider was intentionally configured.",
        )

    if ct == "removed":
        return (
            "medium",
            f"{provider_type.upper()} identity provider {provider_name!r} was removed. "
            "External identities that authenticated via this provider will lose access.",
        )

    if fp == "oidc_client_id_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv > pv:
            return (
                "medium",
                f"OIDC provider {provider_name!r} now has more allowed client IDs "
                f"({pv} → {nv}). Additional client applications may be able to "
                "authenticate through this provider.",
            )
        return ("low", f"OIDC provider {provider_name!r} client ID count changed.")

    if fp == "oidc_thumbprint_count":
        if isinstance(nv, int) and isinstance(pv, int) and nv < pv and nv == 0:
            return (
                "high",
                f"OIDC provider {provider_name!r} has no thumbprints configured. "
                "Without thumbprint verification, the provider certificate is not "
                "validated. Review the OIDC provider configuration.",
            )
        return ("low", f"OIDC provider {provider_name!r} thumbprint count changed.")

    if fp == "saml_valid_until":
        if nv is None and pv is not None:
            return (
                "medium",
                f"SAML provider {provider_name!r} expiration date was cleared. "
                "Verify the SAML metadata certificate is still valid.",
            )
        return (
            "low",
            f"SAML provider {provider_name!r} validity date changed.",
        )

    return (
        "low",
        f"IAM identity provider {provider_name!r} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ── M40: Sensitive routing name patterns ─────────────────────────────────────

_SENSITIVE_ROUTING_PATTERNS: frozenset[str] = frozenset({
    # Production/live infrastructure
    "prod", "production", "live", "app", "api",
    # CDN / static delivery
    "cdn", "static", "assets", "media",
    # Payment / checkout / auth critical paths
    "checkout", "payments", "pay", "billing",
    "auth", "login", "sso", "secure",
    # Customer-facing
    "customer", "users", "portal",
    # Sensitive S3 patterns inherited
    "uploads", "invoices",
})


def _is_sensitive_routing_name(name: str) -> bool:
    """Return True if a DNS name or CloudFront alias suggests a sensitive service.

    Covers production, CDN, payment, auth, and customer-facing patterns.
    """
    n = name.lower()
    return any(pattern in n for pattern in _SENSITIVE_ROUTING_PATTERNS)


# ── M40: Route53 hosted zone classifier ──────────────────────────────────────


def _classify_route53_hosted_zone_change(change: object) -> tuple[str, str]:
    """Classify risk for aws_route53_hosted_zone record changes.

    Risk matrix:
    - Hosted zone deleted (removed event)    → critical
    - NS changed                             → critical
    - zone_type changed public→private       → high
    - private_zone changed False→True        → high (opposite: low)
    - resource_record_set_count decreased    → high
    - linked_vpc_count decreased             → medium
    - comment changed                        → low
    - tag_keys changed                       → low
    """
    pm: dict = _get(change, "provider_metadata") or {}
    change_type: str = (_get(change, "change_type") or "").lower()
    fp: str = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "previous_value")
    zone_name: str = pm.get("name") or pm.get("zone_name") or "unknown zone"

    # Deletion is always critical — zone removed means DNS stops resolving
    if change_type == "removed":
        return (
            "critical",
            f"Route53 hosted zone {zone_name!r} was deleted. "
            "DNS resolution for all records in this zone will fail. "
            "Verify this was intentional.",
        )

    if fp == "name_servers":
        return (
            "critical",
            f"Route53 hosted zone {zone_name!r} name servers changed. "
            "Unauthorised NS changes can redirect all DNS traffic for the domain. "
            "Verify the new name servers are correct.",
        )

    if fp == "zone_type":
        if pv == "public" and nv == "private":
            return (
                "high",
                f"Route53 hosted zone {zone_name!r} changed from public to private. "
                "The zone is no longer resolvable from the public internet.",
            )
        if pv == "private" and nv == "public":
            return (
                "high",
                f"Route53 hosted zone {zone_name!r} changed from private to public. "
                "Internal DNS records may now be visible to the public internet.",
            )
        return (
            "medium",
            f"Route53 hosted zone {zone_name!r} zone type changed.",
        )

    if fp == "private_zone":
        if pv is False and nv is True:
            return (
                "high",
                f"Route53 hosted zone {zone_name!r} is now private. "
                "Public DNS resolution for this zone has been disabled.",
            )
        return (
            "low",
            f"Route53 hosted zone {zone_name!r} private flag changed.",
        )

    if fp == "resource_record_set_count":
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv < pv:
            return (
                "high",
                f"Route53 hosted zone {zone_name!r} record count decreased "
                f"({pv} → {nv}). DNS records may have been removed.",
            )
        return (
            "low",
            f"Route53 hosted zone {zone_name!r} record count changed ({pv} → {nv}).",
        )

    if fp == "linked_vpc_count":
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv < pv:
            return (
                "medium",
                f"Route53 hosted zone {zone_name!r} linked VPC count decreased "
                f"({pv} → {nv}). Private DNS resolution may be affected.",
            )
        return (
            "low",
            f"Route53 hosted zone {zone_name!r} linked VPC count changed.",
        )

    if fp == "comment":
        return (
            "low",
            f"Route53 hosted zone {zone_name!r} comment changed.",
        )

    if fp == "tag_keys":
        return (
            "low",
            f"Route53 hosted zone {zone_name!r} tags changed.",
        )

    return (
        "low",
        f"Route53 hosted zone {zone_name!r} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ── M40: Route53 record classifier ───────────────────────────────────────────


def _classify_route53_record_change(change: object) -> tuple[str, str]:
    """Classify risk for aws_route53_record record changes.

    Risk matrix:
    - Record removed (apex A/ALIAS)              → critical
    - MX record removed                          → critical
    - NS record changed                          → critical
    - DMARC none policy                          → critical
    - value_hash changed (apex A/ALIAS sensitive)→ critical
    - value_hash changed (sensitive name)        → high
    - alias_target_dns_name changed (sensitive)  → critical / high
    - value_hash changed (any)                   → medium
    - ttl changed                                → low/medium
    - routing_policy changed                     → medium
    - failover changed                           → medium
    - evaluate_target_health changed             → medium
    - weight/region changed                      → low
    - health_check_id changed                    → medium
    - dmarc_policy changed to weaker             → high
    - dmarc_policy changed                       → medium
    """
    pm: dict = _get(change, "provider_metadata") or {}
    change_type: str = (_get(change, "change_type") or "").lower()
    fp: str = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "previous_value")
    record_name: str = pm.get("record_name") or pm.get("name") or "unknown"
    dns_type: str = pm.get("dns_record_type") or ""
    zone_name: str = pm.get("zone_name") or ""
    is_sensitive = _is_sensitive_routing_name(record_name) or _is_sensitive_routing_name(zone_name)

    # Apex/root record: name matches zone_name (or is @ or empty)
    is_apex = (
        record_name == zone_name or
        record_name == zone_name.rstrip(".") or
        record_name in ("@", "")
    )

    if change_type == "removed":
        if dns_type == "MX":
            return (
                "critical",
                f"MX record {record_name!r} was removed from zone {zone_name!r}. "
                "Email delivery to this domain will fail.",
            )
        if dns_type in ("A", "AAAA") and is_apex:
            return (
                "critical",
                f"Apex DNS record {record_name!r} ({dns_type}) was removed from "
                f"zone {zone_name!r}. The domain may become unreachable.",
            )
        if is_sensitive:
            return (
                "high",
                f"DNS record {record_name!r} ({dns_type}) was removed from "
                f"zone {zone_name!r}. This record serves a sensitive path.",
            )
        return (
            "medium",
            f"DNS record {record_name!r} ({dns_type}) was removed from zone {zone_name!r}.",
        )

    if fp == "value_hash":
        if dns_type == "NS":
            return (
                "critical",
                f"NS record values changed for {record_name!r} in zone {zone_name!r}. "
                "Nameserver changes can redirect all DNS traffic for the domain.",
            )
        if is_apex and dns_type in ("A", "AAAA"):
            return (
                "critical",
                f"Apex DNS record {record_name!r} ({dns_type}) value changed in "
                f"zone {zone_name!r}. The domain now points to a different destination.",
            )
        if is_sensitive:
            return (
                "high",
                f"DNS record {record_name!r} ({dns_type}) value changed in "
                f"zone {zone_name!r}. This record serves a sensitive path.",
            )
        return (
            "medium",
            f"DNS record {record_name!r} ({dns_type}) value changed in zone {zone_name!r}.",
        )

    if fp == "alias_target_dns_name":
        if is_apex or is_sensitive:
            return (
                "critical",
                f"Alias target for DNS record {record_name!r} ({dns_type}) changed "
                f"in zone {zone_name!r} ({pv!r} → {nv!r}). "
                "Traffic may now be routed to a different destination.",
            )
        return (
            "high",
            f"Alias target for DNS record {record_name!r} ({dns_type}) changed "
            f"in zone {zone_name!r} ({pv!r} → {nv!r}).",
        )

    if fp == "dmarc_policy":
        if nv == "none":
            return (
                "critical",
                f"DMARC policy for {zone_name!r} is set to 'none'. "
                "Phishing/spoofing emails will not be quarantined or rejected.",
            )
        # reject → quarantine: explicit downgrade (quarantine is weaker than reject)
        if pv == "reject" and nv == "quarantine":
            return (
                "high",
                f"DMARC policy for {zone_name!r} weakened from 'reject' to 'quarantine'. "
                "Email domain spoofing protection has been reduced.",
            )
        if pv in ("reject", "quarantine") and nv not in ("reject", "quarantine"):
            return (
                "high",
                f"DMARC policy for {zone_name!r} weakened from {pv!r} to {nv!r}. "
                "Email domain spoofing protection has been reduced.",
            )
        if pv == "none" and nv in ("quarantine", "reject"):
            return (
                "low",
                f"DMARC policy for {zone_name!r} strengthened from {pv!r} to {nv!r}.",
            )
        return (
            "medium",
            f"DMARC policy for {zone_name!r} changed from {pv!r} to {nv!r}.",
        )

    if fp == "ttl":
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)):
            if nv < 60 and pv >= 60:
                return (
                    "medium",
                    f"TTL for DNS record {record_name!r} ({dns_type}) decreased below "
                    f"60 seconds ({pv}s → {nv}s). Very short TTLs can indicate "
                    "preparation for a DNS change.",
                )
        return (
            "low",
            f"TTL for DNS record {record_name!r} ({dns_type}) changed ({pv} → {nv}).",
        )

    if fp == "routing_policy":
        return (
            "medium",
            f"Routing policy for DNS record {record_name!r} ({dns_type}) changed "
            f"from {pv!r} to {nv!r} in zone {zone_name!r}.",
        )

    if fp == "failover":
        return (
            "medium",
            f"Failover setting for DNS record {record_name!r} ({dns_type}) changed "
            f"in zone {zone_name!r}.",
        )

    if fp == "evaluate_target_health":
        return (
            "medium",
            f"EvaluateTargetHealth for DNS record {record_name!r} ({dns_type}) "
            f"changed in zone {zone_name!r}. Health-check routing may be affected.",
        )

    if fp == "health_check_id":
        if nv is None and pv is not None:
            return (
                "medium",
                f"Health check removed from DNS record {record_name!r} ({dns_type}) "
                f"in zone {zone_name!r}. Failover routing may no longer work.",
            )
        return (
            "low",
            f"Health check ID changed for DNS record {record_name!r} ({dns_type}).",
        )

    if fp in ("weight", "region", "geo_location_summary"):
        return (
            "low",
            f"Routing weight/region metadata changed for DNS record "
            f"{record_name!r} ({dns_type}) in zone {zone_name!r}.",
        )

    return (
        "low",
        f"DNS record {record_name!r} ({dns_type}) configuration changed "
        f"({fp or 'unknown field'}) in zone {zone_name!r}.",
    )


# ── M40: CloudFront distribution classifier ───────────────────────────────────


def _classify_cloudfront_distribution_change(change: object) -> tuple[str, str]:
    """Classify risk for aws_cloudfront_distribution record changes.

    Risk matrix:
    - Distribution removed                       → critical
    - enabled changed True→False                 → critical
    - viewer_protocol_policy = allow-all         → critical
    - origins_summary changed (sensitive alias)  → critical / high
    - web_acl_id removed                         → high
    - TLS minimum_protocol_version weakened      → high
    - aliases changed                            → high
    - default_cache_behavior_summary changed     → high
    - status changed to Disabled                 → high
    - logging_enabled changed True→False         → medium
    - price_class changed                        → low
    - ipv6_enabled changed                       → low
    - default_root_object changed                → low
    - tag_keys changed                           → low
    """
    pm: dict = _get(change, "provider_metadata") or {}
    change_type: str = (_get(change, "change_type") or "").lower()
    fp: str = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "previous_value")
    dist_name: str = pm.get("name") or pm.get("domain_name") or pm.get("distribution_id") or "unknown"
    aliases: list = pm.get("aliases") or []
    is_sensitive = (
        _is_sensitive_routing_name(dist_name) or
        any(_is_sensitive_routing_name(a) for a in aliases)
    )

    if change_type == "removed":
        return (
            "critical",
            f"CloudFront distribution {dist_name!r} was removed. "
            "CDN delivery for associated aliases will fail.",
        )

    if fp == "enabled":
        if pv is True and nv is False:
            if is_sensitive:
                return (
                    "critical",
                    f"CloudFront distribution {dist_name!r} was disabled. "
                    "This distribution serves a sensitive or production endpoint.",
                )
            return (
                "high",
                f"CloudFront distribution {dist_name!r} was disabled. "
                "CDN delivery for this distribution has stopped.",
            )
        return (
            "low",
            f"CloudFront distribution {dist_name!r} enabled state changed.",
        )

    if fp == "default_cache_behavior_summary":
        # Detect viewer_protocol_policy weakening
        new_vpp: str = ""
        if isinstance(nv, dict):
            new_vpp = nv.get("viewer_protocol_policy") or ""
        elif isinstance(nv, str):
            new_vpp = nv
        if new_vpp == "allow-all":
            return (
                "critical",
                f"CloudFront distribution {dist_name!r} now allows HTTP (allow-all). "
                "Visitors may be served over unencrypted connections. "
                "Set viewer protocol policy to redirect-to-https or https-only.",
            )
        return (
            "high",
            f"CloudFront distribution {dist_name!r} default cache behavior changed. "
            "Verify the viewer protocol policy and caching settings are correct.",
        )

    if fp == "viewer_certificate_summary":
        # Detect TLS minimum_protocol_version weakening
        _WEAK_TLS = {"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}
        new_mpv: str = ""
        old_mpv: str = ""
        if isinstance(nv, dict):
            new_mpv = nv.get("minimum_protocol_version") or ""
        if isinstance(pv, dict):
            old_mpv = pv.get("minimum_protocol_version") or ""
        if new_mpv in _WEAK_TLS and old_mpv not in _WEAK_TLS:
            return (
                "high",
                f"CloudFront distribution {dist_name!r} TLS minimum protocol version "
                f"weakened from {old_mpv!r} to {new_mpv!r}. "
                "Older, weaker TLS versions are now permitted.",
            )
        return (
            "medium",
            f"CloudFront distribution {dist_name!r} viewer certificate changed.",
        )

    if fp == "web_acl_id":
        if (nv is None or nv == "") and (pv is not None and pv != ""):
            return (
                "high",
                f"CloudFront distribution {dist_name!r} WAF web ACL was removed. "
                "The distribution is no longer protected by AWS WAF.",
            )
        return (
            "medium",
            f"CloudFront distribution {dist_name!r} WAF web ACL changed.",
        )

    if fp == "origins_summary":
        if is_sensitive:
            return (
                "critical",
                f"CloudFront distribution {dist_name!r} origin configuration changed. "
                "This distribution serves a sensitive or production endpoint. "
                "Verify the new origin is correct.",
            )
        return (
            "high",
            f"CloudFront distribution {dist_name!r} origin configuration changed. "
            "Verify the new origin is correct.",
        )

    if fp == "aliases":
        return (
            "high",
            f"CloudFront distribution {dist_name!r} domain aliases changed "
            f"({pv!r} → {nv!r}). Verify CNAME records are still correct.",
        )

    if fp == "alias_count":
        if isinstance(nv, (int, float)) and isinstance(pv, (int, float)) and nv < pv:
            return (
                "high",
                f"CloudFront distribution {dist_name!r} alias count decreased "
                f"({pv} → {nv}). A domain alias may have been removed.",
            )
        return (
            "low",
            f"CloudFront distribution {dist_name!r} alias count changed.",
        )

    if fp == "status":
        if isinstance(nv, str) and "disabled" in nv.lower():
            return (
                "high",
                f"CloudFront distribution {dist_name!r} status changed to {nv!r}.",
            )
        return (
            "low",
            f"CloudFront distribution {dist_name!r} status changed to {nv!r}.",
        )

    if fp == "logging_enabled":
        if pv is True and nv is False:
            return (
                "medium",
                f"CloudFront distribution {dist_name!r} access logging was disabled. "
                "CDN request logs will no longer be collected.",
            )
        return (
            "low",
            f"CloudFront distribution {dist_name!r} logging setting changed.",
        )

    if fp == "ordered_cache_behaviors_summary":
        return (
            "medium",
            f"CloudFront distribution {dist_name!r} ordered cache behavior changed. "
            "Verify path-based routing is still correct.",
        )

    if fp in ("price_class", "http_version", "ipv6_enabled", "default_root_object"):
        return (
            "low",
            f"CloudFront distribution {dist_name!r} {fp.replace('_', ' ')} changed.",
        )

    if fp == "tag_keys":
        return (
            "low",
            f"CloudFront distribution {dist_name!r} tags changed.",
        )

    return (
        "low",
        f"CloudFront distribution {dist_name!r} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ── M41: Secrets Manager secret changes ──────────────────────────────────────

# Sensitivity categories that warrant elevated risk.
_SENSITIVE_SECRET_CATEGORIES: frozenset[str] = frozenset({
    "secret", "credential", "api_key", "auth", "payment", "database", "production",
})


def _secret_name_is_sensitive(name: str) -> bool:
    """Return True if the secret name suggests production/sensitive content."""
    # Import inline to avoid circular imports with the connector.
    from app.connectors.aws import _classify_secret_name_sensitivity
    return _classify_secret_name_sensitivity(name) in _SENSITIVE_SECRET_CATEGORIES


def _classify_secretsmanager_secret_change(change: object) -> tuple[str, str]:
    """Classify a single aws_secretsmanager_secret change."""
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")

    pm: dict = _get(change, "provider_metadata") or {}
    secret_name: str = pm.get("record_name") or ""
    is_sensitive = _secret_name_is_sensitive(secret_name)

    # ── Added: new secret appeared ────────────────────────────────────────────
    if ct == "added":
        record: dict = nv if isinstance(nv, dict) else {}
        sensitive_cat = record.get("sensitive_name_category", "none")
        rotation_enabled = record.get("rotation_enabled", False)
        has_policy = record.get("has_resource_policy", False)
        policy_summary = record.get("policy_summary") or {}
        wildcard_principal = policy_summary.get("has_wildcard_principal", False)
        if wildcard_principal:
            return (
                "critical",
                f"New Secrets Manager secret {secret_name!r} has a resource policy "
                "with a wildcard principal (*). Any AWS principal may be able to read "
                "this secret. Review the resource policy immediately.",
            )
        if sensitive_cat in _SENSITIVE_SECRET_CATEGORIES:
            if not rotation_enabled:
                return (
                    "high",
                    f"New Secrets Manager secret {secret_name!r} (sensitive category: "
                    f"{sensitive_cat!r}) was added without rotation enabled. "
                    "Consider enabling automatic rotation.",
                )
            return (
                "medium",
                f"New Secrets Manager secret {secret_name!r} (sensitive category: "
                f"{sensitive_cat!r}) was added with rotation enabled.",
            )
        return (
            "low",
            f"New Secrets Manager secret {secret_name!r} was added.",
        )

    # ── Removed: secret disappeared ───────────────────────────────────────────
    if ct == "removed":
        record = pv if isinstance(pv, dict) else {}
        sensitive_cat = record.get("sensitive_name_category", "none")
        if sensitive_cat in _SENSITIVE_SECRET_CATEGORIES:
            return (
                "critical",
                f"Secrets Manager secret {secret_name!r} (sensitive category: "
                f"{sensitive_cat!r}) was removed. Verify this secret is no longer in "
                "use before accepting this change.",
            )
        return (
            "high",
            f"Secrets Manager secret {secret_name!r} was removed. "
            "Verify no application still depends on this secret.",
        )

    # ── Modified: individual field changed ────────────────────────────────────
    if fp == "rotation_enabled":
        if pv is True and nv is False:
            if is_sensitive:
                return (
                    "critical",
                    f"Secrets Manager secret {secret_name!r} had automatic rotation "
                    "disabled. This is a sensitive secret — disabling rotation may "
                    "leave stale credentials active indefinitely.",
                )
            return (
                "high",
                f"Secrets Manager secret {secret_name!r} had automatic rotation "
                "disabled. Static secrets are at higher risk of credential compromise.",
            )
        if pv is False and nv is True:
            return (
                "low",
                f"Secrets Manager secret {secret_name!r} had automatic rotation "
                "enabled. This is a security improvement.",
            )
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} rotation_enabled changed.",
        )

    if fp == "kms_key_id_present":
        if pv is True and nv is False:
            if is_sensitive:
                return (
                    "critical",
                    f"Secrets Manager secret {secret_name!r} lost its KMS customer-managed "
                    "key. This is a sensitive secret — removal of a CMK may indicate "
                    "a downgrade to AWS-managed encryption.",
                )
            return (
                "high",
                f"Secrets Manager secret {secret_name!r} lost its KMS customer-managed key. "
                "The secret may now use only AWS-managed encryption.",
            )
        if pv is False and nv is True:
            return (
                "low",
                f"Secrets Manager secret {secret_name!r} gained a KMS customer-managed key. "
                "This is a security improvement.",
            )
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} KMS key presence changed.",
        )

    if fp == "kms_key_id_hash":
        return (
            "medium",
            f"Secrets Manager secret {secret_name!r} KMS encryption key changed. "
            "Verify the new key is correct and accessible.",
        )

    if fp == "deleted_date":
        if pv is None and nv is not None:
            if is_sensitive:
                return (
                    "critical",
                    f"Secrets Manager secret {secret_name!r} was scheduled for deletion "
                    f"(deletion date: {nv}). This is a sensitive secret — confirm it is "
                    "not still used by any application.",
                )
            return (
                "high",
                f"Secrets Manager secret {secret_name!r} was scheduled for deletion "
                f"(deletion date: {nv}). Verify no application still depends on it.",
            )
        if pv is not None and nv is None:
            return (
                "low",
                f"Secrets Manager secret {secret_name!r} deletion was cancelled "
                "and the secret was restored.",
            )
        return (
            "medium",
            f"Secrets Manager secret {secret_name!r} deletion date changed.",
        )

    if fp == "policy_summary":
        prev_wildcard = (pv or {}).get("has_wildcard_principal", False) if isinstance(pv, dict) else False
        new_wildcard = (nv or {}).get("has_wildcard_principal", False) if isinstance(nv, dict) else False
        if new_wildcard and not prev_wildcard:
            return (
                "critical",
                f"Secrets Manager secret {secret_name!r} resource policy was changed to "
                "include a wildcard principal (*). Any AWS principal may be able to read "
                "this secret. Review the policy immediately.",
            )
        if prev_wildcard and not new_wildcard:
            return (
                "low",
                f"Secrets Manager secret {secret_name!r} resource policy wildcard principal "
                "was removed. This is a security improvement.",
            )
        return (
            "medium",
            f"Secrets Manager secret {secret_name!r} resource policy changed. "
            "Verify the new policy grants only intended access.",
        )

    if fp == "has_resource_policy":
        if pv is True and nv is False:
            return (
                "medium",
                f"Secrets Manager secret {secret_name!r} resource policy was removed. "
                "Verify IAM identity-based policies still restrict access appropriately.",
            )
        if pv is False and nv is True:
            return (
                "low",
                f"Secrets Manager secret {secret_name!r} gained a resource policy.",
            )
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} resource policy presence changed.",
        )

    if fp == "rotation_rules_summary":
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} rotation schedule changed.",
        )

    if fp in ("rotation_lambda_arn_present",):
        if pv is True and nv is False:
            return (
                "medium",
                f"Secrets Manager secret {secret_name!r} rotation Lambda ARN was removed. "
                "Automatic rotation may no longer function.",
            )
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} rotation Lambda ARN changed.",
        )

    if fp == "replica_region_count":
        if isinstance(pv, int) and isinstance(nv, int) and nv < pv:
            return (
                "medium",
                f"Secrets Manager secret {secret_name!r} replica region count decreased "
                f"from {pv} to {nv}. Verify cross-region availability is not impacted.",
            )
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} replica region count changed.",
        )

    if fp == "tag_keys":
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} tags changed.",
        )

    if fp in (
        "description_present", "owning_service", "primary_region",
        "replica_regions", "last_changed_date", "last_accessed_date",
        "created_date", "version_count", "active_version_count",
        "deprecated_version_count", "sensitive_name_category",
    ):
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} {fp.replace('_', ' ')} changed.",
        )

    if fp == "config_fetch_warnings":
        return (
            "low",
            f"Secrets Manager secret {secret_name!r} fetch warnings changed.",
        )

    return (
        "low",
        f"Secrets Manager secret {secret_name!r} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ── M41: SSM Parameter changes ───────────────────────────────────────────────

_SENSITIVE_SSM_CATEGORIES: frozenset[str] = frozenset({
    "secret", "credential", "api_key", "auth", "payment", "database", "production",
})


def _ssm_name_is_sensitive(name: str) -> bool:
    """Return True if the SSM parameter name suggests sensitive content."""
    from app.connectors.aws import _classify_ssm_name_sensitivity
    return _classify_ssm_name_sensitivity(name) in _SENSITIVE_SSM_CATEGORIES


def _classify_ssm_parameter_change(change: object) -> tuple[str, str]:
    """Classify a single aws_ssm_parameter change."""
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    pv = _get(change, "prev_value")
    nv = _get(change, "new_value")

    pm: dict = _get(change, "provider_metadata") or {}
    param_name: str = pm.get("record_name") or ""
    is_sensitive = _ssm_name_is_sensitive(param_name)

    # ── Added: new parameter appeared ────────────────────────────────────────
    if ct == "added":
        record: dict = nv if isinstance(nv, dict) else {}
        sensitive_cat = record.get("sensitive_name_category", "none")
        param_type = record.get("parameter_type", "String")
        key_id_present = record.get("key_id_present", False)

        if sensitive_cat in _SENSITIVE_SSM_CATEGORIES and param_type != "SecureString":
            return (
                "critical",
                f"New SSM parameter {param_name!r} (sensitive category: "
                f"{sensitive_cat!r}) was added as type {param_type!r} without "
                "SecureString encryption. Sensitive parameters should be SecureString.",
            )
        if sensitive_cat in _SENSITIVE_SSM_CATEGORIES:
            return (
                "medium",
                f"New SSM parameter {param_name!r} (sensitive category: "
                f"{sensitive_cat!r}) was added as SecureString.",
            )
        return (
            "low",
            f"New SSM parameter {param_name!r} was added (type: {param_type!r}).",
        )

    # ── Removed: parameter disappeared ───────────────────────────────────────
    if ct == "removed":
        record = pv if isinstance(pv, dict) else {}
        sensitive_cat = record.get("sensitive_name_category", "none")
        if sensitive_cat in _SENSITIVE_SSM_CATEGORIES:
            return (
                "critical",
                f"SSM parameter {param_name!r} (sensitive category: "
                f"{sensitive_cat!r}) was removed. Verify no application still "
                "depends on this parameter.",
            )
        return (
            "medium",
            f"SSM parameter {param_name!r} was removed. "
            "Verify no application still depends on this parameter.",
        )

    # ── Modified: individual field changed ────────────────────────────────────
    if fp == "parameter_type":
        prev_str = str(pv) if pv is not None else ""
        new_str = str(nv) if nv is not None else ""
        if prev_str == "SecureString" and new_str != "SecureString":
            if is_sensitive:
                return (
                    "critical",
                    f"SSM parameter {param_name!r} type changed from SecureString to "
                    f"{new_str!r}. This is a sensitive parameter — the value is now "
                    "stored unencrypted. Review immediately.",
                )
            return (
                "high",
                f"SSM parameter {param_name!r} type changed from SecureString to "
                f"{new_str!r}. The value is now stored unencrypted.",
            )
        if prev_str != "SecureString" and new_str == "SecureString":
            return (
                "low",
                f"SSM parameter {param_name!r} type changed from {prev_str!r} to "
                "SecureString. This is a security improvement.",
            )
        return (
            "medium",
            f"SSM parameter {param_name!r} type changed from {prev_str!r} to {new_str!r}. "
            "Verify all consumers are updated.",
        )

    if fp == "key_id_present":
        if pv is True and nv is False:
            if is_sensitive:
                return (
                    "critical",
                    f"SSM parameter {param_name!r} lost its KMS customer-managed key. "
                    "This is a sensitive parameter — removal of a CMK may indicate "
                    "a downgrade to AWS-managed encryption.",
                )
            return (
                "high",
                f"SSM parameter {param_name!r} lost its KMS customer-managed key. "
                "The parameter may now use only AWS-managed encryption.",
            )
        if pv is False and nv is True:
            return (
                "low",
                f"SSM parameter {param_name!r} gained a KMS customer-managed key. "
                "This is a security improvement.",
            )
        return (
            "low",
            f"SSM parameter {param_name!r} KMS key presence changed.",
        )

    if fp == "key_id_hash":
        return (
            "medium",
            f"SSM parameter {param_name!r} KMS encryption key changed. "
            "Verify the new key is correct and accessible.",
        )

    if fp == "tier":
        return (
            "low",
            f"SSM parameter {param_name!r} tier changed from {pv!r} to {nv!r}.",
        )

    if fp == "version":
        return (
            "low",
            f"SSM parameter {param_name!r} version changed from {pv} to {nv}. "
            "Verify consumer applications will use the updated value.",
        )

    if fp == "policy_count":
        if isinstance(pv, int) and isinstance(nv, int):
            if nv > pv:
                return (
                    "low",
                    f"SSM parameter {param_name!r} gained {nv - pv} parameter "
                    "policy(ies). Parameter lifecycle policies are now active.",
                )
            if nv < pv:
                return (
                    "medium",
                    f"SSM parameter {param_name!r} lost {pv - nv} parameter "
                    "policy(ies). Verify expiration/notification policies are "
                    "still in place if required.",
                )
        return (
            "low",
            f"SSM parameter {param_name!r} policy count changed.",
        )

    if fp == "policies_summary":
        return (
            "low",
            f"SSM parameter {param_name!r} parameter policies changed. "
            "Verify expiration and notification policies are correct.",
        )

    if fp == "allowed_pattern_present":
        if pv is True and nv is False:
            return (
                "medium",
                f"SSM parameter {param_name!r} allowed value pattern was removed. "
                "Input validation is no longer enforced for this parameter.",
            )
        return (
            "low",
            f"SSM parameter {param_name!r} allowed value pattern changed.",
        )

    if fp == "tag_keys":
        return (
            "low",
            f"SSM parameter {param_name!r} tags changed.",
        )

    if fp in (
        "data_type", "last_modified_date", "last_modified_user_summary",
        "path_depth", "path_prefix", "sensitive_name_category",
    ):
        return (
            "low",
            f"SSM parameter {param_name!r} {fp.replace('_', ' ')} changed.",
        )

    if fp == "config_fetch_warnings":
        return (
            "low",
            f"SSM parameter {param_name!r} fetch warnings changed.",
        )

    return (
        "low",
        f"SSM parameter {param_name!r} configuration changed "
        f"({fp or 'unknown field'}).",
    )


# ── Entry point ──────────────────────────────────────────────────────────────


# ── M42 RDS helpers ──────────────────────────────────────────────────────────

_SENSITIVE_RDS_CATEGORIES: frozenset[str] = frozenset({
    "production", "credential", "api_key", "auth", "payment",
    "database", "internal", "config", "secure",
})


def _rds_is_sensitive(name: str) -> bool:
    """Return True if the RDS identifier name suggests a sensitive/production resource."""
    from app.connectors.aws import _classify_rds_name_sensitivity
    return _classify_rds_name_sensitivity(name) in _SENSITIVE_RDS_CATEGORIES


# ── aws_rds_db_instance ───────────────────────────────────────────────────────

def _classify_rds_db_instance_change(change: object) -> tuple[str, str]:  # noqa: C901
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    name = str(_get(change, "name") or "")
    sensitive = _rds_is_sensitive(name)

    if ct == "added":
        return "low", f"RDS DB instance '{name}' was added to monitoring."
    if ct == "removed":
        level = "high" if sensitive else "medium"
        return level, f"RDS DB instance '{name}' is no longer visible to ConfigTrace."

    # ── Critical ──────────────────────────────────────────────────────────────
    if fp == "publicly_accessible" and new_val is True:
        level = "critical" if sensitive else "high"
        return (
            level,
            f"RDS DB instance '{name}' is now publicly accessible over the internet. "
            "Verify this is intentional and that network-level controls (security groups, NACLs) "
            "restrict access appropriately.",
        )

    if fp == "storage_encrypted" and new_val is False:
        return (
            "critical",
            f"Encryption at rest was disabled for RDS DB instance '{name}'. "
            "Unencrypted database storage exposes data if the underlying storage is compromised.",
        )

    # ── High ──────────────────────────────────────────────────────────────────
    if fp == "publicly_accessible" and new_val is False:
        return (
            "low",
            f"RDS DB instance '{name}' is no longer publicly accessible. Exposure reduced.",
        )

    if fp == "deletion_protection" and new_val is False:
        level = "critical" if sensitive else "medium"
        return (
            level,
            f"Deletion protection was disabled for RDS DB instance '{name}'. "
            "The instance can now be deleted without an additional safeguard.",
        )

    if fp == "deletion_protection" and new_val is True:
        return "low", f"Deletion protection was enabled for RDS DB instance '{name}'."

    if fp == "backup_retention_period":
        try:
            old_days = int(prev_val) if prev_val is not None else None
            new_days = int(new_val) if new_val is not None else None
        except (TypeError, ValueError):
            old_days = new_days = None
        if new_days == 0:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Automated backups were disabled for RDS DB instance '{name}' "
                "(retention set to 0 days). Point-in-time recovery is no longer available.",
            )
        if old_days is not None and new_days is not None and new_days < old_days:
            return (
                "medium",
                f"Backup retention period for RDS DB instance '{name}' was reduced "
                f"from {old_days} to {new_days} days. Recovery window shortened.",
            )
        if old_days is not None and new_days is not None and new_days > old_days:
            return (
                "low",
                f"Backup retention period for RDS DB instance '{name}' increased "
                f"from {old_days} to {new_days} days.",
            )

    if fp == "iam_database_authentication_enabled" and new_val is False:
        level = "high" if sensitive else "medium"
        return (
            level,
            f"IAM database authentication was disabled for RDS DB instance '{name}'. "
            "Password-based authentication is now the only available method.",
        )

    if fp == "iam_database_authentication_enabled" and new_val is True:
        return (
            "low",
            f"IAM database authentication was enabled for RDS DB instance '{name}'.",
        )

    if fp == "multi_az" and new_val is False:
        level = "high" if sensitive else "medium"
        return (
            level,
            f"Multi-AZ failover was disabled for RDS DB instance '{name}'. "
            "The instance is now a single-AZ deployment; availability is reduced.",
        )

    if fp == "multi_az" and new_val is True:
        return "low", f"Multi-AZ failover was enabled for RDS DB instance '{name}'."

    if fp == "kms_key_id_present" and new_val is False:
        return (
            "high",
            f"The KMS encryption key association was removed from RDS DB instance '{name}'. "
            "Verify storage encryption is still active.",
        )

    if fp == "storage_encrypted" and new_val is True:
        return "low", f"Encryption at rest was enabled for RDS DB instance '{name}'."

    # ── Medium ────────────────────────────────────────────────────────────────
    if fp == "vpc_security_group_ids":
        return (
            "medium",
            f"VPC security groups changed for RDS DB instance '{name}'. "
            "Verify the new security group configuration restricts access appropriately.",
        )

    if fp == "auto_minor_version_upgrade" and new_val is False:
        return (
            "medium",
            f"Auto minor version upgrade was disabled for RDS DB instance '{name}'. "
            "Security patches will not be applied automatically.",
        )

    if fp == "auto_minor_version_upgrade" and new_val is True:
        return (
            "low",
            f"Auto minor version upgrade was enabled for RDS DB instance '{name}'.",
        )

    if fp == "engine_version":
        return (
            "medium",
            f"Engine version changed for RDS DB instance '{name}' "
            f"(was '{prev_val}', now '{new_val}'). Verify compatibility.",
        )

    if fp == "engine_major_version":
        level = "high" if sensitive else "medium"
        return (
            level,
            f"Major engine version changed for RDS DB instance '{name}' "
            f"(was '{prev_val}', now '{new_val}'). Major version upgrades may introduce "
            "breaking changes.",
        )

    if fp == "db_instance_class":
        return (
            "low",
            f"Instance class changed for RDS DB instance '{name}' "
            f"(was '{prev_val}', now '{new_val}').",
        )

    if fp == "db_instance_status":
        if str(new_val or "").lower() in ("stopped", "deleting", "failed", "inaccessible-encryption-credentials"):
            return (
                "high",
                f"RDS DB instance '{name}' entered status '{new_val}'. Investigate immediately.",
            )
        return (
            "low",
            f"RDS DB instance '{name}' status changed to '{new_val}'.",
        )

    if fp == "pending_modified_values_summary":
        return (
            "low",
            f"RDS DB instance '{name}' has pending configuration changes queued "
            "for the next maintenance window.",
        )

    if fp == "preferred_backup_window":
        return "low", f"Backup window changed for RDS DB instance '{name}'."

    if fp == "preferred_maintenance_window":
        return "low", f"Maintenance window changed for RDS DB instance '{name}'."

    if fp in ("tag_keys", "copy_tags_to_snapshot"):
        return "low", f"Tag configuration changed for RDS DB instance '{name}'."

    if fp in ("parameter_group_names", "option_group_names"):
        return (
            "medium",
            f"Parameter/option group configuration changed for RDS DB instance '{name}'. "
            "Verify the new group settings are correct.",
        )

    if fp == "monitoring_interval":
        if new_val == 0:
            return (
                "medium",
                f"Enhanced monitoring was disabled for RDS DB instance '{name}'.",
            )
        return "low", f"Enhanced monitoring interval changed for RDS DB instance '{name}'."

    if fp == "performance_insights_enabled" and new_val is False:
        return "medium", f"Performance Insights was disabled for RDS DB instance '{name}'."
    if fp == "performance_insights_enabled" and new_val is True:
        return "low", f"Performance Insights was enabled for RDS DB instance '{name}'."

    if fp == "db_cluster_identifier":
        return (
            "medium",
            f"RDS DB instance '{name}' cluster association changed. "
            "Verify the instance belongs to the expected cluster.",
        )

    if fp == "read_replica_source":
        return "medium", f"Read replica source changed for RDS DB instance '{name}'."

    if fp == "read_replica_count":
        return "low", f"Number of read replicas changed for RDS DB instance '{name}'."

    return (
        "low",
        f"RDS DB instance '{name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_rds_db_cluster ────────────────────────────────────────────────────────

def _classify_rds_db_cluster_change(change: object) -> tuple[str, str]:  # noqa: C901
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    name = str(_get(change, "name") or "")
    sensitive = _rds_is_sensitive(name)

    if ct == "added":
        return "low", f"RDS DB cluster '{name}' was added to monitoring."
    if ct == "removed":
        level = "high" if sensitive else "medium"
        return level, f"RDS DB cluster '{name}' is no longer visible to ConfigTrace."

    # ── Critical ──────────────────────────────────────────────────────────────
    if fp == "publicly_accessible" and new_val is True:
        level = "critical" if sensitive else "high"
        return (
            level,
            f"RDS DB cluster '{name}' is now publicly accessible. "
            "Verify this is intentional and network controls restrict access.",
        )

    if fp == "storage_encrypted" and new_val is False:
        return (
            "critical",
            f"Encryption at rest was disabled for RDS DB cluster '{name}'.",
        )

    # ── High ──────────────────────────────────────────────────────────────────
    if fp == "publicly_accessible" and new_val is False:
        return "low", f"RDS DB cluster '{name}' is no longer publicly accessible."

    if fp == "deletion_protection" and new_val is False:
        level = "critical" if sensitive else "medium"
        return (
            level,
            f"Deletion protection was disabled for RDS DB cluster '{name}'.",
        )

    if fp == "deletion_protection" and new_val is True:
        return "low", f"Deletion protection was enabled for RDS DB cluster '{name}'."

    if fp == "backup_retention_period":
        try:
            old_days = int(prev_val) if prev_val is not None else None
            new_days = int(new_val) if new_val is not None else None
        except (TypeError, ValueError):
            old_days = new_days = None
        if new_days == 0:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Automated backups were disabled for RDS DB cluster '{name}' "
                "(retention set to 0 days).",
            )
        if old_days is not None and new_days is not None and new_days < old_days:
            return (
                "medium",
                f"Backup retention reduced for RDS DB cluster '{name}' "
                f"from {old_days} to {new_days} days.",
            )
        if old_days is not None and new_days is not None and new_days > old_days:
            return (
                "low",
                f"Backup retention increased for RDS DB cluster '{name}' "
                f"from {old_days} to {new_days} days.",
            )

    if fp == "iam_database_authentication_enabled" and new_val is False:
        level = "high" if sensitive else "medium"
        return (
            level,
            f"IAM database authentication was disabled for RDS DB cluster '{name}'.",
        )

    if fp == "iam_database_authentication_enabled" and new_val is True:
        return "low", f"IAM database authentication was enabled for RDS DB cluster '{name}'."

    if fp == "multi_az" and new_val is False:
        level = "high" if sensitive else "medium"
        return (
            level,
            f"Multi-AZ was disabled for RDS DB cluster '{name}'. Availability reduced.",
        )

    if fp == "multi_az" and new_val is True:
        return "low", f"Multi-AZ was enabled for RDS DB cluster '{name}'."

    if fp == "storage_encrypted" and new_val is True:
        return "low", f"Encryption at rest was enabled for RDS DB cluster '{name}'."

    if fp == "kms_key_id_present" and new_val is False:
        return (
            "high",
            f"KMS encryption key association removed from RDS DB cluster '{name}'.",
        )

    # ── Medium ────────────────────────────────────────────────────────────────
    if fp == "vpc_security_group_ids":
        return (
            "medium",
            f"VPC security groups changed for RDS DB cluster '{name}'. "
            "Verify the new configuration restricts access appropriately.",
        )

    if fp == "engine_version":
        return (
            "medium",
            f"Engine version changed for RDS DB cluster '{name}' "
            f"(was '{prev_val}', now '{new_val}').",
        )

    if fp == "engine_major_version":
        level = "high" if sensitive else "medium"
        return (
            level,
            f"Major engine version changed for RDS DB cluster '{name}' "
            f"(was '{prev_val}', now '{new_val}'). Verify compatibility.",
        )

    if fp == "status":
        if str(new_val or "").lower() in ("stopped", "deleting", "failed", "inaccessible-encryption-credentials"):
            return (
                "high",
                f"RDS DB cluster '{name}' entered status '{new_val}'. Investigate.",
            )
        return "low", f"RDS DB cluster '{name}' status changed to '{new_val}'."

    if fp == "db_cluster_members_count":
        return (
            "medium",
            f"Instance count changed for RDS DB cluster '{name}' "
            f"(was {prev_val}, now {new_val}). Verify cluster scaling is expected.",
        )

    if fp == "db_cluster_parameter_group":
        return (
            "medium",
            f"Cluster parameter group changed for RDS DB cluster '{name}'. "
            "Verify the new group settings are correct.",
        )

    if fp in ("preferred_backup_window", "preferred_maintenance_window"):
        return "low", f"Maintenance/backup window changed for RDS DB cluster '{name}'."

    if fp in ("tag_keys", "copy_tags_to_snapshot"):
        return "low", f"Tag configuration changed for RDS DB cluster '{name}'."

    if fp == "performance_insights_enabled" and new_val is False:
        return "medium", f"Performance Insights was disabled for RDS DB cluster '{name}'."
    if fp == "performance_insights_enabled" and new_val is True:
        return "low", f"Performance Insights was enabled for RDS DB cluster '{name}'."

    return (
        "low",
        f"RDS DB cluster '{name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_rds_db_subnet_group ───────────────────────────────────────────────────

def _classify_rds_db_subnet_group_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    name = str(_get(change, "name") or "")

    if ct == "added":
        return "low", f"RDS DB subnet group '{name}' was added to monitoring."
    if ct == "removed":
        return "low", f"RDS DB subnet group '{name}' is no longer visible."

    if fp == "vpc_id":
        return (
            "high",
            f"The VPC association for RDS subnet group '{name}' changed "
            f"(was '{prev_val}', now '{new_val}'). "
            "Databases using this subnet group may have changed network placement.",
        )

    if fp == "subnet_ids":
        return (
            "medium",
            f"Subnet membership changed for RDS subnet group '{name}'. "
            "Verify database placement and AZ coverage are correct.",
        )

    if fp == "subnet_count":
        return (
            "medium",
            f"Subnet count changed for RDS subnet group '{name}' "
            f"(was {prev_val}, now {new_val}).",
        )

    if fp == "subnet_availability_zones":
        return (
            "medium",
            f"Availability zone coverage changed for RDS subnet group '{name}'.",
        )

    if fp == "status":
        if str(new_val or "").lower() == "incomplete":
            return (
                "high",
                f"RDS subnet group '{name}' status changed to '{new_val}'. "
                "The subnet group may not have coverage in all required AZs.",
            )
        return "low", f"RDS subnet group '{name}' status changed to '{new_val}'."

    if fp == "tag_keys":
        return "low", f"Tag keys changed for RDS subnet group '{name}'."

    return "low", f"RDS DB subnet group '{name}' configuration changed (field: {fp or 'unknown'})."


# ── aws_rds_db_snapshot ───────────────────────────────────────────────────────

def _classify_rds_db_snapshot_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    name = str(_get(change, "name") or "")
    db_id = str(_get(change, "db_instance_identifier") or name)
    sensitive = _rds_is_sensitive(db_id)

    if ct == "added":
        return "low", f"RDS DB snapshot '{name}' was detected."
    if ct == "removed":
        level = "high" if sensitive else "medium"
        return (
            level,
            f"RDS DB snapshot '{name}' was deleted. "
            "Verify this was intentional and a backup exists elsewhere.",
        )

    if fp == "publicly_accessible" and new_val is True:
        level = "critical" if sensitive else "high"
        return (
            level,
            f"RDS DB snapshot '{name}' is now publicly accessible. "
            "Public snapshots can be copied and restored by any AWS account. "
            "Restrict access immediately if this is not intentional.",
        )

    if fp == "publicly_accessible" and new_val is False:
        return "low", f"RDS DB snapshot '{name}' is no longer publicly accessible."

    if fp == "storage_encrypted" and new_val is False:
        level = "high" if sensitive else "medium"
        return (
            level,
            f"RDS DB snapshot '{name}' is unencrypted. "
            "Unencrypted snapshots expose data if shared or copied.",
        )

    if fp == "storage_encrypted" and new_val is True:
        return "low", f"RDS DB snapshot '{name}' is now encrypted."

    if fp == "kms_key_id_present" and new_val is False:
        return (
            "high",
            f"KMS encryption key association removed from RDS snapshot '{name}'.",
        )

    if fp == "snapshot_type":
        return (
            "medium",
            f"Snapshot type changed for '{name}' (was '{prev_val}', now '{new_val}').",
        )

    if fp == "status":
        if str(new_val or "").lower() in ("failed", "deleting"):
            return "high", f"RDS snapshot '{name}' entered status '{new_val}'."
        return "low", f"RDS snapshot '{name}' status changed to '{new_val}'."

    if fp == "tag_keys":
        return "low", f"Tag keys changed for RDS snapshot '{name}'."

    return "low", f"RDS DB snapshot '{name}' configuration changed (field: {fp or 'unknown'})."


# ── aws_rds_db_cluster_snapshot ───────────────────────────────────────────────

def _classify_rds_db_cluster_snapshot_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    name = str(_get(change, "name") or "")
    cluster_id = str(_get(change, "db_cluster_identifier") or name)
    sensitive = _rds_is_sensitive(cluster_id)

    if ct == "added":
        return "low", f"RDS DB cluster snapshot '{name}' was detected."
    if ct == "removed":
        level = "high" if sensitive else "medium"
        return (
            level,
            f"RDS DB cluster snapshot '{name}' was deleted. "
            "Verify this was intentional and a backup exists elsewhere.",
        )

    if fp == "publicly_accessible" and new_val is True:
        level = "critical" if sensitive else "high"
        return (
            level,
            f"RDS DB cluster snapshot '{name}' is now publicly accessible. "
            "Public cluster snapshots can be copied by any AWS account. "
            "Restrict access immediately if unintentional.",
        )

    if fp == "publicly_accessible" and new_val is False:
        return "low", f"RDS DB cluster snapshot '{name}' is no longer publicly accessible."

    if fp == "storage_encrypted" and new_val is False:
        level = "high" if sensitive else "medium"
        return (
            level,
            f"RDS DB cluster snapshot '{name}' is unencrypted.",
        )

    if fp == "storage_encrypted" and new_val is True:
        return "low", f"RDS DB cluster snapshot '{name}' is now encrypted."

    if fp == "kms_key_id_present" and new_val is False:
        return (
            "high",
            f"KMS encryption key association removed from RDS cluster snapshot '{name}'.",
        )

    if fp == "iam_database_authentication_enabled" and new_val is False:
        return (
            "medium",
            f"IAM authentication was disabled in RDS cluster snapshot '{name}'.",
        )

    if fp == "snapshot_type":
        return (
            "medium",
            f"Snapshot type changed for cluster snapshot '{name}' "
            f"(was '{prev_val}', now '{new_val}').",
        )

    if fp == "status":
        if str(new_val or "").lower() in ("failed", "deleting"):
            return "high", f"RDS cluster snapshot '{name}' entered status '{new_val}'."
        return "low", f"RDS cluster snapshot '{name}' status changed to '{new_val}'."

    if fp == "tag_keys":
        return "low", f"Tag keys changed for RDS cluster snapshot '{name}'."

    return (
        "low",
        f"RDS DB cluster snapshot '{name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── M43 Lambda + API Gateway helpers ──────────────────────────────────────────

_SENSITIVE_LAMBDA_CATEGORIES: frozenset[str] = frozenset({
    "production", "credential", "api_key", "auth", "payment",
    "database", "internal", "config", "secure", "admin", "customer",
})


def _lambda_is_sensitive(name: str) -> bool:
    """Return True if the Lambda/API name suggests a sensitive/production resource."""
    from app.connectors.aws import _classify_lambda_name_sensitivity
    return _classify_lambda_name_sensitivity(name) in _SENSITIVE_LAMBDA_CATEGORIES


# ── aws_lambda_function ────────────────────────────────────────────────────────

def _classify_lambda_function_change(change: object) -> tuple[str, str]:  # noqa: C901
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    fn_name: str = pm.get("record_name") or ""
    sensitive = _lambda_is_sensitive(fn_name)

    if ct == "added":
        return "low", f"Lambda function '{fn_name}' was added to monitoring."
    if ct == "removed":
        level = "high" if sensitive else "medium"
        return level, f"Lambda function '{fn_name}' is no longer visible to ConfigTrace."

    # Role changes — execution role determines all AWS permissions the function has
    if fp == "role_arn_present" and new_val is False:
        return (
            "high",
            f"Lambda function '{fn_name}' no longer has an execution role. "
            "The function may be unable to access AWS resources.",
        )

    if fp == "role_arn_hash":
        return (
            "medium",
            f"Lambda function '{fn_name}' execution role changed. "
            "Verify the new role grants only the intended permissions.",
        )

    # KMS key for environment variable encryption
    if fp == "kms_key_arn_present":
        if prev_val is True and new_val is False:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Lambda function '{fn_name}' lost its KMS customer-managed key. "
                "Environment variables may now use only default AWS encryption.",
            )
        if prev_val is False and new_val is True:
            return (
                "low",
                f"Lambda function '{fn_name}' gained a KMS customer-managed key. "
                "This is a security improvement.",
            )
        return "low", f"Lambda function '{fn_name}' KMS key presence changed."

    if fp == "kms_key_arn_hash":
        return (
            "medium",
            f"Lambda function '{fn_name}' KMS encryption key changed. "
            "Verify the new key is correct and accessible.",
        )

    # Environment variable key changes (NEVER values — keys only)
    if fp == "environment_key_names":
        old_keys = set(prev_val) if isinstance(prev_val, list) else set()
        new_keys = set(new_val) if isinstance(new_val, list) else set()
        added_keys = new_keys - old_keys
        if added_keys:
            return (
                "medium",
                f"Lambda function '{fn_name}' gained new environment variable key(s): "
                f"{sorted(added_keys)}. "
                "Verify no sensitive values were added without appropriate KMS encryption.",
            )
        return (
            "low",
            f"Lambda function '{fn_name}' environment variable keys changed. "
            "ConfigTrace stores key names only; values are never accessed.",
        )

    if fp == "environment_sensitive_key_count":
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val > prev_val:
            return (
                "medium",
                f"Lambda function '{fn_name}' has more environment variable keys with "
                f"sensitive-sounding names ({prev_val} → {new_val}). "
                "Verify these are encrypted with a KMS CMK.",
            )
        return "low", f"Lambda function '{fn_name}' sensitive environment key count changed."

    if fp == "environment_key_count":
        return "low", f"Lambda function '{fn_name}' environment variable count changed."

    # VPC configuration — removal means function can reach internet by default
    if fp == "vpc_config_present":
        if prev_val is True and new_val is False:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"Lambda function '{fn_name}' was removed from its VPC. "
                "The function can now access the public internet by default.",
            )
        if prev_val is False and new_val is True:
            return (
                "low",
                f"Lambda function '{fn_name}' was placed in a VPC. "
                "Verify subnet and security group configuration.",
            )
        return "low", f"Lambda function '{fn_name}' VPC configuration changed."

    if fp in ("subnet_ids", "security_group_ids"):
        return (
            "medium",
            f"Lambda function '{fn_name}' VPC network configuration changed ({fp}). "
            "Verify the new subnets/security groups are correct.",
        )

    # Concurrency — zero means fully throttled
    if fp == "reserved_concurrent_executions":
        if new_val == 0:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"Lambda function '{fn_name}' reserved concurrency was set to 0. "
                "The function is now fully throttled and will not execute.",
            )
        if isinstance(new_val, int) and isinstance(prev_val, int) and prev_val != 0 and new_val < prev_val:
            return (
                "medium",
                f"Lambda function '{fn_name}' reserved concurrency decreased "
                f"from {prev_val} to {new_val}. Verify the function capacity is sufficient.",
            )
        return "low", f"Lambda function '{fn_name}' reserved concurrency changed."

    # Runtime change — may introduce incompatibilities or remove security patches
    if fp == "runtime":
        return (
            "medium",
            f"Lambda function '{fn_name}' runtime changed from '{prev_val}' to '{new_val}'. "
            "Verify the new runtime is supported and dependencies are compatible.",
        )

    # X-Ray tracing
    if fp == "tracing_mode":
        if str(new_val or "").lower() == "passthrough":
            return (
                "medium",
                f"Lambda function '{fn_name}' X-Ray tracing was set to PassThrough. "
                "Active tracing has been disabled.",
            )
        return "low", f"Lambda function '{fn_name}' tracing mode changed."

    # Dead-letter queue removal — failed async invocations are silently dropped
    if fp == "dead_letter_target_present":
        if prev_val is True and new_val is False:
            level = "medium" if sensitive else "low"
            return (
                level,
                f"Lambda function '{fn_name}' lost its dead-letter queue/topic. "
                "Failed asynchronous invocations will no longer be captured.",
            )
        return "low", f"Lambda function '{fn_name}' dead-letter target changed."

    if fp in ("layers_count", "layer_arn_hashes"):
        return "low", f"Lambda function '{fn_name}' Lambda layer configuration changed."

    if fp in (
        "handler_present", "timeout", "memory_size", "ephemeral_storage_size",
        "code_size", "last_modified", "version", "architectures",
        "snap_start_apply_on", "package_type", "dead_letter_target_type",
        "subnet_count", "security_group_count",
    ):
        return "low", f"Lambda function '{fn_name}' {fp.replace('_', ' ')} changed."

    if fp == "tag_keys":
        return "low", f"Lambda function '{fn_name}' tags changed."

    if fp == "config_fetch_warnings":
        return "low", f"Lambda function '{fn_name}' fetch warnings changed."

    return (
        "low",
        f"Lambda function '{fn_name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_lambda_alias ───────────────────────────────────────────────────────────

def _classify_lambda_alias_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    alias_id: str = pm.get("record_name") or pm.get("record_id") or ""

    if ct == "added":
        return "low", f"Lambda alias '{alias_id}' was added."
    if ct == "removed":
        return "low", f"Lambda alias '{alias_id}' was removed."

    if fp == "function_version":
        return (
            "medium",
            f"Lambda alias '{alias_id}' now points to function version '{new_val}' "
            f"(was '{prev_val}'). Traffic will be routed to the new version.",
        )

    if fp == "routing_config_present":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"Lambda alias '{alias_id}' weighted routing configuration was removed. "
                "All traffic now goes to the primary version.",
            )
        return "low", f"Lambda alias '{alias_id}' routing configuration changed."

    if fp in ("additional_version_weights_count", "additional_version_weights_summary"):
        return "low", f"Lambda alias '{alias_id}' traffic weights changed."

    return "low", f"Lambda alias '{alias_id}' configuration changed (field: {fp or 'unknown'})."


# ── aws_lambda_event_source_mapping ───────────────────────────────────────────

def _classify_lambda_event_source_mapping_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    esm_id: str = pm.get("record_id") or ""

    if ct == "added":
        return "low", f"Lambda event source mapping '{esm_id}' was added."
    if ct == "removed":
        return (
            "medium",
            f"Lambda event source mapping '{esm_id}' was removed. "
            "Verify the trigger is no longer needed.",
        )

    if fp == "state":
        nv_str = str(new_val or "").lower()
        if nv_str in ("disabled", "disabling"):
            return (
                "medium",
                f"Lambda event source mapping '{esm_id}' state changed to '{new_val}'. "
                "The trigger is no longer active.",
            )
        return "low", f"Lambda event source mapping '{esm_id}' state changed to '{new_val}'."

    if fp == "enabled":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"Lambda event source mapping '{esm_id}' was disabled. "
                "The function will no longer be invoked by this trigger.",
            )
        return "low", f"Lambda event source mapping '{esm_id}' enabled state changed."

    if fp == "event_source_arn_present" and new_val is False:
        return (
            "high",
            f"Lambda event source mapping '{esm_id}' lost its event source ARN. "
            "The trigger may be broken.",
        )

    if fp == "event_source_arn_hash":
        return (
            "medium",
            f"Lambda event source mapping '{esm_id}' event source changed. "
            "Verify the new source is correct.",
        )

    if fp == "function_name":
        return (
            "medium",
            f"Lambda event source mapping '{esm_id}' target function changed "
            f"(was '{prev_val}', now '{new_val}'). "
            "Verify the new function handles the event stream correctly.",
        )

    if fp == "filter_criteria_present":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"Lambda event source mapping '{esm_id}' filter criteria were removed. "
                "All events will now invoke the function, potentially increasing the invocation rate.",
            )
        return "low", f"Lambda event source mapping '{esm_id}' filter criteria changed."

    if fp == "batch_size":
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val > prev_val:
            return (
                "medium",
                f"Lambda event source mapping '{esm_id}' batch size increased "
                f"from {prev_val} to {new_val}. Each invocation will process more records.",
            )
        return "low", f"Lambda event source mapping '{esm_id}' batch size changed."

    if fp in (
        "maximum_batching_window_seconds", "starting_position",
        "destination_config_present", "function_response_types",
    ):
        return "low", f"Lambda event source mapping '{esm_id}' {fp.replace('_', ' ')} changed."

    return (
        "low",
        f"Lambda event source mapping '{esm_id}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_lambda_function_url ────────────────────────────────────────────────────

def _classify_lambda_function_url_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    fn_name: str = pm.get("record_name") or pm.get("record_id") or ""

    if ct == "added":
        nv_dict = new_val if isinstance(new_val, dict) else {}
        auth = (nv_dict.get("auth_type") or "").upper()
        if auth == "NONE":
            return (
                "critical",
                f"Lambda function URL for '{fn_name}' was created with auth_type=NONE. "
                "The function is now publicly invokable by anyone on the internet "
                "without authentication. Verify this is intentional.",
            )
        return (
            "medium",
            f"Lambda function URL for '{fn_name}' was created "
            f"(auth_type={auth or 'unknown'}). "
            "Verify the authentication setting is appropriate.",
        )

    if ct == "removed":
        return (
            "low",
            f"Lambda function URL for '{fn_name}' was removed. "
            "The public endpoint is no longer accessible.",
        )

    if fp == "auth_type":
        prev_str = (str(prev_val or "")).upper()
        new_str = (str(new_val or "")).upper()
        if new_str == "NONE":
            return (
                "critical",
                f"Lambda function URL for '{fn_name}' auth type changed to NONE. "
                "The function is now publicly invokable without authentication. "
                "Set auth_type to AWS_IAM to require authentication.",
            )
        if prev_str == "NONE" and new_str != "NONE":
            return (
                "low",
                f"Lambda function URL for '{fn_name}' auth type changed from NONE "
                f"to {new_str}. Authentication is now required. "
                "This is a security improvement.",
            )
        return (
            "high",
            f"Lambda function URL for '{fn_name}' auth type changed "
            f"from {prev_str!r} to {new_str!r}. Verify the new auth setting is correct.",
        )

    if fp == "cors_wildcard_origin_present":
        if prev_val is not True and new_val is True:
            return (
                "high",
                f"Lambda function URL for '{fn_name}' CORS now allows wildcard origin (*). "
                "Any website can make cross-origin requests to this function URL. "
                "Verify this is intentional and consider restricting allowed origins.",
            )
        if prev_val is True and new_val is not True:
            return "low", f"Lambda function URL for '{fn_name}' CORS wildcard origin was removed."
        return "low", f"Lambda function URL for '{fn_name}' CORS wildcard origin status changed."

    if fp == "cors_allow_credentials":
        if new_val is True:
            return (
                "high",
                f"Lambda function URL for '{fn_name}' CORS now allows credentials. "
                "If wildcard origin is also enabled, this is a critical CORS misconfiguration.",
            )
        return "low", f"Lambda function URL for '{fn_name}' CORS allow-credentials changed."

    if fp in ("cors_present", "cors_allow_origins_count", "cors_allow_methods", "invoke_mode"):
        return "low", f"Lambda function URL for '{fn_name}' {fp.replace('_', ' ')} changed."

    return (
        "low",
        f"Lambda function URL for '{fn_name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_apigateway_rest_api ────────────────────────────────────────────────────

def _classify_apigateway_rest_api_change(change: object) -> tuple[str, str]:  # noqa: C901
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    api_name: str = pm.get("record_name") or ""
    sensitive = _lambda_is_sensitive(api_name)

    if ct == "added":
        nv_dict = new_val if isinstance(new_val, dict) else {}
        unauth = nv_dict.get("unauthenticated_method_count") or 0
        if sensitive and unauth > 0:
            return (
                "high",
                f"API Gateway REST API '{api_name}' appeared with {unauth} unauthenticated "
                "method(s). Verify all endpoints require authentication.",
            )
        return "low", f"API Gateway REST API '{api_name}' was added to monitoring."

    if ct == "removed":
        level = "high" if sensitive else "medium"
        return level, f"API Gateway REST API '{api_name}' is no longer visible to ConfigTrace."

    if fp == "unauthenticated_method_count":
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val > prev_val:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"API Gateway REST API '{api_name}' unauthenticated method count increased "
                f"from {prev_val} to {new_val}. "
                "New methods may be accessible without authentication.",
            )
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val < prev_val:
            return (
                "low",
                f"API Gateway REST API '{api_name}' unauthenticated method count decreased "
                f"from {prev_val} to {new_val}.",
            )
        return "low", f"API Gateway REST API '{api_name}' unauthenticated method count changed."

    if fp == "authorizer_count":
        if isinstance(new_val, int) and new_val == 0 and isinstance(prev_val, int) and prev_val > 0:
            return (
                "high",
                f"API Gateway REST API '{api_name}' has no authorizers. "
                "All authorizers were removed — endpoints may be accessible without authentication.",
            )
        return "low", f"API Gateway REST API '{api_name}' authorizer count changed."

    if fp == "policy_summary":
        prev_ps = prev_val if isinstance(prev_val, dict) else {}
        new_ps = new_val if isinstance(new_val, dict) else {}
        prev_wildcard = prev_ps.get("has_wildcard_principal", False)
        new_wildcard = new_ps.get("has_wildcard_principal", False)
        if new_wildcard and not prev_wildcard:
            return (
                "critical",
                f"API Gateway REST API '{api_name}' resource policy now includes a wildcard "
                "principal (*). Any AWS principal may be able to invoke this API. "
                "Review the resource policy immediately.",
            )
        if prev_wildcard and not new_wildcard:
            return (
                "low",
                f"API Gateway REST API '{api_name}' resource policy wildcard principal "
                "was removed.",
            )
        return (
            "medium",
            f"API Gateway REST API '{api_name}' resource policy changed. "
            "Verify the updated policy grants only intended access.",
        )

    if fp == "endpoint_configuration_types":
        return (
            "medium",
            f"API Gateway REST API '{api_name}' endpoint type changed "
            f"(was {prev_val!r}, now {new_val!r}). "
            "Verify the API is still accessible from intended locations.",
        )

    if fp == "disable_execute_api_endpoint":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"API Gateway REST API '{api_name}' default execute-api endpoint was "
                "re-enabled. The API is now accessible via the default AWS-managed URL.",
            )
        if prev_val is False and new_val is True:
            return (
                "low",
                f"API Gateway REST API '{api_name}' default execute-api endpoint was "
                "disabled. The API must be accessed via a custom domain.",
            )
        return "low", f"API Gateway REST API '{api_name}' execute-api endpoint setting changed."

    if fp == "api_key_source":
        return (
            "medium",
            f"API Gateway REST API '{api_name}' API key source changed "
            f"(was {prev_val!r}, now {new_val!r}). Verify API key usage plans are correct.",
        )

    if fp in ("method_count", "resource_count", "integration_type_counts",
              "binary_media_types_count", "minimum_compression_size"):
        return "low", f"API Gateway REST API '{api_name}' {fp.replace('_', ' ')} changed."

    if fp == "tag_keys":
        return "low", f"API Gateway REST API '{api_name}' tags changed."

    return (
        "low",
        f"API Gateway REST API '{api_name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_apigateway_rest_stage ──────────────────────────────────────────────────

def _classify_apigateway_rest_stage_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    stage_id: str = pm.get("record_name") or pm.get("record_id") or ""

    if ct == "added":
        return "low", f"API Gateway REST stage '{stage_id}' was added."
    if ct == "removed":
        return "medium", f"API Gateway REST stage '{stage_id}' was removed."

    if fp == "deployment_id_present":
        if prev_val is True and new_val is False:
            return (
                "high",
                f"API Gateway REST stage '{stage_id}' is no longer linked to a deployment. "
                "The stage may be serving stale or undefined API configuration.",
            )
        return "low", f"API Gateway REST stage '{stage_id}' deployment presence changed."

    if fp == "deployment_id_hash":
        return (
            "medium",
            f"API Gateway REST stage '{stage_id}' was redeployed. "
            "Verify the new deployment reflects the intended API configuration.",
        )

    if fp == "tracing_enabled":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"X-Ray tracing was disabled for API Gateway REST stage '{stage_id}'.",
            )
        return "low", f"API Gateway REST stage '{stage_id}' tracing setting changed."

    if fp == "access_logging_enabled":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"Access logging was disabled for API Gateway REST stage '{stage_id}'. "
                "API request logs will no longer be collected.",
            )
        return "low", f"API Gateway REST stage '{stage_id}' access logging setting changed."

    if fp == "metrics_enabled_count":
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val < prev_val:
            return (
                "medium",
                f"API Gateway REST stage '{stage_id}' CloudWatch metrics count decreased "
                f"({prev_val} → {new_val}). Some route metrics may no longer be collected.",
            )
        return "low", f"API Gateway REST stage '{stage_id}' metrics configuration changed."

    if fp == "web_acl_arn_present":
        if prev_val is True and new_val is False:
            return (
                "high",
                f"API Gateway REST stage '{stage_id}' WAF Web ACL was removed. "
                "The stage is no longer protected by AWS WAF.",
            )
        return "low", f"API Gateway REST stage '{stage_id}' WAF configuration changed."

    if fp in (
        "cache_cluster_enabled", "cache_cluster_size", "logging_level_summary",
        "variables_key_count", "variables_key_names", "canary_settings_present",
        "throttling_present",
    ):
        return "low", f"API Gateway REST stage '{stage_id}' {fp.replace('_', ' ')} changed."

    return (
        "low",
        f"API Gateway REST stage '{stage_id}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_apigatewayv2_api ───────────────────────────────────────────────────────

def _classify_apigatewayv2_api_change(change: object) -> tuple[str, str]:  # noqa: C901
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    api_name: str = pm.get("record_name") or ""
    sensitive = _lambda_is_sensitive(api_name)

    if ct == "added":
        nv_dict = new_val if isinstance(new_val, dict) else {}
        unauth = nv_dict.get("unauthenticated_route_count") or 0
        if sensitive and unauth > 0:
            return (
                "high",
                f"API Gateway V2 API '{api_name}' appeared with {unauth} unauthenticated "
                "route(s). Verify all routes require authentication.",
            )
        return "low", f"API Gateway V2 API '{api_name}' was added to monitoring."

    if ct == "removed":
        level = "high" if sensitive else "medium"
        return level, f"API Gateway V2 API '{api_name}' is no longer visible to ConfigTrace."

    if fp == "unauthenticated_route_count":
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val > prev_val:
            level = "high" if sensitive else "medium"
            return (
                level,
                f"API Gateway V2 API '{api_name}' unauthenticated route count increased "
                f"from {prev_val} to {new_val}. "
                "New routes may be accessible without authentication.",
            )
        if isinstance(new_val, int) and isinstance(prev_val, int) and new_val < prev_val:
            return (
                "low",
                f"API Gateway V2 API '{api_name}' unauthenticated route count decreased "
                f"from {prev_val} to {new_val}.",
            )
        return "low", f"API Gateway V2 API '{api_name}' unauthenticated route count changed."

    if fp == "authorizer_count":
        if isinstance(new_val, int) and new_val == 0 and isinstance(prev_val, int) and prev_val > 0:
            return (
                "high",
                f"API Gateway V2 API '{api_name}' has no authorizers. "
                "All authorizers were removed — routes may be accessible without authentication.",
            )
        return "low", f"API Gateway V2 API '{api_name}' authorizer count changed."

    if fp == "cors_wildcard_origin_present":
        if prev_val is not True and new_val is True:
            return (
                "high",
                f"API Gateway V2 API '{api_name}' CORS now allows wildcard origin (*). "
                "Any website can make cross-origin requests to this API. "
                "Consider restricting allowed origins.",
            )
        if prev_val is True and new_val is not True:
            return "low", f"API Gateway V2 API '{api_name}' CORS wildcard origin was removed."
        return "low", f"API Gateway V2 API '{api_name}' CORS wildcard origin status changed."

    if fp == "cors_allow_credentials":
        if new_val is True:
            return (
                "high",
                f"API Gateway V2 API '{api_name}' CORS now allows credentials. "
                "If wildcard origin is also enabled, this is a critical CORS misconfiguration.",
            )
        return "low", f"API Gateway V2 API '{api_name}' CORS allow-credentials changed."

    if fp == "cors_present":
        if prev_val is True and new_val is False:
            return "low", f"API Gateway V2 API '{api_name}' CORS configuration was removed."
        return "low", f"API Gateway V2 API '{api_name}' CORS configuration changed."

    if fp == "disable_execute_api_endpoint":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"API Gateway V2 API '{api_name}' default execute-api endpoint was re-enabled.",
            )
        return "low", f"API Gateway V2 API '{api_name}' execute-api endpoint setting changed."

    if fp in ("route_count", "integration_type_counts", "route_selection_expression_present",
              "api_endpoint_present", "protocol_type"):
        return "low", f"API Gateway V2 API '{api_name}' {fp.replace('_', ' ')} changed."

    if fp == "tag_keys":
        return "low", f"API Gateway V2 API '{api_name}' tags changed."

    return (
        "low",
        f"API Gateway V2 API '{api_name}' configuration changed (field: {fp or 'unknown'}).",
    )


# ── aws_apigatewayv2_stage ─────────────────────────────────────────────────────

def _classify_apigatewayv2_stage_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_val = _get(change, "new_value")
    prev_val = _get(change, "prev_value")
    pm: dict = _get(change, "provider_metadata") or {}
    stage_id: str = pm.get("record_name") or pm.get("record_id") or ""

    if ct == "added":
        return "low", f"API Gateway V2 stage '{stage_id}' was added."
    if ct == "removed":
        return "medium", f"API Gateway V2 stage '{stage_id}' was removed."

    if fp == "deployment_id_present":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"API Gateway V2 stage '{stage_id}' is no longer linked to a deployment.",
            )
        return "low", f"API Gateway V2 stage '{stage_id}' deployment presence changed."

    if fp == "deployment_id_hash":
        return "low", f"API Gateway V2 stage '{stage_id}' deployment changed."

    if fp == "auto_deploy":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"API Gateway V2 stage '{stage_id}' auto-deploy was disabled. "
                "API changes will no longer be automatically deployed to this stage.",
            )
        return "low", f"API Gateway V2 stage '{stage_id}' auto-deploy setting changed."

    if fp == "access_logging_enabled":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"Access logging was disabled for API Gateway V2 stage '{stage_id}'. "
                "API request logs will no longer be collected.",
            )
        return "low", f"API Gateway V2 stage '{stage_id}' access logging setting changed."

    if fp == "detailed_metrics_enabled":
        if prev_val is True and new_val is False:
            return (
                "medium",
                f"Detailed CloudWatch metrics were disabled for API Gateway V2 stage '{stage_id}'.",
            )
        return "low", f"API Gateway V2 stage '{stage_id}' metrics setting changed."

    if fp in (
        "stage_variables_key_count", "stage_variables_key_names",
        "default_route_settings_summary",
    ):
        return "low", f"API Gateway V2 stage '{stage_id}' {fp.replace('_', ' ')} changed."

    return (
        "low",
        f"API Gateway V2 stage '{stage_id}' configuration changed (field: {fp or 'unknown'}).",
    )


def classify_aws_change(change: object) -> tuple[str, str]:
    """Route an AWS change to the appropriate risk rule.

    Args:
        change: A Change ORM instance or plain dict.

    Returns:
        (risk_level, risk_reason) — level is one of critical/high/medium/low.
    """
    pm: dict = _get(change, "provider_metadata") or {}
    record_type: str = (pm.get("record_type") or "").lower()

    if record_type == AWS_ACCOUNT_IDENTITY:
        return _classify_account_identity_change(change)
    if record_type == AWS_REGION:
        return _classify_region_change(change)
    if record_type == AWS_SERVICE_INVENTORY:
        return _classify_service_inventory_change(change)
    if record_type == AWS_S3_BUCKET:
        return _classify_s3_change(change)
    # ── M38 ──────────────────────────────────────────────────────────────────
    if record_type == AWS_SECURITY_GROUP_RULE:
        return _classify_security_group_rule_change(change)
    if record_type == AWS_SECURITY_GROUP:
        return _classify_security_group_change(change)
    if record_type == AWS_VPC:
        return _classify_vpc_change(change)
    if record_type == AWS_SUBNET:
        return _classify_subnet_change(change)
    if record_type == AWS_ROUTE_TABLE:
        return _classify_route_table_change(change)
    if record_type == AWS_INTERNET_GATEWAY:
        return _classify_igw_change(change)
    if record_type == AWS_NETWORK_ACL:
        return _classify_network_acl_change(change)
    # ── M39 IAM ───────────────────────────────────────────────────────────────
    if record_type == AWS_IAM_ACCOUNT_SUMMARY:
        return _classify_iam_account_summary_change(change)
    if record_type == AWS_IAM_USER:
        return _classify_iam_user_change(change)
    if record_type == AWS_IAM_ACCESS_KEY:
        return _classify_iam_access_key_change(change)
    if record_type == AWS_IAM_GROUP:
        return _classify_iam_group_change(change)
    if record_type == AWS_IAM_ROLE:
        return _classify_iam_role_change(change)
    if record_type == AWS_IAM_POLICY:
        return _classify_iam_policy_change(change)
    if record_type == AWS_IAM_POLICY_ATTACHMENT:
        return _classify_iam_policy_attachment_change(change)
    if record_type == AWS_IAM_INLINE_POLICY:
        return _classify_iam_inline_policy_change(change)
    if record_type == AWS_IAM_IDENTITY_PROVIDER:
        return _classify_iam_identity_provider_change(change)
    # ── M40 Route53 + CloudFront ──────────────────────────────────────────────
    if record_type == AWS_ROUTE53_HOSTED_ZONE:
        return _classify_route53_hosted_zone_change(change)
    if record_type == AWS_ROUTE53_RECORD:
        return _classify_route53_record_change(change)
    if record_type == AWS_CLOUDFRONT_DISTRIBUTION:
        return _classify_cloudfront_distribution_change(change)
    # ── M41 Secrets Manager + SSM ─────────────────────────────────────────────
    if record_type == AWS_SECRETSMANAGER_SECRET:
        return _classify_secretsmanager_secret_change(change)
    if record_type == AWS_SSM_PARAMETER:
        return _classify_ssm_parameter_change(change)
    # ── M42 RDS ───────────────────────────────────────────────────────────────
    if record_type == AWS_RDS_DB_INSTANCE:
        return _classify_rds_db_instance_change(change)
    if record_type == AWS_RDS_DB_CLUSTER:
        return _classify_rds_db_cluster_change(change)
    if record_type == AWS_RDS_DB_SUBNET_GROUP:
        return _classify_rds_db_subnet_group_change(change)
    if record_type == AWS_RDS_DB_SNAPSHOT:
        return _classify_rds_db_snapshot_change(change)
    if record_type == AWS_RDS_DB_CLUSTER_SNAPSHOT:
        return _classify_rds_db_cluster_snapshot_change(change)
    # ── M43 Lambda + API Gateway ──────────────────────────────────────────────
    if record_type == AWS_LAMBDA_FUNCTION:
        return _classify_lambda_function_change(change)
    if record_type == AWS_LAMBDA_ALIAS:
        return _classify_lambda_alias_change(change)
    if record_type == AWS_LAMBDA_EVENT_SOURCE_MAPPING:
        return _classify_lambda_event_source_mapping_change(change)
    if record_type == AWS_LAMBDA_FUNCTION_URL:
        return _classify_lambda_function_url_change(change)
    if record_type == AWS_APIGATEWAY_REST_API:
        return _classify_apigateway_rest_api_change(change)
    if record_type == AWS_APIGATEWAY_REST_STAGE:
        return _classify_apigateway_rest_stage_change(change)
    if record_type == AWS_APIGATEWAYV2_API:
        return _classify_apigatewayv2_api_change(change)
    if record_type == AWS_APIGATEWAYV2_STAGE:
        return _classify_apigatewayv2_stage_change(change)

    # Unknown AWS record type — conservative default
    return (
        "low",
        f"AWS configuration changed ({record_type or 'unknown record type'}).",
    )
