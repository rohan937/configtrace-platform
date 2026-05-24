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


# ── Entry point ──────────────────────────────────────────────────────────────


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

    # Unknown AWS record type — conservative default
    return (
        "low",
        f"AWS configuration changed ({record_type or 'unknown record type'}).",
    )
