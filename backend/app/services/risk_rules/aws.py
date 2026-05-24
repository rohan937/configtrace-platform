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
) -> tuple[str, str]:
    """Return (risk_level, risk_reason) for a public ingress rule (added).

    Uses "may be reachable" hedging throughout — a SG rule allowing public
    access does not prove reachability without subnet/IGW/route-table context.
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
        # Distinguish HTTP (risky for data exposure) from HTTPS (expected)
        if _has_port_in_range(80, from_port, to_port, protocol) or _has_port_in_range(8080, from_port, to_port, protocol):
            return (
                "medium",
                f"An inbound HTTP rule ({port_str}) was added to security group {group_id!r} "
                f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
                f"Verify that public HTTP access is intentional for the attached resources. "
                f"HTTPS (port 443) is preferred for web traffic.",
            )
        # HTTPS (443, 8443) — standard for public web services
        return (
            "low",
            f"An inbound HTTPS rule ({port_str}) was added to security group {group_id!r} "
            f"in {region or 'unknown region'} allowing traffic from {cidr or 'all sources'}. "
            f"HTTPS access from the internet is expected for public web services.",
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
      - Medium for public inbound HTTP or other non-web ports.
      - Low for public HTTPS, private CIDRs, group references, or egress.
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
            return _risk_for_public_ingress_rule(
                group_id, region, protocol, from_port, to_port, cidr
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

    # Unknown AWS record type — conservative default
    return (
        "low",
        f"AWS configuration changed ({record_type or 'unknown record type'}).",
    )
