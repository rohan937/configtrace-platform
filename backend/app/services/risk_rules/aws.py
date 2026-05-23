"""AWS risk classification rules — M36 + M37.

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

from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    AWS_S3_BUCKET,
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
        return (
            "low",
            f"Public WRITE ACL was removed from S3 bucket {bucket_name!r}. "
            "This is a security improvement.",
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
        return (
            "low",
            f"Public READ ACL was removed from S3 bucket {bucket_name!r}.",
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
        return (
            "low",
            f"AuthenticatedUsers WRITE ACL was removed from S3 bucket {bucket_name!r}.",
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
        return (
            "low",
            f"AuthenticatedUsers READ ACL was removed from S3 bucket {bucket_name!r}.",
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
        nv_str = str(nv).lower() if nv is not None else "disabled"
        pv_str = str(pv).lower() if pv is not None else "disabled"
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

    # Unknown AWS record type — future surfaces; conservative default
    return (
        "low",
        f"AWS configuration changed ({record_type or 'unknown record type'}).",
    )
