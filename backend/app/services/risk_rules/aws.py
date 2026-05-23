"""AWS risk classification rules — M36.

Entry point: classify_aws_change(change)

Risk levels for M36 (account/inventory changes only)
------------------------------------------------------
high     — Account identity changed unexpectedly, principal ARN changed
           to a different principal, selected regions significantly reduced.
medium   — Selected regions changed, default region changed, new region added,
           principal type changed.
low      — Routine metadata, opt-in status metadata, service inventory
           placeholder changes, future surfaces list changes.
"""
from __future__ import annotations

from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
)


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

    # Unknown AWS record type — future surfaces; conservative default
    return (
        "low",
        f"AWS configuration changed ({record_type or 'unknown record type'}).",
    )
