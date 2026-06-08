"""Security Exposure coverage-quality service — M62.3.

Read-only. For each provider, inspects STORED snapshots (never calls provider
APIs) to report whether ConfigTrace is collecting the metadata needed to
evaluate Security Exposure rules.

Coverage is a TRUST signal, not a safety verdict:
  * "good"  = every expected record type for the provider's rules was observed.
  * "limited" = some expected record types observed, others missing.
  * "not_synced" = connected but no usable records observed yet.
  * "needs_attention" = the integration needs reconnect / recent syncs failed.
  * "not_connected" = no integration for this provider.

Good coverage does NOT mean a system is safe — it only means the rules have
enough data to run. Demo/deleted integrations are ignored.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.integration import Integration
from app.models.resource import Resource
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rule_settings_service import get_disabled_rule_keys
from app.services.snapshot_service import get_latest_snapshot

logger = logging.getLogger(__name__)

PROVIDERS = [
    "github",
    "aws",
    "cloudflare",
    "supabase",
    "firebase",
    "stripe",
    "vercel",
    "shopify",
]

# rule_key → the snapshot record_type(s) the rule consumes. A rule is
# "supported by observed records" when ANY of its record types is present.
RULE_RECORD_TYPES: dict[str, tuple[str, ...]] = {
    # GitHub
    "github_webhook_http": ("github_webhook",),
    "github_branch_protection_missing": ("github_branch_protection",),
    "github_force_pushes_allowed": ("github_branch_protection",),
    "github_branch_deletion_allowed": ("github_branch_protection",),
    "github_pr_review_not_required": ("github_branch_protection",),
    "github_status_checks_not_required": ("github_branch_protection",),
    "github_deploy_key_write_access": ("github_deploy_key",),
    "github_env_protection_missing": ("github_environment_protection",),
    # AWS
    "aws_public_admin_port": ("aws_security_group_rule",),
    "aws_public_database_port": ("aws_security_group_rule",),
    "aws_public_all_ports": ("aws_security_group_rule",),
    "aws_s3_public_policy": ("aws_s3_bucket",),
    "aws_s3_public_acl": ("aws_s3_bucket",),
    "aws_iam_admin_policy_attached": ("aws_iam_policy_attachment",),
    "aws_access_key_unused": ("aws_iam_access_key",),
    # Cloudflare
    "cloudflare_ssl_mode_weak": ("cloudflare_zone_setting",),
    "cloudflare_always_https_off": ("cloudflare_zone_setting",),
    "cloudflare_min_tls_weak": ("cloudflare_zone_setting",),
    "cloudflare_security_level_low": ("cloudflare_zone_setting",),
    "cloudflare_development_mode_on": ("cloudflare_zone_setting",),
    "cloudflare_hsts_disabled": ("cloudflare_zone_setting",),
    "cloudflare_waf_rule_disabled": ("cloudflare_waf_rule",),
    "cloudflare_dns_private_origin": ("A", "AAAA"),
    # Supabase
    "supabase_rls_disabled": ("supabase_rls_status",),
    "supabase_anonymous_access_enabled": ("supabase_auth_config",),
    "supabase_jwt_expiry_long": ("supabase_auth_config",),
    # Firebase
    "firebase_rules_public": ("firebase_firestore_ruleset",),
    "firebase_storage_rules_public": ("firebase_storage_ruleset",),
    "firebase_anonymous_auth_enabled": ("firebase_auth_config",),
    # Stripe
    "stripe_webhook_http": ("stripe_webhook_endpoint",),
    # Vercel
    "vercel_preview_unprotected": ("vercel_deployment_protection",),
    # Shopify
    "shopify_webhook_http": ("shopify_webhook_subscription",),
}

# Friendly, human surfaces per provider for display (no internal jargon).
PROVIDER_SURFACES: dict[str, list[str]] = {
    "github": ["Webhooks", "Branch protection", "Deploy keys", "Environment protection"],
    "aws": ["Security group rules", "S3 buckets", "IAM policy attachments", "IAM access keys"],
    "cloudflare": ["Zone settings", "WAF rules", "DNS records"],
    "supabase": ["Row-level security", "Auth configuration"],
    "firebase": ["Firestore rules", "Storage rules", "Auth configuration"],
    "stripe": ["Webhook endpoints"],
    "vercel": ["Deployment protection"],
    "shopify": ["Webhook subscriptions"],
}


def _provider_of(rule_key: str) -> str:
    return rule_key.split("_", 1)[0]


def _expected_record_types(provider: str) -> set[str]:
    out: set[str] = set()
    for rk in KNOWN_RULE_KEYS:
        if _provider_of(rk) == provider:
            out.update(RULE_RECORD_TYPES.get(rk, ()))
    return out


def _rule_keys_for(provider: str) -> list[str]:
    return sorted(rk for rk in KNOWN_RULE_KEYS if _provider_of(rk) == provider)


def _observed_record_types(
    integ_ids: list[uuid.UUID], db: Session
) -> set[str]:
    """Union of record_type values across the latest snapshot of each resource."""
    observed: set[str] = set()
    if not integ_ids:
        return observed
    resources = (
        db.query(Resource)
        .filter(
            Resource.integration_id.in_(integ_ids),
            Resource.is_active.is_(True),
        )
        .all()
    )
    for res in resources:
        snap = get_latest_snapshot(res.id, db)
        if snap is None or not isinstance(snap.state, list):
            continue
        for record in snap.state:
            if isinstance(record, dict):
                rt = record.get("record_type")
                if isinstance(rt, str) and rt:
                    observed.add(rt)
    return observed


def _recommendation(status: str) -> str:
    return {
        "not_connected": "Connect this provider to evaluate its security rules.",
        "not_synced": "Run a sync to collect provider metadata.",
        "needs_attention": "Reconnect this provider; recent syncs may not have completed.",
        "limited": "Some surfaces are missing — check provider permissions and run a sync.",
        "good": "Coverage is good. Good coverage does not mean no risk exists.",
    }.get(status, "Run a sync to collect provider metadata.")


def get_coverage(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Build the per-provider coverage report for a workspace (read-only)."""
    # Real (non-demo, non-deleted) integrations grouped by provider.
    integrations = (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.status != "deleted",
            Integration.provider.in_(PROVIDERS),
        )
        .all()
    )
    by_provider: dict[str, list[Integration]] = {}
    for i in integrations:
        by_provider.setdefault(i.provider, []).append(i)

    disabled = get_disabled_rule_keys(workspace_id, db)

    providers_out: list[dict[str, Any]] = []
    summary = {
        "connected_providers": 0,
        "good_coverage": 0,
        "limited_coverage": 0,
        "not_connected": 0,
        "disabled_rules": 0,
    }

    for provider in PROVIDERS:
        integs = by_provider.get(provider, [])
        rule_keys = _rule_keys_for(provider)
        supported_total = len(rule_keys)
        disabled_count = sum(1 for rk in rule_keys if rk in disabled)
        active_count = supported_total - disabled_count
        summary["disabled_rules"] += disabled_count

        expected = _expected_record_types(provider)

        if not integs:
            status = "not_connected"
            observed: set[str] = set()
            integration_id = None
            integration_status = None
            last_synced_at = None
            summary["not_connected"] += 1
        else:
            summary["connected_providers"] += 1
            # Prefer the most recently synced integration for display fields.
            integ = max(
                integs,
                key=lambda x: x.last_synced_at or x.created_at,
            )
            integration_id = str(integ.id)
            integration_status = integ.status
            last_synced_at = integ.last_synced_at
            observed = _observed_record_types([i.id for i in integs], db)
            observed_expected = expected & observed

            if integration_status in ("needs_reconnect", "error"):
                status = "needs_attention"
            elif not observed_expected:
                status = "not_synced"
            elif observed_expected >= expected:
                status = "good"
                summary["good_coverage"] += 1
            else:
                status = "limited"
                summary["limited_coverage"] += 1

        missing = sorted(expected - observed)

        # Per-rule coverage: enabled + supported-by-observed-records.
        rules_out = []
        for rk in rule_keys:
            needed = RULE_RECORD_TYPES.get(rk, ())
            supported = bool(set(needed) & observed) if needed else False
            rules_out.append(
                {
                    "rule_key": rk,
                    "enabled": rk not in disabled,
                    "supported": supported,  # observed records exist for this rule
                }
            )

        providers_out.append(
            {
                "provider": provider,
                "connected": bool(integs),
                "integration_id": integration_id,
                "integration_status": integration_status,
                "last_synced_at": last_synced_at,
                "coverage_status": status,
                "monitored_surfaces": PROVIDER_SURFACES.get(provider, []),
                "observed_record_types": sorted(observed),
                "expected_record_types": sorted(expected),
                "missing_record_types": missing,
                "active_rules": active_count,
                "disabled_rules": disabled_count,
                "supported_rules": supported_total,
                "recommendation": _recommendation(status),
                "rules": rules_out,
            }
        )

    return {"providers": providers_out, "summary": summary}
