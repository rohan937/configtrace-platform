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
    "azure",
    "google_cloud",
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
    # GitHub rulesets (M69.5A)
    "github_ruleset_not_enforced": ("github_ruleset",),
    "github_ruleset_force_push_allowed": ("github_ruleset",),
    "github_ruleset_pr_review_missing": ("github_ruleset",),
    "github_ruleset_status_checks_missing": ("github_ruleset",),
    "github_ruleset_bypass_actors_present": ("github_ruleset",),
    "github_ruleset_weak_target_coverage": ("github_ruleset",),
    # GitHub automation permissions (M69.5B)
    "github_automation_admin_permission": ("github_automation_permissions",),
    "github_automation_write_permission": ("github_automation_permissions",),
    "github_token_broad_scopes": ("github_automation_permissions",),
    "github_webhook_secret_missing": ("github_webhook",),
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
    "supabase_public_select_sensitive_table": ("supabase_rls_status",),
    "supabase_public_write_policy": ("supabase_rls_status",),
    "supabase_edge_function_jwt_disabled": ("supabase_edge_function",),
    "supabase_auth_protection_missing": ("supabase_auth_config",),
    # Firebase
    "firebase_rules_public": ("firebase_firestore_ruleset",),
    "firebase_storage_rules_public": ("firebase_storage_ruleset",),
    "firebase_anonymous_auth_enabled": ("firebase_auth_config",),
    # Firebase — M72A
    "firebase_database_public_read": ("firebase_database_ruleset",),
    "firebase_database_public_write": ("firebase_database_ruleset",),
    "firebase_auth_protection_missing": ("firebase_auth_config",),
    # Stripe
    "stripe_webhook_http": ("stripe_webhook_endpoint",),
    # Stripe — M73A
    "stripe_webhook_disabled": ("stripe_webhook_endpoint",),
    "stripe_webhook_broad_events": ("stripe_webhook_endpoint",),
    "stripe_payment_link_tax_disabled": ("stripe_payment_link",),
    "stripe_payment_link_promo_codes_enabled": ("stripe_payment_link",),
    "stripe_portal_subscription_cancel_enabled": ("stripe_billing_portal_config",),
    "stripe_portal_login_enabled": ("stripe_billing_portal_config",),
    "stripe_account_capability_incomplete": ("stripe_account_settings",),
    # Vercel
    "vercel_preview_unprotected": ("vercel_deployment_protection",),
    "vercel_production_branch_missing": ("vercel_project",),
    "vercel_production_branch_unusual": ("vercel_project",),
    "vercel_domain_unverified": ("vercel_domain",),
    "vercel_env_var_broad_target": ("vercel_env_var",),
    "vercel_sensitive_env_var_broad_scope": ("vercel_env_var",),
    "vercel_deploy_hook_production_branch": ("vercel_deploy_hook_metadata",),
    # Shopify
    "shopify_webhook_http": ("shopify_webhook_subscription",),
    # Shopify — M74A
    "shopify_webhook_high_risk_topic": ("shopify_webhook_subscription",),
    "shopify_app_broad_write_scopes": ("shopify_app_scope_summary",),
    "shopify_app_customer_data_scope": ("shopify_app_scope_summary",),
    "shopify_domain_ssl_missing": ("shopify_domain",),
    "shopify_domain_unverified": ("shopify_domain",),
    "shopify_policy_missing": ("shopify_store_policy",),
    # Azure — M77B
    "azure_nsg_public_admin_ingress": ("azure_network_security_group",),
    "azure_nsg_public_broad_ingress": ("azure_network_security_group",),
    "azure_storage_public_blob_access": ("azure_storage_account",),
    "azure_storage_public_network_access": ("azure_storage_account",),
    "azure_storage_weak_tls": ("azure_storage_account",),
    "azure_storage_shared_key_enabled": ("azure_storage_account",),
    "azure_key_vault_public_network_access": ("azure_key_vault",),
    "azure_key_vault_purge_protection_disabled": ("azure_key_vault",),
    "azure_key_vault_soft_delete_disabled": ("azure_key_vault",),
    "azure_key_vault_rbac_disabled": ("azure_key_vault",),
    # Azure — M77C
    "azure_role_assignment_broad_privilege": ("azure_role_assignment",),
    "azure_app_service_https_disabled": ("azure_app_service",),
    "azure_app_service_ftp_enabled": ("azure_app_service",),
    "azure_app_service_weak_tls": ("azure_app_service",),
    "azure_app_service_public_network_access": ("azure_app_service",),
    "azure_sql_public_network_access": ("azure_sql_server",),
    "azure_sql_weak_tls": ("azure_sql_server",),
    "azure_aks_local_accounts_enabled": ("azure_aks_cluster",),
    "azure_aks_public_api_access": ("azure_aks_cluster",),
    "azure_aks_network_policy_missing": ("azure_aks_cluster",),
}

# Friendly, human surfaces per provider for display (no internal jargon).
PROVIDER_SURFACES: dict[str, list[str]] = {
    "github": ["Webhooks", "Branch protection", "Deploy keys", "Environment protection"],
    "aws": ["Security group rules", "S3 buckets", "IAM policy attachments", "IAM access keys"],
    "cloudflare": ["Zone settings", "WAF rules", "DNS records"],
    "supabase": ["Row-level security", "Public table policies", "Auth configuration", "Edge Functions"],
    "firebase": ["Firestore rules", "Realtime Database rules", "Storage rules", "Auth configuration"],
    "stripe": ["Webhook endpoints", "Payment links", "Customer portal", "Account configuration"],
    "vercel": ["Deployment protection", "Production branch", "Domains", "Environment variables", "Deploy hooks"],
    "shopify": ["Webhook subscriptions", "App scopes", "Domains", "Store policies"],
    "azure": [
        "Network security groups",
        "Storage accounts",
        "Key Vaults",
        "Identity / Role assignments",
        "App Service / Functions",
        "SQL Servers",
        "AKS Clusters",
    ],
    "google_cloud": [
        "Project metadata",
        "IAM policy bindings",
        "VPC networks",
        "VPC firewall rules",
        "Cloud Storage buckets",
    ],
}


# ── M62.8 diagnostics ────────────────────────────────────────────────────────
#
# Per record_type, a careful human message + any provider permission hints to
# show when ConfigTrace has NOT observed that metadata. These are diagnostics
# (help users understand/fix coverage gaps), never findings, and never claim a
# provider is misconfigured — wording stays in "may need / could indicate /
# ConfigTrace has not observed / check provider permissions".
RECORD_TYPE_DIAGNOSTICS: dict[str, dict[str, Any]] = {
    # GitHub
    "github_branch_protection": {
        "message": "ConfigTrace has not observed default-branch protection metadata.",
        "hints": ["Check that the GitHub App has repository administration/metadata access where required."],
    },
    "github_webhook": {
        "message": "Webhook metadata was not observed for this repository/resource.",
        "hints": [],
    },
    "github_deploy_key": {
        "message": "Deploy key metadata may require repository-level access.",
        "hints": [],
    },
    "github_environment_protection": {
        "message": "Environment protection metadata may require repository-level access.",
        "hints": [],
    },
    # AWS
    "aws_security_group_rule": {
        "message": "EC2 security group rule metadata was not observed.",
        "hints": ["ec2:DescribeSecurityGroups"],
    },
    "aws_s3_bucket": {
        "message": "S3 bucket public-access metadata was not observed.",
        "hints": ["s3:GetBucketPolicyStatus", "s3:GetBucketAcl", "s3:GetPublicAccessBlock"],
    },
    "aws_iam_policy_attachment": {
        "message": "IAM policy attachment metadata was not observed.",
        "hints": ["iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies"],
    },
    "aws_iam_access_key": {
        "message": "IAM access key metadata was not observed.",
        "hints": ["iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"],
    },
    # Cloudflare
    "cloudflare_zone_setting": {
        "message": "Zone setting metadata was not observed.",
        "hints": ["Zone settings read access"],
    },
    "cloudflare_waf_rule": {
        "message": "WAF rule metadata was not observed.",
        "hints": ["WAF / rulesets read access"],
    },
    "A": {"message": "DNS A record metadata was not observed.", "hints": []},
    "AAAA": {"message": "DNS AAAA record metadata was not observed.", "hints": []},
    # Supabase
    "supabase_rls_status": {
        "message": "Table RLS metadata was not observed.",
        "hints": [],
    },
    "supabase_auth_config": {
        "message": "Auth configuration metadata was not observed.",
        "hints": [],
    },
    # Firebase
    "firebase_firestore_ruleset": {
        "message": "Firestore ruleset metadata was not observed.",
        "hints": [],
    },
    "firebase_database_ruleset": {
        "message": "Realtime Database ruleset metadata was not observed.",
        "hints": ["A Realtime Database instance + rules read access are required."],
    },
    "firebase_storage_ruleset": {
        "message": "Storage ruleset metadata was not observed.",
        "hints": [],
    },
    "firebase_auth_config": {
        "message": "Auth configuration metadata was not observed.",
        "hints": [],
    },
    # Stripe
    "stripe_webhook_endpoint": {
        "message": "Webhook endpoint metadata was not observed.",
        "hints": ["Verify the API key can list webhook endpoints."],
    },
    "stripe_payment_link": {
        "message": "Payment link metadata was not observed.",
        "hints": ["Verify the API key has read access to Payment Links."],
    },
    "stripe_billing_portal_config": {
        "message": "Customer portal configuration metadata was not observed.",
        "hints": ["Verify the API key has read access to Billing Portal configurations."],
    },
    "stripe_account_settings": {
        "message": "Account settings metadata was not observed.",
        "hints": ["A restricted key without the Account permission cannot read account settings."],
    },
    # Vercel
    "vercel_deployment_protection": {
        "message": "Deployment protection metadata was not observed.",
        "hints": ["Verify project/team API access."],
    },
    # Shopify
    "shopify_app_scope_summary": {
        "message": "App scope summary metadata was not observed.",
        "hints": ["Verify the access token can read /admin/oauth/access_scopes.json."],
    },
    "shopify_domain": {
        "message": "Shop domain metadata was not observed.",
        "hints": ["Verify the access token can read /admin/api/{ver}/shop/domains.json."],
    },
    "shopify_store_policy": {
        "message": "Store policy metadata was not observed.",
        "hints": ["Verify the access token can read /admin/api/{ver}/policies.json."],
    },
    "shopify_webhook_subscription": {
        "message": "Webhook subscription metadata was not observed.",
        "hints": ["Verify the app/admin API can read webhook subscriptions."],
    },
}

# Provider-level permission hints appended once when any surface is missing.
PROVIDER_PERMISSION_HINT: dict[str, str] = {
    "supabase": "Verify the project credentials/API access used by the connector.",
    "firebase": "Verify Firebase project credentials and ruleset/auth read access.",
}


def _diagnose(
    provider: str,
    *,
    connected: bool,
    integration_status: Optional[str],
    last_synced_at: Any,
    expected: set[str],
    observed: set[str],
) -> dict[str, Any]:
    """Read-only diagnosis of why coverage may be limited. No provider calls."""
    ok_payload = {
        "diagnostic_status": "ok",
        "diagnostic_messages": ["Coverage data looks sufficient for currently supported rules."],
        "recommended_actions": [],
        "permission_hints": [],
        "docs_hint": None,
        "diagnostic_confidence": "high",
    }

    if not connected:
        return {
            "diagnostic_status": "provider_not_connected",
            "diagnostic_messages": ["ConfigTrace has no active connection for this provider."],
            "recommended_actions": ["Connect this provider to collect security metadata."],
            "permission_hints": [],
            "docs_hint": None,
            "diagnostic_confidence": "high",
        }

    if integration_status in ("needs_reconnect", "error"):
        return {
            "diagnostic_status": "provider_attention_needed",
            "diagnostic_messages": [
                "This provider connection may need attention; recent syncs could indicate incomplete access.",
            ],
            "recommended_actions": ["Reconnect the provider or check its credentials, then run a sync."],
            "permission_hints": [],
            "docs_hint": None,
            "diagnostic_confidence": "high",
        }

    if last_synced_at is None:
        return {
            "diagnostic_status": "needs_sync",
            "diagnostic_messages": [
                "ConfigTrace has not yet synced this provider, so no metadata has been observed.",
            ],
            "recommended_actions": ["Run a sync to collect provider metadata."],
            "permission_hints": [],
            "docs_hint": None,
            "diagnostic_confidence": "high",
        }

    if not expected:
        return ok_payload

    observed_expected = expected & observed
    missing = sorted(expected - observed)

    if not missing:
        return ok_payload

    messages: list[str] = []
    actions: list[str] = []
    hints: list[str] = []

    if not observed_expected:
        status = "permissions_likely_limited"
        messages.append(
            "ConfigTrace has not observed expected security metadata for this provider after syncing."
        )
        messages.append(
            "This could indicate limited permissions, unavailable provider APIs, or provider setup gaps."
        )
        actions.append("Check provider permissions, then re-run a sync.")
    else:
        status = "missing_metadata"
        messages.append(
            "ConfigTrace has observed some provider metadata, but not all expected surfaces."
        )
        actions.append("Re-run a sync, and check provider permissions for the missing surfaces.")

    # Per-missing-surface messages + permission hints (deterministic order).
    for rt in missing:
        diag = RECORD_TYPE_DIAGNOSTICS.get(rt)
        if not diag:
            continue
        msg = diag.get("message")
        if msg and msg not in messages:
            messages.append(msg)
        for h in diag.get("hints", []):
            if h not in hints:
                hints.append(h)

    prov_hint = PROVIDER_PERMISSION_HINT.get(provider)
    if prov_hint and prov_hint not in hints:
        hints.append(prov_hint)

    actions.append("Review which rules apply on the Security Rules page.")

    # AWS account structures may intentionally omit services — keep the
    # diagnostic conservative (lower confidence, explicit caveat).
    if provider == "aws":
        messages.append(
            "AWS account structure may intentionally omit some services, so missing surfaces are not always a permission gap."
        )
        confidence = "low"
    else:
        confidence = "medium"

    return {
        "diagnostic_status": status,
        "diagnostic_messages": messages,
        "recommended_actions": actions,
        "permission_hints": hints,
        "docs_hint": None,
        "diagnostic_confidence": confidence,
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
        "diagnostics_ok": 0,
        "diagnostics_needs_sync": 0,
        "diagnostics_missing_metadata": 0,
        "diagnostics_permissions_likely_limited": 0,
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

        # M62.8 — permission diagnostics (read-only; inspects only the data
        # already gathered above, never calls a provider).
        diag = _diagnose(
            provider,
            connected=bool(integs),
            integration_status=integration_status,
            last_synced_at=last_synced_at,
            expected=expected,
            observed=observed,
        )
        if diag["diagnostic_status"] == "ok":
            summary["diagnostics_ok"] += 1
        elif diag["diagnostic_status"] == "needs_sync":
            summary["diagnostics_needs_sync"] += 1
        elif diag["diagnostic_status"] == "missing_metadata":
            summary["diagnostics_missing_metadata"] += 1
        elif diag["diagnostic_status"] == "permissions_likely_limited":
            summary["diagnostics_permissions_likely_limited"] += 1

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
                "diagnostic_status": diag["diagnostic_status"],
                "diagnostic_messages": diag["diagnostic_messages"],
                "recommended_actions": diag["recommended_actions"],
                "permission_hints": diag["permission_hints"],
                "docs_hint": diag["docs_hint"],
                "diagnostic_confidence": diag["diagnostic_confidence"],
            }
        )

    return {"providers": providers_out, "summary": summary}
