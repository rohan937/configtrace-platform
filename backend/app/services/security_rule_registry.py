"""Security rule registry — M61.7.

Authoritative set of implemented security-rule keys (the prefix of a
``finding_key``, which is shaped ``rule_key:record_identifier``). Used by the
rule enable/disable settings to validate rule keys and by the evaluator to map a
finding back to its base rule.

Keep this in sync with the rule constants in ``app/services/security_rules/*``.
This is metadata only — it never evaluates provider state.
"""

from __future__ import annotations

# Exact rule keys emitted by app/services/security_rules/*.py (verified M61.7).
KNOWN_RULE_KEYS: frozenset[str] = frozenset(
    {
        # GitHub
        "github_webhook_http",
        "github_branch_protection_missing",
        "github_force_pushes_allowed",
        "github_branch_deletion_allowed",
        "github_pr_review_not_required",
        "github_status_checks_not_required",
        "github_deploy_key_write_access",
        "github_env_protection_missing",
        # GitHub rulesets (M69.5A)
        "github_ruleset_not_enforced",
        "github_ruleset_force_push_allowed",
        "github_ruleset_pr_review_missing",
        "github_ruleset_status_checks_missing",
        "github_ruleset_bypass_actors_present",
        "github_ruleset_weak_target_coverage",
        # GitHub automation permissions (M69.5B)
        "github_automation_admin_permission",
        "github_automation_write_permission",
        "github_token_broad_scopes",
        "github_webhook_secret_missing",
        # AWS
        "aws_public_admin_port",
        "aws_public_database_port",
        "aws_public_all_ports",
        "aws_s3_public_policy",
        "aws_s3_public_acl",
        "aws_iam_admin_policy_attached",
        "aws_access_key_unused",
        # Cloudflare
        "cloudflare_ssl_mode_weak",
        "cloudflare_always_https_off",
        "cloudflare_min_tls_weak",
        "cloudflare_security_level_low",
        "cloudflare_development_mode_on",
        "cloudflare_hsts_disabled",
        "cloudflare_waf_rule_disabled",
        "cloudflare_dns_private_origin",
        # Supabase
        "supabase_rls_disabled",
        "supabase_anonymous_access_enabled",
        "supabase_jwt_expiry_long",
        "supabase_public_select_sensitive_table",
        "supabase_public_write_policy",
        "supabase_edge_function_jwt_disabled",
        "supabase_auth_protection_missing",
        # Firebase
        "firebase_rules_public",
        "firebase_storage_rules_public",
        "firebase_anonymous_auth_enabled",
        # Firebase — M72A (Realtime Database rules + auth hardening)
        "firebase_database_public_read",
        "firebase_database_public_write",
        "firebase_auth_protection_missing",
        # Stripe
        "stripe_webhook_http",
        # Stripe — M73A (webhook posture + payment links + portal + account)
        "stripe_webhook_disabled",
        "stripe_webhook_broad_events",
        "stripe_payment_link_tax_disabled",
        "stripe_payment_link_promo_codes_enabled",
        "stripe_portal_subscription_cancel_enabled",
        "stripe_portal_login_enabled",
        "stripe_account_capability_incomplete",
        # Vercel
        "vercel_preview_unprotected",
        "vercel_production_branch_missing",
        "vercel_production_branch_unusual",
        "vercel_domain_unverified",
        "vercel_env_var_broad_target",
        "vercel_sensitive_env_var_broad_scope",
        "vercel_deploy_hook_production_branch",
        # Shopify
        "shopify_webhook_http",
    }
)


def is_known_rule_key(rule_key: str) -> bool:
    """True when *rule_key* is an implemented security rule."""
    return rule_key in KNOWN_RULE_KEYS


def base_rule_key(finding_key: str) -> str:
    """Return the rule key portion of a ``finding_key`` (``rule_key:record_id``).

    If there is no colon, the whole string is treated as the rule key.
    """
    if not finding_key:
        return finding_key
    idx = finding_key.find(":")
    return finding_key if idx < 0 else finding_key[:idx]
