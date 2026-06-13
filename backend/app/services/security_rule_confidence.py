"""Security rule confidence registry — M62.4.

Per-rule confidence metadata used to make findings more trustworthy and
explainable. Confidence describes HOW the rule reached its conclusion, not how
severe the issue is (severity stays the routing/priority signal):

  * high   — backed by a direct normalized field that clearly indicates the
             risky state.
  * medium — backed by strong provider metadata, but may depend on environment
             context.
  * low    — inferred from limited/ambiguous signals; such rules are deferred
             and do NOT emit active findings (none of the implemented rules are
             low).

The ``false_positive_guard`` text mirrors the conservative guard already shown
in the frontend Security Rules catalog, so the same explanation is consistent
across the rules catalog and individual finding detail.

This is metadata only — it never claims a confirmed exploit/breach.
"""

from __future__ import annotations

from app.services.security_rule_registry import KNOWN_RULE_KEYS, base_rule_key

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

VALID_CONFIDENCE = frozenset({HIGH, MEDIUM, LOW})

_REASON = {
    HIGH: "Backed by a direct normalized field that clearly indicates the risky state.",
    MEDIUM: "Backed by strong provider metadata, but may depend on environment context.",
    LOW: "Inferred from limited or ambiguous signals; treated conservatively.",
}

# rule_key → (confidence, false_positive_guard). Confidence values mirror the
# frontend securityRuleCatalog; every implemented rule is high or medium.
RULE_CONFIDENCE: dict[str, tuple[str, str]] = {
    # GitHub
    "github_webhook_http": (HIGH, "Only fires for active webhooks whose URL begins with http://."),
    "github_branch_protection_missing": (HIGH, "Only the default branch is evaluated; a permission error aborts before this fires."),
    "github_force_pushes_allowed": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_branch_deletion_allowed": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_pr_review_not_required": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_status_checks_not_required": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_deploy_key_write_access": (HIGH, "A missing read_only flag defaults to read-only (safe); partial records are ignored."),
    "github_env_protection_missing": (HIGH, "Narrowly scoped to environments explicitly named production/prod."),
    # GitHub rulesets (M69.5A)
    "github_ruleset_not_enforced": (HIGH, "Reads the ruleset's enforcement field directly; only fires when it is not 'active'."),
    "github_ruleset_force_push_allowed": (HIGH, "Only fires for active branch rulesets that lack a non-fast-forward (block force push) rule."),
    "github_ruleset_pr_review_missing": (MEDIUM, "Depends on the protected-branch target heuristic; only active branch rulesets are evaluated."),
    "github_ruleset_status_checks_missing": (MEDIUM, "Depends on the protected-branch target heuristic; only active branch rulesets are evaluated."),
    "github_ruleset_bypass_actors_present": (HIGH, "Reads the bypass-actor count directly; counts only, never identities."),
    "github_ruleset_weak_target_coverage": (MEDIUM, "Based on a default-branch coverage heuristic; conservative and may under-report."),
    # GitHub automation permissions (M69.5B)
    "github_automation_admin_permission": (HIGH, "Reads the authenticated credential's repository permission object directly."),
    "github_automation_write_permission": (HIGH, "Reads the authenticated credential's repository permission object directly."),
    "github_token_broad_scopes": (MEDIUM, "Classic-PAT scopes only (from X-OAuth-Scopes); fine-grained tokens/Apps expose no scopes, so it may under-report."),
    "github_webhook_secret_missing": (HIGH, "GitHub reliably masks a configured secret and omits the field when none is set."),
    # AWS
    "aws_public_admin_port": (HIGH, "Only 0.0.0.0/0 or ::/0 count as public; reachability is not claimed."),
    "aws_public_database_port": (HIGH, "Only canonical 'any' CIDRs count as public."),
    "aws_public_all_ports": (HIGH, "Only canonical 'any' CIDRs count as public."),
    "aws_s3_public_policy": (HIGH, "Only an explicit public flag fires; an unknown state is never treated as public."),
    "aws_s3_public_acl": (HIGH, "Only an explicit public grant fires; an unknown state is never treated as public."),
    "aws_iam_admin_policy_attached": (HIGH, "Exact AdministratorAccess ARN match, not a keyword guess."),
    "aws_access_key_unused": (HIGH, "An unknown last-used age (never-used vs fetch-failed) is not flagged."),
    # Cloudflare
    "cloudflare_ssl_mode_weak": (HIGH, "Only off/flexible fire; full/strict are treated as safe."),
    "cloudflare_always_https_off": (HIGH, "Only fires when the value is explicitly 'off'."),
    "cloudflare_min_tls_weak": (HIGH, "Only TLS 1.0/1.1 fire."),
    "cloudflare_security_level_low": (HIGH, "Only off/essentially_off fire; low/medium/high are treated as normal."),
    "cloudflare_development_mode_on": (HIGH, "Only fires when development mode is explicitly 'on'."),
    "cloudflare_hsts_disabled": (HIGH, "Only an explicit enabled=false fires; indeterminate values are skipped."),
    "cloudflare_waf_rule_disabled": (HIGH, "Disabled log/skip rules are ignored — only protective actions fire."),
    "cloudflare_dns_private_origin": (HIGH, "Public/global IPs are normal and never flagged; non-IP content is ignored."),
    # Supabase
    "supabase_rls_disabled": (HIGH, "Only an explicit rls_enabled=false fires; missing/unknown is skipped."),
    "supabase_anonymous_access_enabled": (MEDIUM, "Anonymous auth is a feature; risky mainly with weak RLS, so wording stays careful."),
    "supabase_jwt_expiry_long": (HIGH, "Only a concrete value over the threshold fires; unknown values are skipped."),
    # Firebase
    "firebase_rules_public": (MEDIUM, "Low-confidence ruleset parses are skipped to avoid false positives."),
    "firebase_storage_rules_public": (MEDIUM, "Low-confidence ruleset parses are skipped to avoid false positives."),
    "firebase_anonymous_auth_enabled": (MEDIUM, "Risky mainly when paired with permissive rules; reported at medium severity."),
    # Stripe
    "stripe_webhook_http": (HIGH, "Only an explicit http scheme fires; disabled endpoints are not flagged."),
    # Vercel
    "vercel_preview_unprotected": (MEDIUM, "Only fires when every protection mechanism is off; previews are not production data."),
    "vercel_production_branch_missing": (MEDIUM, "Only fires when a git repository is connected but no production branch is configured."),
    "vercel_production_branch_unusual": (MEDIUM, "Only fires when the production branch matches a known non-production name; main/master/prod are treated as normal."),
    "vercel_domain_unverified": (MEDIUM, "Only an explicit verified=false fires; verified or unknown domains are skipped."),
    "vercel_env_var_broad_target": (MEDIUM, "Only fires when one variable spans production and a non-production environment."),
    "vercel_sensitive_env_var_broad_scope": (HIGH, "Only fires when a secret-suggestive key name is also scoped to a non-production environment; the value is never read."),
    "vercel_deploy_hook_production_branch": (MEDIUM, "Only fires when a deploy hook's target ref is the production branch; the hook URL is never stored."),
    # Shopify
    "shopify_webhook_http": (HIGH, "Only an explicit http scheme fires; non-HTTP transports are ignored."),
}


def confidence_for(finding_key: str) -> tuple[str, str, str]:
    """Return (confidence, confidence_reason, false_positive_guard) for a finding.

    Looks up the base rule key. Unknown keys default to high confidence with a
    generic reason and no guard (preserves existing behavior — never suppresses).
    """
    rule_key = base_rule_key(finding_key)
    confidence, guard = RULE_CONFIDENCE.get(rule_key, (HIGH, ""))
    return confidence, _REASON.get(confidence, _REASON[HIGH]), guard


# Sanity: every known rule has a confidence entry, and none is low.
def _self_check() -> None:  # pragma: no cover - import-time guard
    missing = KNOWN_RULE_KEYS - set(RULE_CONFIDENCE)
    assert not missing, f"rules missing confidence: {sorted(missing)}"
    assert all(c in (HIGH, MEDIUM) for c, _ in RULE_CONFIDENCE.values())


_self_check()
