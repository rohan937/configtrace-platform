"""Security Exposure rule pack / versioning registry (M63.3).

Lightweight, static traceability layer over the existing rule registries. It
answers: "which rule pack + version is active, and which version produced this
finding?" — without adding rules, a marketplace, or a rule editor.

Sources of truth it aligns with (never duplicated logic):
  * security_rule_registry.KNOWN_RULE_KEYS  — the implemented rule keys
  * security_rule_confidence.confidence_for — per-rule confidence
  * provider/severity/category mirror the frontend securityRuleCatalog

This is the first versioned pack, so every rule shares the baseline
``rule_version`` and ``introduced_in``. Bump SECURITY_RULE_PACK_VERSION (and the
relevant per-rule entries) when the pack changes.
"""

from __future__ import annotations

from typing import Any

from app.services.security_rule_confidence import confidence_for
from app.services.security_rule_registry import KNOWN_RULE_KEYS, base_rule_key

SECURITY_RULE_PACK_NAME = "configtrace_security_exposure"
SECURITY_RULE_PACK_VERSION = "2026.06"
SECURITY_RULE_PACK_RELEASED_AT = "2026-06-08"
SECURITY_RULE_PACK_DESCRIPTION = (
    "ConfigTrace Security Exposure rule pack — metadata-only configuration "
    "exposure checks across connected cloud and SaaS providers. Rules evaluate "
    "provider configuration, never payloads or secrets."
)

# Baselines for the first versioned pack. Per-rule overrides can be added later.
DEFAULT_RULE_VERSION = "1.0"
DEFAULT_INTRODUCED_IN = SECURITY_RULE_PACK_VERSION

# rule_key → (provider, severity, category). Mirrors the frontend catalog so the
# pack manifest is self-describing on the backend. Severity is the rule's
# headline (worst-case) severity.
_RULE_META: dict[str, tuple[str, str, str]] = {
    # GitHub
    "github_webhook_http": ("github", "critical", "Webhooks"),
    "github_branch_protection_missing": ("github", "high", "Branch protection"),
    "github_force_pushes_allowed": ("github", "high", "Branch protection"),
    "github_branch_deletion_allowed": ("github", "high", "Branch protection"),
    "github_pr_review_not_required": ("github", "high", "Branch protection"),
    "github_status_checks_not_required": ("github", "medium", "Branch protection"),
    "github_deploy_key_write_access": ("github", "high", "Deploy keys"),
    "github_env_protection_missing": ("github", "medium", "Environment protection"),
    # AWS
    "aws_public_admin_port": ("aws", "high", "Security groups"),
    "aws_public_database_port": ("aws", "critical", "Security groups"),
    "aws_public_all_ports": ("aws", "critical", "Security groups"),
    "aws_s3_public_policy": ("aws", "critical", "S3 public access"),
    "aws_s3_public_acl": ("aws", "critical", "S3 public access"),
    "aws_iam_admin_policy_attached": ("aws", "high", "IAM"),
    "aws_access_key_unused": ("aws", "medium", "IAM access keys"),
    # Cloudflare
    "cloudflare_ssl_mode_weak": ("cloudflare", "high", "SSL/TLS"),
    "cloudflare_always_https_off": ("cloudflare", "medium", "HTTPS"),
    "cloudflare_min_tls_weak": ("cloudflare", "medium", "SSL/TLS"),
    "cloudflare_security_level_low": ("cloudflare", "medium", "WAF / security"),
    "cloudflare_development_mode_on": ("cloudflare", "medium", "WAF / security"),
    "cloudflare_hsts_disabled": ("cloudflare", "medium", "HTTPS"),
    "cloudflare_waf_rule_disabled": ("cloudflare", "high", "WAF / security"),
    "cloudflare_dns_private_origin": ("cloudflare", "high", "DNS"),
    # Supabase
    "supabase_rls_disabled": ("supabase", "high", "RLS"),
    "supabase_anonymous_access_enabled": ("supabase", "medium", "Auth"),
    "supabase_jwt_expiry_long": ("supabase", "medium", "Auth"),
    # Firebase
    "firebase_rules_public": ("firebase", "critical", "Security rules"),
    "firebase_storage_rules_public": ("firebase", "critical", "Security rules"),
    "firebase_anonymous_auth_enabled": ("firebase", "medium", "Auth"),
    # Stripe
    "stripe_webhook_http": ("stripe", "critical", "Webhooks"),
    # Vercel
    "vercel_preview_unprotected": ("vercel", "medium", "Deployment protection"),
    # Shopify
    "shopify_webhook_http": ("shopify", "critical", "Webhooks"),
}


def rule_version_for(finding_key: str) -> str:
    """Return the rule_version for a finding/rule key (baseline for this pack)."""
    rule_key = base_rule_key(finding_key)
    # Per-rule overrides could live here later; for now every known rule shares
    # the baseline. Unknown keys still get the baseline (null-safe, never raises).
    _ = rule_key
    return DEFAULT_RULE_VERSION


def pack_metadata_for(finding_key: str) -> tuple[str, str, str]:
    """Return (rule_pack_name, rule_pack_version, rule_version) for a finding."""
    return (
        SECURITY_RULE_PACK_NAME,
        SECURITY_RULE_PACK_VERSION,
        rule_version_for(finding_key),
    )


def list_pack_rules() -> list[dict[str, Any]]:
    """Per-rule manifest for the pack endpoint (sorted, deterministic)."""
    out: list[dict[str, Any]] = []
    for rule_key in sorted(_RULE_META):
        provider, severity, category = _RULE_META[rule_key]
        confidence, _reason, _guard = confidence_for(rule_key)
        out.append(
            {
                "rule_key": rule_key,
                "provider": provider,
                "rule_version": DEFAULT_RULE_VERSION,
                "introduced_in": DEFAULT_INTRODUCED_IN,
                "status": "active",
                "confidence": confidence,
                "severity": severity,
                "category": category,
            }
        )
    return out


def pack_summary() -> dict[str, Any]:
    """Full rule pack descriptor for GET /security/rules/pack."""
    rules = list_pack_rules()
    providers = sorted({r["provider"] for r in rules})
    return {
        "name": SECURITY_RULE_PACK_NAME,
        "version": SECURITY_RULE_PACK_VERSION,
        "released_at": SECURITY_RULE_PACK_RELEASED_AT,
        "description": SECURITY_RULE_PACK_DESCRIPTION,
        "rule_count": len(rules),
        "providers": providers,
        "rules": rules,
    }


# Sanity: the manifest must cover exactly the implemented rule keys. Surfacing a
# drift early (import-time) is cheaper than a silently incomplete pack.
assert set(_RULE_META) == set(KNOWN_RULE_KEYS), (
    "security_rule_pack._RULE_META is out of sync with KNOWN_RULE_KEYS: "
    f"missing={set(KNOWN_RULE_KEYS) - set(_RULE_META)}, "
    f"extra={set(_RULE_META) - set(KNOWN_RULE_KEYS)}"
)
