"""Policy engine service — M58.14.

Deterministic, metadata-only policy evaluation.
Policies classify configuration changes; they never mutate providers.

Architecture:
  - BUILT_IN_POLICIES: static catalog of 18 built-in policy definitions.
  - evaluate_change(): matches a Change against all enabled policies and
    returns PolicyViolation objects.
  - compute_violations(): main entry point — resolves workspace, loads
    enabled overrides, evaluates, returns PolicyViolationsResponse.
  - get_workspace_policies(): returns catalog merged with workspace overrides.
  - set_policy_enabled(): upserts a workspace-level enable/disable override.

Safety rules (permanent):
  - No provider API calls.
  - No provider mutations.
  - Evidence strings are always pre-defined facts derived from record_type /
    field_path / change_type / risk_reason.  Raw prev_value / new_value string
    content is NEVER forwarded into evidence or descriptions.
  - prev_value / new_value may be checked as booleans/presence only.
  - Language: "may indicate", "appears", "detected in metadata" — never
    "confirmed breach", "guaranteed", "publicly reachable".
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.schemas.policy import (
    PolicyListResponse,
    PolicyUpdateRequest,
    PolicyViolation,
    PolicyViolationsResponse,
    WorkspacePolicyResponse,
)


# ── Internal catalog type ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class _PolicyDef:
    key: str
    name: str
    description: str
    provider: Optional[str]
    severity: str   # "critical" | "high" | "medium"
    category: str
    enabled_by_default: bool
    recommended_action: str
    # matcher(change) → list[str] | None
    # Returns evidence strings if violated, None if not violated.
    matcher: Callable  # type: ignore[type-arg]


# ── Matcher helpers ───────────────────────────────────────────────────────────


def _kw(text: Optional[str], *keywords: str) -> bool:
    """Case-insensitive ALL-keyword check on a string."""
    if not text:
        return False
    t = text.lower()
    return all(k.lower() in t for k in keywords)


def _any_kw(text: Optional[str], *keywords: str) -> bool:
    """Case-insensitive ANY-keyword check on a string."""
    if not text:
        return False
    t = text.lower()
    return any(k.lower() in t for k in keywords)


def _rt(change, prefix: str) -> bool:
    """True if record_type starts with prefix (case-insensitive)."""
    rt = ((change.provider_metadata or {}).get("record_type") or "").lower()
    return rt.startswith(prefix.lower())


def _rt_exact(change, value: str) -> bool:
    """True if record_type exactly equals value (case-insensitive)."""
    rt = ((change.provider_metadata or {}).get("record_type") or "").lower()
    return rt == value.lower()


def _fp(change, *keywords: str) -> bool:
    """True if field_path contains any of the keywords (case-insensitive)."""
    fp = (change.field_path or "").lower()
    return any(k.lower() in fp for k in keywords)


def _new_falsy(change) -> bool:
    """True if new_value is falsy (False, 0, None, empty string)."""
    nv = change.new_value
    if nv is None:
        return False  # missing value — don't infer
    if isinstance(nv, bool):
        return not nv
    if isinstance(nv, (int, float)):
        return nv == 0
    if isinstance(nv, str):
        return nv.lower() in ("false", "0", "disabled", "none", "")
    return False


def _new_truthy(change) -> bool:
    """True if new_value is truthy (True, non-zero, non-empty)."""
    nv = change.new_value
    if nv is None:
        return False
    if isinstance(nv, bool):
        return nv
    if isinstance(nv, (int, float)):
        return nv != 0
    if isinstance(nv, str):
        return nv.lower() in ("true", "1", "enabled")
    return False


# ── Per-policy matcher functions ──────────────────────────────────────────────

# AWS ─────────────────────────────────────────────────────────────────────────

def _match_aws_no_public_ssh(c) -> list[str] | None:
    if not _rt(c, "aws_security_group"):
        return None
    rr = c.risk_reason or ""
    has_public = _any_kw(rr, "0.0.0.0", "::/0")
    has_ssh = _any_kw(rr, "/22", "port 22", "ssh")
    if not (has_public and has_ssh):
        return None
    evidence: list[str] = ["Port 22 (SSH) detected in security group rule metadata"]
    if _kw(rr, "0.0.0.0"):
        evidence.append("Public IPv4 CIDR (0.0.0.0/0) detected")
    if _kw(rr, "::/0"):
        evidence.append("Public IPv6 CIDR (::/0) detected")
    return evidence


def _match_aws_no_public_rdp(c) -> list[str] | None:
    if not _rt(c, "aws_security_group"):
        return None
    rr = c.risk_reason or ""
    has_public = _any_kw(rr, "0.0.0.0", "::/0")
    has_rdp = _any_kw(rr, "/3389", "port 3389", "rdp")
    if not (has_public and has_rdp):
        return None
    evidence: list[str] = ["Port 3389 (RDP) detected in security group rule metadata"]
    if _kw(rr, "0.0.0.0"):
        evidence.append("Public IPv4 CIDR (0.0.0.0/0) detected")
    if _kw(rr, "::/0"):
        evidence.append("Public IPv6 CIDR (::/0) detected")
    return evidence


def _match_aws_cloudtrail_must_log(c) -> list[str] | None:
    if not _rt(c, "aws_cloudtrail"):
        return None
    rr = c.risk_reason or ""
    fp = (c.field_path or "").lower()
    if c.change_type == "removed":
        return ["CloudTrail trail was removed"]
    if _any_kw(rr, "disabled", "stopped", "logging disabled"):
        return ["CloudTrail logging appears to have been disabled or stopped"]
    if _any_kw(fp, "logging_enabled", "is_logging") and _new_falsy(c):
        return ["CloudTrail logging_enabled flag changed to false"]
    if _any_kw(rr, "cloudtrail", "logging") and c.risk_level in ("high", "critical"):
        return ["CloudTrail configuration change detected at high/critical risk level"]
    return None


def _match_aws_waf_must_remain_attached(c) -> list[str] | None:
    rr = c.risk_reason or ""
    is_waf_rt = _rt(c, "aws_waf") or _rt(c, "aws_wafv2")
    is_cf_waf = _rt(c, "aws_cloudfront") and _any_kw(rr, "waf")
    if not (is_waf_rt or is_cf_waf):
        return None
    if c.change_type == "removed":
        return ["WAF resource was removed"]
    if _any_kw(rr, "detached", "disabled", "removed", "weakened"):
        return ["WAF attachment or rule configuration appears to have been reduced or removed"]
    if c.risk_level in ("high", "critical"):
        return ["WAF configuration change detected at high/critical risk level"]
    return None


# Firebase ────────────────────────────────────────────────────────────────────

def _match_firebase_no_public_writes(c) -> list[str] | None:
    is_rules = _rt(c, "firebase_firestore_ruleset") or _rt(c, "firebase_storage")
    if not is_rules:
        return None
    rr = c.risk_reason or ""
    if _any_kw(rr, "public write", "allow write", "unauthenticated write"):
        return [
            "Firestore or Storage ruleset metadata indicates write access may be unrestricted",
            "Rule change detected at high or critical risk level",
        ]
    if c.risk_level in ("critical", "high") and c.change_type in ("modified", "added"):
        return ["Ruleset hash change detected at high/critical risk level — review write conditions"]
    return None


def _match_firebase_app_check_required(c) -> list[str] | None:
    if not _rt(c, "firebase_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "app_check", "enforcement") and _new_falsy(c):
        return ["Firebase App Check enforcement flag changed to disabled or unenforced"]
    if _any_kw(rr, "app check", "enforcement") and _any_kw(rr, "disabled", "off", "unenforced"):
        return ["Firebase App Check enforcement appears to have been reduced or disabled"]
    return None


# Supabase ────────────────────────────────────────────────────────────────────

def _match_supabase_rls_required(c) -> list[str] | None:
    if not _rt(c, "supabase_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "rls", "row_level_security", "row level security") and _new_falsy(c):
        return ["RLS enabled flag changed to false on a Supabase table"]
    if _any_kw(rr, "rls", "row level security") and _any_kw(rr, "disabled", "off", "false"):
        return ["Row Level Security appears to have been disabled on a Supabase table"]
    if _any_kw(rr, "rls") and c.risk_level in ("critical", "high"):
        return ["RLS configuration change detected at high/critical risk level"]
    return None


def _match_supabase_auth_security_required(c) -> list[str] | None:
    if not _rt(c, "supabase_auth"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "mfa", "totp") and _new_falsy(c):
        return ["MFA configuration appears to have been disabled or weakened"]
    if _any_kw(fp, "captcha", "hcaptcha", "turnstile") and _new_falsy(c):
        return ["CAPTCHA enforcement appears to have been disabled"]
    if _any_kw(fp, "password_strength", "leaked_password") and _new_falsy(c):
        return ["Password security configuration appears to have been weakened"]
    if _any_kw(fp, "refresh_token_rotation") and _new_falsy(c):
        return ["Refresh token rotation appears to have been disabled"]
    if _any_kw(rr, "security", "auth") and c.risk_level in ("critical", "high"):
        return ["Supabase Auth security configuration change detected at high/critical risk level"]
    return None


# GitHub ──────────────────────────────────────────────────────────────────────

def _match_github_required_reviewers(c) -> list[str] | None:
    if not _rt(c, "github_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "required_reviewer", "reviewers_count") and _new_falsy(c):
        return ["Required reviewer count was reduced to zero on a GitHub environment or branch"]
    if _any_kw(fp, "prevent_self_review") and _new_falsy(c):
        return ["Prevent-self-review was disabled on a GitHub environment"]
    if _any_kw(fp, "required_reviewer", "branch_protection", "protection") and \
            _any_kw(rr, "reviewer", "protection", "weakened", "disabled", "reduced"):
        return [
            "Branch or environment protection reviewer requirement appears to have been weakened",
            "Required reviewer count or protection setting changed",
        ]
    if _any_kw(rr, "reviewer", "required reviewer") and c.risk_level in ("high", "critical"):
        return ["GitHub protection change detected at high/critical risk level — review required reviewers"]
    return None


def _match_github_no_force_pushes(c) -> list[str] | None:
    if not _rt(c, "github_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "allow_force_push") and _new_truthy(c):
        return ["allow_force_pushes was enabled on a protected branch"]
    if _any_kw(rr, "force push", "allow_force_push") and _any_kw(rr, "enabled", "allowed", "true"):
        return ["Force pushes appear to have been enabled on a protected branch"]
    return None


# Cloudflare ──────────────────────────────────────────────────────────────────

def _match_cloudflare_waf_enabled(c) -> list[str] | None:
    rr = c.risk_reason or ""
    is_waf_rt = _rt(c, "cloudflare_ruleset") or _rt(c, "cloudflare_waf")
    is_waf_rr = _rt(c, "cloudflare_") and _any_kw(rr, "waf", "ruleset")
    if not (is_waf_rt or is_waf_rr):
        return None
    if c.change_type == "removed":
        return ["Cloudflare WAF ruleset was removed"]
    if _any_kw(rr, "disabled", "weakened", "reduced", "skip", "bypass"):
        return [
            "Cloudflare WAF rule coverage appears to have been reduced",
            "Block or challenge actions may have been changed to skip",
        ]
    if c.risk_level in ("high", "critical"):
        return ["Cloudflare WAF configuration change detected at high/critical risk level"]
    return None


def _match_cloudflare_https_required(c) -> list[str] | None:
    if not _rt(c, "cloudflare_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "ssl", "tls", "https", "always_use_https") and _new_falsy(c):
        return ["SSL/TLS or HTTPS enforcement appears to have been disabled or weakened"]
    if _any_kw(rr, "https", "ssl", "tls") and _any_kw(rr, "disabled", "off", "weakened"):
        return ["HTTPS or SSL/TLS enforcement appears to have been weakened"]
    return None


# Stripe ──────────────────────────────────────────────────────────────────────

def _match_stripe_webhooks_must_stay_enabled(c) -> list[str] | None:
    if not _rt(c, "stripe_webhook"):
        return None
    rr = c.risk_reason or ""
    fp = (c.field_path or "").lower()
    if c.change_type == "removed":
        return ["Stripe webhook endpoint was removed"]
    if _any_kw(fp, "enabled") and _new_falsy(c):
        return ["Stripe webhook endpoint was disabled"]
    if _any_kw(fp, "url", "endpoint") or _any_kw(rr, "url", "endpoint", "destination"):
        return [
            "Stripe webhook endpoint URL or destination was modified",
            "Payment event delivery may be affected if the change was unintended",
        ]
    if c.change_type == "modified" and c.risk_level in ("high", "critical"):
        return ["Stripe webhook configuration change detected at high/critical risk level"]
    return None


def _match_stripe_api_keys_least_privilege(c) -> list[str] | None:
    if not _rt(c, "stripe_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "permissions", "scope", "restricted") and \
            _any_kw(rr, "widened", "increased", "expanded", "broadened"):
        return ["Stripe API key permissions appear to have been broadened"]
    return None


# Vercel ──────────────────────────────────────────────────────────────────────

def _match_vercel_deployment_protection_required(c) -> list[str] | None:
    if not _rt(c, "vercel_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "password", "protection", "sso_protection", "trusted_ips") and _new_falsy(c):
        return ["Vercel deployment protection (password, SSO, or trusted IP) was disabled"]
    if _any_kw(rr, "protection", "deploy protection") and _any_kw(rr, "disabled", "off", "removed"):
        return ["Vercel deployment protection appears to have been disabled or reduced"]
    return None


def _match_vercel_production_branch_stable(c) -> list[str] | None:
    if not _rt(c, "vercel_"):
        return None
    fp = (c.field_path or "").lower()
    rr = c.risk_reason or ""
    if _any_kw(fp, "production_branch", "git_branch", "target_branch", "ref"):
        return [
            "Vercel production branch or deploy hook target ref was modified",
            "Future deployments may target a different branch",
        ]
    if _rt(c, "vercel_deploy_hook") and c.change_type in ("added", "modified"):
        return ["Vercel deploy hook was added or modified — confirm target branch is correct"]
    if _any_kw(rr, "production branch", "deploy hook", "target branch"):
        return ["Vercel branch or hook configuration change detected"]
    return None


# Shopify ─────────────────────────────────────────────────────────────────────

def _match_shopify_sensitive_scopes_review(c) -> list[str] | None:
    if not _rt(c, "shopify_"):
        return None
    rr = c.risk_reason or ""
    if _any_kw(rr, "scope", "write", "sensitive") and \
            c.change_type in ("added", "modified"):
        return [
            "Shopify app scope metadata indicates write-level or sensitive scopes were added",
            "App scope list change detected — review with app vendor before accepting",
        ]
    return None


def _match_shopify_webhooks_https_required(c) -> list[str] | None:
    if not _rt(c, "shopify_webhook"):
        return None
    rr = c.risk_reason or ""
    fp = (c.field_path or "").lower()
    if c.change_type == "removed":
        return ["Shopify webhook subscription was removed"]
    if _any_kw(fp, "address", "endpoint", "url") or \
            _any_kw(rr, "endpoint", "http://", "non-https", "destination"):
        return [
            "Shopify webhook endpoint URL was modified or non-HTTPS endpoint detected",
            "Webhook event delivery may be affected",
        ]
    if _any_kw(rr, "https") and _any_kw(rr, "disabled", "missing", "non-https"):
        return ["Shopify webhook endpoint appears to lack HTTPS enforcement"]
    return None


# ── Built-in catalog ──────────────────────────────────────────────────────────

BUILT_IN_POLICIES: list[_PolicyDef] = [
    # AWS
    _PolicyDef(
        key="aws_no_public_ssh",
        name="No public SSH",
        description=(
            "Flags security group rules that may allow SSH (port 22) from public CIDRs "
            "(0.0.0.0/0 or ::/0). Direct SSH access from the internet expands the attack surface."
        ),
        provider="aws",
        severity="critical",
        category="Network exposure",
        enabled_by_default=True,
        recommended_action=(
            "Restrict the tcp/22 inbound rule to a VPN or bastion CIDR, "
            "or remove SSH access entirely and use SSM Session Manager."
        ),
        matcher=_match_aws_no_public_ssh,
    ),
    _PolicyDef(
        key="aws_no_public_rdp",
        name="No public RDP",
        description=(
            "Flags security group rules that may allow RDP (port 3389) from public CIDRs. "
            "Publicly reachable RDP is a common attack vector."
        ),
        provider="aws",
        severity="critical",
        category="Network exposure",
        enabled_by_default=True,
        recommended_action=(
            "Restrict the tcp/3389 inbound rule to a VPN CIDR, "
            "or use a bastion host or SSM Fleet Manager for Windows access."
        ),
        matcher=_match_aws_no_public_rdp,
    ),
    _PolicyDef(
        key="aws_cloudtrail_must_log",
        name="CloudTrail must remain enabled",
        description=(
            "Flags CloudTrail changes that appear to disable or remove audit logging. "
            "Active CloudTrail logging is required for incident investigation and compliance."
        ),
        provider="aws",
        severity="high",
        category="Audit logging",
        enabled_by_default=True,
        recommended_action=(
            "Re-enable CloudTrail logging. Confirm the trail is active and "
            "delivers logs to a protected S3 bucket."
        ),
        matcher=_match_aws_cloudtrail_must_log,
    ),
    _PolicyDef(
        key="aws_waf_must_remain_attached",
        name="WAF must remain attached",
        description=(
            "Flags WAF or CloudFront changes that appear to detach, disable, or "
            "significantly reduce WAF protection."
        ),
        provider="aws",
        severity="high",
        category="Edge protection",
        enabled_by_default=True,
        recommended_action=(
            "Verify WAF attachment status on CloudFront distributions or load balancers. "
            "Re-attach or restore the WAF Web ACL if the change was unintended."
        ),
        matcher=_match_aws_waf_must_remain_attached,
    ),
    # Firebase
    _PolicyDef(
        key="firebase_no_public_writes",
        name="No public Firestore/Storage writes",
        description=(
            "Flags Firestore or Storage ruleset changes that may introduce unrestricted "
            "write access. Public write rules can allow any external request to modify data."
        ),
        provider="firebase",
        severity="critical",
        category="Auth",
        enabled_by_default=True,
        recommended_action=(
            "Review the Firestore rules in Firebase Console. "
            "Add 'allow write: if request.auth != null;' as a minimum guard."
        ),
        matcher=_match_firebase_no_public_writes,
    ),
    _PolicyDef(
        key="firebase_app_check_required",
        name="Firebase App Check must remain enabled",
        description=(
            "Flags Firebase changes that appear to disable or reduce App Check enforcement. "
            "App Check prevents unauthorized clients from accessing Firebase resources."
        ),
        provider="firebase",
        severity="high",
        category="Auth",
        enabled_by_default=True,
        recommended_action=(
            "Re-enable App Check enforcement in the Firebase Console "
            "under App Check settings."
        ),
        matcher=_match_firebase_app_check_required,
    ),
    # Supabase
    _PolicyDef(
        key="supabase_rls_required",
        name="Supabase RLS must remain enabled",
        description=(
            "Flags Supabase changes that appear to disable Row Level Security on a table. "
            "Without RLS, all authenticated requests can access all rows in the table."
        ),
        provider="supabase",
        severity="critical",
        category="Auth",
        enabled_by_default=True,
        recommended_action=(
            "Re-enable RLS: ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; "
            "Confirm appropriate policies exist before re-enabling."
        ),
        matcher=_match_supabase_rls_required,
    ),
    _PolicyDef(
        key="supabase_auth_security_required",
        name="Supabase Auth security settings must remain enabled",
        description=(
            "Flags Supabase Auth changes that appear to disable MFA, CAPTCHA, "
            "password strength checks, or refresh token rotation."
        ),
        provider="supabase",
        severity="high",
        category="Auth",
        enabled_by_default=True,
        recommended_action=(
            "Review Supabase Auth settings and re-enable security features "
            "that were disabled unintentionally."
        ),
        matcher=_match_supabase_auth_security_required,
    ),
    # GitHub
    _PolicyDef(
        key="github_required_reviewers",
        name="GitHub required reviewers must not be removed",
        description=(
            "Flags GitHub branch protection or environment protection changes that appear "
            "to remove required reviewers or disable prevent-self-review."
        ),
        provider="github",
        severity="high",
        category="Branch protection",
        enabled_by_default=True,
        recommended_action=(
            "Restore the required reviewer count in GitHub → Repository → Settings → "
            "Environments or Branches. Re-enable prevent-self-review."
        ),
        matcher=_match_github_required_reviewers,
    ),
    _PolicyDef(
        key="github_no_force_pushes",
        name="Force pushes must not be allowed on protected branches",
        description=(
            "Flags GitHub branch protection changes that appear to enable force pushes "
            "on a protected branch. Force pushes can overwrite commit history."
        ),
        provider="github",
        severity="high",
        category="Branch protection",
        enabled_by_default=True,
        recommended_action=(
            "Disable allow_force_pushes in the branch protection rule. "
            "Use revert commits or tags to handle history corrections instead."
        ),
        matcher=_match_github_no_force_pushes,
    ),
    # Cloudflare
    _PolicyDef(
        key="cloudflare_waf_enabled",
        name="Cloudflare WAF protection must remain active",
        description=(
            "Flags Cloudflare WAF or ruleset changes that appear to disable, remove, "
            "or significantly reduce WAF rule coverage."
        ),
        provider="cloudflare",
        severity="high",
        category="Edge protection",
        enabled_by_default=True,
        recommended_action=(
            "Review WAF Custom Rules and Managed Rules for recently added skip actions. "
            "Remove or narrow unintended skip rules and restore block/challenge coverage."
        ),
        matcher=_match_cloudflare_waf_enabled,
    ),
    _PolicyDef(
        key="cloudflare_https_required",
        name="Cloudflare HTTPS must remain enforced",
        description=(
            "Flags Cloudflare zone or SSL/TLS changes that appear to disable or weaken "
            "HTTPS enforcement, such as disabling Always Use HTTPS or downgrading TLS."
        ),
        provider="cloudflare",
        severity="high",
        category="TLS/HTTPS",
        enabled_by_default=True,
        recommended_action=(
            "Re-enable Always Use HTTPS in Cloudflare Dashboard → SSL/TLS → Edge Certificates. "
            "Confirm TLS minimum version is TLS 1.2 or higher."
        ),
        matcher=_match_cloudflare_https_required,
    ),
    # Stripe
    _PolicyDef(
        key="stripe_webhooks_must_stay_enabled",
        name="Stripe webhooks must remain enabled and unchanged",
        description=(
            "Flags Stripe webhook changes including removal, disabling, or modification "
            "of the endpoint URL. Unexpected changes may affect payment event delivery."
        ),
        provider="stripe",
        severity="high",
        category="Webhooks",
        enabled_by_default=True,
        recommended_action=(
            "Verify the current webhook endpoint is correct and owned by your team. "
            "Restore the previous endpoint and rotate the signing secret if the change was unintended."
        ),
        matcher=_match_stripe_webhooks_must_stay_enabled,
    ),
    _PolicyDef(
        key="stripe_api_keys_least_privilege",
        name="Stripe API keys must follow least privilege",
        description=(
            "Flags Stripe configuration changes that appear to expand API key permissions "
            "or broaden scope beyond what was previously set."
        ),
        provider="stripe",
        severity="high",
        category="Access control",
        enabled_by_default=True,
        recommended_action=(
            "Review the Stripe restricted API key permissions and reduce to the minimum "
            "scopes required. Rotate the key if it was unintentionally broadened."
        ),
        matcher=_match_stripe_api_keys_least_privilege,
    ),
    # Vercel
    _PolicyDef(
        key="vercel_deployment_protection_required",
        name="Vercel deployment protection must remain enabled",
        description=(
            "Flags Vercel changes that appear to disable deployment protection features "
            "such as password protection, SSO protection, or trusted IP restrictions."
        ),
        provider="vercel",
        severity="high",
        category="Deployment",
        enabled_by_default=True,
        recommended_action=(
            "Re-enable deployment protection in Vercel Dashboard → Project → Settings → "
            "Deployment Protection."
        ),
        matcher=_match_vercel_deployment_protection_required,
    ),
    _PolicyDef(
        key="vercel_production_branch_stable",
        name="Vercel production branch must remain stable",
        description=(
            "Flags Vercel changes that modify the production branch or deploy hook target ref. "
            "Unintended branch changes can cause non-production code to be deployed."
        ),
        provider="vercel",
        severity="high",
        category="Deployment",
        enabled_by_default=True,
        recommended_action=(
            "Verify the current production branch in Vercel Dashboard → Project → Settings → Git. "
            "Restore the correct branch if the change was unintended."
        ),
        matcher=_match_vercel_production_branch_stable,
    ),
    # Shopify
    _PolicyDef(
        key="shopify_sensitive_scopes_review",
        name="Shopify sensitive app scopes require review",
        description=(
            "Flags Shopify changes where app permission scope metadata indicates "
            "write-level or sensitive scopes were added. New write scopes can allow "
            "apps to modify orders, products, or customer data."
        ),
        provider="shopify",
        severity="high",
        category="Commerce",
        enabled_by_default=True,
        recommended_action=(
            "Confirm the business justification for each new scope with the app vendor. "
            "Reinstall the app with reduced scopes if the expansion was not planned."
        ),
        matcher=_match_shopify_sensitive_scopes_review,
    ),
    _PolicyDef(
        key="shopify_webhooks_https_required",
        name="Shopify webhooks must use HTTPS",
        description=(
            "Flags Shopify webhook changes including removal, endpoint URL changes, "
            "or apparent non-HTTPS endpoint destinations."
        ),
        provider="shopify",
        severity="high",
        category="Webhooks",
        enabled_by_default=True,
        recommended_action=(
            "Verify the webhook endpoint uses HTTPS and is owned by your team. "
            "Remove or update the endpoint if the change was unintended."
        ),
        matcher=_match_shopify_webhooks_https_required,
    ),
]

# Index by key for O(1) lookup
_CATALOG_BY_KEY: dict[str, _PolicyDef] = {p.key: p for p in BUILT_IN_POLICIES}


# ── Public service functions ──────────────────────────────────────────────────


def get_catalog() -> list[_PolicyDef]:
    """Return the full built-in policy catalog."""
    return list(BUILT_IN_POLICIES)


def _get_workspace_overrides(workspace_id: uuid.UUID, db: Session) -> dict[str, bool]:
    """Return {policy_key: enabled} for workspace-specific overrides."""
    from app.models.workspace_policy import WorkspacePolicy

    rows = (
        db.query(WorkspacePolicy)
        .filter(WorkspacePolicy.workspace_id == workspace_id)
        .all()
    )
    return {r.policy_key: r.enabled for r in rows}


def get_workspace_policies(
    workspace_id: uuid.UUID,
    db: Session,
) -> PolicyListResponse:
    """Return full catalog merged with workspace-level enabled overrides."""
    overrides = _get_workspace_overrides(workspace_id, db)
    policies = []
    for p in BUILT_IN_POLICIES:
        enabled = overrides.get(p.key, p.enabled_by_default)
        policies.append(
            WorkspacePolicyResponse(
                policy_key=p.key,
                name=p.name,
                description=p.description,
                provider=p.provider,
                severity=p.severity,
                category=p.category,
                enabled=enabled,
                built_in=True,
            )
        )
    return PolicyListResponse(policies=policies, total=len(policies))


def set_policy_enabled(
    workspace_id: uuid.UUID,
    policy_key: str,
    enabled: bool,
    db: Session,
) -> WorkspacePolicyResponse:
    """Upsert the workspace-level enabled flag for a policy.

    Raises KeyError if the policy_key is not in the catalog.
    Caller owns db.commit().
    """
    if policy_key not in _CATALOG_BY_KEY:
        raise KeyError(f"Unknown policy key: {policy_key!r}")

    from app.models.workspace_policy import WorkspacePolicy

    row = (
        db.query(WorkspacePolicy)
        .filter(
            WorkspacePolicy.workspace_id == workspace_id,
            WorkspacePolicy.policy_key == policy_key,
        )
        .first()
    )
    if row is None:
        row = WorkspacePolicy(
            workspace_id=workspace_id,
            policy_key=policy_key,
            enabled=enabled,
        )
        db.add(row)
    else:
        row.enabled = enabled
    db.flush()

    p = _CATALOG_BY_KEY[policy_key]
    return WorkspacePolicyResponse(
        policy_key=p.key,
        name=p.name,
        description=p.description,
        provider=p.provider,
        severity=p.severity,
        category=p.category,
        enabled=enabled,
        built_in=True,
    )


def evaluate_change(
    change,
    enabled_policy_keys: set[str],
) -> list[PolicyViolation]:
    """Evaluate a change against all enabled policies.

    Returns a list of PolicyViolation objects (may be empty).
    Does not access the database.
    """
    violations: list[PolicyViolation] = []
    for policy in BUILT_IN_POLICIES:
        if policy.key not in enabled_policy_keys:
            continue
        evidence = policy.matcher(change)
        if evidence is not None:
            violations.append(
                PolicyViolation(
                    policy_key=policy.key,
                    name=policy.name,
                    severity=policy.severity,
                    description=policy.description,
                    evidence=evidence,
                    recommended_action=policy.recommended_action,
                )
            )
    return violations


def compute_violations(
    change_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> PolicyViolationsResponse:
    """Main entry point.

    Loads the change (must belong to user's workspace), resolves the workspace,
    gets enabled policies, evaluates, returns violations.
    Raises HTTP-style errors only through LookupError for not-found cases.
    """
    from app.models.change import Change
    from app.models.integration import Integration
    from app.models.workspace import WorkspaceMember

    # Load change
    change = db.get(Change, change_id)
    if change is None:
        raise LookupError("Change not found.")

    # Derive workspace via integration
    integration = db.get(Integration, change.integration_id)
    if integration is None:
        raise LookupError("Change not found.")  # hide internal detail

    workspace_id = integration.workspace_id

    # Verify user is a member
    member = (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user_id,
        )
        .first()
    )
    if member is None:
        raise LookupError("Change not found.")  # 404, not 403

    # Get enabled policy keys
    overrides = _get_workspace_overrides(workspace_id, db)
    enabled_keys: set[str] = {
        p.key
        for p in BUILT_IN_POLICIES
        if overrides.get(p.key, p.enabled_by_default)
    }

    violations = evaluate_change(change, enabled_keys)
    return PolicyViolationsResponse(violations=violations)
