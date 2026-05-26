"""Remediation summary service — M58.4.

Builds compact, safe remediation summaries for alert payloads (email,
Slack webhook, and generic webhook).

CRITICAL constraints (must remain in effect permanently):
  - execution_enabled is ALWAYS False.  This service never applies changes.
  - This module never calls any provider write API.
  - No backend jobs that apply fixes.
  - No one-click language ("apply fix", "auto-fix", etc.).

Data safety:
  - No raw prev_value / new_value forwarded into any summary text.
  - No secrets, tokens, webhook URLs, customer PII, or payment data.
  - record_identifier used only as structural context; never forwarded raw.
  - Summaries contain only safe, human-readable description text.

Coverage — flagship alert patterns:
  - AWS public admin ingress (SSH, RDP, any security group)
  - AWS CloudFront weakened
  - Cloudflare DNS removal (email-auth records prioritised)
  - Firebase security rules permissive / App Check weakened
  - Supabase RLS disabled
  - GitHub branch protection weakened / removed
  - Stripe webhook / account capability drift
  - Vercel deploy hook added / removed
  - Shopify webhook / scope / shop metadata drift
  - Generic fallback for high/critical with no specific pattern
"""

from __future__ import annotations

from typing import Any


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return obj[key] for dicts, or getattr(obj, key, None) for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _s(value: Any) -> str:
    """Safely coerce to lowercase string; returns '' for non-strings."""
    return value.lower() if isinstance(value, str) else ""


# ── Hard constants ────────────────────────────────────────────────────────────

# execution_enabled is a hard constant — never computed, never set to True.
_EXECUTION_ENABLED: bool = False
_ACTION_LABEL: str = "Open remediation preview"

# Cloudflare uses raw DNS record types as record_type values.
_CLOUDFLARE_DNS_TYPES: frozenset[str] = frozenset(
    {"a", "aaaa", "cname", "txt", "mx", "srv", "ns", "ptr", "soa", "caa", "https", "ds"}
)


# ── Builder helper ────────────────────────────────────────────────────────────

def _summary(
    title: str,
    summary: str,
    confidence: str = "medium",
    fix_plan_available: bool = False,
    remediation_preview_available: bool = True,
) -> dict:
    """Build a compact remediation summary dict.

    execution_enabled is always False — hardcoded, never overridden.
    """
    return {
        "available": True,
        "title": title,
        "summary": summary,
        "confidence": confidence,
        "fix_plan_available": fix_plan_available,
        "remediation_preview_available": remediation_preview_available,
        "execution_enabled": _EXECUTION_ENABLED,
        "action_label": _ACTION_LABEL,
    }


def _generic_fallback() -> dict:
    """Return the generic high/critical fallback summary."""
    return _summary(
        title="Review suggested remediation",
        summary=(
            "Open ConfigTrace to review safe remediation guidance for this change."
        ),
        confidence="low",
        fix_plan_available=False,
        remediation_preview_available=True,
    )


# ── Per-provider handlers ─────────────────────────────────────────────────────


def _aws_sg_summary(fp: str, rl: str, rr: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    is_ssh = fp == "has_public_ssh" or "ssh" in rr or "port 22" in rr or "tcp/22" in rr
    is_rdp = fp == "has_public_rdp" or "rdp" in rr or "port 3389" in rr or "tcp/3389" in rr
    if is_ssh:
        return _summary(
            title="Restrict public SSH access",
            summary=(
                "Remove or restrict the TCP/22 inbound rule to a trusted VPN, "
                "bastion host, or office CIDR."
            ),
            confidence="high",
            fix_plan_available=True,
            remediation_preview_available=True,
        )
    if is_rdp:
        return _summary(
            title="Restrict public RDP access",
            summary=(
                "Remove or restrict the TCP/3389 inbound rule to a trusted network."
            ),
            confidence="high",
            fix_plan_available=True,
            remediation_preview_available=True,
        )
    return _summary(
        title="Review public inbound rule",
        summary=(
            "Review the security group's inbound rules and restrict access to "
            "trusted CIDRs only."
        ),
        confidence="medium",
        fix_plan_available=False,
        remediation_preview_available=True,
    )


def _aws_cloudfront_summary(fp: str, rl: str, rr: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    return _summary(
        title="Review CloudFront security configuration",
        summary=(
            "Review and restore the weakened or removed CloudFront security setting."
        ),
        confidence="medium",
    )


def _github_summary(rt: str, fp: str, ct: str, rl: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    if rt == "github_branch_protection":
        return _summary(
            title="Restore branch protection rules",
            summary=(
                "Restore the weakened or removed branch protection settings via "
                "GitHub repository Settings → Branches."
            ),
            confidence="high",
            fix_plan_available=True,
            remediation_preview_available=True,
        )
    if rt == "github_repo_settings" and fp == "visibility":
        return _summary(
            title="Review repository visibility change",
            summary=(
                "Confirm whether the repository visibility change was intentional. "
                "Private repos keep code and history confidential."
            ),
            confidence="high",
        )
    if rt == "github_webhook":
        return _summary(
            title="Audit GitHub webhook change",
            summary=(
                "Review the GitHub webhook change and confirm the endpoint is "
                "authorized and under your control."
            ),
            confidence="medium",
        )
    if rt == "github_actions_secret":
        return _summary(
            title="Review Actions secret change",
            summary=(
                "A GitHub Actions secret was changed or deleted. "
                "Confirm dependent workflows still work correctly."
            ),
            confidence="medium",
        )
    return _summary(
        title="Review GitHub configuration change",
        summary=(
            "Review the GitHub repository configuration change and confirm it "
            "was intentional."
        ),
        confidence="medium",
    )


def _firebase_summary(rt: str, fp: str, rl: str, rr: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    if rt in ("firebase_firestore_ruleset", "firebase_storage_ruleset"):
        return _summary(
            title="Tighten Firebase security rules",
            summary=(
                "Restrict overly permissive Firebase rules to require authentication "
                "and authorization checks."
            ),
            confidence="high",
            fix_plan_available=True,
            remediation_preview_available=True,
        )
    if rt == "firebase_app_check_config":
        return _summary(
            title="Restore Firebase App Check enforcement",
            summary=(
                "Re-enable App Check enforcement to protect your Firebase backend "
                "from unauthorized clients."
            ),
            confidence="high",
        )
    if rt == "firebase_auth_config":
        return _summary(
            title="Review Firebase Auth configuration",
            summary=(
                "Review the authentication configuration change and confirm it was "
                "intentional."
            ),
            confidence="medium",
        )
    return _summary(
        title="Review Firebase configuration change",
        summary=(
            "Review the Firebase configuration change and confirm it was intentional."
        ),
        confidence="medium",
    )


def _supabase_summary(rt: str, fp: str, rl: str, rr: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    if rt == "supabase_rls_status":
        return _summary(
            title="Enable Row Level Security",
            summary=(
                "Enable RLS on the affected table to prevent unauthorized row access."
            ),
            confidence="high",
            fix_plan_available=True,
            remediation_preview_available=True,
        )
    if rt == "supabase_auth_config":
        return _summary(
            title="Review Supabase auth configuration",
            summary=(
                "Review and restore the weakened authentication setting."
            ),
            confidence="medium",
        )
    if rt == "supabase_network_restriction":
        return _summary(
            title="Review Supabase network restrictions",
            summary=(
                "Verify the network restriction change does not expose the database "
                "to untrusted IP addresses."
            ),
            confidence="high",
        )
    return _summary(
        title="Review Supabase configuration change",
        summary=(
            "Review the Supabase configuration change and confirm it was intentional."
        ),
        confidence="medium",
    )


def _stripe_summary(rt: str, fp: str, ct: str, rl: str, rr: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    if rt == "stripe_webhook_endpoint":
        if ct == "removed":
            return _summary(
                title="Review removed Stripe webhook",
                summary=(
                    "A Stripe webhook endpoint was deleted. Confirm events are no "
                    "longer expected and dependent systems have been updated."
                ),
                confidence="medium",
            )
        return _summary(
            title="Audit Stripe webhook change",
            summary=(
                "Review the Stripe webhook change and confirm the endpoint is under "
                "your control."
            ),
            confidence="medium",
        )
    if rt == "stripe_account_settings":
        if fp in ("charges_enabled", "payouts_enabled"):
            return _summary(
                title="Review Stripe account capability",
                summary=(
                    "A critical Stripe account capability (charges or payouts) was "
                    "disabled. Confirm this was intentional and check the Stripe "
                    "Dashboard for the reason."
                ),
                confidence="high",
            )
        return _summary(
            title="Review Stripe account settings",
            summary=(
                "Review the Stripe account settings change and confirm it was "
                "intentional."
            ),
            confidence="medium",
        )
    return _summary(
        title="Review Stripe configuration change",
        summary=(
            "Review the Stripe configuration change and confirm it was intentional."
        ),
        confidence="medium",
    )


def _vercel_summary(rt: str, fp: str, ct: str, rl: str) -> dict | None:
    # Deploy hook changes are medium risk (see M58.1c) — include them.
    if rt == "vercel_deploy_hook_metadata":
        if rl not in ("high", "critical", "medium"):
            return None
        if ct == "added":
            return _summary(
                title="Audit newly added deploy hook",
                summary=(
                    "A new Vercel deploy hook was added. Deploy hooks trigger "
                    "deployments via an unauthenticated URL — confirm it is authorized."
                ),
                confidence="medium",
                fix_plan_available=False,
                remediation_preview_available=True,
            )
        return _summary(
            title="Review removed deploy hook",
            summary=(
                "A Vercel deploy hook was removed. If this was unintentional, "
                "restore it in Vercel project settings."
            ),
            confidence="medium",
            fix_plan_available=False,
            remediation_preview_available=True,
        )
    # Other Vercel record types: only include for high/critical
    if rl not in ("high", "critical"):
        return None
    return _summary(
        title="Review Vercel configuration change",
        summary=(
            "Review the Vercel configuration change and confirm it was intentional."
        ),
        confidence="medium",
    )


def _shopify_summary(rt: str, fp: str, ct: str, rl: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    if rt == "shopify_webhook_subscription":
        return _summary(
            title="Review Shopify webhook change",
            summary=(
                "Review the Shopify webhook change for unauthorized modifications "
                "to event routing."
            ),
            confidence="medium",
        )
    if rt == "shopify_app_scope_summary":
        return _summary(
            title="Review Shopify app scope change",
            summary=(
                "An app's requested permissions changed. Review the new scope for "
                "unnecessary or sensitive access."
            ),
            confidence="medium",
        )
    if rt == "shopify_shop_metadata":
        return _summary(
            title="Review Shopify shop configuration",
            summary=(
                "A Shopify shop configuration setting changed. Review for "
                "unauthorized changes to payments or storefront access."
            ),
            confidence="medium",
        )
    return _summary(
        title="Review Shopify configuration change",
        summary=(
            "Review the Shopify configuration change and confirm it was intentional."
        ),
        confidence="medium",
    )


def _cloudflare_summary(rt: str, fp: str, ct: str, rl: str, rr: str) -> dict | None:
    if rl not in ("high", "critical"):
        return None
    is_email_auth = (
        rt in ("txt", "mx")
        or "spf" in rr or "dmarc" in rr or "dkim" in rr or "email auth" in rr
    )
    if ct == "removed":
        if is_email_auth:
            return _summary(
                title="Restore removed email security record",
                summary=(
                    "Restore the SPF, DMARC, or DKIM record to prevent email "
                    "spoofing and delivery failures."
                ),
                confidence="high",
                fix_plan_available=True,
                remediation_preview_available=True,
            )
        return _summary(
            title="Restore removed DNS record",
            summary=(
                "Review and restore the removed DNS record if this removal was "
                "not intentional."
            ),
            confidence="medium",
            fix_plan_available=True,
            remediation_preview_available=True,
        )
    return _summary(
        title="Review DNS configuration change",
        summary=(
            "Review the DNS configuration change and confirm it was intentional."
        ),
        confidence="medium",
    )


# ── Public entry point ────────────────────────────────────────────────────────


def build_alert_remediation_summary(change: Any) -> dict | None:
    """Return a compact remediation summary for alert payloads, or None.

    Returns None for low/medium-risk changes with no specific pattern match,
    so alerts stay focused and uncluttered.  For high/critical changes with
    no specific pattern, returns a generic fallback.

    CRITICAL: execution_enabled in every returned dict is always False.
    This function never mutates resources and never calls provider write APIs.

    Data safety: no raw prev_value/new_value forwarded; no secrets, tokens,
    webhook URLs, customer data, or commands included.

    Args:
        change: A Change ORM instance or a plain dict with the same fields.

    Returns:
        A dict with keys:
          available (True), title, summary, confidence, fix_plan_available,
          remediation_preview_available, execution_enabled (False), action_label
        or None if no remediation summary is warranted for this change.
    """
    pm = _get(change, "provider_metadata")
    if not isinstance(pm, dict):
        pm = {}

    rt = _s(pm.get("record_type"))
    fp = _s(_get(change, "field_path"))
    ct = _s(_get(change, "change_type"))
    rl = _s(_get(change, "risk_level"))
    rr = _s(_get(change, "risk_reason"))

    # ── Provider-specific dispatch ────────────────────────────────────────────
    if rt == "aws_security_group" or rt == "aws_security_group_rule":
        return _aws_sg_summary(fp, rl, rr)

    if rt.startswith("aws_cloudfront"):
        return _aws_cloudfront_summary(fp, rl, rr)

    if rt.startswith("github_"):
        return _github_summary(rt, fp, ct, rl)

    if rt.startswith("firebase_"):
        return _firebase_summary(rt, fp, rl, rr)

    if rt.startswith("supabase_"):
        return _supabase_summary(rt, fp, rl, rr)

    if rt.startswith("stripe_"):
        return _stripe_summary(rt, fp, ct, rl, rr)

    if rt.startswith("vercel_"):
        return _vercel_summary(rt, fp, ct, rl)

    if rt.startswith("shopify_"):
        return _shopify_summary(rt, fp, ct, rl)

    # Cloudflare DNS — record_type is the raw DNS type (e.g. "cname", "a", "txt")
    if rt in _CLOUDFLARE_DNS_TYPES or rt == "cloudflare_ruleset":
        return _cloudflare_summary(rt, fp, ct, rl, rr)

    # ── Fallback ──────────────────────────────────────────────────────────────
    # For high/critical changes from any unrecognised provider: generic fallback.
    # Low/medium with no specific match: no remediation noise.
    if rl in ("high", "critical"):
        return _generic_fallback()

    return None
