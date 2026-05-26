"""Change Correlation / Risk Cluster service — M58.10.

Deterministic, on-demand correlation engine. Computes which nearby changes
are likely part of the same operational event by scoring time proximity,
provider relationships, risk domains, and cross-provider workflow patterns.

Design constraints (permanent):
  - No external API calls. No LLM. No AI.
  - Clusters are computed fresh per request; nothing is persisted.
  - cluster_id is a stable hash of sorted change IDs, not a DB primary key.
  - Raw prev_value / new_value content is NEVER forwarded into output.
  - Language in all generated text uses "possible" / "may" — never
    "confirmed", "root cause", "caused by", or "definitely related".

Architecture:
  1. Load the primary change (user-scoped).
  2. Query nearby changes within ±24h (same user).
  3. Score each candidate for relevance to the primary change.
  4. Filter to candidates with score ≥ MIN_SCORE.
  5. Identify the cluster type from the provider/domain matrix.
  6. Assign confidence (high/medium/low).
  7. Build and return CorrelationResponse.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.schemas.change_correlation import (
    CorrelationChangeItem,
    CorrelationResponse,
    PrimaryCluster,
)

# ── Constants ─────────────────────────────────────────────────────────────────

_LOOSE_WINDOW_HOURS = 24   # outer window for candidate lookup
_MIN_SCORE = 3             # minimum score to treat a candidate as related
_MAX_CANDIDATES = 50       # DB row cap for candidate query
_MAX_CLUSTER_MEMBERS = 5   # max related changes shown in the cluster

# ── Provider derivation ───────────────────────────────────────────────────────


def _derive_provider(record_type: str) -> str:
    """Derive the provider key from a record_type string.

    Mirrors getTimelineProvider in timeline.ts (kept local to avoid cross-layer deps).
    """
    rt = (record_type or "").lower()
    if rt.startswith("aws_"):       return "aws"
    if rt.startswith("github_"):    return "github"
    if rt.startswith("vercel_"):    return "vercel"
    if rt.startswith("stripe_"):    return "stripe"
    if rt.startswith("firebase_"):  return "firebase"
    if rt.startswith("supabase_"):  return "supabase"
    if rt.startswith("shopify_"):   return "shopify"
    if rt:                          return "cloudflare"   # bare DNS type ("a", "cname", …)
    return "unknown"


# ── Risk domain mapping ───────────────────────────────────────────────────────
# Maps record_type → risk domain used for correlation scoring.

_DOMAIN_MAP: dict[str, str] = {
    # ── Network / Edge ────────────────────────────────────────────────────────
    "aws_security_group":           "network_edge",
    "aws_security_group_rule":      "network_edge",
    "aws_cloudfront":               "network_edge",
    "aws_waf":                      "network_edge",
    "aws_route53":                  "network_edge",
    "cloudflare_waf":               "network_edge",
    "cloudflare_ssl":               "network_edge",
    "cloudflare_ruleset":           "network_edge",
    # Cloudflare DNS — email/security records
    "mx":   "network_edge",
    "txt":  "network_edge",
    "spf":  "network_edge",
    "caa":  "network_edge",
    "ds":   "network_edge",
    "tlsa": "network_edge",

    # ── Deployment / Routing ──────────────────────────────────────────────────
    # Cloudflare DNS routing records (bare DNS types)
    "a":     "deployment_routing",
    "aaaa":  "deployment_routing",
    "cname": "deployment_routing",
    "ns":    "deployment_routing",
    "srv":   "deployment_routing",
    # GitHub
    "github_branch_protection":       "deployment",
    "github_environment_protection":  "deployment",
    "github_webhook":                 "deployment",
    "github_deploy_key":              "deployment",
    "github_repo_settings":           "deployment",
    "github_actions_secret":          "deployment",
    # Vercel
    "vercel_project":                 "deployment",
    "vercel_deploy_hook_metadata":    "deployment",
    "vercel_env_var":                 "deployment",
    "vercel_domain":                  "deployment",
    "vercel_deployment_protection":   "deployment",
    # Firebase
    "firebase_remote_config":         "deployment",
    "firebase_functions":             "deployment",

    # ── Auth / Access ─────────────────────────────────────────────────────────
    "firebase_auth":              "auth_access",
    "firebase_app_check":         "auth_access",
    "firebase_authorized_domain": "auth_access",
    "supabase_auth_settings":     "auth_access",
    "supabase_auth":              "auth_access",
    "aws_iam_policy":             "auth_access",
    "aws_iam_role":               "auth_access",
    "shopify_app_permission":     "auth_access",
    "shopify_app_scope":          "auth_access",

    # ── Data Protection ───────────────────────────────────────────────────────
    "firebase_security_rules":    "data_protection",
    "firebase_rules":             "data_protection",
    "firebase_firestore_rules":   "data_protection",
    "firebase_storage_rules":     "data_protection",
    "firebase_realtime_database": "data_protection",
    "supabase_rls_status":        "data_protection",
    "supabase_policy":            "data_protection",
    "supabase_storage_policy":    "data_protection",

    # ── Payments / Commerce ───────────────────────────────────────────────────
    "stripe_webhook_endpoint":    "payments_commerce",
    "stripe_webhook":             "payments_commerce",
    "stripe_api_key":             "payments_commerce",
    "stripe_billing_portal":      "payments_commerce",
    "stripe_payment_method":      "payments_commerce",
    "stripe_tax_settings":        "payments_commerce",
    "shopify_webhook":            "payments_commerce",
    "shopify_shop_metadata":      "payments_commerce",
    "shopify_store_policy":       "payments_commerce",
}


def _get_risk_domain(record_type: str, field_path: Optional[str] = None) -> str:
    """Return the risk domain for a record_type (used for correlation scoring)."""
    return _DOMAIN_MAP.get((record_type or "").lower(), "unknown")


# ── Cluster templates ─────────────────────────────────────────────────────────
# Each template defines which provider/domain signals match it.
# Templates are checked in order; first sufficient match wins.

_CLUSTER_TEMPLATES: list[dict] = [
    # edge_security checked BEFORE deployment_routing so that cloudflare WAF/SSL
    # + AWS security-group changes don't get misclassified as a deploy cluster.
    {
        "type":        "edge_security",
        "title":       "Possible edge or security posture changes",
        "min_signals": 2,
        "provider_domains": {
            "cloudflare": {"network_edge"},
            "aws":        {"network_edge"},
        },
        "recommended_review": [
            "Confirm whether a security hardening or WAF rule update was planned.",
            "Verify that legitimate traffic is not blocked by the updated rules.",
            "Review WAF dashboards for traffic anomalies after these changes.",
        ],
    },
    {
        "type":        "deployment_routing",
        "title":       "Possible deployment or release-related changes",
        "min_signals": 2,
        "provider_domains": {
            "github":     {"deployment"},
            "vercel":     {"deployment"},
            # Only routing DNS records (A/CNAME/NS) match deployment; WAF/SSL do not.
            "cloudflare": {"deployment_routing"},
            "firebase":   {"deployment"},
            "aws":        {"network_edge"},
        },
        "recommended_review": [
            "Confirm whether a deployment or release was planned around this time.",
            "Check whether routing, deploy hooks, and DNS changes were tested together.",
            "Review CI/CD logs or deploybot history for this time window.",
        ],
    },
    {
        "type":        "payments_commerce",
        "title":       "Possible checkout or commerce workflow changes",
        "min_signals": 2,
        "provider_domains": {
            "stripe":     {"payments_commerce"},
            "shopify":    {"payments_commerce"},
            "cloudflare": {"deployment_routing", "network_edge"},
            "vercel":     {"deployment"},
        },
        "recommended_review": [
            "Confirm whether a checkout system or payment provider migration was planned.",
            "Verify Stripe webhook delivery and Shopify order processing are functioning.",
            "Review whether payment and checkout flows were tested after these changes.",
        ],
    },
    {
        "type":        "auth_access",
        "title":       "Possible access-control posture changes",
        "min_signals": 2,
        "provider_domains": {
            "firebase":  {"auth_access"},
            "supabase":  {"auth_access", "data_protection"},
            "github":    {"deployment"},
            "aws":       {"auth_access"},
            "shopify":   {"auth_access"},
        },
        "recommended_review": [
            "Confirm whether an access-control policy update was planned.",
            "Review authentication flows and confirm they are working as expected.",
            "Check that no unintended access was granted or removed by these changes.",
        ],
    },
    {
        "type":        "data_protection",
        "title":       "Possible data-access posture changes",
        "min_signals": 2,
        "provider_domains": {
            "firebase":  {"data_protection"},
            "supabase":  {"data_protection"},
            "aws":       {"network_edge"},
        },
        "recommended_review": [
            "Confirm whether a data access policy update was planned.",
            "Verify that sensitive data paths are not publicly accessible.",
            "Review database access policies and confirm correct permissions.",
        ],
    },
]

# Provider sets for cross-provider pair scoring
_DEPLOYMENT_PROVIDERS = frozenset({"github", "vercel", "cloudflare", "firebase", "aws"})
_COMMERCE_PROVIDERS   = frozenset({"stripe", "shopify", "cloudflare", "vercel"})
_AUTH_PROVIDERS       = frozenset({"firebase", "supabase", "github", "aws"})
_DATA_PROVIDERS       = frozenset({"firebase", "supabase", "aws"})
_EDGE_PROVIDERS       = frozenset({"cloudflare", "aws"})


# ── Scoring ───────────────────────────────────────────────────────────────────


def _time_delta_minutes(t1: datetime, t2: datetime) -> float:
    """Absolute time delta in minutes, timezone-safe."""
    if t1.tzinfo is None:
        t1 = t1.replace(tzinfo=timezone.utc)
    if t2.tzinfo is None:
        t2 = t2.replace(tzinfo=timezone.utc)
    return abs((t1 - t2).total_seconds()) / 60.0


def _score_candidate(
    primary_record_id: str,
    primary_integration_id: uuid.UUID,
    primary_provider: str,
    primary_domain: str,
    primary_rt: str,
    cand_record_id: str,
    cand_integration_id: uuid.UUID,
    cand_provider: str,
    cand_domain: str,
    cand_rt: str,
    cand_risk_level: str,
    delta_minutes: float,
) -> tuple[int, list[str]]:
    """
    Score the relatedness of a candidate change to the primary change.

    Returns (score, signal_descriptions).
    Higher score = more likely part of the same event.
    """
    score = 0
    signals: list[str] = []

    # ── Same record identifier — very strong (same resource, likely same intent) ──
    if primary_record_id and primary_record_id == cand_record_id:
        score += 5
        signals.append(f"Same resource: {primary_record_id}")

    # ── Integration membership ────────────────────────────────────────────────
    if primary_integration_id == cand_integration_id:
        score += 3
        signals.append("Same integration")
    elif primary_provider == cand_provider and primary_provider != "unknown":
        score += 2
        signals.append(f"Same provider: {primary_provider}")

    # ── Record type match ─────────────────────────────────────────────────────
    if primary_rt and primary_rt == cand_rt:
        score += 2
        signals.append(f"Same resource type: {primary_rt}")

    # ── Risk domain match ─────────────────────────────────────────────────────
    if primary_domain != "unknown" and primary_domain == cand_domain:
        score += 2
        signals.append(f"Same risk domain: {primary_domain}")

    # ── Cross-provider workflow signals ───────────────────────────────────────
    pair = frozenset({primary_provider, cand_provider})
    if len(pair) > 1:  # only cross-provider
        if pair.issubset(_DEPLOYMENT_PROVIDERS):
            score += 3
            signals.append("Cross-provider deployment signal")
        elif pair.issubset(_COMMERCE_PROVIDERS):
            score += 3
            signals.append("Cross-provider commerce signal")
        elif pair.issubset(_AUTH_PROVIDERS) and (
            primary_domain in ("auth_access", "data_protection")
            or cand_domain in ("auth_access", "data_protection")
        ):
            score += 3
            signals.append("Cross-provider auth/access signal")
        elif pair.issubset(_DATA_PROVIDERS) and (
            primary_domain == "data_protection" or cand_domain == "data_protection"
        ):
            score += 3
            signals.append("Cross-provider data-protection signal")
        elif pair.issubset(_EDGE_PROVIDERS) and (
            primary_domain == "network_edge" or cand_domain == "network_edge"
        ):
            score += 3
            signals.append("Cross-provider edge/security signal")

    # ── Time proximity ────────────────────────────────────────────────────────
    if delta_minutes <= 15:
        score += 4
        signals.append(f"Within {round(delta_minutes)} min")
    elif delta_minutes <= 60:
        score += 2
        signals.append(f"Within {round(delta_minutes)} min")
    elif delta_minutes <= 24 * 60:
        score += 1
        signals.append(f"Within {round(delta_minutes / 60)} h")

    # ── Risk level boost ──────────────────────────────────────────────────────
    if cand_risk_level in ("high", "critical"):
        score += 1

    return score, signals


# ── Cluster identification ────────────────────────────────────────────────────


def _identify_cluster_type(all_providers: set[str], all_domains: set[str]) -> str:
    """Return the best-matching cluster type for the observed provider/domain set."""
    best_type = "provider_local"
    best_count = 0

    for tmpl in _CLUSTER_TEMPLATES:
        count = 0
        for prov, domains in tmpl["provider_domains"].items():
            if prov in all_providers and all_domains.intersection(domains):
                count += 1
        if count >= tmpl["min_signals"] and count > best_count:
            best_count = count
            best_type = tmpl["type"]

    return best_type


# ── Confidence assignment ─────────────────────────────────────────────────────


def _assign_confidence(
    related: list[tuple[object, int, float]],  # (change, score, delta_minutes)
    primary_record_id: str,
) -> str:
    """
    Assign confidence based on the cluster composition:
      high:   same resource + multiple within 15 min,
              OR ≥ 3 tight-window members,
              OR ≥ 2 high-scoring signals within 30 min.
      medium: ≥ 2 within 30–60 min, or same provider/domain within 30 min.
      low:    weak signal(s) within 24 h.
    """
    if not related:
        return "low"

    tight_count     = sum(1 for _, _, d in related if d <= 30)
    very_tight_count = sum(1 for _, _, d in related if d <= 15)
    high_score_count = sum(1 for _, s, _ in related if s >= 7)

    same_resource_tight = sum(
        1 for c, _, d in related
        if getattr(c, "record_identifier", None) == primary_record_id and d <= 15
    )

    if same_resource_tight >= 1 and very_tight_count >= 1:
        return "high"
    if high_score_count >= 2 and tight_count >= 2:
        return "high"
    if tight_count >= 3:
        return "high"
    if tight_count >= 2:
        return "medium"
    if len(related) >= 2 and all(d <= 60 for _, _, d in related):
        return "medium"
    if len(related) >= 1 and all(d <= 30 for _, _, d in related):
        return "medium"
    return "low"


# ── Safe title builder ────────────────────────────────────────────────────────


def _safe_title(change) -> str:
    """Human-readable title without raw values."""
    pm = getattr(change, "provider_metadata", None) or {}
    rt = (pm.get("record_type") or "").lower()
    ct = (getattr(change, "change_type", "") or "").lower()
    ct_label = {"added": "added", "removed": "removed", "modified": "modified"}.get(ct, ct)

    for prefix, label in (
        ("github_",   "GitHub"),
        ("vercel_",   "Vercel"),
        ("stripe_",   "Stripe"),
        ("firebase_", "Firebase"),
        ("supabase_", "Supabase"),
        ("shopify_",  "Shopify"),
        ("aws_",      "AWS"),
    ):
        if rt.startswith(prefix):
            readable = rt[len(prefix):].replace("_", " ")
            return f"{label} {readable} {ct_label}".strip().capitalize()

    if rt:
        return f"{rt.upper()} record {ct_label}".strip()
    return f"Configuration {ct_label}".strip()


# ── Summary sentence ──────────────────────────────────────────────────────────


def _build_summary(
    cluster_type: str,
    n_related: int,
    provider_names: list[str],
    time_window_minutes: int,
) -> str:
    """Build a one-sentence cluster summary using 'possible/may' language."""
    total = n_related + 1  # include primary
    unique_providers = sorted(set(provider_names))
    prov_str = ", ".join(unique_providers) if unique_providers else "the same provider"

    descriptions = {
        "deployment_routing": "deployment or release",
        "payments_commerce":  "checkout or commerce workflow",
        "edge_security":      "edge or security posture",
        "auth_access":        "access-control posture",
        "data_protection":    "data-access posture",
        "provider_local":     "operational",
        "unknown":            "operational",
    }
    desc = descriptions.get(cluster_type, "operational")

    if time_window_minutes < 60:
        time_str = f"{max(time_window_minutes, 1)} minute{'s' if time_window_minutes != 1 else ''}"
    else:
        hrs = max(round(time_window_minutes / 60), 1)
        time_str = f"{hrs} hour{'s' if hrs != 1 else ''}"

    return (
        f"{total} change{'s' if total != 1 else ''} across {prov_str} "
        f"may be part of the same {desc} event. "
        f"These changes occurred within {time_str} of each other."
    )


# ── Cluster ID ────────────────────────────────────────────────────────────────


def _cluster_id(change_ids: list[uuid.UUID]) -> str:
    """Stable hash derived from sorted change UUIDs (non-persisted, non-stable across syncs)."""
    sorted_ids = sorted(str(i) for i in change_ids)
    return hashlib.sha256("|".join(sorted_ids).encode()).hexdigest()[:16]


# ── Main entry point ──────────────────────────────────────────────────────────


def correlate_change(
    change_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> CorrelationResponse:
    """
    Compute the correlation / risk cluster for a change.

    Returns ``CorrelationResponse(available=False)`` when:
      - The primary change is not found / doesn't belong to user.
      - No nearby changes exist within the window.
      - No nearby changes score above the minimum threshold.

    Never raises; returns available=False on any unexpected condition.
    """
    from app.models.change import Change as ChangeModel

    # ── 1. Load primary change ────────────────────────────────────────────────
    primary = (
        db.query(ChangeModel)
        .filter(ChangeModel.id == change_id, ChangeModel.user_id == user_id)
        .first()
    )
    if primary is None:
        return CorrelationResponse(available=False)

    # ── 2. Extract primary metadata ───────────────────────────────────────────
    pm_p = primary.provider_metadata or {}
    rt_p = (pm_p.get("record_type") or "").lower()
    provider_p = _derive_provider(rt_p)
    domain_p = _get_risk_domain(rt_p, primary.field_path)

    primary_time = primary.created_at
    if primary_time.tzinfo is None:
        primary_time = primary_time.replace(tzinfo=timezone.utc)

    # ── 3. Query nearby candidates (±24 h, same user, excluding self) ─────────
    since = primary_time - timedelta(hours=_LOOSE_WINDOW_HOURS)
    until = primary_time + timedelta(hours=_LOOSE_WINDOW_HOURS)

    candidates = (
        db.query(ChangeModel)
        .filter(
            ChangeModel.user_id == user_id,
            ChangeModel.id != change_id,
            ChangeModel.created_at >= since,
            ChangeModel.created_at <= until,
        )
        .order_by(ChangeModel.created_at)
        .limit(_MAX_CANDIDATES)
        .all()
    )

    if not candidates:
        return CorrelationResponse(available=False)

    # ── 4. Score each candidate ───────────────────────────────────────────────
    scored: list[tuple[ChangeModel, int, float, list[str]]] = []
    for cand in candidates:
        pm_c = cand.provider_metadata or {}
        rt_c = (pm_c.get("record_type") or "").lower()
        prov_c = _derive_provider(rt_c)
        dom_c = _get_risk_domain(rt_c, cand.field_path)

        cand_time = cand.created_at
        if cand_time.tzinfo is None:
            cand_time = cand_time.replace(tzinfo=timezone.utc)

        delta = _time_delta_minutes(primary_time, cand_time)

        score, sigs = _score_candidate(
            primary_record_id=primary.record_identifier or "",
            primary_integration_id=primary.integration_id,
            primary_provider=provider_p,
            primary_domain=domain_p,
            primary_rt=rt_p,
            cand_record_id=cand.record_identifier or "",
            cand_integration_id=cand.integration_id,
            cand_provider=prov_c,
            cand_domain=dom_c,
            cand_rt=rt_c,
            cand_risk_level=cand.risk_level or "low",
            delta_minutes=delta,
        )

        if score >= _MIN_SCORE:
            scored.append((cand, score, delta, sigs))

    # ── 5. Nothing related ────────────────────────────────────────────────────
    if not scored:
        return CorrelationResponse(available=False)

    # Sort by score descending, then by time proximity ascending
    scored.sort(key=lambda x: (-x[1], x[2]))
    top = scored[:_MAX_CLUSTER_MEMBERS]

    # ── 6. Identify cluster type ──────────────────────────────────────────────
    all_providers = {provider_p}
    all_domains = {domain_p}
    for cand, _, _, _ in top:
        pm = cand.provider_metadata or {}
        rt = (pm.get("record_type") or "").lower()
        all_providers.add(_derive_provider(rt))
        all_domains.add(_get_risk_domain(rt, cand.field_path))

    cluster_type = _identify_cluster_type(all_providers, all_domains)

    # ── 7. Assign confidence ──────────────────────────────────────────────────
    conf_input = [(c, s, d) for c, s, d, _ in top]
    confidence = _assign_confidence(conf_input, primary.record_identifier or "")

    # ── 8. Build output ───────────────────────────────────────────────────────
    time_window_minutes = max((int(d) for _, _, d, _ in top), default=1)
    time_window_minutes = max(time_window_minutes, 1)

    # Unique signals (preserve insertion order, de-dup)
    seen: set[str] = set()
    all_signals: list[str] = []
    for _, _, _, sigs in top:
        for s in sigs:
            if s not in seen:
                seen.add(s)
                all_signals.append(s)

    # Recommended review from the matched template
    recommended_review = [
        "Confirm whether these changes were part of a planned deployment, migration, or maintenance window.",
        "Review each change individually and acknowledge, mark expected, or investigate as needed.",
    ]
    for tmpl in _CLUSTER_TEMPLATES:
        if tmpl["type"] == cluster_type:
            recommended_review = tmpl["recommended_review"]
            break

    # Related change items — no raw values
    related_items: list[CorrelationChangeItem] = []
    for cand, _, _, _ in top:
        pm = cand.provider_metadata or {}
        rt = (pm.get("record_type") or "").lower()
        cand_time = cand.created_at
        if cand_time.tzinfo is None:
            cand_time = cand_time.replace(tzinfo=timezone.utc)
        related_items.append(
            CorrelationChangeItem(
                id=cand.id,
                provider=_derive_provider(rt),
                risk_level=cand.risk_level or "unknown",
                record_type=rt or None,
                title=_safe_title(cand),
                detected_at=cand_time,
                url=f"/changes/{cand.id}",
            )
        )

    cluster_titles = {
        "deployment_routing": "Possible deployment or release-related changes",
        "payments_commerce":  "Possible checkout or commerce workflow changes",
        "edge_security":      "Possible edge or security posture changes",
        "auth_access":        "Possible access-control posture changes",
        "data_protection":    "Possible data-access posture changes",
        "provider_local":     "Multiple related changes on this resource",
        "unknown":            "Possible related configuration changes",
    }
    title = cluster_titles.get(cluster_type, "Possible related configuration changes")

    prov_labels = [
        _derive_provider((c.provider_metadata or {}).get("record_type") or "")
        for c, _, _, _ in top
    ]
    summary = _build_summary(cluster_type, len(top), [provider_p] + prov_labels, time_window_minutes)

    cid = _cluster_id([primary.id] + [c.id for c, _, _, _ in top])

    return CorrelationResponse(
        available=True,
        primary_cluster=PrimaryCluster(
            cluster_id=cid,
            title=title,
            summary=summary,
            confidence=confidence,
            cluster_type=cluster_type,
            time_window_minutes=time_window_minutes,
            signals=all_signals[:8],
            recommended_review=recommended_review,
            related_changes=related_items,
        ),
    )
