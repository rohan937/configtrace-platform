/**
 * securityExposure.ts — M60.2
 *
 * A frontend-only helper layer that re-interprets EXISTING ConfigTrace change /
 * integration data through a "Configuration Risk" lens. It does NOT call any new
 * backend, invent findings, or persist anything.
 *
 * Honesty rules (M60.2):
 *   - We summarise *security-relevant drift* from existing change data.
 *   - We never claim a "confirmed exposure" / "breach". The real, persistent
 *     active-exposure findings engine arrives in M60.3/M60.4.
 *   - Everything here is defensive around missing/legacy fields.
 *
 * Detection strategy (conservative + transparent):
 *   1. Prefer the STRUCTURED field `provider_metadata.record_type` — we know
 *      exactly which record types are security-relevant per provider.
 *   2. Fall back to keyword matching over field_path / record_identifier /
 *      risk_reason / the derived event title only when no record_type match.
 */

import type { ChangeListItem, Integration, RiskLevel } from "@/types";
import {
  getTimelineProvider,
  getTimelineCategory,
  getTimelineEventTitle,
} from "@/lib/timeline";
import {
  PROVIDER_IDS,
  getProviderMeta,
  type ProviderId,
} from "@/lib/providers";

// ── Severity ─────────────────────────────────────────────────────────────────

export type SecuritySeverity = "critical" | "high" | "medium" | "info";

/**
 * Map a change's existing risk_level onto a security severity.
 * Only `critical`/`high` are treated as exposure-grade in summaries.
 */
export function getSecuritySeverity(change: ChangeListItem): SecuritySeverity {
  switch (change.risk_level) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    default:
      return "info";
  }
}

// ── Structured record-type allow-list (preferred signal) ─────────────────────

/**
 * Exact `record_type` values that are inherently security-relevant.
 * (Lower-cased comparison.)
 */
const SECURITY_RECORD_TYPES: ReadonlySet<string> = new Set([
  // GitHub
  "github_branch_protection",
  "github_environment_protection",
  "github_webhook",
  "github_actions_secret",
  "github_deploy_key",
  // Stripe
  "stripe_webhook_endpoint",
  // Vercel
  "vercel_env_var",
  "vercel_domain",
  // Supabase
  "supabase_rls_status",
  "supabase_oauth_provider",
  "supabase_network_restriction",
  "supabase_api_config",
  // Shopify
  "shopify_webhook_subscription",
  "shopify_app_scope_summary",
  // AWS (singletons)
  "aws_security_group",
  "aws_security_group_rule",
  "aws_internet_gateway",
]);

/**
 * `record_type` PREFIXES that are security-relevant (covers families).
 * (Lower-cased comparison.)
 */
const SECURITY_RECORD_PREFIXES: readonly string[] = [
  "aws_iam_",
  "aws_s3_",
  "aws_kms",
  "aws_secretsmanager",
  "aws_ssm",
  "aws_wafv2",
  "aws_route53",
  "aws_network_acl",
  "aws_vpc",
  "aws_subnet",
  "aws_route",
  "aws_cloudtrail",
  "aws_guardduty",
  "aws_securityhub",
  "firebase_auth",
  "supabase_auth",
];

// ── Keyword fallback (transparent, only when no record_type match) ───────────

/**
 * Conservative keyword list drawn from the M60.2 spec. Matched against
 * field_path, record_identifier, risk_reason, and the derived event title.
 */
const SECURITY_KEYWORDS: readonly string[] = [
  "webhook",
  "branch protection",
  "ruleset",
  "secret",
  "deploy key",
  "dns",
  "waf",
  "ssl",
  "tls",
  "security group",
  "ingress",
  "public",
  "rls",
  "auth",
  "oauth",
  "callback",
  "environment",
  "domain",
  "payment",
];

function recordType(change: ChangeListItem): string {
  return (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
}

/**
 * True when a change is security-relevant. Prefers the structured record_type
 * field; falls back to a conservative keyword scan. Defensive on every field.
 */
export function isSecurityRelevantChange(change: ChangeListItem): boolean {
  try {
    const rt = recordType(change);
    if (rt) {
      if (SECURITY_RECORD_TYPES.has(rt)) return true;
      if (SECURITY_RECORD_PREFIXES.some((p) => rt.startsWith(p))) return true;
      // Cloudflare DNS record types have no underscore (e.g. "a", "cname").
      // DNS is security-relevant (public-facing surface).
      if (!rt.includes("_")) return true;
    }

    // Keyword fallback over human-readable / path fields.
    const haystack = [
      change.field_path ?? "",
      change.record_identifier ?? "",
      change.risk_reason ?? "",
      safeTitle(change),
    ]
      .join(" ")
      .toLowerCase();

    return SECURITY_KEYWORDS.some((kw) => haystack.includes(kw));
  } catch {
    return false;
  }
}

function safeTitle(change: ChangeListItem): string {
  try {
    return getTimelineEventTitle(change);
  } catch {
    return "";
  }
}

/** Reuse the existing structured category (Network, Webhooks, IAM, …). */
export function getSecurityCategory(change: ChangeListItem): string | null {
  try {
    return getTimelineCategory(change);
  } catch {
    return null;
  }
}

// ── Overview metrics ─────────────────────────────────────────────────────────

export interface SecurityOverviewMetrics {
  /** Critical-risk security-relevant changes in the loaded window. */
  criticalCount: number;
  /** High-risk security-relevant changes in the loaded window. */
  highCount: number;
  /** Security-relevant changes still needing review. */
  needsSecurityReview: number;
  /** Active (non-deleted, non-error) connected providers. */
  connectedProviders: number;
  /** Security-relevant changes reviewed/resolved in the loaded window. */
  recentlyReviewed: number;
  /**
   * True when the change-derived counts are computed from a loaded "recent"
   * window rather than an exhaustive backend aggregate. Used to keep the UI
   * honest (counts reflect recent change data, not a findings engine).
   */
  windowed: boolean;
}

const RESOLVED_REVIEW_STATUSES = new Set(["acknowledged", "expected"]);

/**
 * Derive the Security Overview summary numbers from already-fetched data.
 * Every input is optional/defensive so a partial load still renders.
 */
export function deriveSecurityOverviewMetrics(args: {
  changes?: ChangeListItem[] | null;
  needsReviewChanges?: ChangeListItem[] | null;
  integrations?: Integration[] | null;
}): SecurityOverviewMetrics {
  const changes = Array.isArray(args.changes) ? args.changes : [];
  const needsReview = Array.isArray(args.needsReviewChanges)
    ? args.needsReviewChanges
    : [];
  const integrations = Array.isArray(args.integrations) ? args.integrations : [];

  const secChanges = changes.filter(isSecurityRelevantChange);

  const criticalCount = secChanges.filter((c) => c.risk_level === "critical").length;
  const highCount = secChanges.filter((c) => c.risk_level === "high").length;

  const needsSecurityReview = needsReview.filter(isSecurityRelevantChange).length;

  const connectedProviders = integrations.filter(
    (i) => i.status !== "deleted" && i.status !== "unknown",
  ).length;

  const recentlyReviewed = secChanges.filter(
    (c) =>
      c.review != null &&
      RESOLVED_REVIEW_STATUSES.has(c.review.review_status) &&
      c.review.reviewed_at != null,
  ).length;

  return {
    criticalCount,
    highCount,
    needsSecurityReview,
    connectedProviders,
    recentlyReviewed,
    windowed: true,
  };
}

// ── Security-relevant feed ───────────────────────────────────────────────────

export interface SecurityFeedItem {
  change: ChangeListItem;
  severity: SecuritySeverity;
  provider: string;
  providerLabel: string;
  title: string;
  category: string | null;
  reviewStatus: string | null;
}

/**
 * Build the "Recent security-relevant drift" feed: high/critical, security-
 * relevant changes, newest first. Returns at most `limit` items.
 */
export function buildSecurityFeed(
  changes: ChangeListItem[] | null | undefined,
  limit = 12,
): SecurityFeedItem[] {
  const list = Array.isArray(changes) ? changes : [];
  return list
    .filter(isSecurityRelevantChange)
    .filter((c) => c.risk_level === "critical" || c.risk_level === "high")
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
    .slice(0, limit)
    .map((change) => {
      const provider = safeProvider(change);
      return {
        change,
        severity: getSecuritySeverity(change),
        provider,
        providerLabel: getProviderMeta(provider).shortLabel,
        title: safeTitle(change) || change.record_identifier || "Configuration change",
        category: getSecurityCategory(change),
        reviewStatus: change.review?.review_status ?? null,
      };
    });
}

function safeProvider(change: ChangeListItem): string {
  try {
    return getTimelineProvider(change);
  } catch {
    return "unknown";
  }
}

// ── Provider security coverage ───────────────────────────────────────────────

export interface ProviderSecurityCoverage {
  providerId: ProviderId;
  label: string;
  shortLabel: string;
  connected: boolean;
  /** Display status of the matched integration, if connected. */
  status: string | null;
  lastSyncedAt: string | null;
  /** Security-relevant surfaces ConfigTrace monitors for this provider. */
  surfaces: string[];
  color: string;
}

/**
 * For every known provider, report whether it is connected and what
 * security-relevant surfaces ConfigTrace covers. Surfaces come from the
 * existing provider registry (`monitoredSurfaces`).
 */
export function getProviderSecurityCoverage(
  integrations: Integration[] | null | undefined,
): ProviderSecurityCoverage[] {
  const list = Array.isArray(integrations) ? integrations : [];

  return PROVIDER_IDS.map((pid) => {
    const meta = getProviderMeta(pid);
    // Newest active matching integration (ignore soft-deleted).
    const matches = list.filter(
      (i) => i.provider === pid && i.status !== "deleted",
    );
    const active = matches.find((i) => i.status === "active") ?? matches[0] ?? null;

    return {
      providerId: pid,
      label: meta.label,
      shortLabel: meta.shortLabel,
      connected: active != null,
      status: active?.status ?? null,
      lastSyncedAt: active?.last_synced_at ?? null,
      surfaces: meta.monitoredSurfaces ?? [],
      color: meta.color,
    };
  });
}

// ── Misc ─────────────────────────────────────────────────────────────────────

export const SECURITY_SEVERITY_COLOR: Record<SecuritySeverity, string> = {
  critical: "#e84040",
  high: "#f5632a",
  medium: "#f5a623",
  info: "#6b9cf8",
};

export function isExposureGrade(level: RiskLevel): boolean {
  return level === "critical" || level === "high";
}
