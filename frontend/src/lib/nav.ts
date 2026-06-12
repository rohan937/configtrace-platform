/**
 * nav.ts — central navigation config for ConfigTrace's two product modes.
 *
 * M60.1 introduced a second product mode alongside "Drift Detection". M66.1
 * repositions that mode from "Security Exposure" to "Configuration Risk" — the
 * configuration-risk half of a future "Incident Signals" product:
 *
 *   • Drift Detection    → "what changed" (timelines, needs review, blast radius)
 *   • Configuration Risk → "which current provider settings are risky right now"
 *   • Incident Signals   → FUTURE: audit/activity-log correlation (gated, not live)
 *
 * The active mode is derived from the URL so deep links and refreshes are
 * preserved (see resolveMode). Shared platform pages (Integrations, Alerts,
 * Settings) reuse the EXISTING routes — providers and notifications are shared,
 * never duplicated.
 */

export type ProductMode = "drift" | "security";

export interface NavItem {
  label: string;
  href: string;
  /** Render as an indented sub-item under a parent section. */
  sub?: boolean;
  /** Marks a route that is shared across both modes (Integrations/Alerts/etc). */
  shared?: boolean;
  /**
   * Future/gated area: rendered non-clickable with a "Soon" badge. Used for the
   * Incident Signals roadmap entry, which is not yet implemented (M66.1).
   */
  comingSoon?: boolean;
  /**
   * Small inline badge next to the label (e.g. "Beta"). Used to mark a live but
   * early surface like Incident Signals (M66.4).
   */
  badge?: string;
}

/** Landing route for each mode (used by the mode switch). */
export const DRIFT_HOME = "/dashboard";
export const SECURITY_HOME = "/security";

/* ──────────────────────────────────────────────────────────────────────────
   Drift Detection — unchanged from the pre-M60.1 sidebar.
   ────────────────────────────────────────────────────────────────────────── */

export const DRIFT_NAV: NavItem[] = [
  { label: "Dashboard", href: "/dashboard" },
  { label: "Needs Review", href: "/needs-review" },
  { label: "Timeline", href: "/timeline" },
  { label: "Integrations", href: "/integrations" },
  { label: "Resources", href: "/resources" },
  { label: "Settings", href: "/settings" },
  { label: "Workspace", href: "/settings/workspace" },
  { label: "Members", href: "/settings/workspace/members", sub: true },
  { label: "Audit Log", href: "/settings/workspace/audit", sub: true },
  { label: "Billing", href: "/settings/workspace/billing", sub: true },
  { label: "Notifications", href: "/settings/workspace/notifications", sub: true },
  { label: "Trust Center", href: "/settings/workspace/data-access", sub: true },
  { label: "Policies", href: "/settings/workspace/policies", sub: true },
  { label: "Expected Changes", href: "/settings/workspace/expected-changes", sub: true },
];

/* ──────────────────────────────────────────────────────────────────────────
   Configuration Risk — security nav (repositioned in M66.1). Configuration-risk
   pages plus a gated "Incident Signals" roadmap entry and SHARED platform
   routes that reuse the existing Drift Detection routes.

   Route notes (M66.1): /security/exposures → /security/risks and
   /security/incident-review → /security/cases (old routes redirect). The
   Coverage page keeps its /security/coverage route — that path is also the
   backend API endpoint — but is relabeled "Data Sources".
   ────────────────────────────────────────────────────────────────────────── */

export const SECURITY_NAV: NavItem[] = [
  { label: "Security Overview", href: "/security" },
  { label: "Configuration Risks", href: "/security/risks" },
  { label: "Affected Assets", href: "/security/assets" },
  { label: "Risk Timeline", href: "/security/timeline" },
  { label: "Cases", href: "/security/cases" },
  { label: "Reports", href: "/security/reports" },
  { label: "Data Sources", href: "/security/coverage" },
  { label: "Risk Rules", href: "/security/rules" },
  { label: "Beta Analytics", href: "/security/beta-analytics" },
  { label: "Demo Script", href: "/security/demo-script" },
  // Incident Signals — live in GitHub beta (M66.4). Control-plane review signals
  // generated from normalized GitHub audit activity (M66.2/M66.3). Not breach
  // detection — see the page's claim-discipline copy.
  { label: "Incident Signals", href: "/security/signals", badge: "Beta" },
  // Activity Events — GitHub beta evidence viewer (M66.5). Normalized GitHub
  // audit activity behind the signals; control-plane metadata, not detection.
  { label: "Activity Events", href: "/security/activity", badge: "Beta" },
  // Correlations — GitHub beta (M66.6). Configuration Risk × audit activity:
  // evidence for review, not breach detection.
  { label: "Correlations", href: "/security/correlations", badge: "Beta" },
  // Shared platform pages — reuse existing routes (no duplication).
  { label: "Integrations", href: "/integrations", shared: true },
  { label: "Alerts", href: "/settings/workspace/notifications", shared: true },
  { label: "Settings", href: "/settings", shared: true },
];

/* ──────────────────────────────────────────────────────────────────────────
   Mode resolution
   ────────────────────────────────────────────────────────────────────────── */

/** Routes that are unambiguously part of Drift Detection. */
const DRIFT_PREFIXES = [
  "/dashboard",
  "/needs-review",
  "/timeline",
  "/resources",
  "/changes",
];

/**
 * Resolve the active product mode for a pathname.
 *
 * - Any `/security…` URL  → "security" (so refresh/deep-link is preserved).
 * - A drift-specific URL  → "drift".
 * - A SHARED URL (Integrations/Settings/…) → `null`, meaning "keep whatever
 *   mode the user was last in". The Sidebar falls back to the persisted mode
 *   so clicking a shared item from Configuration Risk keeps you in that mode.
 */
export function resolveMode(pathname: string): ProductMode | null {
  if (pathname === SECURITY_HOME || pathname.startsWith("/security/")) {
    return "security";
  }
  if (
    DRIFT_PREFIXES.some(
      (p) => pathname === p || pathname.startsWith(p + "/"),
    )
  ) {
    return "drift";
  }
  return null; // shared page → caller decides via persisted mode
}

/** Routes whose active state requires an EXACT match (avoid over-matching). */
const EXACT_ONLY = new Set([DRIFT_HOME, "/settings", SECURITY_HOME]);

/** Whether a nav item should render as active for the current pathname. */
export function isNavActive(href: string, pathname: string): boolean {
  if (pathname === href) return true;
  if (EXACT_ONLY.has(href)) return false;
  return pathname.startsWith(href + "/");
}

export const navForMode = (mode: ProductMode): NavItem[] =>
  mode === "security" ? SECURITY_NAV : DRIFT_NAV;
