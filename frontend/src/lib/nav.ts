/**
 * nav.ts — central navigation config for ConfigTrace's two product modes.
 *
 * M60.1 introduces a second product mode, "Security Exposure", alongside the
 * existing "Drift Detection" experience:
 *
 *   • Drift Detection   → "what changed" (timelines, needs review, blast radius)
 *   • Security Exposure → "what is dangerous right now"
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
   Security Exposure — MVP nav. Security-specific pages plus SHARED platform
   routes that reuse the existing Drift Detection routes.
   ────────────────────────────────────────────────────────────────────────── */

export const SECURITY_NAV: NavItem[] = [
  { label: "Security Overview", href: "/security" },
  { label: "Active Exposures", href: "/security/exposures" },
  { label: "Affected Assets", href: "/security/assets" },
  { label: "Exposure Timeline", href: "/security/timeline" },
  { label: "Incident Review", href: "/security/incident-review" },
  { label: "Reports", href: "/security/reports" },
  { label: "Coverage", href: "/security/coverage" },
  { label: "Security Rules", href: "/security/rules" },
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
 *   so clicking a shared item from Security Exposure keeps you in that mode.
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
