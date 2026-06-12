/**
 * securityBetaEvents.ts — first-party beta usage instrumentation (M63.1).
 *
 * A tiny, fire-and-forget client helper that records coarse Configuration Risk
 * usage events to our own backend (POST /security/beta-events). No third-party
 * analytics SDK, no blocking UI, and failures are swallowed silently so product
 * actions NEVER depend on tracking success.
 *
 * Privacy: a frontend allowlist mirrors the backend one. Only the allowlisted
 * keys with scalar values are sent; evidence, remediation, note bodies,
 * acceptance reasons, provider payloads, secrets, tokens, and raw query params
 * are never transmitted. This is for beta learning, not surveillance.
 */

import { postSecurityBetaEvent } from "@/lib/api";

export const SECURITY_BETA_EVENTS = [
  "security_page_viewed",
  "security_demo_seed_clicked",
  "security_demo_seed_completed",
  "security_demo_clear_clicked",
  "security_walkthrough_opened",
  "security_walkthrough_step_clicked",
  "security_onboarding_cta_clicked",
  "security_exposure_opened",
  "security_exposure_action_clicked",
  "security_exposure_action_completed",
  "security_note_added",
  "security_report_exported",
  "security_rule_toggled",
  "security_coverage_viewed",
  "security_incident_review_run",
  "security_asset_expanded",
] as const;

export type SecurityBetaEventName = (typeof SECURITY_BETA_EVENTS)[number];

const EVENT_SET = new Set<string>(SECURITY_BETA_EVENTS);

/** Allowlisted, non-sensitive metadata keys (mirrors the backend). */
const ALLOWED_METADATA_KEYS = new Set<string>([
  "provider",
  "severity",
  "status",
  "rule_key",
  "finding_id",
  "asset_type",
  "report_type",
  "demo_loaded",
  "checklist_item_id",
  "action",
  "result",
  "error_code",
  "route_group",
]);

const MAX_STR = 200;

/** Keep only allowlisted scalar values; truncate strings; drop everything else. */
export function sanitizeBetaMetadata(
  raw?: Record<string, unknown> | null,
): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  if (!raw || typeof raw !== "object") return out;
  for (const [key, value] of Object.entries(raw)) {
    if (!ALLOWED_METADATA_KEYS.has(key)) continue;
    if (typeof value === "boolean" || typeof value === "number") {
      out[key] = value;
    } else if (typeof value === "string") {
      out[key] = value.slice(0, MAX_STR);
    }
    // objects/arrays/null/undefined are dropped
  }
  return out;
}

export interface TrackOptions {
  /** Clerk token getter, e.g. useAuth().getToken. */
  getToken?: () => Promise<string | null>;
  /** Normalized page path (no sensitive query params). */
  pagePath?: string;
}

/**
 * Fire-and-forget: record a Configuration Risk beta event. Never throws, never
 * blocks, and returns immediately (the network call runs in the background).
 */
export function trackSecurityBetaEvent(
  eventName: SecurityBetaEventName,
  metadata?: Record<string, unknown> | null,
  options?: TrackOptions,
): void {
  // Guard: only known event names, and only in the browser.
  if (typeof window === "undefined") return;
  if (!EVENT_SET.has(eventName)) return;

  const payload = {
    event_name: eventName,
    page_path: options?.pagePath,
    metadata: sanitizeBetaMetadata(metadata),
  };

  // Run async without awaiting; swallow all errors.
  void (async () => {
    try {
      const token = options?.getToken ? await options.getToken() : null;
      await postSecurityBetaEvent(payload, token);
    } catch {
      /* tracking is best-effort — never surface to the user */
    }
  })();
}

/** Map a Security pathname to a coarse route_group (no IDs leaked). */
export function routeGroupFor(pathname: string | null): string | null {
  if (!pathname) return null;
  if (pathname === "/security") return "overview";
  if (/^\/security\/exposures\/[^/]+$/.test(pathname)) return "detail";
  if (pathname === "/security/risks") return "exposures";
  if (pathname === "/security/assets") return "assets";
  if (pathname === "/security/timeline") return "timeline";
  if (pathname === "/security/rules") return "rules";
  if (pathname === "/security/coverage") return "coverage";
  if (pathname === "/security/cases") return "incident-review";
  if (pathname === "/security/reports") return "reports";
  return null;
}

/** Normalize a path so dynamic IDs are templated, not stored verbatim. */
export function normalizeSecurityPath(pathname: string | null): string | null {
  if (!pathname) return null;
  if (/^\/security\/exposures\/[^/]+$/.test(pathname)) {
    return "/security/risks/[id]";
  }
  return pathname;
}

/** Extract the exposure finding id from a detail path, if present. */
export function exposureIdFromPath(pathname: string | null): string | null {
  if (!pathname) return null;
  const m = pathname.match(/^\/security\/exposures\/([^/]+)$/);
  return m ? m[1] : null;
}
