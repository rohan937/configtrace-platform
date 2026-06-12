/**
 * securityPostureSummary.ts — derive the dashboard Configuration Risk summary (M62.6).
 *
 * Pure and deterministic: given data already fetched from existing APIs, it
 * returns compact posture metrics + flags for the main dashboard card. No
 * backend, no AI, no fake data — counts come from real findings/coverage only.
 *
 * Wording stays conservative: this summarizes "risky current states", never
 * claims a system is safe/secure/compliant.
 */

import type {
  Integration,
  SecurityFinding,
  SecurityCoverageProvider,
  SecurityDemoDataStatus,
} from "@/types";

export interface PostureSummary {
  activeCount: number;
  criticalActiveCount: number;
  highActiveCount: number;
  acceptedCount: number;
  snoozedCount: number;
  needsReviewCount: number; // active findings without a review timestamp
  coverage: {
    good: number;
    limited: number;
    not_connected: number;
    needs_attention: number; // not_synced + needs_attention
  };
  connected: boolean; // at least one real (non-demo, non-deleted) integration
  demoLoaded: boolean;
  hasAnyData: boolean; // any findings present (real or demo)
  hasCriticalOrHigh: boolean;
  hasLimitedCoverage: boolean;
}

export interface PostureInputs {
  integrations: Integration[] | null;
  findings: SecurityFinding[] | null; // sample across statuses (page_size ~100)
  activeTotal: number | null; // accurate active total from a status=active query
  coverage: SecurityCoverageProvider[] | null;
  demo: SecurityDemoDataStatus | null;
}

function realIntegrations(integrations: Integration[] | null): Integration[] {
  return (integrations ?? []).filter(
    (i) => i.provider !== "demo" && i.status !== "deleted",
  );
}

export function buildPostureSummary(inp: PostureInputs): PostureSummary {
  const findings = inp.findings ?? [];
  const active = findings.filter((f) => f.status === "active");

  const criticalActiveCount = active.filter((f) => f.severity === "critical").length;
  const highActiveCount = active.filter((f) => f.severity === "high").length;
  const needsReviewCount = active.filter((f) => f.reviewed_at == null).length;
  const acceptedCount = findings.filter((f) => f.status === "accepted_risk").length;
  const snoozedCount = findings.filter((f) => f.status === "snoozed").length;

  // Prefer the accurate active total when available, else the sample count.
  const activeCount = inp.activeTotal ?? active.length;

  const cov = { good: 0, limited: 0, not_connected: 0, needs_attention: 0 };
  for (const p of inp.coverage ?? []) {
    if (p.coverage_status === "good") cov.good += 1;
    else if (p.coverage_status === "limited") cov.limited += 1;
    else if (p.coverage_status === "not_connected") cov.not_connected += 1;
    else cov.needs_attention += 1; // not_synced + needs_attention
  }

  const connected = realIntegrations(inp.integrations).length > 0;
  const demoLoaded = !!inp.demo?.exists;
  const hasAnyData = findings.length > 0 || activeCount > 0;

  return {
    activeCount,
    criticalActiveCount,
    highActiveCount,
    acceptedCount,
    snoozedCount,
    needsReviewCount,
    coverage: cov,
    connected,
    demoLoaded,
    hasAnyData,
    hasCriticalOrHigh: criticalActiveCount > 0 || highActiveCount > 0,
    hasLimitedCoverage: cov.limited > 0,
  };
}
