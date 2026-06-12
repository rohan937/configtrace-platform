/**
 * securityReportExport.ts — build a shareable Configuration Risk review packet
 * (M61.6, expanded in M62.7).
 *
 * Deterministic, frontend-only report generation from existing data:
 *   • GET /security/findings              (findings metadata)
 *   • GET /security/coverage   (M62.3)    (provider coverage quality)
 *   • GET /security/rules/settings (M61.7) (rule enabled/disabled state)
 *   • the static rule catalog + securityAssets grouping
 *
 * Output is a customer-facing "security exposure review packet" in Markdown,
 * plus metadata-only JSON and a findings CSV.
 *
 * Privacy / metadata-only invariants:
 *   • Never include evidence blobs, remediation blobs, secrets, tokens, payloads,
 *     webhook signing secrets, private keys, or raw rule internals.
 *   • Never export review-note bodies. (We do not even fetch them here.)
 *   • The only human-entered text included is a finding's acceptance reason,
 *     which is the intentional justification for an accepted risk.
 *   • Careful wording: "configuration exposure", "risky current state",
 *     "accepted risk", "snoozed", "resolved". Never breach/attack/compromise or
 *     compliance/SOC/SIEM certification claims.
 */

import type {
  SecurityFinding,
  SecurityFindingSeverity,
  SecurityCoverageProvider,
  SecurityRuleSetting,
} from "@/types";
import { groupFindingsByAsset, type AffectedAsset } from "@/lib/securityAssets";
import { findingInWindow, type TimeWindow } from "@/lib/securityIncidentReview";
import { SECURITY_RULES, type SecurityRuleMeta } from "@/lib/securityRuleCatalog";
import {
  SEVERITY_RANK,
  SEVERITY_LABEL,
  STATUS_LABEL,
  CONFIDENCE_LABEL,
} from "@/components/security/findingDisplay";
import { getProviderMeta } from "@/lib/providers";

export type ReportType = "summary" | "review_packet" | "rule_coverage_appendix";

export const REPORT_TYPE_LABEL: Record<ReportType, string> = {
  summary: "Configuration Risk Summary",
  review_packet: "Review Packet",
  rule_coverage_appendix: "Rule Coverage Appendix",
};

export interface ReportConfig {
  reportType: ReportType;
  periodLabel: string;
  /** epoch ms inclusive; null = all time (no period filter). */
  start: number | null;
  end: number | null;
  provider: string; // "all" or a provider id
  severity: string; // "all" or a severity
  includeActive: boolean;
  includeResolved: boolean;
  includeAcceptedRisk: boolean;
  includeSnoozed: boolean;
  includeAssets: boolean;
  includeRuleCoverage: boolean;
  includeActivitySummary: boolean;
  includeCoverage: boolean; // M62.7: provider coverage section (M62.3 data)
  includeConfidence: boolean; // M62.7: rule confidence section (M62.4 data)
  includeRuleSettings: boolean; // M62.7: reflect enabled/disabled (M61.7 data)
  rulePackName?: string; // M63.3: active rule pack name (header traceability)
  rulePackVersion?: string; // M63.3: active rule pack version
}

export const DEFAULT_REPORT_CONFIG: ReportConfig = {
  reportType: "review_packet",
  periodLabel: "Last 7 days",
  start: null,
  end: null,
  provider: "all",
  severity: "all",
  includeActive: true,
  includeResolved: false,
  includeAcceptedRisk: true,
  includeSnoozed: true,
  includeAssets: true,
  includeRuleCoverage: true,
  includeActivitySummary: true,
  includeCoverage: true,
  includeConfidence: true,
  includeRuleSettings: true,
};

export interface CoverageRow {
  provider: string;
  coverage_status: string;
  observed_record_types: string[];
  missing_record_types: string[];
  active_rules: number;
  disabled_rules: number;
  recommendation: string;
  diagnostic_status: string; // M62.8
}

export interface ReportModel {
  generatedAtIso: string;
  config: ReportConfig;
  findings: SecurityFinding[]; // filtered + sorted, in scope
  summary: {
    active: number;
    critical: number; // active critical
    high: number; // active high
    acceptedRisks: number;
    snoozed: number;
    resolvedInPeriod: number;
    resolved: number; // alias of resolvedInPeriod for report clarity
    affectedAssets: number;
    providersCovered: number;
    providersGoodCoverage: number;
    providersLimitedCoverage: number;
    disabledRules: number;
    rulesEvaluated: number;
  };
  reviewStatus: {
    activeUnreviewed: number;
    acknowledgedActive: number; // active findings with a recorded review action
    acceptedRisk: number;
    snoozed: number;
    resolved: number;
  };
  confidence: {
    high: number;
    medium: number;
    low: number;
    criticalHighActive: SecurityFinding[]; // active critical/high, sorted
  };
  coverage: CoverageRow[];
  ruleSettingsByKey: Record<string, boolean>; // rule_key -> enabled
  statusBreakdown: { status: string; count: number }[];
  severityBreakdown: { severity: string; count: number }[];
  providerBreakdown: { provider: string; count: number }[];
  assets: AffectedAsset[];
  ruleCoverage: SecurityRuleMeta[];
  followUps: string[];
}

export interface ReportExtras {
  coverage?: SecurityCoverageProvider[] | null;
  ruleSettings?: SecurityRuleSetting[] | null;
}

const INCLUDED_STATUSES = (c: ReportConfig): Set<string> => {
  const s = new Set<string>();
  if (c.includeActive) s.add("active");
  if (c.includeResolved) s.add("resolved");
  if (c.includeAcceptedRisk) s.add("accepted_risk");
  if (c.includeSnoozed) s.add("snoozed");
  return s;
};

function ts(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/** Deterministic UTC timestamp formatting for report output. */
export function fmtUtc(iso: string | null | undefined): string {
  const t = ts(iso);
  if (t === null) return "—";
  const d = new Date(t);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

function severityRank(sev: string): number {
  return SEVERITY_RANK[sev as SecurityFindingSeverity] ?? 99;
}

// ── Model ──────────────────────────────────────────────────────────────────────

export function buildReportModel(
  allFindings: SecurityFinding[],
  config: ReportConfig,
  generatedAtIso: string,
  extras: ReportExtras = {},
): ReportModel {
  const statuses = INCLUDED_STATUSES(config);
  const hasWindow = config.start !== null && config.end !== null;
  const win: TimeWindow = { start: config.start ?? 0, end: config.end ?? 0 };

  const findings = allFindings
    .filter((f) => statuses.has(f.status))
    .filter((f) => config.provider === "all" || f.provider === config.provider)
    .filter((f) => config.severity === "all" || f.severity === config.severity)
    .filter((f) => (hasWindow ? findingInWindow(f, win) : true))
    .sort((a, b) => {
      const r = severityRank(a.severity) - severityRank(b.severity);
      if (r !== 0) return r;
      return (ts(b.last_seen_at) ?? 0) - (ts(a.last_seen_at) ?? 0);
    });

  const active = findings.filter((f) => f.status === "active");
  const acceptedRisks = findings.filter((f) => f.status === "accepted_risk");
  const snoozed = findings.filter((f) => f.status === "snoozed");
  const resolvedInPeriod = findings.filter(
    (f) => f.status === "resolved" && (!hasWindow || (ts(f.resolved_at) !== null && ts(f.resolved_at)! >= win.start && ts(f.resolved_at)! <= win.end)),
  );

  const assets = groupFindingsByAsset(findings);

  const ruleCoverage = SECURITY_RULES.filter(
    (r) =>
      (config.provider === "all" || r.provider === config.provider) &&
      (config.severity === "all" || r.severity === config.severity),
  ).sort((a, b) => {
    const r = severityRank(a.severity) - severityRank(b.severity);
    if (r !== 0) return r;
    return a.provider.localeCompare(b.provider) || a.key.localeCompare(b.key);
  });

  const countBy = (items: string[]) => {
    const m = new Map<string, number>();
    for (const k of items) m.set(k, (m.get(k) ?? 0) + 1);
    return m;
  };

  const statusMap = countBy(findings.map((f) => f.status));
  const sevMap = countBy(findings.map((f) => f.severity));
  const provMap = countBy(findings.map((f) => f.provider));

  const statusBreakdown = [...statusMap.entries()]
    .map(([status, count]) => ({ status, count }))
    .sort((a, b) => b.count - a.count || a.status.localeCompare(b.status));
  const severityBreakdown = [...sevMap.entries()]
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const providerBreakdown = [...provMap.entries()]
    .map(([provider, count]) => ({ provider, count }))
    .sort((a, b) => b.count - a.count || a.provider.localeCompare(b.provider));

  // ── Review status (counts only; never note bodies) ─────────────────────────
  const activeUnreviewed = active.filter((f) => !f.reviewed_at).length;
  const acknowledgedActive = active.filter((f) => !!f.reviewed_at).length;
  const reviewStatus = {
    activeUnreviewed,
    acknowledgedActive,
    acceptedRisk: acceptedRisks.length,
    snoozed: snoozed.length,
    resolved: resolvedInPeriod.length,
  };

  // ── Confidence (M62.4) ─────────────────────────────────────────────────────
  const confCount = (level: string) => findings.filter((f) => f.confidence === level).length;
  const criticalHighActive = active.filter(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  const confidence = {
    high: confCount("high"),
    medium: confCount("medium"),
    low: confCount("low"),
    criticalHighActive,
  };

  // ── Provider coverage (M62.3) ──────────────────────────────────────────────
  const coverageSource = config.includeCoverage ? extras.coverage ?? [] : [];
  const coverage: CoverageRow[] = coverageSource
    .filter((p) => config.provider === "all" || p.provider === config.provider)
    .map((p) => ({
      provider: p.provider,
      coverage_status: p.coverage_status,
      observed_record_types: p.observed_record_types ?? [],
      missing_record_types: p.missing_record_types ?? [],
      active_rules: p.active_rules ?? 0,
      disabled_rules: p.disabled_rules ?? 0,
      recommendation: p.recommendation ?? "",
      diagnostic_status: p.diagnostic_status ?? "ok",
    }))
    .sort((a, b) => a.provider.localeCompare(b.provider));

  const providersGoodCoverage = coverage.filter((c) => c.coverage_status === "good").length;
  const providersLimitedCoverage = coverage.filter((c) => c.coverage_status === "limited").length;

  // ── Rule settings (M61.7) ──────────────────────────────────────────────────
  const ruleSettingsByKey: Record<string, boolean> = {};
  let disabledRules = 0;
  if (config.includeRuleSettings) {
    for (const rs of extras.ruleSettings ?? []) {
      ruleSettingsByKey[rs.rule_key] = rs.enabled;
      if (!rs.enabled) disabledRules += 1;
    }
  }

  const summary = {
    active: active.length,
    critical: active.filter((f) => f.severity === "critical").length,
    high: active.filter((f) => f.severity === "high").length,
    acceptedRisks: acceptedRisks.length,
    snoozed: snoozed.length,
    resolvedInPeriod: resolvedInPeriod.length,
    resolved: resolvedInPeriod.length,
    affectedAssets: assets.length,
    providersCovered: provMap.size,
    providersGoodCoverage,
    providersLimitedCoverage,
    disabledRules,
    rulesEvaluated: ruleCoverage.length,
  };

  // ── Deterministic, context-aware follow-up checklist ───────────────────────
  const followUps: string[] = [];
  if (summary.critical + summary.high > 0) followUps.push("Review critical/high active risks.");
  if (summary.acceptedRisks > 0) followUps.push("Confirm accepted risks still have owners and valid expiry dates.");
  if (summary.snoozed > 0) followUps.push("Revisit snoozed findings before expiry.");
  if (providersLimitedCoverage > 0) followUps.push("Review provider coverage gaps.");
  if (disabledRules > 0) followUps.push("Confirm disabled rules are intentional.");
  if (activeUnreviewed > 0) followUps.push("Add review notes or acknowledgement for unreviewed exposures.");
  followUps.push("Re-run sync after remediation.");

  return {
    generatedAtIso,
    config,
    findings,
    summary,
    reviewStatus,
    confidence,
    coverage,
    ruleSettingsByKey,
    statusBreakdown,
    severityBreakdown,
    providerBreakdown,
    assets,
    ruleCoverage,
    followUps,
  };
}

// ── Section flags by report type ─────────────────────────────────────────────

interface SectionFlags {
  executive: boolean;
  reviewStatus: boolean;
  breakdowns: boolean;
  openCritHigh: boolean;
  findingsTable: boolean;
  assets: boolean;
  acceptedRegister: boolean;
  snoozedRegister: boolean;
  confidence: boolean;
  providerCoverage: boolean;
  ruleCoverage: boolean;
  followUp: boolean;
}

function sectionFlags(c: ReportConfig): SectionFlags {
  const appendix = c.reportType === "rule_coverage_appendix";
  const packet = c.reportType === "review_packet";
  return {
    executive: true,
    reviewStatus: !appendix && c.includeActivitySummary,
    breakdowns: packet,
    openCritHigh: !appendix,
    findingsTable: packet,
    assets: !appendix && c.includeAssets,
    acceptedRegister: !appendix && c.includeAcceptedRisk,
    snoozedRegister: !appendix && c.includeSnoozed,
    confidence: c.includeConfidence && (packet || appendix),
    providerCoverage: c.includeCoverage,
    ruleCoverage: c.includeRuleCoverage && (packet || appendix),
    followUp: !appendix,
  };
}

// ── Markdown ────────────────────────────────────────────────────────────────────

/** Escape a value for use inside a Markdown table cell. */
function mdCell(v: string | null | undefined): string {
  return (v ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim() || "—";
}

function sevLabel(sev: string): string {
  return SEVERITY_LABEL[sev as SecurityFindingSeverity] ?? sev;
}
function statusLabel(status: string): string {
  return STATUS_LABEL[status] ?? status;
}
function provLabel(provider: string): string {
  return getProviderMeta(provider).shortLabel;
}
function confLabel(conf: string | null | undefined): string {
  if (!conf) return "—";
  return CONFIDENCE_LABEL[conf] ?? conf;
}
function coverageLabel(status: string): string {
  const map: Record<string, string> = {
    good: "Good",
    limited: "Limited",
    not_synced: "Not synced",
    needs_attention: "Needs attention",
    not_connected: "Not connected",
  };
  return map[status] ?? status;
}
function diagnosticLabel(status: string): string {
  const map: Record<string, string> = {
    ok: "OK",
    needs_sync: "Needs sync",
    missing_metadata: "Missing metadata",
    permissions_likely_limited: "Permissions likely limited",
    provider_not_connected: "Not connected",
    provider_attention_needed: "Attention needed",
  };
  return map[status] ?? status;
}

function header(model: ReportModel, L: string[]): void {
  const c = model.config;
  L.push("# ConfigTrace — Configuration Risk Report");
  L.push("");
  L.push(`_${REPORT_TYPE_LABEL[c.reportType]}_`);
  L.push("");
  L.push(`- Generated: ${fmtUtc(model.generatedAtIso)}`);
  if (c.rulePackVersion) {
    L.push(`- Rule pack: ${c.rulePackName ?? "configtrace_security_exposure"} · version ${c.rulePackVersion}`);
  }
  L.push(`- Period: ${c.periodLabel}${c.start && c.end ? ` (${fmtUtc(new Date(c.start).toISOString())} → ${fmtUtc(new Date(c.end).toISOString())})` : ""}`);
  const filters: string[] = [];
  filters.push(`provider: ${c.provider === "all" ? "all" : provLabel(c.provider)}`);
  filters.push(`severity: ${c.severity === "all" ? "all" : sevLabel(c.severity)}`);
  const inc = [
    c.includeActive && "active",
    c.includeAcceptedRisk && "accepted risk",
    c.includeSnoozed && "snoozed",
    c.includeResolved && "resolved",
  ].filter(Boolean);
  filters.push(`statuses: ${inc.length ? inc.join(", ") : "none"}`);
  L.push(`- Filters: ${filters.join(" · ")}`);
  L.push(`- Scope: metadata-only configuration exposure findings. This report does not inspect payloads, secrets, or customer data.`);
  L.push("");
}

function executiveSummary(model: ReportModel, L: string[]): void {
  const s = model.summary;
  L.push("## Executive posture summary");
  L.push("");
  L.push(`| Metric | Count |`);
  L.push(`| --- | ---: |`);
  L.push(`| Active risks | ${s.active} |`);
  L.push(`| Critical (active) | ${s.critical} |`);
  L.push(`| High (active) | ${s.high} |`);
  L.push(`| Accepted risks | ${s.acceptedRisks} |`);
  L.push(`| Snoozed findings | ${s.snoozed} |`);
  L.push(`| Resolved findings | ${s.resolved} |`);
  L.push(`| Affected assets | ${s.affectedAssets} |`);
  if (model.config.includeCoverage) {
    L.push(`| Providers with good coverage | ${s.providersGoodCoverage} |`);
    L.push(`| Providers with limited coverage | ${s.providersLimitedCoverage} |`);
  }
  if (model.config.includeRuleSettings) {
    L.push(`| Disabled rules | ${s.disabledRules} |`);
  }
  L.push(`| Rules evaluated | ${s.rulesEvaluated} |`);
  L.push("");
}

export function generateMarkdown(model: ReportModel): string {
  const c = model.config;
  const flags = sectionFlags(c);
  const L: string[] = [];

  header(model, L);

  if (flags.executive) executiveSummary(model, L);

  // Review status
  if (flags.reviewStatus) {
    const r = model.reviewStatus;
    L.push("## Review status");
    L.push("");
    L.push(`- Active unreviewed: ${r.activeUnreviewed}`);
    L.push(`- Acknowledged active: ${r.acknowledgedActive}`);
    L.push(`- Accepted risk: ${r.acceptedRisk}`);
    L.push(`- Snoozed: ${r.snoozed}`);
    L.push(`- Resolved: ${r.resolved}`);
    L.push("");
    L.push("Review-note text is intentionally excluded from this export; only review status counts are shown.");
    L.push("");
  }

  // Breakdowns (review packet only)
  if (flags.breakdowns) {
    L.push("## Current exposure summary");
    L.push("");
    L.push("**Status breakdown**");
    L.push("");
    if (model.statusBreakdown.length) {
      for (const b of model.statusBreakdown) L.push(`- ${statusLabel(b.status)}: ${b.count}`);
    } else L.push("- No findings in scope.");
    L.push("");
    L.push("**Severity breakdown**");
    L.push("");
    if (model.severityBreakdown.length) {
      for (const b of model.severityBreakdown) L.push(`- ${sevLabel(b.severity)}: ${b.count}`);
    } else L.push("- No findings in scope.");
    L.push("");
    L.push("**Provider breakdown**");
    L.push("");
    if (model.providerBreakdown.length) {
      for (const b of model.providerBreakdown) L.push(`- ${provLabel(b.provider)}: ${b.count}`);
    } else L.push("- No findings in scope.");
    L.push("");
  }

  // Open critical/high findings
  if (flags.openCritHigh) {
    const list = model.confidence.criticalHighActive;
    L.push("## Open critical and high exposures");
    L.push("");
    if (list.length === 0) {
      L.push("No active critical or high exposures in scope.");
    } else {
      L.push(`| Severity | Provider | Title | Confidence | First detected | Last seen | Reviewed | Detail |`);
      L.push(`| --- | --- | --- | --- | --- | --- | --- | --- |`);
      for (const f of list) {
        L.push(
          `| ${mdCell(sevLabel(f.severity))} | ${mdCell(provLabel(f.provider))} | ${mdCell(f.title)} | ${mdCell(confLabel(f.confidence))} | ${fmtUtc(f.first_detected_at)} | ${fmtUtc(f.last_seen_at)} | ${f.reviewed_at ? "Reviewed" : "Unreviewed"} | /security/risks/${f.id} |`,
        );
      }
    }
    L.push("");
  }

  // Affected assets
  if (flags.assets) {
    L.push("## Affected assets");
    L.push("");
    if (model.assets.length === 0) {
      L.push("No affected assets in scope.");
    } else {
      L.push(`| Asset | Type | Provider | Highest severity | Findings | Top findings |`);
      L.push(`| --- | --- | --- | --- | ---: | --- |`);
      for (const a of model.assets) {
        const top = a.findings.slice(0, 3).map((f) => f.title).join("; ");
        L.push(`| ${mdCell(a.asset_label)} | ${mdCell(a.asset_type)} | ${mdCell(provLabel(a.provider))} | ${mdCell(sevLabel(a.highest_severity))} | ${a.exposure_count} | ${mdCell(top)} |`);
      }
    }
    L.push("");
  }

  // Full findings table (review packet)
  if (flags.findingsTable) {
    L.push("## Findings");
    L.push("");
    if (model.findings.length === 0) {
      L.push("No findings match this report configuration.");
    } else {
      L.push(`| Severity | Confidence | Status | Provider | Title | First detected | Last seen | Detail |`);
      L.push(`| --- | --- | --- | --- | --- | --- | --- | --- |`);
      for (const f of model.findings) {
        L.push(
          `| ${mdCell(sevLabel(f.severity))} | ${mdCell(confLabel(f.confidence))} | ${mdCell(statusLabel(f.status))} | ${mdCell(provLabel(f.provider))} | ${mdCell(f.title)} | ${fmtUtc(f.first_detected_at)} | ${fmtUtc(f.last_seen_at)} | /security/risks/${f.id} |`,
        );
      }
    }
    L.push("");
  }

  // Accepted risk register
  const accepted = model.findings.filter((f) => f.status === "accepted_risk");
  if (flags.acceptedRegister && accepted.length) {
    L.push("## Accepted risk register");
    L.push("");
    L.push("Accepted risk means the team is intentionally carrying this exposure until the listed date. It does not mean the exposure is fixed.");
    L.push("");
    L.push(`| Title | Severity | Provider | Accepted until | First detected | Reason | Detail |`);
    L.push(`| --- | --- | --- | --- | --- | --- | --- |`);
    for (const f of accepted) {
      L.push(`| ${mdCell(f.title)} | ${mdCell(sevLabel(f.severity))} | ${mdCell(provLabel(f.provider))} | ${fmtUtc(f.accepted_until)} | ${fmtUtc(f.first_detected_at)} | ${mdCell(f.acceptance_reason)} | /security/risks/${f.id} |`);
    }
    L.push("");
  }

  // Snoozed register
  const snoozedList = model.findings.filter((f) => f.status === "snoozed");
  if (flags.snoozedRegister && snoozedList.length) {
    L.push("## Snoozed findings register");
    L.push("");
    L.push("Snoozed findings are temporarily deferred. They are not resolved or accepted risk.");
    L.push("");
    L.push(`| Title | Severity | Provider | Snoozed until | First detected | Detail |`);
    L.push(`| --- | --- | --- | --- | --- | --- |`);
    for (const f of snoozedList) {
      L.push(`| ${mdCell(f.title)} | ${mdCell(sevLabel(f.severity))} | ${mdCell(provLabel(f.provider))} | ${fmtUtc(f.snoozed_until)} | ${fmtUtc(f.first_detected_at)} | /security/risks/${f.id} |`);
    }
    L.push("");
  }

  // Rule confidence (M62.4)
  if (flags.confidence) {
    const cf = model.confidence;
    L.push("## Rule confidence");
    L.push("");
    L.push("Confidence reflects how strongly a rule's metadata signal indicates a real exposure. Lower-confidence findings may warrant manual review before action.");
    L.push("");
    L.push(`- High confidence findings: ${cf.high}`);
    L.push(`- Medium confidence findings: ${cf.medium}`);
    if (cf.low > 0) L.push(`- Low confidence findings: ${cf.low}`);
    L.push("");
    if (cf.criticalHighActive.length) {
      L.push("**Critical/high active findings with confidence**");
      L.push("");
      L.push(`| Severity | Provider | Title | Confidence | False-positive guard |`);
      L.push(`| --- | --- | --- | --- | --- |`);
      for (const f of cf.criticalHighActive) {
        L.push(`| ${mdCell(sevLabel(f.severity))} | ${mdCell(provLabel(f.provider))} | ${mdCell(f.title)} | ${mdCell(confLabel(f.confidence))} | ${mdCell(f.false_positive_guard)} |`);
      }
      L.push("");
    }
  }

  // Provider coverage (M62.3)
  if (flags.providerCoverage) {
    L.push("## Provider coverage");
    L.push("");
    L.push("Coverage reflects whether connected providers are returning the configuration record types each rule set expects.");
    L.push("");
    if (model.coverage.length === 0) {
      L.push("No provider coverage data is available for this scope.");
    } else {
      L.push(`| Provider | Coverage | Diagnostic | Observed types | Missing types | Active rules | Disabled rules | Recommendation |`);
      L.push(`| --- | --- | --- | --- | --- | ---: | ---: | --- |`);
      for (const p of model.coverage) {
        L.push(
          `| ${mdCell(provLabel(p.provider))} | ${mdCell(coverageLabel(p.coverage_status))} | ${mdCell(diagnosticLabel(p.diagnostic_status))} | ${mdCell(p.observed_record_types.join(", "))} | ${mdCell(p.missing_record_types.join(", "))} | ${p.active_rules} | ${p.disabled_rules} | ${mdCell(p.recommendation)} |`,
        );
      }
    }
    L.push("");
  }

  // Rule coverage catalog
  if (flags.ruleCoverage) {
    L.push("## Rule coverage");
    L.push("");
    L.push("All rules are metadata-only: they evaluate provider configuration, never payloads or secrets.");
    L.push("");
    if (model.ruleCoverage.length === 0) {
      L.push("No rules match the selected provider/severity.");
    } else {
      const showState = c.includeRuleSettings;
      L.push(`| Provider | Rule key | Severity | Confidence | Category |${showState ? " Status |" : ""}`);
      L.push(`| --- | --- | --- | --- | --- |${showState ? " --- |" : ""}`);
      for (const r of model.ruleCoverage) {
        const enabled = model.ruleSettingsByKey[r.key];
        const state = enabled === false ? "Disabled" : "Enabled";
        L.push(
          `| ${mdCell(provLabel(r.provider))} | ${mdCell(r.key)} | ${mdCell(sevLabel(r.severity))} | ${mdCell(confLabel(r.confidence))} | ${mdCell(r.category)} |${showState ? ` ${state} |` : ""}`,
        );
      }
    }
    L.push("");
  }

  // Follow-up checklist (deterministic, context-aware)
  if (flags.followUp) {
    L.push("## Suggested follow-up");
    L.push("");
    for (const item of model.followUps) L.push(`- ${item}`);
    L.push("");
  }

  // Disclaimer (always)
  L.push("## Disclaimer");
  L.push("");
  L.push(
    "This report summarizes configuration exposure findings detected from connected provider metadata. It does not inspect payloads, secrets, or customer data, and it does not claim breach detection or formal compliance certification. It is intended for internal review and customer feedback.",
  );
  L.push("");

  return L.join("\n");
}

/** Compact executive summary + follow-up checklist only (for "Copy executive summary"). */
export function generateExecutiveSummaryMarkdown(model: ReportModel): string {
  const L: string[] = [];
  header(model, L);
  executiveSummary(model, L);
  L.push("## Suggested follow-up");
  L.push("");
  for (const item of model.followUps) L.push(`- ${item}`);
  L.push("");
  L.push(
    "_Configuration exposure summary from connected provider metadata. Not a breach-detection or formal compliance certification report._",
  );
  L.push("");
  return L.join("\n");
}

// ── JSON ────────────────────────────────────────────────────────────────────────

/** Safe, metadata-only JSON bundle (no evidence/remediation/notes). */
export function generateJSON(model: ReportModel): string {
  const c = model.config;
  const out = {
    report_type: c.reportType,
    rule_pack_name: c.rulePackName ?? null,
    rule_pack_version: c.rulePackVersion ?? null,
    generated_at: model.generatedAtIso,
    period: c.periodLabel,
    filters: {
      provider: c.provider,
      severity: c.severity,
      include: {
        active: c.includeActive,
        resolved: c.includeResolved,
        accepted_risk: c.includeAcceptedRisk,
        snoozed: c.includeSnoozed,
        coverage: c.includeCoverage,
        confidence: c.includeConfidence,
        rule_settings: c.includeRuleSettings,
      },
    },
    summary: model.summary,
    review_status: model.reviewStatus,
    confidence_summary: {
      high: model.confidence.high,
      medium: model.confidence.medium,
      low: model.confidence.low,
    },
    status_breakdown: model.statusBreakdown,
    severity_breakdown: model.severityBreakdown,
    provider_breakdown: model.providerBreakdown,
    assets: c.includeAssets
      ? model.assets.map((a) => ({
          asset_label: a.asset_label,
          asset_type: a.asset_type,
          provider: a.provider,
          highest_severity: a.highest_severity,
          exposure_count: a.exposure_count,
          active_count: a.active_count,
          accepted_count: a.accepted_count,
          snoozed_count: a.snoozed_count,
          resolved_count: a.resolved_count,
          top_finding_titles: a.findings.slice(0, 3).map((f) => f.title),
        }))
      : [],
    findings: model.findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      confidence: f.confidence,
      status: f.status,
      provider: f.provider,
      title: f.title,
      finding_key: f.finding_key,
      first_detected_at: f.first_detected_at,
      last_seen_at: f.last_seen_at,
      resolved_at: f.resolved_at,
      reviewed_at: f.reviewed_at,
      accepted_until: f.accepted_until,
      snoozed_until: f.snoozed_until,
      acceptance_reason: f.status === "accepted_risk" ? f.acceptance_reason : null,
      link_path: `/security/risks/${f.id}`,
    })),
    provider_coverage: c.includeCoverage
      ? model.coverage.map((p) => ({
          provider: p.provider,
          coverage_status: p.coverage_status,
          diagnostic_status: p.diagnostic_status,
          observed_record_types: p.observed_record_types,
          missing_record_types: p.missing_record_types,
          active_rules: p.active_rules,
          disabled_rules: p.disabled_rules,
          recommendation: p.recommendation,
        }))
      : [],
    rule_coverage: c.includeRuleCoverage
      ? model.ruleCoverage.map((r) => ({
          provider: r.provider,
          key: r.key,
          severity: r.severity,
          confidence: r.confidence,
          category: r.category,
          enabled: c.includeRuleSettings ? model.ruleSettingsByKey[r.key] !== false : undefined,
          metadata_only: true,
        }))
      : [],
  };
  return JSON.stringify(out, null, 2);
}

// ── CSV ────────────────────────────────────────────────────────────────────────

function csvCell(v: string | null | undefined): string {
  const s = v ?? "";
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Findings CSV (metadata-only columns). */
export function generateFindingsCSV(model: ReportModel): string {
  const header = [
    "severity",
    "confidence",
    "status",
    "provider",
    "title",
    "finding_key",
    "first_detected_at",
    "last_seen_at",
    "resolved_at",
    "reviewed_at",
    "accepted_until",
    "snoozed_until",
    "link_path",
  ];
  const rows = model.findings.map((f) =>
    [
      f.severity,
      f.confidence,
      f.status,
      f.provider,
      f.title,
      f.finding_key,
      f.first_detected_at ?? "",
      f.last_seen_at ?? "",
      f.resolved_at ?? "",
      f.reviewed_at ?? "",
      f.accepted_until ?? "",
      f.snoozed_until ?? "",
      `/security/risks/${f.id}`,
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.join(","), ...rows].join("\r\n");
}

/** Filename stem like configtrace-security-report-2026-06-08. */
export function reportFileStem(generatedAtIso: string): string {
  const d = new Date(generatedAtIso);
  const pad = (n: number) => String(n).padStart(2, "0");
  const ymd = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  return `configtrace-security-report-${ymd}`;
}
