/**
 * securityReportExport.ts — build a shareable Security Exposure report (M61.6).
 *
 * Deterministic, frontend-only report generation from existing data
 * (GET /security/findings + the static rule catalog + securityAssets grouping).
 * Output is a customer/demo-friendly Markdown summary (plus optional JSON/CSV).
 *
 * Privacy / metadata-only invariants:
 *   • Never include evidence blobs, remediation blobs, secrets, tokens, payloads,
 *     or raw rule internals.
 *   • Never export review-note bodies. (We do not even fetch them here.)
 *   • The only human-entered text included is a finding's acceptance reason,
 *     which is the intentional justification for an accepted risk.
 *   • Careful wording: "configuration exposure", "risky current state",
 *     "accepted risk", "snoozed", "resolved". Never breach/attack/compromise or
 *     compliance/SOC/SIEM claims.
 */

import type { SecurityFinding, SecurityFindingSeverity } from "@/types";
import { groupFindingsByAsset, type AffectedAsset } from "@/lib/securityAssets";
import { findingInWindow, type TimeWindow } from "@/lib/securityIncidentReview";
import { SECURITY_RULES, type SecurityRuleMeta } from "@/lib/securityRuleCatalog";
import { SEVERITY_RANK, SEVERITY_LABEL, STATUS_LABEL } from "@/components/security/findingDisplay";
import { getProviderMeta } from "@/lib/providers";

export interface ReportConfig {
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
}

export const DEFAULT_REPORT_CONFIG: ReportConfig = {
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
};

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
    affectedAssets: number;
    providersCovered: number;
    rulesEvaluated: number;
  };
  statusBreakdown: { status: string; count: number }[];
  severityBreakdown: { severity: string; count: number }[];
  providerBreakdown: { provider: string; count: number }[];
  assets: AffectedAsset[];
  ruleCoverage: SecurityRuleMeta[];
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

  return {
    generatedAtIso,
    config,
    findings,
    summary: {
      active: active.length,
      critical: active.filter((f) => f.severity === "critical").length,
      high: active.filter((f) => f.severity === "high").length,
      acceptedRisks: acceptedRisks.length,
      snoozed: snoozed.length,
      resolvedInPeriod: resolvedInPeriod.length,
      affectedAssets: assets.length,
      providersCovered: provMap.size,
      rulesEvaluated: ruleCoverage.length,
    },
    statusBreakdown,
    severityBreakdown,
    providerBreakdown,
    assets,
    ruleCoverage,
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

export function generateMarkdown(model: ReportModel): string {
  const c = model.config;
  const L: string[] = [];

  // 1. Header
  L.push("# ConfigTrace — Security Exposure Report");
  L.push("");
  L.push(`- Generated: ${fmtUtc(model.generatedAtIso)}`);
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

  // 2. Executive summary
  const s = model.summary;
  L.push("## Executive summary");
  L.push("");
  L.push(`| Metric | Count |`);
  L.push(`| --- | ---: |`);
  L.push(`| Active exposures | ${s.active} |`);
  L.push(`| Critical (active) | ${s.critical} |`);
  L.push(`| High (active) | ${s.high} |`);
  L.push(`| Accepted risks | ${s.acceptedRisks} |`);
  L.push(`| Snoozed findings | ${s.snoozed} |`);
  L.push(`| Resolved in period | ${s.resolvedInPeriod} |`);
  L.push(`| Affected assets | ${s.affectedAssets} |`);
  L.push(`| Providers covered | ${s.providersCovered} |`);
  L.push(`| Rules evaluated | ${s.rulesEvaluated} |`);
  L.push("");

  // 3. Current exposure summary (breakdowns)
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

  // 4. Affected assets
  if (c.includeAssets) {
    L.push("## Affected assets");
    L.push("");
    if (model.assets.length === 0) {
      L.push("No affected assets in scope.");
    } else {
      L.push(`| Asset | Type | Provider | Highest severity | Findings |`);
      L.push(`| --- | --- | --- | --- | ---: |`);
      for (const a of model.assets) {
        L.push(`| ${mdCell(a.asset_label)} | ${mdCell(a.asset_type)} | ${mdCell(provLabel(a.provider))} | ${mdCell(sevLabel(a.highest_severity))} | ${a.exposure_count} |`);
      }
    }
    L.push("");
  }

  // 5. Findings table
  L.push("## Findings");
  L.push("");
  if (model.findings.length === 0) {
    L.push("No findings match this report configuration.");
  } else {
    L.push(`| Severity | Confidence | Status | Provider | Title | First detected | Last seen | Detail |`);
    L.push(`| --- | --- | --- | --- | --- | --- | --- | --- |`);
    for (const f of model.findings) {
      L.push(
        `| ${mdCell(sevLabel(f.severity))} | ${mdCell(f.confidence)} | ${mdCell(statusLabel(f.status))} | ${mdCell(provLabel(f.provider))} | ${mdCell(f.title)} | ${fmtUtc(f.first_detected_at)} | ${fmtUtc(f.last_seen_at)} | /security/exposures/${f.id} |`,
      );
    }
  }
  L.push("");

  // 6. Accepted risk / snoozed
  const accepted = model.findings.filter((f) => f.status === "accepted_risk");
  const snoozedList = model.findings.filter((f) => f.status === "snoozed");
  if ((c.includeAcceptedRisk && accepted.length) || (c.includeSnoozed && snoozedList.length)) {
    L.push("## Accepted risk and snoozed findings");
    L.push("");
    L.push("Accepted and snoozed findings are not fixed or resolved — they are intentionally carried or temporarily paused.");
    L.push("");
    if (c.includeAcceptedRisk && accepted.length) {
      L.push("**Accepted risk**");
      L.push("");
      L.push(`| Title | Provider | Accepted until | Reason |`);
      L.push(`| --- | --- | --- | --- |`);
      for (const f of accepted) {
        L.push(`| ${mdCell(f.title)} | ${mdCell(provLabel(f.provider))} | ${fmtUtc(f.accepted_until)} | ${mdCell(f.acceptance_reason)} |`);
      }
      L.push("");
    }
    if (c.includeSnoozed && snoozedList.length) {
      L.push("**Snoozed**");
      L.push("");
      L.push(`| Title | Provider | Snoozed until |`);
      L.push(`| --- | --- | --- |`);
      for (const f of snoozedList) {
        L.push(`| ${mdCell(f.title)} | ${mdCell(provLabel(f.provider))} | ${fmtUtc(f.snoozed_until)} |`);
      }
      L.push("");
    }
  }

  // 7. Rule coverage
  if (c.includeRuleCoverage) {
    L.push("## Rule coverage");
    L.push("");
    L.push("All rules are metadata-only: they evaluate provider configuration, never payloads or secrets.");
    L.push("");
    if (model.ruleCoverage.length === 0) {
      L.push("No rules match the selected provider/severity.");
    } else {
      L.push(`| Provider | Rule key | Severity | Category |`);
      L.push(`| --- | --- | --- | --- |`);
      for (const r of model.ruleCoverage) {
        L.push(`| ${mdCell(provLabel(r.provider))} | ${mdCell(r.key)} | ${mdCell(sevLabel(r.severity))} | ${mdCell(r.category)} |`);
      }
    }
    L.push("");
  }

  // (Optional) activity summary — counts only, never note bodies.
  if (c.includeActivitySummary) {
    const reviewed = model.findings.filter((f) => f.reviewed_at).length;
    L.push("## Review activity summary");
    L.push("");
    L.push(`- Findings with a recorded review action: ${reviewed}`);
    L.push(`- Accepted risk: ${model.summary.acceptedRisks}`);
    L.push(`- Snoozed: ${model.summary.snoozed}`);
    L.push(`- Resolved in period: ${model.summary.resolvedInPeriod}`);
    L.push("");
    L.push("Review-note text is intentionally excluded from this export.");
    L.push("");
  }

  // 8. Suggested follow-up checklist
  L.push("## Suggested follow-up");
  L.push("");
  L.push("- Review all critical active findings.");
  L.push("- Confirm accepted risks have owners and expiry dates.");
  L.push("- Revisit snoozed findings before their snooze expires.");
  L.push("- Check affected assets that carry multiple findings.");
  L.push("- Add review notes for unresolved critical/high findings.");
  L.push("- Re-run a sync after remediation to confirm exposures clear.");
  L.push("");

  // 9. Disclaimer
  L.push("## Disclaimer");
  L.push("");
  L.push(
    "This report summarizes configuration exposure findings detected from connected provider metadata. It does not inspect payloads, secrets, or customer data, and it does not claim breach detection. It is intended for internal review and customer feedback, not formal compliance certification.",
  );
  L.push("");

  return L.join("\n");
}

// ── JSON ────────────────────────────────────────────────────────────────────────

/** Safe, metadata-only JSON bundle (no evidence/remediation/notes). */
export function generateJSON(model: ReportModel): string {
  const out = {
    generated_at: model.generatedAtIso,
    period: model.config.periodLabel,
    filters: {
      provider: model.config.provider,
      severity: model.config.severity,
      include: {
        active: model.config.includeActive,
        resolved: model.config.includeResolved,
        accepted_risk: model.config.includeAcceptedRisk,
        snoozed: model.config.includeSnoozed,
      },
    },
    summary: model.summary,
    status_breakdown: model.statusBreakdown,
    severity_breakdown: model.severityBreakdown,
    provider_breakdown: model.providerBreakdown,
    assets: model.config.includeAssets
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
      accepted_until: f.accepted_until,
      snoozed_until: f.snoozed_until,
      detail_path: `/security/exposures/${f.id}`,
    })),
    rule_coverage: model.config.includeRuleCoverage
      ? model.ruleCoverage.map((r) => ({
          provider: r.provider,
          key: r.key,
          severity: r.severity,
          category: r.category,
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
    "accepted_until",
    "snoozed_until",
    "detail_path",
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
      f.accepted_until ?? "",
      f.snoozed_until ?? "",
      `/security/exposures/${f.id}`,
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
