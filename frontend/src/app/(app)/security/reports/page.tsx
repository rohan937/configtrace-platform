"use client";

/**
 * Security Reports (M61.6).
 *
 * Builds a customer/demo-friendly Configuration Risk report from existing
 * findings + the static rule catalog + securityAssets grouping, and exports it
 * as Markdown (plus optional JSON / findings CSV). Frontend-only, deterministic,
 * metadata-only — see lib/securityReportExport.ts for the privacy invariants.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@clerk/nextjs";

import type {
  SecurityFinding,
  SecurityFindingSeverity,
  SecurityCoverageProvider,
  SecurityRuleSetting,
} from "@/types";
import { getSecurityFindings, getSecurityCoverage, getSecurityRuleSettings, getSecurityRulePack, submitSecurityBetaFeedback } from "@/lib/api";
import type { SecurityRulePack, SecurityBetaFeedbackRating } from "@/types";
import { trackSecurityBetaEvent } from "@/lib/securityBetaEvents";
import { getProviderMeta } from "@/lib/providers";
import { SEVERITY_LABEL } from "@/components/security/findingDisplay";
import Link from "next/link";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import {
  type ReportConfig,
  type ReportType,
  REPORT_TYPE_LABEL,
  DEFAULT_REPORT_CONFIG,
  buildReportModel,
  generateMarkdown,
  generateExecutiveSummaryMarkdown,
  generateJSON,
  generateFindingsCSV,
  reportFileStem,
} from "@/lib/securityReportExport";

const FETCH_SIZE = 100;
const SEVERITY_OPTIONS: SecurityFindingSeverity[] = ["critical", "high", "medium", "low", "info"];

type PeriodMode = "24h" | "7d" | "30d" | "custom";
const PERIOD_HOURS: Record<Exclude<PeriodMode, "custom">, number> = {
  "24h": 24,
  "7d": 24 * 7,
  "30d": 24 * 30,
};
const PERIOD_LABEL: Record<PeriodMode, string> = {
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  custom: "Custom",
};

function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function SecurityReportsPage() {
  const { getToken } = useAuth();

  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [coverage, setCoverage] = useState<SecurityCoverageProvider[]>([]);
  const [ruleSettings, setRuleSettings] = useState<SecurityRuleSetting[]>([]);
  const [pack, setPack] = useState<SecurityRulePack | null>(null);
  const [total, setTotal] = useState(0);
  const [generatedAtIso, setGeneratedAtIso] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedExec, setCopiedExec] = useState(false);

  // M63.6 — post-export feedback prompt (optional, non-blocking, dismissible).
  const [feedbackVisible, setFeedbackVisible] = useState(false);
  const [feedbackFormat, setFeedbackFormat] = useState<string>("");
  const [feedbackRating, setFeedbackRating] = useState<SecurityBetaFeedbackRating | null>(null);
  const [feedbackComment, setFeedbackComment] = useState("");
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  const previewRef = useRef<HTMLPreElement>(null);

  // Controls
  const [reportType, setReportType] = useState<ReportType>(DEFAULT_REPORT_CONFIG.reportType);
  const [periodMode, setPeriodMode] = useState<PeriodMode>("7d");
  const [customStart, setCustomStart] = useState<string>(() => toLocalInput(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)));
  const [customEnd, setCustomEnd] = useState<string>(() => toLocalInput(new Date()));
  const [provider, setProvider] = useState<string>("all");
  const [severity, setSeverity] = useState<string>("all");
  const [inc, setInc] = useState({
    active: DEFAULT_REPORT_CONFIG.includeActive,
    resolved: DEFAULT_REPORT_CONFIG.includeResolved,
    acceptedRisk: DEFAULT_REPORT_CONFIG.includeAcceptedRisk,
    snoozed: DEFAULT_REPORT_CONFIG.includeSnoozed,
    assets: DEFAULT_REPORT_CONFIG.includeAssets,
    ruleCoverage: DEFAULT_REPORT_CONFIG.includeRuleCoverage,
    activitySummary: DEFAULT_REPORT_CONFIG.includeActivitySummary,
    coverage: DEFAULT_REPORT_CONFIG.includeCoverage,
    confidence: DEFAULT_REPORT_CONFIG.includeConfidence,
    ruleSettings: DEFAULT_REPORT_CONFIG.includeRuleSettings,
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      // Findings are required; coverage + rule settings are optional enrichers
      // and degrade gracefully so the report still renders if they fail.
      const [findingsRes, coverageRes, ruleRes, packRes] = await Promise.allSettled([
        getSecurityFindings({ page_size: FETCH_SIZE }, token),
        getSecurityCoverage(token),
        getSecurityRuleSettings(token),
        getSecurityRulePack(token),
      ]);

      if (findingsRes.status !== "fulfilled") {
        throw new Error("findings");
      }
      setFindings(findingsRes.value.items ?? []);
      setTotal(findingsRes.value.total ?? 0);
      setCoverage(coverageRes.status === "fulfilled" ? coverageRes.value.providers ?? [] : []);
      setRuleSettings(ruleRes.status === "fulfilled" ? ruleRes.value.items ?? [] : []);
      setPack(packRes.status === "fulfilled" ? packRes.value : null);
      setGeneratedAtIso(new Date().toISOString());
    } catch {
      setError("Could not load report data. Please try again.");
      setFindings([]);
      setCoverage([]);
      setRuleSettings([]);
      setPack(null);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  // Derive the report config from the controls.
  const config: ReportConfig = useMemo(() => {
    let start: number | null = null;
    let end: number | null = null;
    if (periodMode === "custom") {
      const s = customStart ? new Date(customStart).getTime() : NaN;
      const e = customEnd ? new Date(customEnd).getTime() : NaN;
      start = Number.isNaN(s) ? null : s;
      end = Number.isNaN(e) ? null : e;
    } else {
      end = Date.now();
      start = end - PERIOD_HOURS[periodMode] * 60 * 60 * 1000;
    }
    return {
      reportType,
      periodLabel: PERIOD_LABEL[periodMode],
      start,
      end,
      provider,
      severity,
      includeActive: inc.active,
      includeResolved: inc.resolved,
      includeAcceptedRisk: inc.acceptedRisk,
      includeSnoozed: inc.snoozed,
      includeAssets: inc.assets,
      includeRuleCoverage: inc.ruleCoverage,
      includeActivitySummary: inc.activitySummary,
      includeCoverage: inc.coverage,
      includeConfidence: inc.confidence,
      includeRuleSettings: inc.ruleSettings,
      rulePackName: pack?.name,
      rulePackVersion: pack?.version,
    };
  }, [reportType, periodMode, customStart, customEnd, provider, severity, inc, pack]);

  const model = useMemo(
    () =>
      buildReportModel(findings, config, generatedAtIso || new Date(0).toISOString(), {
        coverage,
        ruleSettings,
      }),
    [findings, config, generatedAtIso, coverage, ruleSettings],
  );
  const markdown = useMemo(() => generateMarkdown(model), [model]);

  const providerOptions = useMemo(
    () => [...new Set(findings.map((f) => f.provider))].sort(),
    [findings],
  );

  const fileStem = reportFileStem(generatedAtIso || new Date().toISOString());

  const FEEDBACK_DISMISS_KEY = "ct.securityReportFeedback.dismissed";

  const trackExport = useCallback(
    (action: string) => {
      trackSecurityBetaEvent(
        "security_report_exported",
        { action, report_type: config.reportType },
        { getToken, pagePath: "/security/reports" },
      );
      // M63.6 — surface the (optional) feedback prompt after a successful export,
      // unless the user dismissed/sent it before. Never blocks the download.
      setFeedbackFormat(action);
      let dismissed = false;
      try {
        dismissed = typeof window !== "undefined" && window.localStorage.getItem(FEEDBACK_DISMISS_KEY) === "1";
      } catch {
        dismissed = false;
      }
      if (!dismissed && !feedbackSent) {
        setFeedbackVisible(true);
      }
    },
    [getToken, config.reportType, feedbackSent],
  );

  const dismissFeedback = useCallback(() => {
    setFeedbackVisible(false);
    try {
      window.localStorage.setItem(FEEDBACK_DISMISS_KEY, "1");
    } catch {
      /* private mode — session state already hides it */
    }
  }, []);

  const sendFeedback = useCallback(async () => {
    if (!feedbackRating) return;
    setFeedbackBusy(true);
    setFeedbackError(null);
    try {
      const token = await getToken();
      await submitSecurityBetaFeedback(
        {
          feedback_type: "report_export",
          rating: feedbackRating,
          comment: feedbackComment.trim() || undefined,
          context: {
            report_type: config.reportType,
            export_format: feedbackFormat,
            finding_count: model.findings.length,
            active_count: model.summary.active,
            critical_count: model.summary.critical,
            high_count: model.summary.high,
          },
        },
        token,
      );
      setFeedbackSent(true);
      try {
        window.localStorage.setItem(FEEDBACK_DISMISS_KEY, "1");
      } catch {
        /* non-fatal */
      }
    } catch {
      setFeedbackError("Could not send feedback. Please try again.");
    } finally {
      setFeedbackBusy(false);
    }
  }, [feedbackRating, feedbackComment, getToken, config.reportType, feedbackFormat, model]);

  const onCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(markdown);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
      trackExport("markdown_copied");
    } catch {
      setError("Could not copy to clipboard. Use Download Markdown instead.");
    }
  }, [markdown, trackExport]);

  const onCopyExec = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(generateExecutiveSummaryMarkdown(model));
      setCopiedExec(true);
      window.setTimeout(() => setCopiedExec(false), 2000);
      trackExport("executive_summary_copied");
    } catch {
      setError("Could not copy to clipboard. Use Download Markdown instead.");
    }
  }, [model, trackExport]);

  // Section jump: scroll the Markdown preview to the first matching heading.
  const jumpTo = useCallback(
    (headings: string[]) => {
      const el = previewRef.current;
      if (!el) return;
      let idx = -1;
      for (const h of headings) {
        idx = markdown.indexOf(h);
        if (idx >= 0) break;
      }
      if (idx < 0) return;
      const linesBefore = markdown.slice(0, idx).split("\n").length - 1;
      const totalLines = Math.max(1, markdown.split("\n").length);
      el.scrollTop = (linesBefore / totalLines) * (el.scrollHeight - el.clientHeight);
    },
    [markdown],
  );

  const noData = findings.length === 0;
  const noMatches = !noData && model.findings.length === 0;

  const JUMP_TARGETS: { label: string; headings: string[] }[] = [
    { label: "Summary", headings: ["## Executive posture summary"] },
    { label: "Findings", headings: ["## Findings", "## Open critical and high exposures"] },
    { label: "Assets", headings: ["## Affected assets"] },
    { label: "Rules", headings: ["## Rule coverage", "## Rule confidence"] },
    { label: "Coverage", headings: ["## Provider coverage"] },
    { label: "Checklist", headings: ["## Suggested follow-up"] },
  ];

  return (
    <div>
      <PageHeader
        title="Security Reports"
        description="Export a configuration risk summary from current findings, assets, and rule coverage."
      />

      <p style={{ margin: "-12px 0 24px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, maxWidth: "800px" }}>
        Security reports summarize configuration risk findings, affected assets,
        and review status. They are designed for internal review and customer
        feedback, not formal compliance certification.
      </p>

      {/* 1. Report controls */}
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "22px" }}>
        <SectionLabel>Report configuration</SectionLabel>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", margin: "12px 0" }}>
          <FilterSelect
            label="Report type"
            value={reportType}
            onChange={(v) => setReportType(v as ReportType)}
            options={(["summary", "review_packet", "rule_coverage_appendix"] as ReportType[]).map((t) => ({
              value: t,
              label: REPORT_TYPE_LABEL[t],
            }))}
          />
          <FilterSelect
            label="Period"
            value={periodMode}
            onChange={(v) => setPeriodMode(v as PeriodMode)}
            options={[
              { value: "24h", label: "Last 24 hours" },
              { value: "7d", label: "Last 7 days" },
              { value: "30d", label: "Last 30 days" },
              { value: "custom", label: "Custom" },
            ]}
          />
          {periodMode === "custom" ? (
            <>
              <FieldLabel label="Start">
                <input type="datetime-local" value={customStart} onChange={(e) => setCustomStart(e.target.value)} style={inputStyle} />
              </FieldLabel>
              <FieldLabel label="End">
                <input type="datetime-local" value={customEnd} onChange={(e) => setCustomEnd(e.target.value)} style={inputStyle} />
              </FieldLabel>
            </>
          ) : null}
          <FilterSelect
            label="Provider"
            value={provider}
            onChange={setProvider}
            options={[
              { value: "all", label: "All providers" },
              ...providerOptions.map((p) => ({ value: p, label: getProviderMeta(p).shortLabel })),
            ]}
          />
          <FilterSelect
            label="Severity"
            value={severity}
            onChange={setSeverity}
            options={[
              { value: "all", label: "All severities" },
              ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: SEVERITY_LABEL[s] })),
            ]}
          />
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "14px 18px", marginTop: "4px" }}>
          <Check label="Active findings" checked={inc.active} onChange={(v) => setInc((p) => ({ ...p, active: v }))} />
          <Check label="Resolved findings" checked={inc.resolved} onChange={(v) => setInc((p) => ({ ...p, resolved: v }))} />
          <Check label="Accepted risk" checked={inc.acceptedRisk} onChange={(v) => setInc((p) => ({ ...p, acceptedRisk: v }))} />
          <Check label="Snoozed" checked={inc.snoozed} onChange={(v) => setInc((p) => ({ ...p, snoozed: v }))} />
          <Check label="Affected assets" checked={inc.assets} onChange={(v) => setInc((p) => ({ ...p, assets: v }))} />
          <Check label="Rule coverage" checked={inc.ruleCoverage} onChange={(v) => setInc((p) => ({ ...p, ruleCoverage: v }))} />
          <Check label="Review status (counts only)" checked={inc.activitySummary} onChange={(v) => setInc((p) => ({ ...p, activitySummary: v }))} />
          <Check label="Provider coverage" checked={inc.coverage} onChange={(v) => setInc((p) => ({ ...p, coverage: v }))} />
          <Check label="Rule confidence" checked={inc.confidence} onChange={(v) => setInc((p) => ({ ...p, confidence: v }))} />
          <Check label="Disabled rules (rule settings)" checked={inc.ruleSettings} onChange={(v) => setInc((p) => ({ ...p, ruleSettings: v }))} />
        </div>
      </div>

      {/* 2. Summary preview cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: "14px",
          marginBottom: "22px",
        }}
      >
        <Metric label="Active risks" value={model.summary.active} accent="#f5632a" />
        <Metric label="Critical (active)" value={model.summary.critical} accent="#e84040" />
        <Metric label="High (active)" value={model.summary.high} accent="#f5632a" />
        <Metric label="Accepted risk" value={model.summary.acceptedRisks} accent="#f5a623" />
        <Metric label="High-confidence findings" value={model.confidence.high} accent="#3ccf7e" />
        <Metric label="Affected assets" value={model.summary.affectedAssets} accent="#6b9cf8" />
      </div>

      {/* Section jump links */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", alignItems: "center", marginBottom: "16px" }}>
        <span style={{ fontSize: "12px", color: "#565b6e", marginRight: "4px" }}>Jump to:</span>
        {JUMP_TARGETS.map((t) => {
          const present = t.headings.some((h) => markdown.includes(h));
          return (
            <button
              key={t.label}
              type="button"
              disabled={!present || noData || noMatches}
              onClick={() => jumpTo(t.headings)}
              style={{
                fontSize: "12px", color: present ? "#6b9cf8" : "#565b6e", background: "transparent",
                border: "1px solid #2a2d38", borderRadius: "999px", padding: "4px 11px",
                cursor: present && !noData && !noMatches ? "pointer" : "not-allowed",
                opacity: present ? 1 : 0.5, fontFamily: "inherit",
              }}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Export buttons */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", alignItems: "center", marginBottom: "18px" }}>
        <button
          type="button"
          disabled={noData || noMatches}
          onClick={() => {
            download(`${fileStem}.md`, markdown, "text/markdown;charset=utf-8");
            trackExport("markdown_download");
          }}
          style={primaryBtn(noData || noMatches)}
        >
          Download Markdown
        </button>
        <button
          type="button"
          disabled={noData || noMatches}
          onClick={onCopy}
          style={secondaryBtn(noData || noMatches)}
        >
          {copied ? "Copied ✓" : "Copy Markdown"}
        </button>
        <button
          type="button"
          disabled={noData || noMatches}
          onClick={onCopyExec}
          style={secondaryBtn(noData || noMatches)}
        >
          {copiedExec ? "Copied ✓" : "Copy executive summary"}
        </button>
        <button
          type="button"
          disabled={noData || noMatches}
          onClick={() => {
            download(`${fileStem}.json`, generateJSON(model), "application/json;charset=utf-8");
            trackExport("json_download");
          }}
          style={secondaryBtn(noData || noMatches)}
        >
          Download JSON
        </button>
        <button
          type="button"
          disabled={noData || noMatches}
          onClick={() => {
            download(`${fileStem}-findings.csv`, generateFindingsCSV(model), "text/csv;charset=utf-8");
            trackExport("csv_download");
          }}
          style={secondaryBtn(noData || noMatches)}
        >
          Download findings CSV
        </button>
        <button type="button" onClick={() => void load()} style={{ ...secondaryBtn(false), marginLeft: "auto" }}>
          Refresh
        </button>
      </div>

      {/* M63.6 — optional, non-blocking feedback prompt after an export. */}
      {feedbackVisible ? (
        <div
          className="bg-surface1 border border-border"
          style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "18px", maxWidth: "560px" }}
        >
          {feedbackSent ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
              <span style={{ fontSize: "13px", color: "#3ccf7e", fontWeight: 600 }}>
                Thanks — your feedback helps improve beta.
              </span>
              <button type="button" onClick={() => setFeedbackVisible(false)} style={secondaryBtn(false)}>
                Close
              </button>
            </div>
          ) : (
            <>
              <div style={{ fontSize: "13.5px", fontWeight: 600, color: "#e8eaf0" }}>Was this report useful?</div>
              <p style={{ fontSize: "12px", color: "#565b6e", margin: "4px 0 12px" }}>
                Optional · helps improve beta · does not include report contents.
              </p>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                {([
                  { v: "useful", label: "Yes" },
                  { v: "somewhat", label: "Somewhat" },
                  { v: "not_useful", label: "No" },
                ] as { v: SecurityBetaFeedbackRating; label: string }[]).map((o) => {
                  const active = feedbackRating === o.v;
                  return (
                    <button
                      key={o.v}
                      type="button"
                      onClick={() => setFeedbackRating(o.v)}
                      style={{
                        fontSize: "13px", fontWeight: 600, fontFamily: "inherit",
                        color: active ? "#fff" : "#c4c8d4",
                        background: active ? "#6b9cf8" : "transparent",
                        border: `1px solid ${active ? "#6b9cf8" : "#2a2d38"}`,
                        borderRadius: "8px", padding: "6px 16px", cursor: "pointer",
                      }}
                    >
                      {o.label}
                    </button>
                  );
                })}
              </div>
              <textarea
                value={feedbackComment}
                onChange={(e) => setFeedbackComment(e.target.value)}
                rows={2}
                maxLength={500}
                placeholder="What would make this report more useful? (optional)"
                style={{
                  width: "100%", boxSizing: "border-box", marginTop: "12px",
                  background: "#13151a", border: "1px solid #2a2d38", borderRadius: "8px",
                  padding: "8px 10px", fontSize: "12.5px", color: "#e8eaf0", fontFamily: "inherit",
                  resize: "vertical",
                }}
              />
              {feedbackError ? (
                <p style={{ fontSize: "12px", color: "#e07a5f", margin: "8px 0 0" }}>{feedbackError}</p>
              ) : null}
              <div style={{ display: "flex", gap: "10px", marginTop: "12px" }}>
                <button
                  type="button"
                  onClick={sendFeedback}
                  disabled={!feedbackRating || feedbackBusy}
                  style={primaryBtn(!feedbackRating || feedbackBusy)}
                >
                  {feedbackBusy ? "Sending…" : "Send feedback"}
                </button>
                <button type="button" onClick={dismissFeedback} style={secondaryBtn(false)}>
                  Dismiss
                </button>
              </div>
            </>
          )}
        </div>
      ) : null}

      {/* 3. Report preview / states */}
      {loading ? (
        <LoadingState message="Loading report data…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : noData ? (
        <EmptyNoFindings />
      ) : noMatches ? (
        <EmptyFiltered />
      ) : (
        <div>
          <SectionLabel>Report preview</SectionLabel>
          <pre
            ref={previewRef}
            className="bg-surface1 border border-border"
            style={{
              marginTop: "10px", borderRadius: "12px", padding: "18px 20px",
              fontSize: "12.5px", lineHeight: 1.6, color: "#c4c8d4",
              whiteSpace: "pre-wrap", wordBreak: "break-word", overflowX: "auto",
              maxHeight: "640px", overflowY: "auto", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            }}
          >
            {markdown}
          </pre>
        </div>
      )}

      {total > findings.length && !loading && !error ? (
        <p style={{ marginTop: "16px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
          This report covers the {findings.length} most recent findings of {total}. Narrow the
          period, provider, or severity for a focused report.
        </p>
      ) : null}

      {/* Case Evidence Reports (M66.9) */}
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "16px 18px", marginTop: "28px" }}
      >
        <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0", marginBottom: "4px" }}>
          Case Evidence Reports
        </div>
        <p style={{ margin: "0 0 8px", fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.6 }}>
          Investigation packets are generated from a case in{" "}
          <Link href="/security/cases" style={{ color: "#6b9cf8", textDecoration: "none" }}>
            Cases
          </Link>
          . Open a case and use Export Markdown / Export JSON to download a
          metadata-only evidence report grouping its signals, configuration risks,
          activity events, and correlations.
        </p>
      </div>

      <p style={{ marginTop: "24px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        Reports are metadata-only: they exclude evidence blobs, secrets, payloads, and
        review-note text. ConfigTrace reports configuration exposure; it does not detect
        breaches or claim compliance certification.
      </p>
    </div>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  fontSize: "13px", color: "#e8eaf0", background: "#13151a",
  border: "1px solid #2a2d38", borderRadius: "8px", padding: "7px 10px",
};

function primaryBtn(disabled: boolean): React.CSSProperties {
  return {
    fontSize: "13px", fontWeight: 600, color: "#fff", background: "#6b9cf8",
    border: "1px solid #6b9cf8", borderRadius: "8px", padding: "8px 14px",
    cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.5 : 1, fontFamily: "inherit",
  };
}
function secondaryBtn(disabled: boolean): React.CSSProperties {
  return {
    fontSize: "13px", fontWeight: 600, color: "#c4c8d4", background: "transparent",
    border: "1px solid #2a2d38", borderRadius: "8px", padding: "8px 14px",
    cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.5 : 1, fontFamily: "inherit",
  };
}

function FieldLabel({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>{label}</span>
      {children}
    </label>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} style={{ ...inputStyle, cursor: "pointer" }}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  );
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "7px", cursor: "pointer", fontSize: "12.5px", color: "#c4c8d4" }}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} style={{ cursor: "pointer" }} />
      {label}
    </label>
  );
}

function Metric({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: "28px", fontWeight: 700, color: accent, marginTop: "8px", letterSpacing: "-0.02em" }}>
        {value}
      </div>
    </div>
  );
}

function EmptyNoFindings() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>No findings available for this report.</div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6, maxWidth: "520px", marginLeft: "auto", marginRight: "auto" }}>
        Connect providers and run a sync. Configuration risk findings will appear in
        reports after detection.
      </p>
    </div>
  );
}

function EmptyFiltered() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>No findings match this report configuration.</div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
        Adjust the period, provider, severity, or included statuses.
      </p>
    </div>
  );
}
