"use client";

/**
 * Security Coverage (M62.3).
 *
 * A trust view: for each provider, shows whether ConfigTrace is collecting the
 * metadata needed to evaluate Security Exposure rules. Read-only, backed by
 * GET /security/coverage (which inspects stored snapshots only).
 *
 * Conservative wording: "Good coverage" never means "safe". Limited coverage
 * means some checks may not run.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type {
  SecurityCoverageProvider,
  SecurityCoverageResponse,
  SecurityCoverageStatus,
  SecurityDiagnosticStatus,
} from "@/types";
import { getSecurityCoverage, getSecurityDemoDataStatus } from "@/lib/api";
import { getProviderMeta } from "@/lib/providers";
import { formatRelativeTime } from "@/lib/utils";
import { humanizeKey } from "@/components/security/findingDisplay";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";

const STATUS_META: Record<SecurityCoverageStatus, { label: string; color: string }> = {
  good: { label: "Good coverage", color: "#3ccf7e" },
  limited: { label: "Limited coverage", color: "#f5a623" },
  not_synced: { label: "Needs sync", color: "#6b9cf8" },
  needs_attention: { label: "Needs attention", color: "#f5632a" },
  not_connected: { label: "Not connected", color: "#8b90a0" },
};

const DIAGNOSTIC_META: Record<SecurityDiagnosticStatus, { label: string; color: string }> = {
  ok: { label: "Diagnostics OK", color: "#3ccf7e" },
  needs_sync: { label: "Needs sync", color: "#6b9cf8" },
  missing_metadata: { label: "Missing metadata", color: "#f5a623" },
  permissions_likely_limited: { label: "Permissions likely limited", color: "#f5632a" },
  provider_not_connected: { label: "Not connected", color: "#8b90a0" },
  provider_attention_needed: { label: "Attention needed", color: "#f5632a" },
};

const CONF_LABEL: Record<string, string> = {
  high: "High-confidence diagnostic",
  medium: "Medium-confidence diagnostic",
  low: "Low-confidence diagnostic",
};

/** CTA links per diagnostic status (read-only navigation only). */
function diagnosticCtas(status: SecurityDiagnosticStatus): { label: string; href: string }[] {
  switch (status) {
    case "provider_not_connected":
      return [{ label: "Connect provider", href: "/integrations" }];
    case "needs_sync":
    case "provider_attention_needed":
      return [{ label: "View integrations", href: "/integrations" }];
    case "missing_metadata":
    case "permissions_likely_limited":
      return [
        { label: "View integrations", href: "/integrations" },
        { label: "View rules", href: "/security/rules" },
      ];
    default:
      return [];
  }
}

export default function SecurityCoveragePage() {
  const { getToken } = useAuth();
  const [data, setData] = useState<SecurityCoverageResponse | null>(null);
  const [demoLoaded, setDemoLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const [cov, demo] = await Promise.allSettled([
        getSecurityCoverage(token),
        getSecurityDemoDataStatus(token),
      ]);
      if (cov.status === "fulfilled") setData(cov.value);
      else throw new Error("coverage failed");
      setDemoLoaded(demo.status === "fulfilled" ? demo.value.exists : false);
    } catch {
      setError("Could not load coverage. Please try again.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  const summary = data?.summary;
  const needsSyncOrConnect = summary
    ? data!.providers.filter((p) =>
        ["not_synced", "needs_attention", "not_connected"].includes(p.coverage_status),
      ).length
    : 0;

  return (
    <div>
      <PageHeader
        title="Security Coverage"
        description="See which provider surfaces are monitored and which security rules have enough data to run."
      />

      <p style={{ margin: "-12px 0 20px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, maxWidth: "800px" }}>
        Coverage checks help verify that ConfigTrace is collecting the metadata
        needed to evaluate Security Exposure rules. Limited coverage does not mean
        a system is safe; it means ConfigTrace may need more data or permissions.
      </p>

      {demoLoaded ? (
        <div
          className="bg-surface1 border border-border"
          style={{ borderRadius: "10px", padding: "10px 14px", marginBottom: "16px", fontSize: "12.5px", color: "#8b90a0" }}
        >
          Demo data is loaded. Coverage reflects connected provider metadata, not
          demo findings.
        </div>
      ) : null}

      {loading ? (
        <LoadingState message="Loading coverage…" />
      ) : error || !data || !summary ? (
        <ErrorState message={error ?? "Coverage unavailable."} />
      ) : (
        <>
          {/* Summary cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: "14px",
              marginBottom: "22px",
            }}
          >
            <Metric label="Connected providers" value={summary.connected_providers} accent="#6b9cf8" />
            <Metric label="Good coverage" value={summary.good_coverage} accent="#3ccf7e" />
            <Metric label="Limited coverage" value={summary.limited_coverage} accent="#f5a623" />
            <Metric label="Needs sync / connect" value={needsSyncOrConnect} accent="#f5632a" />
            <Metric label="Disabled rules" value={summary.disabled_rules} accent="#8b90a0" />
          </div>

          {/* Diagnostics summary */}
          <SectionLabel>Diagnostics</SectionLabel>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: "14px",
              margin: "10px 0 22px",
            }}
          >
            <Metric label="Providers OK" value={summary.diagnostics_ok} accent="#3ccf7e" />
            <Metric label="Needs sync" value={summary.diagnostics_needs_sync} accent="#6b9cf8" />
            <Metric label="Missing metadata" value={summary.diagnostics_missing_metadata} accent="#f5a623" />
            <Metric label="Permissions likely limited" value={summary.diagnostics_permissions_likely_limited} accent="#f5632a" />
          </div>

          {summary.connected_providers === 0 ? (
            <div
              className="bg-surface1 border border-border"
              style={{ borderRadius: "12px", padding: "28px", textAlign: "center", marginBottom: "22px" }}
            >
              <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>
                No providers connected yet.
              </div>
              <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
                Connect a provider and run a sync to see Security Exposure coverage.
              </p>
            </div>
          ) : null}

          <p style={{ fontSize: "12px", color: "#565b6e", margin: "0 0 14px", lineHeight: 1.6, maxWidth: "800px" }}>
            Coverage means ConfigTrace has enough metadata to evaluate the rule.
            Good coverage does not mean no risk exists; limited coverage means some
            checks may not run.
          </p>

          {/* Provider coverage cards */}
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {data.providers.map((p) => (
              <ProviderCard key={p.provider} p={p} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function Metric({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: "26px", fontWeight: 700, color: accent, marginTop: "8px", letterSpacing: "-0.02em" }}>
        {value}
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: SecurityCoverageStatus }) {
  const m = STATUS_META[status];
  return (
    <span
      style={{
        fontSize: "11px",
        fontWeight: 700,
        letterSpacing: "0.03em",
        textTransform: "uppercase",
        color: m.color,
        background: `${m.color}1f`,
        border: `1px solid ${m.color}55`,
        borderRadius: "6px",
        padding: "2px 8px",
        whiteSpace: "nowrap",
      }}
    >
      {m.label}
    </span>
  );
}

function ProviderCard({ p }: { p: SecurityCoverageProvider }) {
  const meta = getProviderMeta(p.provider);
  const muted = p.coverage_status === "not_connected";
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "16px 18px", opacity: muted ? 0.8 : 1 }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
          <span style={{ fontSize: "14px", fontWeight: 700, color: meta.color }}>{meta.shortLabel}</span>
          <StatusPill status={p.coverage_status} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "14px", fontSize: "12px", color: "#565b6e" }}>
          {p.connected && p.last_synced_at ? (
            <span>Last synced {formatRelativeTime(p.last_synced_at)}</span>
          ) : p.connected ? (
            <span>Not synced yet</span>
          ) : null}
          <span>{p.active_rules} active · {p.disabled_rules} disabled · {p.supported_rules} rules</span>
        </div>
      </div>

      {/* Monitored surfaces */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "12px" }}>
        {p.monitored_surfaces.map((s) => (
          <span
            key={s}
            style={{
              fontSize: "11.5px",
              color: "#8b90a0",
              background: "rgba(148,163,184,0.08)",
              border: "1px solid #2a2d38",
              borderRadius: "7px",
              padding: "3px 9px",
            }}
          >
            {s}
          </span>
        ))}
      </div>

      {/* Missing surfaces when partial / unsynced */}
      {p.connected && p.missing_record_types.length > 0 ? (
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "10px" }}>
          <span style={{ color: "#565b6e" }}>Missing records: </span>
          {p.missing_record_types.map((r) => humanizeRecord(r)).join(", ")}
        </div>
      ) : null}

      {/* Recommendation */}
      <div style={{ fontSize: "12.5px", color: "#c4c8d4", marginTop: "10px", lineHeight: 1.55 }}>
        {p.recommendation}
      </div>

      {/* M62.8 — Permission diagnostics */}
      <Diagnostics p={p} />

      {/* Rule coverage */}
      {p.rules.length > 0 ? (
        <div style={{ marginTop: "12px" }}>
          <SectionLabel>Rule coverage</SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "8px" }}>
            {p.rules.map((r) => (
              <div key={r.rule_key} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "10px" }}>
                <span style={{ fontSize: "12.5px", color: "#c4c8d4", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {humanizeKey(r.rule_key)}
                </span>
                <span style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
                  <RuleTag
                    label={r.enabled ? "Enabled" : "Disabled"}
                    color={r.enabled ? "#3ccf7e" : "#8b90a0"}
                  />
                  <RuleTag
                    label={r.supported ? "Data available" : "No data yet"}
                    color={r.supported ? "#6b9cf8" : "#565b6e"}
                  />
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function RuleTag({ label, color }: { label: string; color: string }) {
  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        color,
        background: `${color}1a`,
        border: `1px solid ${color}44`,
        borderRadius: "5px",
        padding: "1px 6px",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function DiagnosticPill({ status }: { status: SecurityDiagnosticStatus }) {
  const m = DIAGNOSTIC_META[status];
  return (
    <span
      style={{
        fontSize: "11px", fontWeight: 700, letterSpacing: "0.03em", textTransform: "uppercase",
        color: m.color, background: `${m.color}1f`, border: `1px solid ${m.color}55`,
        borderRadius: "6px", padding: "2px 8px", whiteSpace: "nowrap",
      }}
    >
      {m.label}
    </span>
  );
}

function Diagnostics({ p }: { p: SecurityCoverageProvider }) {
  const ctas = diagnosticCtas(p.diagnostic_status);

  // For an OK diagnostic, keep it to a single subtle line (no "secure" claims).
  if (p.diagnostic_status === "ok") {
    return (
      <div style={{ marginTop: "12px" }}>
        <SectionLabel>Diagnostics</SectionLabel>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "8px", flexWrap: "wrap" }}>
          <DiagnosticPill status={p.diagnostic_status} />
          <span style={{ fontSize: "12.5px", color: "#8b90a0" }}>
            Coverage data looks sufficient for currently supported rules.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ marginTop: "14px", paddingTop: "12px", borderTop: "1px solid #1f2229" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
        <SectionLabel>Diagnostics</SectionLabel>
        <DiagnosticPill status={p.diagnostic_status} />
        <span style={{ fontSize: "11px", color: "#565b6e" }}>
          {CONF_LABEL[p.diagnostic_confidence] ?? p.diagnostic_confidence}
        </span>
      </div>

      {/* Diagnostic messages */}
      {p.diagnostic_messages.length > 0 ? (
        <ul style={{ margin: "8px 0 0", paddingLeft: "16px", display: "flex", flexDirection: "column", gap: "3px" }}>
          {p.diagnostic_messages.map((m, i) => (
            <li key={i} style={{ fontSize: "12.5px", color: "#c4c8d4", lineHeight: 1.5 }}>{m}</li>
          ))}
        </ul>
      ) : null}

      {/* Permission hints */}
      {p.permission_hints.length > 0 ? (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "11px", color: "#565b6e", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
            Permission hints
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "6px" }}>
            {p.permission_hints.map((h) => (
              <span
                key={h}
                style={{
                  fontSize: "11.5px", color: "#c4c8d4",
                  background: "rgba(148,163,184,0.08)", border: "1px solid #2a2d38",
                  borderRadius: "6px", padding: "2px 8px",
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                }}
              >
                {h}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* Recommended actions */}
      {p.recommended_actions.length > 0 ? (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "11px", color: "#565b6e", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
            Recommended action
          </div>
          <ul style={{ margin: "6px 0 0", paddingLeft: "16px", display: "flex", flexDirection: "column", gap: "3px" }}>
            {p.recommended_actions.map((a, i) => (
              <li key={i} style={{ fontSize: "12.5px", color: "#c4c8d4", lineHeight: 1.5 }}>{a}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Docs hint */}
      {p.docs_hint ? (
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "8px" }}>{p.docs_hint}</div>
      ) : null}

      {/* CTAs */}
      {ctas.length > 0 ? (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "12px" }}>
          {ctas.map((c) => (
            <Link
              key={c.href + c.label}
              href={c.href}
              style={{
                fontSize: "12px", fontWeight: 600, color: "#6b9cf8", textDecoration: "none",
                border: "1px solid #2a2d38", borderRadius: "8px", padding: "5px 12px", whiteSpace: "nowrap",
              }}
            >
              {c.label} →
            </Link>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function humanizeRecord(rt: string): string {
  // Friendly-ish rendering of a record_type string for display.
  if (rt === "A" || rt === "AAAA") return `DNS ${rt} record`;
  return rt.replace(/_/g, " ");
}
