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
import { useAuth } from "@clerk/nextjs";

import type {
  SecurityCoverageProvider,
  SecurityCoverageResponse,
  SecurityCoverageStatus,
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

function humanizeRecord(rt: string): string {
  // Friendly-ish rendering of a record_type string for display.
  if (rt === "A" || rt === "AAAA") return `DNS ${rt} record`;
  return rt.replace(/_/g, " ");
}
