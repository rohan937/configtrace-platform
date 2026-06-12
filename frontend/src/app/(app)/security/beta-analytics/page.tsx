"use client";

/**
 * Beta Analytics (M63.4).
 *
 * Read-only, first-party, workspace-scoped usage analytics over the
 * security_beta_events table. No third-party analytics, no provider payloads,
 * no evidence/secrets/note bodies — only the already-allowlisted metadata.
 * Admin/owner only (backend returns 403 otherwise).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@clerk/nextjs";

import type { SecurityBetaSummary } from "@/types";
import { getSecurityBetaEventsSummary } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";

const DAYS_OPTIONS = [
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
  { value: "90", label: "Last 90 days" },
];

const ROUTE_GROUPS = [
  "overview",
  "exposures",
  "detail",
  "assets",
  "timeline",
  "rules",
  "coverage",
  "incident-review",
  "reports",
];

const inputStyle: React.CSSProperties = {
  fontSize: "13px", color: "#e8eaf0", background: "#13151a",
  border: "1px solid #2a2d38", borderRadius: "8px", padding: "7px 10px",
};

export default function SecurityBetaAnalyticsPage() {
  const { getToken } = useAuth();
  const [data, setData] = useState<SecurityBetaSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);

  const [days, setDays] = useState("7");
  const [eventName, setEventName] = useState("all");
  const [routeGroup, setRouteGroup] = useState("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setForbidden(false);
    try {
      const token = await getToken();
      const res = await getSecurityBetaEventsSummary(
        {
          days: Number(days),
          event_name: eventName === "all" ? undefined : eventName,
          route_group: routeGroup === "all" ? undefined : routeGroup,
        },
        token,
      );
      setData(res);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      if (msg.includes("HTTP 403")) {
        setForbidden(true);
      } else {
        setError("Could not load beta analytics. Please try again.");
      }
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [getToken, days, eventName, routeGroup]);

  useEffect(() => {
    void load();
  }, [load]);

  // Event-name options come from whatever the summary saw (plus "all").
  const eventOptions = useMemo(() => {
    const names = Object.keys(data?.events_by_name ?? {}).sort();
    return [{ value: "all", label: "All events" }, ...names.map((n) => ({ value: n, label: n }))];
  }, [data]);

  const noData = !!data && data.total_events === 0;

  return (
    <div>
      <PageHeader
        title="Beta Analytics"
        description="Understand how beta users interact with Configuration Risk."
      />

      <p style={{ margin: "-12px 0 22px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, maxWidth: "820px" }}>
        Beta Analytics summarizes first-party, workspace-scoped usage events. It does
        not use third-party analytics and does not store provider payloads, evidence,
        secrets, or note bodies.
      </p>

      {/* Controls */}
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px", marginBottom: "22px" }}>
        <SectionLabel>Controls</SectionLabel>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", marginTop: "12px" }}>
          <Select label="Period" value={days} onChange={setDays} options={DAYS_OPTIONS} />
          <Select label="Event" value={eventName} onChange={setEventName} options={eventOptions} />
          <Select
            label="Route group"
            value={routeGroup}
            onChange={setRouteGroup}
            options={[{ value: "all", label: "All routes" }, ...ROUTE_GROUPS.map((r) => ({ value: r, label: r }))]}
          />
          <button type="button" onClick={() => void load()} style={{ ...inputStyle, cursor: "pointer", color: "#c4c8d4", marginLeft: "auto" }}>
            Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <LoadingState message="Loading beta analytics…" />
      ) : forbidden ? (
        <ErrorState message="You need workspace admin access to view beta analytics." />
      ) : error ? (
        <ErrorState message={error} />
      ) : !data ? (
        <ErrorState message="Beta analytics unavailable." />
      ) : noData ? (
        <EmptyState />
      ) : (
        <>
          {/* Summary cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: "14px", marginBottom: "22px" }}>
            <Metric label="Total events" value={data.total_events} accent="#6b9cf8" />
            <Metric label="Unique users" value={data.unique_users} accent="#6b9cf8" />
            <Metric label="Page views" value={data.page_views} accent="#3ccf7e" />
            <Metric label="Demo seeds" value={data.demo_seeds} accent="#3ccf7e" />
            <Metric label="Walkthrough opens" value={data.walkthrough_opens} accent="#f5a623" />
            <Metric label="Risk actions" value={data.exposure_actions} accent="#f5632a" />
            <Metric label="Reports exported" value={data.report_exports} accent="#f5a623" />
            <Metric label="Rule toggles" value={data.rule_toggles} accent="#8b90a0" />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "18px", marginBottom: "22px" }}>
            <BarTable title="Events by name" rows={mapToRows(data.events_by_name)} />
            <BarTable title="Events by route group" rows={mapToRows(data.events_by_route_group)} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "18px", marginBottom: "22px" }}>
            <BarTable title="Events by day" rows={data.events_by_day.map((d) => ({ label: d.day, count: d.count }))} />
            <BarTable title="Top actions" rows={data.top_actions.map((a) => ({ label: a.action, count: a.count }))} />
          </div>

          {/* Recent events */}
          <SectionLabel>Recent events</SectionLabel>
          <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "8px 0", marginTop: "10px" }}>
            {data.recent_events.length === 0 ? (
              <div style={{ padding: "16px", fontSize: "13px", color: "#8b90a0" }}>No recent events.</div>
            ) : (
              data.recent_events.map((e, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap",
                    padding: "10px 16px", borderTop: i === 0 ? "none" : "1px solid #1a1c23",
                  }}
                >
                  <span style={{ fontSize: "12.5px", color: "#e8eaf0", fontWeight: 600, minWidth: "220px" }}>
                    {e.event_name}
                  </span>
                  <span style={{ fontSize: "11.5px", color: "#565b6e", fontFamily: "ui-monospace, monospace" }}>
                    {e.page_path ?? "—"}
                  </span>
                  <span style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {Object.entries(e.metadata).map(([k, v]) => (
                      <span
                        key={k}
                        style={{
                          fontSize: "11px", color: "#8b90a0", background: "rgba(148,163,184,0.08)",
                          border: "1px solid #2a2d38", borderRadius: "6px", padding: "1px 7px",
                        }}
                      >
                        {k}: {String(v)}
                      </span>
                    ))}
                  </span>
                  <span style={{ marginLeft: "auto", fontSize: "11.5px", color: "#565b6e", whiteSpace: "nowrap" }}>
                    {formatRelativeTime(e.created_at)}
                  </span>
                </div>
              ))
            )}
          </div>
        </>
      )}

      <p style={{ marginTop: "24px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        First-party only. Events are workspace-scoped and metadata is allowlisted; this
        page sends nothing to external analytics services.
      </p>
    </div>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function mapToRows(m: Record<string, number>): { label: string; count: number }[] {
  return Object.entries(m)
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function Select({
  label, value, onChange, options,
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

function BarTable({ title, rows }: { title: string; rows: { label: string; count: number }[] }) {
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0) || 1;
  return (
    <div>
      <SectionLabel>{title}</SectionLabel>
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "12px 14px", marginTop: "10px" }}>
        {rows.length === 0 ? (
          <div style={{ fontSize: "12.5px", color: "#565b6e" }}>No data.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {rows.map((r) => (
              <div key={r.label} style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span style={{ fontSize: "12px", color: "#c4c8d4", minWidth: "150px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {r.label}
                </span>
                <span style={{ flex: 1, height: "8px", background: "#1d1f27", borderRadius: "999px", overflow: "hidden" }}>
                  <span style={{ display: "block", width: `${(r.count / max) * 100}%`, height: "100%", background: "#6b9cf8" }} />
                </span>
                <span style={{ fontSize: "12px", color: "#8b90a0", minWidth: "32px", textAlign: "right" }}>{r.count}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>No beta events recorded yet.</div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6, maxWidth: "520px", marginLeft: "auto", marginRight: "auto" }}>
        Events will appear here after users interact with Configuration Risk pages and actions.
      </p>
    </div>
  );
}
