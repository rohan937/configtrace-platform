"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type {
  DashboardRecentChange,
  DashboardRecentFailedSync,
  DashboardSummary,
} from "@/types";
import { getDashboardSummary } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import RiskBadge from "@/components/common/RiskBadge";
import { formatRelativeTime, formatAbsoluteTime } from "@/lib/utils";
import { usePollingRefresh } from "@/hooks/usePollingRefresh";

// ── Design tokens ─────────────────────────────────────────────────────────────

const CARD: React.CSSProperties = {
  background: "#13151a",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  padding: "20px 22px",
};

const SECTION_LABEL: React.CSSProperties = {
  fontSize: "11px",
  color: "#565b6e",
  textTransform: "uppercase" as const,
  letterSpacing: "0.06em",
  fontWeight: 500,
  marginBottom: "14px",
};

// ── Helper components ─────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <p style={SECTION_LABEL}>{children}</p>;
}

function Card({
  children,
  style,
}: {
  children: React.ReactNode;
  style?: React.CSSProperties;
}) {
  return <div style={{ ...CARD, ...style }}>{children}</div>;
}

function Divider() {
  return (
    <div style={{ width: "1px", height: "36px", background: "#2a2d38", flexShrink: 0 }} />
  );
}

// ── Stat block ────────────────────────────────────────────────────────────────

function StatCell({
  value,
  label,
  valueColor,
  href,
}: {
  value: string | number;
  label: string;
  valueColor?: string;
  href?: string;
}) {
  const inner = (
    <div className="flex flex-col gap-1">
      <span
        style={{
          fontSize: "24px",
          fontWeight: 600,
          color: valueColor ?? "#e8eaf0",
          lineHeight: 1,
        }}
      >
        {value}
      </span>
      <span style={{ fontSize: "12px", color: "#8b90a0", lineHeight: 1 }}>
        {label}
      </span>
    </div>
  );
  if (href) {
    return (
      <Link href={href} style={{ textDecoration: "none" }}>
        {inner}
      </Link>
    );
  }
  return inner;
}

// ── Risk badge helper ─────────────────────────────────────────────────────────

function RiskDot({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: "#e84040",
    high: "#f5632a",
    medium: "#f5a623",
    low: "#6b9cf8",
  };
  return (
    <span
      style={{
        display: "inline-block",
        width: "8px",
        height: "8px",
        borderRadius: "50%",
        background: colors[level.toLowerCase()] ?? "#8b90a0",
        flexShrink: 0,
      }}
    />
  );
}

// ── Provider label helper ─────────────────────────────────────────────────────

function providerLabel(provider: string | null | undefined): string {
  switch (provider?.toLowerCase()) {
    case "cloudflare": return "Cloudflare";
    case "github":     return "GitHub";
    case "vercel":     return "Vercel";
    case "stripe":     return "Stripe";
    case "aws":        return "AWS";
    case "firebase":   return "Firebase";
    case "supabase":   return "Supabase";
    default:           return provider ?? "Unknown";
  }
}

// ── Onboarding panel ──────────────────────────────────────────────────────────

interface OnboardingStep {
  num: number;
  label: string;
  body: string;
  done?: boolean;
}

function OnboardingPanel({
  steps,
  actionLabel,
  actionHref,
  note,
}: {
  steps: OnboardingStep[];
  actionLabel: string;
  actionHref: string;
  note?: string;
}) {
  return (
    <div style={CARD}>
      <p
        style={{
          margin: "0 0 20px",
          fontSize: "15px",
          fontWeight: 600,
          color: "#e8eaf0",
          lineHeight: 1.4,
        }}
      >
        Start monitoring your first configuration surface.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginBottom: "24px" }}>
        {steps.map((step) => (
          <div key={step.num} style={{ display: "flex", gap: "14px", alignItems: "flex-start" }}>
            <div
              style={{
                flexShrink: 0,
                width: "22px",
                height: "22px",
                borderRadius: "50%",
                background: step.done ? "#4f80f7" : "#1e2030",
                border: step.done ? "none" : "1px solid #3a3d4a",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "11px",
                fontWeight: 700,
                color: step.done ? "#ffffff" : "#565b6e",
                marginTop: "1px",
              }}
            >
              {step.done ? "✓" : step.num}
            </div>
            <div>
              <p style={{ margin: "0 0 2px", fontSize: "13px", fontWeight: 500, color: step.done ? "#8b90a0" : "#e8eaf0" }}>
                {step.label}
              </p>
              <p style={{ margin: 0, fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
                {step.body}
              </p>
            </div>
          </div>
        ))}
      </div>
      <Link
        href={actionHref}
        style={{
          display: "inline-block",
          background: "#4f80f7",
          color: "#ffffff",
          textDecoration: "none",
          borderRadius: "6px",
          padding: "8px 18px",
          fontSize: "13px",
          fontWeight: 500,
        }}
      >
        {actionLabel}
      </Link>
      {note && (
        <p style={{ margin: "16px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
          {note}
        </p>
      )}
    </div>
  );
}

// ── Risk distribution card ────────────────────────────────────────────────────

function RiskDistributionCard({ data }: { data: DashboardSummary["risk_distribution"] }) {
  const total = data.critical + data.high + data.medium + data.low;
  const levels = [
    { key: "critical", label: "Critical", count: data.critical, color: "#e84040" },
    { key: "high",     label: "High",     count: data.high,     color: "#f5632a" },
    { key: "medium",   label: "Medium",   count: data.medium,   color: "#f5a623" },
    { key: "low",      label: "Low",      count: data.low,      color: "#6b9cf8" },
  ];

  return (
    <Card>
      <SectionLabel>Risk distribution</SectionLabel>
      {total === 0 ? (
        <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
          No changes recorded yet.
        </p>
      ) : (
        <>
          {/* Bar */}
          <div
            style={{
              display: "flex",
              height: "6px",
              borderRadius: "3px",
              overflow: "hidden",
              marginBottom: "16px",
              gap: "1px",
            }}
          >
            {levels.map(({ key, count, color }) =>
              count > 0 ? (
                <div
                  key={key}
                  style={{
                    flex: count,
                    background: color,
                  }}
                  title={`${key}: ${count}`}
                />
              ) : null,
            )}
          </div>

          {/* Counts */}
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {levels.map(({ key, label, count, color }) => (
              <div key={key} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <RiskDot level={key} />
                  <span style={{ fontSize: "12px", color: "#8b90a0" }}>{label}</span>
                </div>
                <Link
                  href={`/timeline?risk_level=${key}`}
                  style={{
                    fontSize: "13px",
                    fontWeight: 600,
                    color: count > 0 ? color : "#565b6e",
                    textDecoration: "none",
                  }}
                >
                  {count}
                </Link>
              </div>
            ))}
          </div>
        </>
      )}
    </Card>
  );
}

// ── Provider distribution card ────────────────────────────────────────────────

function ProviderDistributionCard({ data }: { data: DashboardSummary["provider_distribution"] }) {
  if (data.length === 0) {
    return (
      <Card>
        <SectionLabel>Provider coverage</SectionLabel>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
          No integrations yet.
        </p>
      </Card>
    );
  }

  return (
    <Card>
      <SectionLabel>Provider coverage</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {data.map((p) => (
          <div key={p.provider} className="flex items-center justify-between gap-4">
            <span style={{ fontSize: "13px", color: "#e8eaf0", fontWeight: 500 }}>
              {providerLabel(p.provider)}
            </span>
            <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
              <span style={{ fontSize: "12px", color: "#8b90a0" }}>
                {p.integration_count} integration{p.integration_count !== 1 ? "s" : ""}
              </span>
              <span style={{ fontSize: "12px", color: "#8b90a0" }}>
                {p.resource_count} resource{p.resource_count !== 1 ? "s" : ""}
              </span>
              <Link
                href={`/timeline?provider=${p.provider}&time_range=7d`}
                style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
                title="Changes in last 7 days"
              >
                {p.change_count_7d} change{p.change_count_7d !== 1 ? "s" : ""} (7d)
              </Link>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Recent high/critical changes table ────────────────────────────────────────

function RecentHighCriticalChanges({
  changes,
}: {
  changes: DashboardRecentChange[];
}) {
  if (changes.length === 0) {
    return (
      <Card>
        <SectionLabel>Recent high / critical changes</SectionLabel>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
          No high or critical changes detected yet.
        </p>
      </Card>
    );
  }

  return (
    <Card style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ padding: "16px 20px 12px" }}>
        <SectionLabel>Recent high / critical changes</SectionLabel>
      </div>

      {/* Table header */}
      <div
        className="flex items-center gap-3 px-5 py-2"
        style={{
          borderTop: "1px solid #1e2030",
          borderBottom: "1px solid #1e2030",
          background: "#1a1d26",
          fontSize: "10px",
          color: "#565b6e",
          textTransform: "uppercase" as const,
          letterSpacing: "0.06em",
        }}
      >
        <span style={{ width: "64px", flexShrink: 0 }}>Risk</span>
        <span style={{ flex: 1, minWidth: 0 }}>Record</span>
        <span style={{ width: "80px", flexShrink: 0 }}>Provider</span>
        <span style={{ width: "60px", flexShrink: 0 }}>Type</span>
        <span style={{ width: "90px", flexShrink: 0, textAlign: "right" }}>Detected</span>
      </div>

      {changes.map((c) => (
        <Link
          key={c.id}
          href={`/changes/${c.id}`}
          style={{ textDecoration: "none", display: "block" }}
        >
          <div
            className="flex items-center gap-3 px-5 py-2.5 hover:bg-surface2"
            style={{ borderBottom: "1px solid #1e2030" }}
          >
            <span style={{ width: "64px", flexShrink: 0 }}>
              <RiskBadge level={c.risk_level as "critical" | "high" | "medium" | "low"} />
            </span>
            <span
              className="font-mono truncate"
              style={{ flex: 1, minWidth: 0, fontSize: "12px", color: "#e8eaf0" }}
              title={c.record_identifier}
            >
              {c.record_identifier}
              {c.field_path && (
                <span style={{ color: "#565b6e" }}> · {c.field_path}</span>
              )}
            </span>
            <span style={{ width: "80px", flexShrink: 0, fontSize: "11px", color: "#8b90a0" }}>
              {providerLabel(c.provider)}
            </span>
            <span style={{ width: "60px", flexShrink: 0 }}>
              <span
                style={{
                  fontSize: "10px",
                  color: "#8b90a0",
                  textTransform: "uppercase" as const,
                  letterSpacing: "0.04em",
                }}
              >
                {c.change_type}
              </span>
            </span>
            <span
              style={{ width: "90px", flexShrink: 0, fontSize: "11px", color: "#565b6e", textAlign: "right" }}
              title={formatAbsoluteTime(c.created_at)}
            >
              {formatRelativeTime(c.created_at)}
            </span>
          </div>
        </Link>
      ))}

      <div style={{ padding: "10px 20px" }}>
        <Link
          href="/timeline?risk_level=high"
          style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
        >
          View all high / critical changes →
        </Link>
      </div>
    </Card>
  );
}

// ── Recent failed syncs ───────────────────────────────────────────────────────

function RecentFailedSyncs({ syncs }: { syncs: DashboardRecentFailedSync[] }) {
  if (syncs.length === 0) return null;

  return (
    <Card style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ padding: "16px 20px 12px" }}>
        <SectionLabel>Recent sync failures</SectionLabel>
      </div>
      {syncs.map((s) => (
        <Link
          key={s.integration_id}
          href={`/integrations/${s.integration_id}`}
          style={{ textDecoration: "none", display: "block" }}
        >
          <div
            className="flex items-start gap-4 px-5 py-3 hover:bg-surface2"
            style={{ borderTop: "1px solid #1e2030" }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="flex items-center gap-2" style={{ marginBottom: "3px" }}>
                <span style={{ fontSize: "13px", color: "#e8eaf0", fontWeight: 500 }}>
                  {s.integration_name}
                </span>
                {s.needs_attention && (
                  <span
                    style={{
                      fontSize: "10px",
                      color: "#e84040",
                      background: "rgba(232,64,64,0.10)",
                      border: "1px solid rgba(232,64,64,0.25)",
                      borderRadius: "4px",
                      padding: "1px 6px",
                      fontWeight: 500,
                    }}
                  >
                    Needs attention
                  </span>
                )}
              </div>
              <p style={{ margin: 0, fontSize: "11px", color: "#565b6e" }}>
                {providerLabel(s.provider)}
                {s.failure_category && (
                  <> · <span style={{ color: "#8b90a0" }}>{s.failure_category}</span></>
                )}
                {s.consecutive_failure_count > 0 && (
                  <> · {s.consecutive_failure_count} consecutive failure{s.consecutive_failure_count !== 1 ? "s" : ""}</>
                )}
              </p>
              {s.recommended_action && (
                <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#8b90a0", lineHeight: 1.5 }}>
                  {s.recommended_action}
                </p>
              )}
            </div>
            {s.last_failure_at && (
              <span
                style={{ fontSize: "11px", color: "#565b6e", flexShrink: 0 }}
                title={formatAbsoluteTime(s.last_failure_at)}
              >
                {formatRelativeTime(s.last_failure_at)}
              </span>
            )}
          </div>
        </Link>
      ))}
    </Card>
  );
}

// ── Integration health card ───────────────────────────────────────────────────

function IntegrationHealthCard({
  data,
}: {
  data: DashboardSummary["integration_health"];
}) {
  return (
    <Card>
      <SectionLabel>Integrations</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {[
          { label: "Total",               value: data.total,                      href: "/integrations" },
          { label: "Active",              value: data.active,                     href: "/integrations" },
          { label: "Paused",              value: data.paused,                     color: data.paused > 0 ? "#f5a623" : undefined },
          { label: "Needs attention",     value: data.needs_attention,            color: data.needs_attention > 0 ? "#e84040" : undefined, href: "/integrations" },
          { label: "Failed (last 24h)",   value: data.failed_last_24h,            color: data.failed_last_24h > 0 ? "#f5632a" : undefined },
        ].map(({ label, value, color, href }) => (
          <div key={label} className="flex items-center justify-between">
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>{label}</span>
            {href && value > 0 ? (
              <Link
                href={href}
                style={{ fontSize: "13px", fontWeight: 600, color: color ?? "#e8eaf0", textDecoration: "none" }}
              >
                {value}
              </Link>
            ) : (
              <span style={{ fontSize: "13px", fontWeight: 600, color: color ?? "#e8eaf0" }}>
                {value}
              </span>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Change activity card ──────────────────────────────────────────────────────

function ChangeActivityCard({
  data,
}: {
  data: DashboardSummary["change_activity"];
}) {
  return (
    <Card>
      <SectionLabel>Change activity</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {[
          { label: "Total changes",       value: data.total,               href: "/timeline" },
          { label: "Last 24 hours",       value: data.last_24h,            href: "/timeline?time_range=24h" },
          { label: "Last 7 days",         value: data.last_7d,             href: "/timeline?time_range=7d" },
          {
            label: "High/critical (7d)",
            value: data.high_critical_last_7d,
            color: data.high_critical_last_7d > 0 ? "#f5632a" : undefined,
            href: "/timeline?time_range=7d&risk_level=high",
          },
        ].map(({ label, value, color, href }) => (
          <div key={label} className="flex items-center justify-between">
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>{label}</span>
            {href ? (
              <Link
                href={href}
                style={{ fontSize: "13px", fontWeight: 600, color: color ?? "#e8eaf0", textDecoration: "none" }}
              >
                {value}
              </Link>
            ) : (
              <span style={{ fontSize: "13px", fontWeight: 600, color: color ?? "#e8eaf0" }}>
                {value}
              </span>
            )}
          </div>
        ))}
        {data.last_change_at && (
          <div
            style={{ paddingTop: "8px", borderTop: "1px solid #2a2d38", marginTop: "4px" }}
            className="flex items-center justify-between"
          >
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>Last change</span>
            <span
              style={{ fontSize: "12px", color: "#8b90a0" }}
              title={formatAbsoluteTime(data.last_change_at)}
            >
              {formatRelativeTime(data.last_change_at)}
            </span>
          </div>
        )}
      </div>
    </Card>
  );
}

// ── Refresh bar ───────────────────────────────────────────────────────────────

function RefreshBar({
  lastUpdatedAt,
  onRefresh,
}: {
  lastUpdatedAt: Date | null;
  onRefresh: () => void;
}) {
  return (
    <div
      className="flex items-center justify-between"
      style={{ marginBottom: "20px" }}
    >
      <span style={{ fontSize: "11px", color: "#565b6e" }}>
        {lastUpdatedAt
          ? `Updated ${formatRelativeTime(lastUpdatedAt.toISOString())}`
          : "Refreshing…"}
      </span>
      <button
        onClick={onRefresh}
        style={{
          background: "transparent",
          border: "1px solid #2a2d38",
          color: "#8b90a0",
          borderRadius: "4px",
          padding: "3px 10px",
          fontSize: "11px",
          cursor: "pointer",
          fontFamily: "inherit",
        }}
        onMouseOver={(e) => {
          (e.currentTarget as HTMLButtonElement).style.color = "#e8eaf0";
        }}
        onMouseOut={(e) => {
          (e.currentTarget as HTMLButtonElement).style.color = "#8b90a0";
        }}
      >
        ↻ Refresh
      </button>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { getToken, isLoaded } = useAuth();

  const fetchSummary = useCallback(async () => {
    if (!isLoaded) return;
    try {
      const token = await getToken();
      const data = await getDashboardSummary(token);
      setSummary(data);
      if (loading) setLoading(false);
      if (error) setError(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load dashboard.";
      if (!summary) {
        // Only show error on first load — polling errors are silent
        setError(msg);
      }
      if (loading) setLoading(false);
    }
  }, [isLoaded, getToken, loading, error, summary]);

  useEffect(() => {
    if (isLoaded) void fetchSummary();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded]);

  const { refresh, lastUpdatedAt } = usePollingRefresh({
    callback: fetchSummary,
    intervalMs: 30_000,
    enabled: !loading && isLoaded,
  });

  // ── Derived state ─────────────────────────────────────────────────────────
  const ih = summary?.integration_health;
  const noIntegrations = !loading && !error && summary && ih?.total === 0;
  const hasData = !loading && !error && summary && (ih?.total ?? 0) > 0;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Operational overview of all your configuration surfaces."
      />

      {/* ── Top stat bar ──────────────────────────────────────────────────── */}
      {summary && (
        <div
          className="flex flex-wrap items-center gap-6 px-6 py-4"
          style={{ borderBottom: "1px solid #2a2d38" }}
        >
          <StatCell
            value={summary.integration_health.total}
            label="Integrations"
            href="/integrations"
          />
          <Divider />
          <StatCell
            value={summary.resource_counts.active}
            label="Resources"
            href="/resources"
          />
          <Divider />
          <StatCell
            value={summary.change_activity.total}
            label="Changes"
            href="/timeline"
          />
          <Divider />
          <StatCell
            value={summary.risk_distribution.critical}
            label="Critical"
            valueColor={summary.risk_distribution.critical > 0 ? "#e84040" : undefined}
            href={summary.risk_distribution.critical > 0 ? "/timeline?risk_level=critical" : undefined}
          />
          <Divider />
          <StatCell
            value={summary.risk_distribution.high}
            label="High risk"
            valueColor={summary.risk_distribution.high > 0 ? "#f5632a" : undefined}
            href={summary.risk_distribution.high > 0 ? "/timeline?risk_level=high" : undefined}
          />
          {summary.change_activity.last_change_at && (
            <>
              <Divider />
              <div className="flex flex-col gap-1">
                <span
                  style={{ fontSize: "24px", fontWeight: 600, color: "#e8eaf0", lineHeight: 1 }}
                  title={formatAbsoluteTime(summary.change_activity.last_change_at)}
                >
                  {formatRelativeTime(summary.change_activity.last_change_at)}
                </span>
                <span style={{ fontSize: "12px", color: "#8b90a0", lineHeight: 1 }}>
                  Last change
                </span>
              </div>
            </>
          )}
        </div>
      )}

      <div className="px-6 py-6">
        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}

        {/* ── Onboarding ───────────────────────────────────────────────── */}
        {noIntegrations && (
          <OnboardingPanel
            steps={[
              {
                num: 1,
                label: "Connect Cloudflare, GitHub, or Vercel",
                body: "Add an integration — ConfigTrace monitors configuration drift, not code.",
              },
              {
                num: 2,
                label: "Create a baseline",
                body: "The first sync snapshots your current configuration. Nothing is flagged as changed on this run — it establishes the comparison point.",
              },
              {
                num: 3,
                label: "Track changes automatically",
                body: "ConfigTrace syncs on your chosen schedule and surfaces exactly what changed and how risky each change is.",
              },
            ]}
            actionLabel="Connect an integration →"
            actionHref="/integrations"
            note="High-risk and critical changes trigger email alerts automatically."
          />
        )}

        {/* ── Command center ───────────────────────────────────────────── */}
        {hasData && summary && (
          <>
            <RefreshBar lastUpdatedAt={lastUpdatedAt} onRefresh={refresh} />

            {/* Row 1: integration health + change activity + risk + provider */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: "16px",
                marginBottom: "20px",
              }}
            >
              <IntegrationHealthCard data={summary.integration_health} />
              <ChangeActivityCard data={summary.change_activity} />
              <RiskDistributionCard data={summary.risk_distribution} />
              <ProviderDistributionCard data={summary.provider_distribution} />
            </div>

            {/* Row 2: recent failures (if any) */}
            {summary.recent_failed_syncs.length > 0 && (
              <div style={{ marginBottom: "20px" }}>
                <RecentFailedSyncs syncs={summary.recent_failed_syncs} />
              </div>
            )}

            {/* Row 3: recent high/critical changes */}
            <RecentHighCriticalChanges
              changes={summary.recent_high_critical_changes}
            />

            {/* Footer link to full timeline */}
            <div style={{ marginTop: "16px", textAlign: "right" }}>
              <Link
                href="/timeline"
                style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
              >
                View full timeline →
              </Link>
            </div>
          </>
        )}
      </div>
    </>
  );
}
