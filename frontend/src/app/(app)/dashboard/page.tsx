"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
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
import { formatRelativeTime, formatAbsoluteTime } from "@/lib/utils";
import { usePollingRefresh } from "@/hooks/usePollingRefresh";
import { formatFieldLabel } from "@/lib/timeline";
import { PROVIDER_IDS, getProviderMeta } from "@/lib/providers";

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
    <div
      style={{ width: "1px", height: "36px", background: "#2a2d38", flexShrink: 0 }}
    />
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
      <div
        style={{ display: "flex", flexDirection: "column", gap: "14px", marginBottom: "24px" }}
      >
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
              <p
                style={{
                  margin: "0 0 2px",
                  fontSize: "13px",
                  fontWeight: 500,
                  color: step.done ? "#8b90a0" : "#e8eaf0",
                }}
              >
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
        aria-label="Refresh dashboard"
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

// ── Attention card — security posture summary ─────────────────────────────────

/**
 * Top-level security posture card. Shows "All clear" when there are no
 * high/critical changes and no integration issues; otherwise surfaces the
 * most urgent signal with a direct link to act.
 */
function AttentionCard({ summary }: { summary: DashboardSummary }) {
  const rd = summary.risk_distribution;
  const ih = summary.integration_health;
  const failedSyncs = summary.recent_failed_syncs.length;
  const highCritical7d = summary.change_activity.high_critical_last_7d;

  const hasCritical = rd.critical > 0;
  const hasHighRisk = rd.high > 0 || highCritical7d > 0;
  const hasIssues   = ih.needs_attention > 0 || failedSyncs > 0;

  // ── All clear ────────────────────────────────────────────────────────────
  if (!hasCritical && !hasHighRisk && !hasIssues) {
    return (
      <div
        style={{
          ...CARD,
          display: "flex",
          alignItems: "center",
          gap: "12px",
          borderColor: "rgba(60,207,126,0.25)",
          background: "rgba(60,207,126,0.05)",
          marginBottom: "20px",
        }}
        role="status"
        aria-label="Security posture: all clear"
      >
        <span
          aria-hidden="true"
          style={{
            flexShrink: 0,
            width: "10px",
            height: "10px",
            borderRadius: "50%",
            background: "#3ccf7e",
          }}
        />
        <div>
          <p style={{ margin: "0 0 2px", fontSize: "13px", fontWeight: 600, color: "#3ccf7e" }}>
            All clear
          </p>
          <p style={{ margin: 0, fontSize: "12px", color: "#565b6e" }}>
            No high-risk or critical changes detected. Monitoring is healthy.
          </p>
        </div>
      </div>
    );
  }

  // ── Attention needed ──────────────────────────────────────────────────────
  const msgs: string[] = [];
  if (rd.critical > 0)
    msgs.push(`${rd.critical} critical change${rd.critical !== 1 ? "s" : ""}`);
  if (rd.high > 0)
    msgs.push(`${rd.high} high-risk change${rd.high !== 1 ? "s" : ""}`);
  if (ih.needs_attention > 0)
    msgs.push(`${ih.needs_attention} integration${ih.needs_attention !== 1 ? "s" : ""} need attention`);
  if (failedSyncs > 0)
    msgs.push(`${failedSyncs} sync failure${failedSyncs !== 1 ? "s" : ""}`);

  const borderColor = hasCritical ? "rgba(232,64,64,0.35)" : "rgba(245,99,42,0.35)";
  const bgColor     = hasCritical ? "rgba(232,64,64,0.06)" : "rgba(245,99,42,0.06)";
  const titleColor  = hasCritical ? "#e84040" : "#f5632a";
  const title       = hasCritical ? "Critical attention required" : "Attention needed";
  const reviewHref  = hasCritical
    ? "/timeline?risk_level=critical"
    : rd.high > 0
    ? "/timeline?risk_level=high"
    : "/integrations";

  return (
    <div
      style={{
        ...CARD,
        display: "flex",
        alignItems: "flex-start",
        gap: "12px",
        borderColor,
        background: bgColor,
        marginBottom: "20px",
      }}
      role="status"
      aria-label={`Security posture: ${title}`}
    >
      <span
        aria-hidden="true"
        style={{
          flexShrink: 0,
          width: "10px",
          height: "10px",
          borderRadius: "50%",
          background: titleColor,
          marginTop: "3px",
        }}
      />
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ margin: "0 0 4px", fontSize: "13px", fontWeight: 600, color: titleColor }}>
          {title}
        </p>
        <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
          {msgs.join(" · ")}
          {(hasCritical || rd.high > 0) && (
            <>
              {" "}
              <Link
                href={reviewHref}
                style={{ color: titleColor, textDecoration: "none", fontWeight: 500 }}
              >
                Review now →
              </Link>
            </>
          )}
        </p>
      </div>
    </div>
  );
}

// ── Risk metrics row — 4 clickable stat cards ─────────────────────────────────

function RiskMetricsRow({ data }: { data: DashboardSummary["risk_distribution"] }) {
  const levels = [
    { key: "critical", label: "Critical", count: data.critical, color: "#e84040" },
    { key: "high",     label: "High",     count: data.high,     color: "#f5632a" },
    { key: "medium",   label: "Medium",   count: data.medium,   color: "#f5a623" },
    { key: "low",      label: "Low",      count: data.low,      color: "#6b9cf8" },
  ];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(4, 1fr)",
        gap: "12px",
        marginBottom: "20px",
      }}
    >
      {levels.map(({ key, label, count, color }) => (
        <Link
          key={key}
          href={`/timeline?risk_level=${key}`}
          style={{ textDecoration: "none" }}
          aria-label={`${count} ${label.toLowerCase()} risk changes — view in timeline`}
        >
          <div
            style={{
              ...CARD,
              padding: "16px 18px",
              borderColor: count > 0 ? `${color}40` : "#2a2d38",
            }}
            className="hover:bg-surface2"
          >
            <span
              style={{
                display: "block",
                fontSize: "28px",
                fontWeight: 700,
                color: count > 0 ? color : "#3a3d4a",
                lineHeight: 1,
                marginBottom: "6px",
              }}
            >
              {count}
            </span>
            <span
              style={{
                fontSize: "12px",
                color: count > 0 ? color : "#565b6e",
                fontWeight: 500,
              }}
            >
              {label}
            </span>
            <span
              style={{
                display: "block",
                fontSize: "10px",
                color: "#3a3d4a",
                marginTop: "2px",
              }}
            >
              all time
            </span>
          </div>
        </Link>
      ))}
    </div>
  );
}

// ── Connected providers card — all 7 providers, connected or not ──────────────

function ConnectedProvidersCard({
  distribution,
}: {
  distribution: DashboardSummary["provider_distribution"];
}) {
  const connectedMap = new Map(distribution.map((p) => [p.provider, p]));

  return (
    <Card>
      <SectionLabel>Provider coverage</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "9px" }}>
        {PROVIDER_IDS.map((pid) => {
          const meta  = getProviderMeta(pid);
          const stats = connectedMap.get(pid);
          const connected = !!stats;

          return (
            <div key={pid} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span
                aria-hidden="true"
                style={{
                  flexShrink: 0,
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: connected ? "#3ccf7e" : "#3a3d4a",
                }}
              />
              <span
                style={{
                  flex: 1,
                  fontSize: "13px",
                  color: connected ? "#e8eaf0" : "#565b6e",
                  fontWeight: 500,
                }}
              >
                {meta.label}
              </span>
              {connected && stats ? (
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <Link
                    href={`/timeline?provider=${pid}&time_range=7d`}
                    style={{ fontSize: "11px", color: "#4f80f7", textDecoration: "none" }}
                    title={`${stats.change_count_7d} change${stats.change_count_7d !== 1 ? "s" : ""} in last 7 days`}
                  >
                    {stats.change_count_7d} (7d)
                  </Link>
                  <span style={{ fontSize: "11px", color: "#565b6e" }}>
                    {stats.resource_count}r
                  </span>
                </div>
              ) : (
                <Link
                  href="/integrations"
                  style={{ fontSize: "11px", color: "#3a3d4a", textDecoration: "none" }}
                  aria-label={`Connect ${meta.label}`}
                >
                  Connect
                </Link>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ── Checklist card — prioritised action items ─────────────────────────────────

type CheckItem = {
  key: string;
  label: string;
  href?: string;
  severity: "critical" | "high" | "medium";
};

const SEV_COLOR: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
};

function ChecklistCard({ summary }: { summary: DashboardSummary }) {
  const items = useMemo<CheckItem[]>(() => {
    const result: CheckItem[] = [];
    const rd = summary.risk_distribution;
    const ih = summary.integration_health;
    const connectedSet = new Set(summary.provider_distribution.map((p) => p.provider));

    if (rd.critical > 0)
      result.push({
        key: "critical",
        label: `Review ${rd.critical} critical change${rd.critical !== 1 ? "s" : ""} immediately`,
        href: "/timeline?risk_level=critical",
        severity: "critical",
      });

    if (rd.high > 0)
      result.push({
        key: "high",
        label: `Investigate ${rd.high} high-risk change${rd.high !== 1 ? "s" : ""}`,
        href: "/timeline?risk_level=high",
        severity: "high",
      });

    if (ih.needs_attention > 0)
      result.push({
        key: "needs_attention",
        label: `Fix ${ih.needs_attention} integration${ih.needs_attention !== 1 ? "s" : ""} needing attention`,
        href: "/integrations",
        severity: "critical",
      });

    if (summary.recent_failed_syncs.length > 0)
      result.push({
        key: "sync_failures",
        label: `Resolve ${summary.recent_failed_syncs.length} sync failure${summary.recent_failed_syncs.length !== 1 ? "s" : ""}`,
        href: "/integrations",
        severity: "high",
      });

    if (ih.paused > 0)
      result.push({
        key: "paused",
        label: `Resume ${ih.paused} paused integration${ih.paused !== 1 ? "s" : ""}`,
        href: "/integrations",
        severity: "medium",
      });

    const disconnected = PROVIDER_IDS.filter((pid) => !connectedSet.has(pid));
    if (disconnected.length > 0 && connectedSet.size > 0)
      result.push({
        key: "disconnected",
        label: `Connect ${disconnected.length} more provider${disconnected.length !== 1 ? "s" : ""} for full coverage`,
        href: "/integrations",
        severity: "medium",
      });

    return result;
  }, [summary]);

  return (
    <Card>
      <SectionLabel>What to check next</SectionLabel>
      {items.length === 0 ? (
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span aria-hidden="true" style={{ color: "#3ccf7e", fontSize: "13px" }}>
            ✓
          </span>
          <span style={{ fontSize: "13px", color: "#8b90a0" }}>
            No immediate actions — all clear.
          </span>
        </div>
      ) : (
        <div
          role="list"
          aria-label="Action items"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          {items.map((item) => (
            <div
              key={item.key}
              role="listitem"
              style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}
            >
              <span
                aria-hidden="true"
                style={{
                  flexShrink: 0,
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: SEV_COLOR[item.severity],
                  marginTop: "5px",
                }}
              />
              {item.href ? (
                <Link
                  href={item.href}
                  style={{
                    fontSize: "12px",
                    color: "#e8eaf0",
                    textDecoration: "none",
                    lineHeight: 1.5,
                  }}
                >
                  {item.label}
                </Link>
              ) : (
                <span style={{ fontSize: "12px", color: "#e8eaf0", lineHeight: 1.5 }}>
                  {item.label}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── Dashboard change title helper ─────────────────────────────────────────────
//
// DashboardRecentChange lacks provider_metadata, so we can't call
// getTimelineEventTitle() directly. We derive a clean human title from the
// available provider + field_path fields.
//   e.g. "AWS: Last Used Service changed"
//        "GitHub: MFA Enabled added"
//        "Cloudflare: example.com"

function getDashboardChangeTitle(c: DashboardRecentChange): string {
  const pLabel = providerLabel(c.provider);
  const fieldLabel = c.field_path ? formatFieldLabel(c.field_path) : null;
  const ctLabel =
    c.change_type === "added"   ? "added" :
    c.change_type === "removed" ? "removed" :
    "changed";
  if (fieldLabel) {
    return `${pLabel}: ${fieldLabel} ${ctLabel}`;
  }
  return `${pLabel}: ${c.record_identifier}`;
}

// ── Risk colours for feed rows ────────────────────────────────────────────────

const RISK_DOT_COLOR: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
  low:      "#6b9cf8",
  unknown:  "#565b6e",
};

const RISK_LEFT_SHADOW: Partial<Record<string, string>> = {
  critical: "inset 3px 0 0 #e84040",
  high:     "inset 3px 0 0 #f5632a",
};

// ── Recent high/critical changes — polished feed ──────────────────────────────

function RecentHighCriticalChanges({
  changes,
}: {
  changes: DashboardRecentChange[];
}) {
  if (changes.length === 0) {
    return (
      <Card>
        <SectionLabel>Recent high & critical changes</SectionLabel>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
          No high or critical changes detected — your configuration surfaces look stable.
        </p>
      </Card>
    );
  }

  return (
    <Card style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ padding: "16px 20px 10px" }}>
        <SectionLabel>Recent high & critical changes</SectionLabel>
      </div>

      <div
        role="feed"
        aria-label="Recent high and critical changes"
        style={{ borderTop: "1px solid #2a2d38" }}
      >
        {changes.map((c) => {
          const riskKey    = (c.risk_level ?? "unknown").toLowerCase();
          const dotColor   = RISK_DOT_COLOR[riskKey] ?? RISK_DOT_COLOR.unknown;
          const leftShadow = RISK_LEFT_SHADOW[riskKey] ?? "none";
          const title      = getDashboardChangeTitle(c);

          return (
            <Link
              key={c.id}
              href={`/changes/${c.id}`}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "10px",
                padding: "10px 20px",
                borderBottom: "1px solid #1e2030",
                textDecoration: "none",
                cursor: "pointer",
                boxShadow: leftShadow,
                transition: "background 0.1s",
              }}
              className="hover:bg-surface2"
            >
              {/* Risk dot */}
              <span
                aria-hidden="true"
                style={{
                  flexShrink: 0,
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  background: dotColor,
                  marginTop: "5px",
                }}
              />

              {/* Content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                {/* Title + time */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "13px",
                      color: "#e8eaf0",
                      fontWeight: 500,
                      lineHeight: 1.4,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      minWidth: 0,
                    }}
                    title={title}
                  >
                    {title}
                  </span>
                  <span
                    style={{ fontSize: "11px", color: "#565b6e", flexShrink: 0 }}
                    title={formatAbsoluteTime(c.created_at)}
                  >
                    {formatRelativeTime(c.created_at)}
                  </span>
                </div>

                {/* Record identifier (secondary line) */}
                <div
                  style={{
                    marginTop: "3px",
                    fontSize: "11px",
                    color: "#565b6e",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {c.record_identifier}
                </div>
              </div>
            </Link>
          );
        })}
      </div>

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
                  <>
                    {" · "}
                    <span style={{ color: "#8b90a0" }}>{s.failure_category}</span>
                  </>
                )}
                {s.consecutive_failure_count > 0 && (
                  <>
                    {" · "}
                    {s.consecutive_failure_count} consecutive failure
                    {s.consecutive_failure_count !== 1 ? "s" : ""}
                  </>
                )}
              </p>
              {s.recommended_action && (
                <p
                  style={{
                    margin: "4px 0 0",
                    fontSize: "11px",
                    color: "#8b90a0",
                    lineHeight: 1.5,
                  }}
                >
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
        description="See what changed, what matters, and what needs review."
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
            value={summary.change_activity.high_critical_last_7d}
            label="High/critical (7d)"
            valueColor={
              summary.change_activity.high_critical_last_7d > 0 ? "#f5632a" : undefined
            }
            href={
              summary.change_activity.high_critical_last_7d > 0
                ? "/timeline?time_range=7d&risk_level=high"
                : undefined
            }
          />
          {summary.change_activity.last_change_at && (
            <>
              <Divider />
              <div className="flex flex-col gap-1">
                <span
                  style={{
                    fontSize: "24px",
                    fontWeight: 600,
                    color: "#e8eaf0",
                    lineHeight: 1,
                  }}
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
                label: "Connect a provider",
                body: "Add an integration — ConfigTrace supports Cloudflare, GitHub, Vercel, Stripe, AWS, Firebase, and Supabase. It monitors configuration drift, not code.",
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

        {/* ── Security command center ───────────────────────────────────── */}
        {hasData && summary && (
          <>
            <RefreshBar lastUpdatedAt={lastUpdatedAt} onRefresh={refresh} />

            {/* 1. Security posture — all-clear or attention-needed */}
            <AttentionCard summary={summary} />

            {/* 2. Risk metrics — Critical / High / Medium / Low (all-time) */}
            <RiskMetricsRow data={summary.risk_distribution} />

            {/* 3. Recent changes (left) + sidebar: checklist + providers (right) */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 300px",
                gap: "16px",
                marginBottom: "20px",
                alignItems: "start",
              }}
            >
              {/* What changed & what is risky */}
              <RecentHighCriticalChanges
                changes={summary.recent_high_critical_changes}
              />

              {/* What to do + which providers are connected */}
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <ChecklistCard summary={summary} />
                <ConnectedProvidersCard distribution={summary.provider_distribution} />
              </div>
            </div>

            {/* 4. Sync failures (if any) — monitoring health detail */}
            {summary.recent_failed_syncs.length > 0 && (
              <div style={{ marginBottom: "20px" }}>
                <RecentFailedSyncs syncs={summary.recent_failed_syncs} />
              </div>
            )}

            {/* Footer link to full timeline */}
            <div style={{ textAlign: "right" }}>
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
