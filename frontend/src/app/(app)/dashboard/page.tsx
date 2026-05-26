"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type {
  DashboardRecentChange,
  DashboardRecentFailedSync,
  DashboardSummary,
  DriftScoreFactor,
  DriftScoreResponse,
  ReviewQueueCounts,
} from "@/types";
import { getDashboardSummary, getWorkspaceDriftScore } from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
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
    case "shopify":    return "Shopify";
    default:           return provider ?? "Unknown";
  }
}

// ── Activation progress panel ─────────────────────────────────────────────────
//
// Shows in three pre-operational states:
//   doneCount = 0 → no integrations connected
//   doneCount = 1 → has integrations, waiting for first sync / no resources yet
//   doneCount = 2 → baseline established, waiting for second sync to detect changes

const ACTIVATION_STEPS: { label: string; body: string }[] = [
  {
    label: "Connect a provider",
    body:  "Link AWS, GitHub, Cloudflare, Vercel, Stripe, Firebase, Supabase, or Shopify. ConfigTrace monitors configuration metadata — not source code, secret values, or customer data.",
  },
  {
    label: "Run your first sync",
    body:  "The first sync captures a baseline snapshot of your current configuration. Nothing is flagged as a change on this run — it establishes the comparison point.",
  },
  {
    label: "See your first change",
    body:  "From the second sync onwards, ConfigTrace compares snapshots and surfaces exactly what changed, when, and what the risk score is.",
  },
];

const ACTIVATION_HEADING = [
  "Start monitoring your first configuration surface.",
  "Ready for your first sync.",
  "Baseline captured — sync again to detect configuration drift.",
] as const;

const ACTIVATION_CTA: Array<{ label: string; href: string }> = [
  { label: "Connect an integration →", href: "/integrations" },
  { label: "Go to Integrations →",     href: "/integrations" },
  { label: "Browse your resources →",  href: "/resources"    },
];

function ActivationPanel({ doneCount }: { doneCount: 0 | 1 | 2 }) {
  const cta = ACTIVATION_CTA[doneCount];
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
        {ACTIVATION_HEADING[doneCount]}
      </p>

      <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginBottom: "24px" }}>
        {ACTIVATION_STEPS.map((step, i) => {
          const done    = i < doneCount;
          const current = i === doneCount;
          return (
            <div key={step.label} style={{ display: "flex", gap: "14px", alignItems: "flex-start" }}>
              {/* Step indicator */}
              <div
                style={{
                  flexShrink: 0,
                  width: "22px",
                  height: "22px",
                  borderRadius: "50%",
                  background: done ? "#3ccf7e" : current ? "#4f80f7" : "#1e2030",
                  border: (done || current) ? "none" : "1px solid #3a3d4a",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: "11px",
                  fontWeight: 700,
                  color: (done || current) ? "#ffffff" : "#565b6e",
                  marginTop: "1px",
                }}
              >
                {done ? "✓" : i + 1}
              </div>

              {/* Step content */}
              <div>
                <p
                  style={{
                    margin: "0 0 2px",
                    fontSize: "13px",
                    fontWeight: 500,
                    color: done ? "#565b6e" : current ? "#e8eaf0" : "#8b90a0",
                  }}
                >
                  {step.label}
                </p>
                <p
                  style={{
                    margin: 0,
                    fontSize: "12px",
                    color: done ? "#3a3d4a" : "#565b6e",
                    lineHeight: 1.6,
                  }}
                >
                  {step.body}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      <Link
        href={cta.href}
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
        {cta.label}
      </Link>

      <p style={{ margin: "14px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        High-risk and critical changes trigger email alerts automatically.
        ConfigTrace reads configuration metadata only — never source code, secret values, or customer data.{" "}
        <Link
          href="/settings/workspace/data-access"
          style={{ color: "#4f80f7", textDecoration: "none" }}
        >
          Data access policy →
        </Link>
      </p>
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
  const ih = summary.integration_health;
  const rq = summary.review_queue;
  const failedSyncs = summary.recent_failed_syncs.length;

  // "Attention needed" when there are UNREVIEWED critical/high changes or integration issues.
  // "All clear" means the review queue is empty and monitoring is healthy.
  const hasCritical = rq.critical > 0;
  const hasHighRisk = rq.high > 0;
  const hasIssues   = ih.needs_attention > 0 || failedSyncs > 0;

  // ── All clear ────────────────────────────────────────────────────────────
  if (!hasCritical && !hasHighRisk && !hasIssues) {
    const allSyncsHealthy = ih.total > 0 && ih.needs_attention === 0 && failedSyncs === 0;
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
            {allSyncsHealthy
              ? "Review queue is empty. Monitoring is healthy."
              : "No unreviewed high-risk or critical changes. Review queue is empty."}
          </p>
        </div>
      </div>
    );
  }

  // ── Attention needed ──────────────────────────────────────────────────────
  const msgs: string[] = [];
  if (rq.critical > 0)
    msgs.push(`${rq.critical} critical change${rq.critical !== 1 ? "s" : ""} need review`);
  if (rq.high > 0)
    msgs.push(`${rq.high} high-risk change${rq.high !== 1 ? "s" : ""} need review`);
  if (ih.needs_attention > 0)
    msgs.push(`${ih.needs_attention} integration${ih.needs_attention !== 1 ? "s" : ""} need attention`);
  if (failedSyncs > 0)
    msgs.push(`${failedSyncs} sync failure${failedSyncs !== 1 ? "s" : ""}`);

  const borderColor = hasCritical ? "rgba(232,64,64,0.35)" : "rgba(245,99,42,0.35)";
  const bgColor     = hasCritical ? "rgba(232,64,64,0.06)" : "rgba(245,99,42,0.06)";
  const titleColor  = hasCritical ? "#e84040" : "#f5632a";
  const title       = hasCritical ? "Critical attention required" : "Attention needed";
  const reviewHref  = (hasCritical || hasHighRisk) ? "/needs-review" : "/integrations";

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
          {(hasCritical || hasHighRisk) && (
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

// ── Review queue card — unreviewed critical/high counts ──────────────────────

function ReviewQueueCard({ rq }: { rq: ReviewQueueCounts }) {
  if (rq.total === 0) return null;
  const other = Math.max(0, rq.total - rq.critical - rq.high);

  return (
    <div
      style={{
        ...CARD,
        marginBottom: "20px",
        display: "flex",
        alignItems: "center",
        gap: "16px",
        padding: "12px 20px",
      }}
    >
      <span
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase" as const,
          letterSpacing: "0.06em",
          fontWeight: 500,
          flexShrink: 0,
        }}
      >
        Review queue
      </span>
      <div style={{ flex: 1, display: "flex", flexWrap: "wrap", alignItems: "center", gap: "10px" }}>
        {rq.critical > 0 && (
          <span style={{ fontSize: "12px", color: "#e84040", fontWeight: 600 }}>
            ● {rq.critical} critical
          </span>
        )}
        {rq.high > 0 && (
          <span style={{ fontSize: "12px", color: "#f5632a", fontWeight: 600 }}>
            ● {rq.high} high
          </span>
        )}
        {other > 0 && (
          <span style={{ fontSize: "12px", color: "#8b90a0" }}>
            {other} other
          </span>
        )}
        <span style={{ fontSize: "12px", color: "#565b6e" }}>
          unreviewed
        </span>
      </div>
      <Link
        href="/needs-review"
        style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none", flexShrink: 0, fontWeight: 500 }}
      >
        Open review queue →
      </Link>
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
    const rq = summary.review_queue;
    const connectedSet = new Set(summary.provider_distribution.map((p) => p.provider));

    // M57.3: unreviewed critical/high changes are the top priority
    if (rq.critical > 0)
      result.push({
        key: "review_critical",
        label: `Review ${rq.critical} critical unreviewed change${rq.critical !== 1 ? "s" : ""}`,
        href: "/needs-review",
        severity: "critical",
      });

    if (rq.high > 0)
      result.push({
        key: "review_high",
        label: `Review ${rq.high} high-risk unreviewed change${rq.high !== 1 ? "s" : ""}`,
        href: "/needs-review",
        severity: "high",
      });

    if (rd.critical > 0 && rq.critical === 0)
      result.push({
        key: "critical",
        label: `Review ${rd.critical} critical change${rd.critical !== 1 ? "s" : ""} immediately`,
        href: "/timeline?risk_level=critical",
        severity: "critical",
      });

    if (rd.high > 0 && rq.high === 0)
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
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
            <span aria-hidden="true" style={{ color: "#3ccf7e", fontSize: "13px" }}>
              ✓
            </span>
            <span style={{ fontSize: "13px", color: "#8b90a0" }}>
              No immediate actions — all clear.
            </span>
          </div>
          <p
            style={{
              margin: "0 0 8px",
              fontSize: "10px",
              color: "#3a3d4a",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
            }}
          >
            Suggested
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
            <Link
              href="/settings/workspace/notifications"
              style={{ fontSize: "12px", color: "#565b6e", textDecoration: "none" }}
            >
              → Configure Slack or webhook alerts
            </Link>
            <Link
              href="/settings/workspace/data-access"
              style={{ fontSize: "12px", color: "#565b6e", textDecoration: "none" }}
            >
              → Review data access policy
            </Link>
            <Link
              href="/settings/workspace/members"
              style={{ fontSize: "12px", color: "#565b6e", textDecoration: "none" }}
            >
              → Invite a teammate
            </Link>
          </div>
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

// ── Drift Control Score card (M58.17) ────────────────────────────────────────

const GRADE_COLOR: Record<string, string> = {
  strong: "#3ccf7e",
  good: "#4f80f7",
  needs_attention: "#f5a623",
  weak: "#f5632a",
};

const GRADE_LABEL: Record<string, string> = {
  strong: "Strong",
  good: "Good",
  needs_attention: "Needs Attention",
  weak: "Weak",
};

const STATUS_COLOR: Record<string, string> = {
  good: "#3ccf7e",
  needs_attention: "#f5a623",
  critical: "#f5632a",
};

function DriftScoreFactorRow({ factor }: { factor: DriftScoreFactor }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "8px 0",
        borderBottom: "1px solid #1e2130",
      }}
    >
      <span
        style={{
          flexShrink: 0,
          minWidth: "40px",
          fontSize: "12px",
          fontWeight: 600,
          color: STATUS_COLOR[factor.status] ?? "#8b90a0",
          textAlign: "right",
        }}
      >
        {factor.impact > 0 ? `+${factor.impact}` : factor.impact}
      </span>
      <div style={{ flex: 1 }}>
        <p style={{ margin: 0, fontSize: "12px", color: "#c4c8d4", fontWeight: 500 }}>
          {factor.label}
        </p>
        <p style={{ margin: "2px 0 0", fontSize: "11px", color: "#8b90a0" }}>
          {factor.detail}
        </p>
      </div>
      {factor.action_href && factor.action_label && (
        <Link
          href={factor.action_href}
          style={{
            flexShrink: 0,
            fontSize: "11px",
            color: "#4f80f7",
            textDecoration: "none",
            whiteSpace: "nowrap",
          }}
        >
          {factor.action_label} →
        </Link>
      )}
    </div>
  );
}

function DriftScoreCard({ score }: { score: DriftScoreResponse }) {
  const gradeColor = GRADE_COLOR[score.grade] ?? "#8b90a0";
  const gradeLabel = GRADE_LABEL[score.grade] ?? score.grade;

  return (
    <Card style={{ marginBottom: "20px" }}>
      {/* Header row: score + grade */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "4px",
        }}
      >
        <div>
          <SectionLabel>Drift Control Score</SectionLabel>
          <p
            style={{
              margin: 0,
              fontSize: "13px",
              color: "#8b90a0",
              maxWidth: "480px",
            }}
          >
            {score.summary}
          </p>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0, marginLeft: "16px" }}>
          <span
            style={{
              fontSize: "40px",
              fontWeight: 700,
              color: gradeColor,
              lineHeight: 1,
            }}
          >
            {score.score}
          </span>
          <span
            style={{
              display: "block",
              fontSize: "11px",
              color: gradeColor,
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              marginTop: "2px",
            }}
          >
            {gradeLabel}
          </span>
        </div>
      </div>

      {/* Score bar */}
      <div
        style={{
          height: "4px",
          background: "#1e2130",
          borderRadius: "2px",
          margin: "14px 0",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${score.score}%`,
            background: gradeColor,
            borderRadius: "2px",
            transition: "width 0.4s ease",
          }}
        />
      </div>

      {/* Penalty factors */}
      {score.factors.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          {score.factors.map((f) => (
            <DriftScoreFactorRow key={f.key} factor={f} />
          ))}
        </div>
      )}

      {/* Positive signals */}
      {score.positive_signals.length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "6px",
            marginBottom: "12px",
          }}
        >
          {score.positive_signals.map((sig, i) => (
            <span
              key={i}
              style={{
                fontSize: "11px",
                color: "#3ccf7e",
                background: "#0d2018",
                border: "1px solid #1a4028",
                borderRadius: "12px",
                padding: "2px 8px",
              }}
            >
              ✓ {sig}
            </span>
          ))}
        </div>
      )}

      {/* Footer: period + advisory note */}
      <p style={{ margin: 0, fontSize: "11px", color: "#565b6e" }}>
        Based on the last {score.period_days} days ·{" "}
        <span style={{ fontStyle: "italic" }}>
          Advisory only — not a compliance or security rating
        </span>
      </p>
    </Card>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { getToken, isLoaded } = useAuth();
  const { selectedWorkspace } = useWorkspace();

  // ── Drift Control Score state (M58.17) ───────────────────────────────────
  const [driftScore, setDriftScore] = useState<DriftScoreResponse | null>(null);

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

  // Fetch Drift Control Score whenever the selected workspace changes
  useEffect(() => {
    if (!isLoaded || !selectedWorkspace) return;
    void (async () => {
      try {
        const token = await getToken();
        const scoreData = await getWorkspaceDriftScore(selectedWorkspace.id, token);
        setDriftScore(scoreData);
      } catch {
        // Score fetch failure is non-fatal; card simply won't render
        setDriftScore(null);
      }
    })();
  }, [isLoaded, selectedWorkspace, getToken]);

  const { refresh, lastUpdatedAt } = usePollingRefresh({
    callback: fetchSummary,
    intervalMs: 30_000,
    enabled: !loading && isLoaded,
  });

  // ── Derived state ─────────────────────────────────────────────────────────
  const ih                = summary?.integration_health;
  const totalIntegrations = ih?.total ?? 0;
  const totalResources    = summary?.resource_counts.active ?? 0;
  const totalChanges      = summary?.change_activity.total ?? 0;
  // Pre-operational activation phases
  const noIntegrations = !loading && !error && !!summary && totalIntegrations === 0;
  const isSyncPending  = !loading && !error && !!summary && totalIntegrations > 0 && totalResources === 0;
  const isBaselineOnly = !loading && !error && !!summary && totalResources > 0 && totalChanges === 0;
  // Operational state — changes detected
  const hasData        = !loading && !error && !!summary && totalChanges > 0;

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
          <Divider />
          <StatCell
            value={summary.review_queue.total}
            label="Needs review"
            valueColor={summary.review_queue.total > 0 ? "#f5a623" : undefined}
            href={summary.review_queue.total > 0 ? "/needs-review" : undefined}
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

        {/* ── Activation progress (pre-operational states) ─────────────── */}
        {noIntegrations && <ActivationPanel doneCount={0} />}
        {isSyncPending  && <ActivationPanel doneCount={1} />}
        {isBaselineOnly && (
          <>
            <ActivationPanel doneCount={2} />
            {summary && (
              <div style={{ marginTop: "16px" }}>
                <ConnectedProvidersCard distribution={summary.provider_distribution} />
              </div>
            )}
          </>
        )}

        {/* ── Security command center ───────────────────────────────────── */}
        {hasData && summary && (
          <>
            <RefreshBar lastUpdatedAt={lastUpdatedAt} onRefresh={refresh} />

            {/* 1. Drift Control Score — advisory 0-100 hygiene measure (M58.17) */}
            {driftScore && <DriftScoreCard score={driftScore} />}

            {/* 2. Security posture — all-clear or attention-needed */}
            <AttentionCard summary={summary} />

            {/* 3. Review queue — unreviewed critical / high counts */}
            <ReviewQueueCard rq={summary.review_queue} />

            {/* 4. Risk metrics — Critical / High / Medium / Low (all-time) */}
            <RiskMetricsRow data={summary.risk_distribution} />

            {/* 4. Recent changes (left) + sidebar: checklist + providers (right) */}
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

            {/* 5. Sync failures (if any) — monitoring health detail */}
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
