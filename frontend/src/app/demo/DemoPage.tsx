"use client";

/**
 * DemoPage — M58.13 Public Demo Risk Timeline.
 *
 * Fully self-contained, no auth context, no API calls.
 * All data comes from @/lib/demoData (synthetic).
 *
 * Layout (top → bottom):
 *   1. Top nav (logo + Demo badge + CTA)
 *   2. Hero section (title, subtitle, hero copy)
 *   3. Risk summary strip
 *   4. Main content — split: timeline list + selected change detail
 *   5. Cross-provider cluster callout
 *   6. Product feature pills
 *   7. Data safety disclaimer + footer
 *
 * Design uses the app's colour tokens (same dark theme).
 * No external dependencies beyond project-internal libs.
 */

import { useState } from "react";
import Link from "next/link";
import {
  DEMO_CHANGES,
  DEMO_CLUSTERS,
  getDemoRiskCounts,
  getDemoClusterForChange,
  type DemoChange,
  type DemoCluster,
} from "@/lib/demoData";
import { getProviderMeta } from "@/lib/providers";

// ── Colour / style helpers ────────────────────────────────────────────────────

const RISK_COLORS: Record<string, { dot: string; bg: string; text: string; border: string }> = {
  critical: { dot: "#e84040", bg: "rgba(232,64,64,0.12)",  text: "#e84040", border: "rgba(232,64,64,0.35)" },
  high:     { dot: "#f5632a", bg: "rgba(245,99,42,0.12)",  text: "#f5632a", border: "rgba(245,99,42,0.35)" },
  medium:   { dot: "#f5a623", bg: "rgba(245,166,35,0.12)", text: "#f5a623", border: "rgba(245,166,35,0.35)" },
  low:      { dot: "#6b9cf8", bg: "rgba(107,156,248,0.12)", text: "#6b9cf8", border: "rgba(107,156,248,0.35)" },
};

const RISK_LEFT_STRIPE: Partial<Record<string, string>> = {
  critical: "inset 3px 0 0 #e84040",
  high:     "inset 3px 0 0 #f5632a",
};

const CHANGE_TYPE_COLOR: Record<string, string> = {
  added:    "#3ccf7e",
  removed:  "#e84040",
  modified: "#8b90a0",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const s = RISK_COLORS[level] ?? RISK_COLORS.low;
  return (
    <span
      aria-label={`Risk: ${level}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        background: s.bg,
        color: s.text,
        border: `1px solid ${s.border}`,
        borderRadius: "4px",
        padding: "1px 7px",
        fontSize: "10px",
        fontWeight: 700,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      {level}
    </span>
  );
}

function ProviderBadge({ provider }: { provider: string }) {
  const meta = getProviderMeta(provider);
  return (
    <span
      aria-label={`Provider: ${meta.shortLabel}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        background: meta.bgColor,
        color: meta.color,
        border: `1px solid ${meta.borderColor}`,
        borderRadius: "4px",
        padding: "1px 6px",
        fontSize: "10px",
        fontWeight: 500,
        whiteSpace: "nowrap",
        flexShrink: 0,
        letterSpacing: "0.02em",
      }}
    >
      {meta.shortLabel}
    </span>
  );
}

// ── Timeline row ──────────────────────────────────────────────────────────────

function DemoChangeRow({
  change,
  selected,
  onClick,
}: {
  change: DemoChange;
  selected: boolean;
  onClick: () => void;
}) {
  const risk = RISK_COLORS[change.risk_level] ?? RISK_COLORS.low;
  const leftShadow = RISK_LEFT_STRIPE[change.risk_level] ?? "none";
  const hasCluster = !!change.cluster_id;

  return (
    <button
      onClick={onClick}
      aria-selected={selected}
      style={{
        width: "100%",
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "10px 16px",
        borderTop: "none",
        borderLeft: "none",
        borderRight: "none",
        borderBottom: "1px solid #2a2d38",
        textDecoration: "none",
        cursor: "pointer",
        boxShadow: selected
          ? `inset 3px 0 0 #4f80f7, inset 0 0 0 1px rgba(79,128,247,0.18)`
          : leftShadow,
        background: selected ? "rgba(79,128,247,0.06)" : "transparent",
        outline: selected ? "1px solid rgba(79,128,247,0.18)" : "none",
        outlineOffset: "-1px",
        fontFamily: "inherit",
        textAlign: "left",
        transition: "background 0.1s",
      }}
      className={selected ? "" : "hover:bg-surface3"}
    >
      {/* Risk dot */}
      <span
        aria-hidden="true"
        style={{
          flexShrink: 0,
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: risk.dot,
          marginTop: "5px",
        }}
      />

      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Title + risk badge */}
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
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={change.title}
          >
            {change.title}
          </span>
          <RiskBadge level={change.risk_level} />
        </div>

        {/* Description */}
        <p
          style={{
            margin: "3px 0 0",
            fontSize: "12px",
            color: "#8b90a0",
            lineHeight: 1.5,
            overflow: "hidden",
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
          }}
        >
          {change.description}
        </p>

        {/* Metadata row */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "4px",
            marginTop: "5px",
            fontSize: "11px",
            color: "#565b6e",
          }}
        >
          <span>{change.timestamp_label}</span>
          <span aria-hidden="true">·</span>
          <ProviderBadge provider={change.provider} />
          <span aria-hidden="true">·</span>
          <span>{change.category}</span>
          <span aria-hidden="true">·</span>
          <span style={{ color: CHANGE_TYPE_COLOR[change.change_type] ?? "#8b90a0" }}>
            {change.change_type}
          </span>
          {hasCluster && (
            <>
              <span aria-hidden="true">·</span>
              <span
                style={{
                  fontSize: "10px",
                  color: "#8b5cf6",
                  border: "1px solid rgba(139,92,246,0.25)",
                  borderRadius: "3px",
                  padding: "1px 5px",
                }}
              >
                clustered
              </span>
            </>
          )}
        </div>
      </div>
    </button>
  );
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p
      style={{
        margin: "0 0 6px",
        fontSize: "10px",
        fontWeight: 600,
        color: "#3a3e50",
        textTransform: "uppercase",
        letterSpacing: "0.07em",
      }}
    >
      {children}
    </p>
  );
}

function BulletList({ items, color = "#8b90a0" }: { items: string[]; color?: string }) {
  return (
    <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
      {items.map((item, i) => (
        <li
          key={i}
          style={{
            fontSize: "12px",
            color,
            lineHeight: 1.6,
            paddingBottom: "2px",
            display: "flex",
            gap: "7px",
          }}
        >
          <span aria-hidden="true" style={{ color: "#4f80f7", flexShrink: 0, marginTop: "1px" }}>
            ·
          </span>
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

function DemoDetailPanel({
  change,
  cluster,
}: {
  change: DemoChange;
  cluster: DemoCluster | null;
}) {
  const meta = getProviderMeta(change.provider);

  return (
    <div
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        overflow: "hidden",
        animation: "fadeIn 0.15s ease",
      }}
    >
      {/* Panel header */}
      <div
        style={{
          padding: "14px 18px",
          borderBottom: "1px solid #2a2d38",
          background: "#0f1117",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            flexWrap: "wrap",
            marginBottom: "6px",
          }}
        >
          <ProviderBadge provider={change.provider} />
          <RiskBadge level={change.risk_level} />
          <span style={{ fontSize: "11px", color: "#565b6e" }}>{change.timestamp_label}</span>
        </div>
        <h2
          style={{
            margin: 0,
            fontSize: "14px",
            fontWeight: 600,
            color: "#e8eaf0",
            lineHeight: 1.4,
          }}
        >
          {change.title}
        </h2>
        <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#8b90a0", lineHeight: 1.5 }}>
          {change.resource_name} · {change.category}
        </p>
      </div>

      <div style={{ padding: "16px 18px", display: "flex", flexDirection: "column", gap: "18px" }}>

        {/* Cluster callout */}
        {cluster && (
          <div
            style={{
              background: "rgba(139,92,246,0.06)",
              border: "1px solid rgba(139,92,246,0.20)",
              borderRadius: "6px",
              padding: "10px 14px",
            }}
          >
            <p
              style={{
                margin: "0 0 4px",
                fontSize: "10px",
                fontWeight: 600,
                color: "#8b5cf6",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              Risk cluster · {cluster.title}
            </p>
            <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.5 }}>
              {cluster.description}
            </p>
          </div>
        )}

        {/* What changed */}
        <div>
          <SectionLabel>What changed</SectionLabel>
          <p style={{ margin: 0, fontSize: "13px", color: "#b0b5c4", lineHeight: 1.7 }}>
            {change.what_changed}
          </p>
        </div>

        {/* Why it matters */}
        <div>
          <SectionLabel>Why it matters</SectionLabel>
          <p style={{ margin: 0, fontSize: "13px", color: "#b0b5c4", lineHeight: 1.7 }}>
            {change.why_it_matters}
          </p>
        </div>

        {/* What to check */}
        <div>
          <SectionLabel>What to check</SectionLabel>
          <BulletList items={change.what_to_check} />
        </div>

        {/* Remediation */}
        <div
          style={{
            background: "rgba(60,207,126,0.04)",
            border: "1px solid rgba(60,207,126,0.14)",
            borderRadius: "6px",
            padding: "12px 14px",
          }}
        >
          <SectionLabel>Suggested remediation</SectionLabel>
          <p
            style={{
              margin: "0 0 10px",
              fontSize: "13px",
              color: "#b0b5c4",
              lineHeight: 1.7,
            }}
          >
            {change.remediation_summary}
          </p>
          <BulletList items={change.remediation_steps} />
        </div>

        {/* Fix plan + Dry-run grid */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "12px",
          }}
        >
          <div
            style={{
              background: "#0e0f11",
              border: "1px solid #1e2030",
              borderRadius: "6px",
              padding: "10px 12px",
            }}
          >
            <SectionLabel>Fix plan preview</SectionLabel>
            <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
              {change.fix_plan_summary}
            </p>
          </div>
          <div
            style={{
              background: "#0e0f11",
              border: "1px solid #1e2030",
              borderRadius: "6px",
              padding: "10px 12px",
            }}
          >
            <SectionLabel>Dry-run preview</SectionLabel>
            <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
              {change.dry_run_summary}
            </p>
          </div>
        </div>

        {/* Blast radius */}
        <div
          style={{
            background: "#0e0f11",
            border: "1px solid #1e2030",
            borderRadius: "6px",
            padding: "10px 12px",
          }}
        >
          <SectionLabel>Blast radius</SectionLabel>
          <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
            {change.blast_radius_summary}
          </p>
        </div>

        {/* Ask ConfigTrace Q&A */}
        <div
          style={{
            background: "rgba(79,128,247,0.04)",
            border: "1px solid rgba(79,128,247,0.14)",
            borderRadius: "6px",
            padding: "12px 14px",
          }}
        >
          <p
            style={{
              margin: "0 0 6px",
              fontSize: "10px",
              fontWeight: 600,
              color: "#4f80f7",
              textTransform: "uppercase",
              letterSpacing: "0.07em",
            }}
          >
            Ask ConfigTrace
          </p>
          <p
            style={{
              margin: "0 0 8px",
              fontSize: "12px",
              color: "#c4c8d4",
              fontWeight: 500,
              fontStyle: "italic",
            }}
          >
            "{change.ask_configtrace.question}"
          </p>
          <p style={{ margin: "0 0 8px", fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
            {change.ask_configtrace.answer}
          </p>
          <BulletList items={change.ask_configtrace.bullets} color="#565b6e" />
        </div>

        {/* Disclaimer */}
        <p
          style={{
            margin: 0,
            fontSize: "10px",
            color: "#3a3e50",
            fontStyle: "italic",
            lineHeight: 1.5,
            borderTop: "1px solid #1e2030",
            paddingTop: "10px",
          }}
        >
          ℹ All information above is based on configuration metadata only. ConfigTrace does not read
          customer data, secret values, source code, or database rows. Review provider context before
          taking action.
        </p>
      </div>
    </div>
  );
}

// ── Risk summary strip ────────────────────────────────────────────────────────

function DemoRiskStrip() {
  const counts = getDemoRiskCounts();
  const items: { key: string; label: string; count: number; color: string }[] = [
    { key: "critical", label: "Critical", count: counts.critical, color: "#e84040" },
    { key: "high",     label: "High",     count: counts.high,     color: "#f5632a" },
    { key: "medium",   label: "Medium",   count: counts.medium,   color: "#f5a623" },
    { key: "low",      label: "Low",      count: counts.low,      color: "#6b9cf8" },
  ];

  return (
    <div
      aria-label="Demo risk summary"
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "6px",
        padding: "8px 14px",
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        marginBottom: "20px",
        fontSize: "12px",
      }}
    >
      <span style={{ color: "#8b90a0", fontWeight: 500 }}>Synthetic demo data</span>
      <span aria-hidden="true" style={{ color: "#2a2d38" }}>·</span>
      {items.map(({ key, label, count, color }, i) => (
        <span key={key} style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
          <span
            aria-hidden="true"
            style={{
              display: "inline-block",
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              background: color,
            }}
          />
          <span style={{ color: count > 0 ? color : "#3a3e50", fontWeight: count > 0 ? 600 : 400 }}>
            {count}
          </span>{" "}
          <span style={{ color: "#565b6e" }}>{label}</span>
          {i < items.length - 1 && (
            <span aria-hidden="true" style={{ color: "#2a2d38", marginLeft: "2px" }}>
              ·
            </span>
          )}
        </span>
      ))}
      <span aria-hidden="true" style={{ color: "#2a2d38" }}>·</span>
      <span style={{ color: "#565b6e" }}>
        <span style={{ color: "#b0b5c4", fontWeight: 600 }}>{counts.providerCount}</span>{" "}
        providers covered
      </span>
      <span aria-hidden="true" style={{ color: "#2a2d38" }}>·</span>
      <span style={{ color: "#565b6e" }}>
        <span style={{ color: "#f5a623", fontWeight: 600 }}>{counts.needsReview}</span>{" "}
        needs review
      </span>
    </div>
  );
}

// ── Cluster callout ───────────────────────────────────────────────────────────

function ClusterCallout({
  cluster,
  onSelectChange,
}: {
  cluster: DemoCluster;
  onSelectChange: (id: string) => void;
}) {
  return (
    <section
      aria-labelledby="demo-cluster-title"
      style={{
        background: "rgba(139,92,246,0.05)",
        border: "1px solid rgba(139,92,246,0.20)",
        borderRadius: "8px",
        padding: "18px 20px",
        marginBottom: "24px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: "8px",
        }}
      >
        <span
          style={{
            fontSize: "10px",
            fontWeight: 700,
            color: "#8b5cf6",
            textTransform: "uppercase",
            letterSpacing: "0.07em",
          }}
        >
          Cross-provider risk cluster
        </span>
      </div>

      <h3
        id="demo-cluster-title"
        style={{ margin: "0 0 6px", fontSize: "14px", fontWeight: 600, color: "#c4c8d4" }}
      >
        {cluster.title}
      </h3>

      <p style={{ margin: "0 0 12px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        {cluster.description}
      </p>

      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "6px",
          marginBottom: "10px",
        }}
      >
        {cluster.providers.map((p) => (
          <ProviderBadge key={p} provider={p} />
        ))}
        <span
          style={{
            fontSize: "11px",
            color: "#8b5cf6",
            padding: "1px 7px",
            border: "1px solid rgba(139,92,246,0.20)",
            borderRadius: "4px",
          }}
        >
          within {cluster.timespan_label}
        </span>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {cluster.change_ids.map((id) => {
          const change = DEMO_CHANGES.find((c) => c.id === id);
          if (!change) return null;
          return (
            <button
              key={id}
              onClick={() => onSelectChange(id)}
              style={{
                fontSize: "11px",
                color: "#4f80f7",
                background: "rgba(79,128,247,0.06)",
                border: "1px solid rgba(79,128,247,0.18)",
                borderRadius: "4px",
                padding: "3px 9px",
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              {change.resource_name} ({getProviderMeta(change.provider).shortLabel})
            </button>
          );
        })}
      </div>
    </section>
  );
}

// ── Product feature pills ──────────────────────────────────────────────────────

const FEATURE_PILLS = [
  { icon: "📡", label: "Configuration metadata-only monitoring" },
  { icon: "🔔", label: "Slack, email, webhook & browser push alerts" },
  { icon: "✅", label: "Review workflow (ack, snooze, expected)" },
  { icon: "🛠", label: "Remediation guidance + fix plan preview" },
  { icon: "🧪", label: "Dry-run remediation preview" },
  { icon: "🔍", label: "Risk cluster correlation" },
  { icon: "💥", label: "Blast radius analysis" },
  { icon: "🛡", label: "Trust Center + security packet export" },
] as const;

function FeaturePills() {
  return (
    <section aria-label="Product capabilities" style={{ marginBottom: "32px" }}>
      <p
        style={{
          margin: "0 0 12px",
          fontSize: "11px",
          color: "#3a3e50",
          textTransform: "uppercase",
          letterSpacing: "0.07em",
          fontWeight: 600,
        }}
      >
        What&apos;s included
      </p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
        {FEATURE_PILLS.map(({ icon, label }) => (
          <span
            key={label}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "12px",
              color: "#8b90a0",
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "6px 12px",
            }}
          >
            <span aria-hidden="true">{icon}</span>
            {label}
          </span>
        ))}
      </div>
    </section>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DemoPage() {
  const [selectedId, setSelectedId] = useState<string | null>(DEMO_CHANGES[0].id);

  const selectedChange = DEMO_CHANGES.find((c) => c.id === selectedId) ?? null;
  const selectedCluster = selectedChange ? getDemoClusterForChange(selectedChange.id) : null;
  const primaryCluster = DEMO_CLUSTERS[0];

  function handleSelectChange(id: string) {
    setSelectedId((prev) => (prev === id ? null : id));
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0e0f11",
        color: "#e8eaf0",
        fontFamily: "Inter, system-ui, -apple-system, sans-serif",
      }}
    >
      {/* ── Top nav ──────────────────────────────────────────────────── */}
      <nav
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "14px 32px",
          borderBottom: "1px solid #2a2d38",
          background: "#13151a",
          position: "sticky",
          top: 0,
          zIndex: 10,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ fontSize: "15px", fontWeight: 700, color: "#e8eaf0", letterSpacing: "-0.01em" }}>
            ConfigTrace
          </span>
          <span
            style={{
              fontSize: "10px",
              fontWeight: 700,
              color: "#4f80f7",
              background: "rgba(79,128,247,0.12)",
              border: "1px solid rgba(79,128,247,0.25)",
              borderRadius: "4px",
              padding: "1px 6px",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
          >
            Demo
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <Link
            href="/sign-in"
            style={{
              fontSize: "13px",
              color: "#4f80f7",
              textDecoration: "none",
              background: "rgba(79,128,247,0.10)",
              border: "1px solid rgba(79,128,247,0.28)",
              borderRadius: "6px",
              padding: "6px 14px",
              fontWeight: 500,
            }}
          >
            Sign in to ConfigTrace →
          </Link>
        </div>
      </nav>

      <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "36px 28px 60px" }}>

        {/* ── Hero ─────────────────────────────────────────────────── */}
        <section aria-labelledby="demo-hero-title" style={{ marginBottom: "36px" }}>
          <p
            style={{
              margin: "0 0 10px",
              fontSize: "11px",
              color: "#4f80f7",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
            }}
          >
            Public Demo Risk Timeline
          </p>
          <h1
            id="demo-hero-title"
            style={{
              margin: "0 0 10px",
              fontSize: "28px",
              fontWeight: 700,
              color: "#e8eaf0",
              lineHeight: 1.25,
              letterSpacing: "-0.02em",
            }}
          >
            Production doesn&apos;t only break because code changed.
          </h1>
          <p
            style={{
              margin: "0 0 16px",
              fontSize: "16px",
              color: "#8b90a0",
              lineHeight: 1.6,
              maxWidth: "640px",
            }}
          >
            Explore how ConfigTrace detects, explains, and helps review risky configuration drift
            across cloud and SaaS tools — across all 8 providers, without connecting any of them.
          </p>

          {/* Hero callout */}
          <div
            style={{
              display: "inline-block",
              background: "rgba(79,128,247,0.06)",
              border: "1px solid rgba(79,128,247,0.18)",
              borderRadius: "8px",
              padding: "12px 16px",
              marginBottom: "20px",
              maxWidth: "580px",
            }}
          >
            <p
              style={{
                margin: 0,
                fontSize: "14px",
                color: "#c4c8d4",
                lineHeight: 1.6,
                fontStyle: "italic",
              }}
            >
              "Your code has Git history. Your production settings usually do not. ConfigTrace gives
              those settings a security timeline."
            </p>
          </div>

          {/* CTAs */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
            <Link
              href="/sign-in"
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: "#fff",
                background: "#4f80f7",
                border: "none",
                borderRadius: "6px",
                padding: "9px 20px",
                textDecoration: "none",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              Start monitoring your providers →
            </Link>
            <Link
              href="/settings/workspace/data-access"
              style={{
                fontSize: "13px",
                color: "#8b90a0",
                background: "transparent",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                padding: "9px 16px",
                textDecoration: "none",
              }}
            >
              View Trust Center
            </Link>
          </div>
        </section>

        {/* ── Risk summary strip ────────────────────────────────────── */}
        <DemoRiskStrip />

        {/* ── Timeline + detail panel ───────────────────────────────── */}
        <section aria-labelledby="demo-timeline-label" style={{ marginBottom: "32px" }}>
          <p
            id="demo-timeline-label"
            style={{
              margin: "0 0 12px",
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.07em",
              fontWeight: 600,
            }}
          >
            Configuration drift events — select a row to investigate
          </p>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "360px 1fr",
              gap: "16px",
              alignItems: "start",
            }}
          >
            {/* Timeline list */}
            <div
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                overflow: "hidden",
              }}
            >
              {DEMO_CHANGES.map((change) => (
                <DemoChangeRow
                  key={change.id}
                  change={change}
                  selected={selectedId === change.id}
                  onClick={() => handleSelectChange(change.id)}
                />
              ))}
            </div>

            {/* Detail panel */}
            <div style={{ position: "sticky", top: "68px" }}>
              {selectedChange ? (
                <DemoDetailPanel change={selectedChange} cluster={selectedCluster} />
              ) : (
                <div
                  style={{
                    background: "#13151a",
                    border: "1px solid #2a2d38",
                    borderRadius: "8px",
                    padding: "40px 20px",
                    textAlign: "center",
                    color: "#3a3e50",
                    fontSize: "13px",
                  }}
                >
                  Select a change from the timeline to investigate it.
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ── Cross-provider cluster callout ────────────────────────── */}
        {primaryCluster && (
          <ClusterCallout
            cluster={primaryCluster}
            onSelectChange={(id) => setSelectedId(id)}
          />
        )}

        {/* ── Product feature pills ──────────────────────────────────── */}
        <FeaturePills />

        {/* ── Data safety disclaimer ────────────────────────────────── */}
        <section
          aria-labelledby="demo-safety-title"
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "18px 20px",
            marginBottom: "28px",
          }}
        >
          <h2
            id="demo-safety-title"
            style={{
              margin: "0 0 8px",
              fontSize: "13px",
              fontWeight: 600,
              color: "#c4c8d4",
            }}
          >
            About this demo
          </h2>
          <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.7 }}>
            Demo data is <strong style={{ color: "#c4c8d4" }}>entirely synthetic</strong>. No real
            workspace, customer, provider, integration, or credential data is used. The "Acme"
            company and all resource names are fictional.
          </p>
          <p style={{ margin: "8px 0 0", fontSize: "13px", color: "#8b90a0", lineHeight: 1.7 }}>
            In production, ConfigTrace monitors{" "}
            <strong style={{ color: "#c4c8d4" }}>configuration metadata only</strong>. It does not
            read customer data, secret values, source code, payment details, order contents, or
            database rows. All analysis is derived from provider configuration APIs using read-only
            credentials.
          </p>
        </section>

        {/* ── Footer ───────────────────────────────────────────────── */}
        <footer
          style={{
            borderTop: "1px solid #1e2030",
            paddingTop: "20px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "12px",
          }}
        >
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#565b6e" }}>
            ConfigTrace
          </span>
          <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
            <Link
              href="/sign-in"
              style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
            >
              Sign in
            </Link>
            <Link
              href="/sign-up"
              style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
            >
              Sign up
            </Link>
            <Link
              href="/settings/workspace/data-access"
              style={{ fontSize: "12px", color: "#565b6e", textDecoration: "none" }}
            >
              Trust Center
            </Link>
          </div>
          <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
            Demo data is synthetic. Not real customer data.
          </span>
        </footer>
      </div>

      {/* Fade-in keyframe */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
