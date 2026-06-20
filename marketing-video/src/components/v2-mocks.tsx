import React from "react";
import { interpolate } from "remotion";
import {
  COLORS,
  FONT_MONO,
  FONT_SANS,
  Severity,
  severityColor,
} from "../theme";
import {
  PROVIDERS_BY_CATEGORY,
  Provider,
  ProviderCategory,
} from "../providers";
import { Card, SectionLabel, hexA } from "./ui-mocks";

/* ============================================================================
   Monogram — provider initials in a tinted rounded square
   ========================================================================== */

export const Monogram: React.FC<{
  abbr: string;
  color: string;
  size?: number;
  dim?: boolean;
}> = ({ abbr, color, size = 38, dim = false }) => (
  <div
    style={{
      width: size,
      height: size,
      borderRadius: Math.round(size * 0.28),
      background: hexA(color, dim ? 0.08 : 0.16),
      border: `1px solid ${hexA(color, dim ? 0.28 : 0.5)}`,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: FONT_SANS,
      fontWeight: 800,
      fontSize: size * (abbr.length > 2 ? 0.3 : 0.4),
      letterSpacing: -0.3,
      color: dim ? hexA(color, 0.7) : color,
      flexShrink: 0,
    }}
  >
    {abbr}
  </div>
);

/* ============================================================================
   GlowBadge — generic glowing pill
   ========================================================================== */

export const GlowBadge: React.FC<{
  children: React.ReactNode;
  color?: string;
  glow?: number; // 0..1
  dot?: boolean;
}> = ({ children, color = COLORS.cyan, glow = 0, dot = true }) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
      padding: "6px 13px",
      borderRadius: 999,
      background: hexA(color, 0.12),
      border: `1px solid ${hexA(color, 0.5)}`,
      color,
      fontFamily: FONT_SANS,
      fontWeight: 700,
      fontSize: 12,
      letterSpacing: 0.4,
      boxShadow: glow > 0 ? `0 0 ${12 + glow * 24}px ${hexA(color, 0.45 * glow)}` : undefined,
      whiteSpace: "nowrap",
    }}
  >
    {dot ? <span style={{ width: 7, height: 7, borderRadius: 4, background: color }} /> : null}
    {children}
  </span>
);

/* ============================================================================
   ProviderChip — compact provider pill
   ========================================================================== */

export const ProviderChip: React.FC<{
  provider: Provider;
  active?: boolean;
}> = ({ provider, active }) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 9,
      padding: "6px 11px 6px 7px",
      borderRadius: 10,
      background: COLORS.card,
      border: `1px solid ${active ? COLORS.cardBorderActive : COLORS.cardBorder}`,
      boxShadow: active ? `0 0 16px ${hexA(COLORS.blueBright, 0.28)}` : undefined,
    }}
  >
    <Monogram abbr={provider.abbr} color={provider.color} size={22} />
    <span
      style={{
        fontFamily: FONT_SANS,
        fontSize: 12.5,
        fontWeight: 600,
        color: COLORS.text,
        whiteSpace: "nowrap",
      }}
    >
      {provider.name}
    </span>
  </span>
);

/* ============================================================================
   ProviderGrid — control-plane grid, streams in by category
   ========================================================================== */

const CATEGORY_ACCENT: Record<ProviderCategory, string> = {
  "Cloud / Edge": COLORS.cyan,
  "DevOps / Source": COLORS.blueBright,
  "Payments / Commerce": COLORS.violet,
  "App / Data / Backend": COLORS.green,
  Messaging: COLORS.cyanBright,
  Identity: COLORS.violetBright,
  "Observability / Incident": COLORS.amber,
  "Work management": COLORS.blue,
  "Infrastructure as code": COLORS.violet,
};

export const ProviderGrid: React.FC<{
  /** 0..1 — categories reveal in sequence as this advances. */
  progress: number;
  columns?: number;
}> = ({ progress, columns = 3 }) => {
  const groups = PROVIDERS_BY_CATEGORY;
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: `repeat(${columns}, 1fr)`,
        gap: 16,
        width: "100%",
      }}
    >
      {groups.map((g, gi) => {
        const reveal = interpolate(
          progress,
          [gi / groups.length, gi / groups.length + 0.16],
          [0, 1],
          { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
        );
        const accent = CATEGORY_ACCENT[g.category];
        return (
          <div
            key={g.category}
            style={{
              opacity: reveal,
              transform: `translateY(${(1 - reveal) * 16}px)`,
            }}
          >
            <Card glow={reveal > 0.6 ? 0.12 : 0} style={{ padding: 14, height: "100%" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <span style={{ width: 7, height: 7, borderRadius: 4, background: accent }} />
                <SectionLabel color={accent}>{g.category}</SectionLabel>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {g.providers.map((p) => (
                  <ProviderChip key={p.name} provider={p} />
                ))}
              </div>
            </Card>
          </div>
        );
      })}
    </div>
  );
};

/* ============================================================================
   MetricCard — compact KPI tile
   ========================================================================== */

export const MetricCard: React.FC<{
  label: string;
  value: string;
  accent?: string;
  hint?: string;
  glow?: number;
}> = ({ label, value, accent = COLORS.blueBright, hint, glow = 0 }) => (
  <Card glow={glow} style={{ padding: 16, minWidth: 0 }}>
    <SectionLabel>{label}</SectionLabel>
    <div
      style={{
        fontFamily: FONT_SANS,
        fontWeight: 800,
        fontSize: 30,
        color: accent,
        marginTop: 7,
        letterSpacing: -1,
      }}
    >
      {value}
    </div>
    {hint ? (
      <div style={{ fontFamily: FONT_SANS, fontSize: 11, color: COLORS.textFaint, marginTop: 4 }}>
        {hint}
      </div>
    ) : null}
  </Card>
);

/* ============================================================================
   NormalizedRecordRow — a provider config collapsed into a normalized record
   ========================================================================== */

export const NormalizedRecordRow: React.FC<{
  provider: Provider;
  recordKey: string;
  fields: string[];
  active?: boolean;
}> = ({ provider, recordKey, fields, active }) => (
  <Card active={active} glow={active ? 0.3 : 0} style={{ padding: "11px 14px" }}>
    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <Monogram abbr={provider.abbr} color={provider.color} size={28} />
      <span
        style={{
          fontFamily: FONT_MONO,
          fontSize: 13.5,
          color: COLORS.text,
          fontWeight: 600,
          minWidth: 230,
        }}
      >
        {recordKey}
      </span>
      <div style={{ display: "flex", gap: 7, flexWrap: "wrap", flex: 1 }}>
        {fields.map((f) => (
          <span
            key={f}
            style={{
              fontFamily: FONT_MONO,
              fontSize: 10.5,
              color: COLORS.textMuted,
              background: hexA(COLORS.cyan, 0.08),
              border: `1px solid ${hexA(COLORS.cyan, 0.22)}`,
              borderRadius: 6,
              padding: "3px 7px",
            }}
          >
            {f}
          </span>
        ))}
      </div>
    </div>
  </Card>
);

/* ============================================================================
   SnapshotEnginePanel — metrics rail + normalized records streaming in
   ========================================================================== */

const SNAPSHOT_RECORDS: { provider: string; recordKey: string; fields: string[] }[] = [
  { provider: "Cloudflare", recordKey: "cloudflare_dns_record", fields: ["type", "proxied:bool", "ttl:int"] },
  { provider: "GitHub", recordKey: "github_branch_protection", fields: ["required_reviews:int", "enforce_admins:bool"] },
  { provider: "Stripe", recordKey: "stripe_webhook", fields: ["status", "has_secret:bool", "events:count"] },
  { provider: "AWS", recordKey: "aws_s3_bucket", fields: ["acl:category", "public_access:bool"] },
  { provider: "Auth0", recordKey: "auth0_application", fields: ["callbacks:count", "grant_types:category"] },
  { provider: "Datadog", recordKey: "datadog_monitor", fields: ["type", "notify:count", "muted:bool"] },
  { provider: "PagerDuty", recordKey: "pagerduty_service", fields: ["escalation_id:opaque", "urgency:category"] },
  { provider: "Linear", recordKey: "linear_webhook", fields: ["enabled:bool", "resource_types:count"] },
  { provider: "Jira", recordKey: "jira_permission_scheme", fields: ["grants:count", "holder_type:category"] },
  { provider: "Terraform Cloud", recordKey: "terraform_workspace", fields: ["auto_apply:bool", "vars:count"] },
];

const PROVIDER_BY_NAME = Object.fromEntries(
  PROVIDERS_BY_CATEGORY.flatMap((g) => g.providers).map((p) => [p.name, p]),
);

export const SnapshotEnginePanel: React.FC<{
  metrics: { label: string; value: string; accent?: string }[];
  /** 0..1 — records stream in. */
  reveal: number;
  visibleCount?: number;
}> = ({ metrics, reveal, visibleCount = 6 }) => {
  const records = SNAPSHOT_RECORDS.slice(0, visibleCount);
  return (
    <div style={{ display: "flex", gap: 18, height: "100%" }}>
      {/* left metrics rail */}
      <div style={{ width: 270, display: "flex", flexDirection: "column", gap: 11, flexShrink: 0 }}>
        {metrics.map((m, i) => (
          <MetricCard key={m.label} label={m.label} value={m.value} accent={m.accent} glow={i === 0 ? 0.2 : 0} />
        ))}
        <GlowBadge color={COLORS.green} glow={0.25}>safe fields only</GlowBadge>
        <div style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLORS.textFaint, lineHeight: 1.6 }}>
          booleans · counts · categories · opaque IDs
        </div>
      </div>

      {/* center: normalized records */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 9, minWidth: 0 }}>
        <SectionLabel color={COLORS.cyan}>Normalized config records</SectionLabel>
        {records.map((r, i) => {
          const rowReveal = interpolate(
            reveal,
            [i / records.length, i / records.length + 0.18],
            [0, 1],
            { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
          );
          return (
            <div
              key={r.recordKey}
              style={{
                opacity: rowReveal,
                transform: `translateX(${(1 - rowReveal) * 28}px) scale(${0.96 + rowReveal * 0.04})`,
              }}
            >
              <NormalizedRecordRow
                provider={PROVIDER_BY_NAME[r.provider]}
                recordKey={r.recordKey}
                fields={r.fields}
                active={i === 0}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* ============================================================================
   DriftDiffPanel — before/after drift rows with an expandable detail
   ========================================================================== */

export type DriftRow = {
  label: string;
  provider: string;
  before: string;
  after: string;
  severity: Severity;
};

export const DriftDiffPanel: React.FC<{
  rows: DriftRow[];
  /** 0..1 — rows reveal + green→amber transition. */
  reveal: number;
  /** index of the row that is hovered/expanded (or -1). */
  expandedIndex?: number;
  /** 0..1 expand progress of the detail panel. */
  expand?: number;
}> = ({ rows, reveal, expandedIndex = -1, expand = 0 }) => (
  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
    {rows.map((r, i) => {
      const rowReveal = interpolate(
        reveal,
        [i / rows.length, i / rows.length + 0.2],
        [0, 1],
        { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
      );
      // green→amber: settled state shifts toward severity color as it reveals.
      const shift = rowReveal;
      const sev = severityColor(r.severity);
      const isExpanded = i === expandedIndex;
      const p = PROVIDER_BY_NAME[r.provider];
      return (
        <div
          key={r.label}
          style={{
            opacity: rowReveal,
            transform: `translateY(${(1 - rowReveal) * 14}px)`,
          }}
        >
          <Card
            active={isExpanded}
            glow={isExpanded ? 0.45 * expand : shift > 0.9 ? 0.1 : 0}
            style={{ padding: 0, overflow: "hidden" }}
          >
            <div style={{ display: "flex" }}>
              <div
                style={{
                  width: 4,
                  background: `linear-gradient(${COLORS.green}, ${sev})`,
                  backgroundSize: "100% 200%",
                  backgroundPosition: `0% ${shift * 100}%`,
                }}
              />
              <div style={{ flex: 1, padding: "13px 16px" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
                    {p ? <Monogram abbr={p.abbr} color={p.color} size={26} /> : null}
                    <span style={{ fontFamily: FONT_SANS, fontSize: 14.5, fontWeight: 600, color: COLORS.text }}>
                      {r.label}
                    </span>
                  </div>
                  <span
                    style={{
                      fontFamily: FONT_SANS,
                      fontSize: 11.5,
                      fontWeight: 600,
                      color: isExpanded ? sev : COLORS.textFaint,
                      whiteSpace: "nowrap",
                    }}
                  >
                    {isExpanded ? "View drift ›" : "drift detected"}
                  </span>
                </div>

                {/* expandable before/after detail */}
                <div
                  style={{
                    overflow: "hidden",
                    height: isExpanded ? expand * 96 : 0,
                    opacity: isExpanded ? expand : 0,
                    marginTop: isExpanded ? expand * 12 : 0,
                  }}
                >
                  <DiffPair before={r.before} after={r.after} sev={sev} />
                </div>
              </div>
            </div>
          </Card>
        </div>
      );
    })}
  </div>
);

const DiffPair: React.FC<{ before: string; after: string; sev: string }> = ({ before, after, sev }) => (
  <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
    <div style={diffLine(COLORS.textMuted, "rgba(148,163,184,0.08)")}>
      <span style={{ fontFamily: FONT_MONO, fontWeight: 700, color: COLORS.textFaint, width: 12 }}>-</span>
      <span style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: COLORS.textMuted, textDecoration: "line-through" }}>
        {before}
      </span>
    </div>
    <div style={diffLine(sev, hexA(sev, 0.1))}>
      <span style={{ fontFamily: FONT_MONO, fontWeight: 700, color: sev, width: 12 }}>+</span>
      <span style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: COLORS.text }}>{after}</span>
    </div>
  </div>
);

const diffLine = (border: string, bg: string): React.CSSProperties => ({
  display: "flex",
  alignItems: "center",
  gap: 10,
  padding: "8px 12px",
  borderRadius: 8,
  background: bg,
  border: `1px solid ${hexA(border, 0.3)}`,
});
