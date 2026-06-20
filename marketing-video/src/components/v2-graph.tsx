import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import {
  COLORS,
  EASE,
  FONT_MONO,
  FONT_SANS,
  Severity,
  severityColor,
} from "../theme";
import { PROVIDERS, Provider } from "../providers";
import { Card, RiskBadgeMock, SectionLabel, hexA } from "./ui-mocks";
import { Monogram, GlowBadge } from "./v2-mocks";

const PROVIDER_BY_NAME: Record<string, Provider> = Object.fromEntries(
  PROVIDERS.map((p) => [p.name, p]),
);

/* ============================================================================
   RiskFindingCard — a single classified configuration finding
   ========================================================================== */

export type Finding = {
  severity: Severity;
  title: string;
  provider: string;
};

export const RiskFindingCard: React.FC<{
  finding: Finding;
  active?: boolean;
  glow?: number;
}> = ({ finding, active, glow = 0 }) => {
  const sev = severityColor(finding.severity);
  const p = PROVIDER_BY_NAME[finding.provider];
  return (
    <Card severity={finding.severity} active={active} glow={glow} style={{ padding: 13 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 10 }}>
        {p ? <Monogram abbr={p.abbr} color={p.color} size={24} /> : null}
        <span style={{ fontFamily: FONT_SANS, fontSize: 11.5, color: COLORS.textMuted }}>
          {finding.provider}
        </span>
        <span style={{ marginLeft: "auto", width: 8, height: 8, borderRadius: 4, background: sev, boxShadow: `0 0 10px ${sev}` }} />
      </div>
      <div style={{ fontFamily: FONT_SANS, fontSize: 13.5, fontWeight: 600, color: COLORS.text, lineHeight: 1.4 }}>
        {finding.title}
      </div>
      <div style={{ marginTop: 10 }}>
        <span
          style={{
            fontFamily: FONT_SANS,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 0.5,
            color: COLORS.textFaint,
          }}
        >
          may require review
        </span>
      </div>
    </Card>
  );
};

/* ============================================================================
   RiskBoard — High / Medium / Low columns; cards animate in
   ========================================================================== */

export type RiskColumn = { level: "High" | "Medium" | "Low"; findings: Finding[] };

export const RiskBoard: React.FC<{
  columns: RiskColumn[];
  /** 0..1 — cards fall into their columns. */
  progress: number;
  activeCard?: { col: number; row: number };
}> = ({ columns, progress, activeCard }) => {
  const levelColor = (l: string) => (l === "High" ? COLORS.red : l === "Medium" ? COLORS.amber : COLORS.cyan);
  // flat index for staggered reveal
  let flat = 0;
  const total = columns.reduce((a, c) => a + c.findings.length, 0);
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 18, width: "100%" }}>
      {columns.map((col, ci) => {
        const c = levelColor(col.level);
        return (
          <div key={col.level} style={{ display: "flex", flexDirection: "column", gap: 11 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "10px 14px",
                borderRadius: 10,
                background: hexA(c, 0.1),
                border: `1px solid ${hexA(c, 0.4)}`,
              }}
            >
              <span style={{ fontFamily: FONT_SANS, fontSize: 13, fontWeight: 700, color: c, letterSpacing: 0.4 }}>
                {col.level}
              </span>
              <span style={{ fontFamily: FONT_SANS, fontSize: 12, fontWeight: 700, color: c }}>
                {col.findings.length}
              </span>
            </div>
            {col.findings.map((f, ri) => {
              const myIndex = flat++;
              const reveal = interpolate(
                progress,
                [myIndex / total, myIndex / total + 0.22],
                [0, 1],
                { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
              );
              const isActive = activeCard && activeCard.col === ci && activeCard.row === ri;
              return (
                <div
                  key={f.title}
                  style={{
                    opacity: reveal,
                    transform: `translateY(${(1 - reveal) * 26}px) scale(${0.95 + reveal * 0.05})`,
                  }}
                >
                  <RiskFindingCard finding={f} active={!!isActive} glow={isActive ? 0.5 : f.severity === "critical" ? 0.18 : 0} />
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
};

/* ============================================================================
   ActivityTimeline — vertical control-plane activity feed (+ evidence popover)
   ========================================================================== */

export type ActivityEvent = {
  provider: string;
  title: string;
  time: string;
};

export const ActivityTimeline: React.FC<{
  events: ActivityEvent[];
  /** 0..1 — events scroll/reveal. */
  progress: number;
  /** index whose evidence popover is shown (or -1). */
  popoverIndex?: number;
  popoverReveal?: number;
}> = ({ events, progress, popoverIndex = -1, popoverReveal = 0 }) => (
  <div style={{ position: "relative", paddingLeft: 30 }}>
    {/* rail */}
    <div style={{ position: "absolute", left: 9, top: 8, bottom: 8, width: 2, background: hexA(COLORS.cyan, 0.35) }} />
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {events.map((e, i) => {
        const reveal = interpolate(
          progress,
          [i / events.length, i / events.length + 0.18],
          [0, 1],
          { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
        );
        const p = PROVIDER_BY_NAME[e.provider];
        const showPop = i === popoverIndex && popoverReveal > 0.01;
        return (
          <div
            key={e.title}
            style={{
              position: "relative",
              opacity: reveal,
              transform: `translateX(${(1 - reveal) * 22}px)`,
            }}
          >
            <span
              style={{
                position: "absolute",
                left: -29,
                top: 16,
                width: 14,
                height: 14,
                borderRadius: 8,
                background: COLORS.cyan,
                border: `2px solid ${COLORS.bgBase}`,
                boxShadow: `0 0 10px ${hexA(COLORS.cyan, 0.7)}`,
              }}
            />
            <Card active={showPop} glow={showPop ? 0.4 : 0} style={{ padding: "12px 15px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
                {p ? <Monogram abbr={p.abbr} color={p.color} size={26} /> : null}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: FONT_SANS, fontSize: 13.5, fontWeight: 600, color: COLORS.text }}>
                    {e.title}
                  </div>
                  <div style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLORS.textFaint, marginTop: 3 }}>
                    {e.provider} · {e.time}
                  </div>
                </div>
                <span
                  style={{
                    fontFamily: FONT_SANS,
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.4,
                    color: COLORS.cyan,
                    background: hexA(COLORS.cyan, 0.1),
                    border: `1px solid ${hexA(COLORS.cyan, 0.3)}`,
                    borderRadius: 6,
                    padding: "3px 8px",
                  }}
                >
                  evidence
                </span>
              </div>

              {showPop ? (
                <div
                  style={{
                    marginTop: popoverReveal * 11,
                    height: popoverReveal * 70,
                    opacity: popoverReveal,
                    overflow: "hidden",
                    borderTop: `1px solid ${COLORS.cardBorder}`,
                    paddingTop: 10,
                  }}
                >
                  <div style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLORS.textMuted, lineHeight: 1.7 }}>
                    actor: service-account · scope: project-admin
                    <br />
                    related finding: permission scheme may allow broad access
                  </div>
                </div>
              ) : null}
            </Card>
          </div>
        );
      })}
    </div>
  </div>
);

/* ============================================================================
   EvidenceGraph — Security Case at center; evidence nodes orbit + connect
   ========================================================================== */

export const EvidenceGraph: React.FC<{
  /** 0..1 — edges + nodes animate in. */
  progress: number;
  width?: number;
  height?: number;
}> = ({ progress, width = 560, height = 460 }) => {
  const cx = width / 2;
  const cy = height / 2;
  const satellites = [
    { label: "Finding", color: COLORS.red },
    { label: "Drift", color: COLORS.amber },
    { label: "Activity", color: COLORS.cyan },
    { label: "Signal", color: COLORS.violet },
    { label: "Correlation", color: COLORS.blueBright },
    { label: "Provider", color: COLORS.green },
    { label: "Resource", color: COLORS.cyanBright },
    { label: "Report", color: COLORS.violetBright },
  ];
  const rx = width * 0.4;
  const ry = height * 0.39;
  const positions = satellites.map((s, i) => {
    const ang = (-90 + (360 / satellites.length) * i) * (Math.PI / 180);
    return { ...s, x: cx + Math.cos(ang) * rx, y: cy + Math.sin(ang) * ry };
  });

  return (
    <div style={{ position: "relative", width, height }}>
      {/* edges */}
      <svg width={width} height={height} style={{ position: "absolute", inset: 0 }}>
        {positions.map((pos, i) => {
          const edge = interpolate(
            progress,
            [0.15 + (i / positions.length) * 0.45, 0.15 + (i / positions.length) * 0.45 + 0.18],
            [0, 1],
            { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
          );
          const mx = cx + (pos.x - cx) * edge;
          const my = cy + (pos.y - cy) * edge;
          return (
            <line
              key={pos.label}
              x1={cx}
              y1={cy}
              x2={mx}
              y2={my}
              stroke={hexA(pos.color, 0.55)}
              strokeWidth={1.5}
              strokeDasharray="3 4"
            />
          );
        })}
      </svg>

      {/* satellite nodes */}
      {positions.map((pos, i) => {
        const appear = interpolate(
          progress,
          [0.25 + (i / positions.length) * 0.45, 0.25 + (i / positions.length) * 0.45 + 0.16],
          [0, 1],
          { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
        );
        return (
          <div
            key={pos.label}
            style={{
              position: "absolute",
              left: pos.x,
              top: pos.y,
              transform: `translate(-50%, -50%) scale(${0.7 + appear * 0.3})`,
              opacity: appear,
              padding: "7px 13px",
              borderRadius: 9,
              background: COLORS.card,
              border: `1px solid ${hexA(pos.color, 0.5)}`,
              boxShadow: `0 0 14px ${hexA(pos.color, 0.25)}`,
              fontFamily: FONT_SANS,
              fontSize: 12,
              fontWeight: 600,
              color: COLORS.text,
              whiteSpace: "nowrap",
              display: "flex",
              alignItems: "center",
              gap: 7,
            }}
          >
            <span style={{ width: 7, height: 7, borderRadius: 4, background: pos.color }} />
            {pos.label}
          </div>
        );
      })}

      {/* center: Security Case */}
      <div
        style={{
          position: "absolute",
          left: cx,
          top: cy,
          transform: "translate(-50%, -50%)",
          width: 168,
          padding: "16px 14px",
          borderRadius: EASE.radius,
          textAlign: "center",
          background: hexA(COLORS.blue, 0.12),
          border: `1.5px solid ${COLORS.cardBorderActive}`,
          boxShadow: `0 0 ${24 + progress * 26}px ${hexA(COLORS.blueBright, 0.35)}`,
        }}
      >
        <div style={{ fontFamily: FONT_SANS, fontSize: 10, fontWeight: 700, letterSpacing: 1.5, color: COLORS.blueBright, textTransform: "uppercase" }}>
          Security Case
        </div>
        <div style={{ fontFamily: FONT_SANS, fontSize: 13.5, fontWeight: 700, color: COLORS.text, marginTop: 7, lineHeight: 1.3 }}>
          Jira permission scheme review
        </div>
      </div>
    </div>
  );
};

/* ============================================================================
   CaseReportPanel — case summary + generate-report action / report slide-in
   ========================================================================== */

export const CaseReportPanel: React.FC<{
  /** 0..1 — report panel slides open after "Generate report". */
  reportReveal?: number;
  generateHot?: boolean;
}> = ({ reportReveal = 0, generateHot = false }) => (
  <Card style={{ padding: 0, overflow: "hidden", height: "100%", display: "flex", flexDirection: "column" }}>
    <div style={{ padding: "16px 20px", borderBottom: `1px solid ${COLORS.cardBorder}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <RiskBadgeMock severity="warning" label="NEEDS REVIEW" />
        <span style={{ fontFamily: FONT_SANS, fontWeight: 700, fontSize: 16, color: COLORS.text }}>
          Jira permission scheme review
        </span>
      </div>
      <GlowBadge color={COLORS.green} glow={0.2}>case created</GlowBadge>
    </div>

    <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 14, flex: 1 }}>
      <div>
        <SectionLabel color={COLORS.blueBright}>Case summary</SectionLabel>
        <div style={{ fontFamily: FONT_SANS, fontSize: 13.5, color: COLORS.text, marginTop: 10, lineHeight: 1.65 }}>
          Configuration evidence indicates a permission scheme may require review. Related
          configuration activity was observed.
        </div>
        <div style={{ fontFamily: FONT_SANS, fontSize: 12, color: COLORS.textFaint, marginTop: 10, lineHeight: 1.6 }}>
          This does not confirm compromise, unauthorized access, or data exposure.
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {["Finding", "Drift", "Activity", "Correlation", "Provider · Jira", "Resource · permission scheme"].map((t) => (
          <span
            key={t}
            style={{
              fontFamily: FONT_SANS,
              fontSize: 11,
              color: COLORS.textMuted,
              background: hexA(COLORS.blue, 0.08),
              border: `1px solid ${hexA(COLORS.blue, 0.25)}`,
              borderRadius: 7,
              padding: "5px 10px",
            }}
          >
            {t}
          </span>
        ))}
      </div>

      {/* generate-report action */}
      <div style={{ marginTop: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        <span
          style={{
            padding: "10px 18px",
            borderRadius: 10,
            fontFamily: FONT_SANS,
            fontSize: 13.5,
            fontWeight: 700,
            color: COLORS.textInk,
            background: COLORS.blueBright,
            border: `1px solid ${generateHot ? "#fff" : "transparent"}`,
            boxShadow: generateHot ? `0 0 18px ${hexA(COLORS.blueBright, 0.6)}` : undefined,
          }}
        >
          Generate report
        </span>
        <span style={{ fontFamily: FONT_SANS, fontSize: 12, color: COLORS.textFaint }}>
          Markdown · JSON · CSV
        </span>
      </div>

      {/* report slide-in */}
      <div
        style={{
          height: reportReveal * 88,
          opacity: reportReveal,
          overflow: "hidden",
          transform: `translateY(${(1 - reportReveal) * 10}px)`,
        }}
      >
        <div style={{ borderTop: `1px solid ${COLORS.cardBorder}`, paddingTop: 12, display: "flex", flexDirection: "column", gap: 7 }}>
          <SectionLabel>Review packet</SectionLabel>
          {[92, 74, 60].map((w, i) => (
            <div key={i} style={{ height: 7, borderRadius: 4, width: `${w}%`, background: hexA(COLORS.textMuted, 0.16) }} />
          ))}
        </div>
      </div>
    </div>
  </Card>
);

/* ============================================================================
   ProviderCoverageMatrix — all 20 providers shown with ✓
   ========================================================================== */

export const ProviderCoverageMatrix: React.FC<{
  /** 0..1 — cells fill left to right. */
  progress: number;
  columns?: number;
}> = ({ progress, columns = 5 }) => (
  <div style={{ display: "grid", gridTemplateColumns: `repeat(${columns}, 1fr)`, gap: 10, width: "100%" }}>
    {PROVIDERS.map((p, i) => {
      const reveal = interpolate(
        progress,
        [i / PROVIDERS.length, i / PROVIDERS.length + 0.1],
        [0, 1],
        { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
      );
      return (
        <div
          key={p.name}
          style={{
            opacity: reveal,
            transform: `translateY(${(1 - reveal) * 12}px)`,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "10px 12px",
            borderRadius: 10,
            background: COLORS.card,
            border: `1px solid ${COLORS.cardBorder}`,
          }}
        >
          <Monogram abbr={p.abbr} color={p.color} size={26} />
          <span style={{ fontFamily: FONT_SANS, fontSize: 12.5, fontWeight: 600, color: COLORS.text, flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {p.name}
          </span>
          <span style={{ color: COLORS.green, fontSize: 14, fontWeight: 800 }}>✓</span>
        </div>
      );
    })}
  </div>
);

/* ============================================================================
   SystemMap — Snapshot → Drift → Risk → Activity → Correlation → Case → Report
   ========================================================================== */

export const SystemMap: React.FC<{ progress: number }> = ({ progress }) => {
  const stages = ["Snapshot", "Drift", "Risk", "Activity", "Correlation", "Case", "Report"];
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", flexWrap: "wrap", gap: 0 }}>
      {stages.map((s, i) => {
        const on = progress >= (i + 1) / stages.length - 0.0001;
        const lit = interpolate(
          progress,
          [i / stages.length, i / stages.length + 0.1],
          [0, 1],
          { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
        );
        return (
          <React.Fragment key={s}>
            <div
              style={{
                padding: "12px 18px",
                borderRadius: 12,
                background: on ? hexA(COLORS.blue, 0.16) : COLORS.card,
                border: `1px solid ${on ? COLORS.cardBorderActive : COLORS.cardBorder}`,
                color: on ? COLORS.text : COLORS.textMuted,
                fontFamily: FONT_SANS,
                fontSize: 14.5,
                fontWeight: 700,
                opacity: 0.4 + lit * 0.6,
                boxShadow: on ? `0 0 18px ${hexA(COLORS.blueBright, 0.25)}` : undefined,
                transform: `scale(${0.94 + lit * 0.06})`,
              }}
            >
              {s}
            </div>
            {i < stages.length - 1 ? (
              <div style={{ width: 30, height: 2, margin: "0 3px", background: COLORS.cardBorder, position: "relative", overflow: "hidden" }}>
                <div
                  style={{
                    position: "absolute",
                    inset: 0,
                    width: `${Math.max(0, Math.min(1, progress * stages.length - i)) * 100}%`,
                    background: `linear-gradient(90deg, ${COLORS.cyan}, ${COLORS.blueBright})`,
                  }}
                />
              </div>
            ) : null}
          </React.Fragment>
        );
      })}
    </div>
  );
};

/* ============================================================================
   ControlPlaneMap — central Production node; control-plane nodes orbit
   ========================================================================== */

export const ControlPlaneMap: React.FC<{
  width?: number;
  height?: number;
}> = ({ width = 760, height = 620 }) => {
  const frame = useCurrentFrame();
  const cx = width / 2;
  const cy = height / 2;
  const nodes = [
    "DNS",
    "Webhooks",
    "IAM",
    "Billing",
    "OAuth",
    "CI/CD",
    "Incident routes",
    "Feature flags",
    "Cloud permissions",
  ];
  const rx = width * 0.41;
  const ry = height * 0.41;
  // The "drift" node (Webhooks) shifts blue→amber with a drift line.
  const driftIdx = 1;
  const driftAppear = interpolate(frame, [70, 105], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  const positions = nodes.map((label, i) => {
    const ang = (-90 + (360 / nodes.length) * i) * (Math.PI / 180);
    return { label, i, x: cx + Math.cos(ang) * rx, y: cy + Math.sin(ang) * ry };
  });

  return (
    <div style={{ position: "relative", width, height }}>
      <svg width={width} height={height} style={{ position: "absolute", inset: 0 }}>
        {positions.map((pos) => {
          const isDrift = pos.i === driftIdx;
          const c = isDrift ? COLORS.amber : COLORS.blue;
          const op = isDrift ? 0.4 + driftAppear * 0.5 : 0.4;
          return (
            <line
              key={pos.label}
              x1={cx}
              y1={cy}
              x2={pos.x}
              y2={pos.y}
              stroke={hexA(c, op)}
              strokeWidth={isDrift ? 2 : 1.2}
              strokeDasharray={isDrift ? "5 4" : undefined}
            />
          );
        })}
      </svg>

      {positions.map((pos) => {
        // staggered pulse appearance
        const appear = interpolate(frame, [10 + pos.i * 5, 10 + pos.i * 5 + 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
        const pulse = interpolate(Math.sin((frame - pos.i * 7) / 9), [-1, 1], [0.85, 1]);
        const isDrift = pos.i === driftIdx;
        const c = isDrift && driftAppear > 0.3 ? COLORS.amber : COLORS.blue;
        return (
          <div
            key={pos.label}
            style={{
              position: "absolute",
              left: pos.x,
              top: pos.y,
              transform: `translate(-50%, -50%) scale(${0.7 + appear * 0.3})`,
              opacity: appear,
              padding: "9px 14px",
              borderRadius: 10,
              background: COLORS.card,
              border: `1px solid ${hexA(c, 0.55)}`,
              boxShadow: `0 0 ${10 + pulse * 12}px ${hexA(c, 0.3 * (isDrift ? driftAppear : 1))}`,
              fontFamily: FONT_SANS,
              fontSize: 12.5,
              fontWeight: 600,
              color: COLORS.text,
              whiteSpace: "nowrap",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ width: 7, height: 7, borderRadius: 4, background: c }} />
            {pos.label}
            {isDrift && driftAppear > 0.5 ? (
              <span style={{ fontFamily: FONT_SANS, fontSize: 9.5, fontWeight: 700, color: COLORS.amber, letterSpacing: 0.4 }}>drift</span>
            ) : null}
          </div>
        );
      })}

      {/* center: Production */}
      <div
        style={{
          position: "absolute",
          left: cx,
          top: cy,
          transform: "translate(-50%, -50%)",
          width: 150,
          height: 150,
          borderRadius: "50%",
          background: `radial-gradient(circle at 50% 40%, ${hexA(COLORS.blueBright, 0.28)}, ${hexA(COLORS.blue, 0.08)})`,
          border: `1.5px solid ${COLORS.cardBorderActive}`,
          boxShadow: `0 0 40px ${hexA(COLORS.blueBright, 0.3)}`,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 4,
        }}
      >
        <span style={{ fontFamily: FONT_SANS, fontSize: 19, fontWeight: 800, color: COLORS.text, letterSpacing: -0.3 }}>
          Production
        </span>
        <span style={{ fontFamily: FONT_SANS, fontSize: 11, color: COLORS.textMuted }}>
          control plane
        </span>
      </div>
    </div>
  );
};
