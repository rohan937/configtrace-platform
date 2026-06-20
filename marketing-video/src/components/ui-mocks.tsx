import React from "react";
import {
  COLORS,
  EASE,
  FONT_MONO,
  FONT_SANS,
  Severity,
  severityBorder,
  severityColor,
} from "../theme";

/* ============================================================================
   Shared primitives
   ========================================================================== */

export const SectionLabel: React.FC<{ children: React.ReactNode; color?: string }> = ({
  children,
  color = COLORS.textFaint,
}) => (
  <div
    style={{
      fontFamily: FONT_SANS,
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: 2,
      textTransform: "uppercase",
      color,
    }}
  >
    {children}
  </div>
);

export const Card: React.FC<{
  severity?: Severity;
  active?: boolean;
  children?: React.ReactNode;
  style?: React.CSSProperties;
  glow?: number; // 0..1 ambient glow strength
}> = ({ severity, active, children, style, glow = 0 }) => {
  const border = active
    ? COLORS.cardBorderActive
    : severity
      ? severityBorder(severity)
      : COLORS.cardBorder;
  const glowColor = severity ? severityColor(severity) : COLORS.blue;
  return (
    <div
      style={{
        background: COLORS.card,
        border: `1px solid ${border}`,
        borderRadius: EASE.radius,
        boxShadow:
          glow > 0
            ? `0 0 ${20 + glow * 30}px ${hexA(glowColor, 0.12 + glow * 0.22)}, ${EASE.shadowSoft}`
            : EASE.shadowSoft,
        ...style,
      }}
    >
      {children}
    </div>
  );
};

export const RiskBadgeMock: React.FC<{
  severity: Severity;
  label?: string;
  pulse?: number; // 0..1
}> = ({ severity, label, pulse = 0 }) => {
  const c = severityColor(severity);
  const text =
    label ?? (severity === "critical" ? "CRITICAL" : severity === "warning" ? "NEEDS REVIEW" : severity === "safe" ? "SAFE" : "INFO");
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        padding: "5px 11px",
        borderRadius: 999,
        background: hexA(c, 0.14),
        border: `1px solid ${hexA(c, 0.5)}`,
        color: c,
        fontFamily: FONT_SANS,
        fontWeight: 700,
        fontSize: 11,
        letterSpacing: 1,
        boxShadow: pulse > 0 ? `0 0 ${10 + pulse * 22}px ${hexA(c, 0.4 * pulse)}` : undefined,
      }}
    >
      <span style={{ width: 7, height: 7, borderRadius: 4, background: c }} />
      {text}
    </span>
  );
};

export const Chip: React.FC<{ children: React.ReactNode; color?: string }> = ({
  children,
  color = COLORS.cyan,
}) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 6,
      padding: "5px 10px",
      borderRadius: 8,
      background: hexA(color, 0.1),
      border: `1px solid ${hexA(color, 0.32)}`,
      color,
      fontFamily: FONT_SANS,
      fontSize: 12,
      fontWeight: 500,
    }}
  >
    {children}
  </span>
);

/* ============================================================================
   1. AppHeaderMock
   ========================================================================== */

export const AppHeaderMock: React.FC<{ title: string; subtitle?: string }> = ({
  title,
  subtitle,
}) => (
  <div
    style={{
      height: 64,
      borderBottom: `1px solid ${COLORS.cardBorder}`,
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "0 26px",
      flexShrink: 0,
    }}
  >
    <div>
      <div
        style={{
          fontFamily: FONT_SANS,
          fontWeight: 700,
          fontSize: 18,
          color: COLORS.text,
          letterSpacing: -0.2,
        }}
      >
        {title}
      </div>
      {subtitle ? (
        <div style={{ fontFamily: FONT_SANS, fontSize: 12, color: COLORS.textFaint, marginTop: 2 }}>
          {subtitle}
        </div>
      ) : null}
    </div>
    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <Chip color={COLORS.green}>● Metadata-only</Chip>
      <div
        style={{
          width: 34,
          height: 34,
          borderRadius: 10,
          background: hexA(COLORS.blue, 0.2),
          border: `1px solid ${COLORS.cardBorderActive}`,
        }}
      />
    </div>
  </div>
);

/* ============================================================================
   2. SidebarMock
   ========================================================================== */

export const SidebarMock: React.FC<{ active?: string }> = ({ active = "Dashboard" }) => {
  const items = ["Dashboard", "Integrations", "Timeline", "Needs Review", "Remediation", "Settings"];
  return (
    <div style={{ padding: "20px 14px", display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 8px 18px" }}>
        <div
          style={{
            width: 30,
            height: 30,
            borderRadius: 8,
            border: `2px solid ${COLORS.blueBright}`,
            background: hexA(COLORS.blue, 0.16),
          }}
        />
        <span style={{ fontFamily: FONT_SANS, fontWeight: 800, fontSize: 15, color: COLORS.text }}>
          ConfigTrace
        </span>
      </div>
      {items.map((it) => {
        const on = it === active;
        return (
          <div
            key={it}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "10px 12px",
              borderRadius: 10,
              marginBottom: 4,
              background: on ? hexA(COLORS.blue, 0.16) : "transparent",
              border: `1px solid ${on ? COLORS.cardBorderActive : "transparent"}`,
              color: on ? COLORS.text : COLORS.textMuted,
              fontFamily: FONT_SANS,
              fontSize: 13.5,
              fontWeight: on ? 600 : 500,
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: 4,
                background: on ? COLORS.blueBright : COLORS.textFaint,
              }}
            />
            {it}
          </div>
        );
      })}
    </div>
  );
};

/* ============================================================================
   3. ProviderCardMock
   ========================================================================== */

const PROVIDER_COLORS: Record<string, string> = {
  GitHub: "#E5EAF2",
  Cloudflare: "#F38020",
  AWS: "#FF9900",
  Stripe: "#635BFF",
  Vercel: "#E5EAF2",
  Firebase: "#FFCA28",
  Supabase: "#3ECF8E",
  Shopify: "#95BF47",
};

export const ProviderCardMock: React.FC<{
  name: string;
  status?: string;
  active?: boolean;
  glow?: number;
  compact?: boolean;
}> = ({ name, status = "Active", active, glow = 0, compact }) => {
  const c = PROVIDER_COLORS[name] ?? COLORS.text;
  return (
    <Card active={active} glow={glow} style={{ padding: compact ? 14 : 18 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div
          style={{
            width: compact ? 34 : 42,
            height: compact ? 34 : 42,
            borderRadius: 11,
            background: hexA(c, 0.14),
            border: `1px solid ${hexA(c, 0.4)}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontFamily: FONT_SANS,
            fontWeight: 800,
            fontSize: compact ? 13 : 16,
            color: c,
          }}
        >
          {name.slice(0, 2)}
        </div>
        <div style={{ flex: 1 }}>
          <div
            style={{
              fontFamily: FONT_SANS,
              fontWeight: 600,
              fontSize: compact ? 13.5 : 15,
              color: COLORS.text,
            }}
          >
            {name}
          </div>
          {!compact ? (
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 5 }}>
              <span style={{ width: 7, height: 7, borderRadius: 4, background: COLORS.green }} />
              <span style={{ fontFamily: FONT_SANS, fontSize: 12, color: COLORS.green }}>
                {status}
              </span>
            </div>
          ) : null}
        </div>
      </div>
    </Card>
  );
};

/* ============================================================================
   4. DashboardMetricCardMock
   ========================================================================== */

export const DashboardMetricCardMock: React.FC<{
  label: string;
  value: string;
  accent?: string;
  hint?: string;
}> = ({ label, value, accent = COLORS.blue, hint }) => (
  <Card style={{ padding: 18, minWidth: 0 }}>
    <SectionLabel>{label}</SectionLabel>
    <div
      style={{
        fontFamily: FONT_SANS,
        fontWeight: 800,
        fontSize: 34,
        color: accent,
        marginTop: 8,
        letterSpacing: -1,
      }}
    >
      {value}
    </div>
    {hint ? (
      <div style={{ fontFamily: FONT_SANS, fontSize: 11.5, color: COLORS.textFaint, marginTop: 4 }}>
        {hint}
      </div>
    ) : null}
  </Card>
);

/* ============================================================================
   5. TimelineEventMock
   ========================================================================== */

export const TimelineEventMock: React.FC<{
  severity: Severity;
  title: string;
  meta: string;
  time: string;
  active?: boolean;
  glow?: number;
  pulse?: number;
}> = ({ severity, title, meta, time, active, glow = 0, pulse = 0 }) => {
  const c = severityColor(severity);
  return (
    <Card severity={severity} active={active} glow={glow} style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ display: "flex" }}>
        <div style={{ width: 4, background: c }} />
        <div style={{ flex: 1, padding: "16px 18px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
            <RiskBadgeMock severity={severity} pulse={pulse} />
            <span style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLORS.textFaint }}>{time}</span>
          </div>
          <div
            style={{
              fontFamily: FONT_SANS,
              fontWeight: 600,
              fontSize: 15.5,
              color: COLORS.text,
              marginTop: 12,
            }}
          >
            {title}
          </div>
          <div style={{ fontFamily: FONT_SANS, fontSize: 12.5, color: COLORS.textMuted, marginTop: 5 }}>
            {meta}
          </div>
        </div>
      </div>
    </Card>
  );
};

/* ============================================================================
   6. ChangeDiffMock
   ========================================================================== */

export const ChangeDiffMock: React.FC<{
  before: string;
  after: string;
  reveal?: number; // 0..1 reveal of the "after" line
  label?: string;
}> = ({ before, after, reveal = 1, label }) => (
  <Card style={{ padding: 16 }}>
    {label ? (
      <div style={{ marginBottom: 12 }}>
        <SectionLabel>{label}</SectionLabel>
      </div>
    ) : null}
    <DiffLine sign="-" text={before} color={COLORS.red} bg="rgba(255,90,95,0.10)" />
    <div style={{ height: 8 }} />
    <div style={{ opacity: reveal, transform: `translateY(${(1 - reveal) * 8}px)` }}>
      <DiffLine sign="+" text={after} color={COLORS.green} bg="rgba(52,211,153,0.10)" />
    </div>
  </Card>
);

const DiffLine: React.FC<{ sign: string; text: string; color: string; bg: string }> = ({
  sign,
  text,
  color,
  bg,
}) => (
  <div
    style={{
      display: "flex",
      alignItems: "center",
      gap: 12,
      padding: "11px 14px",
      borderRadius: 10,
      background: bg,
      border: `1px solid ${hexA(color, 0.3)}`,
    }}
  >
    <span style={{ fontFamily: FONT_MONO, fontWeight: 700, color, width: 12 }}>{sign}</span>
    <span style={{ fontFamily: FONT_MONO, fontSize: 14, color: COLORS.text }}>{text}</span>
  </div>
);

/* ============================================================================
   7. BlastRadiusPanelMock
   ========================================================================== */

export const BlastRadiusPanelMock: React.FC<{
  items: string[];
  expand?: number; // 0..1
  active?: boolean;
}> = ({ items, expand = 1, active }) => (
  <Card active={active} glow={active ? 0.5 : 0} style={{ padding: 18 }}>
    <SectionLabel color={COLORS.amber}>Blast radius</SectionLabel>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 14 }}>
      {items.map((it, i) => {
        const shown = expand >= (i + 1) / items.length - 0.001;
        return (
          <span
            key={it}
            style={{
              opacity: shown ? 1 : 0.0,
              transform: `translateY(${shown ? 0 : 6}px)`,
              padding: "7px 12px",
              borderRadius: 9,
              background: hexA(COLORS.amber, 0.1),
              border: `1px solid ${hexA(COLORS.amber, 0.34)}`,
              color: COLORS.amber,
              fontFamily: FONT_SANS,
              fontSize: 12.5,
              fontWeight: 500,
            }}
          >
            {it}
          </span>
        );
      })}
    </div>
  </Card>
);

/* ============================================================================
   8. SuggestedFixPanelMock
   ========================================================================== */

export const SuggestedFixPanelMock: React.FC<{
  steps: string[];
  lit?: number; // 0..1 how many steps are "lit"
  active?: boolean;
}> = ({ steps, lit = 1, active }) => (
  <Card active={active} glow={active ? 0.5 : 0} style={{ padding: 18 }}>
    <SectionLabel color={COLORS.green}>Suggested fix</SectionLabel>
    <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
      {steps.map((s, i) => {
        const on = lit >= (i + 1) / steps.length - 0.001;
        return (
          <div key={s} style={{ display: "flex", alignItems: "center", gap: 11 }}>
            <span
              style={{
                width: 20,
                height: 20,
                borderRadius: 6,
                border: `1.5px solid ${on ? COLORS.green : COLORS.textFaint}`,
                background: on ? hexA(COLORS.green, 0.2) : "transparent",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: COLORS.green,
                fontSize: 12,
                fontWeight: 800,
                flexShrink: 0,
              }}
            >
              {on ? "✓" : ""}
            </span>
            <span
              style={{
                fontFamily: FONT_SANS,
                fontSize: 13.5,
                color: on ? COLORS.text : COLORS.textMuted,
              }}
            >
              {s}
            </span>
          </div>
        );
      })}
    </div>
  </Card>
);

/* ============================================================================
   9. AlertCardMock (email / browser push)
   ========================================================================== */

export const AlertCardMock: React.FC<{
  kind: "email" | "push";
  title: string;
  body: string;
  glow?: number;
}> = ({ kind, title, body, glow = 0 }) => (
  <Card severity="critical" glow={glow} style={{ padding: 18, width: "100%" }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
      <span
        style={{
          fontFamily: FONT_SANS,
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: 1,
          textTransform: "uppercase",
          color: COLORS.textMuted,
        }}
      >
        {kind === "email" ? "✉ Email alert" : "🔔 Browser push"}
      </span>
    </div>
    <div style={{ fontFamily: FONT_SANS, fontWeight: 600, fontSize: 14.5, color: COLORS.text }}>
      {title}
    </div>
    <div style={{ fontFamily: FONT_SANS, fontSize: 12.5, color: COLORS.textMuted, marginTop: 6 }}>
      {body}
    </div>
  </Card>
);

/* ============================================================================
   10. SlackAlertMock
   ========================================================================== */

export const SlackAlertMock: React.FC<{
  glow?: number;
  buttonHighlight?: string;
}> = ({ glow = 0, buttonHighlight }) => {
  const buttons = ["Open Change", "Acknowledge", "Snooze 24h", "View Remediation"];
  return (
    <Card severity="critical" glow={glow} style={{ padding: 18, width: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <div style={{ width: 22, height: 22, borderRadius: 6, background: "#4A154B" }} />
        <span
          style={{
            fontFamily: FONT_SANS,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 1,
            textTransform: "uppercase",
            color: COLORS.textMuted,
          }}
        >
          Slack alert
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <RiskBadgeMock severity="critical" />
        <span style={{ fontFamily: FONT_SANS, fontWeight: 600, fontSize: 14, color: COLORS.text }}>
          Configuration change detected
        </span>
      </div>
      <div style={{ fontFamily: FONT_SANS, fontSize: 12.5, color: COLORS.textMuted, marginTop: 8 }}>
        GitHub · configtrace-demo-risk · webhook URL changed
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 14 }}>
        {buttons.map((b) => {
          const hot = b === buttonHighlight;
          const primary = b === "Open Change";
          return (
            <span
              key={b}
              style={{
                padding: "7px 13px",
                borderRadius: 8,
                fontFamily: FONT_SANS,
                fontSize: 12.5,
                fontWeight: 600,
                color: primary ? COLORS.textInk : COLORS.text,
                background: primary ? COLORS.blueBright : "rgba(148,163,184,0.1)",
                border: `1px solid ${hot ? COLORS.blueBright : primary ? "transparent" : COLORS.cardBorder}`,
                boxShadow: hot ? `0 0 16px ${hexA(COLORS.blueBright, 0.5)}` : undefined,
              }}
            >
              {b}
            </span>
          );
        })}
      </div>
    </Card>
  );
};

/* ============================================================================
   11. BillingPlanMock
   ========================================================================== */

export const BillingPlanMock: React.FC<{
  name: string;
  price: string;
  features: string[];
  highlighted?: boolean;
  glow?: number;
  disabledLabel?: string;
}> = ({ name, price, features, highlighted, glow = 0, disabledLabel }) => (
  <Card active={highlighted} glow={highlighted ? glow : 0} style={{ padding: 20, width: 250 }}>
    <div style={{ fontFamily: FONT_SANS, fontWeight: 700, fontSize: 15, color: COLORS.text }}>
      {name}
    </div>
    <div
      style={{
        fontFamily: FONT_SANS,
        fontWeight: 800,
        fontSize: 28,
        color: highlighted ? COLORS.blueBright : COLORS.text,
        marginTop: 8,
        letterSpacing: -0.5,
      }}
    >
      {price}
    </div>
    <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 14 }}>
      {features.map((f) => (
        <div key={f} style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ color: COLORS.green, fontSize: 12 }}>✓</span>
          <span style={{ fontFamily: FONT_SANS, fontSize: 12.5, color: COLORS.textMuted }}>{f}</span>
        </div>
      ))}
    </div>
    <div
      style={{
        marginTop: 18,
        padding: "9px 0",
        borderRadius: 9,
        textAlign: "center",
        fontFamily: FONT_SANS,
        fontSize: 12.5,
        fontWeight: 600,
        background: disabledLabel ? "rgba(148,163,184,0.08)" : COLORS.blueBright,
        color: disabledLabel ? COLORS.textFaint : COLORS.textInk,
        border: `1px solid ${disabledLabel ? COLORS.cardBorder : "transparent"}`,
      }}
    >
      {disabledLabel ?? "Choose plan"}
    </div>
  </Card>
);

/* ============================================================================
   12. SystemMapMock
   ========================================================================== */

export const SystemMapMock: React.FC<{ progress?: number }> = ({ progress = 1 }) => {
  const stages = [
    "Providers",
    "Baseline snapshots",
    "Drift detection",
    "Risk classification",
    "Alerts",
    "Review workflow",
    "Remediation packet",
  ];
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", flexWrap: "wrap", gap: 0 }}>
      {stages.map((s, i) => {
        const on = progress >= (i + 1) / stages.length - 0.0001;
        return (
          <React.Fragment key={s}>
            <div
              style={{
                padding: "11px 16px",
                borderRadius: 11,
                background: on ? hexA(COLORS.blue, 0.14) : COLORS.card,
                border: `1px solid ${on ? COLORS.cardBorderActive : COLORS.cardBorder}`,
                color: on ? COLORS.text : COLORS.textMuted,
                fontFamily: FONT_SANS,
                fontSize: 13,
                fontWeight: 600,
                opacity: on ? 1 : 0.5,
              }}
            >
              {s}
            </div>
            {i < stages.length - 1 ? (
              <div
                style={{
                  width: 26,
                  height: 2,
                  margin: "0 2px",
                  background: on ? COLORS.cyan : COLORS.cardBorder,
                  opacity: on ? 1 : 0.4,
                }}
              />
            ) : null}
          </React.Fragment>
        );
      })}
    </div>
  );
};

/* ============================================================================
   13. PipelineRail — small horizontal step pipeline (baseline scene)
   ========================================================================== */

export const PipelineRail: React.FC<{ steps: string[]; progress: number }> = ({
  steps,
  progress,
}) => (
  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 0 }}>
    {steps.map((s, i) => {
      const on = progress >= (i + 1) / steps.length - 0.0001;
      return (
        <React.Fragment key={s}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
            <div
              style={{
                width: 16,
                height: 16,
                borderRadius: 9,
                background: on ? COLORS.blueBright : COLORS.bgElevated,
                border: `2px solid ${on ? COLORS.blueBright : COLORS.cardBorder}`,
                boxShadow: on ? `0 0 14px ${hexA(COLORS.blueBright, 0.5)}` : undefined,
              }}
            />
            <span
              style={{
                fontFamily: FONT_SANS,
                fontSize: 12,
                fontWeight: on ? 600 : 500,
                color: on ? COLORS.text : COLORS.textFaint,
              }}
            >
              {s}
            </span>
          </div>
          {i < steps.length - 1 ? (
            <div
              style={{
                width: 78,
                height: 2,
                marginBottom: 26,
                background: COLORS.cardBorder,
                position: "relative",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  width: `${Math.max(0, Math.min(1, progress * steps.length - i)) * 100}%`,
                  background: COLORS.cyan,
                }}
              />
            </div>
          ) : null}
        </React.Fragment>
      );
    })}
  </div>
);

/* ============================================================================
   helpers
   ========================================================================== */

/** Apply alpha to a #RRGGBB hex color. */
export function hexA(hex: string, a: number): string {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}
