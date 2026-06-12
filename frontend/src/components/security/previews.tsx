/**
 * previews.tsx — presentational building blocks for the Configuration Risk
 * placeholder pages (M60.1).
 *
 * IMPORTANT: nothing here is backed by real data. The security findings engine
 * lands in M60.3/M60.4. Every component is clearly framed as a preview/empty
 * state so users never mistake the examples for live findings.
 */

import type { ReactNode } from "react";

type Severity = "critical" | "high" | "medium" | "info";

const SEV_COLOR: Record<Severity, string> = {
  critical: "#e84040",
  high: "#f5632a",
  medium: "#f5a623",
  info: "#6b9cf8",
};

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  info: "Info",
};

/** Amber notice that frames the page as a pre-engine preview. */
export function PreviewBanner({ children }: { children: ReactNode }) {
  return (
    <div
      role="note"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "12px 14px",
        borderRadius: "10px",
        background: "rgba(245, 166, 35, 0.08)",
        border: "1px solid rgba(245, 166, 35, 0.32)",
        marginBottom: "24px",
      }}
    >
      <span
        aria-hidden
        style={{
          width: "7px",
          height: "7px",
          borderRadius: "4px",
          background: "#f5a623",
          marginTop: "6px",
          flexShrink: 0,
        }}
      />
      <p style={{ margin: 0, fontSize: "13px", color: "#c9a35a", lineHeight: 1.5 }}>
        {children}
      </p>
    </div>
  );
}

/** Small uppercase eyebrow label used above sections. */
export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        fontSize: "11px",
        fontWeight: 600,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: "#565b6e",
        marginBottom: "12px",
      }}
    >
      {children}
    </div>
  );
}

/** A dashboard metric card with an empty/zero preview state. */
export function StatCard({
  label,
  accent = "#4f80f7",
  hint,
}: {
  label: string;
  accent?: string;
  hint?: string;
}) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "16px 18px" }}
    >
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: "28px",
          fontWeight: 700,
          color: accent,
          marginTop: "8px",
          letterSpacing: "-0.02em",
          opacity: 0.55,
        }}
      >
        —
      </div>
      <div style={{ fontSize: "11px", color: "#565b6e", marginTop: "4px" }}>
        {hint ?? "No data yet"}
      </div>
    </div>
  );
}

/** A preview exposure row (clearly labelled as an example). */
export function ExposureRow({
  severity,
  title,
  provider,
  detail,
}: {
  severity: Severity;
  title: string;
  provider: string;
  detail: string;
}) {
  const c = SEV_COLOR[severity];
  return (
    <div
      className="bg-surface1 border border-border"
      style={{
        borderRadius: "12px",
        padding: "0",
        overflow: "hidden",
        display: "flex",
        opacity: 0.92,
      }}
    >
      <div style={{ width: "3px", background: c, flexShrink: 0 }} />
      <div style={{ flex: 1, padding: "14px 16px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "12px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span
              style={{
                fontSize: "10px",
                fontWeight: 700,
                letterSpacing: "0.04em",
                textTransform: "uppercase",
                color: c,
                background: `${c}1f`,
                border: `1px solid ${c}55`,
                borderRadius: "999px",
                padding: "3px 9px",
              }}
            >
              {SEV_LABEL[severity]}
            </span>
            <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0" }}>
              {title}
            </span>
          </div>
          <span
            style={{
              fontSize: "10px",
              color: "#565b6e",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "2px 8px",
            }}
          >
            preview example
          </span>
        </div>
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "7px" }}>
          {provider} · {detail}
        </div>
      </div>
    </div>
  );
}

/** Horizontal lifecycle flow (e.g. Opened → Alert sent → Reviewed → Resolved). */
export function LifecycleFlow({ steps }: { steps: string[] }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "0",
      }}
    >
      {steps.map((s, i) => (
        <span key={s} style={{ display: "flex", alignItems: "center" }}>
          <span
            className="bg-surface2 border border-border"
            style={{
              fontSize: "13px",
              color: "#c4c8d4",
              padding: "8px 14px",
              borderRadius: "9px",
              fontWeight: 500,
            }}
          >
            {s}
          </span>
          {i < steps.length - 1 ? (
            <span
              aria-hidden
              style={{ color: "#565b6e", padding: "0 10px", fontSize: "13px" }}
            >
              →
            </span>
          ) : null}
        </span>
      ))}
    </div>
  );
}

/** A preview security-rule row. */
export function RuleRow({
  title,
  severity,
  providers,
}: {
  title: string;
  severity: Severity;
  providers: string;
}) {
  const c = SEV_COLOR[severity];
  return (
    <div
      className="bg-surface1 border border-border"
      style={{
        borderRadius: "10px",
        padding: "13px 16px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        opacity: 0.92,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <span
          aria-hidden
          style={{
            width: "8px",
            height: "8px",
            borderRadius: "5px",
            background: c,
            flexShrink: 0,
          }}
        />
        <span style={{ fontSize: "14px", color: "#e8eaf0", fontWeight: 500 }}>
          {title}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <span style={{ fontSize: "11px", color: "#8b90a0" }}>{providers}</span>
        <span
          style={{
            fontSize: "10px",
            color: "#565b6e",
            border: "1px solid #2a2d38",
            borderRadius: "6px",
            padding: "2px 8px",
          }}
        >
          not active yet
        </span>
      </div>
    </div>
  );
}
