/**
 * findingDisplay.tsx — shared presentational helpers for Security Exposure
 * findings (M60.6).
 *
 * Used by both the Active Exposures queue (M60.5) and the Exposure Detail page
 * (M60.6) so severity styling, sensitive-value masking, and evidence/remediation
 * rendering stay consistent and DRY.
 *
 * Nothing here imports backend logic; all input is the read-only SecurityFinding
 * shape from GET /security/findings.
 */

import type { SecurityFinding, SecurityFindingSeverity } from "@/types";
import { SectionLabel } from "@/components/security/previews";

// ── Severity / status tokens ────────────────────────────────────────────────

export const SEVERITY_COLOR: Record<SecurityFindingSeverity, string> = {
  critical: "#e84040",
  high: "#f5632a",
  medium: "#f5a623",
  low: "#6b9cf8",
  info: "#6b9cf8",
};

export const SEVERITY_LABEL: Record<SecurityFindingSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SEVERITY_RANK: Record<SecurityFindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const STATUS_LABEL: Record<string, string> = {
  active: "Active",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
  snoozed: "Snoozed",
};

export function sevColor(sev: string): string {
  return SEVERITY_COLOR[sev as SecurityFindingSeverity] ?? "#8b90a0";
}

// ── Sensitive-value masking ─────────────────────────────────────────────────

/**
 * Keys whose values must never be shown. ``secret`` alone already covers
 * signing_secret / webhook_secret / client_secret; the rest add tokens,
 * passwords, and *_key variants.
 */
export const SECRET_KEY_RE =
  /secret|token|password|api_?key|access_?key|private_?key|client_secret/i;

export function humanizeKey(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Mask values for secret-looking keys; otherwise stringify defensively. */
export function maskSensitiveValue(key: string, value: unknown): string {
  if (SECRET_KEY_RE.test(key)) return "••••••••";
  if (value === null || value === undefined) return "—";
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "[unrenderable]";
  }
}

// ── Exposure duration ───────────────────────────────────────────────────────

/** Format a millisecond span as a compact "2d 3h" / "2h 14m" / "18m" / "45s". */
export function formatDurationMs(ms: number): string {
  if (ms < 0) ms = 0;
  const sec = Math.floor(ms / 1000);
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  if (mins > 0) return `${mins}m`;
  return `${sec}s`;
}

/**
 * Human-readable exposure-duration phrase for a finding.
 * - active   → "Open for 2h 14m"
 * - resolved → "Resolved after 18m"
 * Falls back to null when timestamps are unparseable.
 */
export function formatExposureDuration(finding: SecurityFinding): string | null {
  const start = Date.parse(finding.first_detected_at);
  if (Number.isNaN(start)) return null;

  if (finding.status === "resolved" && finding.resolved_at) {
    const end = Date.parse(finding.resolved_at);
    if (Number.isNaN(end)) return null;
    return `Resolved after ${formatDurationMs(end - start)}`;
  }
  return `Open for ${formatDurationMs(Date.now() - start)}`;
}

// ── Badges ───────────────────────────────────────────────────────────────────

export function SeverityBadge({ severity }: { severity: string }) {
  const c = sevColor(severity);
  const label = SEVERITY_LABEL[severity as SecurityFindingSeverity] ?? severity;
  return (
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
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

export function FindingStatusBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; fg: string }> = {
    active: { bg: "rgba(232,64,64,0.14)", fg: "#e84040" },
    resolved: { bg: "rgba(60,207,126,0.14)", fg: "#3ccf7e" },
    accepted_risk: { bg: "rgba(245,166,35,0.14)", fg: "#f5a623" },
    snoozed: { bg: "rgba(139,144,160,0.14)", fg: "#8b90a0" },
  };
  const s = map[status] ?? { bg: "rgba(139,144,160,0.14)", fg: "#8b90a0" };
  return (
    <span
      style={{
        fontSize: "11px",
        fontWeight: 600,
        color: s.fg,
        background: s.bg,
        borderRadius: "6px",
        padding: "2px 8px",
        whiteSpace: "nowrap",
      }}
    >
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

// ── Evidence / remediation rendering ─────────────────────────────────────────

export function KeyValueList({
  obj,
  only,
}: {
  obj: Record<string, unknown>;
  only: string[];
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "10px",
        marginTop: "8px",
      }}
    >
      {only.map((k) => (
        <div key={k}>
          <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "2px" }}>
            {humanizeKey(k)}
          </div>
          <div
            style={{
              fontSize: "12.5px",
              color: "#c4c8d4",
              fontFamily: "monospace",
              wordBreak: "break-all",
            }}
          >
            {maskSensitiveValue(k, obj[k])}
          </div>
        </div>
      ))}
    </div>
  );
}

export function EvidenceBlock({
  evidence,
}: {
  evidence: Record<string, unknown>;
}) {
  // The internal "rule" key is an implementation detail, not user evidence.
  const keys = Object.keys(evidence).filter((k) => k !== "rule");
  return (
    <div>
      <SectionLabel>Evidence</SectionLabel>
      {keys.length > 0 ? (
        <KeyValueList obj={evidence} only={keys} />
      ) : (
        <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
          No additional evidence recorded.
        </div>
      )}
    </div>
  );
}

export function RemediationBlock({
  remediation,
}: {
  remediation: Record<string, unknown>;
}) {
  const summary =
    typeof remediation.summary === "string" ? remediation.summary : null;
  const steps = Array.isArray(remediation.steps)
    ? (remediation.steps as unknown[]).filter((s) => typeof s === "string")
    : [];
  const otherKeys = Object.keys(remediation).filter(
    (k) => k !== "summary" && k !== "steps",
  );

  return (
    <div>
      <SectionLabel>Suggested remediation</SectionLabel>
      {summary ? (
        <div
          style={{
            fontSize: "13px",
            color: "#c4c8d4",
            lineHeight: 1.6,
            marginTop: "6px",
          }}
        >
          {summary}
        </div>
      ) : null}
      {steps.length > 0 ? (
        <ol
          style={{
            margin: "10px 0 0",
            paddingLeft: "20px",
            color: "#8b90a0",
            fontSize: "12.5px",
            lineHeight: 1.8,
          }}
        >
          {steps.map((s, i) => (
            <li key={i}>{s as string}</li>
          ))}
        </ol>
      ) : null}
      {otherKeys.length > 0 ? (
        <KeyValueList obj={remediation} only={otherKeys} />
      ) : null}
      {!summary && steps.length === 0 && otherKeys.length === 0 ? (
        <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
          No remediation guidance provided.
        </div>
      ) : null}
    </div>
  );
}
