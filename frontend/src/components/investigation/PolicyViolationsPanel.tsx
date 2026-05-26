"use client";

/**
 * PolicyViolationsPanel — M58.14.
 *
 * Displays built-in policy violations detected for the current change.
 * Data comes from GET /changes/{id}/policy-violations — deterministic,
 * computed on demand, nothing persisted.
 *
 * Design rules:
 *   - No free-text input.  No LLM.  No external API calls from this component.
 *   - Language: "may indicate", "appears", "detected in metadata" — never
 *     "confirmed breach", "guaranteed", "publicly reachable".
 *   - Empty state: a brief note that no policy violations were detected.
 *   - Never displays prev_value / new_value.
 *   - Disclaimer: "Policy checks use configuration metadata only. Review
 *     provider context before acting."
 */

import type { PolicyViolation, PolicyViolationsResponse } from "@/types";

// ── Colour helpers ────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "#3a1515", text: "#f87171", border: "#7f1d1d" },
  high:     { bg: "#2d1a0a", text: "#fb923c", border: "#7c2d12" },
  medium:   { bg: "#2a2208", text: "#fbbf24", border: "#78350f" },
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high:     "High",
  medium:   "Medium",
};

const CATEGORY_ICONS: Record<string, string> = {
  "Network exposure":  "🌐",
  "Audit logging":     "📋",
  "Edge protection":   "🛡",
  "Auth":              "🔐",
  "Branch protection": "🌿",
  "TLS/HTTPS":         "🔒",
  "Webhooks":          "🔗",
  "Access control":    "🗝",
  "Deployment":        "🚀",
  "Commerce":          "🛍",
};


// ── Sub-components ────────────────────────────────────────────────────────────

function ViolationCard({ v }: { v: PolicyViolation }) {
  const colors = SEVERITY_COLORS[v.severity] ?? SEVERITY_COLORS.high;

  return (
    <div
      style={{
        background: colors.bg,
        border: `1px solid ${colors.border}`,
        borderRadius: 8,
        padding: "14px 16px",
        marginBottom: 10,
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: colors.text,
            background: `${colors.border}55`,
            border: `1px solid ${colors.border}`,
            borderRadius: 4,
            padding: "2px 7px",
          }}
        >
          {SEVERITY_LABELS[v.severity] ?? v.severity}
        </span>
        <span style={{ fontSize: 13, fontWeight: 600, color: "#e8eaf0" }}>
          {v.name}
        </span>
      </div>

      {/* Description */}
      <p style={{ fontSize: 12, color: "#9ca3b0", margin: "0 0 10px", lineHeight: 1.55 }}>
        {v.description}
      </p>

      {/* Evidence */}
      {v.evidence.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 5 }}>
            Evidence
          </div>
          <ul style={{ margin: 0, padding: "0 0 0 16px" }}>
            {v.evidence.map((e, i) => (
              <li key={i} style={{ fontSize: 12, color: "#b0b8c8", marginBottom: 3 }}>
                {e}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended action */}
      <div
        style={{
          background: "#1a1d26",
          border: "1px solid #2a2d38",
          borderRadius: 6,
          padding: "8px 12px",
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 600, color: "#6b9cf8", marginRight: 6 }}>
          Recommended:
        </span>
        <span style={{ fontSize: 12, color: "#9ca3b0" }}>{v.recommended_action}</span>
      </div>
    </div>
  );
}


// ── Main panel ────────────────────────────────────────────────────────────────

interface Props {
  data: PolicyViolationsResponse | null;
  loading: boolean;
}

export default function PolicyViolationsPanel({ data, loading }: Props) {
  // Shared container style
  const containerStyle: React.CSSProperties = {
    background: "#13151e",
    border: "1px solid #1e2130",
    borderRadius: 10,
    padding: "16px 18px",
    marginBottom: 16,
  };

  const headerStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    gap: 8,
    marginBottom: 14,
  };

  // Loading skeleton
  if (loading) {
    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <span style={{ fontSize: 14, fontWeight: 600, color: "#e8eaf0" }}>
            🚨 Policy Violations
          </span>
        </div>
        <div style={{ color: "#565b6e", fontSize: 13 }}>Checking policies…</div>
      </div>
    );
  }

  const violations = data?.violations ?? [];

  const criticalCount = violations.filter((v) => v.severity === "critical").length;
  const highCount = violations.filter((v) => v.severity === "high").length;

  const badgeColor =
    criticalCount > 0 ? "#e84040"
    : highCount > 0 ? "#f5632a"
    : "#3ccf7e";

  const badgeBg =
    criticalCount > 0 ? "#3a1515"
    : highCount > 0 ? "#2d1a0a"
    : "#0e2a1a";

  return (
    <div style={containerStyle}>
      {/* Panel header */}
      <div style={headerStyle}>
        <span style={{ fontSize: 14, fontWeight: 600, color: "#e8eaf0" }}>
          🚨 Policy Violations
        </span>
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            color: badgeColor,
            background: badgeBg,
            border: `1px solid ${badgeColor}55`,
            borderRadius: 10,
            padding: "2px 8px",
          }}
        >
          {violations.length === 0 ? "None" : `${violations.length} detected`}
        </span>
      </div>

      {/* Empty state */}
      {violations.length === 0 && (
        <div
          style={{
            background: "#0e2a1a",
            border: "1px solid #14532d",
            borderRadius: 8,
            padding: "12px 14px",
            color: "#3ccf7e",
            fontSize: 13,
          }}
        >
          ✓ No policy violations detected for this change.
        </div>
      )}

      {/* Violation cards */}
      {violations.map((v) => (
        <ViolationCard key={v.policy_key} v={v} />
      ))}

      {/* Disclaimer */}
      <p
        style={{
          fontSize: 11,
          color: "#454a5a",
          marginTop: violations.length > 0 ? 10 : 8,
          marginBottom: 0,
          lineHeight: 1.5,
        }}
      >
        Policy checks use configuration metadata only. Review provider context
        before acting on any violation.
      </p>
    </div>
  );
}
