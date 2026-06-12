/**
 * signalDisplay.tsx — shared presentational helpers for Incident Signals (M66.4).
 *
 * Severity/confidence badges are reused from findingDisplay. This adds the
 * signal-specific status badge (open/acknowledged/dismissed/resolved).
 */

const SIGNAL_STATUS_LABEL: Record<string, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  dismissed: "Dismissed",
  resolved: "Resolved",
};

const CASE_STATUS_LABEL: Record<string, string> = {
  open: "Open",
  investigating: "Investigating",
  confirmed_by_user: "Confirmed by user",
  dismissed: "Dismissed",
  resolved: "Resolved",
};

/** Status badge for investigation cases (M66.8). "Confirmed by user" is a human action. */
export function CaseStatusBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; fg: string }> = {
    open: { bg: "rgba(245,99,42,0.14)", fg: "#f5632a" },
    investigating: { bg: "rgba(107,156,248,0.14)", fg: "#6b9cf8" },
    confirmed_by_user: { bg: "rgba(232,64,64,0.14)", fg: "#e84040" },
    dismissed: { bg: "rgba(139,144,160,0.14)", fg: "#8b90a0" },
    resolved: { bg: "rgba(60,207,126,0.14)", fg: "#3ccf7e" },
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
      {CASE_STATUS_LABEL[status] ?? status}
    </span>
  );
}

export function SignalStatusBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; fg: string }> = {
    open: { bg: "rgba(245,99,42,0.14)", fg: "#f5632a" },
    acknowledged: { bg: "rgba(107,156,248,0.14)", fg: "#6b9cf8" },
    dismissed: { bg: "rgba(139,144,160,0.14)", fg: "#8b90a0" },
    resolved: { bg: "rgba(60,207,126,0.14)", fg: "#3ccf7e" },
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
      {SIGNAL_STATUS_LABEL[status] ?? status}
    </span>
  );
}
