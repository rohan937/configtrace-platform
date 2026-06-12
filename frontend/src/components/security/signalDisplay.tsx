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
