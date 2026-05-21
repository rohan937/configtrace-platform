/**
 * Shared formatting helpers for the ConfigTrace frontend.
 */

// ── Date / time ───────────────────────────────────────────────────────────────

/**
 * Returns a human-readable relative time string, e.g. "3 minutes ago",
 * "2 hours ago", "5 days ago".  Falls back to the absolute date for anything
 * older than 30 days.
 */
export function formatRelativeTime(isoString: string): string {
  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diffMs = now - then;
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return "just now";
  if (diffSec < 3600) {
    const m = Math.floor(diffSec / 60);
    return `${m} ${m === 1 ? "minute" : "minutes"} ago`;
  }
  if (diffSec < 86400) {
    const h = Math.floor(diffSec / 3600);
    return `${h} ${h === 1 ? "hour" : "hours"} ago`;
  }
  if (diffSec < 30 * 86400) {
    const d = Math.floor(diffSec / 86400);
    return `${d} ${d === 1 ? "day" : "days"} ago`;
  }
  return formatDate(isoString);
}

/**
 * Returns a short absolute date string, e.g. "Jan 15, 2025".
 */
export function formatDate(isoString: string): string {
  return new Date(isoString).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/**
 * Returns a datetime string, e.g. "Jan 15, 2025, 14:32 UTC".
 */
export function formatDateTime(isoString: string): string {
  return (
    new Date(isoString).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "UTC",
      timeZoneName: "short",
    })
  );
}

// ── Values ────────────────────────────────────────────────────────────────────

/**
 * Serialise an arbitrary field value for display.  Objects/arrays are
 * pretty-printed as compact JSON; primitives are shown as-is.
 */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Produce a short "prev → new" diff label for a change row.
 * Both values are formatted via formatValue.
 */
export function formatValueChange(prev: unknown, next: unknown): string {
  return `${formatValue(prev)} → ${formatValue(next)}`;
}

// ── Change type labels ────────────────────────────────────────────────────────

export function changeTypeLabel(changeType: string): string {
  switch (changeType) {
    case "added":
      return "Added";
    case "removed":
      return "Removed";
    case "modified":
      return "Modified";
    default:
      return changeType;
  }
}
