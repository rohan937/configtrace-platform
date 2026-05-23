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
    return `${m}m ago`;
  }
  if (diffSec < 86400) {
    const h = Math.floor(diffSec / 3600);
    return `${h}h ago`;
  }
  if (diffSec < 30 * 86400) {
    const d = Math.floor(diffSec / 86400);
    return `${d}d ago`;
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
 * Returns a full UTC datetime string suitable for a tooltip or detail view,
 * e.g. "2026-05-19 14:32:07 UTC".
 */
export function formatAbsoluteTime(isoString: string): string {
  const d = new Date(isoString);
  const pad = (n: number) => String(n).padStart(2, "0");
  return [
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`,
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`,
    "UTC",
  ].join(" ");
}

// ── Values ────────────────────────────────────────────────────────────────────

/**
 * Serialise a change field value for display in the timeline.
 *
 * Rules (applied in order):
 * 1. null / undefined → "—"
 * 2. boolean → "true" / "false"
 * 3. number → string representation
 * 4. string → as-is
 * 5. DNS record object (has "content" field) → extract the content value
 * 6. array → "N records"
 * 7. any other object → compact JSON, truncated to 60 chars
 */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;

  if (Array.isArray(value)) {
    return `${value.length} record${value.length === 1 ? "" : "s"}`;
  }

  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;

    // DNS record object — show the meaningful content/value field.
    if ("content" in rec && rec.content !== undefined && rec.content !== null) {
      return String(rec.content);
    }

    // Fallback: compact JSON, capped at 60 characters to avoid huge blobs.
    const json = JSON.stringify(value);
    return json.length > 60 ? `${json.slice(0, 60)}…` : json;
  }

  return String(value);
}

/**
 * Produce a short "prev → new" diff label.
 * Both values are formatted via formatValue.
 */
export function formatValueChange(prev: unknown, next: unknown): string {
  return `${formatValue(prev)} → ${formatValue(next)}`;
}

/**
 * Format a change field value for full display in a diff panel.
 *
 * Unlike formatValue (which truncates objects to 60 chars), this variant
 * returns pretty-printed JSON for objects so engineers can read the full
 * record. Scalars and DNS record "content" fields are returned as plain text.
 */
export function formatDiffValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;

  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    // For DNS record objects, surface the content field directly.
    if ("content" in rec && rec.content !== null && rec.content !== undefined) {
      return String(rec.content);
    }
    return JSON.stringify(value, null, 2);
  }

  return String(value);
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

// ── ID / hash helpers ─────────────────────────────────────────────────────────

/**
 * Returns the first 8 characters of a UUID for compact display.
 * e.g. "3cb3e46a-…" → "3cb3e46a"
 */
export function shortId(id: string): string {
  return id.slice(0, 8);
}

/**
 * Returns the first 10 characters of a snapshot content_hash.
 * e.g. "sha256:abcdef…" → "sha256:abc" (or first 10 of a bare hex hash)
 */
export function formatSnapshotHash(hash: string): string {
  return hash.slice(0, 10);
}

// ── Resource type labels ──────────────────────────────────────────────────────

/**
 * Convert an internal provider_resource_type to a user-friendly label.
 *
 * Examples:
 *   "cloudflare_dns_zone" → "Cloudflare DNS zone"
 *   "github_repo"         → "GitHub repository"
 *   "some_unknown_type"   → "Some unknown type"
 */
export function formatResourceType(rawType: string): string {
  switch (rawType.toLowerCase()) {
    case "cloudflare_dns_zone":
      return "Cloudflare DNS zone";
    case "github_repo":
      return "GitHub repository";
    default:
      return rawType.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
  }
}

// ── Time range helpers ────────────────────────────────────────────────────────

/**
 * Convert a time-range token to an ISO 8601 "since" query parameter.
 * Returns undefined for "all" (no time filter).
 */
export function timeRangeToSince(range: string): string | undefined {
  const now = Date.now();
  switch (range) {
    case "24h":
      return new Date(now - 24 * 60 * 60 * 1000).toISOString();
    case "7d":
      return new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    case "30d":
      return new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
    default:
      return undefined;
  }
}
