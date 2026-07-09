/**
 * Sync health helpers — M57.6.
 *
 * Centralises all logic for deciding how to label, describe, and warn about
 * an integration's monitoring health.  Components import from here instead
 * of duplicating if-chains.
 *
 * Key semantic note on last_synced_at:
 *   The backend sets last_synced_at only when a sync run completes without
 *   throwing an exception (i.e. the connector.fetch + snapshot pipeline
 *   succeeds).  Failed runs do NOT update last_synced_at.  So last_synced_at
 *   is effectively "last successfully synced at".
 *
 * Status priority order (highest wins):
 *   sync_running  → a sync is currently in progress
 *   sync_failed   → last sync run threw an exception
 *   monitoring_paused → integration is paused
 *   never_synced  → no successful sync has ever run
 *   sync_may_be_stale → scheduled but last sync > 2x interval ago
 *   manual_sync_only → scheduled_sync_enabled is false
 *   recently_synced   → everything looks healthy
 */

import type { Integration } from "@/types";

// ── Types ─────────────────────────────────────────────────────────────────────

export type SyncHealthStatus =
  | "recently_synced"
  | "sync_running"
  | "never_synced"
  | "sync_failed"
  | "sync_may_be_stale"
  | "monitoring_paused"
  | "manual_sync_only"
  | "unknown";

export interface SyncHealth {
  status: SyncHealthStatus;
  label: string;
  color: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

/** Default cadence when sync_interval_minutes is null. */
const DEFAULT_INTERVAL_MINUTES = 60;

/**
 * Multiplier for stale detection.
 * If last_synced_at > interval * STALE_MULTIPLIER minutes ago, the sync is stale.
 */
const STALE_MULTIPLIER = 2;

// ── Core helpers ──────────────────────────────────────────────────────────────

/** Return the effective sync interval in minutes, falling back to the default. */
export function getEffectiveInterval(integration: Integration): number {
  return integration.sync_interval_minutes ?? DEFAULT_INTERVAL_MINUTES;
}

/**
 * Compute elapsed seconds since a UTC ISO timestamp string.
 * Returns Infinity if the string is null or unparseable.
 */
function elapsedSecsSince(isoOrNull: string | null): number {
  if (!isoOrNull) return Infinity;
  const ms = Date.now() - new Date(isoOrNull).getTime();
  return ms / 1000;
}

// ── Sync health status ────────────────────────────────────────────────────────

/**
 * Derive the overall sync health status and display label for an integration.
 *
 * Rules (evaluated in priority order):
 *  1. running/pending   → "Sync running…"
 *  2. paused            → "Monitoring paused"
 *  3. failed            → "Sync failed"
 *  4. never synced      → "Never synced"
 *  5. stale (scheduled) → "Sync may be stale"
 *  6. manual-only       → "Manual sync only"
 *  7. healthy           → "Recently synced"
 */
export function getSyncHealth(integration: Integration): SyncHealth {
  const { status, last_synced_at, last_sync_status, scheduled_sync_enabled } = integration;

  // 1. In-progress — highest priority
  if (last_sync_status === "running" || last_sync_status === "pending") {
    return { status: "sync_running", label: "Sync running…", color: "#f5a623" };
  }

  // 2. Paused
  if (status === "paused") {
    return { status: "monitoring_paused", label: "Monitoring paused", color: "#565b6e" };
  }

  // 3. Last sync failed
  if (last_sync_status === "failed") {
    return { status: "sync_failed", label: "Sync failed", color: "#e84040" };
  }

  // 4. Never synced
  if (!last_synced_at) {
    return { status: "never_synced", label: "Never synced", color: "#565b6e" };
  }

  // 5. Stale — only applies to integrations with scheduled sync enabled
  if (scheduled_sync_enabled) {
    const interval = getEffectiveInterval(integration);
    const staleSecs = interval * 60 * STALE_MULTIPLIER;
    if (elapsedSecsSince(last_synced_at) > staleSecs) {
      return { status: "sync_may_be_stale", label: "Sync may be stale", color: "#f5a623" };
    }
  }

  // 6. Scheduled sync off but at least one successful sync
  if (!scheduled_sync_enabled) {
    return { status: "manual_sync_only", label: "Manual sync only", color: "#8b90a0" };
  }

  // 7. Healthy
  return { status: "recently_synced", label: "Recently synced", color: "#3ccf7e" };
}

// ── Cadence display ───────────────────────────────────────────────────────────

/**
 * Human-readable monitoring cadence for an integration's metadata strip.
 *
 * Examples:
 *   "Monitoring cadence: every 5 min"
 *   "Monitoring cadence: every 1 hour"
 *   "Manual sync only"
 *   "Monitoring paused"
 */
export function formatCadence(integration: Integration): string {
  if (integration.status === "paused") return "Monitoring paused";
  if (!integration.scheduled_sync_enabled) return "Manual sync only";
  const m = getEffectiveInterval(integration);
  if (m < 60) return `Monitoring cadence: every ${m} min`;
  return "Monitoring cadence: every 1 hour";
}

/**
 * Short interval label used inside the interval selector row.
 * Does NOT repeat "Monitoring cadence:" prefix.
 *
 * Examples: "every 5 min", "every 15 min", "every 1 hour"
 */
export function formatIntervalLabel(minutes: number | null): string {
  const m = minutes ?? DEFAULT_INTERVAL_MINUTES;
  if (m < 60) return `every ${m} min`;
  return "every 1 hour";
}

// ── Stale warning ─────────────────────────────────────────────────────────────

/**
 * Return a one-sentence stale warning, or null if not applicable.
 *
 * Only shown when:
 *  - scheduled_sync_enabled is true
 *  - integration is not paused
 *  - a successful sync has run (last_synced_at is set)
 *  - last_synced_at is older than 2× the configured interval
 *  - no sync is currently running
 *
 * Example:
 *   "Sync may be stale — last successful sync was 2h 45m ago, expected every 1h."
 */
export function getStalenessWarning(integration: Integration): string | null {
  if (!integration.scheduled_sync_enabled) return null;
  if (integration.status === "paused") return null;
  if (!integration.last_synced_at) return null;
  if (
    integration.last_sync_status === "running" ||
    integration.last_sync_status === "pending"
  ) {
    return null;
  }

  const interval = getEffectiveInterval(integration);
  const staleSecs = interval * 60 * STALE_MULTIPLIER;
  const elapsed = elapsedSecsSince(integration.last_synced_at);
  if (elapsed <= staleSecs) return null;

  const elapsedStr = formatDuration(elapsed);
  const intervalStr = interval < 60 ? `every ${interval} min` : "every 1 hour";
  return `Sync may be stale — last successful sync was ${elapsedStr} ago, expected ${intervalStr}.`;
}

// ── Next expected sync ────────────────────────────────────────────────────────

/**
 * Return a "next expected sync" estimate string, or null when not applicable.
 *
 * Only shown when:
 *  - scheduled_sync_enabled is true
 *  - integration is not paused
 *  - a successful sync has run (last_synced_at is set)
 *  - no sync is currently running
 *  - the next expected time is at most 10 minutes overdue (avoids stale noise)
 *
 * Examples:
 *   "Expected next sync: in ~7 min"
 *   "Expected next sync: should have run already"
 *   "Expected next sync: very soon"
 *
 * Uses "expected" language because Celery Beat scheduling is approximate.
 */
export function getNextExpectedSync(integration: Integration): string | null {
  if (!integration.scheduled_sync_enabled) return null;
  if (integration.status === "paused") return null;
  if (!integration.last_synced_at) return null;
  if (
    integration.last_sync_status === "running" ||
    integration.last_sync_status === "pending"
  ) {
    return null;
  }

  const interval = getEffectiveInterval(integration);
  const lastSync = new Date(integration.last_synced_at).getTime();
  const nextSync = lastSync + interval * 60 * 1000;
  const secsUntil = (nextSync - Date.now()) / 1000;

  // More than 10 minutes overdue — too imprecise to display; stale warning covers this
  if (secsUntil < -(60 * 10)) return null;

  if (secsUntil <= 0) return "Expected next sync: should have run already";
  if (secsUntil < 90) return "Expected next sync: very soon";
  return `Expected next sync: in ~${Math.round(secsUntil / 60)} min`;
}

// ── Friendly error copy ───────────────────────────────────────────────────────

/**
 * Return a concise, user-friendly description of a sync error, or null.
 *
 * Avoids raw stack traces and never surfaces credentials.
 * The recommended action depends on the error category.
 */
export function getFriendlyErrorCopy(
  lastSyncError: string | null,
  needsAttention: boolean,
): string | null {
  if (!lastSyncError) return null;
  const msg = lastSyncError.toLowerCase();

  // Check 403/permission-denied signals BEFORE the generic "authentication"
  // match below: connector error text for both 401 and 403 often contains the
  // word "authentication" (e.g. "GitHub authentication failed (HTTP 403)"),
  // which would otherwise always classify a 403 as "invalid or expired"
  // credentials even when the token is fine but simply lacks access to this
  // specific resource (e.g. a repo that just went private). 403 is a more
  // specific signal than the generic word "authentication", so it must win.
  if (
    msg.includes("permission") ||
    msg.includes("403") ||
    msg.includes("forbidden") ||
    msg.includes("insufficient scopes")
  ) {
    return "Permission denied — review provider permissions or reconnect this integration.";
  }
  if (
    msg.includes("authentication") ||
    msg.includes("invalid") ||
    msg.includes("revoked") ||
    msg.includes("401")
  ) {
    return "Credentials invalid or expired — reconnect this integration.";
  }
  if (msg.includes("not found") || msg.includes("404")) {
    return "Resource not found — the provider resource may have been deleted or renamed.";
  }
  if (msg.includes("rate limit") || msg.includes("429")) {
    return "Provider API rate limit reached — sync will retry automatically.";
  }
  if (
    msg.includes("timeout") ||
    msg.includes("network") ||
    msg.includes("unavailable") ||
    msg.includes("502") ||
    msg.includes("503")
  ) {
    return "Provider API temporarily unavailable — try again later or check provider status.";
  }
  if (needsAttention) {
    return "Repeated sync failures — reconnect the integration or check the provider's status page.";
  }

  // Truncate unrecognized raw errors to keep the UI clean
  return lastSyncError.length > 120
    ? `${lastSyncError.slice(0, 120)}…`
    : lastSyncError;
}

// ── Duration formatter ────────────────────────────────────────────────────────

/** Format a duration in seconds as a compact human string. */
function formatDuration(seconds: number): string {
  const totalMins = Math.round(seconds / 60);
  if (totalMins < 60) return `${totalMins} min`;
  const hours = Math.floor(totalMins / 60);
  const mins = totalMins % 60;
  if (mins === 0) return `${hours}h`;
  return `${hours}h ${mins}m`;
}
