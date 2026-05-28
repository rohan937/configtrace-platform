/**
 * M59.15 — derived display status for an integration row.
 *
 * Backend ``Integration.status`` is the *credential* state: ``active``,
 * ``paused``, ``needs_reconnect``, ``deleted``.  But the UI also needs to
 * reflect the *health of the latest sync* — an integration whose credentials
 * are still valid but whose last sync hit a 404 or a 5xx is not "Active" in
 * any honest sense, and showing a green badge there is misleading.
 *
 * This helper combines the backend status with the latest sync outcome to
 * produce a single display status the UI can render consistently across the
 * list, detail page, and provider cards.
 *
 * Status precedence (most → least restrictive):
 *   1. ``deleted``         → caller should filter the row out entirely.
 *   2. ``needs_reconnect`` → upstream credentials gone, must reconnect.
 *   3. ``paused``          → user-paused; manual + scheduled syncs blocked.
 *   4. ``needs_attention`` → backend status active, but the latest sync
 *                            failed with ``resource_missing`` (provider
 *                            resource deleted/renamed; retrying may help
 *                            but the user should also verify the target).
 *   5. ``degraded``        → backend status active, but the latest sync
 *                            failed with any other category (transient
 *                            5xx, rate-limit, network, etc.).
 *   6. ``active``          → healthy; last sync succeeded or never ran.
 *   7. ``unknown``         → fallback if the backend ships a status we
 *                            don't recognise yet (forwards-compat).
 */

import type { Integration } from "@/types";

export type DisplayStatus =
  | "active"
  | "needs_reconnect"
  | "paused"
  | "needs_attention"
  | "degraded"
  | "deleted"
  | "unknown";

export function getDisplayStatus(integration: Integration): DisplayStatus {
  const s = integration.status;
  if (s === "deleted") return "deleted";
  if (s === "needs_reconnect") return "needs_reconnect";
  if (s === "paused") return "paused";

  // From here on the backend considers credentials valid.  The display state
  // depends on whether the most recent sync succeeded.
  if (s === "active" || s === "error" || s === "unknown") {
    if (integration.last_sync_status === "failed") {
      // A failed run with no category means a very old SyncRun from before
      // M32; treat conservatively as ``degraded`` rather than ``active``.
      if (integration.last_sync_failure_category === "resource_missing") {
        return "needs_attention";
      }
      return "degraded";
    }
    // Pending / running / completed / null → backend is in charge; show active.
    return "active";
  }

  return "unknown";
}

/** Whether this row counts toward the provider card's "healthy" tally. */
export function isHealthy(integration: Integration): boolean {
  return getDisplayStatus(integration) === "active";
}

/**
 * Whether this row should be shown as "connected" at all — i.e. we still
 * believe the integration exists and could become healthy again (degraded /
 * needs_attention / needs_reconnect all qualify; ``deleted`` does not).
 */
export function isConnected(integration: Integration): boolean {
  const d = getDisplayStatus(integration);
  return d !== "deleted" && d !== "unknown";
}
