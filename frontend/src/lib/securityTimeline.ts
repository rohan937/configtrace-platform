/**
 * securityTimeline.ts — derive a lifecycle timeline from security findings.
 *
 * The Risk Timeline (M60.8) turns persisted security_findings into ordered
 * lifecycle events. Every event is derived ONLY from fields the finding already
 * carries — no invented event types:
 *
 *   opened       ← first_detected_at        (always)
 *   reopened     ← first_detected_at        (when an earlier finding with the
 *                                            same finding_key exists in the set)
 *   still_active  ← last_seen_at            (active findings, seen after open)
 *   resolved      ← resolved_at             (resolved findings)
 *   accepted_risk ← reviewed_at             (M61.1: accepted_risk findings)
 *   acknowledged  ← reviewed_at             (M61.2: active findings with a review)
 *   snoozed       ← reviewed_at             (M61.2: snoozed findings)
 *
 * We deliberately do NOT derive "Alert sent" — that requires alert data that
 * does not exist yet (deferred to the M61.3 audit trail).
 */

import type { SecurityFinding } from "@/types";
import { formatDurationMs } from "@/components/security/findingDisplay";

export type TimelineEventType =
  | "opened"
  | "reopened"
  | "still_active"
  | "resolved"
  | "accepted_risk"
  | "acknowledged"
  | "snoozed";

export interface TimelineEvent {
  /** Stable key: `${finding.id}:${type}`. */
  key: string;
  type: TimelineEventType;
  /** ISO timestamp this event occurred at. */
  at: string;
  finding: SecurityFinding;
}

export const EVENT_LABEL: Record<TimelineEventType, string> = {
  opened: "Configuration risk opened",
  reopened: "Re-opened",
  still_active: "Still active",
  resolved: "Configuration risk resolved",
  accepted_risk: "Risk accepted",
  acknowledged: "Acknowledged",
  snoozed: "Snoozed",
};

/** Filter value for the event-type control. "opened" includes "reopened". */
export type EventTypeFilter =
  | "all"
  | "opened"
  | "still_active"
  | "resolved"
  | "accepted_risk"
  | "acknowledged"
  | "snoozed";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

function ts(iso: string | null | undefined): number {
  if (!iso) return NaN;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? NaN : t;
}

/**
 * Build lifecycle events from a set of findings, newest event first.
 *
 * "reopened" is only claimed when an earlier finding with the same finding_key
 * is present in the loaded set — conservative, so we never falsely label the
 * first time we see a key as a re-open.
 */
export function buildTimelineEvents(findings: SecurityFinding[]): TimelineEvent[] {
  // Earliest first_detected_at per finding_key (within the loaded window).
  const earliestByKey = new Map<string, number>();
  for (const f of findings) {
    const t = ts(f.first_detected_at);
    if (Number.isNaN(t)) continue;
    const cur = earliestByKey.get(f.finding_key);
    if (cur === undefined || t < cur) earliestByKey.set(f.finding_key, t);
  }

  const events: TimelineEvent[] = [];
  for (const f of findings) {
    const opened = ts(f.first_detected_at);
    if (!Number.isNaN(opened)) {
      const earliest = earliestByKey.get(f.finding_key);
      const isReopen = earliest !== undefined && opened > earliest;
      events.push({
        key: `${f.id}:${isReopen ? "reopened" : "opened"}`,
        type: isReopen ? "reopened" : "opened",
        at: f.first_detected_at,
        finding: f,
      });
    }

    // Still active: only for active findings actually seen after they opened.
    if (f.status === "active") {
      const lastSeen = ts(f.last_seen_at);
      if (!Number.isNaN(lastSeen) && !Number.isNaN(opened) && lastSeen > opened) {
        events.push({
          key: `${f.id}:still_active`,
          type: "still_active",
          at: f.last_seen_at,
          finding: f,
        });
      }
    }

    // Resolved.
    if (f.status === "resolved" && f.resolved_at && !Number.isNaN(ts(f.resolved_at))) {
      events.push({
        key: `${f.id}:resolved`,
        type: "resolved",
        at: f.resolved_at,
        finding: f,
      });
    }

    // Risk accepted (M61.1): derived from reviewed_at on accepted_risk findings.
    if (f.status === "accepted_risk" && f.reviewed_at && !Number.isNaN(ts(f.reviewed_at))) {
      events.push({
        key: `${f.id}:accepted_risk`,
        type: "accepted_risk",
        at: f.reviewed_at,
        finding: f,
      });
    }

    // Acknowledged (M61.2): an active finding that carries a review timestamp.
    if (f.status === "active" && f.reviewed_at && !Number.isNaN(ts(f.reviewed_at))) {
      events.push({
        key: `${f.id}:acknowledged`,
        type: "acknowledged",
        at: f.reviewed_at,
        finding: f,
      });
    }

    // Snoozed (M61.2): derived from reviewed_at on snoozed findings.
    if (f.status === "snoozed" && f.reviewed_at && !Number.isNaN(ts(f.reviewed_at))) {
      events.push({
        key: `${f.id}:snoozed`,
        type: "snoozed",
        at: f.reviewed_at,
        finding: f,
      });
    }
  }

  events.sort((a, b) => ts(b.at) - ts(a.at)); // newest first
  return events;
}

/** Apply the event-type filter ("opened" includes "reopened"). */
export function filterEventsByType(
  events: TimelineEvent[],
  filter: EventTypeFilter,
): TimelineEvent[] {
  if (filter === "all") return events;
  if (filter === "opened") {
    return events.filter((e) => e.type === "opened" || e.type === "reopened");
  }
  return events.filter((e) => e.type === filter);
}

export interface TimelineDayGroup {
  /** YYYY-MM-DD key. */
  day: string;
  /** Human label: "Today" / "Yesterday" / locale date. */
  label: string;
  events: TimelineEvent[];
}

/** Group already-sorted (newest-first) events by calendar day. */
export function groupEventsByDay(events: TimelineEvent[]): TimelineDayGroup[] {
  const groups: TimelineDayGroup[] = [];
  const index = new Map<string, TimelineDayGroup>();

  const today = dayKey(Date.now());
  const yesterday = dayKey(Date.now() - 24 * 60 * 60 * 1000);

  for (const e of events) {
    const t = ts(e.at);
    const key = Number.isNaN(t) ? "unknown" : dayKey(t);
    let g = index.get(key);
    if (!g) {
      const label =
        key === "unknown"
          ? "Unknown date"
          : key === today
            ? "Today"
            : key === yesterday
              ? "Yesterday"
              : new Date(t).toLocaleDateString(undefined, {
                  weekday: "short",
                  month: "short",
                  day: "numeric",
                  year: "numeric",
                });
      g = { day: key, label, events: [] };
      index.set(key, g);
      groups.push(g);
    }
    g.events.push(e);
  }
  return groups;
}

function dayKey(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

export interface TimelineMetrics {
  openedThisWeek: number;
  activeNow: number;
  resolvedThisWeek: number;
  longestOpen: string; // human duration, or "—"
  criticalHigh: number;
}

/** Compute summary metrics from the loaded findings. */
export function deriveTimelineMetrics(findings: SecurityFinding[]): TimelineMetrics {
  const now = Date.now();
  let openedThisWeek = 0;
  let activeNow = 0;
  let resolvedThisWeek = 0;
  let criticalHigh = 0;
  let longestMs = 0;

  for (const f of findings) {
    const opened = ts(f.first_detected_at);
    if (!Number.isNaN(opened) && now - opened <= WEEK_MS) openedThisWeek += 1;

    if (f.status === "active") activeNow += 1;

    if (f.resolved_at) {
      const r = ts(f.resolved_at);
      if (!Number.isNaN(r) && now - r <= WEEK_MS) resolvedThisWeek += 1;
    }

    if (f.severity === "critical" || f.severity === "high") criticalHigh += 1;

    // Longest open exposure: active → now-opened; resolved → resolved-opened.
    if (!Number.isNaN(opened)) {
      const end =
        f.status === "resolved" && f.resolved_at ? ts(f.resolved_at) : now;
      if (!Number.isNaN(end)) longestMs = Math.max(longestMs, end - opened);
    }
  }

  return {
    openedThisWeek,
    activeNow,
    resolvedThisWeek,
    longestOpen: longestMs > 0 ? formatDurationMs(longestMs) : "—",
    criticalHigh,
  };
}
