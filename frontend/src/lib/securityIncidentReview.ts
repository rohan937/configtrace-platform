/**
 * securityIncidentReview.ts — compose an investigation view over a time window (M61.5).
 *
 * Incident Review is a READ-ONLY investigation workspace: it does not detect
 * incidents or breaches. It correlates security exposure findings, drift
 * changes, and affected assets that overlap a user-selected window so a team
 * can reason about "what security-relevant configuration changed around here".
 *
 * Everything here is derived client-side from existing APIs
 * (GET /security/findings, GET /changes) and the existing securityTimeline /
 * securityAssets helpers. No backend changes, no AI, no invented data.
 */

import type { ChangeListItem, SecurityFinding } from "@/types";
import { buildTimelineEvents, EVENT_LABEL } from "@/lib/securityTimeline";
import { groupFindingsByAsset, type AffectedAsset } from "@/lib/securityAssets";
import { SEVERITY_RANK } from "@/components/security/findingDisplay";

export interface TimeWindow {
  /** epoch ms, inclusive start */
  start: number;
  /** epoch ms, inclusive end */
  end: number;
}

function ts(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

function within(t: number | null, w: TimeWindow): boolean {
  return t !== null && t >= w.start && t <= w.end;
}

/**
 * Whether a finding overlaps the window: any lifecycle stamp falls inside it,
 * OR the finding is still active and its open..lastSeen interval intersects.
 */
export function findingInWindow(f: SecurityFinding, w: TimeWindow): boolean {
  const opened = ts(f.first_detected_at);
  const lastSeen = ts(f.last_seen_at);
  if (within(opened, w)) return true;
  if (within(lastSeen, w)) return true;
  if (within(ts(f.resolved_at), w)) return true;
  if (within(ts(f.reviewed_at), w)) return true;
  // Active finding whose lifetime spans the window.
  if (f.status === "active" && opened !== null) {
    const end = lastSeen ?? Date.now();
    if (opened <= w.end && end >= w.start) return true;
  }
  return false;
}

// ── Merged incident timeline ──────────────────────────────────────────────────

export type IncidentEventKind = "exposure" | "drift";

export interface IncidentEvent {
  key: string;
  kind: IncidentEventKind;
  /** machine type, e.g. "opened" | "resolved" | "accepted_risk" | "drift_change" */
  type: string;
  label: string;
  at: string;
  atMs: number;
  severity: string | null;
  provider: string;
  title: string;
  description: string | null;
  href: string;
}

// Exposure lifecycle event types we surface in Incident Review. "still_active"
// is intentionally excluded — it is noise for an incident investigation.
const EXPOSURE_EVENT_TYPES = new Set([
  "opened",
  "reopened",
  "resolved",
  "accepted_risk",
  "acknowledged",
  "snoozed",
]);

/** Build exposure-side incident events from findings, filtered to the window. */
export function exposureEvents(
  findings: SecurityFinding[],
  w: TimeWindow,
): IncidentEvent[] {
  const out: IncidentEvent[] = [];
  for (const ev of buildTimelineEvents(findings)) {
    if (!EXPOSURE_EVENT_TYPES.has(ev.type)) continue;
    const atMs = ts(ev.at);
    if (atMs === null || atMs < w.start || atMs > w.end) continue;
    const f = ev.finding;
    out.push({
      key: `exp:${ev.key}`,
      kind: "exposure",
      type: ev.type,
      label: EVENT_LABEL[ev.type] ?? ev.type,
      at: ev.at,
      atMs,
      severity: f.severity,
      provider: f.provider,
      title: f.title,
      description: f.description,
      href: `/security/exposures/${f.id}`,
    });
  }
  return out;
}

/** Build drift-side incident events from changes (already time-filtered by API). */
export function driftEvents(
  changes: ChangeListItem[],
  providerByIntegration: Record<string, string>,
  w: TimeWindow,
): IncidentEvent[] {
  const out: IncidentEvent[] = [];
  for (const c of changes) {
    const atMs = ts(c.created_at);
    if (atMs === null || atMs < w.start || atMs > w.end) continue;
    out.push({
      key: `drift:${c.id}`,
      kind: "drift",
      type: "drift_change",
      label: "Configuration change",
      at: c.created_at,
      atMs,
      severity: c.risk_level ?? null,
      provider: providerByIntegration[c.integration_id] ?? "unknown",
      title: c.risk_reason || c.record_identifier || "Configuration change",
      description: c.field_path ? `${c.change_type} · ${c.field_path}` : c.change_type,
      href: `/changes/${c.id}`,
    });
  }
  return out;
}

/** Merge exposure + drift events, newest first (deterministic). */
export function mergeIncidentEvents(
  exposure: IncidentEvent[],
  drift: IncidentEvent[],
): IncidentEvent[] {
  return [...exposure, ...drift].sort((a, b) => {
    if (b.atMs !== a.atMs) return b.atMs - a.atMs;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    return a.key < b.key ? -1 : 1;
  });
}

// ── Summary ───────────────────────────────────────────────────────────────────

export interface IncidentSummary {
  openedInWindow: number;
  criticalHighInWindow: number;
  resolvedInWindow: number;
  driftInWindow: number;
  affectedAssets: number;
}

export function buildSummary(
  windowFindings: SecurityFinding[],
  driftCount: number,
  assets: AffectedAsset[],
  w: TimeWindow,
): IncidentSummary {
  let opened = 0;
  let critHigh = 0;
  let resolved = 0;
  for (const f of windowFindings) {
    if (within(ts(f.first_detected_at), w)) {
      opened += 1;
      if (f.severity === "critical" || f.severity === "high") critHigh += 1;
    }
    if (f.status === "resolved" && within(ts(f.resolved_at), w)) resolved += 1;
  }
  return {
    openedInWindow: opened,
    criticalHighInWindow: critHigh,
    resolvedInWindow: resolved,
    driftInWindow: driftCount,
    affectedAssets: assets.length,
  };
}

/** Group the in-window findings into affected assets (reuses M61.4 logic). */
export function assetsInWindow(windowFindings: SecurityFinding[]): AffectedAsset[] {
  return groupFindingsByAsset(windowFindings);
}

// ── Suggested investigation checklist (deterministic, data-driven) ─────────────

export interface ChecklistItem {
  id: string;
  text: string;
  /** True when the underlying data makes this check relevant right now. */
  relevant: boolean;
}

/**
 * A static, deterministic checklist. Every item is phrased as a suggested check
 * — never an AI claim and never "root cause found". Items flagged `relevant`
 * are backed by data actually present in the window.
 */
export function buildChecklist(opts: {
  windowFindings: SecurityFinding[];
  driftCount: number;
  assets: AffectedAsset[];
  window: TimeWindow;
}): ChecklistItem[] {
  const { windowFindings, driftCount, window: w } = opts;
  const criticalHighOpened = windowFindings.filter(
    (f) =>
      (f.severity === "critical" || f.severity === "high") &&
      within(ts(f.first_detected_at), w),
  ).length;
  const accepted = windowFindings.filter((f) => f.status === "accepted_risk").length;
  const snoozed = windowFindings.filter((f) => f.status === "snoozed").length;
  const stillActive = windowFindings.filter((f) => f.status === "active").length;

  return [
    {
      id: "critical_high",
      text:
        criticalHighOpened > 0
          ? `Review the ${criticalHighOpened} critical/high exposure${criticalHighOpened === 1 ? "" : "s"} opened during this window.`
          : "Review critical/high exposures opened during the incident window.",
      relevant: criticalHighOpened > 0,
    },
    {
      id: "drift",
      text:
        driftCount > 0
          ? `Check the ${driftCount} drift change${driftCount === 1 ? "" : "s"} in this window for configuration changes near the incident start.`
          : "Check linked drift events for configuration changes near the incident start.",
      relevant: driftCount > 0,
    },
    {
      id: "accepted_snoozed",
      text:
        accepted + snoozed > 0
          ? `Confirm whether the ${accepted} accepted and ${snoozed} snoozed finding(s) overlapping this window are still appropriate.`
          : "Confirm whether any accepted or snoozed findings overlap the window.",
      relevant: accepted + snoozed > 0,
    },
    {
      id: "remediation",
      text:
        stillActive > 0
          ? `Verify remediation for the ${stillActive} exposure${stillActive === 1 ? "" : "s"} that remain active.`
          : "Verify remediation for exposures that remain active.",
      relevant: stillActive > 0,
    },
    {
      id: "notifications",
      text: "Check whether Slack or browser notifications were delivered if relevant.",
      relevant: false,
    },
    {
      id: "notes",
      text: "Add review notes to findings that need owner handoff.",
      relevant: false,
    },
  ];
}

// ── Window helpers ────────────────────────────────────────────────────────────

/** Format a Date as a value for <input type="datetime-local"> (local time). */
export function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Parse a datetime-local string to epoch ms, or null. */
export function fromLocalInput(v: string): number | null {
  if (!v) return null;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? null : t;
}

export const PRESETS: { label: string; hours: number }[] = [
  { label: "Last 1 hour", hours: 1 },
  { label: "Last 6 hours", hours: 6 },
  { label: "Last 24 hours", hours: 24 },
  { label: "Last 7 days", hours: 24 * 7 },
];

/** Highest severity helper for sorting findings/assets consistently. */
export function severityRank(sev: string): number {
  return SEVERITY_RANK[sev as keyof typeof SEVERITY_RANK] ?? 99;
}
