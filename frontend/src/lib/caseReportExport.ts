/**
 * caseReportExport.ts — format a Case Evidence Report payload (M66.9).
 *
 * Pure, deterministic formatting of the backend's metadata-only report
 * (GET /security/cases/{id}/report) into Markdown / JSON for download, plus an
 * executive-summary string for copy.
 *
 * CLAIM DISCIPLINE: this only renders the server-provided, already-safe payload.
 * It never adds claims; the report itself is evidence for review and never
 * asserts breach/attacker/compromise.
 */

import type { SecurityCaseReport } from "@/types";

export function fmtUtc(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toISOString().replace("T", " ").replace(".000Z", " UTC").replace("Z", " UTC");
}

function mdCell(v: string | null | undefined): string {
  if (v === null || v === undefined || v === "") return "—";
  return String(v).replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function statusLabel(s: string): string {
  return s.replace(/_/g, " ");
}

export function caseReportToMarkdown(r: SecurityCaseReport): string {
  const c = r.case;
  const L: string[] = [];
  L.push(`# ${r.title}`);
  L.push("");
  L.push(`_Generated ${fmtUtc(r.generated_at)} · metadata-only evidence_`);
  L.push("");

  L.push("## 1. Executive summary");
  L.push("");
  L.push(r.executive_summary);
  L.push("");

  L.push("## 2. Case overview");
  L.push("");
  L.push(`- **Title:** ${mdCell(c.title)}`);
  L.push(`- **Status:** ${statusLabel(c.status)}`);
  L.push(`- **Severity:** ${c.severity}`);
  L.push(`- **Confidence:** ${c.confidence}`);
  L.push(`- **Provider:** ${mdCell(c.provider)}`);
  if (c.confirmed_at) L.push(`- **Confirmed by user:** ${fmtUtc(c.confirmed_at)}`);
  if (c.dismissed_at) L.push(`- **Dismissed:** ${fmtUtc(c.dismissed_at)}`);
  if (c.resolved_at) L.push(`- **Resolved:** ${fmtUtc(c.resolved_at)}`);
  L.push(`- **Created:** ${fmtUtc(c.created_at)}`);
  L.push(`- **Updated:** ${fmtUtc(c.updated_at)}`);
  if (c.summary) {
    L.push("");
    L.push(c.summary);
  }
  L.push("");

  L.push("## 3. Claim discipline");
  L.push("");
  L.push(r.claim_note);
  L.push("");

  L.push("## 4. Linked Incident Signals");
  L.push("");
  if (r.signals.length === 0) {
    L.push("_None linked._");
  } else {
    L.push("| Title | Type | Severity | Confidence | Status | Evidence | First seen |");
    L.push("|---|---|---|---|---|---|---|");
    for (const s of r.signals) {
      L.push(`| ${mdCell(s.title)} | ${mdCell(s.signal_type)} | ${s.severity} | ${s.confidence} | ${statusLabel(s.status)} | ${s.evidence_level} | ${fmtUtc(s.first_seen_at)} |`);
    }
  }
  L.push("");

  L.push("## 5. Linked Configuration Risks");
  L.push("");
  if (r.risks.length === 0) {
    L.push("_None linked._");
  } else {
    L.push("| Title | Rule | Severity | Status | Confidence | First detected |");
    L.push("|---|---|---|---|---|---|");
    for (const f of r.risks) {
      L.push(`| ${mdCell(f.title)} | ${mdCell(f.rule)} | ${f.severity} | ${statusLabel(f.status)} | ${f.confidence} | ${fmtUtc(f.first_detected_at)} |`);
    }
  }
  L.push("");

  L.push("## 6. Linked Activity Events");
  L.push("");
  if (r.activity_events.length === 0) {
    L.push("_None linked._");
  } else {
    L.push("| Event type | Actor | Resource | Occurred | Source IP (hashed) | Provider event id |");
    L.push("|---|---|---|---|---|---|");
    for (const e of r.activity_events) {
      L.push(`| ${mdCell(e.event_type)} | ${mdCell(e.actor_id)} | ${mdCell(e.resource_id)} | ${fmtUtc(e.occurred_at)} | ${mdCell(e.source_ip_hash)} | ${mdCell(e.provider_event_id)} |`);
    }
  }
  L.push("");

  L.push("## 7. Linked Correlations");
  L.push("");
  if (r.correlations.length === 0) {
    L.push("_None linked._");
  } else {
    L.push("| Title | Type | Severity | Confidence | Status | First seen |");
    L.push("|---|---|---|---|---|---|");
    for (const co of r.correlations) {
      L.push(`| ${mdCell(co.title)} | ${mdCell(co.correlation_type)} | ${co.severity} | ${co.confidence} | ${statusLabel(co.status)} | ${fmtUtc(co.first_seen_at)} |`);
    }
  }
  L.push("");

  L.push("## 8. Evidence timeline");
  L.push("");
  if (r.timeline.length === 0) {
    L.push("_No timeline events._");
  } else {
    for (const t of r.timeline) {
      L.push(`- ${fmtUtc(t.at)} — ${t.label}`);
    }
  }
  L.push("");

  // M69.7A — normalized cross-provider chronological evidence timeline.
  const et = r.evidence_timeline;
  L.push("## 9. Chronological evidence timeline");
  L.push("");
  if (!et || et.timeline_items.length === 0) {
    L.push("_No linked evidence to place on a timeline._");
  } else {
    L.push(
      "Shows linked findings, activity, signals, and correlations for review. " +
        "This does not confirm compromise or unauthorized access.",
    );
    L.push("");
    L.push("| When | Type | Provider | Severity | Summary |");
    L.push("|---|---|---|---|---|");
    for (const it of et.timeline_items) {
      L.push(
        `| ${fmtUtc(it.timestamp)} | ${mdCell(it.item_type)} | ${mdCell(it.provider)} | ${mdCell(it.severity)} | ${mdCell(it.summary)} |`,
      );
    }
  }
  L.push("");

  L.push("## 10. Review checklist");
  L.push("");
  for (const item of r.review_checklist) {
    L.push(`- [ ] ${item}`);
  }
  L.push("");

  L.push("## 11. Metadata-only limitations");
  L.push("");
  L.push(r.limitations);
  L.push("");

  return L.join("\n");
}

export function caseReportToJSON(r: SecurityCaseReport): string {
  return JSON.stringify(r, null, 2);
}

export function caseReportExecutiveSummary(r: SecurityCaseReport): string {
  return `${r.title}\n\n${r.executive_summary}\n\n${r.claim_note}`;
}

export function caseReportFileStem(r: SecurityCaseReport): string {
  const id8 = r.case.id.slice(0, 8);
  const day = (r.generated_at || "").slice(0, 10) || "report";
  return `configtrace-case-report-${id8}-${day}`;
}

/** Trigger a client-side download of text content. */
export function downloadText(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
