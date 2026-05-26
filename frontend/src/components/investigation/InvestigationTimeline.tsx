"use client";

/**
 * InvestigationTimeline — M58.8
 *
 * Vertical event log derived from change metadata and current review state.
 * Shows the lifecycle of a change from detection through review actions.
 *
 * Events (in order):
 *   1. Detected       — change.created_at
 *   2. Classified     — risk level set (same timestamp as detected)
 *   3. Alert routing  — static (always present for high/critical)
 *   4. Review events  — from ChangeReviewResponse (if review exists)
 *   5. Current status — derived from review_status (shown as "now" marker)
 */

import type { ChangeDetail, ChangeReviewResponse, ReviewStatus } from "@/types";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";

// ── Colour palettes ──────────────────────────────────────────────────────────

const RISK_TEXT: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
  low:      "#6b9cf8",
  unknown:  "#565b6e",
};

const STATUS_STYLES: Record<ReviewStatus, { label: string; color: string }> = {
  needs_review: { label: "Needs review",  color: "#f5a623" },
  acknowledged: { label: "Acknowledged",  color: "#3ccf7e" },
  expected:     { label: "Marked expected", color: "#6b9cf8" },
  snoozed:      { label: "Snoozed",       color: "#8b5cf6" },
};

// ── Types ─────────────────────────────────────────────────────────────────────

interface TimelineEvent {
  id: string;
  label: string;
  sublabel?: string;
  ts?: string;         // ISO timestamp
  color: string;
  dotStyle?: "solid" | "ring" | "pulse";
  isNow?: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildEvents(
  change: ChangeDetail,
  review: ChangeReviewResponse | null,
): TimelineEvent[] {
  const riskKey = (change.risk_level ?? "unknown").toLowerCase();
  const riskColor = RISK_TEXT[riskKey] ?? RISK_TEXT.unknown;
  const isElevated = riskKey === "critical" || riskKey === "high";

  const events: TimelineEvent[] = [];

  // 1. Detected
  events.push({
    id: "detected",
    label: "Change detected",
    sublabel: change.record_identifier
      ? `on ${change.record_identifier}`
      : undefined,
    ts: change.created_at,
    color: riskColor,
    dotStyle: "solid",
  });

  // 2. Classified
  const riskLabel = riskKey.charAt(0).toUpperCase() + riskKey.slice(1);
  events.push({
    id: "classified",
    label: `Classified as ${riskLabel} risk`,
    ts: change.created_at,
    color: riskColor,
    dotStyle: "solid",
  });

  // 3. Alert routing active (only for high/critical)
  if (isElevated) {
    events.push({
      id: "alert-routing",
      label: "Alert routing active",
      sublabel: "Notifications sent to configured channels",
      color: "#4f80f7",
      dotStyle: "solid",
    });
  }

  // 4. Review event (if a review action has been taken)
  const hasReviewAction =
    review &&
    review.review_status !== "needs_review" &&
    review.reviewed_at;

  if (hasReviewAction && review) {
    const statusStyle =
      STATUS_STYLES[review.review_status as ReviewStatus] ??
      STATUS_STYLES.needs_review;

    let sublabel = review.review_note ?? undefined;
    if (review.review_status === "snoozed" && review.snooze_reason) {
      sublabel = review.snooze_reason;
    }
    if (review.review_status === "snoozed" && review.snoozed_until) {
      const snoozedUntilLabel = `until ${formatAbsoluteTime(review.snoozed_until)}`;
      sublabel = sublabel
        ? `${sublabel} · ${snoozedUntilLabel}`
        : snoozedUntilLabel;
    }

    events.push({
      id: "review-action",
      label: statusStyle.label,
      sublabel,
      ts: review.reviewed_at ?? undefined,
      color: statusStyle.color,
      dotStyle: "ring",
    });
  }

  // 5. Current status (the "now" marker)
  const currentStatus: ReviewStatus =
    (review?.review_status as ReviewStatus) ?? "needs_review";
  const nowStyle =
    STATUS_STYLES[currentStatus] ?? STATUS_STYLES.needs_review;

  events.push({
    id: "current",
    label: nowStyle.label,
    sublabel: "Current status",
    color: nowStyle.color,
    dotStyle: "pulse",
    isNow: true,
  });

  return events;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function TimelineDot({
  color,
  style: dotStyle = "solid",
}: {
  color: string;
  style?: "solid" | "ring" | "pulse";
}) {
  if (dotStyle === "pulse") {
    return (
      <div
        style={{
          width: "10px",
          height: "10px",
          borderRadius: "50%",
          backgroundColor: color,
          flexShrink: 0,
          boxShadow: `0 0 0 3px ${color}33`,
        }}
      />
    );
  }
  if (dotStyle === "ring") {
    return (
      <div
        style={{
          width: "10px",
          height: "10px",
          borderRadius: "50%",
          backgroundColor: "transparent",
          border: `2px solid ${color}`,
          flexShrink: 0,
        }}
      />
    );
  }
  return (
    <div
      style={{
        width: "8px",
        height: "8px",
        borderRadius: "50%",
        backgroundColor: color,
        flexShrink: 0,
      }}
    />
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface InvestigationTimelineProps {
  change: ChangeDetail;
  review: ChangeReviewResponse | null;
}

export default function InvestigationTimeline({
  change,
  review,
}: InvestigationTimelineProps) {
  const events = buildEvents(change, review);

  return (
    <section aria-labelledby="section-timeline">
      <h2
        id="section-timeline"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Investigation timeline
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "16px",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "0" }}>
          {events.map((ev, idx) => {
            const isLast = idx === events.length - 1;
            return (
              <div
                key={ev.id}
                style={{ display: "flex", gap: "12px", position: "relative" }}
              >
                {/* Dot + vertical connector */}
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    flexShrink: 0,
                    paddingTop: "3px",
                  }}
                >
                  <TimelineDot color={ev.color} style={ev.dotStyle} />
                  {!isLast && (
                    <div
                      style={{
                        width: "1px",
                        flex: 1,
                        minHeight: "20px",
                        background: "#2a2d38",
                        marginTop: "4px",
                        marginBottom: "4px",
                      }}
                    />
                  )}
                </div>

                {/* Event content */}
                <div style={{ paddingBottom: isLast ? "0" : "12px", flex: 1 }}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "baseline",
                      gap: "8px",
                      flexWrap: "wrap",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "13px",
                        fontWeight: ev.isNow ? 600 : 500,
                        color: ev.isNow ? ev.color : "#c8ccd8",
                      }}
                    >
                      {ev.label}
                    </span>
                    {ev.ts && (
                      <span
                        style={{ fontSize: "11px", color: "#565b6e" }}
                        title={formatAbsoluteTime(ev.ts)}
                      >
                        {formatRelativeTime(ev.ts)}
                      </span>
                    )}
                    {ev.isNow && (
                      <span
                        style={{
                          fontSize: "10px",
                          background: "#1e2030",
                          border: "1px solid #2a2d38",
                          borderRadius: "4px",
                          padding: "1px 6px",
                          color: "#565b6e",
                          letterSpacing: "0.04em",
                          textTransform: "uppercase",
                        }}
                      >
                        now
                      </span>
                    )}
                  </div>
                  {ev.sublabel && (
                    <p
                      style={{
                        fontSize: "12px",
                        color: "#565b6e",
                        margin: "2px 0 0",
                        lineHeight: 1.4,
                      }}
                    >
                      {ev.sublabel}
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
