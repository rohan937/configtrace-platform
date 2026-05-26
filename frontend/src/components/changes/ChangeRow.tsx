import Link from "next/link";
import type { ChangeListItem, ReviewStatus } from "@/types";
import { formatRelativeTime, formatAbsoluteTime, changeTypeLabel } from "@/lib/utils";
import { getTimelineEventData } from "@/lib/timeline";

interface ChangeRowProps {
  change: ChangeListItem;
}

// ── Risk-level colours ────────────────────────────────────────────────────────

const RISK_DOT_COLOR: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
  low:      "#6b9cf8",
  unknown:  "#565b6e",
};

const RISK_BADGE_STYLE: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "rgba(232,64,64,0.15)",  text: "#e84040", border: "rgba(232,64,64,0.35)" },
  high:     { bg: "rgba(245,99,42,0.15)",  text: "#f5632a", border: "rgba(245,99,42,0.35)" },
  medium:   { bg: "rgba(245,166,35,0.15)", text: "#f5a623", border: "rgba(245,166,35,0.35)" },
  low:      { bg: "rgba(107,156,248,0.12)", text: "#6b9cf8", border: "rgba(107,156,248,0.35)" },
  unknown:  { bg: "rgba(139,144,160,0.10)", text: "#8b90a0", border: "#2a2d38" },
};

// An inset left stripe for critical/high rows — strong at-a-glance signal.
const RISK_LEFT_SHADOW: Partial<Record<string, string>> = {
  critical: "inset 3px 0 0 #e84040",
  high:     "inset 3px 0 0 #f5632a",
};

// ── Inline risk badge ─────────────────────────────────────────────────────────

function InlineRiskBadge({ level }: { level: string }) {
  const key = (level ?? "unknown").toLowerCase();
  const s = RISK_BADGE_STYLE[key] ?? RISK_BADGE_STYLE.unknown;
  return (
    <span
      aria-label={`Risk level: ${key}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        background: s.bg,
        color: s.text,
        border: `1px solid ${s.border}`,
        borderRadius: "4px",
        padding: "1px 7px",
        fontSize: "10px",
        fontWeight: 600,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      {key}
    </span>
  );
}

// ── Change-type chip ──────────────────────────────────────────────────────────

function ChangeTypeChip({ changeType }: { changeType: string }) {
  const label = changeTypeLabel(changeType);
  const color =
    changeType === "added"   ? "#3ccf7e" :
    changeType === "removed" ? "#e84040" :
    "#8b90a0";
  return (
    <span style={{ color, fontSize: "11px" }}>
      {label}
    </span>
  );
}

// ── Review status badge (M57.2) ───────────────────────────────────────────────

const REVIEW_BADGE: Record<ReviewStatus, { label: string; color: string }> = {
  needs_review:  { label: "Needs Review", color: "#f5a623" },
  acknowledged:  { label: "Acknowledged", color: "#3ccf7e" },
  expected:      { label: "Expected",     color: "#4f80f7" },
  snoozed:       { label: "Snoozed",      color: "#8b5cf6" },
};

function ReviewStatusBadge({ status }: { status: ReviewStatus }) {
  const { label, color } = REVIEW_BADGE[status] ?? REVIEW_BADGE.needs_review;
  if (status === "needs_review") return null; // don't clutter unreviewed rows
  return (
    <span
      aria-label={`Review status: ${label}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        color,
        fontSize: "10px",
        fontWeight: 500,
        whiteSpace: "nowrap",
        flexShrink: 0,
        gap: "3px",
      }}
    >
      <span style={{ fontSize: "9px" }}>●</span>
      {label}
    </span>
  );
}

// ── Row ───────────────────────────────────────────────────────────────────────

/**
 * Security event feed row.
 *
 * Layout:
 *   [risk dot]  [title]                          [risk badge]
 *               [description — optional]
 *               [time · provider · category · type]
 *
 * Critical/High rows show a 3px coloured left edge for rapid scanning.
 */
export default function ChangeRow({ change }: ChangeRowProps) {
  const { title, description, providerLabel, category } = getTimelineEventData(change);
  const riskKey = (change.risk_level ?? "unknown").toLowerCase();
  const dotColor = RISK_DOT_COLOR[riskKey] ?? RISK_DOT_COLOR.unknown;
  const leftShadow = RISK_LEFT_SHADOW[riskKey] ?? "none";

  return (
    <Link
      href={`/changes/${change.id}`}
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "10px 16px",
        borderBottom: "1px solid #2a2d38",
        textDecoration: "none",
        cursor: "pointer",
        boxShadow: leftShadow,
        transition: "background 0.1s",
      }}
      className="hover:bg-surface3"
    >
      {/* Risk indicator dot */}
      <span
        aria-hidden="true"
        style={{
          flexShrink: 0,
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: dotColor,
          marginTop: "5px",
        }}
      />

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>

        {/* Line 1: title + risk badge */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "12px",
          }}
        >
          <span
            style={{
              fontSize: "13px",
              color: "#e8eaf0",
              fontWeight: 500,
              lineHeight: 1.4,
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={title}
          >
            {title}
          </span>
          <InlineRiskBadge level={riskKey} />
        </div>

        {/* Line 2: description (optional) */}
        {description && (
          <p
            style={{
              margin: "3px 0 0",
              fontSize: "12px",
              color: "#8b90a0",
              lineHeight: 1.5,
              overflow: "hidden",
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient: "vertical",
            }}
          >
            {description}
          </p>
        )}

        {/* Line 3: metadata */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "4px",
            marginTop: description ? "5px" : "4px",
            fontSize: "11px",
            color: "#565b6e",
          }}
        >
          <span title={formatAbsoluteTime(change.created_at)}>
            {formatRelativeTime(change.created_at)}
          </span>
          <span aria-hidden="true">·</span>
          <span>{providerLabel}</span>
          {category && (
            <>
              <span aria-hidden="true">·</span>
              <span>{category}</span>
            </>
          )}
          <span aria-hidden="true">·</span>
          <ChangeTypeChip changeType={change.change_type} />
          {/* M57.2: review status (only non-needs_review statuses) */}
          {change.review && change.review.review_status !== "needs_review" && (
            <>
              <span aria-hidden="true">·</span>
              <ReviewStatusBadge status={change.review.review_status} />
            </>
          )}
        </div>
      </div>
    </Link>
  );
}
