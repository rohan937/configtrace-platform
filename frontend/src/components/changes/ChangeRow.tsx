import Link from "next/link";
import type { ChangeListItem } from "@/types";
import RiskBadge from "@/components/common/RiskBadge";
import {
  formatRelativeTime,
  formatAbsoluteTime,
  changeTypeLabel,
  formatValue,
  formatValueChange,
} from "@/lib/utils";

interface ChangeRowProps {
  change: ChangeListItem;
}

/**
 * Returns the secondary value line text for a change row.
 *
 * - added:    "→ {content of new record}"
 * - removed:  "{content of old record} → removed"
 * - modified: "{prev} → {new}"   (field-level values)
 */
function valueDisplay(change: ChangeListItem): string | null {
  switch (change.change_type) {
    case "added": {
      const v = formatValue(change.new_value);
      return v !== "—" ? `→ ${v}` : null;
    }
    case "removed": {
      const v = formatValue(change.prev_value);
      return v !== "—" ? `${v} → removed` : null;
    }
    case "modified": {
      if (
        change.prev_value === undefined &&
        change.new_value === undefined
      )
        return null;
      return formatValueChange(change.prev_value, change.new_value);
    }
    default:
      return null;
  }
}

/**
 * A single flat row in a change list.
 *
 * Layout (fixed-width columns for alignment):
 *   [timestamp 96px] [record flex-1] [type 72px] [field 72px] [risk 72px]
 *
 * Secondary line (when present):
 *   [value diff in monospace] · [risk_reason in italic]
 */
export default function ChangeRow({ change }: ChangeRowProps) {
  const valLine = valueDisplay(change);
  const showSecondary = Boolean(valLine || change.risk_reason);

  return (
    <Link
      href={`/changes/${change.id}`}
      className="flex flex-col px-4 py-2.5 hover:bg-surface3"
      style={{
        borderBottom: "1px solid #2a2d38",
        gap: "3px",
        textDecoration: "none",
        display: "flex",
        cursor: "pointer",
      }}
    >
      {/* ── Main row ───────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 min-w-0">

        {/* Timestamp — compact relative, exact on hover */}
        <span
          className="shrink-0 tabular-nums"
          title={formatAbsoluteTime(change.created_at)}
          style={{ fontSize: "12px", color: "#8b90a0", width: "96px" }}
        >
          {formatRelativeTime(change.created_at)}
        </span>

        {/* Record identifier — most prominent, monospace */}
        <span
          className="font-mono truncate flex-1"
          style={{ fontSize: "13px", color: "#e8eaf0" }}
          title={change.record_identifier}
        >
          {change.record_identifier}
        </span>

        {/* Change type — uppercase label */}
        <span
          className="shrink-0 uppercase tracking-wider"
          style={{
            fontSize: "11px",
            color: "#8b90a0",
            width: "72px",
            textAlign: "right",
          }}
        >
          {changeTypeLabel(change.change_type)}
        </span>

        {/* Field path — always present column, "—" when not applicable */}
        <span
          className="shrink-0 font-mono"
          style={{
            fontSize: "11px",
            color: change.field_path ? "#8b90a0" : "#3a3d4a",
            width: "72px",
            textAlign: "right",
          }}
        >
          {change.field_path ?? "—"}
        </span>

        {/* Risk badge */}
        <div className="shrink-0 flex justify-end" style={{ width: "72px" }}>
          <RiskBadge level={change.risk_level} />
        </div>
      </div>

      {/* ── Secondary line ─────────────────────────────────────────── */}
      {showSecondary && (
        <div
          className="flex items-baseline gap-3 min-w-0"
          style={{ paddingLeft: "108px" }}
        >
          {valLine && (
            <span
              className="font-mono truncate"
              style={{ fontSize: "12px", color: "#8b90a0" }}
            >
              {valLine}
            </span>
          )}
          {change.risk_reason && (
            <span
              className="truncate"
              style={{ fontSize: "12px", color: "#565b6e", fontStyle: "italic" }}
            >
              {change.risk_reason}
            </span>
          )}
        </div>
      )}
    </Link>
  );
}
