import type { ChangeListItem } from "@/types";
import RiskBadge from "@/components/common/RiskBadge";
import { formatRelativeTime, changeTypeLabel, formatValueChange } from "@/lib/utils";

interface ChangeRowProps {
  change: ChangeListItem;
}

/**
 * A single flat row in a change list.
 * Layout: timestamp · record_identifier · change_type · field_path · risk badge
 */
export default function ChangeRow({ change }: ChangeRowProps) {
  const hasValueDiff =
    change.change_type === "modified" &&
    (change.prev_value !== undefined || change.new_value !== undefined);

  return (
    <div
      className="flex flex-col gap-1 px-4 py-3 hover:bg-surface3 cursor-default"
      style={{ borderBottom: "1px solid #2a2d38" }}
    >
      {/* Main row */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Timestamp */}
        <span
          className="shrink-0 tabular-nums"
          style={{ fontSize: "12px", color: "#8b90a0", width: "110px" }}
          title={change.created_at}
        >
          {formatRelativeTime(change.created_at)}
        </span>

        {/* Record identifier */}
        <span
          className="font-mono truncate flex-1"
          style={{ fontSize: "13px", color: "#e8eaf0" }}
        >
          {change.record_identifier}
        </span>

        {/* Change type label */}
        <span
          className="shrink-0 uppercase tracking-wider"
          style={{
            fontSize: "11px",
            color: "#8b90a0",
            width: "64px",
            textAlign: "right",
          }}
        >
          {changeTypeLabel(change.change_type)}
        </span>

        {/* Field path */}
        {change.field_path && (
          <span
            className="shrink-0 font-mono"
            style={{ fontSize: "12px", color: "#8b90a0", width: "80px", textAlign: "right" }}
          >
            {change.field_path}
          </span>
        )}

        {/* Risk badge */}
        <div className="shrink-0">
          <RiskBadge level={change.risk_level} />
        </div>
      </div>

      {/* Secondary: value diff + risk reason */}
      {(hasValueDiff || change.risk_reason) && (
        <div
          className="flex items-baseline gap-4 pl-[122px]"
          style={{ fontSize: "12px", color: "#8b90a0" }}
        >
          {hasValueDiff && (
            <span className="font-mono truncate">
              {formatValueChange(change.prev_value, change.new_value)}
            </span>
          )}
          {change.risk_reason && (
            <span className="truncate italic">{change.risk_reason}</span>
          )}
        </div>
      )}
    </div>
  );
}
