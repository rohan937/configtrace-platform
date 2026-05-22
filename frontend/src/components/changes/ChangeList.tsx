import type { ChangeListItem } from "@/types";
import ChangeRow from "./ChangeRow";
import EmptyState from "@/components/common/EmptyState";

interface ChangeListProps {
  changes: ChangeListItem[];
  emptyTitle?: string;
  emptyDescription?: string;
  /** @deprecated Use emptyTitle instead */
  emptyMessage?: string;
}

export default function ChangeList({
  changes,
  emptyTitle,
  emptyDescription,
  emptyMessage,
}: ChangeListProps) {
  if (changes.length === 0) {
    return (
      <EmptyState
        title={emptyTitle ?? emptyMessage ?? "No changes found."}
        description={emptyDescription}
      />
    );
  }

  return (
    <div
      style={{ border: "1px solid #2a2d38", borderRadius: "6px", overflow: "hidden" }}
    >
      {/* Column header — must match ChangeRow column widths exactly */}
      <div
        className="flex items-center gap-3 px-4 py-2"
        style={{
          borderBottom: "1px solid #2a2d38",
          background: "#1a1d26",
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        <span style={{ width: "96px" }}>When</span>
        <span className="flex-1">Record</span>
        <span style={{ width: "72px", textAlign: "right" }}>Type</span>
        <span style={{ width: "72px", textAlign: "right" }}>Field</span>
        <span style={{ width: "72px", textAlign: "right" }}>Risk</span>
      </div>

      {changes.map((change) => (
        <ChangeRow key={change.id} change={change} />
      ))}
    </div>
  );
}
