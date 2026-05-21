import type { ChangeListItem } from "@/types";
import ChangeRow from "./ChangeRow";
import EmptyState from "@/components/common/EmptyState";

interface ChangeListProps {
  changes: ChangeListItem[];
  emptyMessage?: string;
}

export default function ChangeList({
  changes,
  emptyMessage = "No changes found.",
}: ChangeListProps) {
  if (changes.length === 0) {
    return <EmptyState title={emptyMessage} />;
  }

  return (
    <div
      style={{ border: "1px solid #2a2d38", borderRadius: "6px", overflow: "hidden" }}
    >
      {/* Column header */}
      <div
        className="flex items-center gap-3 px-4 py-2"
        style={{
          borderBottom: "1px solid #2a2d38",
          background: "#1a1d26",
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        <span style={{ width: "110px" }}>When</span>
        <span className="flex-1">Record</span>
        <span style={{ width: "64px", textAlign: "right" }}>Type</span>
        <span style={{ width: "80px", textAlign: "right" }}>Field</span>
        <span style={{ width: "72px", textAlign: "right" }}>Risk</span>
      </div>

      {changes.map((change) => (
        <ChangeRow key={change.id} change={change} />
      ))}
    </div>
  );
}
