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
      role="feed"
      aria-label="Configuration change events"
      style={{ border: "1px solid #2a2d38", borderRadius: "6px", overflow: "hidden" }}
    >
      {changes.map((change) => (
        <ChangeRow key={change.id} change={change} />
      ))}
    </div>
  );
}
