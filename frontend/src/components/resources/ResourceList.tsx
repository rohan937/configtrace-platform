import type { ResourceListItem } from "@/types";
import EmptyState from "@/components/common/EmptyState";
import { formatRelativeTime } from "@/lib/utils";

interface ResourceListProps {
  resources: ResourceListItem[];
}

export default function ResourceList({ resources }: ResourceListProps) {
  if (resources.length === 0) {
    return (
      <EmptyState
        title="No resources yet."
        description="Run a sync to discover resources from your integrations."
      />
    );
  }

  return (
    <div
      style={{ border: "1px solid #2a2d38", borderRadius: "6px", overflow: "hidden" }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-4 px-4 py-2"
        style={{
          borderBottom: "1px solid #2a2d38",
          background: "#1a1d26",
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        <span className="flex-1">Resource</span>
        <span style={{ width: "120px" }}>Type</span>
        <span style={{ width: "140px" }}>Last Snapshot</span>
        <span style={{ width: "60px", textAlign: "right" }}>Status</span>
      </div>

      {resources.map((resource) => (
        <div
          key={resource.id}
          className="flex items-center gap-4 px-4 py-3 hover:bg-surface3 cursor-default"
          style={{ borderBottom: "1px solid #2a2d38" }}
        >
          {/* Name + provider ID */}
          <div className="flex flex-col gap-0.5 flex-1 min-w-0">
            <span
              className="font-mono truncate"
              style={{ fontSize: "13px", color: "#e8eaf0" }}
            >
              {resource.display_name ?? resource.provider_resource_id}
            </span>
            {resource.display_name && (
              <span
                className="font-mono truncate"
                style={{ fontSize: "11px", color: "#8b90a0" }}
              >
                {resource.provider_resource_id}
              </span>
            )}
          </div>

          {/* Type */}
          <span
            className="shrink-0 uppercase tracking-wider"
            style={{ fontSize: "11px", color: "#8b90a0", width: "120px" }}
          >
            {resource.provider_resource_type}
          </span>

          {/* Last snapshot */}
          <span
            className="shrink-0 tabular-nums"
            style={{ fontSize: "12px", color: "#8b90a0", width: "140px" }}
          >
            {resource.last_snapshot_at
              ? formatRelativeTime(resource.last_snapshot_at)
              : "—"}
          </span>

          {/* Active status */}
          <span
            className="shrink-0 text-right"
            style={{
              fontSize: "12px",
              width: "60px",
              color: resource.is_active ? "#4ade80" : "#8b90a0",
            }}
          >
            {resource.is_active ? "Active" : "Inactive"}
          </span>
        </div>
      ))}
    </div>
  );
}
