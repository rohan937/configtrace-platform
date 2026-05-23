import Link from "next/link";
import type { ResourceListItem } from "@/types";
import EmptyState from "@/components/common/EmptyState";
import { formatRelativeTime, formatResourceType } from "@/lib/utils";

interface ResourceListProps {
  resources: ResourceListItem[];
}

// ── Provider badge ────────────────────────────────────────────────────────────

function ProviderBadge({ resourceType }: { resourceType: string }) {
  const type = resourceType.toLowerCase();
  let label = "";
  let color = "#8b90a0";
  let bg = "rgba(139,144,160,0.10)";
  let border = "#2a2d38";

  if (type === "cloudflare_dns_zone") {
    label = "Cloudflare";
    color = "#f48120";
    bg = "rgba(244,129,32,0.10)";
    border = "rgba(244,129,32,0.25)";
  } else if (type === "github_repo") {
    label = "GitHub";
    color = "#b0b5c4";
    bg = "rgba(176,181,196,0.08)";
    border = "#2a2d38";
  } else if (type === "vercel_project") {
    label = "Vercel";
    color = "#b0b5c4";
    bg = "rgba(176,181,196,0.08)";
    border = "#2a2d38";
  } else if (type === "stripe_account") {
    label = "Stripe";
    color = "#8b90a0";
    bg = "rgba(99,91,255,0.10)";
    border = "rgba(99,91,255,0.25)";
  }

  if (!label) return null;

  return (
    <span
      style={{
        display: "inline-block",
        fontSize: "10px",
        fontWeight: 500,
        letterSpacing: "0.04em",
        padding: "1px 6px",
        borderRadius: "4px",
        background: bg,
        color,
        border: `1px solid ${border}`,
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      {label}
    </span>
  );
}

// ── Resource row ──────────────────────────────────────────────────────────────

function ResourceRow({ resource }: { resource: ResourceListItem }) {
  return (
    <div
      className="flex items-center gap-4 px-4 py-3 hover:bg-surface3"
      style={{ borderBottom: "1px solid #2a2d38" }}
    >
      {/* Name + provider ID + integration link */}
      <div className="flex flex-col gap-0.5 flex-1 min-w-0">
        <Link
          href={`/resources/${resource.id}`}
          className="font-mono truncate"
          style={{ fontSize: "13px", color: "#e8eaf0", textDecoration: "none" }}
          onMouseOver={(e) => { (e.currentTarget as HTMLAnchorElement).style.color = "#b0b5c4"; }}
          onMouseOut={(e) => { (e.currentTarget as HTMLAnchorElement).style.color = "#e8eaf0"; }}
        >
          {resource.display_name ?? resource.provider_resource_id}
        </Link>

        <div className="flex items-center gap-2">
          {resource.display_name && (
            <span
              className="font-mono truncate"
              style={{ fontSize: "11px", color: "#565b6e" }}
            >
              {resource.provider_resource_id}
            </span>
          )}
          {resource.integration_id && (
            <>
              {resource.display_name && (
                <span style={{ color: "#2a2d38", fontSize: "10px" }}>·</span>
              )}
              <Link
                href={`/integrations/${resource.integration_id}`}
                style={{ fontSize: "11px", color: "#3a3d4a", textDecoration: "none" }}
                onMouseOver={(e) => { (e.currentTarget as HTMLAnchorElement).style.color = "#565b6e"; }}
                onMouseOut={(e) => { (e.currentTarget as HTMLAnchorElement).style.color = "#3a3d4a"; }}
              >
                View integration ↗
              </Link>
            </>
          )}
        </div>
      </div>

      {/* Type — friendly label + provider badge */}
      <div
        className="shrink-0 flex items-center gap-2"
        style={{ width: "220px" }}
      >
        <ProviderBadge resourceType={resource.provider_resource_type} />
        <span style={{ fontSize: "12px", color: "#8b90a0" }}>
          {formatResourceType(resource.provider_resource_type)}
        </span>
      </div>

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
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

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
        <span style={{ width: "220px" }}>Type</span>
        <span style={{ width: "140px" }}>Last Snapshot</span>
        <span style={{ width: "60px", textAlign: "right" }}>Status</span>
      </div>

      {resources.map((resource) => (
        <ResourceRow key={resource.id} resource={resource} />
      ))}
    </div>
  );
}
