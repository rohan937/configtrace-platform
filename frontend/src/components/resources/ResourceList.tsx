import Link from "next/link";
import type { ResourceListItem } from "@/types";
import EmptyState from "@/components/common/EmptyState";
import { formatRelativeTime, formatAbsoluteTime } from "@/lib/utils";
import {
  getResourceProvider,
  getResourceProviderMeta,
  getResourceCategory,
  formatResourceTypeLabel,
} from "@/lib/resources";
import { PROVIDER_IDS } from "@/lib/providers";
import type { ProviderId } from "@/lib/providers";

interface ResourceListProps {
  resources: ResourceListItem[];
  emptyTitle?: string;
  emptyDescription?: string;
}

// ── Category chip ─────────────────────────────────────────────────────────────

function CategoryChip({ label }: { label: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        fontSize: "10px",
        fontWeight: 500,
        letterSpacing: "0.04em",
        padding: "1px 6px",
        borderRadius: "4px",
        background: "rgba(139,144,160,0.10)",
        color: "#8b90a0",
        border: "1px solid #2a2d38",
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      {label}
    </span>
  );
}

// ── Active status dot ─────────────────────────────────────────────────────────

function StatusDot({ active }: { active: boolean }) {
  return (
    <span
      aria-label={active ? "Active" : "Inactive"}
      title={active ? "Active" : "Inactive"}
      style={{
        flexShrink: 0,
        display: "inline-block",
        width: "7px",
        height: "7px",
        borderRadius: "50%",
        background: active ? "#3ccf7e" : "#3a3d4a",
      }}
    />
  );
}

// ── Resource row ──────────────────────────────────────────────────────────────

function ResourceRow({ resource }: { resource: ResourceListItem }) {
  const typeLabel = formatResourceTypeLabel(resource.provider_resource_type);
  const category  = getResourceCategory(resource.provider_resource_type);
  const name      = resource.display_name ?? resource.provider_resource_id;
  const showId    = resource.display_name != null;

  return (
    <Link
      href={`/resources/${resource.id}`}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "12px",
        padding: "9px 16px",
        borderBottom: "1px solid #1e2030",
        textDecoration: "none",
        transition: "background 0.1s",
      }}
      className="hover:bg-surface3"
    >
      {/* Name + provider_resource_id */}
      <div
        style={{
          flex: 1,
          minWidth: 0,
          display: "flex",
          flexDirection: "column",
          gap: "2px",
        }}
      >
        <span
          className="font-mono"
          style={{
            fontSize: "13px",
            color: "#e8eaf0",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={name}
        >
          {name}
        </span>
        {showId && (
          <span
            className="font-mono"
            style={{
              fontSize: "11px",
              color: "#3a3d4a",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={resource.provider_resource_id}
          >
            {resource.provider_resource_id}
          </span>
        )}
      </div>

      {/* Category chip */}
      <div style={{ flexShrink: 0, width: "80px", textAlign: "right" }}>
        {category && <CategoryChip label={category} />}
      </div>

      {/* Type label */}
      <span
        style={{
          flexShrink: 0,
          width: "160px",
          fontSize: "12px",
          color: "#8b90a0",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={typeLabel}
      >
        {typeLabel}
      </span>

      {/* Last snapshot */}
      <span
        style={{
          flexShrink: 0,
          width: "90px",
          fontSize: "11px",
          color: "#565b6e",
          textAlign: "right",
        }}
        title={
          resource.last_snapshot_at
            ? formatAbsoluteTime(resource.last_snapshot_at)
            : undefined
        }
      >
        {resource.last_snapshot_at
          ? formatRelativeTime(resource.last_snapshot_at)
          : "—"}
      </span>

      {/* Active dot */}
      <StatusDot active={resource.is_active} />
    </Link>
  );
}

// ── Provider section header ───────────────────────────────────────────────────

function ProviderSection({
  providerId,
  resources,
}: {
  providerId: ProviderId;
  resources: ResourceListItem[];
}) {
  const meta = getResourceProviderMeta(resources[0].provider_resource_type);

  return (
    <section aria-label={`${meta.label} resources`}>
      {/* Section header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          padding: "8px 16px",
          background: "#1a1d26",
          borderBottom: "1px solid #2a2d38",
          position: "sticky",
          top: 0,
        }}
      >
        <span
          aria-hidden="true"
          style={{
            flexShrink: 0,
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            background: meta.color,
          }}
        />
        <span
          style={{
            fontSize: "12px",
            fontWeight: 600,
            color: meta.color,
            letterSpacing: "0.02em",
          }}
        >
          {meta.label}
        </span>
        <span style={{ fontSize: "11px", color: "#565b6e" }}>
          {resources.length} resource{resources.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Rows */}
      {resources.map((r) => (
        <ResourceRow key={r.id} resource={r} />
      ))}
    </section>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ResourceList({
  resources,
  emptyTitle,
  emptyDescription,
}: ResourceListProps) {
  if (resources.length === 0) {
    return (
      <EmptyState
        title={emptyTitle ?? "No resources found."}
        description={emptyDescription}
      />
    );
  }

  // Group resources by provider, preserving PROVIDER_IDS canonical order.
  const grouped = new Map<ProviderId, ResourceListItem[]>();
  for (const r of resources) {
    const pid = getResourceProvider(r.provider_resource_type);
    if (!grouped.has(pid)) grouped.set(pid, []);
    grouped.get(pid)!.push(r);
  }

  // Render sections in canonical provider order; unknown providers at the end.
  const orderedIds = [
    ...PROVIDER_IDS.filter((pid) => grouped.has(pid)),
    ...[...grouped.keys()].filter((pid) => !PROVIDER_IDS.includes(pid as ProviderId)),
  ];

  return (
    <div
      style={{
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        overflow: "hidden",
      }}
      role="list"
      aria-label="Configuration resources"
    >
      {orderedIds.map((pid) => (
        <ProviderSection
          key={pid}
          providerId={pid as ProviderId}
          resources={grouped.get(pid as ProviderId)!}
        />
      ))}
    </div>
  );
}
