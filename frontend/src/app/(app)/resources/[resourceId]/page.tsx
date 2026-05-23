"use client";

import { useParams } from "next/navigation";
import { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ResourceDetail, SnapshotListItem, ChangeListItem, DnsRecord } from "@/types";
import { getResource, getResourceSnapshots, getResourceChanges } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import {
  formatRelativeTime,
  formatAbsoluteTime,
  formatSnapshotHash,
  formatResourceType,
  shortId,
} from "@/lib/utils";

// ── DNS table helpers ─────────────────────────────────────────────────────────

function dnsCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

// ── DNS State Table ───────────────────────────────────────────────────────────

interface DnsTableProps {
  records: DnsRecord[];
}

function DnsTable({ records }: DnsTableProps) {
  if (records.length === 0) {
    return (
      <p style={{ fontSize: "13px", color: "#565b6e", fontStyle: "italic" }}>
        No records in this snapshot.
      </p>
    );
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "12px",
        }}
      >
        <thead>
          <tr
            style={{
              background: "#1a1d26",
              borderBottom: "1px solid #2a2d38",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "#565b6e",
              fontSize: "11px",
            }}
          >
            {["Type", "Name", "Content", "TTL", "Proxied", "Priority", "Comment"].map(
              (col) => (
                <th
                  key={col}
                  style={{
                    padding: "6px 10px",
                    textAlign: "left",
                    fontWeight: 500,
                    whiteSpace: "nowrap",
                  }}
                >
                  {col}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {records.map((rec, i) => (
            <tr
              key={i}
              style={{
                borderBottom: "1px solid #2a2d38",
                background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.015)",
              }}
            >
              {/* Type */}
              <td
                style={{
                  padding: "6px 10px",
                  color: "#b0b5c4",
                  whiteSpace: "nowrap",
                  fontFamily: "monospace",
                }}
              >
                {dnsCell(rec.record_type)}
              </td>
              {/* Name */}
              <td
                style={{
                  padding: "6px 10px",
                  color: "#e8eaf0",
                  fontFamily: "monospace",
                  maxWidth: "240px",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={typeof rec.name === "string" ? rec.name : undefined}
              >
                {dnsCell(rec.name)}
              </td>
              {/* Content */}
              <td
                style={{
                  padding: "6px 10px",
                  color: "#e8eaf0",
                  fontFamily: "monospace",
                  maxWidth: "280px",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={typeof rec.content === "string" ? rec.content : undefined}
              >
                {dnsCell(rec.content)}
              </td>
              {/* TTL */}
              <td
                style={{
                  padding: "6px 10px",
                  color: "#8b90a0",
                  whiteSpace: "nowrap",
                }}
              >
                {dnsCell(rec.ttl)}
              </td>
              {/* Proxied */}
              <td
                style={{
                  padding: "6px 10px",
                  color:
                    rec.proxied === true
                      ? "#f5a623"
                      : rec.proxied === false
                      ? "#565b6e"
                      : "#3a3d4a",
                  whiteSpace: "nowrap",
                }}
              >
                {dnsCell(rec.proxied)}
              </td>
              {/* Priority */}
              <td
                style={{
                  padding: "6px 10px",
                  color: "#8b90a0",
                  whiteSpace: "nowrap",
                }}
              >
                {dnsCell(rec.priority)}
              </td>
              {/* Comment */}
              <td
                style={{
                  padding: "6px 10px",
                  color: "#565b6e",
                  fontStyle: "italic",
                  maxWidth: "200px",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={typeof rec.comment === "string" ? rec.comment : undefined}
              >
                {dnsCell(rec.comment)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Snapshot list item ────────────────────────────────────────────────────────

interface SnapshotRowProps {
  snapshot: SnapshotListItem;
  selected: boolean;
  onClick: () => void;
}

function SnapshotRow({ snapshot, selected, onClick }: SnapshotRowProps) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%",
        textAlign: "left",
        background: selected ? "rgba(79,128,247,0.10)" : "transparent",
        border: "none",
        borderBottom: "1px solid #2a2d38",
        borderLeft: selected ? "2px solid #4f80f7" : "2px solid transparent",
        padding: "8px 10px",
        cursor: "pointer",
        fontFamily: "inherit",
        display: "flex",
        flexDirection: "column",
        gap: "2px",
      }}
    >
      <div className="flex items-center justify-between gap-2">
        <span
          style={{
            fontSize: "12px",
            color: selected ? "#e8eaf0" : "#b0b5c4",
            fontWeight: selected ? 600 : 400,
          }}
          title={formatAbsoluteTime(snapshot.created_at)}
        >
          {formatRelativeTime(snapshot.created_at)}
        </span>
        <span
          style={{
            fontSize: "11px",
            color: "#565b6e",
            fontFamily: "monospace",
            letterSpacing: "0.02em",
          }}
        >
          {formatSnapshotHash(snapshot.content_hash)}
        </span>
      </div>
      <span style={{ fontSize: "11px", color: "#565b6e" }}>
        via {snapshot.triggered_by}
      </span>
    </button>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ResourceDetailPage() {
  const params = useParams();
  const resourceId = params.resourceId as string;

  const [resource, setResource] = useState<ResourceDetail | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotListItem[]>([]);
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [selectedSnapshot, setSelectedSnapshot] = useState<SnapshotListItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { getToken, isLoaded } = useAuth();

  useEffect(() => {
    if (!resourceId || !isLoaded) return;
    let cancelled = false;

    setLoading(true);
    setError(null);

    (async () => {
      try {
        const token = await getToken();
        const [res, snaps, chgs] = await Promise.all([
          getResource(resourceId, token),
          getResourceSnapshots(resourceId, { page_size: 50 }, token),
          getResourceChanges(resourceId, { page_size: 50 }, token),
        ]);
        if (cancelled) return;
        setResource(res);
        setSnapshots(snaps.items);
        setChanges(chgs.items);
        // Default: select newest snapshot (first item — backend returns newest first).
        if (snaps.items.length > 0) {
          setSelectedSnapshot(snaps.items[0]);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load resource.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [resourceId, isLoaded, getToken]);

  // ── Loading / error ──────────────────────────────────────────────────────

  if (loading) {
    return (
      <>
        <PageHeader title="Resource" description="" />
        <div className="px-6 py-6">
          <LoadingState />
        </div>
      </>
    );
  }

  if (error || !resource) {
    return (
      <>
        <PageHeader title="Resource" description="" />
        <div className="px-6 py-6">
          <ErrorState message={error ?? "Resource not found."} />
          <div className="mt-4">
            <Link
              href="/resources"
              style={{ fontSize: "13px", color: "#4f80f7", textDecoration: "none" }}
            >
              ← Back to Resources
            </Link>
          </div>
        </div>
      </>
    );
  }

  const title = resource.display_name ?? resource.provider_resource_id;

  return (
    <>
      <PageHeader
        title={title}
        description={`${formatResourceType(resource.provider_resource_type)} · ${resource.provider_resource_id}`}
      />

      <div className="px-6 pb-10" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>

        {/* ── Back link ───────────────────────────────────────────────── */}
        <div>
          <Link
            href="/resources"
            style={{ fontSize: "13px", color: "#565b6e", textDecoration: "none" }}
          >
            ← All Resources
          </Link>
        </div>

        {/* ── Resource metadata bar ────────────────────────────────────── */}
        <div
          className="flex flex-wrap items-center gap-4"
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "6px",
            padding: "12px 16px",
            fontSize: "12px",
            color: "#8b90a0",
          }}
        >
          <MetaBadge label="Type" value={formatResourceType(resource.provider_resource_type)} />
          <MetaDivider />
          <MetaBadge label="ID" value={resource.provider_resource_id} mono />
          <MetaDivider />
          <MetaBadge
            label="Status"
            value={resource.is_active ? "Active" : "Inactive"}
            color={resource.is_active ? "#4ade80" : "#8b90a0"}
          />
          <MetaDivider />
          <MetaBadge
            label="Last snapshot"
            value={
              resource.last_snapshot_at
                ? formatRelativeTime(resource.last_snapshot_at)
                : "—"
            }
          />
          <MetaDivider />
          <MetaBadge
            label="Snapshots"
            value={String(resource.snapshot_count)}
          />
          <MetaDivider />
          <MetaBadge
            label="Changes"
            value={String(resource.change_count)}
          />
        </div>

        {/* ── Snapshot history + DNS state ─────────────────────────────── */}
        {snapshots.length === 0 ? (
          <div
            style={{
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "32px 16px",
              textAlign: "center",
              color: "#565b6e",
              fontSize: "13px",
            }}
          >
            No snapshots recorded yet. Run a sync to capture the current state.
          </div>
        ) : (
          <div
            style={{
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              overflow: "hidden",
              display: "grid",
              gridTemplateColumns: "240px 1fr",
            }}
          >
            {/* Left — snapshot list */}
            <div
              style={{
                borderRight: "1px solid #2a2d38",
                overflowY: "auto",
                maxHeight: "480px",
              }}
            >
              {/* Panel header */}
              <div
                style={{
                  padding: "8px 10px",
                  background: "#1a1d26",
                  borderBottom: "1px solid #2a2d38",
                  fontSize: "11px",
                  color: "#565b6e",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                }}
              >
                Snapshots ({snapshots.length})
              </div>

              {snapshots.map((s) => (
                <SnapshotRow
                  key={s.id}
                  snapshot={s}
                  selected={selectedSnapshot?.id === s.id}
                  onClick={() => setSelectedSnapshot(s)}
                />
              ))}
            </div>

            {/* Right — snapshot state for selected snapshot */}
            <div style={{ overflowX: "auto" }}>
              {/* Panel header */}
              <div
                style={{
                  padding: "8px 10px",
                  background: "#1a1d26",
                  borderBottom: "1px solid #2a2d38",
                  fontSize: "11px",
                  color: "#565b6e",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "8px",
                }}
              >
                <span>
                  {resource.provider_resource_type === "cloudflare_dns_zone"
                    ? "DNS State"
                    : "Snapshot State"}
                </span>
                {selectedSnapshot && (
                  <span
                    style={{ fontFamily: "monospace", color: "#3a3d4a", fontSize: "11px" }}
                    title={formatAbsoluteTime(selectedSnapshot.created_at)}
                  >
                    {formatAbsoluteTime(selectedSnapshot.created_at)}
                  </span>
                )}
              </div>

              {selectedSnapshot ? (
                <div style={{ padding: "0" }}>
                  <DnsTable records={selectedSnapshot.state} />
                </div>
              ) : (
                <p
                  style={{
                    padding: "16px",
                    fontSize: "13px",
                    color: "#565b6e",
                    fontStyle: "italic",
                  }}
                >
                  Select a snapshot to view its state.
                </p>
              )}
            </div>
          </div>
        )}

        {/* ── Changes for this resource ────────────────────────────────── */}
        <div>
          <h2
            style={{
              fontSize: "13px",
              color: "#8b90a0",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              marginBottom: "12px",
              fontWeight: 500,
            }}
          >
            Changes ({resource.change_count})
          </h2>
          <ChangeList
            changes={changes}
            emptyTitle="No changes recorded yet."
            emptyDescription="The baseline is in place. Any configuration changes detected on the next sync will appear here, with risk classification and old/new values."
          />
        </div>
      </div>
    </>
  );
}

// ── Small metadata display helpers ────────────────────────────────────────────

function MetaDivider() {
  return (
    <span
      aria-hidden
      style={{ color: "#2a2d38", userSelect: "none" }}
    >
      ·
    </span>
  );
}

interface MetaBadgeProps {
  label: string;
  value: string;
  mono?: boolean;
  color?: string;
}

function MetaBadge({ label, value, mono, color }: MetaBadgeProps) {
  return (
    <span style={{ display: "inline-flex", alignItems: "baseline", gap: "5px" }}>
      <span style={{ color: "#565b6e", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </span>
      <span
        style={{
          color: color ?? "#b0b5c4",
          fontSize: "12px",
          fontFamily: mono ? "monospace" : "inherit",
        }}
      >
        {value}
      </span>
    </span>
  );
}
