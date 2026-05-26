"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ResourceListItem } from "@/types";
import { getResources } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import ResourceList from "@/components/resources/ResourceList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { getResourceProvider, formatResourceTypeLabel } from "@/lib/resources";
import { PROVIDER_IDS, getProviderMeta } from "@/lib/providers";
import type { ProviderId } from "@/lib/providers";

// ── Summary strip ─────────────────────────────────────────────────────────────

interface SummaryStripProps {
  total: number;
  loaded: number;
  providerCounts: Array<{ id: ProviderId; count: number }>;
  activeFilter: ProviderId | "all";
  onFilter: (id: ProviderId | "all") => void;
}

function SummaryStrip({
  total,
  loaded,
  providerCounts,
  activeFilter,
  onFilter,
}: SummaryStripProps) {
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        gap: "8px",
        marginBottom: "16px",
      }}
    >
      {/* Total count */}
      <span style={{ fontSize: "13px", color: "#8b90a0", marginRight: "4px" }}>
        {total} resource{total !== 1 ? "s" : ""}
        {loaded < total && (
          <span style={{ color: "#565b6e" }}> (showing first {loaded})</span>
        )}
      </span>

      {/* Provider filter pills */}
      <button
        onClick={() => onFilter("all")}
        aria-pressed={activeFilter === "all"}
        style={{
          background: activeFilter === "all" ? "#4f80f7" : "transparent",
          color: activeFilter === "all" ? "#ffffff" : "#8b90a0",
          border: `1px solid ${activeFilter === "all" ? "#4f80f7" : "#2a2d38"}`,
          borderRadius: "4px",
          padding: "2px 9px",
          fontSize: "11px",
          cursor: "pointer",
          fontFamily: "inherit",
          fontWeight: activeFilter === "all" ? 500 : 400,
        }}
      >
        All
      </button>

      {providerCounts.map(({ id, count }) => {
        const meta    = getProviderMeta(id);
        const active  = activeFilter === id;
        return (
          <button
            key={id}
            onClick={() => onFilter(id)}
            aria-pressed={active}
            aria-label={`Filter by ${meta.label}: ${count} resource${count !== 1 ? "s" : ""}`}
            style={{
              background: active ? meta.bgColor : "transparent",
              color: active ? meta.color : "#8b90a0",
              border: `1px solid ${active ? meta.borderColor : "#2a2d38"}`,
              borderRadius: "4px",
              padding: "2px 9px",
              fontSize: "11px",
              cursor: "pointer",
              fontFamily: "inherit",
              fontWeight: active ? 500 : 400,
              display: "flex",
              alignItems: "center",
              gap: "5px",
            }}
          >
            <span
              aria-hidden="true"
              style={{
                display: "inline-block",
                width: "5px",
                height: "5px",
                borderRadius: "50%",
                background: meta.color,
                flexShrink: 0,
              }}
            />
            {meta.shortLabel}
            <span style={{ color: active ? meta.color : "#565b6e" }}>
              {count}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// ── Search bar ────────────────────────────────────────────────────────────────

function SearchBar({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div style={{ position: "relative", marginBottom: "16px" }}>
      <span
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "10px",
          top: "50%",
          transform: "translateY(-50%)",
          fontSize: "12px",
          color: "#565b6e",
          pointerEvents: "none",
        }}
      >
        ⌕
      </span>
      <input
        type="search"
        aria-label="Search resources"
        placeholder="Search by name, type, or provider…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          width: "100%",
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          color: "#e8eaf0",
          fontSize: "13px",
          padding: "7px 12px 7px 30px",
          outline: "none",
          fontFamily: "inherit",
          boxSizing: "border-box",
        }}
        onFocus={(e) => {
          (e.currentTarget as HTMLInputElement).style.borderColor = "#4f80f7";
        }}
        onBlur={(e) => {
          (e.currentTarget as HTMLInputElement).style.borderColor = "#2a2d38";
        }}
      />
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ResourcesPage() {
  const [resources, setResources] = useState<ResourceListItem[]>([]);
  const [total, setTotal]         = useState<number>(0);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [search, setSearch]       = useState("");
  const [providerFilter, setProviderFilter] = useState<ProviderId | "all">("all");
  const { getToken, isLoaded }    = useAuth();

  useEffect(() => {
    if (!isLoaded) return;
    let cancelled = false;

    (async () => {
      try {
        const token = await getToken();
        const data  = await getResources({ page_size: 100 }, token);
        if (!cancelled) {
          setResources(data.items);
          setTotal(data.total);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load resources.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
  }, [isLoaded, getToken]);

  // ── Provider counts (from loaded data) ────────────────────────────────────
  const providerCounts = useMemo<Array<{ id: ProviderId; count: number }>>(() => {
    const counts = new Map<ProviderId, number>();
    for (const r of resources) {
      const pid = getResourceProvider(r.provider_resource_type);
      counts.set(pid, (counts.get(pid) ?? 0) + 1);
    }
    // Return in canonical PROVIDER_IDS order, then any extras
    return [
      ...PROVIDER_IDS
        .filter((pid) => counts.has(pid))
        .map((pid) => ({ id: pid, count: counts.get(pid)! })),
      ...[...counts.entries()]
        .filter(([pid]) => !PROVIDER_IDS.includes(pid as ProviderId))
        .map(([pid, count]) => ({ id: pid, count })),
    ];
  }, [resources]);

  // ── Filtered resources ────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    let result = resources;

    if (providerFilter !== "all") {
      result = result.filter(
        (r) => getResourceProvider(r.provider_resource_type) === providerFilter,
      );
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter((r) => {
        const name      = (r.display_name ?? r.provider_resource_id).toLowerCase();
        const typeLabel = formatResourceTypeLabel(r.provider_resource_type).toLowerCase();
        const provider  = getProviderMeta(getResourceProvider(r.provider_resource_type))
          .label.toLowerCase();
        return name.includes(q) || typeLabel.includes(q) || provider.includes(q);
      });
    }

    return result;
  }, [resources, providerFilter, search]);

  // ── Derived booleans ──────────────────────────────────────────────────────
  const hasResources   = resources.length > 0;
  const isFiltered     = search.trim() !== "" || providerFilter !== "all";
  const noMatchFilter  = hasResources && isFiltered && filtered.length === 0;

  // ── Empty state messages ──────────────────────────────────────────────────
  const emptyTitle = noMatchFilter
    ? "No resources match these filters."
    : "No resources captured yet.";

  const emptyDescription = noMatchFilter
    ? "Try clearing the search or changing the provider filter."
    : "Run a sync to populate your configuration inventory.";

  return (
    <>
      <PageHeader
        title="Resources"
        description="Inventory of monitored configuration resources across your providers."
      />

      <div className="px-6 py-6">
        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}

        {/* ── No resources empty state ──────────────────────────────── */}
        {!loading && !error && total === 0 && (
          <div
            style={{
              textAlign: "center",
              padding: "48px 24px",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              background: "#13151a",
            }}
          >
            <p
              style={{
                margin: "0 0 8px",
                fontSize: "15px",
                fontWeight: 600,
                color: "#e8eaf0",
              }}
            >
              No resources yet
            </p>
            <p
              style={{
                margin: "0 0 6px",
                fontSize: "13px",
                color: "#8b90a0",
                lineHeight: 1.6,
              }}
            >
              Resources are populated from your first sync with a connected provider.
            </p>
            <p
              style={{
                margin: "0 0 20px",
                fontSize: "12px",
                color: "#565b6e",
                lineHeight: 1.6,
              }}
            >
              Connect a provider and run a sync to start monitoring AWS, Firebase,
              Supabase, Stripe, GitHub, Cloudflare, Vercel, or Shopify configuration.
            </p>
            <Link
              href="/integrations"
              style={{
                display: "inline-block",
                background: "#4f80f7",
                color: "#ffffff",
                textDecoration: "none",
                borderRadius: "6px",
                padding: "8px 18px",
                fontSize: "13px",
                fontWeight: 500,
              }}
            >
              Go to Integrations →
            </Link>
          </div>
        )}

        {/* ── Loaded state ──────────────────────────────────────────── */}
        {!loading && !error && total > 0 && (
          <>
            {/* Summary strip + provider filter pills */}
            <SummaryStrip
              total={total}
              loaded={resources.length}
              providerCounts={providerCounts}
              activeFilter={providerFilter}
              onFilter={(id) => {
                setProviderFilter(id);
                setSearch("");
              }}
            />

            {/* Search */}
            <SearchBar value={search} onChange={setSearch} />

            {/* Resource list (grouped by provider) */}
            <ResourceList
              resources={filtered}
              emptyTitle={emptyTitle}
              emptyDescription={emptyDescription}
            />

            {/* Footer — link to timeline */}
            {hasResources && (
              <div style={{ marginTop: "16px", textAlign: "right" }}>
                <Link
                  href="/timeline"
                  style={{
                    fontSize: "12px",
                    color: "#4f80f7",
                    textDecoration: "none",
                  }}
                >
                  View change timeline →
                </Link>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
