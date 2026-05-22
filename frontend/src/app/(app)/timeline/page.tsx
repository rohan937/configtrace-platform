"use client";

import { useRef, useState, useEffect } from "react";
import type { ChangeListItem } from "@/types";
import type { GetChangesParams } from "@/lib/api";
import { getChanges } from "@/lib/api";
import { timeRangeToSince } from "@/lib/utils";
import PageHeader from "@/components/common/PageHeader";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

// ── Filter state type ─────────────────────────────────────────────────────────

interface Filters {
  riskLevel: string;   // "all" | "critical" | "high" | "medium" | "low" | "unknown"
  changeType: string;  // "all" | "added" | "removed" | "modified"
  timeRange: string;   // "all" | "24h" | "7d" | "30d"
}

const DEFAULT_FILTERS: Filters = {
  riskLevel: "all",
  changeType: "all",
  timeRange: "all",
};

// ── Risk pill colors ──────────────────────────────────────────────────────────

const RISK_PILL_COLORS: Record<
  string,
  { activeBg: string; activeText: string; activeBorder: string }
> = {
  critical: {
    activeBg: "rgba(232,64,64,0.12)",
    activeText: "#e84040",
    activeBorder: "rgba(232,64,64,0.35)",
  },
  high: {
    activeBg: "rgba(245,99,42,0.12)",
    activeText: "#f5632a",
    activeBorder: "rgba(245,99,42,0.35)",
  },
  medium: {
    activeBg: "rgba(245,166,35,0.12)",
    activeText: "#f5a623",
    activeBorder: "rgba(245,166,35,0.35)",
  },
  low: {
    activeBg: "rgba(107,156,248,0.12)",
    activeText: "#6b9cf8",
    activeBorder: "rgba(107,156,248,0.35)",
  },
  unknown: {
    activeBg: "rgba(86,91,110,0.18)",
    activeText: "#8b90a0",
    activeBorder: "rgba(86,91,110,0.35)",
  },
};

// ── FilterPill component ──────────────────────────────────────────────────────

interface FilterPillProps {
  label: string;
  active: boolean;
  onClick: () => void;
  riskKey?: string;
}

function FilterPill({ label, active, onClick, riskKey }: FilterPillProps) {
  let activeStyle: React.CSSProperties = {};
  if (active) {
    const c = riskKey ? RISK_PILL_COLORS[riskKey] : undefined;
    if (c) {
      activeStyle = {
        background: c.activeBg,
        color: c.activeText,
        borderColor: c.activeBorder,
        fontWeight: 600,
      };
    } else {
      activeStyle = {
        background: "rgba(79,128,247,0.12)",
        color: "#4f80f7",
        borderColor: "rgba(79,128,247,0.35)",
        fontWeight: 600,
      };
    }
  }

  return (
    <button
      onClick={onClick}
      style={{
        background: "#1c1e26",
        border: "1px solid #2a2d38",
        color: "#8b90a0",
        borderRadius: "6px",
        padding: "4px 10px",
        fontSize: "11px",
        textTransform: "uppercase" as const,
        letterSpacing: "0.06em",
        cursor: "pointer",
        fontFamily: "inherit",
        fontWeight: 400,
        ...activeStyle,
      }}
    >
      {label}
    </button>
  );
}

// ── FilterRow component ───────────────────────────────────────────────────────

interface FilterRowProps {
  label: string;
  children: React.ReactNode;
}

function FilterRow({ label, children }: FilterRowProps) {
  return (
    <div className="flex items-center gap-3">
      <span
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          width: "84px",
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TimelinePage() {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Generation counter prevents stale async responses from overwriting state.
  const genRef = useRef(0);

  function buildParams(f: Filters, p: number): GetChangesParams {
    const params: GetChangesParams = { page: p, page_size: PAGE_SIZE };
    if (f.riskLevel !== "all") params.risk_level = f.riskLevel;
    if (f.changeType !== "all") params.change_type = f.changeType;
    const since = timeRangeToSince(f.timeRange);
    if (since) params.since = since;
    return params;
  }

  function doFetch(f: Filters, p: number, mode: "replace" | "append") {
    genRef.current += 1;
    const gen = genRef.current;

    if (mode === "append") {
      setLoadingMore(true);
    } else {
      setLoading(true);
      setError(null);
    }

    getChanges(buildParams(f, p))
      .then((data) => {
        if (gen !== genRef.current) return;
        setChanges((prev) =>
          mode === "append" ? [...prev, ...data.items] : data.items,
        );
        setTotal(data.total);
      })
      .catch((err) => {
        if (gen !== genRef.current) return;
        setError(
          err instanceof Error ? err.message : "Failed to load changes.",
        );
      })
      .finally(() => {
        if (gen !== genRef.current) return;
        setLoading(false);
        setLoadingMore(false);
      });
  }

  // Initial load on mount.
  useEffect(() => {
    doFetch(DEFAULT_FILTERS, 1, "replace");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Apply a new filter value — resets to page 1 and replaces results.
  function setFilter<K extends keyof Filters>(key: K, value: Filters[K]) {
    const next = { ...filters, [key]: value };
    setFilters(next);
    setPage(1);
    doFetch(next, 1, "replace");
  }

  function handleLoadMore() {
    const next = page + 1;
    setPage(next);
    doFetch(filters, next, "append");
  }

  function handleRetry() {
    doFetch(filters, 1, "replace");
    setPage(1);
  }

  const remaining = total - changes.length;
  const hasMore = remaining > 0;
  const hasFilters =
    filters.riskLevel !== "all" ||
    filters.changeType !== "all" ||
    filters.timeRange !== "all";

  return (
    <>
      <PageHeader
        title="Timeline"
        description="Configuration changes across all integrations, newest first."
      />

      <div className="px-6 pb-8">

        {/* ── Filter controls ─────────────────────────────────────────── */}
        <div
          className="flex flex-col gap-2.5 mb-6 p-4"
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "6px",
          }}
        >
          <FilterRow label="Risk">
            <FilterPill
              label="All"
              active={filters.riskLevel === "all"}
              onClick={() => setFilter("riskLevel", "all")}
            />
            {(["critical", "high", "medium", "low", "unknown"] as const).map(
              (r) => (
                <FilterPill
                  key={r}
                  label={r}
                  active={filters.riskLevel === r}
                  onClick={() => setFilter("riskLevel", r)}
                  riskKey={r}
                />
              ),
            )}
          </FilterRow>

          <FilterRow label="Type">
            {(
              [
                ["all", "All"],
                ["added", "Added"],
                ["removed", "Removed"],
                ["modified", "Modified"],
              ] as const
            ).map(([val, lbl]) => (
              <FilterPill
                key={val}
                label={lbl}
                active={filters.changeType === val}
                onClick={() => setFilter("changeType", val)}
              />
            ))}
          </FilterRow>

          <FilterRow label="Since">
            {(
              [
                ["all", "All time"],
                ["24h", "Last 24h"],
                ["7d", "Last 7 days"],
                ["30d", "Last 30 days"],
              ] as const
            ).map(([val, lbl]) => (
              <FilterPill
                key={val}
                label={lbl}
                active={filters.timeRange === val}
                onClick={() => setFilter("timeRange", val)}
              />
            ))}
          </FilterRow>
        </div>

        {/* ── Result count ────────────────────────────────────────────── */}
        {!loading && !error && (
          <p
            className="mb-3"
            style={{ fontSize: "12px", color: "#565b6e" }}
          >
            {total === 0 ? null : `${total} change${total === 1 ? "" : "s"} total`}
          </p>
        )}

        {/* ── Content ─────────────────────────────────────────────────── */}
        {loading && <LoadingState />}

        {!loading && error && (
          <div>
            <ErrorState message={error} />
            <div className="flex justify-center mt-4">
              <button
                onClick={handleRetry}
                style={{
                  background: "transparent",
                  border: "1px solid #4f80f7",
                  color: "#4f80f7",
                  borderRadius: "6px",
                  padding: "6px 14px",
                  fontSize: "13px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                }}
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {!loading && !error && (
          <ChangeList
            changes={changes}
            emptyTitle={
              hasFilters
                ? "No changes match the current filters."
                : "Your change timeline is empty."
            }
            emptyDescription={
              hasFilters
                ? "Try clearing the filters or expanding the time range."
                : "Connect Cloudflare and run your first sync to start tracking configuration changes."
            }
          />
        )}

        {/* ── Load more ───────────────────────────────────────────────── */}
        {!loading && !error && hasMore && (
          <div className="flex items-center justify-center mt-6 gap-4">
            <span style={{ fontSize: "12px", color: "#565b6e" }}>
              Showing {changes.length} of {total}
            </span>
            <button
              onClick={handleLoadMore}
              disabled={loadingMore}
              style={{
                background: loadingMore ? "#1c1e26" : "#1e2030",
                border: "1px solid #3a3d4a",
                color: loadingMore ? "#565b6e" : "#b0b5c4",
                borderRadius: "6px",
                padding: "6px 16px",
                fontSize: "13px",
                cursor: loadingMore ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              {loadingMore
                ? "Loading…"
                : `Load more (${remaining} remaining)`}
            </button>
          </div>
        )}

        {/* ── Inline loading indicator for load more ───────────────────── */}
        {loadingMore && (
          <div className="flex justify-center mt-4">
            <span style={{ fontSize: "12px", color: "#565b6e" }}>
              Loading more…
            </span>
          </div>
        )}
      </div>
    </>
  );
}
