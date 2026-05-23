"use client";

import { Suspense, useRef, useState, useEffect, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import type { ChangeListItem, Integration } from "@/types";
import type { GetChangesParams } from "@/lib/api";
import { getChanges, getIntegrations } from "@/lib/api";
import { timeRangeToSince } from "@/lib/utils";
import { usePollingRefresh } from "@/hooks/usePollingRefresh";
import PageHeader from "@/components/common/PageHeader";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

// ── Filter state type ─────────────────────────────────────────────────────────

interface Filters {
  provider: string;        // "all" | "cloudflare" | "github"
  integrationId: string;   // "all" | <uuid>
  riskLevel: string;       // "all" | "critical" | "high" | "medium" | "low"
  changeType: string;      // "all" | "added" | "removed" | "modified"
  timeRange: string;       // "all" | "24h" | "7d" | "30d"
}

const DEFAULT_FILTERS: Filters = {
  provider: "all",
  integrationId: "all",
  riskLevel: "all",
  changeType: "all",
  timeRange: "all",
};

// ── Risk pill colors ──────────────────────────────────────────────────────────

const RISK_PILL_COLORS: Record<
  string,
  { activeBg: string; activeText: string; activeBorder: string }
> = {
  critical: { activeBg: "rgba(232,64,64,0.12)", activeText: "#e84040", activeBorder: "rgba(232,64,64,0.35)" },
  high: { activeBg: "rgba(245,99,42,0.12)", activeText: "#f5632a", activeBorder: "rgba(245,99,42,0.35)" },
  medium: { activeBg: "rgba(245,166,35,0.12)", activeText: "#f5a623", activeBorder: "rgba(245,166,35,0.35)" },
  low: { activeBg: "rgba(107,156,248,0.12)", activeText: "#6b9cf8", activeBorder: "rgba(107,156,248,0.35)" },
};

// ── FilterPill ────────────────────────────────────────────────────────────────

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
      activeStyle = { background: c.activeBg, color: c.activeText, borderColor: c.activeBorder, fontWeight: 600 };
    } else {
      activeStyle = { background: "rgba(79,128,247,0.12)", color: "#4f80f7", borderColor: "rgba(79,128,247,0.35)", fontWeight: 600 };
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

// ── FilterRow ─────────────────────────────────────────────────────────────────

function FilterRow({ label, children }: { label: string; children: React.ReactNode }) {
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

// ── Filter helpers ────────────────────────────────────────────────────────────

function filtersFromParams(params: URLSearchParams): Filters {
  return {
    provider: params.get("provider") ?? "all",
    integrationId: params.get("integration_id") ?? "all",
    riskLevel: params.get("risk_level") ?? "all",
    changeType: params.get("change_type") ?? "all",
    timeRange: params.get("time_range") ?? "all",
  };
}

function buildQuery(params: URLSearchParams, filters: Filters): URLSearchParams {
  const next = new URLSearchParams();
  if (filters.provider !== "all") next.set("provider", filters.provider);
  if (filters.integrationId !== "all") next.set("integration_id", filters.integrationId);
  if (filters.riskLevel !== "all") next.set("risk_level", filters.riskLevel);
  if (filters.changeType !== "all") next.set("change_type", filters.changeType);
  if (filters.timeRange !== "all") next.set("time_range", filters.timeRange);
  void params; // keep param for possible future use
  return next;
}

// ── Inner content (uses useSearchParams — must be inside Suspense) ─────────────

function TimelineContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [filters, setFilters] = useState<Filters>(() =>
    filtersFromParams(searchParams)
  );
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [integrationsList, setIntegrationsList] = useState<Integration[]>([]);

  const { getToken, isLoaded } = useAuth();
  const genRef = useRef(0);

  // ── Fetch integrations for the integration-filter dropdown ───────────────
  useEffect(() => {
    if (!isLoaded) return;
    (async () => {
      try {
        const token = await getToken();
        const data = await getIntegrations(token);
        setIntegrationsList(data.integrations);
      } catch {
        // Non-fatal — integration filter just won't populate
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded]);

  // ── Build API params from filters ────────────────────────────────────────
  function buildApiParams(f: Filters, p: number): GetChangesParams {
    const params: GetChangesParams = { page: p, page_size: PAGE_SIZE };
    if (f.provider !== "all") params.provider = f.provider;
    if (f.integrationId !== "all") params.integration_id = f.integrationId;
    if (f.riskLevel !== "all") params.risk_level = f.riskLevel;
    if (f.changeType !== "all") params.change_type = f.changeType;
    const since = timeRangeToSince(f.timeRange);
    if (since) params.since = since;
    return params;
  }

  // ── Fetch changes ────────────────────────────────────────────────────────
  const doFetch = useCallback(
    async (f: Filters, p: number, mode: "replace" | "append") => {
      genRef.current += 1;
      const gen = genRef.current;

      if (mode === "append") {
        setLoadingMore(true);
      } else {
        setLoading(true);
        setError(null);
      }

      try {
        const token = await getToken();
        const data = await getChanges(buildApiParams(f, p), token);
        if (gen !== genRef.current) return;
        setChanges((prev) =>
          mode === "append" ? [...prev, ...data.items] : data.items
        );
        setTotal(data.total);
      } catch (err) {
        if (gen !== genRef.current) return;
        setError(err instanceof Error ? err.message : "Failed to load changes.");
      } finally {
        if (gen !== genRef.current) return;
        setLoading(false);
        setLoadingMore(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [getToken]
  );

  // Initial load
  useEffect(() => {
    if (!isLoaded) return;
    doFetch(filters, 1, "replace");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded]);

  // Polling — 60s background refresh of page-1 with current filters.
  // Does NOT reset pagination (previously-loaded pages stay visible).
  // Filters, URL params, and scroll position are all preserved.
  const pollCallback = useCallback(() => {
    // Use a non-replace refetch so loadingMore state isn't affected.
    // We silently overwrite page-1 data with fresh results.
    doFetch(filters, 1, "replace");
  }, [doFetch, filters]);

  const { refresh: manualRefresh, lastUpdatedAt } = usePollingRefresh({
    callback: pollCallback,
    intervalMs: 60_000,
    enabled: !loading && error === null && isLoaded,
  });

  // ── Filter change — resets page, updates URL ─────────────────────────────
  function setFilter<K extends keyof Filters>(key: K, value: Filters[K]) {
    const next = { ...filters, [key]: value };
    // Reset integration filter when provider changes to avoid stale cross-filter
    if (key === "provider") {
      next.integrationId = "all";
    }
    setFilters(next);
    setPage(1);
    const qs = buildQuery(searchParams, next);
    router.replace(`/timeline${qs.toString() ? `?${qs.toString()}` : ""}`, { scroll: false });
    doFetch(next, 1, "replace");
  }

  function clearFilters() {
    setFilters(DEFAULT_FILTERS);
    setPage(1);
    router.replace("/timeline", { scroll: false });
    doFetch(DEFAULT_FILTERS, 1, "replace");
  }

  function handleLoadMore() {
    const next = page + 1;
    setPage(next);
    doFetch(filters, next, "append");
  }

  const remaining = total - changes.length;
  const hasMore = remaining > 0;
  const hasFilters =
    filters.provider !== "all" ||
    filters.integrationId !== "all" ||
    filters.riskLevel !== "all" ||
    filters.changeType !== "all" ||
    filters.timeRange !== "all";

  // Filtered integrations for the integration dropdown (by selected provider)
  const filteredIntegrations =
    filters.provider === "all"
      ? integrationsList
      : integrationsList.filter((i) => i.provider === filters.provider);

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
          style={{ background: "#13151a", border: "1px solid #2a2d38", borderRadius: "6px" }}
        >
          {/* Provider */}
          <FilterRow label="Provider">
            <FilterPill label="All" active={filters.provider === "all"} onClick={() => setFilter("provider", "all")} />
            <FilterPill label="Cloudflare" active={filters.provider === "cloudflare"} onClick={() => setFilter("provider", "cloudflare")} />
            <FilterPill label="GitHub" active={filters.provider === "github"} onClick={() => setFilter("provider", "github")} />
          </FilterRow>

          {/* Integration */}
          <FilterRow label="Integration">
            <FilterPill
              label="All"
              active={filters.integrationId === "all"}
              onClick={() => setFilter("integrationId", "all")}
            />
            {filteredIntegrations.map((integration) => (
              <FilterPill
                key={integration.id}
                label={integration.display_name}
                active={filters.integrationId === integration.id}
                onClick={() => setFilter("integrationId", integration.id)}
              />
            ))}
            {filteredIntegrations.length === 0 && filters.integrationId === "all" && integrationsList.length > 0 && (
              <span style={{ fontSize: "11px", color: "#3a3d4a", padding: "4px 0" }}>
                No integrations for this provider
              </span>
            )}
          </FilterRow>

          {/* Risk */}
          <FilterRow label="Risk">
            <FilterPill label="All" active={filters.riskLevel === "all"} onClick={() => setFilter("riskLevel", "all")} />
            {(["critical", "high", "medium", "low"] as const).map((r) => (
              <FilterPill
                key={r}
                label={r}
                active={filters.riskLevel === r}
                onClick={() => setFilter("riskLevel", r)}
                riskKey={r}
              />
            ))}
          </FilterRow>

          {/* Type */}
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

          {/* Since */}
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

        {/* ── Result count + clear filters + refresh ──────────────────── */}
        {!loading && !error && (
          <div className="flex items-center justify-between mb-3">
            <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
              {total === 0 ? null : `${total} change${total === 1 ? "" : "s"} total`}
            </p>
            <div className="flex items-center gap-4">
              {hasFilters && (
                <button
                  onClick={clearFilters}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#4f80f7",
                    fontSize: "12px",
                    cursor: "pointer",
                    padding: 0,
                    fontFamily: "inherit",
                  }}
                >
                  Clear filters
                </button>
              )}
              {total > 0 && (
                <p
                  style={{ fontSize: "11px", color: "#3a3d4a", margin: 0 }}
                  title="Low and medium changes are recorded but do not trigger email alerts"
                >
                  Email alerts: high-risk and critical only
                </p>
              )}
              {lastUpdatedAt && (
                <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
                  Updated {(() => {
                    const s = Math.round((Date.now() - lastUpdatedAt.getTime()) / 1000);
                    if (s < 5) return "just now";
                    if (s < 60) return `${s}s ago`;
                    return `${Math.floor(s / 60)}m ago`;
                  })()}
                </span>
              )}
              <button
                onClick={manualRefresh}
                title="Refresh timeline"
                style={{
                  background: "transparent",
                  border: "1px solid #2a2d38",
                  borderRadius: "6px",
                  color: "#565b6e",
                  fontSize: "11px",
                  padding: "3px 8px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                }}
              >
                ↻
              </button>
            </div>
          </div>
        )}

        {/* ── Content ─────────────────────────────────────────────────── */}
        {loading && <LoadingState />}

        {!loading && error && (
          <div>
            <ErrorState message={error} />
            <div className="flex justify-center mt-4">
              <button
                onClick={() => doFetch(filters, 1, "replace")}
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
                ? "No changes match these filters."
                : "Your change timeline is empty."
            }
            emptyDescription={
              hasFilters
                ? "Try clearing the filters or expanding the time range."
                : "The first sync creates a baseline — no changes are recorded on that run because there's nothing to compare against yet. Changes appear here from the second sync onwards whenever records differ from the baseline."
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
              {loadingMore ? "Loading…" : `Load more (${remaining} remaining)`}
            </button>
          </div>
        )}

        {loadingMore && (
          <div className="flex justify-center mt-4">
            <span style={{ fontSize: "12px", color: "#565b6e" }}>Loading more…</span>
          </div>
        )}
      </div>
    </>
  );
}

// ── Page wrapper — Suspense required for useSearchParams in App Router ────────

export default function TimelinePage() {
  return (
    <Suspense fallback={<LoadingState />}>
      <TimelineContent />
    </Suspense>
  );
}
