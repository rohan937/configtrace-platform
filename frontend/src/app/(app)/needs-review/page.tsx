"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ChangeListItem, ChangeReviewResponse } from "@/types";
import {
  getNeedsReviewChanges,
  acknowledgeChange,
  markChangeExpected,
  snoozeChange,
} from "@/lib/api";
import { getTimelineProvider } from "@/lib/timeline";
import { getProviderMeta } from "@/lib/providers";
import { formatRelativeTime } from "@/lib/utils";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import ChangeRow from "@/components/changes/ChangeRow";

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

type RiskFilter = "all" | "critical" | "high";

// ── Design tokens ─────────────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
  low:      "#6b9cf8",
};

// ── Summary strip ─────────────────────────────────────────────────────────────

function SummaryStrip({ changes, total }: { changes: ChangeListItem[]; total: number }) {
  if (changes.length === 0) return null;

  const criticalCount = changes.filter((c) => c.risk_level === "critical").length;
  const highCount     = changes.filter((c) => c.risk_level === "high").length;

  // Distinct provider labels from the loaded page
  const providerSet = new Set(changes.map((c) => getTimelineProvider(c)));
  const providerLabels = [...providerSet].map((p) => getProviderMeta(p).shortLabel);

  // Oldest change in the loaded set
  const oldest = changes.reduce((min, c) => (c.created_at < min.created_at ? c : min));

  return (
    <div
      aria-label="Needs review summary"
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "8px",
        padding: "8px 14px",
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        marginBottom: "12px",
        fontSize: "12px",
      }}
    >
      {criticalCount > 0 && (
        <span style={{ color: "#e84040", fontWeight: 600 }}>
          {criticalCount} critical
        </span>
      )}
      {criticalCount > 0 && highCount > 0 && (
        <span aria-hidden="true" style={{ color: "#3a3d4a" }}>·</span>
      )}
      {highCount > 0 && (
        <span style={{ color: "#f5632a", fontWeight: 600 }}>
          {highCount} high
        </span>
      )}
      {(criticalCount > 0 || highCount > 0) && (
        <span aria-hidden="true" style={{ color: "#3a3d4a" }}>·</span>
      )}
      {changes.length < total ? (
        <span style={{ color: "#565b6e" }}>
          {changes.length} of {total} loaded
        </span>
      ) : (
        <span style={{ color: "#565b6e" }}>
          {total} total
        </span>
      )}
      {providerLabels.length > 0 && (
        <>
          <span aria-hidden="true" style={{ color: "#3a3d4a" }}>·</span>
          <span style={{ color: "#8b90a0" }}>
            {providerLabels.join(", ")}
          </span>
        </>
      )}
      <span aria-hidden="true" style={{ color: "#3a3d4a" }}>·</span>
      <span style={{ color: "#565b6e" }}>
        Oldest: {formatRelativeTime(oldest.created_at)}
      </span>
    </div>
  );
}

// ── Risk filter pills ─────────────────────────────────────────────────────────

function RiskFilterPills({
  current,
  counts,
  onChange,
}: {
  current: RiskFilter;
  counts: { all: number; critical: number; high: number };
  onChange: (f: RiskFilter) => void;
}) {
  const pills: { key: RiskFilter; label: string; count: number; color?: string }[] = [
    { key: "all",      label: "All",      count: counts.all                           },
    { key: "critical", label: "Critical", count: counts.critical, color: "#e84040"   },
    { key: "high",     label: "High",     count: counts.high,     color: "#f5632a"   },
  ];

  return (
    <div
      style={{ display: "flex", gap: "6px", marginBottom: "12px", flexWrap: "wrap" }}
      role="group"
      aria-label="Filter by risk level"
    >
      {pills.map(({ key, label, count, color }) => {
        const isActive = current === key;
        const activeColor = color ?? "#4f80f7";
        return (
          <button
            key={key}
            onClick={() => onChange(key)}
            aria-pressed={isActive}
            style={{
              background: isActive ? `${activeColor}18` : "#1c1e26",
              border: `1px solid ${isActive ? `${activeColor}55` : "#2a2d38"}`,
              color: isActive ? activeColor : "#8b90a0",
              borderRadius: "6px",
              padding: "4px 10px",
              fontSize: "11px",
              textTransform: "uppercase" as const,
              letterSpacing: "0.06em",
              cursor: "pointer",
              fontFamily: "inherit",
              fontWeight: isActive ? 600 : 400,
            }}
          >
            {label}
            {count > 0 && (
              <span
                style={{
                  marginLeft: "5px",
                  background: isActive ? `${activeColor}30` : "#2a2d38",
                  color: isActive ? activeColor : "#565b6e",
                  borderRadius: "3px",
                  padding: "0 4px",
                  fontSize: "10px",
                }}
              >
                {count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// ── Group header ──────────────────────────────────────────────────────────────

function GroupHeader({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div
      style={{
        padding: "7px 16px 5px",
        background: "#0f1117",
        borderBottom: "1px solid #2a2d38",
        display: "flex",
        alignItems: "center",
        gap: "8px",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          flexShrink: 0,
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: color,
        }}
      />
      <span
        style={{
          fontSize: "11px",
          color,
          fontWeight: 600,
          textTransform: "uppercase" as const,
          letterSpacing: "0.06em",
        }}
      >
        {label}
      </span>
      <span style={{ fontSize: "11px", color: "#565b6e" }}>({count})</span>
    </div>
  );
}

// ── Quick-action button ───────────────────────────────────────────────────────

interface QuickActionButtonProps {
  label: string;
  color: string;
  onClick: () => void;
  disabled?: boolean;
  loading?: boolean;
}

function QuickActionButton({
  label,
  color,
  onClick,
  disabled,
  loading,
}: QuickActionButtonProps) {
  return (
    <button
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onClick();
      }}
      disabled={disabled || loading}
      style={{
        background: "transparent",
        border: `1px solid ${color}60`,
        color: loading ? "#565b6e" : color,
        borderRadius: "4px",
        padding: "2px 8px",
        fontSize: "10px",
        fontWeight: 500,
        cursor: disabled || loading ? "default" : "pointer",
        fontFamily: "inherit",
        whiteSpace: "nowrap",
        flexShrink: 0,
        opacity: disabled ? 0.5 : 1,
        transition: "opacity 0.1s",
      }}
    >
      {loading ? "…" : label}
    </button>
  );
}

// ── Snooze quick-select modal ─────────────────────────────────────────────────

interface SnoozeModalProps {
  changeId: string;
  token: string | null;
  onSnoozed: (review: ChangeReviewResponse) => void;
  onClose: () => void;
}

function SnoozeModal({ changeId, token, onSnoozed, onClose }: SnoozeModalProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const presets = [
    { label: "1 day",   days: 1 },
    { label: "7 days",  days: 7 },
    { label: "30 days", days: 30 },
  ];

  const doSnooze = async (days: number) => {
    setLoading(true);
    setError(null);
    const until = new Date(Date.now() + days * 86_400_000).toISOString();
    try {
      const review = await snoozeChange(changeId, { until }, token);
      onSnoozed(review);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to snooze.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      onClick={(e) => e.stopPropagation()}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
    >
      <div
        style={{
          background: "#1a1d24",
          border: "1px solid #2a2d38",
          borderRadius: "8px",
          padding: "20px 22px",
          minWidth: "260px",
        }}
      >
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          Snooze change
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {presets.map((p) => (
            <button
              key={p.days}
              onClick={() => doSnooze(p.days)}
              disabled={loading}
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                color: "#e8eaf0",
                borderRadius: "4px",
                padding: "7px 12px",
                fontSize: "13px",
                cursor: loading ? "default" : "pointer",
                fontFamily: "inherit",
                textAlign: "left",
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
        {error && (
          <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#e84040" }}>
            {error}
          </p>
        )}
        <button
          onClick={onClose}
          style={{
            marginTop: "14px",
            background: "transparent",
            border: "none",
            color: "#565b6e",
            fontSize: "12px",
            cursor: "pointer",
            fontFamily: "inherit",
            padding: 0,
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Review row wrapper ────────────────────────────────────────────────────────

interface ReviewRowProps {
  change: ChangeListItem;
  token: string | null;
  onReviewed: (changeId: string) => void;
}

function ReviewRow({ change, token, onReviewed }: ReviewRowProps) {
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [showSnooze, setShowSnooze] = useState(false);

  const handleAck = async () => {
    setLoadingAction("ack");
    try {
      await acknowledgeChange(change.id, {}, token);
      onReviewed(change.id);
    } catch {
      // silently ignore — user can retry
    } finally {
      setLoadingAction(null);
    }
  };

  const handleExpected = async () => {
    setLoadingAction("expected");
    try {
      await markChangeExpected(change.id, {}, token);
      onReviewed(change.id);
    } catch {
      // silently ignore
    } finally {
      setLoadingAction(null);
    }
  };

  return (
    <>
      {showSnooze && (
        <SnoozeModal
          changeId={change.id}
          token={token}
          onSnoozed={() => {
            setShowSnooze(false);
            onReviewed(change.id);
          }}
          onClose={() => setShowSnooze(false)}
        />
      )}
      <div style={{ position: "relative" }}>
        <ChangeRow change={change} />
        {/* Quick-action bar — overlaid at bottom-right */}
        <div
          style={{
            position: "absolute",
            bottom: "9px",
            right: "16px",
            display: "flex",
            gap: "5px",
            alignItems: "center",
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <QuickActionButton
            label="✓ Acknowledge"
            color="#3ccf7e"
            onClick={handleAck}
            loading={loadingAction === "ack"}
            disabled={loadingAction !== null}
          />
          <QuickActionButton
            label="◎ Expected"
            color="#4f80f7"
            onClick={handleExpected}
            loading={loadingAction === "expected"}
            disabled={loadingAction !== null}
          />
          <QuickActionButton
            label="⏸ Snooze"
            color="#8b5cf6"
            onClick={() => setShowSnooze(true)}
            disabled={loadingAction !== null}
          />
        </div>
      </div>
    </>
  );
}

// ── Pagination ────────────────────────────────────────────────────────────────

function Pagination({
  page,
  total,
  pageSize,
  onPage,
}: {
  page: number;
  total: number;
  pageSize: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.ceil(total / pageSize);
  if (totalPages <= 1) return null;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "12px 16px",
        borderTop: "1px solid #2a2d38",
        fontSize: "12px",
        color: "#565b6e",
      }}
    >
      <span>
        Page {page} of {totalPages} · {total} total
      </span>
      <div style={{ display: "flex", gap: "6px" }}>
        <button
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          style={{
            background: "transparent",
            border: "1px solid #2a2d38",
            color: page <= 1 ? "#3a3d4a" : "#8b90a0",
            borderRadius: "4px",
            padding: "3px 10px",
            fontSize: "11px",
            cursor: page <= 1 ? "default" : "pointer",
            fontFamily: "inherit",
          }}
        >
          ← Prev
        </button>
        <button
          onClick={() => onPage(page + 1)}
          disabled={page >= totalPages}
          style={{
            background: "transparent",
            border: "1px solid #2a2d38",
            color: page >= totalPages ? "#3a3d4a" : "#8b90a0",
            borderRadius: "4px",
            padding: "3px 10px",
            fontSize: "11px",
            cursor: page >= totalPages ? "default" : "pointer",
            fontFamily: "inherit",
          }}
        >
          Next →
        </button>
      </div>
    </div>
  );
}

// ── Grouped change list ───────────────────────────────────────────────────────

function GroupedChangeList({
  changes,
  token,
  onReviewed,
}: {
  changes: ChangeListItem[];
  token: string | null;
  onReviewed: (id: string) => void;
}) {
  const critical = useMemo(
    () => changes.filter((c) => c.risk_level === "critical"),
    [changes],
  );
  const high = useMemo(
    () => changes.filter((c) => c.risk_level === "high"),
    [changes],
  );
  const other = useMemo(
    () => changes.filter((c) => c.risk_level !== "critical" && c.risk_level !== "high"),
    [changes],
  );

  // If only one risk level is present, skip grouping headers for clarity
  const multipleGroups =
    [critical, high, other].filter((g) => g.length > 0).length > 1;

  return (
    <div role="feed" aria-label="Changes needing review">
      {critical.length > 0 && (
        <>
          {multipleGroups && (
            <GroupHeader label="Critical" count={critical.length} color={RISK_COLOR.critical} />
          )}
          {critical.map((change) => (
            <ReviewRow key={change.id} change={change} token={token} onReviewed={onReviewed} />
          ))}
        </>
      )}
      {high.length > 0 && (
        <>
          {multipleGroups && (
            <GroupHeader label="High" count={high.length} color={RISK_COLOR.high} />
          )}
          {high.map((change) => (
            <ReviewRow key={change.id} change={change} token={token} onReviewed={onReviewed} />
          ))}
        </>
      )}
      {other.length > 0 && (
        <>
          {multipleGroups && (
            <GroupHeader label="Other" count={other.length} color="#8b90a0" />
          )}
          {other.map((change) => (
            <ReviewRow key={change.id} change={change} token={token} onReviewed={onReviewed} />
          ))}
        </>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NeedsReviewPage() {
  const [changes, setChanges]         = useState<ChangeListItem[]>([]);
  const [total, setTotal]             = useState(0);
  const [page, setPage]               = useState(1);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);
  const [token, setToken]             = useState<string | null>(null);
  const [riskFilter, setRiskFilter]   = useState<RiskFilter>("all");
  const { getToken, isLoaded } = useAuth();

  const fetchChanges = useCallback(
    async (targetPage: number) => {
      if (!isLoaded) return;
      setLoading(true);
      setError(null);
      try {
        const tok = await getToken();
        setToken(tok);
        const data = await getNeedsReviewChanges(
          { page: targetPage, page_size: PAGE_SIZE },
          tok,
        );
        setChanges(data.items);
        setTotal(data.total);
        setLastUpdatedAt(new Date());
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load changes.");
      } finally {
        setLoading(false);
      }
    },
    [isLoaded, getToken],
  );

  useEffect(() => {
    if (isLoaded) void fetchChanges(page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded, page]);

  // Remove a change from the list optimistically when reviewed
  const handleReviewed = useCallback((changeId: string) => {
    setChanges((prev) => prev.filter((c) => c.id !== changeId));
    setTotal((prev) => Math.max(0, prev - 1));
  }, []);

  // Client-side risk filter applied to the loaded page
  const filteredChanges = useMemo(() => {
    if (riskFilter === "all") return changes;
    return changes.filter((c) => (c.risk_level ?? "").toLowerCase() === riskFilter);
  }, [changes, riskFilter]);

  // Counts for the filter pill badges
  const filterCounts = useMemo(
    () => ({
      all:      changes.length,
      critical: changes.filter((c) => c.risk_level === "critical").length,
      high:     changes.filter((c) => c.risk_level === "high").length,
    }),
    [changes],
  );

  const isEmpty          = !loading && !error && changes.length === 0;
  const hasFilteredEmpty = !loading && !error && changes.length > 0 && filteredChanges.length === 0;

  return (
    <>
      <PageHeader
        title="Needs Review"
        description="High-risk configuration changes that have not been acknowledged, marked expected, or snoozed."
      />

      {/* ── Refresh bar ────────────────────────────────────────────────── */}
      <div
        className="flex items-center justify-between px-6 py-3"
        style={{ borderBottom: "1px solid #2a2d38" }}
      >
        <span style={{ fontSize: "11px", color: "#565b6e" }}>
          {loading
            ? "Loading…"
            : lastUpdatedAt
            ? `${total} change${total !== 1 ? "s" : ""} needing review · updated ${lastUpdatedAt.toLocaleTimeString()}`
            : ""}
        </span>
        <button
          onClick={() => void fetchChanges(page)}
          disabled={loading}
          aria-label="Refresh"
          style={{
            background: "transparent",
            border: "1px solid #2a2d38",
            color: "#8b90a0",
            borderRadius: "4px",
            padding: "3px 10px",
            fontSize: "11px",
            cursor: loading ? "default" : "pointer",
            fontFamily: "inherit",
          }}
        >
          ↻ Refresh
        </button>
      </div>

      <div className="px-6 py-6">
        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}

        {/* ── Empty state ─────────────────────────────────────────────── */}
        {isEmpty && (
          <div
            style={{
              background: "rgba(60,207,126,0.05)",
              border: "1px solid rgba(60,207,126,0.25)",
              borderRadius: "6px",
              padding: "28px 24px",
            }}
          >
            <div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}>
              <span
                aria-hidden="true"
                style={{
                  flexShrink: 0,
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: "#3ccf7e",
                  marginTop: "3px",
                }}
              />
              <div>
                <p style={{ margin: "0 0 3px", fontSize: "13px", fontWeight: 600, color: "#3ccf7e" }}>
                  Nothing needs review.
                </p>
                <p style={{ margin: "0 0 14px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
                  High and critical changes that need review will appear here. Low and medium
                  changes are recorded in the Timeline but do not require review.
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "12px" }}>
                  <Link
                    href="/timeline"
                    style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
                  >
                    View Timeline →
                  </Link>
                  <Link
                    href="/settings/workspace/notifications"
                    style={{ fontSize: "12px", color: "#8b90a0", textDecoration: "none" }}
                  >
                    Check notification settings
                  </Link>
                  <Link
                    href="/integrations"
                    style={{ fontSize: "12px", color: "#8b90a0", textDecoration: "none" }}
                  >
                    Run a sync
                  </Link>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Change feed ─────────────────────────────────────────────── */}
        {!loading && !error && changes.length > 0 && (
          <>
            {/* Summary strip */}
            <SummaryStrip changes={changes} total={total} />

            {/* Risk filter pills */}
            <RiskFilterPills
              current={riskFilter}
              counts={filterCounts}
              onChange={(f) => setRiskFilter(f)}
            />

            {/* Filtered-empty state */}
            {hasFilteredEmpty ? (
              <div
                style={{
                  padding: "20px 16px",
                  background: "#13151a",
                  border: "1px solid #2a2d38",
                  borderRadius: "6px",
                  textAlign: "center",
                }}
              >
                <p style={{ margin: "0 0 6px", fontSize: "13px", color: "#8b90a0" }}>
                  No {riskFilter} changes in this page.
                </p>
                <button
                  onClick={() => setRiskFilter("all")}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#4f80f7",
                    fontSize: "12px",
                    cursor: "pointer",
                    fontFamily: "inherit",
                    padding: 0,
                  }}
                >
                  Clear filter →
                </button>
              </div>
            ) : (
              <div
                style={{
                  background: "#13151a",
                  border: "1px solid #2a2d38",
                  borderRadius: "6px",
                  overflow: "hidden",
                }}
              >
                {/* Header */}
                <div
                  style={{
                    padding: "10px 16px 8px",
                    borderBottom: "1px solid #2a2d38",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                  }}
                >
                  <span
                    style={{
                      fontSize: "11px",
                      color: "#565b6e",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      fontWeight: 500,
                    }}
                  >
                    {riskFilter === "all"
                      ? `Review queue · ${total}`
                      : `${riskFilter} · ${filteredChanges.length}`}
                  </span>
                  <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
                    ✓ Ack &nbsp; ◎ Expected &nbsp; ⏸ Snooze
                  </span>
                </div>

                {/* Grouped rows */}
                <GroupedChangeList
                  changes={filteredChanges}
                  token={token}
                  onReviewed={handleReviewed}
                />

                <Pagination
                  page={page}
                  total={total}
                  pageSize={PAGE_SIZE}
                  onPage={(p) => {
                    setPage(p);
                    void fetchChanges(p);
                  }}
                />
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
