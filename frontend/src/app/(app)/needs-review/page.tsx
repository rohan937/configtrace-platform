"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type { ChangeListItem, ChangeReviewResponse } from "@/types";
import {
  getNeedsReviewChanges,
  acknowledgeChange,
  markChangeExpected,
  snoozeChange,
} from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import ChangeRow from "@/components/changes/ChangeRow";

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

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
        <p
          style={{
            margin: "0 0 14px",
            fontSize: "13px",
            fontWeight: 600,
            color: "#e8eaf0",
          }}
        >
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
          <p
            style={{
              margin: "10px 0 0",
              fontSize: "11px",
              color: "#e84040",
            }}
          >
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
        {/* Quick-action bar overlaid at bottom-right of the row */}
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

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NeedsReviewPage() {
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);
  const [token, setToken] = useState<string | null>(null);
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

  // Remove a change from the list optimistically when it's reviewed
  const handleReviewed = useCallback(
    (changeId: string) => {
      setChanges((prev) => prev.filter((c) => c.id !== changeId));
      setTotal((prev) => Math.max(0, prev - 1));
    },
    [],
  );

  const isEmpty = !loading && !error && changes.length === 0;

  return (
    <>
      <PageHeader
        title="Needs Review"
        description="Changes that have not been acknowledged, marked expected, or snoozed."
      />

      {/* Refresh bar */}
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

        {/* Empty state */}
        {isEmpty && (
          <div
            style={{
              background: "rgba(60,207,126,0.05)",
              border: "1px solid rgba(60,207,126,0.25)",
              borderRadius: "6px",
              padding: "28px 24px",
              display: "flex",
              alignItems: "center",
              gap: "14px",
            }}
          >
            <span
              aria-hidden="true"
              style={{
                flexShrink: 0,
                width: "10px",
                height: "10px",
                borderRadius: "50%",
                background: "#3ccf7e",
              }}
            />
            <div>
              <p
                style={{
                  margin: "0 0 3px",
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "#3ccf7e",
                }}
              >
                All caught up!
              </p>
              <p style={{ margin: 0, fontSize: "12px", color: "#565b6e" }}>
                No changes need review right now. New changes appear here when they
                are detected.
              </p>
            </div>
          </div>
        )}

        {/* Change feed with quick-action buttons */}
        {!loading && !error && changes.length > 0 && (
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
                padding: "12px 16px 10px",
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
                Needs review · {total}
              </span>
              <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
                Quick actions: ✓ Ack &nbsp; ◎ Expected &nbsp; ⏸ Snooze
              </span>
            </div>

            {/* Rows */}
            <div role="feed" aria-label="Changes needing review">
              {changes.map((change) => (
                <ReviewRow
                  key={change.id}
                  change={change}
                  token={token}
                  onReviewed={handleReviewed}
                />
              ))}
            </div>

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
      </div>
    </>
  );
}
