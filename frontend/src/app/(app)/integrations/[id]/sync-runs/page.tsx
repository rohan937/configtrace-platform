"use client";

/**
 * Sync history page — M32.
 *
 * Full paginated sync-run history for a single integration.
 * URL: /integrations/[id]/sync-runs
 *
 * Features:
 *   - Paginated table (25 rows per page)
 *   - Status filter: all | completed | failed
 *   - Trigger filter: all | manual | scheduled
 *   - Failure detail rows (category, code, recommended action)
 *   - "← Back to integration" breadcrumb
 */

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { Integration, SyncRun, SyncRunListResponse } from "@/types";
import { getIntegration, getIntegrationSyncRuns } from "@/lib/api";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { formatRelativeTime, formatAbsoluteTime } from "@/lib/utils";

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDuration(startedAt: string | null, completedAt: string | null): string | null {
  if (!startedAt || !completedAt) return null;
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  if (ms < 0) return null;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
}

function StatusPill({ status }: { status: string }) {
  const colors: Record<string, { bg: string; text: string }> = {
    completed: { bg: "rgba(60,207,126,0.1)", text: "#3ccf7e" },
    failed:    { bg: "rgba(232,64,64,0.1)",  text: "#e84040" },
    running:   { bg: "rgba(79,128,247,0.1)", text: "#4f80f7" },
    pending:   { bg: "rgba(139,144,160,0.1)", text: "#8b90a0" },
  };
  const c = colors[status] ?? { bg: "rgba(139,144,160,0.1)", text: "#8b90a0" };
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 7px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 600,
        background: c.bg,
        color: c.text,
      }}
    >
      {status}
    </span>
  );
}

// ── Filter controls ───────────────────────────────────────────────────────────

function FilterBar({
  status,
  trigger,
  onStatusChange,
  onTriggerChange,
}: {
  status: string;
  trigger: string;
  onStatusChange: (v: string) => void;
  onTriggerChange: (v: string) => void;
}) {
  const chipStyle = (active: boolean): React.CSSProperties => ({
    padding: "4px 10px",
    borderRadius: "4px",
    border: active ? "1px solid #4f80f7" : "1px solid #2a2d38",
    background: active ? "rgba(79,128,247,0.12)" : "transparent",
    color: active ? "#4f80f7" : "#8b90a0",
    fontSize: "12px",
    cursor: "pointer",
    fontFamily: "inherit",
  });

  const statuses = ["", "completed", "failed"] as const;
  const statusLabels: Record<string, string> = { "": "All status", completed: "Completed", failed: "Failed" };

  const triggers = ["", "manual", "scheduled"] as const;
  const triggerLabels: Record<string, string> = { "": "All types", manual: "Manual", scheduled: "Scheduled" };

  return (
    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>Filter:</span>
      {statuses.map((s) => (
        <button key={s || "all-status"} style={chipStyle(status === s)} onClick={() => onStatusChange(s)}>
          {statusLabels[s]}
        </button>
      ))}
      <span style={{ fontSize: "12px", color: "#2a2d38" }}>|</span>
      {triggers.map((t) => (
        <button key={t || "all-trigger"} style={chipStyle(trigger === t)} onClick={() => onTriggerChange(t)}>
          {triggerLabels[t]}
        </button>
      ))}
    </div>
  );
}

// ── Run table ─────────────────────────────────────────────────────────────────

function RunRow({ run }: { run: SyncRun }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetail = run.status === "failed" && (run.error_message || run.recommended_action);

  return (
    <>
      <tr
        style={{
          borderBottom: "1px solid #1e2030",
          background: run.status === "failed" ? "rgba(232,64,64,0.03)" : "transparent",
          cursor: hasDetail ? "pointer" : "default",
        }}
        onClick={() => hasDetail && setExpanded((e) => !e)}
        title={hasDetail ? "Click to expand failure details" : undefined}
      >
        <td style={{ padding: "8px 8px 8px 0", color: "#8b90a0", whiteSpace: "nowrap" }}
            title={run.started_at ? formatAbsoluteTime(run.started_at) : ""}>
          {run.started_at ? formatRelativeTime(run.started_at) : "—"}
        </td>
        <td style={{ padding: "8px 8px 8px 0", color: "#565b6e" }}>
          {run.triggered_by === "scheduled" ? "scheduled" : "manual"}
        </td>
        <td style={{ padding: "8px 8px 8px 0" }}>
          <StatusPill status={run.status} />
        </td>
        <td style={{ padding: "8px 8px 8px 0", textAlign: "right", color: "#565b6e" }}>
          {run.snapshot_count ?? "—"}
        </td>
        <td style={{ padding: "8px 8px 8px 0", textAlign: "right", color: "#565b6e" }}>
          {run.change_count != null ? run.change_count : "—"}
        </td>
        <td style={{ padding: "8px 0", textAlign: "right", color: "#565b6e" }}>
          {formatDuration(run.started_at, run.completed_at) ?? "—"}
        </td>
        <td style={{ padding: "8px 0 8px 8px", textAlign: "center", color: "#565b6e", width: "20px" }}>
          {hasDetail ? (expanded ? "▲" : "▼") : null}
        </td>
      </tr>
      {expanded && hasDetail && (
        <tr style={{ background: "rgba(232,64,64,0.05)" }}>
          <td
            colSpan={7}
            style={{ padding: "10px 12px", borderBottom: "1px solid #1e2030" }}
          >
            {run.failure_category && (
              <div style={{ marginBottom: "4px" }}>
                <span style={{ fontSize: "10px", color: "#565b6e", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  Category
                </span>{" "}
                <span style={{ fontSize: "12px", color: "#8b90a0" }}>
                  {run.failure_category}
                  {run.error_code && run.error_code !== run.failure_category
                    ? ` · ${run.error_code}` : ""}
                </span>
              </div>
            )}
            {run.error_message && (
              <div style={{ marginBottom: "4px" }}>
                <span style={{ fontSize: "10px", color: "#565b6e", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  Error
                </span>{" "}
                <span style={{ fontSize: "12px", color: "#e84040" }}>{run.error_message}</span>
              </div>
            )}
            {run.recommended_action && (
              <div style={{ marginTop: "6px" }}>
                <span style={{ fontSize: "10px", color: "#565b6e", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  Recommended action
                </span>{" "}
                <span style={{ fontSize: "12px", color: "#f5a623" }}>{run.recommended_action}</span>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function RunsTable({ runs }: { runs: SyncRun[] }) {
  if (runs.length === 0) {
    return (
      <p style={{ fontSize: "13px", color: "#565b6e", margin: "24px 0" }}>
        No sync runs match the selected filters.
      </p>
    );
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
        <thead>
          <tr
            style={{
              borderBottom: "1px solid #2a2d38",
              color: "#565b6e",
              textTransform: "uppercase",
              fontSize: "10px",
              letterSpacing: "0.05em",
            }}
          >
            <th style={{ textAlign: "left", padding: "4px 8px 8px 0", fontWeight: 500 }}>When</th>
            <th style={{ textAlign: "left", padding: "4px 8px 8px 0", fontWeight: 500 }}>Type</th>
            <th style={{ textAlign: "left", padding: "4px 8px 8px 0", fontWeight: 500 }}>Status</th>
            <th style={{ textAlign: "right", padding: "4px 8px 8px 0", fontWeight: 500 }}>Snaps</th>
            <th style={{ textAlign: "right", padding: "4px 8px 8px 0", fontWeight: 500 }}>Changes</th>
            <th style={{ textAlign: "right", padding: "4px 8px 8px 0", fontWeight: 500 }}>Duration</th>
            <th style={{ width: "20px" }}></th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <RunRow key={run.id} run={run} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Paginator ─────────────────────────────────────────────────────────────────

function Paginator({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  onPageChange: (p: number) => void;
}) {
  if (totalPages <= 1) return null;

  const btnStyle = (disabled: boolean): React.CSSProperties => ({
    padding: "4px 10px",
    borderRadius: "4px",
    border: "1px solid #2a2d38",
    background: "transparent",
    color: disabled ? "#3a3d4a" : "#8b90a0",
    fontSize: "12px",
    cursor: disabled ? "not-allowed" : "pointer",
    fontFamily: "inherit",
  });

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "16px" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>
        {start}–{end} of {total}
      </span>
      <div style={{ display: "flex", gap: "8px" }}>
        <button
          style={btnStyle(page <= 1)}
          onClick={() => page > 1 && onPageChange(page - 1)}
          disabled={page <= 1}
        >
          ← Prev
        </button>
        <span style={{ fontSize: "12px", color: "#8b90a0", padding: "4px 8px" }}>
          {page} / {totalPages}
        </span>
        <button
          style={btnStyle(page >= totalPages)}
          onClick={() => page < totalPages && onPageChange(page + 1)}
          disabled={page >= totalPages}
        >
          Next →
        </button>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SyncRunsPage() {
  const params = useParams();
  const router = useRouter();
  const { getToken, isLoaded } = useAuth();

  const integrationId = typeof params.id === "string" ? params.id : "";

  const [integration, setIntegration] = useState<Integration | null>(null);
  const [data, setData] = useState<SyncRunListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [triggerFilter, setTriggerFilter] = useState("");

  const fetchPage = useCallback(
    async (p: number, sf: string, tf: string) => {
      setLoading(true);
      try {
        const token = await getToken();
        const [integData, runsData] = await Promise.all([
          integration ? Promise.resolve(integration) : getIntegration(integrationId, token),
          getIntegrationSyncRuns(
            integrationId,
            {
              page: p,
              page_size: 25,
              ...(sf ? { status: sf } : {}),
              ...(tf ? { trigger: tf } : {}),
            },
            token,
          ),
        ]);
        setIntegration(integData as Integration);
        setData(runsData);
        setError(null);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to load sync runs.";
        if (msg.includes("404")) {
          router.replace("/integrations");
          return;
        }
        setError(msg);
      } finally {
        setLoading(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [integrationId, getToken, router],
  );

  useEffect(() => {
    if (!isLoaded || !integrationId) return;
    void fetchPage(page, statusFilter, triggerFilter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded, page, statusFilter, triggerFilter]);

  const handleStatusChange = (s: string) => {
    setPage(1);
    setStatusFilter(s);
  };
  const handleTriggerChange = (t: string) => {
    setPage(1);
    setTriggerFilter(t);
  };

  if (!isLoaded || (loading && !data)) {
    return (
      <div className="px-6 py-12">
        <LoadingState />
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-6 py-8">
        <ErrorState message={error} />
      </div>
    );
  }

  const title = integration
    ? `${integration.display_name} · Sync history`
    : "Sync history";

  return (
    <div className="px-6 py-8" style={{ maxWidth: "900px" }}>
      {/* Breadcrumb */}
      <div style={{ marginBottom: "20px" }}>
        <Link
          href={`/integrations/${integrationId}`}
          style={{ fontSize: "13px", color: "#4f80f7", textDecoration: "none" }}
        >
          ← {integration?.display_name ?? "Integration"}
        </Link>
      </div>

      <h1 style={{ fontSize: "18px", fontWeight: 600, color: "#e8eaf0", marginBottom: "4px" }}>
        Sync history
      </h1>
      {integration && (
        <p style={{ fontSize: "13px", color: "#8b90a0", marginBottom: "20px" }}>
          {integration.display_name}
        </p>
      )}

      {/* Needs-attention warning */}
      {integration?.needs_attention && (
        <div
          style={{
            padding: "10px 14px",
            marginBottom: "16px",
            background: "rgba(245,166,35,0.08)",
            border: "1px solid rgba(245,166,35,0.3)",
            borderRadius: "6px",
            fontSize: "13px",
            color: "#f5a623",
          }}
        >
          ⚠ {integration.consecutive_failure_count} consecutive scheduled syncs have failed.{" "}
          Check the failure details below for remediation steps.
        </div>
      )}

      {/* Filters */}
      <div style={{ marginBottom: "16px" }}>
        <FilterBar
          status={statusFilter}
          trigger={triggerFilter}
          onStatusChange={handleStatusChange}
          onTriggerChange={handleTriggerChange}
        />
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ padding: "24px 0" }}>
          <LoadingState />
        </div>
      ) : (
        <>
          <RunsTable runs={data?.sync_runs ?? []} />
          {data && (
            <Paginator
              page={data.page}
              totalPages={data.total_pages}
              total={data.total}
              pageSize={data.page_size}
              onPageChange={setPage}
            />
          )}
        </>
      )}
    </div>
  );
}
