"use client";

import { useEffect, useRef, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type { Integration } from "@/types";
import StatusBadge from "@/components/common/StatusBadge";
import { formatRelativeTime } from "@/lib/utils";
import { getSyncStatus, triggerSync } from "@/lib/api";

// ── Per-row sync state ────────────────────────────────────────────────────────

interface SyncRowState {
  /** True while the Celery task is pending / running (still polling). */
  polling: boolean;
  /** Terminal success message shown after completion. */
  result: string | null;
  /** Terminal error shown after failure or network problem. */
  error: string | null;
}

// ── Component ─────────────────────────────────────────────────────────────────

interface IntegrationListProps {
  integrations: Integration[];
  /** Called when a sync run reaches a terminal state (completed or failed). */
  onSyncComplete?: () => void;
}

const POLL_INTERVAL_MS = 2000;
const MAX_POLLS = 90; // ~3 minutes before giving up

export default function IntegrationList({
  integrations,
  onSyncComplete,
}: IntegrationListProps) {
  const [syncStates, setSyncStates] = useState<Record<string, SyncRowState>>({});
  const mountedRef = useRef(true);
  const { getToken } = useAuth();

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  if (integrations.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-16 gap-2"
        style={{ color: "#8b90a0", fontSize: "14px" }}
      >
        <span>No integrations connected yet.</span>
        <span style={{ fontSize: "12px" }}>
          Use the form above to connect your first Cloudflare integration.
        </span>
      </div>
    );
  }

  function setRowState(integrationId: string, patch: Partial<SyncRowState>) {
    setSyncStates((prev) => ({
      ...prev,
      [integrationId]: { ...(prev[integrationId] ?? { polling: false, result: null, error: null }), ...patch },
    }));
  }

  async function handleSync(integrationId: string) {
    setRowState(integrationId, { polling: true, result: null, error: null });

    let syncRunId: string;

    try {
      const token = await getToken();
      const run = await triggerSync(integrationId, token);
      syncRunId = run.id;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to start sync.";
      setRowState(integrationId, { polling: false, error: msg, result: null });
      return;
    }

    // ── Poll until terminal state ──────────────────────────────────────────
    let polls = 0;

    function poll() {
      setTimeout(async () => {
        if (!mountedRef.current) return;

        polls++;

        try {
          const token = await getToken();
          const run = await getSyncStatus(syncRunId, token);

          if (run.status === "completed") {
            const snaps = run.snapshot_count ?? 0;
            const changes = run.change_count ?? 0;
            const msg =
              snaps === 0
                ? "Sync complete — no new changes detected."
                : `Sync complete — ${snaps} snapshot${snaps === 1 ? "" : "s"}, ${changes} change${changes === 1 ? "" : "s"} detected.`;

            if (mountedRef.current) {
              setRowState(integrationId, { polling: false, result: msg, error: null });
              onSyncComplete?.();
            }
            return;
          }

          if (run.status === "failed") {
            const msg = run.error_message
              ? `Sync failed: ${run.error_message}`
              : "Sync failed. Check that the Celery worker is running.";

            if (mountedRef.current) {
              setRowState(integrationId, { polling: false, error: msg, result: null });
              onSyncComplete?.();
            }
            return;
          }

          // Still pending / running — keep polling
          if (polls < MAX_POLLS && mountedRef.current) {
            poll();
          } else if (mountedRef.current) {
            setRowState(integrationId, {
              polling: false,
              error: "Sync timed out waiting for completion. The worker may still be running.",
              result: null,
            });
          }
        } catch (err) {
          if (mountedRef.current) {
            const msg =
              err instanceof Error ? err.message : "Lost connection while polling sync status.";
            setRowState(integrationId, { polling: false, error: msg, result: null });
          }
        }
      }, POLL_INTERVAL_MS);
    }

    poll();
  }

  return (
    <div
      style={{ border: "1px solid #2a2d38", borderRadius: "6px", overflow: "hidden" }}
    >
      {/* Column header */}
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
        <span className="flex-1">Integration</span>
        <span style={{ width: "100px" }}>Provider</span>
        <span style={{ width: "150px" }}>Last Sync</span>
        <span style={{ width: "72px" }}>Status</span>
        <span style={{ width: "96px" }}></span>
      </div>

      {integrations.map((integration) => {
        const state = syncStates[integration.id] ?? {
          polling: false,
          result: null,
          error: null,
        };

        return (
          <div
            key={integration.id}
            className="flex flex-col hover:bg-surface3"
            style={{ borderBottom: "1px solid #2a2d38" }}
          >
            {/* Main row */}
            <div className="flex items-center gap-4 px-4 py-3">
              {/* Name */}
              <span
                className="flex-1 truncate"
                style={{ fontSize: "13px", color: "#e8eaf0" }}
              >
                {integration.display_name}
              </span>

              {/* Provider */}
              <span
                className="shrink-0 uppercase tracking-wider"
                style={{ fontSize: "11px", color: "#8b90a0", width: "100px" }}
              >
                {integration.provider}
              </span>

              {/* Last synced */}
              <span
                className="shrink-0 tabular-nums"
                style={{ fontSize: "12px", color: "#8b90a0", width: "150px" }}
              >
                {integration.last_synced_at
                  ? formatRelativeTime(integration.last_synced_at)
                  : "Never"}
              </span>

              {/* Status badge */}
              <div className="shrink-0" style={{ width: "72px" }}>
                <StatusBadge status={integration.status} />
              </div>

              {/* Sync Now button */}
              <div className="shrink-0" style={{ width: "96px" }}>
                <button
                  onClick={() => handleSync(integration.id)}
                  disabled={state.polling}
                  style={{
                    width: "100%",
                    textAlign: "center",
                    padding: "5px 8px",
                    borderRadius: "6px",
                    background: state.polling ? "#22252f" : "#1e2030",
                    border: "1px solid #3a3d4a",
                    color: state.polling ? "#565b6e" : "#b0b5c4",
                    cursor: state.polling ? "not-allowed" : "pointer",
                    fontSize: "12px",
                    fontFamily: "inherit",
                  }}
                >
                  {state.polling ? "Syncing…" : "Sync Now"}
                </button>
              </div>
            </div>

            {/* Feedback row — shown after terminal state */}
            {(state.result || state.error) && (
              <div
                className="px-4 pb-3"
                style={{
                  fontSize: "12px",
                  color: state.error ? "#e84040" : "#3ccf7e",
                }}
              >
                {state.error ?? state.result}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
