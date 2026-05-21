"use client";

import { useState } from "react";
import type { Integration } from "@/types";
import StatusBadge from "@/components/common/StatusBadge";
import { formatRelativeTime } from "@/lib/utils";
import { triggerSync } from "@/lib/api";

interface SyncState {
  syncing: boolean;
  result: string | null;
  error: string | null;
}

interface IntegrationListProps {
  integrations: Integration[];
}

export default function IntegrationList({ integrations }: IntegrationListProps) {
  const [syncStates, setSyncStates] = useState<Record<string, SyncState>>({});

  if (integrations.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-16 gap-2"
        style={{ color: "#8b90a0", fontSize: "14px" }}
      >
        <span>No integrations configured.</span>
        <span style={{ fontSize: "12px" }}>
          Integrations are added via the API or CLI.
        </span>
      </div>
    );
  }

  async function handleSync(integrationId: string) {
    setSyncStates((prev) => ({
      ...prev,
      [integrationId]: { syncing: true, result: null, error: null },
    }));

    try {
      const run = await triggerSync(integrationId);
      setSyncStates((prev) => ({
        ...prev,
        [integrationId]: {
          syncing: false,
          result: `Sync started (run ${run.id.slice(0, 8)}…)`,
          error: null,
        },
      }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setSyncStates((prev) => ({
        ...prev,
        [integrationId]: { syncing: false, result: null, error: msg },
      }));
    }
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
        <span className="flex-1">Integration</span>
        <span style={{ width: "100px" }}>Provider</span>
        <span style={{ width: "140px" }}>Last Sync</span>
        <span style={{ width: "80px" }}>Status</span>
        <span style={{ width: "90px" }}></span>
      </div>

      {integrations.map((integration) => {
        const state = syncStates[integration.id];
        const isSyncing = state?.syncing ?? false;

        return (
          <div
            key={integration.id}
            className="flex flex-col gap-1 px-4 py-3 hover:bg-surface3"
            style={{ borderBottom: "1px solid #2a2d38" }}
          >
            {/* Main row */}
            <div className="flex items-center gap-4">
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
                style={{ fontSize: "12px", color: "#8b90a0", width: "140px" }}
              >
                {integration.last_synced_at
                  ? formatRelativeTime(integration.last_synced_at)
                  : "Never"}
              </span>

              {/* Status badge */}
              <div className="shrink-0" style={{ width: "80px" }}>
                <StatusBadge status={integration.status} />
              </div>

              {/* Sync Now button */}
              <div className="shrink-0" style={{ width: "90px" }}>
                <button
                  onClick={() => handleSync(integration.id)}
                  disabled={isSyncing}
                  className="w-full text-center py-1 px-2 rounded text-xs"
                  style={{
                    background: isSyncing ? "#2a2d38" : "#1e2030",
                    border: "1px solid #3a3d4a",
                    color: isSyncing ? "#8b90a0" : "#b0b5c4",
                    cursor: isSyncing ? "not-allowed" : "pointer",
                    fontSize: "12px",
                  }}
                >
                  {isSyncing ? "Syncing…" : "Sync Now"}
                </button>
              </div>
            </div>

            {/* Feedback row */}
            {(state?.result || state?.error) && (
              <div
                className="pl-0"
                style={{
                  fontSize: "12px",
                  color: state?.error ? "#e05252" : "#4ade80",
                }}
              >
                {state?.error ?? state?.result}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
