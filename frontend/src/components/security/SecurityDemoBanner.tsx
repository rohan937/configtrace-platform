"use client";

/**
 * SecurityDemoBanner (M62.2).
 *
 * Opt-in Security Exposure demo-data control. Renders:
 *   • a "Load demo data" CTA when the workspace has no findings and no demo data;
 *   • a "Demo data loaded" banner with a "Clear demo data" action when demo data
 *     exists.
 * Otherwise renders nothing (real findings present, no demo data).
 *
 * Wording stays safe: "demo data", "safe demo dataset", "preview".
 */

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";

import type { SecurityDemoDataStatus } from "@/types";
import {
  getSecurityDemoDataStatus,
  seedSecurityDemoData,
  clearSecurityDemoData,
} from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { canManageDemoData } from "@/lib/workspacePermissions";

export default function SecurityDemoBanner({
  findingsEmpty,
  onChanged,
}: {
  /** True when the page has no findings to show (drives the load CTA). */
  findingsEmpty: boolean;
  /** Called after demo data is seeded/cleared so the host page can refresh. */
  onChanged?: () => void;
}) {
  const { getToken } = useAuth();
  const { role } = useWorkspace();
  const canManage = canManageDemoData(role);
  const [status, setStatus] = useState<SecurityDemoDataStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const token = await getToken();
      setStatus(await getSecurityDemoDataStatus(token));
    } catch {
      // Non-fatal: hide the banner if status can't be read.
      setStatus(null);
    }
  }, [getToken]);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const seed = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      const s = await seedSecurityDemoData(token);
      setStatus(s);
      onChanged?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load demo data.");
    } finally {
      setBusy(false);
    }
  }, [getToken, onChanged]);

  const clear = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      await clearSecurityDemoData(token);
      setStatus({
        exists: false,
        finding_count: 0,
        active_count: 0,
        resolved_count: 0,
        accepted_count: 0,
        snoozed_count: 0,
      });
      onChanged?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not clear demo data.");
    } finally {
      setBusy(false);
    }
  }, [getToken, onChanged]);

  if (status === null) return null;

  // Demo data present → show the "loaded" banner with a clear action.
  if (status.exists) {
    return (
      <div
        className="bg-surface1 border border-border"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          flexWrap: "wrap",
          borderRadius: "10px",
          padding: "10px 14px",
          marginBottom: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
          <span
            style={{
              fontSize: "11px",
              fontWeight: 700,
              letterSpacing: "0.03em",
              textTransform: "uppercase",
              color: "#6b9cf8",
              background: "rgba(107,156,248,0.12)",
              border: "1px solid rgba(107,156,248,0.4)",
              borderRadius: "6px",
              padding: "2px 8px",
              whiteSpace: "nowrap",
            }}
          >
            Demo data loaded
          </span>
          <span style={{ fontSize: "12.5px", color: "#8b90a0" }}>
            Showing {status.finding_count} sample findings. This is a safe preview,
            not data from connected providers.
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {error ? <span style={{ fontSize: "12px", color: "#e07a5f" }}>{error}</span> : null}
          {!canManage ? (
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>
              Ask a workspace admin to clear demo data.
            </span>
          ) : (
            <button
              type="button"
              onClick={clear}
              disabled={busy}
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: "#8b90a0",
                background: "transparent",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "6px 12px",
                cursor: busy ? "wait" : "pointer",
                opacity: busy ? 0.6 : 1,
                fontFamily: "inherit",
              }}
            >
              {busy ? "Working…" : "Clear demo data"}
            </button>
          )}
        </div>
      </div>
    );
  }

  // No demo data: only offer the load CTA when the page is otherwise empty.
  if (!findingsEmpty) return null;

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "20px 22px", marginBottom: "16px" }}
    >
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>
        Explore Security Exposure with demo data
      </div>
      <p style={{ fontSize: "13px", color: "#8b90a0", margin: "8px 0 14px", lineHeight: 1.6, maxWidth: "640px" }}>
        Load a safe demo dataset to preview findings, assets, timelines, review
        workflows, and reports without connecting real providers. You can clear it
        any time.
      </p>
      {error ? (
        <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 10px" }}>{error}</p>
      ) : null}
      {canManage ? (
        <button
          type="button"
          onClick={seed}
          disabled={busy}
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: "#fff",
            background: "#6b9cf8",
            border: "1px solid #6b9cf8",
            borderRadius: "8px",
            padding: "8px 16px",
            cursor: busy ? "wait" : "pointer",
            opacity: busy ? 0.6 : 1,
            fontFamily: "inherit",
          }}
        >
          {busy ? "Loading…" : "Load demo data"}
        </button>
      ) : (
        <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: 0 }}>
          Ask a workspace admin to load demo data.
        </p>
      )}
    </div>
  );
}
