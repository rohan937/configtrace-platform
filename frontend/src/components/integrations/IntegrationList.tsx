"use client";

import { useEffect, useRef, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type { Integration } from "@/types";
import StatusBadge from "@/components/common/StatusBadge";
import { formatRelativeTime } from "@/lib/utils";
import { getSyncStatus, patchIntegration, triggerSync } from "@/lib/api";
import RenameIntegrationModal from "./RenameIntegrationModal";
import DeleteIntegrationModal from "./DeleteIntegrationModal";
import ReconnectIntegrationModal from "./ReconnectIntegrationModal";

// ── Providers that have live sync available ───────────────────────────────────
// Used to gate the "Live / webhook sync: coming soon" copy.
// Both current providers have scheduled polling but not true live/webhook sync.
const PROVIDERS_WITH_LIVE_SYNC: string[] = [];

// ── Sync interval display helper ──────────────────────────────────────────────

function formatInterval(minutes: number | null): string {
  const m = minutes ?? 60;
  if (m < 60) return `every ${m} min`;
  return "every 1 hour";
}

// ── Per-row sync state ────────────────────────────────────────────────────────

interface SyncRowState {
  polling: boolean;
  result: string | null;
  error: string | null;
}

// ── Kebab menu ────────────────────────────────────────────────────────────────

interface KebabMenuProps {
  integration: Integration;
  onRename: () => void;
  onTogglePause: () => void;
  onUpdateToken: () => void;
  onDelete: () => void;
  busy: boolean;
}

function KebabMenu({ integration, onRename, onTogglePause, onUpdateToken, onDelete, busy }: KebabMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handle(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, [open]);

  const isPaused = integration.status === "paused";

  const menuItems: { label: string; action: () => void; danger?: boolean }[] = [
    { label: "Rename", action: onRename },
    { label: isPaused ? "Resume" : "Pause", action: onTogglePause },
    { label: "Update token", action: onUpdateToken },
    { label: "Delete", action: onDelete, danger: true },
  ];

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        disabled={busy}
        title="Integration options"
        style={{
          background: "transparent",
          border: "1px solid transparent",
          borderRadius: "4px",
          color: "#565b6e",
          cursor: busy ? "not-allowed" : "pointer",
          padding: "4px 6px",
          fontSize: "16px",
          lineHeight: 1,
          fontFamily: "inherit",
          display: "flex",
          alignItems: "center",
        }}
        onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "#3a3d4a"; }}
        onMouseOut={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "transparent"; }}
      >
        ⋮
      </button>
      {open && (
        <div
          style={{
            position: "absolute",
            right: 0,
            top: "100%",
            marginTop: "4px",
            background: "#1a1d26",
            border: "1px solid #2a2d38",
            borderRadius: "6px",
            zIndex: 100,
            minWidth: "160px",
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
            overflow: "hidden",
          }}
        >
          {menuItems.map((item) => (
            <button
              key={item.label}
              onClick={() => { setOpen(false); item.action(); }}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                background: "transparent",
                border: "none",
                padding: "9px 14px",
                fontSize: "13px",
                color: item.danger ? "#e84040" : "#b0b5c4",
                cursor: "pointer",
                fontFamily: "inherit",
              }}
              onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "#22252f"; }}
              onMouseOut={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; }}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Sync interval selector ────────────────────────────────────────────────────

const INTERVAL_OPTIONS = [5, 10, 15, 30, 60] as const;

interface SyncIntervalSelectorProps {
  integration: Integration;
  onChanged: (updated: Integration) => void;
}

function SyncIntervalSelector({ integration, onChanged }: SyncIntervalSelectorProps) {
  const [saving, setSaving] = useState(false);
  const { getToken } = useAuth();

  async function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const minutes = Number(e.target.value);
    setSaving(true);
    try {
      const token = await getToken();
      const updated = await patchIntegration(
        integration.id,
        { sync_interval_minutes: minutes },
        token,
      );
      onChanged(updated);
    } catch {
      // Silent — the select reverts on next render
    } finally {
      setSaving(false);
    }
  }

  const currentValue = integration.sync_interval_minutes ?? 60;

  return (
    <select
      value={currentValue}
      onChange={handleChange}
      disabled={saving || integration.status === "paused"}
      title="Scheduled sync interval"
      style={{
        background: "#1c1e26",
        border: "1px solid #2a2d38",
        borderRadius: "4px",
        color: saving ? "#565b6e" : "#8b90a0",
        fontSize: "11px",
        padding: "1px 4px",
        cursor: saving ? "wait" : "pointer",
        fontFamily: "inherit",
      }}
    >
      {INTERVAL_OPTIONS.map((m) => (
        <option key={m} value={m}>
          {m < 60 ? `${m} min` : "1 hour"}
        </option>
      ))}
    </select>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

type ModalType = "rename" | "delete" | "reconnect" | null;

interface IntegrationListProps {
  integrations: Integration[];
  onSyncComplete?: () => void;
  /** Called after rename, pause/resume, delete, or reconnect succeeds. */
  onManagementComplete?: () => void;
}

const POLL_INTERVAL_MS = 2000;
const MAX_POLLS = 90;

export default function IntegrationList({
  integrations,
  onSyncComplete,
  onManagementComplete,
}: IntegrationListProps) {
  const [syncStates, setSyncStates] = useState<Record<string, SyncRowState>>({});
  const [localIntegrations, setLocalIntegrations] = useState<Integration[]>(integrations);
  const [activeModal, setActiveModal] = useState<ModalType>(null);
  const [modalIntegration, setModalIntegration] = useState<Integration | null>(null);
  const [pauseInProgress, setPauseInProgress] = useState<Record<string, boolean>>({});
  const mountedRef = useRef(true);
  const { getToken } = useAuth();

  // Keep local state in sync when the parent re-fetches
  useEffect(() => {
    setLocalIntegrations(integrations);
  }, [integrations]);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  if (localIntegrations.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-16 gap-2"
        style={{ color: "#8b90a0", fontSize: "14px" }}
      >
        <span>No integrations connected yet.</span>
        <span style={{ fontSize: "12px" }}>
          Use the form above to connect your first integration.
        </span>
      </div>
    );
  }

  // ── Local state helpers ───────────────────────────────────────────────────

  function setRowState(integrationId: string, patch: Partial<SyncRowState>) {
    setSyncStates((prev) => ({
      ...prev,
      [integrationId]: { ...(prev[integrationId] ?? { polling: false, result: null, error: null }), ...patch },
    }));
  }

  function updateLocal(updated: Integration) {
    setLocalIntegrations((prev) =>
      prev.map((i) => (i.id === updated.id ? updated : i))
    );
  }

  function removeLocal(id: string) {
    setLocalIntegrations((prev) => prev.filter((i) => i.id !== id));
  }

  // ── Modal helpers ─────────────────────────────────────────────────────────

  function openModal(type: ModalType, integration: Integration) {
    setModalIntegration(integration);
    setActiveModal(type);
  }

  function closeModal() {
    setActiveModal(null);
    setModalIntegration(null);
  }

  // ── Pause / resume ────────────────────────────────────────────────────────

  async function handleTogglePause(integration: Integration) {
    const newStatus = integration.status === "paused" ? "active" : "paused";
    setPauseInProgress((prev) => ({ ...prev, [integration.id]: true }));
    try {
      const token = await getToken();
      const updated = await patchIntegration(integration.id, { status: newStatus }, token);
      updateLocal(updated);
      onManagementComplete?.();
    } catch {
      // Revert optimistic update — parent re-fetch will correct it
    } finally {
      setPauseInProgress((prev) => ({ ...prev, [integration.id]: false }));
    }
  }

  // ── Sync Now ──────────────────────────────────────────────────────────────

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
            let msg: string;
            if (changes > 0) {
              msg = `Sync complete — ${changes} change${changes === 1 ? "" : "s"} detected.`;
            } else if (snaps > 0) {
              msg = "Baseline created. No changes detected yet — future syncs compare against this snapshot. High-risk changes are emailed automatically.";
            } else {
              msg = "No changes since last sync — state is unchanged.";
            }
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
          if (polls < MAX_POLLS && mountedRef.current) {
            poll();
          } else if (mountedRef.current) {
            setRowState(integrationId, { polling: false, error: "Sync timed out.", result: null });
          }
        } catch (err) {
          if (mountedRef.current) {
            const msg = err instanceof Error ? err.message : "Lost connection while polling.";
            setRowState(integrationId, { polling: false, error: msg, result: null });
          }
        }
      }, POLL_INTERVAL_MS);
    }
    poll();
  }

  // ── Last-sync status dot ──────────────────────────────────────────────────

  function LastSyncDot({ integration }: { integration: Integration }) {
    const status = integration.last_sync_status;
    if (!status || status === "completed") return null;
    if (status === "failed") {
      return (
        <span
          title={integration.last_sync_error ?? "Last sync failed"}
          style={{ color: "#e84040", fontSize: "10px" }}
        >
          ● Sync error
        </span>
      );
    }
    if (status === "running" || status === "pending") {
      return <span style={{ color: "#f5a623", fontSize: "10px" }}>● Sync running…</span>;
    }
    return null;
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      {/* ── Modals ── */}
      {activeModal === "rename" && modalIntegration && (
        <RenameIntegrationModal
          integration={modalIntegration}
          onClose={closeModal}
          onSuccess={(updated) => { updateLocal(updated); closeModal(); onManagementComplete?.(); }}
        />
      )}
      {activeModal === "delete" && modalIntegration && (
        <DeleteIntegrationModal
          integration={modalIntegration}
          onClose={closeModal}
          onSuccess={() => { removeLocal(modalIntegration.id); closeModal(); onManagementComplete?.(); }}
        />
      )}
      {activeModal === "reconnect" && modalIntegration && (
        <ReconnectIntegrationModal
          integration={modalIntegration}
          onClose={closeModal}
          onSuccess={(updated) => { updateLocal(updated); closeModal(); onManagementComplete?.(); }}
        />
      )}

      <div style={{ border: "1px solid #2a2d38", borderRadius: "6px", overflow: "hidden" }}>
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
          <span style={{ width: "28px" }}></span>
        </div>

        {localIntegrations.map((integration) => {
          const state = syncStates[integration.id] ?? { polling: false, result: null, error: null };
          const isPaused = integration.status === "paused";
          const isBusy = pauseInProgress[integration.id] ?? false;
          const hasLiveSync = PROVIDERS_WITH_LIVE_SYNC.includes(integration.provider);

          return (
            <div
              key={integration.id}
              className="flex flex-col hover:bg-surface3"
              style={{ borderBottom: "1px solid #2a2d38" }}
            >
              {/* Main row */}
              <div className="flex items-center gap-4 px-4 py-3">
                {/* Name */}
                <span className="flex-1 truncate" style={{ fontSize: "13px", color: "#e8eaf0" }}>
                  {integration.display_name}
                </span>

                {/* Provider */}
                <span
                  className="shrink-0 uppercase tracking-wider"
                  style={{ fontSize: "11px", color: "#8b90a0", width: "100px" }}
                >
                  {integration.provider === "cloudflare" ? "Cloudflare" : integration.provider === "github" ? "GitHub" : integration.provider}
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

                {/* Sync Now / paused button */}
                <div className="shrink-0" style={{ width: "96px" }}>
                  {isPaused ? (
                    <span
                      style={{
                        display: "block",
                        textAlign: "center",
                        padding: "5px 8px",
                        borderRadius: "6px",
                        background: "#1c1e26",
                        border: "1px solid #2a2d38",
                        color: "#565b6e",
                        fontSize: "11px",
                      }}
                      title="Resume the integration to sync"
                    >
                      Sync paused
                    </span>
                  ) : (
                    <button
                      onClick={() => handleSync(integration.id)}
                      disabled={state.polling || isBusy}
                      style={{
                        width: "100%",
                        textAlign: "center",
                        padding: "5px 8px",
                        borderRadius: "6px",
                        background: state.polling ? "#22252f" : "#1e2030",
                        border: "1px solid #3a3d4a",
                        color: state.polling ? "#565b6e" : "#b0b5c4",
                        cursor: state.polling || isBusy ? "not-allowed" : "pointer",
                        fontSize: "12px",
                        fontFamily: "inherit",
                      }}
                    >
                      {state.polling ? "Syncing…" : "Sync Now"}
                    </button>
                  )}
                </div>

                {/* Kebab menu */}
                <div className="shrink-0" style={{ width: "28px" }}>
                  <KebabMenu
                    integration={integration}
                    busy={isBusy}
                    onRename={() => openModal("rename", integration)}
                    onTogglePause={() => handleTogglePause(integration)}
                    onUpdateToken={() => openModal("reconnect", integration)}
                    onDelete={() => openModal("delete", integration)}
                  />
                </div>
              </div>

              {/* Metadata strip */}
              <div
                className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 pb-3"
                style={{ fontSize: "11px", color: "#565b6e" }}
              >
                {/* Scheduled sync interval / paused state */}
                {isPaused ? (
                  <span>
                    Scheduled sync:{" "}
                    <span style={{ color: "#f5a623" }}>Paused</span>
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    Scheduled sync:{" "}
                    <span style={{ color: "#3ccf7e" }}>
                      {formatInterval(integration.sync_interval_minutes)}
                    </span>
                    <SyncIntervalSelector
                      integration={integration}
                      onChanged={(updated) => updateLocal(updated)}
                    />
                  </span>
                )}

                <span style={{ color: "#2a2d38" }}>·</span>

                {/* Email alerts */}
                <span>
                  Email alerts:{" "}
                  <span style={{ color: "#8b90a0" }}>High-risk changes</span>
                </span>

                <span style={{ color: "#2a2d38" }}>·</span>

                {/* Resource count */}
                <span>
                  Resources monitored:{" "}
                  <span style={{ color: "#8b90a0" }}>{integration.resource_count}</span>
                </span>

                {/* Live sync coming soon */}
                {!hasLiveSync && (
                  <>
                    <span style={{ color: "#2a2d38" }}>·</span>
                    <span style={{ color: "#3a3d4a" }} title="Webhook-based real-time sync is not yet available">
                      Live / webhook sync: coming soon
                    </span>
                  </>
                )}

                {/* Last sync status dot */}
                <LastSyncDot integration={integration} />
              </div>

              {/* Feedback row */}
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
    </>
  );
}
