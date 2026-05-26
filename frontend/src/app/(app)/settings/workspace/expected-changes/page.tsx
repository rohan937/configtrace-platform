"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import type {
  ExpectedChangeWindow,
  ExpectedChangeWindowCreate,
} from "@/types";
import {
  listExpectedChangeWindows,
  createExpectedChangeWindow,
  approveExpectedChangeWindow,
  rejectExpectedChangeWindow,
  cancelExpectedChangeWindow,
} from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_COLOR: Record<string, string> = {
  pending:   "#f5a623",
  approved:  "#3ccf7e",
  rejected:  "#e84040",
  cancelled: "#565b6e",
};

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? "#8b90a0";
  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        letterSpacing: "0.05em",
        textTransform: "uppercase",
        color,
        background: `${color}22`,
        padding: "2px 6px",
        borderRadius: "3px",
      }}
    >
      {status}
    </span>
  );
}

// ── Small banner helpers ──────────────────────────────────────────────────────

function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      style={{
        background: "#2a1a1a",
        border: "1px solid #7a2a2a",
        borderRadius: "6px",
        padding: "10px 14px",
        color: "#f87171",
        fontSize: "13px",
        marginBottom: "16px",
      }}
    >
      {message}
    </div>
  );
}

function SuccessBanner({ message }: { message: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        background: "#1a2a1a",
        border: "1px solid #2a5a2a",
        borderRadius: "6px",
        padding: "10px 14px",
        color: "#4ade80",
        fontSize: "13px",
        marginBottom: "16px",
      }}
    >
      {message}
    </div>
  );
}

// ── Inline reject modal ───────────────────────────────────────────────────────

function RejectModal({
  onConfirm,
  onCancel,
  busy,
}: {
  onConfirm: (reason: string) => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const [reason, setReason] = useState("");
  return (
    <div
      style={{
        background: "#1a1d28",
        border: "1px solid #3a3d4a",
        borderRadius: "6px",
        padding: "14px",
        marginTop: "8px",
      }}
    >
      <p style={{ fontSize: "12px", color: "#c4c8d4", marginBottom: "8px" }}>
        Reason for rejection (optional):
      </p>
      <input
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="e.g. Insufficient justification"
        style={{
          width: "100%",
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "4px",
          padding: "6px 10px",
          fontSize: "12px",
          color: "#e2e5ef",
          fontFamily: "inherit",
          marginBottom: "10px",
          boxSizing: "border-box",
        }}
      />
      <div style={{ display: "flex", gap: "8px" }}>
        <button
          onClick={() => onConfirm(reason)}
          disabled={busy}
          style={{
            background: "#e84040",
            color: "#fff",
            border: "none",
            borderRadius: "4px",
            padding: "5px 12px",
            fontSize: "12px",
            cursor: busy ? "not-allowed" : "pointer",
            opacity: busy ? 0.7 : 1,
            fontFamily: "inherit",
          }}
        >
          Reject
        </button>
        <button
          onClick={onCancel}
          style={{
            background: "none",
            color: "#8b90a0",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "5px 10px",
            fontSize: "12px",
            cursor: "pointer",
            fontFamily: "inherit",
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Window row ────────────────────────────────────────────────────────────────

function WindowRow({
  w,
  onApprove,
  onReject,
  onCancel,
  busy,
}: {
  w: ExpectedChangeWindow;
  onApprove: (id: string) => void;
  onReject: (id: string, reason: string) => void;
  onCancel: (id: string) => void;
  busy: string | null;  // window id currently being actioned
}) {
  const [showRejectModal, setShowRejectModal] = useState(false);
  const isBusy = busy === w.id;

  const start = new Date(w.start_time).toLocaleString();
  const end   = new Date(w.end_time).toLocaleString();

  return (
    <li
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "14px 16px",
        marginBottom: "10px",
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <StatusBadge status={w.status} />
            <span style={{ fontSize: "13px", fontWeight: 600, color: "#e2e5ef" }}>
              {w.title}
            </span>
          </div>
          {w.description && (
            <p style={{ fontSize: "12px", color: "#8b90a0", marginBottom: "6px", lineHeight: 1.5 }}>
              {w.description}
            </p>
          )}
          <p style={{ fontSize: "11px", color: "#565b6e", margin: 0 }}>
            {start} – {end}
          </p>
          {/* Filters */}
          {(w.filter_provider || w.filter_integration_id || w.filter_risk_level) && (
            <div style={{ marginTop: "6px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
              {w.filter_provider && (
                <span style={{ fontSize: "10px", color: "#8b90a0", background: "#1e2130", padding: "1px 6px", borderRadius: "3px" }}>
                  provider: {w.filter_provider}
                </span>
              )}
              {w.filter_risk_level && (
                <span style={{ fontSize: "10px", color: "#8b90a0", background: "#1e2130", padding: "1px 6px", borderRadius: "3px" }}>
                  risk: {w.filter_risk_level}
                </span>
              )}
            </div>
          )}
          {w.rejection_reason && (
            <p style={{ fontSize: "11px", color: "#e84040", marginTop: "6px" }}>
              Rejection reason: {w.rejection_reason}
            </p>
          )}
          {w.approved_at && (
            <p style={{ fontSize: "11px", color: "#3ccf7e", marginTop: "4px" }}>
              Approved {new Date(w.approved_at).toLocaleString()}
            </p>
          )}
        </div>

        {/* Action buttons */}
        <div style={{ display: "flex", flexDirection: "column", gap: "6px", flexShrink: 0 }}>
          {w.status === "pending" && (
            <>
              <button
                onClick={() => onApprove(w.id)}
                disabled={isBusy}
                style={{
                  background: "#3ccf7e",
                  color: "#0a0c12",
                  border: "none",
                  borderRadius: "4px",
                  padding: "4px 10px",
                  fontSize: "11px",
                  fontWeight: 600,
                  cursor: isBusy ? "not-allowed" : "pointer",
                  opacity: isBusy ? 0.6 : 1,
                  fontFamily: "inherit",
                }}
              >
                Approve
              </button>
              <button
                onClick={() => setShowRejectModal(true)}
                disabled={isBusy}
                style={{
                  background: "none",
                  color: "#e84040",
                  border: "1px solid rgba(232,64,64,0.40)",
                  borderRadius: "4px",
                  padding: "4px 10px",
                  fontSize: "11px",
                  cursor: isBusy ? "not-allowed" : "pointer",
                  opacity: isBusy ? 0.6 : 1,
                  fontFamily: "inherit",
                }}
              >
                Reject
              </button>
            </>
          )}
          {(w.status === "pending" || w.status === "approved") && (
            <button
              onClick={() => onCancel(w.id)}
              disabled={isBusy}
              style={{
                background: "none",
                color: "#8b90a0",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "4px 10px",
                fontSize: "11px",
                cursor: isBusy ? "not-allowed" : "pointer",
                opacity: isBusy ? 0.6 : 1,
                fontFamily: "inherit",
              }}
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Reject reason inline */}
      {showRejectModal && (
        <RejectModal
          busy={isBusy}
          onConfirm={(reason) => {
            setShowRejectModal(false);
            onReject(w.id, reason);
          }}
          onCancel={() => setShowRejectModal(false)}
        />
      )}
    </li>
  );
}

// ── Create form ───────────────────────────────────────────────────────────────

function CreateWindowForm({
  onSubmit,
  onCancel,
  busy,
}: {
  onSubmit: (body: ExpectedChangeWindowCreate) => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const toLocalInput = (d: Date) =>
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

  const [title, setTitle]             = useState("");
  const [description, setDescription] = useState("");
  const [startTime, setStartTime]     = useState(toLocalInput(now));
  const [endTime, setEndTime]         = useState(toLocalInput(new Date(now.getTime() + 4 * 3600 * 1000)));
  const [alertBehavior, setAlertBehavior] = useState<"annotate_only" | "suppress">("annotate_only");
  const [filterProvider, setFilterProvider]   = useState("");
  const [filterRiskLevel, setFilterRiskLevel] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim() || !startTime || !endTime) return;

    onSubmit({
      title: title.trim(),
      description: description.trim() || undefined,
      start_time: new Date(startTime).toISOString(),
      end_time: new Date(endTime).toISOString(),
      alert_behavior: alertBehavior,
      filter_provider: filterProvider.trim() || null,
      filter_risk_level: filterRiskLevel || null,
    });
  }

  const inputStyle: React.CSSProperties = {
    background: "#1a1d28",
    border: "1px solid #3a3d4a",
    borderRadius: "5px",
    padding: "6px 10px",
    fontSize: "12px",
    color: "#e2e5ef",
    fontFamily: "inherit",
    width: "100%",
    boxSizing: "border-box",
  };

  const labelStyle: React.CSSProperties = {
    fontSize: "11px",
    color: "#8b90a0",
    marginBottom: "4px",
    display: "block",
  };

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "16px",
        marginBottom: "16px",
      }}
    >
      <p style={{ fontSize: "13px", fontWeight: 600, color: "#c4c8d4", marginBottom: "14px" }}>
        New Expected Change Window
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
        <div style={{ gridColumn: "1 / -1" }}>
          <label style={labelStyle}>Title *</label>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
            placeholder="e.g. Deploy v2.1 — Infrastructure update"
            style={inputStyle}
          />
        </div>

        <div style={{ gridColumn: "1 / -1" }}>
          <label style={labelStyle}>Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder="Optional details about what changes are expected…"
            style={{ ...inputStyle, resize: "vertical" }}
          />
        </div>

        <div>
          <label style={labelStyle}>Start time (local) *</label>
          <input
            type="datetime-local"
            value={startTime}
            onChange={(e) => setStartTime(e.target.value)}
            required
            style={inputStyle}
          />
        </div>

        <div>
          <label style={labelStyle}>End time (local) *</label>
          <input
            type="datetime-local"
            value={endTime}
            onChange={(e) => setEndTime(e.target.value)}
            required
            style={inputStyle}
          />
        </div>

        <div>
          <label style={labelStyle}>Alert behavior</label>
          <select
            value={alertBehavior}
            onChange={(e) => setAlertBehavior(e.target.value as "annotate_only" | "suppress")}
            style={inputStyle}
          >
            <option value="annotate_only">Annotate only (recommended)</option>
            <option value="suppress">Suppress alerts</option>
          </select>
        </div>

        <div>
          <label style={labelStyle}>Filter by provider (optional)</label>
          <select
            value={filterProvider}
            onChange={(e) => setFilterProvider(e.target.value)}
            style={inputStyle}
          >
            <option value="">All providers</option>
            <option value="cloudflare">Cloudflare</option>
            <option value="github">GitHub</option>
            <option value="vercel">Vercel</option>
            <option value="stripe">Stripe</option>
            <option value="aws">AWS</option>
            <option value="firebase">Firebase</option>
            <option value="supabase">Supabase</option>
            <option value="shopify">Shopify</option>
          </select>
        </div>

        <div>
          <label style={labelStyle}>Filter by risk level (optional)</label>
          <select
            value={filterRiskLevel}
            onChange={(e) => setFilterRiskLevel(e.target.value)}
            style={inputStyle}
          >
            <option value="">All risk levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <p style={{ fontSize: "11px", color: "#565b6e", marginBottom: "12px" }}>
        Windows start in <strong>pending</strong> status and must be approved before they match changes.
        &ldquo;Annotate only&rdquo; surfaces the match in the UI without suppressing alerts.
      </p>

      <div style={{ display: "flex", gap: "8px" }}>
        <button
          type="submit"
          disabled={busy || !title.trim()}
          style={{
            background: "#4f80f7",
            color: "#fff",
            border: "none",
            borderRadius: "5px",
            padding: "7px 16px",
            fontSize: "12px",
            cursor: busy || !title.trim() ? "not-allowed" : "pointer",
            opacity: busy ? 0.7 : 1,
            fontFamily: "inherit",
          }}
        >
          {busy ? "Creating…" : "Create window"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          style={{
            background: "none",
            color: "#8b90a0",
            border: "1px solid #2a2d38",
            borderRadius: "5px",
            padding: "7px 12px",
            fontSize: "12px",
            cursor: "pointer",
            fontFamily: "inherit",
          }}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ExpectedChangesPage() {
  const { getToken } = useAuth();
  const { selectedWorkspace } = useWorkspace();

  const [windows, setWindows]       = useState<ExpectedChangeWindow[]>([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const [success, setSuccess]       = useState<string | null>(null);
  const [creating, setCreating]     = useState(false);
  const [busy, setBusy]             = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null); // window id
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const load = useCallback(async () => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const params = statusFilter !== "all" ? { status: statusFilter } : undefined;
      const data = await listExpectedChangeWindows(selectedWorkspace.id, params, token);
      setWindows(data.windows);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load windows.");
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken, statusFilter]);

  useEffect(() => { void load(); }, [load]);

  async function handleCreate(body: ExpectedChangeWindowCreate) {
    if (!selectedWorkspace) return;
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      await createExpectedChangeWindow(selectedWorkspace.id, body, token);
      setCreating(false);
      setSuccess("Window created and pending approval.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create window.");
    } finally {
      setBusy(false);
    }
  }

  async function handleApprove(windowId: string) {
    if (!selectedWorkspace) return;
    setActionBusy(windowId);
    setError(null);
    try {
      const token = await getToken();
      await approveExpectedChangeWindow(selectedWorkspace.id, windowId, token);
      setSuccess("Window approved.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to approve.");
    } finally {
      setActionBusy(null);
    }
  }

  async function handleReject(windowId: string, reason: string) {
    if (!selectedWorkspace) return;
    setActionBusy(windowId);
    setError(null);
    try {
      const token = await getToken();
      await rejectExpectedChangeWindow(selectedWorkspace.id, windowId, reason || undefined, token);
      setSuccess("Window rejected.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reject.");
    } finally {
      setActionBusy(null);
    }
  }

  async function handleCancel(windowId: string) {
    if (!selectedWorkspace) return;
    setActionBusy(windowId);
    setError(null);
    try {
      const token = await getToken();
      await cancelExpectedChangeWindow(selectedWorkspace.id, windowId, token);
      setSuccess("Window cancelled.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel.");
    } finally {
      setActionBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Expected Changes"
        description="Manage planned change windows so expected drift is annotated — not alarming."
      />

      <div className="px-6 pb-8" style={{ maxWidth: "780px" }}>
        {/* Back link */}
        <Link
          href="/settings/workspace"
          style={{ fontSize: "12px", color: "#4f80f7", display: "inline-block", marginBottom: "16px" }}
        >
          ← Workspace Settings
        </Link>

        {error   && <ErrorBanner   message={error}   />}
        {success && <SuccessBanner message={success} />}

        {/* No workspace */}
        {!selectedWorkspace && (
          <p style={{ fontSize: "13px", color: "#565b6e" }}>No workspace selected.</p>
        )}

        {selectedWorkspace && (
          <>
            {/* Toolbar */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "16px",
              }}
            >
              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <span style={{ fontSize: "12px", color: "#565b6e" }}>Filter:</span>
                {(["all", "pending", "approved", "rejected", "cancelled"] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => { setStatusFilter(s); setSuccess(null); }}
                    style={{
                      fontSize: "11px",
                      padding: "3px 8px",
                      borderRadius: "4px",
                      border: statusFilter === s ? "1px solid #4f80f7" : "1px solid #2a2d38",
                      background: statusFilter === s ? "rgba(79,128,247,0.12)" : "none",
                      color: statusFilter === s ? "#4f80f7" : "#8b90a0",
                      cursor: "pointer",
                      fontFamily: "inherit",
                    }}
                  >
                    {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
                  </button>
                ))}
              </div>

              {!creating && (
                <button
                  onClick={() => { setCreating(true); setSuccess(null); setError(null); }}
                  style={{
                    background: "#4f80f7",
                    color: "#fff",
                    border: "none",
                    borderRadius: "5px",
                    padding: "6px 14px",
                    fontSize: "12px",
                    cursor: "pointer",
                    fontFamily: "inherit",
                  }}
                >
                  + New Window
                </button>
              )}
            </div>

            {/* Create form */}
            {creating && (
              <CreateWindowForm
                busy={busy}
                onSubmit={handleCreate}
                onCancel={() => setCreating(false)}
              />
            )}

            {/* Window list */}
            {loading ? (
              <p style={{ fontSize: "13px", color: "#565b6e" }}>Loading windows…</p>
            ) : windows.length === 0 ? (
              <div
                style={{
                  background: "#13151a",
                  border: "1px solid #2a2d38",
                  borderRadius: "6px",
                  padding: "24px",
                  textAlign: "center",
                }}
              >
                <p style={{ fontSize: "14px", color: "#565b6e", marginBottom: "8px" }}>
                  No expected change windows{statusFilter !== "all" ? ` with status "${statusFilter}"` : ""}.
                </p>
                <p style={{ fontSize: "12px", color: "#3a3d4a" }}>
                  Create a window to mark a planned deployment or maintenance period.
                </p>
              </div>
            ) : (
              <>
                <p style={{ fontSize: "11px", color: "#565b6e", marginBottom: "10px" }}>
                  Showing {windows.length} of {total} window{total !== 1 ? "s" : ""}
                </p>
                <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                  {windows.map((w) => (
                    <WindowRow
                      key={w.id}
                      w={w}
                      onApprove={handleApprove}
                      onReject={handleReject}
                      onCancel={handleCancel}
                      busy={actionBusy}
                    />
                  ))}
                </ul>
              </>
            )}

            {/* Info footer */}
            <div
              style={{
                marginTop: "20px",
                padding: "12px 14px",
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                fontSize: "11px",
                color: "#565b6e",
                lineHeight: 1.6,
              }}
            >
              <strong style={{ color: "#8b90a0" }}>How it works:</strong>
              {" "}Changes detected during an{" "}
              <span style={{ color: "#3ccf7e" }}>approved</span> window that match
              its provider/risk filters will show an &ldquo;Expected Change&rdquo; badge
              on the change detail page.{" "}
              <em>Annotate only</em> surfaces this without suppressing alerts.{" "}
              <em>Suppress alerts</em> prevents alert dispatch for matched changes.{" "}
              Backend enforces admin role for all write operations.
            </div>
          </>
        )}
      </div>
    </>
  );
}
