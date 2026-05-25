"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { getWorkspaceAuditLogs } from "@/lib/api";
import type { WorkspaceAuditLog } from "@/types";

const PAGE_SIZE = 50;

/** Human-readable label for a known event_type. Falls back to raw value. */
function eventLabel(eventType: string): string {
  const labels: Record<string, string> = {
    workspace_created: "Workspace created",
    workspace_renamed: "Workspace renamed",
    member_invited: "Member invited",
    invite_revoked: "Invite revoked",
    invite_accepted: "Invite accepted",
    member_removed: "Member removed",
    member_role_changed: "Role changed",
    integration_created: "Integration added",
    integration_deleted: "Integration deleted",
    manual_sync_triggered: "Sync triggered",
  };
  return labels[eventType] ?? eventType;
}

/** Colour chip for event category. */
function eventColour(eventType: string): string {
  if (eventType.includes("removed") || eventType.includes("deleted") || eventType.includes("revoked")) {
    return "#7a2a2a";
  }
  if (eventType.includes("created") || eventType.includes("invited") || eventType.includes("accepted")) {
    return "#1a3a1a";
  }
  if (eventType.includes("renamed") || eventType.includes("changed") || eventType.includes("triggered")) {
    return "#1a2a3a";
  }
  return "#1e2130";
}

function eventTextColour(eventType: string): string {
  if (eventType.includes("removed") || eventType.includes("deleted") || eventType.includes("revoked")) {
    return "#f87171";
  }
  if (eventType.includes("created") || eventType.includes("invited") || eventType.includes("accepted")) {
    return "#4ade80";
  }
  if (eventType.includes("renamed") || eventType.includes("changed") || eventType.includes("triggered")) {
    return "#60a5fa";
  }
  return "#c4c8d4";
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function actorLabel(log: WorkspaceAuditLog): string {
  if (log.actor_email) return log.actor_email;
  if (log.actor_display_name) return log.actor_display_name;
  if (log.actor_user_id) return log.actor_user_id.slice(0, 8) + "…";
  return "System";
}

export default function AuditLogPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const { selectedWorkspace } = useWorkspace();

  const [logs, setLogs] = useState<WorkspaceAuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0); // 0-indexed
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    getToken()
      .then((token) =>
        getWorkspaceAuditLogs(selectedWorkspace.id, token, {
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        })
      )
      .then((data) => {
        setLogs(data.logs);
        setTotal(data.total);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load audit log."))
      .finally(() => setLoading(false));
  }, [selectedWorkspace, page]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: "32px 24px" }}>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 24,
        }}
      >
        <button
          onClick={() => router.push("/settings/workspace")}
          style={{
            background: "none",
            border: "none",
            color: "#8b90a0",
            cursor: "pointer",
            fontSize: 18,
            padding: 0,
          }}
          aria-label="Back"
        >
          ←
        </button>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, color: "#e2e5ef", margin: 0 }}>
            Audit log
          </h1>
          {selectedWorkspace && (
            <div style={{ fontSize: 12, color: "#565b6e", marginTop: 2 }}>
              {selectedWorkspace.name}
            </div>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            background: "#2a1a1a",
            border: "1px solid #7a2a2a",
            borderRadius: 6,
            padding: "10px 14px",
            color: "#f87171",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ color: "#565b6e", fontSize: 13, padding: "20px 0" }}>
          Loading…
        </div>
      )}

      {/* Log table */}
      {!loading && !error && (
        <section
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: 8,
            overflow: "hidden",
          }}
        >
          {logs.length === 0 ? (
            <div
              style={{
                padding: "32px 20px",
                textAlign: "center",
                color: "#565b6e",
                fontSize: 13,
              }}
            >
              No audit events recorded yet.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr
                  style={{
                    borderBottom: "1px solid #2a2d38",
                    background: "#0f1117",
                  }}
                >
                  {["When", "Event", "Actor", "Target"].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "10px 14px",
                        fontSize: 11,
                        fontWeight: 500,
                        color: "#565b6e",
                        textTransform: "uppercase",
                        letterSpacing: "0.05em",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr
                    key={log.id}
                    style={{ borderBottom: "1px solid #1e2130" }}
                  >
                    {/* When */}
                    <td
                      style={{
                        padding: "10px 14px",
                        fontSize: 12,
                        color: "#8b90a0",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {formatDate(log.created_at)}
                    </td>

                    {/* Event */}
                    <td style={{ padding: "10px 14px" }}>
                      <span
                        style={{
                          display: "inline-block",
                          background: eventColour(log.event_type),
                          color: eventTextColour(log.event_type),
                          borderRadius: 4,
                          padding: "2px 8px",
                          fontSize: 11,
                          fontWeight: 500,
                        }}
                      >
                        {eventLabel(log.event_type)}
                      </span>
                    </td>

                    {/* Actor */}
                    <td
                      style={{
                        padding: "10px 14px",
                        fontSize: 12,
                        color: "#c4c8d4",
                      }}
                    >
                      {actorLabel(log)}
                    </td>

                    {/* Target */}
                    <td
                      style={{
                        padding: "10px 14px",
                        fontSize: 12,
                        color: "#8b90a0",
                      }}
                    >
                      {log.target_display_name ?? log.target_id ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {/* Pagination */}
      {!loading && totalPages > 1 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 12,
            marginTop: 16,
          }}
        >
          <button
            disabled={page === 0}
            onClick={() => setPage((p) => p - 1)}
            style={{
              background: "none",
              border: "1px solid #2a2d38",
              borderRadius: 5,
              padding: "5px 12px",
              fontSize: 12,
              color: page === 0 ? "#3a3d4a" : "#8b90a0",
              cursor: page === 0 ? "not-allowed" : "pointer",
            }}
          >
            ← Previous
          </button>
          <span style={{ fontSize: 12, color: "#565b6e" }}>
            Page {page + 1} of {totalPages}
          </span>
          <button
            disabled={page + 1 >= totalPages}
            onClick={() => setPage((p) => p + 1)}
            style={{
              background: "none",
              border: "1px solid #2a2d38",
              borderRadius: 5,
              padding: "5px 12px",
              fontSize: 12,
              color: page + 1 >= totalPages ? "#3a3d4a" : "#8b90a0",
              cursor: page + 1 >= totalPages ? "not-allowed" : "pointer",
            }}
          >
            Next →
          </button>
        </div>
      )}

      {/* Total count */}
      {!loading && total > 0 && (
        <div
          style={{
            textAlign: "center",
            fontSize: 11,
            color: "#565b6e",
            marginTop: 8,
          }}
        >
          {total} event{total !== 1 ? "s" : ""} total
        </div>
      )}
    </main>
  );
}
